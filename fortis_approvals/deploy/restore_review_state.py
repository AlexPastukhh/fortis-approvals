"""Restore the pinned R7 backup into an empty, separately mounted review volume.

Operator-only helper, not packaged in the Gateway image. No network or secrets.
The backup is read-only; only the review owner Origin is migrated.
"""
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import stat

MANIFEST_SHA256 = '0b783913f0465ab9fb8fc098953ae0b74070cc6f8e854845258390486f7078dd'
SOURCE_ORIGIN = 'http://localhost:19103'
TARGET_ORIGIN = 'http://localhost:19203'
FILES = frozenset({'.fortis-r7-unified-v1', 'approvals.sqlite',
                   'owner.sqlite', 'sonar-receipts.sqlite'})


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


@contextmanager
def database(path):
    # Backups are standalone SQLite files, with no WAL/journal dependency.
    db = sqlite3.connect(path.absolute().as_uri() + '?mode=ro&immutable=1', uri=True)
    try:
        require(db.execute('PRAGMA integrity_check').fetchall() == [('ok',)],
                'R7_DATABASE_INTEGRITY_FAILED:' + path.name)
        yield db
    finally:
        db.close()


def owner_snapshot(path):
    with database(path) as db:
        return {
            'config': dict(db.execute('SELECT setting,value FROM config')),
            'credentials': db.execute('SELECT * FROM credentials ORDER BY id').fetchall(),
            'invitations': db.execute('SELECT * FROM invitations ORDER BY digest').fetchall(),
            'active': db.execute('SELECT COUNT(*) FROM credentials WHERE active=1').fetchone()[0],
        }


def restore(backup, volume, *, target_uid=10001, target_gid=10001,
            expected_manifest_sha256=MANIFEST_SHA256):
    backup, volume = Path(backup), Path(volume)
    require(backup.is_dir() and not backup.is_symlink(), 'R7_BACKUP_DIRECTORY_INVALID')
    require(volume.is_dir() and not volume.is_symlink(), 'R7_TARGET_DIRECTORY_INVALID')
    require(backup.resolve() != volume.resolve() and
            backup.resolve() not in volume.resolve().parents and
            volume.resolve() not in backup.resolve().parents,
            'R7_BACKUP_AND_TARGET_NOT_SEPARATE')
    require(not any(volume.iterdir()), 'R7_TARGET_VOLUME_NOT_EMPTY')
    manifest_path = backup / 'manifest.json'
    require(manifest_path.is_file() and not manifest_path.is_symlink(),
            'R7_MANIFEST_FILE_INVALID')
    require(sha256(manifest_path) == expected_manifest_sha256,
            'R7_PINNED_MANIFEST_HASH_MISMATCH')
    manifest = json.loads(manifest_path.read_bytes())
    require(set(manifest['sha256']) == FILES, 'R7_BACKUP_FILE_SET_MISMATCH')
    require(manifest.get('ownerBindingPass') is True, 'R7_OWNER_BINDING_NOT_VERIFIED')
    for name in FILES:
        source = backup / name
        require(source.is_file() and not source.is_symlink(), 'R7_BACKUP_FILE_INVALID:' + name)
        require(sha256(source) == manifest['sha256'][name], 'R7_BACKUP_FILE_HASH_MISMATCH:' + name)
        for suffix in ('-wal', '-shm', '-journal'):
            require(not (backup / (name + suffix)).exists(), 'R7_BACKUP_SIDECAR_PRESENT')
    require((backup / '.fortis-r7-unified-v1').read_bytes() == b'fortis-r7-unified-v1\n',
            'R7_BACKUP_MARKER_INVALID')
    recorded = manifest['databases']
    require(all(recorded[name]['integrity'] == 'ok' for name in
                ('approvals.sqlite', 'owner.sqlite', 'sonar-receipts.sqlite')),
            'R7_MANIFEST_INTEGRITY_NOT_OK')
    with database(backup / 'approvals.sqlite') as db:
        states = dict(db.execute('SELECT state,COUNT(*) FROM requests GROUP BY state'))
        events = db.execute('SELECT COUNT(*) FROM events').fetchone()[0]
    require(states == recorded['approvals.sqlite']['requestStates'] and
            events == recorded['approvals.sqlite']['events'], 'R7_BACKUP_HISTORY_MISMATCH')
    before = owner_snapshot(backup / 'owner.sqlite')
    require(before['config'] == {'origin': SOURCE_ORIGIN, 'rpId': 'localhost', 'owner': 'owner'},
            'R7_BACKUP_OWNER_BINDING_MISMATCH')
    require(before['active'] == recorded['owner.sqlite']['credentialsActive'] == 1 and
            len(before['credentials']) == recorded['owner.sqlite']['credentialsTotal'] and
            len(before['invitations']) == recorded['owner.sqlite']['invitationsTotal'],
            'R7_BACKUP_OWNER_COUNTS_MISMATCH')
    with database(backup / 'sonar-receipts.sqlite') as db:
        receipts = db.execute('SELECT COUNT(*) FROM receipts').fetchone()[0]
    require(receipts == recorded['sonar-receipts.sqlite']['receipts'],
            'R7_BACKUP_RECEIPTS_MISMATCH')

    # All source validation is complete before the first target write.
    private = volume / 'private'
    private.mkdir(mode=0o700)
    os.chmod(private, 0o700)
    for name in sorted(FILES):
        target = private / name
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as output:
            output.write((backup / name).read_bytes())
            output.flush()
            os.fsync(output.fileno())
        require(sha256(target) == manifest['sha256'][name], 'R7_COPY_HASH_MISMATCH:' + name)
    db = sqlite3.connect(private / 'owner.sqlite')
    try:
        with db:
            changed = db.execute("UPDATE config SET value=? WHERE setting='origin' AND value=?",
                                 (TARGET_ORIGIN, SOURCE_ORIGIN)).rowcount
            require(changed == 1, 'R7_REVIEW_ORIGIN_MIGRATION_FAILED')
    finally:
        db.close()
    after = owner_snapshot(private / 'owner.sqlite')
    require(after['config'] == {'origin': TARGET_ORIGIN, 'rpId': 'localhost', 'owner': 'owner'},
            'R7_REVIEW_OWNER_BINDING_INVALID')
    require(after['credentials'] == before['credentials'] and
            after['invitations'] == before['invitations'] and after['active'] == before['active'],
            'R7_REVIEW_OWNER_DATA_CHANGED')
    for name in ('approvals.sqlite', 'sonar-receipts.sqlite'):
        require(sha256(private / name) == manifest['sha256'][name],
                'R7_REVIEW_HISTORY_BYTES_CHANGED:' + name)
        with database(private / name):
            pass
    require(set(p.name for p in private.iterdir()) == FILES, 'R7_REVIEW_UNEXPECTED_FILE')

    # chmod while still the creator/owner, then CHOWN. No CAP_FOWNER needed.
    for name in sorted(FILES):
        target = private / name
        os.chmod(target, 0o600)
        os.chown(target, target_uid, target_gid)
    os.chown(private, target_uid, target_gid)
    for path, mode in [(private, 0o700)] + [(private / n, 0o600) for n in FILES]:
        info = path.stat()
        require(info.st_uid == target_uid and info.st_gid == target_gid and
                stat.S_IMODE(info.st_mode) == mode, 'R7_REVIEW_PERMISSIONS_INVALID')
    for name in FILES:
        require(sha256(backup / name) == manifest['sha256'][name], 'R7_BACKUP_CHANGED')
    require(sha256(manifest_path) == expected_manifest_sha256, 'R7_MANIFEST_CHANGED')
    return {'requestStates': states, 'requests': sum(states.values()), 'events': events,
            'receipts': receipts, 'credentialsActive': after['active'],
            'credentialsUnchanged': True, 'historyBytesUnchanged': True,
            'ownerOrigin': TARGET_ORIGIN, 'rpId': 'localhost',
            'manifestSha256': expected_manifest_sha256,
            'ownerCopySha256': sha256(private / 'owner.sqlite'),
            'sha256': {name: sha256(private / name) for name in sorted(FILES)}}


if __name__ == '__main__':
    result = restore('/backup', '/state')
    print(json.dumps(result, sort_keys=True))
    print('R7_REVIEW_VOLUME_RESTORE_PASS')

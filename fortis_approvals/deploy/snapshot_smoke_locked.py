"""Stream a SQLite snapshot while retaining source read locks until release/stop.

Private database bytes go only to the redirected exporter pipe and protected
Windows backup. Never invoke this exporter with inherited console stdout.
"""
from contextlib import contextmanager, ExitStack
from datetime import datetime, timezone
import base64
import hashlib
import io
import json
import os
from pathlib import Path
import select
import sqlite3
import stat
import sys
import tempfile
import time
import zipfile

ID = 'd35f999783872ed11225b52fffee534f93777dcd757b326044aa2521dc7bd1f3'
IMAGE = 'sha256:a2fd23c3def0609ed254cd796f40fb51cc4a5a103f0486bb0052d44d76b23267'
DBS = ('approvals.sqlite', 'owner.sqlite', 'sonar-receipts.sqlite')
MARKER = '.fortis-r7-unified-v1'
FILES = {MARKER, *DBS}


def require(condition, error):
    if not condition:
        raise RuntimeError(error)


def hash_bytes(data):
    return hashlib.sha256(data).hexdigest()


def logical_hash(db):
    value = hashlib.sha256()
    for line in db.iterdump():
        value.update(line.encode('utf-8'))
        value.update(b'\n')
    return value.hexdigest()


def check_db(db):
    require(db.execute('PRAGMA integrity_check').fetchall() == [('ok',)], 'R3_SNAPSHOT_INTEGRITY_FAILED')


def summary(connections):
    approvals, owner, receipts = (connections[n] for n in DBS)
    binding = dict(owner.execute('SELECT setting,value FROM config'))
    require(binding == {'origin': 'http://localhost:19103', 'rpId': 'localhost', 'owner': 'owner'},
            'R3_SNAPSHOT_BINDING_UNKNOWN')
    return {
        'requestStates': dict(approvals.execute('SELECT state,COUNT(*) FROM requests GROUP BY state')),
        'requests': approvals.execute('SELECT COUNT(*) FROM requests').fetchone()[0],
        'events': approvals.execute('SELECT COUNT(*) FROM events').fetchone()[0],
        'receipts': receipts.execute('SELECT COUNT(*) FROM receipts').fetchone()[0],
        'credentialsTotal': owner.execute('SELECT COUNT(*) FROM credentials').fetchone()[0],
        'credentialsActive': owner.execute('SELECT COUNT(*) FROM credentials WHERE active=1').fetchone()[0],
        'invitationsTotal': owner.execute('SELECT COUNT(*) FROM invitations').fetchone()[0],
        'ownerOrigin': binding['origin'], 'rpId': binding['rpId'],
    }


@contextmanager
def locked_snapshot(root, *, uid=10001, gid=10001):
    root = Path(root)
    require(os.geteuid() == uid and os.getegid() == gid, 'R3_SNAPSHOT_IDENTITY_MISMATCH')
    info = root.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == uid and
            stat.S_IMODE(info.st_mode) == 0o700, 'R3_SNAPSHOT_STATE_ROOT_INVALID')
    require({p.name for p in root.iterdir()} == FILES, 'R3_SNAPSHOT_UNKNOWN_FILES_OR_JOURNAL')
    require((root / MARKER).read_bytes() == b'fortis-r7-unified-v1\n', 'R3_SNAPSHOT_MARKER_INVALID')
    for name in FILES:
        info = (root / name).lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_uid == uid and
                stat.S_IMODE(info.st_mode) == 0o600, 'R3_SNAPSHOT_FILE_INVALID')
    with ExitStack() as stack:
        connections = {}
        for name in DBS:
            db = sqlite3.connect((root / name).absolute().as_uri() + '?mode=ro', uri=True, timeout=10)
            stack.callback(db.close)
            require(db.execute('PRAGMA journal_mode').fetchone()[0] == 'delete',
                    'R3_SNAPSHOT_JOURNAL_MODE_UNKNOWN')
            db.execute('BEGIN')
            db.execute('SELECT COUNT(*) FROM sqlite_master').fetchone()  # acquire SHARED lock
            check_db(db)
            connections[name] = db
        observed = summary(connections)
        logical = {name: logical_hash(db) for name, db in connections.items()}
        folder = Path(stack.enter_context(tempfile.TemporaryDirectory(prefix='fortis-r3-locked-')))
        folder.chmod(0o700)
        (folder / MARKER).write_bytes((root / MARKER).read_bytes())
        (folder / MARKER).chmod(0o600)
        for name, source in connections.items():
            path = folder / name
            os.close(os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600))
            target = sqlite3.connect(path)
            try:
                source.backup(target)
                check_db(target)
                require(logical_hash(target) == logical[name], 'R3_SNAPSHOT_LOGICAL_CONTENT_MISMATCH')
            finally:
                target.close()
            with path.open('rb') as stream:
                os.fsync(stream.fileno())
        manifest = {'format': 'fortis-r3-locked-snapshot-v1', 'containerId': ID, 'imageId': IMAGE,
            'createdUtc': datetime.now(timezone.utc).isoformat(), 'summary': observed,
            'sha256': {n: hash_bytes((folder / n).read_bytes()) for n in sorted(FILES)},
            'logicalSha256': logical, 'integrity': 'ok for all three databases'}
        raw = (json.dumps(manifest, sort_keys=True, indent=2) + '\n').encode()
        (folder / 'manifest.json').write_bytes(raw)
        (folder / 'manifest.sha256').write_text(hash_bytes(raw) + '  manifest.json\n')
        data = io.BytesIO()
        with zipfile.ZipFile(data, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
            for name in sorted(FILES | {'manifest.json', 'manifest.sha256'}):
                archive.writestr(name, (folder / name).read_bytes())
        payload = data.getvalue()
        require(len(payload) <= 16 * 1024 * 1024, 'R3_SNAPSHOT_TOO_LARGE')
        require(all(db.in_transaction for db in connections.values()), 'R3_SNAPSHOT_LOCKS_NOT_HELD')
        yield payload, manifest, connections


def serve(root='/state/private', *, uid=10001, gid=10001):
    with locked_snapshot(root, uid=uid, gid=gid) as (payload, _manifest, connections):
        encoded = base64.b64encode(payload).decode('ascii')
        print('FORTIS_R3_LOCKED_ZIP_V1 ' + str(len(encoded)) + ' ' + hash_bytes(payload), flush=True)
        print(encoded, flush=True)
        deadline = time.monotonic() + 300
        while True:
            remaining = deadline - time.monotonic()
            require(remaining > 0, 'R3_SNAPSHOT_LOCK_LEASE_EXPIRED')
            readable, _, _ = select.select([sys.stdin], [], [], remaining)
            require(bool(readable), 'R3_SNAPSHOT_LOCK_LEASE_EXPIRED')
            command = sys.stdin.readline().strip()
            if command in ('', 'RELEASE'):
                print('R3_LOCKS_RELEASED', flush=True)
                return
            require(command == 'STATUS', 'R3_SNAPSHOT_PROTOCOL_INVALID')
            require(all(db.in_transaction for db in connections.values()), 'R3_SNAPSHOT_LOCKS_LOST')
            print('R3_LOCKS_HELD ' + str(int(deadline - time.monotonic())), flush=True)


if __name__ == '__main__':
    serve()

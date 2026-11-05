"""Read-only post-restore verification as the Gateway UID, without backup/secrets."""
from contextlib import contextmanager
import hashlib
import os
from pathlib import Path
import sqlite3
import stat

FILES = frozenset({'.fortis-r7-unified-v1', 'approvals.sqlite',
                   'owner.sqlite', 'sonar-receipts.sqlite'})


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


@contextmanager
def database(path):
    db = sqlite3.connect(path.absolute().as_uri() + '?mode=ro&immutable=1', uri=True)
    try:
        require(db.execute('PRAGMA integrity_check').fetchall() == [('ok',)],
                'R7_REVIEW_INTEGRITY_FAILED:' + path.name)
        yield db
    finally:
        db.close()


def verify(volume, expected, *, uid=10001, gid=10001):
    require(os.geteuid() == uid and os.getegid() == gid, 'R7_VERIFIER_WRONG_IDENTITY')
    volume = Path(volume)
    require(not volume.is_symlink() and volume.is_dir(), 'R7_REVIEW_VOLUME_INVALID')
    require(set(p.name for p in volume.iterdir()) == {'private'}, 'R7_REVIEW_VOLUME_CONTENTS_INVALID')
    private = volume / 'private'
    require(not private.is_symlink() and private.is_dir(), 'R7_REVIEW_PRIVATE_DIRECTORY_INVALID')
    require(set(p.name for p in private.iterdir()) == FILES, 'R7_REVIEW_FILE_SET_MISMATCH')
    require(set(expected['sha256']) == FILES, 'R7_RESTORE_RECEIPT_HASH_SET_INVALID')
    for path, mode in [(private, 0o700)] + [(private / n, 0o600) for n in sorted(FILES)]:
        info = path.lstat()
        kind_ok = stat.S_ISDIR(info.st_mode) if path == private else stat.S_ISREG(info.st_mode)
        require(kind_ok and info.st_uid == uid and info.st_gid == gid and
                stat.S_IMODE(info.st_mode) == mode, 'R7_REVIEW_PERMISSIONS_INVALID:' + path.name)
        if path != private:
            require(hashlib.sha256(path.read_bytes()).hexdigest() == expected['sha256'][path.name],
                    'R7_REVIEW_FILE_HASH_MISMATCH:' + path.name)
    require((private / '.fortis-r7-unified-v1').read_bytes() == b'fortis-r7-unified-v1\n',
            'R7_REVIEW_MARKER_INVALID')
    with database(private / 'approvals.sqlite') as db:
        states = dict(db.execute('SELECT state,COUNT(*) FROM requests GROUP BY state'))
        events = db.execute('SELECT COUNT(*) FROM events').fetchone()[0]
    require(states == expected['requestStates'] and events == expected['events'] and
            sum(states.values()) == expected['requests'], 'R7_REVIEW_HISTORY_MISMATCH')
    with database(private / 'owner.sqlite') as db:
        binding = dict(db.execute('SELECT setting,value FROM config'))
        active = db.execute('SELECT COUNT(*) FROM credentials WHERE active=1').fetchone()[0]
    require(binding == {'origin': 'http://localhost:19203', 'rpId': 'localhost', 'owner': 'owner'},
            'R7_REVIEW_OWNER_BINDING_MISMATCH')
    require(active == expected['credentialsActive'] == 1 and
            expected['credentialsUnchanged'] is True and expected['historyBytesUnchanged'] is True,
            'R7_REVIEW_CREDENTIAL_PRESERVATION_FAILED')
    with database(private / 'sonar-receipts.sqlite') as db:
        receipts = db.execute('SELECT COUNT(*) FROM receipts').fetchone()[0]
    require(receipts == expected['receipts'], 'R7_REVIEW_RECEIPTS_MISMATCH')
    # The immutable SQLite readers must not have created journal/WAL files.
    require(set(p.name for p in private.iterdir()) == FILES, 'R7_REVIEW_VERIFIER_CHANGED_FILE_SET')
    for name in FILES:
        require(hashlib.sha256((private / name).read_bytes()).hexdigest() == expected['sha256'][name],
                'R7_REVIEW_VERIFIER_CHANGED_BYTES')
    return {'verification': 'PASS', 'uid': uid, 'gid': gid,
            'requestStates': states, 'requests': sum(states.values()), 'events': events,
            'receipts': receipts, 'credentialsActive': active,
            'ownerOrigin': binding['origin'], 'rpId': binding['rpId'],
            'integrity': 'ok for all three databases', 'allHashesMatchRestoreReceipt': True}

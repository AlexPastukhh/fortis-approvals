"""Read-only count/integrity probe of r3 state; never exposes credential rows."""
import hashlib
import os
from pathlib import Path
import sqlite3
import stat

FILES = {'.fortis-r7-unified-v1', 'approvals.sqlite', 'owner.sqlite', 'sonar-receipts.sqlite'}


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def probe(root='/state/private', *, uid=10001, gid=10001):
    require(os.geteuid() == uid and os.getegid() == gid, 'R3_PROBE_IDENTITY_MISMATCH')
    root = Path(root)
    info = root.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == uid and
            stat.S_IMODE(info.st_mode) == 0o700, 'R3_PRIVATE_DIRECTORY_INVALID')
    require({p.name for p in root.iterdir()} == FILES, 'R3_UNEXPECTED_FILES_OR_SQLITE_JOURNAL')
    for name in FILES:
        info = (root / name).lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_uid == uid and
                stat.S_IMODE(info.st_mode) == 0o600, 'R3_STATE_FILE_INVALID:' + name)
    require((root / '.fortis-r7-unified-v1').read_bytes() == b'fortis-r7-unified-v1\n',
            'R3_MARKER_INVALID')
    before = {name: digest(root / name) for name in FILES}
    counts, binding = {}, None
    expected_tables = {'approvals.sqlite': {'requests', 'events', 'sqlite_sequence'},
                       'owner.sqlite': {'config', 'credentials', 'invitations'},
                       'sonar-receipts.sqlite': {'receipts'}}
    for name in ('approvals.sqlite', 'owner.sqlite', 'sonar-receipts.sqlite'):
        db = sqlite3.connect((root / name).absolute().as_uri() + '?mode=ro&immutable=1', uri=True)
        try:
            require(db.execute('PRAGMA integrity_check').fetchall() == [('ok',)],
                    'R3_DATABASE_INTEGRITY_FAILED:' + name)
            tables = {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            require(tables == expected_tables[name], 'R3_UNEXPECTED_DATABASE_TABLES:' + name)
            if name == 'approvals.sqlite':
                counts['requests'] = db.execute('SELECT COUNT(*) FROM requests').fetchone()[0]
                counts['events'] = db.execute('SELECT COUNT(*) FROM events').fetchone()[0]
                counts['eventSequenceRows'] = db.execute('SELECT COUNT(*) FROM sqlite_sequence').fetchone()[0]
            elif name == 'owner.sqlite':
                binding = dict(db.execute('SELECT setting,value FROM config'))
                counts['credentialsTotal'] = db.execute('SELECT COUNT(*) FROM credentials').fetchone()[0]
                counts['credentialsActive'] = db.execute('SELECT COUNT(*) FROM credentials WHERE active=1').fetchone()[0]
                counts['invitationsTotal'] = db.execute('SELECT COUNT(*) FROM invitations').fetchone()[0]
            else:
                counts['receipts'] = db.execute('SELECT COUNT(*) FROM receipts').fetchone()[0]
        finally:
            db.close()
    require(binding == {'origin': 'http://localhost:19103', 'rpId': 'localhost', 'owner': 'owner'},
            'R3_UNEXPECTED_OWNER_BINDING')
    require({p.name for p in root.iterdir()} == FILES and
            before == {name: digest(root / name) for name in FILES}, 'R3_STATE_CHANGED_DURING_PROBE')
    return {'uid': uid, 'gid': gid, 'integrity': 'ok for all three databases',
            'counts': counts, 'empty': all(value == 0 for value in counts.values()),
            'stableRead': True, 'ownerOrigin': binding['origin'], 'rpId': binding['rpId']}

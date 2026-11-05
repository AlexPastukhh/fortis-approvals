"""Verify the protected Windows r3 backup through a read-only bind mount."""
import hashlib
import json
from pathlib import Path
import sqlite3

FILES = {'.fortis-r7-unified-v1', 'approvals.sqlite', 'owner.sqlite', 'sonar-receipts.sqlite'}
DBS = ('approvals.sqlite', 'owner.sqlite', 'sonar-receipts.sqlite')


def require(condition, error):
    if not condition:
        raise RuntimeError(error)


def logical_hash(db):
    digest = hashlib.sha256()
    for line in db.iterdump():
        digest.update(line.encode('utf-8') + b'\n')
    return digest.hexdigest()


def verify(root):
    root = Path(root)
    raw = (root / 'manifest.json').read_bytes()
    require(hashlib.sha256(raw).hexdigest() == (root / 'manifest.sha256').read_text().split()[0],
            'R3_BACKUP_MANIFEST_HASH_MISMATCH')
    manifest = json.loads(raw)
    require(manifest['format'] == 'fortis-r3-locked-snapshot-v1' and
            manifest['containerId'] == 'd35f999783872ed11225b52fffee534f93777dcd757b326044aa2521dc7bd1f3' and
            manifest['imageId'] == 'sha256:a2fd23c3def0609ed254cd796f40fb51cc4a5a103f0486bb0052d44d76b23267',
            'R3_BACKUP_PROVENANCE_MISMATCH')
    require(set(manifest['sha256']) == FILES, 'R3_BACKUP_FILE_SET_MISMATCH')
    require({p.name for p in root.iterdir()} == FILES | {'manifest.json', 'manifest.sha256', 'snapshot.zip'},
            'R3_BACKUP_UNEXPECTED_FILES')
    for name in FILES:
        path = root / name
        require(not path.is_symlink() and path.is_file() and
                hashlib.sha256(path.read_bytes()).hexdigest() == manifest['sha256'][name],
                'R3_BACKUP_FILE_HASH_MISMATCH:' + name)
    require((root / '.fortis-r7-unified-v1').read_bytes() == b'fortis-r7-unified-v1\n', 'R3_BACKUP_MARKER_INVALID')
    connections = {}
    try:
        for name in DBS:
            db = sqlite3.connect((root / name).absolute().as_uri() + '?mode=ro&immutable=1', uri=True)
            connections[name] = db
            require(db.execute('PRAGMA integrity_check').fetchall() == [('ok',)], 'R3_BACKUP_INTEGRITY_FAILED')
            require(logical_hash(db) == manifest['logicalSha256'][name], 'R3_BACKUP_LOGICAL_HASH_MISMATCH')
        a, o, r = (connections[n] for n in DBS)
        binding = dict(o.execute('SELECT setting,value FROM config'))
        observed = {'requestStates': dict(a.execute('SELECT state,COUNT(*) FROM requests GROUP BY state')),
            'requests': a.execute('SELECT COUNT(*) FROM requests').fetchone()[0],
            'events': a.execute('SELECT COUNT(*) FROM events').fetchone()[0],
            'receipts': r.execute('SELECT COUNT(*) FROM receipts').fetchone()[0],
            'credentialsTotal': o.execute('SELECT COUNT(*) FROM credentials').fetchone()[0],
            'credentialsActive': o.execute('SELECT COUNT(*) FROM credentials WHERE active=1').fetchone()[0],
            'invitationsTotal': o.execute('SELECT COUNT(*) FROM invitations').fetchone()[0],
            'ownerOrigin': binding['origin'], 'rpId': binding['rpId']}
        require(binding == {'origin': 'http://localhost:19103', 'rpId': 'localhost', 'owner': 'owner'} and
                observed == manifest['summary'], 'R3_BACKUP_STATE_SUMMARY_MISMATCH')
    finally:
        for db in connections.values():
            db.close()
    return {'verification': 'PASS', 'summary': observed, 'integrity': 'ok for all three databases',
            'manifestSha256': hashlib.sha256(raw).hexdigest(), 'allLogicalContentHashesMatch': True}

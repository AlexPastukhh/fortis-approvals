"""Private SQLite ledger for *inactive* owner-policy drafts.

Deliberately not mounted into Core/ExtensionRuntime or owner HTTP. Proposals
never grant a permission. A separate reviewed WebAuthn + CAS activation path
will be required before any draft can affect execution.
"""
from contextlib import contextmanager
import hashlib
import os
from pathlib import Path
import re
import sqlite3
import stat
import time
import uuid

from ..core import Denied, Stale, canonical, loads_strict


_POLICY = frozenset(('DENY', 'ASK', 'ALLOW'))
_COORD = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z')
_DIGEST = re.compile(r'[a-f0-9]{64}\Z')
_REASON = re.compile(r'[A-Z][A-Z0-9_]{1,79}\Z')
_GENESIS = '0' * 64


def _hex(value):
    if type(value) is not str or not _DIGEST.fullmatch(value):
        raise Denied('DRAFT_SOURCE_DIGEST_INVALID')
    return value


def _coordinates(value):
    if (type(value) is not tuple or len(value) != 4 or
        any(type(x) is not str or not _COORD.fullmatch(x) for x in value)):
        raise Denied('DRAFT_COORDINATES_INVALID')
    return value


def _baseline(rows):
    if type(rows) is not dict or not (1 <= len(rows) <= 10000):
        raise Denied('DRAFT_BASELINE_INVALID')
    for key, value in rows.items():
        _coordinates(key)
        if type(value) is not str or value not in _POLICY:
            raise Denied('DRAFT_BASELINE_INVALID')
    return dict(rows)


def _sha(data):
    return hashlib.sha256(data.encode('utf-8')).hexdigest()


class PolicyDraftLedger:
    """CAS journal of non-active exact-scope draft grants, not an auth source.

    Constructor needs a trusted, complete exact-key baseline and external pins.
    Existing ledgers reject drift in those inputs until a reviewed migration.
    All write methods change only this private SQLite database.
    """
    def __init__(self, path, *, baseline, source_digest, policy_version,
                 credential_generation_digest, clock=None):
        self.path = Path(path)
        self.baseline = _baseline(baseline)
        self.source_digest = _hex(source_digest)
        self.credential_generation_digest = _hex(credential_generation_digest)
        if (type(policy_version) is not str or not 1 <= len(policy_version) <= 512):
            raise Denied('DRAFT_POLICY_VERSION_INVALID')
        self.policy_version = policy_version
        self.clock = clock or (lambda: int(time.time()))
        self.baseline_digest = _sha(canonical([
            [*key, value] for key, value in sorted(self.baseline.items())]))
        self._guard_path()
        with self._db() as db:
            db.execute('BEGIN IMMEDIATE')
            db.execute("""CREATE TABLE IF NOT EXISTS draft_meta(
                id INTEGER PRIMARY KEY CHECK(id=1), schema_version INTEGER NOT NULL,
                source_digest TEXT NOT NULL, policy_version TEXT NOT NULL,
                credential_generation_digest TEXT NOT NULL, baseline_digest TEXT NOT NULL,
                revision INTEGER NOT NULL, audit_hash TEXT NOT NULL)""")
            db.execute("""CREATE TABLE IF NOT EXISTS draft_baseline(
                actor TEXT NOT NULL, provider TEXT NOT NULL, operation TEXT NOT NULL,
                target TEXT NOT NULL, policy TEXT NOT NULL,
                PRIMARY KEY(actor,provider,operation,target))""")
            db.execute("""CREATE TABLE IF NOT EXISTS draft_current(
                actor TEXT NOT NULL, provider TEXT NOT NULL, operation TEXT NOT NULL,
                target TEXT NOT NULL, policy TEXT NOT NULL,
                PRIMARY KEY(actor,provider,operation,target))""")
            db.execute("""CREATE TABLE IF NOT EXISTS draft_events(
                revision INTEGER PRIMARY KEY, request_id TEXT NOT NULL UNIQUE,
                payload TEXT NOT NULL, previous_hash TEXT NOT NULL,
                event_hash TEXT NOT NULL)""")
            row = db.execute('SELECT * FROM draft_meta WHERE id=1').fetchone()
            if row is None:
                if db.execute('SELECT COUNT(*) FROM draft_events').fetchone()[0] or \
                   db.execute('SELECT COUNT(*) FROM draft_baseline').fetchone()[0] or \
                   db.execute('SELECT COUNT(*) FROM draft_current').fetchone()[0]:
                    raise Denied('DRAFT_UNINITIALIZED_NONEMPTY')
                db.executemany('INSERT INTO draft_baseline VALUES(?,?,?,?,?)',
                               [(*key, policy) for key, policy in sorted(self.baseline.items())])
                db.executemany('INSERT INTO draft_current VALUES(?,?,?,?,?)',
                               [(*key, policy) for key, policy in sorted(self.baseline.items())])
                db.execute('INSERT INTO draft_meta VALUES(1,1,?,?,?,?,0,?)',
                           (self.source_digest, self.policy_version,
                            self.credential_generation_digest,self.baseline_digest,_GENESIS))
            self._verify(db)

    def _guard_path(self):
        parent = self.path.parent
        if self.path.name in ('', '.', '..') or not parent.is_dir() or parent.is_symlink():
            raise Denied('DRAFT_PARENT_INVALID')
        if (parent.stat().st_mode & 0o077) != 0:
            raise Denied('DRAFT_PARENT_PERMISSIONS')
        if self.path.is_symlink():
            raise Denied('DRAFT_STORE_SYMLINK')
        if not self.path.exists():
            try:
                fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
                os.close(fd)
            except FileExistsError:
                pass
        info = self.path.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or
            (info.st_mode & 0o077) != 0 or (info.st_mode & 0o600) != 0o600):
            raise Denied('DRAFT_STORE_PERMISSIONS')

    @contextmanager
    def _db(self):
        # Single-file atomic transactions with full fsync and private directory.
        db = sqlite3.connect(self.path, timeout=10, isolation_level=None)
        db.row_factory = sqlite3.Row
        try:
            db.execute('PRAGMA busy_timeout=10000')
            db.execute('PRAGMA synchronous=FULL')
            db.execute('PRAGMA trusted_schema=OFF')
            db.execute('PRAGMA foreign_keys=ON')
            try:
                yield db
                if db.in_transaction:
                    db.execute('COMMIT')
            except BaseException:
                if db.in_transaction:
                    db.execute('ROLLBACK')
                raise
        finally:
            db.close()

    def _verify(self, db):
        row = db.execute('SELECT * FROM draft_meta WHERE id=1').fetchone()
        if (row is None or row['schema_version'] != 1 or
            row['source_digest'] != self.source_digest or
            row['policy_version'] != self.policy_version or
            row['credential_generation_digest'] != self.credential_generation_digest or
            row['baseline_digest'] != self.baseline_digest):
            raise Denied('DRAFT_BINDING_CHANGED')
        baseline_rows = db.execute('SELECT * FROM draft_baseline').fetchall()
        base = {(r['actor'],r['provider'],r['operation'],r['target']): r['policy']
                for r in baseline_rows}
        if base != self.baseline or len(baseline_rows) != len(self.baseline):
            raise Denied('DRAFT_BASELINE_CORRUPT')
        reconstructed = dict(self.baseline)
        head = _GENESIS
        events = db.execute('SELECT * FROM draft_events ORDER BY revision').fetchall()
        for index, event in enumerate(events, start=1):
            try:
                payload = loads_strict(event['payload'])
                coord = _coordinates(tuple(payload['coordinate']))
                valid = (type(payload) is dict and
                    set(payload) == {'revision','requestId','action','coordinate','before','after',
                                     'expectedRevision','reasonCode','at'} and
                    type(payload['revision']) is int and payload['revision'] == index and
                    type(payload['expectedRevision']) is int and payload['expectedRevision'] == index-1 and
                    type(payload['at']) is int and payload['action'] in ('DRAFT_SET','DRAFT_ROLLBACK') and
                    type(payload['requestId']) is str and
                    str(uuid.UUID(payload['requestId'])) == payload['requestId'] and
                    payload['reasonCode'] and type(payload['reasonCode']) is str and
                    _REASON.fullmatch(payload['reasonCode']) and
                    payload['before'] in _POLICY and payload['after'] in _POLICY and
                    payload['before'] != payload['after'] and coord in reconstructed and
                    reconstructed[coord] == payload['before'] and
                    (payload['action'] != 'DRAFT_ROLLBACK' or
                     payload['after'] == self.baseline[coord]) and
                    event['revision'] == index and event['request_id'] == payload['requestId'] and
                    event['payload'] == canonical(payload) and
                    event['previous_hash'] == head and
                    event['event_hash'] == _sha(head+'\n'+event['payload']))
            except (KeyError, TypeError, ValueError, AttributeError, UnicodeError, Denied):
                valid = False
            if not valid:
                raise Denied('DRAFT_AUDIT_INTEGRITY')
            reconstructed[coord] = payload['after']
            head = event['event_hash']
        current_rows = db.execute('SELECT * FROM draft_current').fetchall()
        current = {(r['actor'],r['provider'],r['operation'],r['target']): r['policy']
                   for r in current_rows}
        if (len(current_rows) != len(reconstructed) or current != reconstructed or
            row['revision'] != len(events) or row['audit_hash'] != head):
            raise Denied('DRAFT_PROJECTION_INTEGRITY')
        return row, reconstructed

    def snapshot(self):
        with self._db() as db:
            row, current = self._verify(db)
        return {'schemaVersion': 1, 'kind': 'INACTIVE_POLICY_DRAFT_LEDGER',
                'revision': row['revision'], 'auditHash': row['audit_hash'],
                'baselineDigest': self.baseline_digest, 'sourceDigest': self.source_digest,
                'credentialGenerationDigest': self.credential_generation_digest,
                'policyVersion': self.policy_version,
                'drafts': [{'actor': key[0], 'provider': key[1],
                            'operation': key[2], 'target': key[3],
                            'baselinePolicy': self.baseline[key], 'draftPolicy': current[key]}
                           for key in sorted(current)],
                'canApply': False, 'runtimeIntegration': 'NOT_CONNECTED'}

    def audit_history(self, *, after_revision=0, limit=100):
        """Bounded verified audit read. No raw credentials or free-form notes."""
        if (type(after_revision) is not int or after_revision < 0 or
            type(limit) is not int or not 1 <= limit <= 100):
            raise Denied('DRAFT_AUDIT_PAGE_INVALID')
        with self._db() as db:
            meta, _ = self._verify(db)
            found = db.execute('''SELECT * FROM draft_events
                WHERE revision>? ORDER BY revision LIMIT?''', (after_revision,limit)).fetchall()
            entries = []
            for event in found:
                payload = loads_strict(event['payload'])
                entries.append({**payload,'previousHash':event['previous_hash'],
                                'eventHash':event['event_hash']})
            return {'schemaVersion':1,'kind':'INACTIVE_POLICY_DRAFT_AUDIT',
                    'currentRevision':meta['revision'],'auditHeadHash':meta['audit_hash'],
                    'items':entries,'canApply':False}

    def _transition(self, action, coordinate, *, request_id, expected_revision,
                    expected_policy, desired_policy, expected_source_digest,
                    expected_credential_generation_digest, expected_policy_version,
                    reason_code):
        coordinate = _coordinates(coordinate)
        try:
            if type(request_id) is not str or str(uuid.UUID(request_id)) != request_id:
                raise ValueError('bad uuid')
        except (ValueError, TypeError, AttributeError):
            raise Denied('DRAFT_REQUEST_ID_INVALID') from None
        if type(expected_revision) is not int or expected_revision < 0:
            raise Denied('DRAFT_EXPECTED_REVISION_INVALID')
        if type(expected_policy) is not str or expected_policy not in _POLICY or \
           type(desired_policy) is not str or desired_policy not in _POLICY:
            raise Denied('DRAFT_POLICY_INVALID')
        if (type(reason_code) is not str or not _REASON.fullmatch(reason_code)):
            raise Denied('DRAFT_REASON_CODE_INVALID')
        if (expected_source_digest != self.source_digest or
            expected_credential_generation_digest != self.credential_generation_digest or
            expected_policy_version != self.policy_version):
            raise Stale('DRAFT_EXPECTED_BINDING_STALE')
        if coordinate not in self.baseline:
            raise Denied('DRAFT_UNKNOWN_EXACT_GRANT')
        if action == 'DRAFT_ROLLBACK' and desired_policy != self.baseline[coordinate]:
            raise Denied('DRAFT_ROLLBACK_NOT_BASELINE')
        with self._db() as db:
            db.execute('BEGIN IMMEDIATE')
            row, current = self._verify(db)
            existing = db.execute('SELECT payload FROM draft_events WHERE request_id=?',
                                  (request_id,)).fetchone()
            if existing:
                payload = loads_strict(existing['payload'])
                if (payload['coordinate'] != list(coordinate) or payload['action'] != action or
                    payload['before'] != expected_policy or payload['after'] != desired_policy or
                    payload['expectedRevision'] != expected_revision or
                    payload['reasonCode'] != reason_code):
                    raise Denied('DRAFT_REQUEST_REPLAY_MISMATCH')
                return {'revision':payload['revision'],'recorded':True,'alreadyRecorded':True,
                        'canApply':False,'runtimeIntegration':'NOT_CONNECTED'}
            if row['revision'] != expected_revision:
                raise Stale('DRAFT_REVISION_STALE')
            if current[coordinate] != expected_policy:
                raise Stale('DRAFT_OLD_POLICY_STALE')
            if expected_policy == desired_policy:
                raise Denied('DRAFT_NOOP')
            revision = expected_revision + 1
            at = self.clock()
            if type(at) is not int:
                raise Denied('DRAFT_CLOCK_INVALID')
            payload = {'revision':revision,'requestId':request_id,'action':action,
                'coordinate':list(coordinate),'before':expected_policy,'after':desired_policy,
                'expectedRevision':expected_revision,'reasonCode':reason_code,'at':at}
            serialized = canonical(payload)
            h = _sha(row['audit_hash']+'\n'+serialized)
            db.execute('INSERT INTO draft_events VALUES(?,?,?,?,?)',
                       (revision,request_id,serialized,row['audit_hash'],h))
            db.execute("""UPDATE draft_current SET policy=? WHERE actor=? AND provider=?
                AND operation=? AND target=?""",(desired_policy,*coordinate))
            if db.execute('SELECT changes()').fetchone()[0] != 1:
                raise Denied('DRAFT_ROW_LOST')
            db.execute('UPDATE draft_meta SET revision=?,audit_hash=? WHERE id=1 AND revision=?',
                       (revision,h,expected_revision))
            if db.execute('SELECT changes()').fetchone()[0] != 1:
                raise Stale('DRAFT_REVISION_RACED')
            self._verify(db)
            return {'revision':revision,'recorded':True,'alreadyRecorded':False,
                    'auditHash':h,'canApply':False,'runtimeIntegration':'NOT_CONNECTED'}

    def stage_draft(self, coordinate, *, desired_policy, **pins):
        """Records an *inactive* draft; no owner permission or Core policy effect."""
        return self._transition('DRAFT_SET',coordinate,desired_policy=desired_policy,**pins)

    def rollback_draft(self, coordinate, **pins):
        """CAS rollback of draft back to trusted baseline, *not* runtime policy."""
        coordinate = _coordinates(coordinate)
        return self._transition('DRAFT_ROLLBACK',coordinate,
                                desired_policy=self.baseline.get(coordinate,'DENY'),**pins)

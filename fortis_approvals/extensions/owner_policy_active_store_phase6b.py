"""Phase 6B protected active-policy STORE CANDIDATE, never runtime authority.

Persist an immutable trusted exact baseline and at most one durable PREPARED
change. This module deliberately has NO commit/apply/release method and is not
imported by Core, Owner Portal, machine ingress or the Windows executor.
The PREPARED barrier is durable; a future independent audit/owner proof
protocol must resolve it before any active grant can change.
"""
from contextlib import contextmanager
import hashlib
import os
from pathlib import Path
import re
import sqlite3
import stat
import uuid

from ..core import Denied, Stale, canonical, loads_strict
from .owner_policy_authority_phase6 import ExactPolicyBaseline

_HEX = re.compile(r'[a-f0-9]{64}\Z')
_REASON = re.compile(r'[A-Z][A-Z0-9_]{1,79}\Z')
_GENESIS = '0' * 64
_COORD = ('actor', 'provider', 'operation', 'target')
_FIELDS = frozenset((*_COORD, 'expectedPolicy', 'desiredPolicy'))


def _sha(text):
    return hashlib.sha256(text.encode('utf-8')).hexdigest()


def _digest(value):
    if type(value) is not str or not _HEX.fullmatch(value):
        raise Denied('PHASE6B_TRUSTED_DIGEST_INVALID')
    return value


def _uuid(value):
    try:
        if type(value) is not str or str(uuid.UUID(value)) != value:
            raise ValueError('invalid')
    except (ValueError, TypeError, AttributeError):
        raise Denied('PHASE6B_UUID_INVALID') from None
    return value


class ProtectedActivePolicyStoreCandidate:
    """Trusted-host-only prepared transaction journal, NOT an active overlay.

    Constructor intentionally needs an explicit protected path and an attested
    ExactPolicyBaseline. It never discovers, migrates or activates production.
    """

    def __init__(self, path, *, baseline, source_digest, policy_version,
                 credential_generation_digest):
        if type(baseline) is not ExactPolicyBaseline:
            raise Denied('PHASE6B_EXACT_TRUSTED_BASELINE_REQUIRED')
        if (type(policy_version) is not str or
                not 1 <= len(policy_version) <= 512):
            raise Denied('PHASE6B_VERSION_INVALID')
        self.baseline = baseline
        self.path = Path(path)
        self.source_digest = _digest(source_digest)
        self.credential_generation_digest = _digest(credential_generation_digest)
        self.policy_version = policy_version
        self._guard_path(create=True)
        with self._db() as db:
            db.execute('BEGIN IMMEDIATE')
            db.execute("""CREATE TABLE IF NOT EXISTS active_meta(
                id INTEGER PRIMARY KEY CHECK(id=1),
                schema_version INTEGER NOT NULL, policy_version TEXT NOT NULL,
                source_digest TEXT NOT NULL, credential_digest TEXT NOT NULL,
                baseline_digest TEXT NOT NULL, revision INTEGER NOT NULL,
                gate TEXT NOT NULL, audit_seq INTEGER NOT NULL,
                audit_hash TEXT NOT NULL)""")
            db.execute("""CREATE TABLE IF NOT EXISTS active_rules(
                coordinate TEXT PRIMARY KEY, policy TEXT NOT NULL)""")
            db.execute("""CREATE TABLE IF NOT EXISTS active_events(
                seq INTEGER PRIMARY KEY, request_id TEXT NOT NULL UNIQUE,
                payload TEXT NOT NULL, previous_hash TEXT NOT NULL,
                event_hash TEXT NOT NULL)""")
            db.execute("""CREATE TABLE IF NOT EXISTS active_pending(
                id INTEGER PRIMARY KEY CHECK(id=1), request_id TEXT NOT NULL,
                payload TEXT NOT NULL, event_hash TEXT NOT NULL)""")
            row = db.execute('SELECT * FROM active_meta WHERE id=1').fetchone()
            if row is None:
                for table in ('active_rules', 'active_events', 'active_pending'):
                    if db.execute('SELECT COUNT(*) FROM '+table).fetchone()[0]:
                        raise Denied('PHASE6B_UNINITIALIZED_NONEMPTY')
                db.executemany('INSERT INTO active_rules VALUES(?,?)',
                    [(canonical(list(coord)), rule)
                     for coord, rule in self.baseline.rules.items()])
                db.execute('INSERT INTO active_meta VALUES(1,1,?,?,?,?,0,?,0,?)',
                    (self.policy_version, self.source_digest,
                     self.credential_generation_digest, self.baseline.digest,
                     'READY', _GENESIS))
            self._verify(db)

    def _guard_path(self, *, create=False):
        parent = self.path.parent
        if (not self.path.is_absolute() or self.path.name in ('', '.', '..') or
                not parent.is_dir() or parent.is_symlink()):
            raise Denied('PHASE6B_PROTECTED_PARENT_REQUIRED')
        # Refuse aliases through ancestor symlinks and known shared Repo mounts.
        if (Path(os.path.realpath(parent)) != parent or
                str(parent).startswith(('/workspace/repo/', '/workspace/repos/'))):
            raise Denied('PHASE6B_UNTRUSTED_PROTECTED_PATH')
        info = parent.stat()
        if info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise Denied('PHASE6B_PROTECTED_PARENT_PERMISSIONS')
        if create and not self.path.exists():
            try:
                fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY |
                             os.O_NOFOLLOW, 0o600)
                os.close(fd)
            except FileExistsError:
                pass
        try:
            info = self.path.lstat()
        except FileNotFoundError:
            raise Denied('PHASE6B_PROTECTED_STORE_MISSING') from None
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or
                info.st_nlink != 1 or info.st_mode & 0o077 or
                info.st_mode & 0o600 != 0o600):
            raise Denied('PHASE6B_PROTECTED_STORE_PERMISSIONS')

    @contextmanager
    def _db(self):
        self._guard_path()
        db = sqlite3.connect(self.path, timeout=10, isolation_level=None)
        db.row_factory = sqlite3.Row
        try:
            db.execute('PRAGMA busy_timeout=10000')
            db.execute('PRAGMA journal_mode=DELETE')
            db.execute('PRAGMA synchronous=FULL')
            db.execute('PRAGMA trusted_schema=OFF')
            db.execute('PRAGMA foreign_keys=ON')
            db.execute('PRAGMA secure_delete=ON')
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
        meta = db.execute('SELECT * FROM active_meta WHERE id=1').fetchone()
        if (meta is None or meta['schema_version'] != 1 or
                meta['policy_version'] != self.policy_version or
                meta['source_digest'] != self.source_digest or
                meta['credential_digest'] != self.credential_generation_digest or
                meta['baseline_digest'] != self.baseline.digest or
                meta['revision'] != 0 or meta['gate'] not in ('READY','PREPARED')):
            raise Denied('PHASE6B_BINDING_OR_REVISION_CHANGED')
        actual = db.execute('SELECT coordinate,policy FROM active_rules').fetchall()
        wanted = {canonical(list(k)): v for k,v in self.baseline.rules.items()}
        if (len(actual) != len(wanted) or
                {r['coordinate']:r['policy'] for r in actual} != wanted):
            raise Denied('PHASE6B_ACTIVE_RULES_INTEGRITY')
        events = db.execute('SELECT * FROM active_events ORDER BY seq').fetchall()
        pending = db.execute('SELECT * FROM active_pending').fetchall()
        head = _GENESIS
        for index, event in enumerate(events, start=1):
            try:
                p = loads_strict(event['payload'])
                valid = (index == 1 and type(p) is dict and
                    set(p) == {'kind','requestId','change','expectedRevision',
                               'expectedAuditHash','baselineDigest',
                               'sourceDigest','credentialGenerationDigest',
                               'policyVersion','reasonCode'} and
                    p['kind'] == 'PHASE6B_PREPARED_INERT' and
                    p['expectedRevision'] == 0 and
                    p['expectedAuditHash'] == _GENESIS and
                    p['baselineDigest'] == self.baseline.digest and
                    p['sourceDigest'] == self.source_digest and
                    p['credentialGenerationDigest'] == self.credential_generation_digest and
                    p['policyVersion'] == self.policy_version and
                    type(p['reasonCode']) is str and _REASON.fullmatch(p['reasonCode']) and
                    type(p['change']) is dict and set(p['change']) == _FIELDS and
                    self.baseline.preview(p['change'])['canApply'] is False and
                    _uuid(p['requestId']) == event['request_id'] and
                    event['seq'] == index and event['payload'] == canonical(p) and
                    event['previous_hash'] == head and
                    event['event_hash'] == _sha(head+'\n'+event['payload']))
            except (Denied, ValueError, KeyError, TypeError, AttributeError):
                valid = False
            if not valid:
                raise Denied('PHASE6B_AUDIT_INTEGRITY')
            head = event['event_hash']
        if (meta['audit_seq'] != len(events) or meta['audit_hash'] != head or
                (meta['gate']=='READY' and (pending or events)) or
                (meta['gate']=='PREPARED' and
                 (len(pending)!=1 or len(events)!=1 or
                  pending[0]['request_id'] != events[0]['request_id'] or
                  pending[0]['payload'] != events[0]['payload'] or
                  pending[0]['event_hash'] != events[0]['event_hash']))):
            raise Denied('PHASE6B_BARRIER_INTEGRITY')
        return meta, pending[0] if pending else None

    def snapshot(self):
        """Verified inactive readback. No result grants activation authority."""
        with self._db() as db:
            meta, pending = self._verify(db)
            return {'kind':'PHASE6B_ACTIVE_STORE_CANDIDATE',
                    'revision':meta['revision'], 'gate':meta['gate'],
                    'auditSequence':meta['audit_seq'], 'auditHeadHash':meta['audit_hash'],
                    'baselineDigest':self.baseline.digest,
                    'policyVersion':self.policy_version,
                    'pendingRequestId':pending['request_id'] if pending else None,
                    'canApply':False, 'runtimeIntegration':'NOT_CONNECTED',
                    'externalAnchorVerified':False}

    def prepare_change(self, change, *, request_id, expected_revision,
                       expected_audit_hash, expected_source_digest,
                       expected_credential_generation_digest,
                       expected_policy_version, reason_code):
        """One durable PREPARED barrier. No commit, active rule update or grant."""
        _uuid(request_id)
        if type(expected_revision) is not int or expected_revision != 0:
            raise Stale('PHASE6B_REVISION_STALE')
        if (type(reason_code) is not str or
                _REASON.fullmatch(reason_code) is None):
            raise Denied('PHASE6B_REASON_INVALID')
        if (expected_source_digest != self.source_digest or
                expected_credential_generation_digest != self.credential_generation_digest or
                expected_policy_version != self.policy_version or
                expected_audit_hash != _GENESIS):
            raise Stale('PHASE6B_TRUSTED_PINS_STALE')
        self.baseline.preview(change)
        payload = {'kind':'PHASE6B_PREPARED_INERT', 'requestId':request_id,
                   'change':change, 'expectedRevision':expected_revision,
                   'expectedAuditHash':expected_audit_hash,
                   'baselineDigest':self.baseline.digest,
                   'sourceDigest':self.source_digest,
                   'credentialGenerationDigest':self.credential_generation_digest,
                   'policyVersion':self.policy_version,'reasonCode':reason_code}
        serialized = canonical(payload)
        head = _sha(_GENESIS+'\n'+serialized)
        with self._db() as db:
            db.execute('BEGIN IMMEDIATE')
            meta, pending = self._verify(db)
            if meta['gate'] == 'PREPARED':
                if pending['request_id'] != request_id or pending['payload'] != serialized:
                    raise Stale('PHASE6B_PREPARED_BARRIER_BLOCKS')
                return {'prepared':True, 'alreadyPrepared':True,
                        'prepareHash':pending['event_hash'], 'canApply':False}
            if meta['revision'] != expected_revision or meta['audit_hash'] != expected_audit_hash:
                raise Stale('PHASE6B_CAS_STALE')
            db.execute('INSERT INTO active_events VALUES(1,?,?,?,?)',
                       (request_id,serialized,_GENESIS,head))
            db.execute('INSERT INTO active_pending VALUES(1,?,?,?)',
                       (request_id,serialized,head))
            db.execute("UPDATE active_meta SET gate='PREPARED',audit_seq=1,audit_hash=? "
                       "WHERE id=1 AND revision=0 AND gate='READY'", (head,))
            if db.execute('SELECT changes()').fetchone()[0] != 1:
                raise Stale('PHASE6B_CAS_RACED')
            self._verify(db)
        return {'prepared':True, 'alreadyPrepared':False,
                'prepareHash':head, 'canApply':False}

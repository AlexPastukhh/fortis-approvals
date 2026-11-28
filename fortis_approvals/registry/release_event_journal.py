"""Registry schema 4 local release-event substrate, no admitted runtime.

Explicit additive migration on an isolated verified clone. V3 prefix stays
immutable, including original receipt bytes. This is not the transition
merge accounting, domain eligibility, controller observation verifier,
Gateway authorization or a protected deployment hold. No public routes.
"""
from contextlib import contextmanager
from pathlib import Path

from ..core import Conflict, Denied, Stale, canonical, loads_strict
from ..integrations.registry_contracts import semantic_contract as sc
from ..integrations.registry_contracts.transition_contract import validate_registry_witness
from .functional_v1_journal import FunctionalV1CandidateJournal, _SCHEMA as _V3
from .state_journal import _CommitUncertain
from . import source_event_journal as sources
from .transition_preservation import prefix_in_transaction, compare_legacy_prefix

_MAX_EVENTS = 512
_MAX_BYTES = 8_000_000
_MAX_EVENT_BYTES = 16384
_SCHEMA = (
    """CREATE TABLE release_meta(id INTEGER PRIMARY KEY CHECK(id=1),
        legacy_witness TEXT NOT NULL, transition_digest TEXT NOT NULL)""",
    """CREATE TABLE release_events(revision INTEGER PRIMARY KEY CHECK(revision>=1),
        operation_id TEXT UNIQUE NOT NULL, subject_digest TEXT NOT NULL,
        target_revision INTEGER NOT NULL CHECK(target_revision>=1),
        request TEXT NOT NULL, fingerprint TEXT NOT NULL,
        recorded_at INTEGER NOT NULL, previous_digest TEXT NOT NULL,
        event_digest TEXT UNIQUE NOT NULL, receipt TEXT NOT NULL,
        UNIQUE(subject_digest,target_revision))""",
    sources.SCHEMA,
)
_KINDS = {
    'RELEASE_ATTEMPT_STARTED': 'begin_release',
    'OWNER_RESULT_RECORDED': 'report_release_result',
}


def _request(value, repo):
    fields = ('operationId', 'kind', 'actor', 'assertionSource', 'parentRequestId', 'params')
    sc.need(type(value) is dict and set(value) in (set(fields), set(fields)|{'profileDigest'}))
    if 'profileDigest' in value:
        sc.hex_id(value['profileDigest'], 64)
    sc.uuid_id(value['operationId'])
    if value['parentRequestId'] is not None:
        sc.uuid_id(value['parentRequestId'])
    sc.need(type(value['kind']) is str and value['kind'] in (*_KINDS, 'TECHNICAL_OBSERVATION_ACCEPTED', 'RELEASE_HOLD_CLOSED'),
            'REGISTRY_RELEASE_EVENT_KIND')
    actor = value['actor']
    sc.need(type(actor) is str and 0 < len(actor) <= 128 and
            all(c.isascii() and (c.isalnum() or c in '._:-') for c in actor),
            'REGISTRY_RELEASE_ACTOR_INVALID')
    if value['kind'] in _KINDS:
        sc.need(value['assertionSource'] in ('OWNER_DIRECT', 'OWNER_TRANSCRIBED'),
                'REGISTRY_RELEASE_ASSERTION_SOURCE')
        params = sc.validate_params(_KINDS[value['kind']], value['params'])
    else:
        sc.need(value['assertionSource'] == 'PROTECTED_CONTROLLER'
                and 'profileDigest' in value and value['parentRequestId'] is None,
                'REGISTRY_PROTECTED_EVENT_REQUIRED')
        params = protected_params(value['kind'], value['params'])
    sc.need(params['subject']['repository'] == repo, 'REGISTRY_RELEASE_SCOPE')
    clean = {**value, 'params': params}
    sc.need(len(canonical(clean).encode('utf-8')) <= _MAX_EVENT_BYTES,
            'REGISTRY_RELEASE_EVENT_SIZE')
    return loads_strict(canonical(clean))


def protected_params(kind, params):
    """Closed evidence references, not verification of the evidence."""
    fields=('subject','source','expected','attemptId','controllerReceiptDigest',
            'readbackDigest','observedAt')
    if kind=='TECHNICAL_OBSERVATION_ACCEPTED' and 'coveredRecordIds' in params:
        fields+=('coveredRecordIds',)
        ids=params['coveredRecordIds']
        sc.need(type(ids) is list and len(ids)<=64)
        for ident in ids:
            sc.hex_id(ident,64)
        sc.need(ids==sorted(set(ids)))
    sc.fields(params,fields)
    sc.subject(params['subject'])
    sc.source(params['source'])
    sc.guard(params['expected'])
    sc.revision(params['observedAt'])
    if params['attemptId'] is not None:
        sc.uuid_id(params['attemptId'])
    sc.need(kind != 'RELEASE_HOLD_CLOSED' or params['attemptId'] is not None)
    for k in ('controllerReceiptDigest', 'readbackDigest'):
        sc.hex_id(params[k], 64)
    sc.need(params['controllerReceiptDigest'] != params['readbackDigest'])
    return loads_strict(canonical(params))


class ReleaseEventJournal(FunctionalV1CandidateJournal):
    """Same private DB/instance; legacy replay plus immutable release events.

    This class is not registered at any ingress. The trusted future domain
    writer must validate enrolled target/catalog, source, CAS, hold eligibility
    and provenance. Local event types do not prove that authority or an actual
    technical install. The source cursor remains frozen until W5 transition.
    """
    def __init__(self, path, *, instance_id, scope, expected_legacy, transition_digest,
                 immutable_snapshot=False):
        sc.need(type(immutable_snapshot) is bool,'REGISTRY_CORRECTIVE_PREVIEW_PIN_REQUIRED')
        self._immutable_snapshot = immutable_snapshot
        self.expected_legacy = validate_registry_witness(expected_legacy)
        sc.hex_id(transition_digest, 64)
        self.transition_digest = transition_digest
        super().__init__(path, instance_id=instance_id, scope=scope,
                         plan_reader=lambda _: (_ for _ in ()).throw(
                             Denied('REGISTRY_LEGACY_WRITES_FROZEN')))
        sc.need(self.expected_legacy['instanceId'] == instance_id and
                self.expected_legacy['scopeDigest'] == self.initial['scopeDigest'],
                'REGISTRY_RELEASE_LEGACY_SCOPE')

    def _frozen_file_identity(self):
        from ..r7_registry_reader_mount import _check_owner_readonly_mount
        _check_owner_readonly_mount(self.path.parent)
        self._paths()
        sc.need(not any(p.exists() or p.is_symlink() for p in
                    (Path(str(self.path)+suffix) for suffix in ('-wal','-shm','-journal'))),
                'REGISTRY_CORRECTIVE_PREVIEW_UNCHECKPOINTED')
        # immutable SQLite ignores the WAL. Only accept the independently
        # stopped, checkpointed database (no sidecars), with the WAL header.
        with self.path.open('rb') as source:
            header=source.read(100)
        sc.need(len(header)==100 and header[:16]==b'SQLite format 3\x00'
                and header[18:20]==b'\x02\x02',
                'REGISTRY_CORRECTIVE_PREVIEW_WAL_HEADER')
        st=self.path.stat()
        return (st.st_dev,st.st_ino,st.st_size,st.st_mtime_ns,st.st_ctime_ns)

    @contextmanager
    def _read_only_db(self):
        if not self._immutable_snapshot:
            with super()._read_only_db() as db:
                yield db
            return
        before=self._frozen_file_identity()
        with super()._read_only_db(immutable_snapshot=True) as db:
            yield db
        sc.need(self._frozen_file_identity()==before,'REGISTRY_CORRECTIVE_PREVIEW_STATE_CHANGED')

    def _db(self, initialize=False):
        sc.need(not self._immutable_snapshot,'REGISTRY_CORRECTIVE_PREVIEW_READ_ONLY')
        return super()._db(initialize=initialize)

    @classmethod
    def initialize(cls, *args, **kwargs):
        raise Denied('REGISTRY_RELEASE_EXPLICIT_MIGRATION_REQUIRED')

    @classmethod
    def migrate_clone(cls, legacy, *, expected_legacy, transition_digest, stage=None):
        """Migrate an inactive clone and optionally stage its verified first event atomically."""
        sc.need(type(legacy) is FunctionalV1CandidateJournal,
                'REGISTRY_RELEASE_LEGACY_REQUIRED')
        obj = cls(legacy.path, instance_id=legacy.instance_id, scope=legacy.scope,
                  expected_legacy=expected_legacy, transition_digest=transition_digest)
        with legacy._db() as db:
            compare_legacy_prefix(obj.expected_legacy, prefix_in_transaction(legacy, db))
            for sql in _SCHEMA:
                db.execute(sql)
            db.execute('INSERT INTO release_meta VALUES(1,?,?)',
                       (canonical(obj.expected_legacy), transition_digest))
            db.execute('PRAGMA user_version=4')
            obj._verify_schema(db)
            if stage is not None:
                stage(obj,db)
            obj._replay(db)
        return obj

    def _verify_schema(self, db):
        actual = db.execute(
            "SELECT sql FROM sqlite_master WHERE name NOT LIKE "
            "'sqlite_autoindex_%' ORDER BY name").fetchall()
        sc.need(actual == sorted((sql,) for sql in (*_V3[:-1], *_SCHEMA))
                and db.execute('PRAGMA user_version').fetchone() == (4,)
                and db.execute('SELECT * FROM meta LIMIT 2').fetchall() ==
                [(self.instance_id, canonical(self.scope))]
                and db.execute('SELECT * FROM release_meta LIMIT 2').fetchall() ==
                [(1, canonical(self.expected_legacy), self.transition_digest)],
                'REGISTRY_RELEASE_SCHEMA_OR_PIN_MISMATCH')

    def append_range(self, **kwargs):
        raise Denied('REGISTRY_LEGACY_WRITES_FROZEN')

    def _state(self, db):
        # Inherited legacy candidate reads return original v3 receipts only.
        # Full release chain validation also required on every v4 read.
        old = super()._state(db)
        _,seen,_=self._release_state(db, old)
        sources.replay(self,db,seen)
        return old

    def _replay(self, db):
        old = super()._state(db)
        state=self._release_state(db, old)
        sources.replay(self,db,state[1])
        return state

    def _release_state(self, db, old):
        # Avoid recursive _state() in prefix helper: replay legacy with
        # exact original implementation, then compute exact original witness.
        observed = prefix_in_transaction(self, db, replay=old)
        compare_legacy_prefix(self.expected_legacy, observed)
        sc.need(db.execute('SELECT COUNT(*) FROM release_events').fetchone()[0] <= _MAX_EVENTS
                and db.execute('SELECT COALESCE(SUM(length(CAST(request AS BLOB)) + '
                               'length(CAST(receipt AS BLOB))),0) FROM release_events'
                               ).fetchone()[0] <= _MAX_BYTES,
                'REGISTRY_RELEASE_CAPACITY')
        previous = sc.digest(['registry-v4-release-genesis', self.instance_id,
                              self.expected_legacy, self.transition_digest])
        seen = {}
        targets = {}
        for row in db.execute('SELECT * FROM release_events ORDER BY revision'):
            rev, op, key, target_rev, raw, fp, at, prev, event, receipt = row
            try:
                req = _request(loads_strict(raw), self.scope['repository'])
            except (TypeError, ValueError, UnicodeError, RecursionError, KeyError) as exc:
                if isinstance(exc, Denied):
                    raise
                raise Denied('REGISTRY_RELEASE_CHAIN') from None
            calculated_key = sc.digest(list(sc.subject_key(req['params']['subject'])))
            prior_target = targets.get(key, 0)
            sc.revision(at)
            sc.need(rev == len(seen)+1 and op == req['operationId']
                    and op not in old[2] and op not in seen
                    and canonical(req) == raw and sc.digest(req) == fp
                    and key == calculated_key and target_rev == prior_target+1
                    and req['params']['expected']['targetRevision'] == prior_target
                    and prev == previous, 'REGISTRY_RELEASE_CHAIN')
            computed = sc.digest([previous, rev, target_rev, key, fp, at])
            result = self._receipt(req, rev, target_rev, computed, at)
            sc.need(event == computed and canonical(result) == receipt,
                    'REGISTRY_RELEASE_CHAIN')
            previous = computed
            targets[key] = target_rev
            seen[op] = (req, result)
        return previous, seen, targets

    def _receipt(self, req, rev, target_rev, event, at):
        return {'schemaVersion': 4, 'instanceId': self.instance_id,
                'operationId': req['operationId'], 'eventKind': req['kind'],
                'subject': req['params']['subject'], 'snapshotRevision': rev,
                'targetRevision': target_rev, 'eventDigest': event,
                'requestDigest': sc.digest(req), 'recordedAt': at,
                'integrityModel': 'LOCAL_EVENT_CHAIN_ONLY',
                'technicalInstallationVerified': False}

    def append_event(self, request, *, recorded_at):
        """Local journal write; trusted domain validation still required.

        Per-target CAS; identical UUID/payload returns the original receipt
        even after later events. No implicit retry of uncertain commit.
        """
        req = _request(request, self.scope['repository'])
        sc.need(req['kind'] in _KINDS and 'profileDigest' not in req, 'REGISTRY_DOMAIN_WRITER_REQUIRED')
        sc.revision(recorded_at)
        ident = req['operationId']
        try:
            with self._db() as db:
                receipt = self._append_in_transaction(db, req, recorded_at)
        except _CommitUncertain:
            return {'result': 'UNKNOWN_OUTCOME', 'operationId': ident}
        try:
            return self.release_operation(ident)
        except Denied:
            return {'result': 'UNKNOWN_OUTCOME', 'operationId': ident}

    def _append_in_transaction(self, db, req, recorded_at):
        """Internal shared writer; callers own the existing write transaction."""
        ident = req['operationId']
        key = sc.digest(list(sc.subject_key(req['params']['subject'])))
        previous, seen, targets = self._replay(db)
        if ident in seen:
            old, receipt = seen[ident]
            if old != req:
                raise Conflict('REGISTRY_RELEASE_OPERATION_CONFLICT')
            return receipt
        sc.need(db.execute('SELECT 1 FROM operations WHERE operation_id=?',
                           (ident,)).fetchone() is None,
                'REGISTRY_RELEASE_LEGACY_OPERATION_CONFLICT')
        target_rev = targets.get(key, 0)
        if target_rev != req['params']['expected']['targetRevision']:
            raise Stale('REGISTRY_RELEASE_TARGET_STALE')
        sc.need(len(seen) < _MAX_EVENTS, 'REGISTRY_RELEASE_CAPACITY')
        rev = len(seen)+1
        fp = sc.digest(req)
        event = sc.digest([previous, rev, target_rev+1, key, fp, recorded_at])
        receipt = self._receipt(req, rev, target_rev+1, event, recorded_at)
        db.execute('INSERT INTO release_events VALUES(?,?,?,?,?,?,?,?,?,?)',
                   (rev, ident, key, target_rev+1, canonical(req), fp,
                    recorded_at, previous, event, canonical(receipt)))
        self._replay(db)
        return receipt

    def release_operation(self, operation_id):
        sc.uuid_id(operation_id)
        with self._read_only_db() as db:
            _, seen, _ = self._replay(db)
            return seen[operation_id][1] if operation_id in seen else None

    def release_checkpoint(self):
        with self._read_only_db() as db:
            head, seen, targets = self._replay(db)
            return {'schemaVersion': 4, 'instanceId': self.instance_id,
                    'legacy': self.expected_legacy.copy(), 'snapshotRevision': len(seen),
                    'eventDigest': head, 'targetCount': len(targets),
                    'remainingEvents': _MAX_EVENTS-len(seen),
                    'sourceTransitionPending': not sources.replay(self,db,seen)['sourceRevision']}

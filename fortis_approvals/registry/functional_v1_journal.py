"""Functional P5 V1 *source candidate*: local-only persistent desired history.

This explicitly versioned schema 3 is NOT an adaptation of the hardened
checkpoint-backed schema 2 and never substitutes a local digest for an
independently protected checkpoint. It makes no claim of collector authenticity,
owner authorization, live Registry, release execution, installed versions or
adversarial rollback protection. No live Gateway method is wired here.
"""
from pathlib import Path
import os
import re
import sqlite3
import uuid
from types import MappingProxyType

from ..core import Conflict, Denied, Stale
from .state_journal import (
    COLLECTOR, REPOSITORY, PLANNER, _checkpoint, _decode, _hash, _hex, _need,
    _plan, _private, _raw, _request, _scope, _uuid, _CommitUncertain,
)
from .state_journal_v2 import (
    RegistryStateJournalV2, MAX_REVISIONS,
    _SCHEMA as _SCHEMA_V2,
)

# A genuinely distinct on-disk contract: no schema-v2 auto-migration or
# silent removal of its independent checkpoint requirement.
_SCHEMA = (*_SCHEMA_V2[:-1], 'PRAGMA user_version=3')


def _result(receipt):
    return {
        'result': 'LOCAL_DESIRED_CANDIDATE_COMMITTED',
        'receipt': receipt,
        'integrityModel': 'LOCAL_EVENT_CHAIN_ONLY',
        'evidenceVerified': False, 'admissionAllowed': False,
        'deploymentAllowed': False,
    }


class FunctionalV1CandidateJournal(RegistryStateJournalV2):
    """Offline local CAS+event chain for candidate desired records only.

    Deliberately no anchor_reader, owner principal, Gateway credentials,
    owner-report event API or outside authority. The source plan callback
    is a test seam and MUST be replaced by authenticated original evidence
    admission in an owner-reviewed functional runtime.
    """

    def __init__(self, path, *, instance_id, scope, plan_reader):
        self.path = Path(path)
        self.instance_id = instance_id
        _need(_uuid(instance_id), 'REGISTRY_LOCAL_INSTANCE_INVALID')
        self.scope = _scope(scope)
        _need(callable(plan_reader), 'REGISTRY_LOCAL_READER_REQUIRED')
        self.plan_reader = plan_reader
        self.initial = _checkpoint(
            instance_id, self.scope, 0,
            _hash(['registry-local-v1-genesis', instance_id, self.scope]),
        )
        self._paths()

    @classmethod
    def initialize(cls, path, *, instance_id, scope, plan_reader):
        path = Path(path)
        _need(path.is_absolute() and path.parent.resolve() == path.parent,
              'REGISTRY_LOCAL_PATH')
        _private(path.parent, True)
        _need(_uuid(instance_id) and callable(plan_reader),
              'REGISTRY_LOCAL_INITIALIZATION_INVALID')
        scope = _scope(scope)
        _need(not path.exists() and not path.is_symlink(),
              'REGISTRY_LOCAL_ALREADY_EXISTS')
        obj = None
        # Preserve the v2 strict no-overwrite/no-symlink/0600 expectations.
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
        os.close(fd)
        obj = cls(path, instance_id=instance_id, scope=scope,
                  plan_reader=plan_reader)
        with obj._db(initialize=True) as db:
            for statement in _SCHEMA:
                db.execute(statement)
            db.execute('INSERT INTO meta VALUES(?,?)',
                       (instance_id, _raw(obj.scope)))
        return obj

    def _verify_schema(self, db):
        actual = db.execute(
            "SELECT sql FROM sqlite_master WHERE name NOT LIKE "
            "'sqlite_autoindex_%' ORDER BY name"
        ).fetchall()
        _need(actual == sorted((sql,) for sql in _SCHEMA[:-1])
              and db.execute('PRAGMA user_version').fetchone() == (3,)
              and db.execute('SELECT * FROM meta LIMIT 2').fetchall() ==
                  [(self.instance_id, _raw(self.scope))],
              'REGISTRY_LOCAL_SCHEMA_MISMATCH')

    def _anchor(self):
        # A local event digest is *not* a checkpoint witness. Parent
        # checkpoint-dependent code must not be accidentally inherited.
        raise Denied('REGISTRY_LOCAL_NO_EXTERNAL_ANCHOR')

    def _event(self, revision, fingerprint, evidence_digest, previous):
        return _hash([
            'registry-local-v1-event', self.instance_id,
            self.initial['scopeDigest'], revision, fingerprint,
            evidence_digest, previous['eventDigest'],
        ])

    def _receipt_v2(self, request, plan, prev, revision, event, links):
        receipt = super()._receipt_v2(
            request, plan, prev, revision, event, links
        )
        receipt['schemaVersion'] = 3
        receipt['integrityModel'] = 'LOCAL_EVENT_CHAIN_ONLY'
        # No external anchor or authenticated original collector.
        return receipt

    def _state(self, db):
        """Replay ALL stored source evidence, not just the latest row."""
        return self._checked(db)

    def append_range(self, *, actor, operation_id, evidence_id,
                     evidence_digest, expected_revision):
        """Locally commit a candidate range under SQLite CAS, not live admission.

        Exact original operation ID is the only supported replay; on an
        ambiguous COMMIT, caller must query operation rather than reissue
        physical side effects. No independent witness is consulted.
        """
        req = _request(actor, operation_id, evidence_id,
                       evidence_digest, expected_revision)
        with self._read_only_db() as db:
            head, cursor, seen, _, previous_collector = self._state(db)
            if operation_id in seen:
                old, receipt = seen[operation_id]
                if old != req:
                    raise Conflict('REGISTRY_LOCAL_OPERATION_CONFLICT')
                return _result(receipt)
            if head['revision'] != expected_revision:
                raise Stale('REGISTRY_LOCAL_REVISION_STALE')
            _need(expected_revision < MAX_REVISIONS, 'REGISTRY_LOCAL_LIMIT')

        # The only source of plans is the injected host callback. It is NOT
        # authenticated by this class, nor are the false candidate flags
        # promoted to proof of deployment or installed state.
        try:
            evidence = _decode(_raw(self.plan_reader(evidence_id)))
        except Denied:
            raise
        except Exception:
            raise Denied('REGISTRY_LOCAL_PLAN_UNAVAILABLE') from None
        observation = _plan(
            evidence, req, self.scope,
            start_sha=cursor if expected_revision else None,
            previous_checkpoint=head if expected_revision else None,
        )
        if previous_collector is not None:
            cp = observation['collectorCheckpoint']
            _need(cp['instanceId'] == previous_collector['instanceId']
                  and cp['revision'] > previous_collector['revision'],
                  'REGISTRY_LOCAL_COLLECTOR_ORDER')
        added = {m['evidenceId'] for m in observation['mergeAudit']}
        merges = {m['mergeSha'] for m in observation['mergeAudit']}
        owners = {m['ownerRequestId'] for m in observation['mergeAudit']}
        numbers = {m['number'] for m in observation['mergeAudit']}
        try:
            with self._db() as db:
                fresh, current, seen, active, last_collector = self._state(db)
                _need(fresh == head and current == cursor
                      and operation_id not in seen,
                      'REGISTRY_LOCAL_CONCURRENT_CHANGE')
                if last_collector is not None:
                    cp = observation['collectorCheckpoint']
                    _need(cp['instanceId'] == last_collector['instanceId']
                          and cp['revision'] > last_collector['revision'],
                          'REGISTRY_LOCAL_COLLECTOR_ORDER')
                _need(not any(
                    (added & {m['evidenceId'] for m in e['plan']['observation']['mergeAudit']}
                     or merges & {m['mergeSha'] for m in e['plan']['observation']['mergeAudit']}
                     or owners & {m['ownerRequestId'] for m in e['plan']['observation']['mergeAudit']}
                     or numbers & {m['number'] for m in e['plan']['observation']['mergeAudit']})
                    for (raw,) in db.execute('SELECT evidence FROM operations')
                    for e in [_decode(raw)]
                ), 'REGISTRY_LOCAL_REPLAYED_MERGE')
                revision = expected_revision + 1
                links = sorted(
                    ({'fromRecordId': active[r['subjectId']],
                      'toRecordId': r['recordId']}
                     for r in observation['recordCandidates']
                     if r['subjectId'] in active),
                    key=lambda link: link['fromRecordId'],
                )
                fingerprint = _hash(req)
                event = self._event(revision, fingerprint, evidence_digest, head)
                receipt = self._receipt_v2(req, evidence['plan'],
                                           head, revision, event, links)
                try:
                    db.execute('INSERT INTO operations VALUES(?,?,?,?,?,?,?,?,?)',
                               (revision, operation_id, _raw(req), fingerprint,
                                _raw(evidence), evidence_digest, _raw(receipt),
                                head['eventDigest'], event))
                    db.executemany('INSERT INTO records VALUES(?,?,?,?)', [
                        (r['recordId'], r['subjectId'], revision, _raw(r))
                        for r in observation['recordCandidates']
                    ])
                    db.executemany(
                        'INSERT INTO supersessions VALUES(?,?,?)', [
                            (link['fromRecordId'], link['toRecordId'], revision)
                            for link in links
                        ],
                    )
                    self._state(db)
                except sqlite3.IntegrityError:
                    raise Denied('REGISTRY_LOCAL_DUPLICATE_OR_CORRUPT') from None
        except _CommitUncertain:
            return {'result': 'UNKNOWN_OUTCOME',
                    'operationId': operation_id,
                    'integrityModel': 'LOCAL_EVENT_CHAIN_ONLY'}

        try:
            return self.operation(actor=actor, operation_id=operation_id)
        except (Denied, Stale):
            return {'result': 'UNKNOWN_OUTCOME',
                    'operationId': operation_id,
                    'integrityModel': 'LOCAL_EVENT_CHAIN_ONLY'}

    def operation(self, *, actor, operation_id):
        _need(actor == PLANNER and _uuid(operation_id),
              'REGISTRY_LOCAL_REQUEST_INVALID')
        with self._read_only_db() as db:
            _, _, seen, _, _ = self._state(db)
            if operation_id in seen:
                return _result(seen[operation_id][1])
            return {'result': 'LOCAL_CANDIDATE_OPERATION_NOT_FOUND',
                    'integrityModel': 'LOCAL_EVENT_CHAIN_ONLY',
                    'evidenceVerified': False, 'admissionAllowed': False}

    def checkpoint(self):
        """Untrusted local head for source composition, never an owner anchor."""
        with self._read_only_db() as db:
            head, cursor, _, _, _ = self._state(db)
            return {'result': 'LOCAL_SOURCE_CANDIDATE_HEAD',
                    'localCheckpoint': head,
                    'candidateCursor': cursor,
                    'integrityModel': 'LOCAL_EVENT_CHAIN_ONLY',
                    'evidenceVerified': False, 'admissionAllowed': False,
                    'deploymentAllowed': False}

    def list_desired_candidates(self, *, limit, cursor=None):
        """Read the current local snapshot, never a live queue claim."""
        _need(type(limit) is int and 1 <= limit <= 100
              and (cursor is None or type(cursor) is str and
                   re.fullmatch(r'[0-9a-f]{64}_[0-9a-f]{64}', cursor)),
              'REGISTRY_LOCAL_PAGE_INVALID')
        with self._read_only_db() as db:
            head, source_sha, _, active, _ = self._state(db)
            ids = sorted(active.values())
            offset = 0
            if cursor is not None:
                last, bound = cursor.split('_', 1)
                _need(last in ids and bound == _hash([
                    'registry-local-v1-page', self.instance_id,
                    head['revision'], head['eventDigest'], last]),
                    'REGISTRY_LOCAL_PAGE_CURSOR_STALE')
                offset = ids.index(last) + 1
            selected = ids[offset:offset+limit]
            items = []
            for record_id in selected:
                row = db.execute(
                    'SELECT payload FROM records WHERE record_id=?',
                    (record_id,)).fetchone()
                _need(row is not None, 'REGISTRY_LOCAL_CORRUPT')
                value = _decode(row[0])
                _need(value['recordId'] == record_id
                      and active.get(value['subjectId']) == record_id
                      and value['actual'] is None
                      and value['evidenceVerified'] is False
                      and value['planningState'] == 'PLANNED_UNVERIFIED',
                      'REGISTRY_LOCAL_CORRUPT')
                items.append({'recordId': record_id,
                              'identity': value['identity'],
                              'requiredActions': value['requiredActions'],
                              'planningState': 'PLANNED_UNVERIFIED',
                              'actual': None, 'evidenceVerified': False})
            last = selected[-1] if offset + len(selected) < len(ids) else None
            next_cursor = (last + '_' + _hash([
                'registry-local-v1-page', self.instance_id,
                head['revision'], head['eventDigest'], last,
            ])) if last is not None else None
            result = {'result': 'LOCAL_DESIRED_CANDIDATE_PAGE',
                      'localRevision': head['revision'],
                      'localEventDigest': head['eventDigest'],
                      'candidateSourceSha': source_sha, 'records': items,
                      'nextCursor': next_cursor,
                      'integrityModel': 'LOCAL_EVENT_CHAIN_ONLY',
                      'evidenceVerified': False, 'admissionAllowed': False,
                      'deploymentVerified': False, 'writeEnabled': False}
            _need(len(_raw(result).encode('utf-8')) <= 8192,
                  'REGISTRY_LOCAL_PAGE_TOO_LARGE')
            return result


# Source-only P5 owner composition. Keep inside the existing explicitly
# noDeploymentPaths Registry module: this does not add a live Gateway route.
class _PinnedOriginalCollector:
    """Bound original persisted collector reader, not a caller batch provider.

    The pin is a HOST-INPUT expected head, *not* authenticated owner approval.
    This rejects arbitrary fake journals and mutable method replacements.
    It does not authenticate the host, its independent checkpoint reader,
    or the original Core/GitHub source from which it gathered the snapshot.
    """

    __slots__ = ('__read', '__expected')

    def __init__(self, journal, expected_checkpoint):
        from ..integrations.github.gateway.collector_snapshot import (
            CollectorSnapshotStore,
        )
        _need(type(journal) is CollectorSnapshotStore
              and getattr(journal.anchored_batch, '__func__', None)
                  is CollectorSnapshotStore.anchored_batch,
              'REGISTRY_SOURCE_ORIGINAL_COLLECTOR_REQUIRED')
        _need(type(expected_checkpoint) is dict
              and set(expected_checkpoint) == {
                  'schemaVersion', 'instanceId', 'revision', 'eventDigest'}
              and type(expected_checkpoint['schemaVersion']) is int
              and expected_checkpoint['schemaVersion'] == 1
              and expected_checkpoint['instanceId'] == journal.instance_id
              and type(expected_checkpoint['revision']) is int
              and 0 < expected_checkpoint['revision'] <= 128
              and _hex(expected_checkpoint['eventDigest'], 64),
              'REGISTRY_SOURCE_COLLECTOR_PIN_INVALID')
        self.__read = journal.anchored_batch
        self.__expected = _decode(_raw(expected_checkpoint))
        # Full original event/history validation and comparison with the
        # independently injected collector anchor happen inside this method.
        self.anchored_batch([])

    def anchored_batch(self, evidence_ids):
        result = self.__read(evidence_ids)
        _need(type(result) is dict and set(result) == {
            'checkpoint', 'entries'}
              and result['checkpoint'] == self.__expected
              and type(result['entries']) is list
              and len(result['entries']) == len(evidence_ids),
              'REGISTRY_SOURCE_COLLECTOR_CHANGED')
        return result

    def head(self):
        return self.anchored_batch([])['checkpoint']


class OfflineSourceRangeComposition:
    """Explicitly bound source-plan ingestion without caller-supplied plan DTO.

    A future owner-reviewed runtime must authenticate its original evidence
    readers, secure the single-writer filesystem and authorize exact Gateway
    operations. None of those trust assumptions are implemented here.
    """

    def __init__(self, *, path, instance_id, scope, adapter, journal,
                 expected_collector_checkpoint, validator,
                 baseline_reader, expected_baseline_digest, policy_reader,
                 expected_policy_digest, binding_reader):
        self.path = path
        self.instance_id = instance_id
        self.scope = _scope(scope)
        _need(_uuid(instance_id)
              and _hex(expected_baseline_digest, 64)
              and _hex(expected_policy_digest, 64)
              and self.scope['baselineDigest'] == expected_baseline_digest
              and self.scope['policyReferenceDigest'] == expected_policy_digest
              and callable(baseline_reader) and callable(policy_reader)
              and callable(binding_reader), 'REGISTRY_SOURCE_COMPOSITION_INVALID')
        self._collector = _PinnedOriginalCollector(
            journal, expected_collector_checkpoint)
        self.sources = MappingProxyType({
            'adapter': adapter, 'journal': self._collector, 'validator': validator,
            'baseline_reader': baseline_reader,
            'expected_baseline_digest': expected_baseline_digest,
            'policy_reader': policy_reader,
            'expected_policy_digest': expected_policy_digest,
            'binding_reader': binding_reader,
        })

    def _store(self, plan_reader=None):
        def no_plan(_):
            raise Denied('REGISTRY_SOURCE_PLAN_UNAVAILABLE')
        return FunctionalV1CandidateJournal(
            self.path, instance_id=self.instance_id, scope=self.scope,
            plan_reader=plan_reader if plan_reader is not None else no_plan,
        )

    def operation(self, *, operation_id):
        """Recover exact local result after a lost ACK; no source recapture."""
        _need(_uuid(operation_id), 'REGISTRY_SOURCE_REQUEST_INVALID')
        return self._store().operation(actor=PLANNER, operation_id=operation_id)

    def candidate_page(self, *, limit, cursor=None):
        """Read inactive desired candidates; never a live empty queue claim."""
        return self._store().list_desired_candidates(limit=limit, cursor=cursor)

    def compose_and_append(self, *, operation_id, expected_revision,
                           selected_main_sha, evidence_ids):
        """Plan from pinned source readers, then perform one local CAS commit.

        The caller chooses only an original operation UUID, expected revision,
        observed selected-main SHA and *references* to original evidence.
        Complete source-plan content, derived desired and digest are recomputed
        by the existing P5 Git planner and cannot be supplied by the caller.
        This is intentionally NOT exposed as registry.ingest_merged.
        """
        _need(_uuid(operation_id)
              and type(expected_revision) is int
              and 0 <= expected_revision <= 2**63 - 1
              and _hex(selected_main_sha, 40)
              and type(evidence_ids) is list and len(evidence_ids) <= 64
              and all(_uuid(e) for e in evidence_ids)
              and len(set(evidence_ids)) == len(evidence_ids),
              'REGISTRY_SOURCE_REQUEST_INVALID')
        # Pin the original persisted collector checkpoint before any Git or
        # Core reads, not a caller-built "anchored" receipt structure.
        collector_head = self._collector.head()
        store = self._store()
        before = store.checkpoint()
        _need(before['integrityModel'] == 'LOCAL_EVENT_CHAIN_ONLY'
              and before['evidenceVerified'] is False
              and before['admissionAllowed'] is False
              and before['deploymentAllowed'] is False,
              'REGISTRY_SOURCE_HEAD_UNSAFE')
        if before['localCheckpoint']['revision'] != expected_revision:
            raise Stale('REGISTRY_SOURCE_REVISION_STALE')

        # Import only inside this offline composition, never into a deployed
        # Registry/Gateway route. Original journal/adapter credentials are not
        # established merely by having callable source-fixture objects.
        from ..integrations.github.gateway import admission_plan
        kwargs = {
            **self.sources,
            'selected_main_sha': selected_main_sha,
            'evidence_ids': list(evidence_ids),
        }
        if expected_revision == 0:
            plan = admission_plan.observe_initial_plan(**kwargs)
        else:
            plan = admission_plan.observe_suffix_plan(
                cursor_reader=store.checkpoint, **kwargs)
        _need(type(plan) is dict and plan.get('result') in (
              'INITIAL_RANGE_PLAN_CANDIDATE','SUFFIX_RANGE_PLAN_CANDIDATE')
              and plan.get('evidenceVerified') is False
              and plan.get('admissionAllowed') is False
              and plan.get('deploymentAllowed') is False,
              'REGISTRY_SOURCE_PLAN_UNSAFE')
        # Exact evidence ID is a stable per-operation local reference, not a
        # collector credential or a claimed authentic original receipt.
        local_evidence_id = str(uuid.uuid5(
            uuid.NAMESPACE_URL,
            'fortis-local-source-v1:' + self.instance_id + ':' + operation_id))
        payload = _decode(_raw({
            'schemaVersion': 1, 'issuer': COLLECTOR,
            # Pinned enrollment scope, never a user-selected repository.
            'repository': self.scope['repository'],
            'evidenceId': local_evidence_id, 'plan': plan,
        }))
        evidence_digest = _hash(payload)

        # Detect an intervening local write before attempting CAS. SQLite's
        # own recheck is still authoritative against concurrent writers.
        if self._store().checkpoint() != before:
            raise Stale('REGISTRY_SOURCE_CURSOR_CHANGED')
        if self._collector.head() != collector_head:
            raise Stale('REGISTRY_SOURCE_COLLECTOR_CHANGED')

        def sealed_reader(reference):
            _need(reference == local_evidence_id,
                  'REGISTRY_SOURCE_EVIDENCE_ID_MISMATCH')
            # Recheck the real collector source at the exact plan-reader
            # boundary, immediately before SQLite's own revision CAS.
            if self._collector.head() != collector_head:
                raise Stale('REGISTRY_SOURCE_COLLECTOR_CHANGED')
            return _decode(_raw(payload))
        accepted = self._store(sealed_reader).append_range(
            actor=PLANNER, operation_id=operation_id,
            evidence_id=local_evidence_id, evidence_digest=evidence_digest,
            expected_revision=expected_revision)
        _need(accepted['result'] in (
              'LOCAL_DESIRED_CANDIDATE_COMMITTED','UNKNOWN_OUTCOME')
              and accepted['integrityModel']=='LOCAL_EVENT_CHAIN_ONLY',
              'REGISTRY_SOURCE_RESULT_UNSAFE')
        return {
            # An ambiguous post-COMMIT readback is never presented as an
            # accepted candidate; callers must query the original UUID.
            'result': ('INACTIVE_SOURCE_RANGE_CANDIDATE'
                       if accepted['result']=='LOCAL_DESIRED_CANDIDATE_COMMITTED'
                       else 'UNKNOWN_OUTCOME'),
            'operationId': operation_id, 'localEvidenceId': local_evidence_id,
            'selectedMainSha': selected_main_sha, 'storage': accepted,
            'collectorCheckpointCandidate': collector_head,
            'collectorProvenanceVerified': False,
            'integrityModel': 'LOCAL_EVENT_CHAIN_ONLY',
            'evidenceVerified': False, 'admissionAllowed': False,
            'deploymentAllowed': False, 'writeEnabled': False,
        }

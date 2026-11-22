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

from ..core import Conflict, Denied, Stale
from .state_journal import (
    REPOSITORY, PLANNER, _checkpoint, _decode, _hash, _need,
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

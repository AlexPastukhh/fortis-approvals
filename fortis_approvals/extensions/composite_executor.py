"""Opt-in Core lifecycle adapter for the two bounded Registry groups.

Not installed in the live composition. The binding is trusted source code,
not an API callback or a generic provider adapter. Real scope/authority,
maintenance and original receipt verification belong to reviewed bindings.
"""
from contextvars import ContextVar
from dataclasses import dataclass
from threading import Lock

from ..core import Denied, canonical, loads_strict
from ..integrations.registry_contracts.semantic_contract import digest, hex_id, need
from . import composite_journal as journal
from .composite_contract import expand_group, expand_composite

_GROUPS = frozenset(('begin_release_group', 'report_release_results'))


@dataclass(frozen=True)
class Admission:
    standalone: str
    contextual: bool
    hard_floor: str
    generation_digest: str

    def checked(self):
        # V1 group bindings cannot consume independent hard owner ceremonies.
        need(self.standalone in ('ALLOW', 'ASK')
             and self.contextual is True and self.hard_floor == 'ALLOW',
             'COMPOSITE_CHILD_AUTHORITY_DENIED')
        hex_id(self.generation_digest, 64)
        return {'standalone': self.standalone, 'contextual': True,
                'hardFloor': self.hard_floor, 'generationDigest': self.generation_digest}


@dataclass(frozen=True)
class StepContext:
    actor: str
    parent_id: str
    fingerprint: str
    policy_version: str
    owner: str | None
    target: str
    definition_digest: str
    authority_digest: str
    step_id: str
    ordinal: int
    operation: str
    params_json: str

    @property
    def params(self):
        return loads_strict(self.params_json)


class GroupAdapter:
    """Trusted, opt-in adapter; only explicit group coordinates intercepted.

    binding.admit must be bounded and nonmutating, resolve exact actor,
    subject, parent coordinate, contextual enrollment and hard floors.
    binding.dispatch and binding.lookup are distinct, reviewed operations.
    binding.verify must verify original receipt identity and actual evidence,
    not merely a result schema. No existing ExtensionAdapter.apply is
    implicitly composable. The process lock assumes the existing sole writer
    deployment; no distributed lease or global maintenance fence is claimed.
    """
    def __init__(self, *, binding, ordinary=None):
        self.binding = binding
        self.ordinary = ordinary
        self.core = None
        self._active = Lock()
        self._submit_actor = ContextVar('composite_submit_actor', default=None)
        self._execution = ContextVar('composite_execution', default=None)

    def is_group(self, payload):
        return (payload.get('service') == 'registry'
                and type(payload.get('operation')) is str and payload['operation'] in _GROUPS)

    def _ordinary(self):
        need(self.ordinary is not None, 'COMPOSITE_ORDINARY_UNAVAILABLE')
        return self.ordinary

    def _admission(self, actor, payload, expansion):
        need(self.core.auth.active(actor), 'COMPOSITE_ACTOR_REVOKED')
        records = []
        for step in expansion['steps']:
            value = self.binding.admit(actor, payload['target'], loads_strict(canonical(step)))
            need(type(value) is Admission, 'COMPOSITE_CHILD_AUTHORITY_DENIED')
            records.append({'stepId': step['stepId'], **value.checked()})
        return digest(records)

    def inner_policy(self, actor, request):
        if not self.is_group(request):
            predicate = getattr(self._ordinary(), 'inner_policy', None)
            return predicate(actor, request) if callable(predicate) else 'ALLOW'
        try:
            expansion = expand_group('registry', request['operation'],
                                     request['requestId'], request['params'])
            self._admission(actor, request, expansion)
        except (Denied, KeyError, TypeError, ValueError):
            return 'DENY'
        return 'ALLOW'

    def prepare(self, request):
        if not self.is_group(request):
            return self._ordinary().prepare(request)
        actor = self._prepare_actor(request)
        expansion = expand_composite(request['service'],request['operation'],request['requestId'],
                                     request['params'])
        preview = {'composite': expansion,
                   'authorityDigest': self._admission(actor, request, expansion)}
        if request['operation'] == 'begin_release_group' and callable(getattr(self.binding,'dispatch_atomic',None)):
            preview['executionMode'] = 'ATOMIC_REGISTRY_LOCAL'
        return preview

    def _prepare_actor(self, request):
        need(self.core is not None, 'COMPOSITE_CORE_NOT_BOUND')
        try:
            row = self.core._read(request['requestId'])
        except Denied:
            row = None
        scoped = self._submit_actor.get()
        if row is not None:
            need(row['request'] == request, 'COMPOSITE_PARENT_BINDING')
            actor = row['actor']
            need(scoped is None or scoped == (actor, request['requestId']),
                 'COMPOSITE_ACTOR_CHANGED')
        else:
            need(scoped is not None and scoped[1] == request['requestId'],
                 'COMPOSITE_ACTOR_MISSING')
            actor = scoped[0]
        return actor

    def _context(self, row, step, authority):
        payload = loads_strict(row['payload'])
        return StepContext(row['actor'], row['id'], row['fingerprint'], row['policy_version'],
                           row['owner'], payload['target'], step['definitionDigest'],
                           authority, step['stepId'], step['ordinal'],
                           step['operation'], canonical(step['params']))

    def _current(self, row, expansion, authority):
        payload = loads_strict(row['payload'])
        need(int(self.core.clock()) < row['expires_at']
             and self.core.auth.active(row['actor'])
             and self.core.policy_version == row['policy_version'],
             'COMPOSITE_PARENT_AUTHORITY_CHANGED')
        expected = 'ALLOW' if row['decision'] is None else 'ASK'
        need(row['decision'] in (None, 'approve')
             and (row['decision'] is None or bool(row['owner']))
             and self.core._policy(row['actor'], payload) == expected
             and self._admission(row['actor'], payload, expansion) == authority,
             'COMPOSITE_PARENT_AUTHORITY_CHANGED')

    def _record(self, ctx, state, detail):
        with self.core._db() as db:
            db.execute('BEGIN IMMEDIATE')
            journal.append_step(db, ctx.parent_id, ordinal=ctx.ordinal,
                                step_id=ctx.step_id, state=state, detail=detail)

    def _verified(self, ctx, receipt):
        need(type(receipt) is dict and receipt.get('operationId') == ctx.step_id
             and len(canonical(receipt).encode('utf-8')) <= 32768
             and self.binding.verify(ctx, receipt) is True,
             'COMPOSITE_RECEIPT_UNVERIFIED')
        return {'operationId': ctx.step_id, 'receiptDigest': digest(receipt)}

    def apply(self, request):
        if not self.is_group(request):
            return self._ordinary().apply(request)
        # Only Core.execute's one winning scoped call may enter. No direct
        # invocation or restarted process is a continuation capability.
        token = self._execution.get()
        need(token is not None and token[0] == request['requestId'] and not token[1],
             'COMPOSITE_EXECUTOR_CONTEXT_REQUIRED')
        token[1] = True
        with self._active:
            try:
                return self._apply_group(request)
            except Exception:
                # The pinned Core catches Stale specially. Never allow a
                # post-dispatch exception to discard a possible child effect.
                raise RuntimeError('COMPOSITE_OUTCOME_UNCONFIRMED') from None

    def _apply_group(self, request):
        parent_id = request['requestId']
        with self.core._db() as db:
            db.execute('BEGIN')
            row, expansion, authority = journal._parent(db, parent_id)
            need(loads_strict(row['payload']) == request and row['state'] == 'DISPATCHED',
                 'COMPOSITE_PARENT_BINDING')
            initial = journal.inspect(db, parent_id)
            need(not initial['interrupted'] and
                 all(s['state'] == 'PLANNED' for s in initial['steps']),
                 'COMPOSITE_NO_CONTINUATION')
        if journal.execution_mode(row) == 'ATOMIC_REGISTRY_LOCAL':
            return self._apply_atomic(parent_id, expansion, authority)
        for step in expansion['steps']:
            with self.core._db() as db:
                db.execute('BEGIN IMMEDIATE')
                row, fresh, pinned = journal._parent(db, parent_id)
                need(fresh == expansion and pinned == authority, 'COMPOSITE_PARENT_BINDING')
                ctx = self._context(row, step, authority)
                try:
                    self._current(row, expansion, authority)
                except Denied:
                    journal.append_step(db, parent_id, ordinal=ctx.ordinal,
                                        step_id=ctx.step_id, state='BLOCKED', detail={})
                    blocked = True
                else:
                    journal.append_step(db, parent_id, ordinal=ctx.ordinal,
                                        step_id=ctx.step_id, state='DISPATCHED', detail={})
                    blocked = False
            if blocked:
                raise Denied('COMPOSITE_CHILD_BLOCKED')
            # Marker committed. Recheck immediately before the external call;
            # actual provider must still enforce current effect-time guards.
            try:
                with self.core._db() as db:
                    db.execute('BEGIN')
                    row, fresh, pinned = journal._parent(db, parent_id)
                    need(fresh == expansion and pinned == authority
                         and row['state'] == 'DISPATCHED', 'COMPOSITE_PARENT_BINDING')
                    self._current(row, expansion, authority)
                result = self.binding.dispatch(ctx)
                detail = self._verified(ctx, result)
                self._record(ctx, 'CONFIRMED', detail)
            except Exception:
                self._record(ctx, 'UNKNOWN', {})
                raise
        return self._result(parent_id)

    def _apply_atomic(self, ident, expansion, authority):
        """One local Registry unit: all markers committed, then one effect."""
        with self.core._db() as db:
            db.execute('BEGIN IMMEDIATE')
            row, fresh, pinned = journal._parent(db, ident)
            need(fresh == expansion and pinned == authority and row['state']=='DISPATCHED',
                 'COMPOSITE_PARENT_BINDING')
            self._current(row, expansion, authority)
            contexts = [self._context(row, step, authority) for step in expansion['steps']]
            for ctx in contexts:
                journal.append_step(db, ident, ordinal=ctx.ordinal, step_id=ctx.step_id,
                                    state='DISPATCHED', detail={})
            journal.inspect(db,ident)
        try:
            with self.core._db() as db:
                db.execute('BEGIN')
                row, fresh, pinned = journal._parent(db, ident)
                need(fresh == expansion and pinned == authority and row['state']=='DISPATCHED',
                     'COMPOSITE_PARENT_BINDING')
                self._current(row, expansion, authority)
            results = self.binding.dispatch_atomic(tuple(contexts))
            need(type(results) is list and len(results)==len(contexts),
                 'COMPOSITE_ATOMIC_OUTCOME_UNKNOWN')
            details = [self._verified(ctx, receipt) for ctx,receipt in zip(contexts,results)]
            with self.core._db() as db:
                db.execute('BEGIN IMMEDIATE')
                for ctx, detail in zip(contexts,details):
                    journal.append_step(db, ident, ordinal=ctx.ordinal, step_id=ctx.step_id,
                                        state='CONFIRMED', detail=detail)
                journal.inspect(db,ident)
        except Exception:
            with self.core._db() as db:
                db.execute('BEGIN IMMEDIATE')
                view = journal.inspect(db,ident)
                for ctx,step in zip(contexts,view['steps']):
                    if step['state']=='DISPATCHED':
                        journal.append_step(db, ident, ordinal=ctx.ordinal, step_id=ctx.step_id,
                                            state='UNKNOWN', detail={})
            raise
        return self._result(ident)

    def _result(self, ident):
        with self.core._db() as db:
            db.execute('BEGIN')
            view = journal.inspect(db, ident)
        if not view['allConfirmed']:
            return None
        return {'kind': 'COMPOSITE_CONFIRMED', 'parentId': ident,
                'receipts': [s['receipt'] for s in view['steps']]}

    def confirm(self, ident, result):
        row = self.core._read(ident)
        if not self.is_group(row['request']):
            return self._ordinary().confirm(ident, result)
        actual = self._result(ident)
        return actual is not None and canonical(actual) == canonical(result)

    def receipt(self, ident):
        row = self.core._read(ident)
        if not self.is_group(row['request']):
            return self._ordinary().receipt(ident)
        # Passive journal-only. Core reconcile for groups is overridden below.
        return self._result(ident)

    def recover(self, ident):
        """Passive original receipt lookup only; no retry or next step.

        Same-process execution is excluded. Production must independently
        enforce single writer/quiescence before cross-generation recovery.
        Current authorization is conservatively required for provider lookup;
        a separate protected accounting path after revocation is still open.
        """
        if not self._active.acquire(blocking=False):
            raise Denied('COMPOSITE_EXECUTION_ACTIVE')
        try:
            with self.core._db() as db:
                db.execute('BEGIN IMMEDIATE')
                row, expansion, authority = journal._parent(db, ident)
                need(row['state'] in ('DISPATCHED', 'UNCERTAIN'),
                     'RECONCILIATION_NOT_AVAILABLE')
                view = journal.inspect(db, ident)
                # Fence a crashed parent before performing receipt lookup.
                for step in view['steps']:
                    if step['state'] == 'DISPATCHED':
                        journal.append_step(db, ident, ordinal=step['ordinal'],
                                            step_id=step['stepId'], state='UNKNOWN', detail={})
                if row['state'] == 'DISPATCHED' and not view['allConfirmed']:
                    db.execute("UPDATE requests SET state='UNCERTAIN',failure=? WHERE id=?",
                               ('COMPOSITE_RECOVERY_REQUIRED', ident))
                    self.core._event(db, ident, 'UNCERTAIN')
            atomic = journal.execution_mode(row) == 'ATOMIC_REGISTRY_LOCAL'
            recovered = []
            for step in expansion['steps']:
                with self.core._db() as db:
                    db.execute('BEGIN')
                    current, fresh, pinned = journal._parent(db, ident)
                    need(fresh == expansion and pinned == authority, 'COMPOSITE_PARENT_BINDING')
                    view = journal.inspect(db, ident)
                    if view['steps'][step['ordinal']]['state'] != 'UNKNOWN':
                        continue
                    self._current(current, expansion, authority)
                    ctx = self._context(current, step, authority)
                receipt = self.binding.lookup(ctx)
                if receipt is not None:
                    detail = self._verified(ctx, receipt)
                    if atomic:
                        recovered.append((ctx,detail))
                    else:
                        self._record(ctx, 'CONFIRMED', detail)
            with self.core._db() as db:
                db.execute('BEGIN IMMEDIATE')
                if atomic and len(recovered)==len(expansion['steps']):
                    for ctx,detail in recovered:
                        journal.append_step(db,ident,ordinal=ctx.ordinal,step_id=ctx.step_id,
                                            state='CONFIRMED',detail=detail)
                view = journal.inspect(db, ident)
                if view['allConfirmed']:
                    result = {'kind': 'COMPOSITE_CONFIRMED', 'parentId': ident,
                              'receipts': [s['receipt'] for s in view['steps']]}
                    changed = db.execute("UPDATE requests SET state='EXECUTED',result=?,failure=NULL "
                                         "WHERE id=? AND state IN ('DISPATCHED','UNCERTAIN')",
                                         (canonical(result), ident)).rowcount
                    if changed:
                        self.core._event(db, ident, 'EXECUTED', {'recovered': True})
                return self.core._view(db.execute('SELECT * FROM requests WHERE id=?',
                                                  (ident,)).fetchone())
        finally:
            self._active.release()


class CompositeCoreMixin:
    """Opt-in, preserves pinned Core source and normal standalone lifecycle.

    Compose before the existing Core class, only after explicit schema and
    reviewed authority migration. W2.3 owns production composition.
    """
    def _composite(self,payload):
        if type(payload) is not dict or type(payload.get('service')) is not str:
            return None
        adapter=self.adapters.get(payload['service'])
        if type(adapter) is GroupAdapter and adapter.is_group(payload):
            return adapter
        if payload.get('service')=='release':
            from .merge_register import MergeRegisterAdapter
            if type(adapter) is MergeRegisterAdapter and adapter.is_group(payload):
                return adapter
        return None

    def _event(self, db, request_id, state, detail=None):
        super()._event(db, request_id, state, detail)
        if state in ('PENDING','APPROVED'):
            row=db.execute('SELECT payload FROM requests WHERE id=?',(request_id,)).fetchone()
            if row is not None and self._composite(loads_strict(row['payload'])) is not None:
                journal.bind_parent(db,request_id)

    def submit(self, actor, payload):
        adapter=self._composite(payload)
        if adapter is None:
            return super().submit(actor,payload)
        self._payload(payload)
        need(adapter.core is self,'COMPOSITE_CORE_NOT_BOUND')
        if payload['service']=='release':
            need(self._policy(actor,payload)=='ASK','MERGE_REGISTER_OWNER_ASK_REQUIRED')
        token=adapter._submit_actor.set((actor,payload['requestId']))
        observed=None
        try:
            if payload['service']=='release':
                try:
                    self._read(payload['requestId'])
                except Denied:
                    observed=adapter.observe_for_prepare(actor,payload)
            return super().submit(actor,payload)
        finally:
            if observed is not None:
                adapter._observation.reset(observed)
            adapter._submit_actor.reset(token)

    def execute(self, ident):
        row=self._read(ident)
        adapter=self._composite(row['request'])
        if adapter is None:
            return super().execute(ident)
        token=adapter._execution.set([ident,False])
        observed=None
        try:
            p=row['request']
            if (p['service']=='release' and row['state']=='APPROVED'
                    and row['decision']=='approve' and bool(row['owner'])
                    and self.auth.active(row['actor']) and self.clock()<row['expiresAt']
                    and self.policy_version==row['policyVersion']
                    and self._policy(row['actor'],p)=='ASK'):
                observed=adapter.observe_for_prepare(row['actor'],p)
            return super().execute(ident)
        finally:
            if observed is not None:
                adapter._observation.reset(observed)
            adapter._execution.reset(token)

    def reconcile(self, ident):
        adapter=self._composite(self._read(ident)['request'])
        if adapter is None:
            return super().reconcile(ident)
        return adapter.recover(ident)

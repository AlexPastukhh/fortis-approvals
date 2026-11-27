"""Reviewed-shape Registry group binding, with transport injected by composition.

Local rehearsal uses the actual SemanticRegistry service on a test database;
the Gateway must not mount/write the Registry DB. Real scoped Unix transport,
protected effect gate and owner principal provisioning remain release gates.
"""
from ..integrations.registry_contracts import semantic_contract as sc
from .composite_executor import StepContext, GroupAdapter
from . import composite_journal as journal


class RegistryGroupBinding:
    def __init__(self, *, transport, admission, provenance, profile_digest):
        sc.hex_id(profile_digest,64)
        sc.need(callable(admission) and callable(provenance))
        self.transport,self.admission,self.provenance=transport,admission,provenance
        self.profile_digest=profile_digest
        self.adapter=None

    def admit(self, actor,target,step):
        return self.admission(actor,target,step)

    def _check(self, ctx, *, lookup=False):
        adapter=self.adapter
        sc.need(type(adapter) is GroupAdapter and adapter.binding is self and type(ctx) is StepContext,
                'REGISTRY_GROUP_BINDING_REQUIRED')
        with adapter.core._db() as db:
            db.execute('BEGIN')
            row,expansion,authority=journal._parent(db,ctx.parent_id)
            sc.need(row['state'] in (('DISPATCHED','UNCERTAIN') if lookup else ('DISPATCHED',))
                    and 0<=ctx.ordinal<len(expansion['steps'])
                    and adapter._context(row,expansion['steps'][ctx.ordinal],authority)==ctx,
                    'REGISTRY_GROUP_CONTEXT_CHANGED')
            view=journal.inspect(db,ctx.parent_id)
            sc.need(view['steps'][ctx.ordinal]['state'] in (('DISPATCHED','UNKNOWN','CONFIRMED') if lookup else ('DISPATCHED',)),
                    'REGISTRY_GROUP_MARKER_REQUIRED')
            adapter._current(row,expansion,authority)
            return journal.execution_mode(row),len(expansion['steps'])

    def _source(self, ctx):
        source=self.provenance(ctx.actor)
        sc.need(source in ('OWNER_DIRECT','OWNER_TRANSCRIBED'),'REGISTRY_GROUP_PROVENANCE')
        return source

    def dispatch(self,ctx):
        mode,_=self._check(ctx)
        sc.need(mode=='SEQUENTIAL','REGISTRY_GROUP_ATOMIC_REQUIRED')
        return self.transport.owner_write(ctx.actor,ctx.operation,ctx.params,
            operation_id=ctx.step_id,assertion_source=self._source(ctx),parent_id=ctx.parent_id)

    def dispatch_atomic(self,contexts):
        sc.need(type(contexts) is tuple and len(contexts)>=2)
        first=contexts[0]
        for i,ctx in enumerate(contexts):
            mode,count=self._check(ctx)
            sc.need(mode=='ATOMIC_REGISTRY_LOCAL' and count==len(contexts) and
                    ctx.parent_id==first.parent_id and ctx.actor==first.actor and
                    ctx.ordinal==i and ctx.operation=='begin_release',
                    'REGISTRY_GROUP_ATOMIC_CONTEXT')
        return self.transport.begin_group(first.actor,{'items':[c.params for c in contexts]},
            operation_ids=[c.step_id for c in contexts],parent_id=first.parent_id,
            assertion_source=self._source(first))

    def lookup(self,ctx):
        self._check(ctx,lookup=True)
        result=self.transport.read(ctx.actor,'get_operation',
                                   {'subject':ctx.params['subject'],'operationId':ctx.step_id})['data']
        return result['receipt'] if result['found'] else None

    def verify(self,ctx,receipt):
        req={'operationId':ctx.step_id,
             'kind':'RELEASE_ATTEMPT_STARTED' if ctx.operation=='begin_release' else 'OWNER_RESULT_RECORDED',
             'actor':ctx.actor,'assertionSource':self._source(ctx),
             'parentRequestId':ctx.parent_id,'profileDigest':self.profile_digest,'params':ctx.params}
        return (type(receipt) is dict and receipt.get('requestDigest')==sc.digest(req)
                and receipt.get('subject')==ctx.params['subject']
                and self.lookup(ctx)==receipt)

"""One owner-reviewed composite, original receipt-bound second step.

The reviewed native provider must use the persisted parent decision, premerge
capture and independent readback. Runtime admission requires protected configuration.
"""
from ..integrations.registry_contracts import semantic_contract as sc
from ..integrations.registry_contracts import source_lineage_contract as lc
from contextvars import ContextVar
from ..core import Denied, Stale
from .composite_contract import expand_composite
from .composite_executor import GroupAdapter, Admission, StepContext
from . import composite_journal as journal
from . import merge_capture


class MergeRegisterAdapter(GroupAdapter):
    def __init__(self, *, binding, ordinary=None):
        super().__init__(binding=binding, ordinary=ordinary)
        self._observation=ContextVar('merge_prepare_observation',default=None)

    def observe_for_prepare(self,actor,request):
        """One invocation, exact actor/request/policy binding; no public cache.

        All external review occurs before Core's write transaction. Core
        still rechecks its policy and deterministic expansion under lock.
        """
        sc.need(self.core.auth.active(actor) and self.core._policy(actor,request)=='ASK',
                'MERGE_REGISTER_OWNER_ASK_REQUIRED')
        version=self.core.policy_version
        material=None
        try:
            p=lc.proposal(request['params'])
            from .native_merge_receipt import NativeMergeProvider
            if type(self.binding.provider) is NativeMergeProvider:
                observed,material=self.binding.preview(actor,p,retain=True)
            else:
                observed=self.binding.preview(actor,p)
            sc.need(observed==p,'MERGE_REGISTER_PREVIEW_CHANGED')
            error=None
        except (Denied,Stale):
            error='MERGE_REGISTER_PREVIEW_CHANGED'
        return self._observation.set((actor,sc.canonical(request),version,error,material))

    def is_group(self,payload):
        return payload.get('service')=='release' and payload.get('operation')=='merge_and_register'

    def _admission(self,actor,payload,expansion):
        sc.need(self.core.auth.active(actor))
        rows=[]
        for step in expansion['steps']:
            value=self.binding.admit(actor,payload['target'],sc.loads_strict(sc.canonical(step)))
            sc.need(type(value) is Admission and value.contextual is True
                    and value.standalone in ('ALLOW','ASK') and
                    value.hard_floor==('ASK' if step['ordinal']==0 else 'ALLOW'),
                    'MERGE_REGISTER_CHILD_AUTHORITY_DENIED')
            sc.hex_id(value.generation_digest,64)
            rows.append({'stepId':step['stepId'],'standalone':value.standalone,
                         'contextual':True,'hardFloor':value.hard_floor,
                         'generationDigest':value.generation_digest})
        return sc.digest(rows)

    def inner_policy(self,actor,request):
        try:
            sc.need(self.is_group(request))
            expansion=expand_composite('release','merge_and_register',request['requestId'],request['params'])
            self._admission(actor,request,expansion)
            return 'ASK'
        except (KeyError,TypeError,ValueError,RuntimeError):
            return 'DENY'
        except Exception:
            return 'DENY'

    def prepare(self,request):
        result=super().prepare(request)
        actor=self._prepare_actor(request)
        observation=self._observation.get()
        sc.need(observation is not None and observation[:3]==(
            actor,sc.canonical(request),self.core.policy_version),
            'MERGE_REGISTER_PREOBSERVATION_REQUIRED')
        if observation[3] is not None:
            raise Stale(observation[3])
        return result

    def _current(self,row,expansion,authority):
        sc.need(row['decision']=='approve' and bool(row['owner']),
                'MERGE_REGISTER_OWNER_ASK_REQUIRED')
        super()._current(row,expansion,authority)

    def _external_review(self,ident,actor):
        from .native_merge_receipt import NativeMergeProvider
        sc.need(type(self.binding.provider) is NativeMergeProvider,
                'MERGE_EXTERNAL_NOT_AVAILABLE')
        with self.core._db() as db:
            db.execute('BEGIN')
            row,_,_=journal._parent(db,ident)
            view=journal.inspect(db,ident)
            sc.need(row['state']=='STALE' and row['failure']=='MERGE_ALREADY_EXTERNAL'
                    and row['actor']==actor and all(s['state']=='PLANNED' for s in view['steps']),
                    'MERGE_EXTERNAL_NOT_AVAILABLE')
            request=sc.loads_strict(row['payload'])
            sc.need(self.core.auth.active(actor) and self.core._policy(actor,request)=='ASK',
                    'MERGE_EXTERNAL_NOT_AVAILABLE')
            events=db.execute("SELECT state,detail FROM events WHERE request_id=? AND "
                              "state IN ('STALE','EXTERNAL_REGISTRATION_STARTED') ORDER BY seq LIMIT 3",
                              (ident,)).fetchall()
            sc.need(len(events) in (1,2) and events[0][0]=='STALE'
                    and (len(events)==1 or events[1][0]=='EXTERNAL_REGISTRATION_STARTED'),
                    'MERGE_EXTERNAL_NOT_AVAILABLE')
            detected=sc.loads_strict(events[0][1])
            sc.fields(detected,('reason','mergeSha'))
            sc.need(detected['reason']=='MERGE_ALREADY_EXTERNAL','MERGE_EXTERNAL_NOT_AVAILABLE')
            sc.hex_id(detected['mergeSha'],40)
            started=sc.loads_strict(events[1][1]) if len(events)==2 else None
            return request['params'],row['fingerprint'],detected['mergeSha'],started

    def _external_result(self,ident,actor,p,merge_sha,started):
        receipt=self.binding.registry.external_source_operation(actor,ident,p)
        if receipt is None:
            return {'requestId':ident,'state':'REGISTRATION_UNCONFIRMED'}
        sc.fields(started,('requestDigest','owner','approvalFingerprint','proofDigest'))
        sc.need(receipt['kind']=='EXTERNAL_MERGE'
                and receipt['operationId']==lc.external_operation(ident)
                and receipt['sourceCursor']==merge_sha
                and receipt['requestDigest']==started['requestDigest'],
                'SOURCE_EXTERNAL_RECEIPT_CHANGED')
        return {'requestId':ident,'state':'EXTERNAL_REGISTERED','mergeSha':merge_sha}

    def external_context(self,ident,actor,owner):
        proposal,fingerprint,merge_sha,started=self._external_review(ident,actor)
        if started is not None:
            return self._external_result(ident,actor,proposal,merge_sha,started)
        sc.need(self.binding.registry.external_source_operation(actor,ident,proposal) is None,
                'SOURCE_EXTERNAL_RECEIPT_CHANGED')
        version=self.core.policy_version
        observed=self.binding.provider.discovery.verify_external(actor,proposal,merge_sha)
        sc.need(self.binding.registry.source_preflight(proposal)==self.binding.source_expected(proposal)
                and self.core.policy_version==version,'MERGE_EXTERNAL_NOT_AVAILABLE')
        approval=sc.digest(['register-external-merge-v1',ident,fingerprint,actor,owner,version,observed])
        return {'proposal':proposal,'observation':observed,'fingerprint':approval,'policyVersion':version}

    def register_external(self,ident,actor,owner,fingerprint,proof):
        from .maintenance_gate import Coordinate
        sc.need(not (type(proof) is dict and proof.get('mode')=='session'),
                'MERGE_REGISTER_OWNER_ASK_REQUIRED')
        sc.need(self._active.acquire(blocking=False),'COMPOSITE_EXECUTION_ACTIVE')
        try:
            current=self.external_context(ident,actor,owner)
            if 'state' in current:
                return current
            sc.need(current['fingerprint']==fingerprint,'MERGE_EXTERNAL_NOT_AVAILABLE')
            sc.need(self.core.owner_verifier.verify(ident,fingerprint,'approve',proof)==owner,
                    'MERGE_REGISTER_OWNER_ASK_REQUIRED')
            p,o=current['proposal'],current['observation']
            proof_digest=sc.digest(proof)
            req={'operationId':lc.external_operation(ident),'kind':'EXTERNAL_MERGE',
                 'parentRequestId':ident,'proposal':p,'observation':o,'transition':None,
                 'evidenceDigest':sc.digest(['external-merge-evidence-v1',ident,p,o,owner,
                                             fingerprint,proof_digest])}
            body=lc.external_registration({'request':req,'owner':owner,
                            'approvalFingerprint':fingerprint,'proofDigest':proof_digest})
            started={'requestDigest':sc.digest(req),'owner':owner,
                     'approvalFingerprint':fingerprint,'proofDigest':proof_digest}
            coordinate=Coordinate('registry','register_merge')
            with self.binding.gate.reserve(coordinate) as token:
                with self.binding.gate.effect(token):
                    with self.core._db() as db:
                        db.execute('BEGIN IMMEDIATE')
                        row,_,_=journal._parent(db,ident)
                        sc.need(row['state']=='STALE' and row['failure']=='MERGE_ALREADY_EXTERNAL'
                                and row['actor']==actor and self.core.auth.active(actor)
                                and current['policyVersion']==self.core.policy_version
                                and not db.execute("SELECT 1 FROM events WHERE request_id=? "
                                    "AND state='EXTERNAL_REGISTRATION_STARTED'",(ident,)).fetchone(),
                                'MERGE_EXTERNAL_NOT_AVAILABLE')
                        sc.need(not db.execute("SELECT 1 FROM requests WHERE state IN "
                            "('DISPATCHED','UNCERTAIN') AND json_extract(payload,'$.service')='release' "
                            "AND json_extract(payload,'$.params.repository')=? LIMIT 1",
                            (p['repository'],)).fetchone(),'MERGE_EXTERNAL_NOT_AVAILABLE')
                        self.core._event(db,ident,'EXTERNAL_REGISTRATION_STARTED',started)
                    try:
                        self.binding.gate.check_effect(token)
                        sc.need(current['policyVersion']==self.core.policy_version
                                and self.core.auth.active(actor),'MERGE_EXTERNAL_NOT_AVAILABLE')
                        self.binding.registry.register_external_source(actor,body)
                        return self._external_result(ident,actor,p,o['mergeSha'],started)
                    except (Denied,Stale,RuntimeError,OSError):
                        return {'requestId':ident,'state':'REGISTRATION_UNCONFIRMED'}
        finally:
            self._active.release()

    def registration_available(self,ident):
        with self.core._db() as db:
            db.execute('PRAGMA query_only=ON')
            db.execute('BEGIN')
            view=journal.inspect(db,ident)
            return view['parentState']=='UNCERTAIN' and [
                s['state'] for s in view['steps']]==['CONFIRMED','PLANNED']

    def registration_context(self,ident,owner):
        with self.core._db() as db:
            db.execute('BEGIN')
            row,expansion,authority=journal._parent(db,ident)
            view=journal.inspect(db,ident)
            sc.need(row['state']=='UNCERTAIN' and row['owner']==owner
                    and [s['state'] for s in view['steps']]==['CONFIRMED','PLANNED'],
                    'MERGE_REGISTRATION_NOT_AVAILABLE')
            self._current(row,expansion,authority)
            ctx=self._context(row,expansion['steps'][1],authority)
        req=self.binding._register_request(ctx,pending_registration=True)
        proposal=ctx.params['proposal']
        sc.need(self.binding.registry.source_preflight(proposal)==self.binding.source_expected(proposal)
                and self.binding.effect_guard(ctx) is True,'MERGE_REGISTRATION_NOT_AVAILABLE')
        fingerprint=sc.digest(['register-confirmed-merge-v1',ctx.fingerprint,sc.digest(req)])
        return ctx,req,fingerprint

    def register_confirmed(self,ident,owner,fingerprint,proof):
        sc.need(not (type(proof) is dict and proof.get('mode')=='session'),
                'MERGE_REGISTER_OWNER_ASK_REQUIRED')
        sc.need(self._active.acquire(blocking=False),'COMPOSITE_EXECUTION_ACTIVE')
        try:
            ctx,req,expected=self.registration_context(ident,owner)
            sc.need(expected==fingerprint,'MERGE_REGISTRATION_NOT_AVAILABLE')
            sc.need(self.core.owner_verifier.verify(ident,fingerprint,'approve',proof)==owner,
                    'MERGE_REGISTER_OWNER_ASK_REQUIRED')
            with self.core._db() as db:
                db.execute('BEGIN IMMEDIATE')
                row,expansion,authority=journal._parent(db,ident)
                sc.need(self._context(row,expansion['steps'][1],authority)==ctx,
                        'MERGE_REGISTRATION_NOT_AVAILABLE')
                self._current(row,expansion,authority)
                journal.append_step(db,ident,ordinal=1,step_id=ctx.step_id,
                    state='MERGE_REGISTRATION_STARTED',detail={'proofDigest':sc.digest(proof)})
            try:
                result=self.binding._write_source(ctx,req)
                detail=self._verified(ctx,result)
            except Exception:
                self._record(ctx,'UNKNOWN',{})
                return self.core._read(ident)
            with self.core._db() as db:
                db.execute('BEGIN IMMEDIATE')
                journal.append_step(db,ident,ordinal=1,step_id=ctx.step_id,
                                    state='CONFIRMED',detail=detail)
                view=journal.inspect(db,ident)
                result={'kind':'COMPOSITE_CONFIRMED','parentId':ident,
                        'receipts':[s['receipt'] for s in view['steps']]}
                changed=db.execute("UPDATE requests SET state='EXECUTED',result=?,failure=NULL "
                                   "WHERE id=? AND state='UNCERTAIN'",
                                   (sc.canonical(result),ident)).rowcount
                sc.need(changed==1,'MERGE_REGISTRATION_NOT_AVAILABLE')
                self.core._event(db,ident,'EXECUTED',{'recovered':True})
            return self.core._read(ident)
        finally:
            self._active.release()


class MergeRegisterBinding:
    """Trusted composition seam, not a generic provider or user callback.

    The provider and Registry transport below are source-installed interfaces.
    No credentials, direct host/DB mount, API route or automatic authorization.
    """
    def __init__(self,*,provider,registry,admission,effect_guard):
        sc.need(callable(admission) and callable(effect_guard))
        self.provider,self.registry=provider,registry
        self.admission,self.effect_guard=admission,effect_guard
        self.adapter=None

    def admit(self,actor,target,step):
        return self.admission(actor,target,step)

    @staticmethod
    def source_expected(p):
        return {'sourceRevision':p['expectedSourceRevision'],'sourceCursor':p['baseSha'],
                'profileDigest':p['profileDigest'],'proposalDigest':sc.digest(p),
                'admissionAllowed':False}

    def preview(self,actor,p,*,retain=False):
        p=lc.proposal(p)
        expected=self.source_expected(p)
        sc.need(self.registry.source_preflight(p)==expected,'MERGE_REGISTER_SOURCE_PREVIEW_CHANGED')
        if retain:
            observed,material=self.provider.discovery.review(actor,p)
        else:
            observed=self.provider.preview(actor,p)
        sc.need(self.registry.source_preflight(p)==expected,'MERGE_REGISTER_SOURCE_PREVIEW_CHANGED')
        return (lc.proposal(observed),material) if retain else lc.proposal(observed)

    def _check(self,ctx,*,lookup=False,pending_registration=False):
        a=self.adapter
        sc.need(type(a) is MergeRegisterAdapter and a.binding is self and type(ctx) is StepContext)
        with a.core._db() as db:
            db.execute('BEGIN')
            row,expansion,authority=journal._parent(db,ctx.parent_id)
            sc.need(row['state'] in (('DISPATCHED','UNCERTAIN') if lookup or ctx.ordinal==1
                                     else ('DISPATCHED',))
                    and 0<=ctx.ordinal<2 and a._context(row,expansion['steps'][ctx.ordinal],authority)==ctx)
            a._current(row,expansion,authority)
            from .native_merge_receipt import NativeMergeProvider
            if type(self.provider) is NativeMergeProvider:
                self._verify_owner_approval(db,row,ctx)
            view=journal.inspect(db,ctx.parent_id)
            if pending_registration:
                sc.need(lookup and ctx.ordinal==1 and row['state']=='UNCERTAIN'
                        and view['steps'][1]['state']=='PLANNED',
                        'MERGE_REGISTRATION_NOT_AVAILABLE')
            else:
                sc.need(view['steps'][ctx.ordinal]['state'] in
                        (('DISPATCHED','UNKNOWN','CONFIRMED') if lookup else ('DISPATCHED',)))
                if row['state']=='UNCERTAIN' and not lookup:
                    sc.need(view['mergeRegistrationStarted'],'MERGE_REGISTRATION_NOT_AVAILABLE')
            return row,expansion,authority,view

    def _verify_owner_approval(self,db,row,ctx):
        core=self.adapter.core
        sc.need(ctx.owner==core.owner_verifier.owner,'MERGE_REGISTER_OWNER_CHANGED')
        events=db.execute('SELECT state,at,detail FROM events WHERE request_id=? '
                          'ORDER BY seq LIMIT 3',(ctx.parent_id,)).fetchall()
        sc.need([entry[0] for entry in events]==['PENDING','APPROVED','DISPATCHED']
                and row['created_at']==events[0][1]<=events[1][1]<=events[2][1]
                and events[1][1]<row['expires_at']
                and sc.loads_strict(events[0][2])=={'policy':'ASK'},
                'MERGE_REGISTER_OWNER_AUDIT_CHANGED')
        proof=sc.loads_strict(events[1][2])
        sc.fields(proof,('owner','proofSHA256','requestSHA256'))
        sc.hex_id(proof['proofSHA256'],64)
        sc.need(proof['owner']==ctx.owner and proof['requestSHA256']==ctx.fingerprint,
                'MERGE_REGISTER_OWNER_AUDIT_CHANGED')

    def _merge_receipt(self,ctx,receipt):
        p=ctx.params['proposal']
        sc.fields(receipt,('operationId','parentRequestId','proposalDigest',
                          'captureDigest','observation'))
        sc.need(receipt['operationId']==ctx.step_id and receipt['parentRequestId']==ctx.parent_id
                and receipt['proposalDigest']==sc.digest(p),'MERGE_REGISTER_RECEIPT_IDENTITY')
        sc.hex_id(receipt['captureDigest'],64)
        with self.adapter.core._db() as db:
            db.execute('BEGIN')
            retained=merge_capture.lookup(db,ctx.parent_id)
        sc.need(retained is not None and retained['stepId']==ctx.step_id and
                retained['materialDigest']==receipt['captureDigest'],'MERGE_CAPTURE_MISSING_OR_CHANGED')
        lc.observation(receipt['observation'],p)
        sc.need(self.provider.verify(ctx,receipt) is True,'MERGE_REGISTER_EVIDENCE_UNVERIFIED')
        return receipt

    def _register_request(self,ctx,*,pending_registration=False):
        row,expansion,authority,view=self._check(ctx,lookup=True,
                                               pending_registration=pending_registration)
        first=self.adapter._context(row,expansion['steps'][0],authority)
        sc.need(ctx.ordinal==1 and ctx.params['verifiedMergeStepId']==first.step_id
                and view['steps'][0]['state']=='CONFIRMED')
        receipt=self._merge_receipt(first,self.provider.lookup(first))
        sc.need(view['steps'][0]['receipt']['receiptDigest']==sc.digest(receipt),
                'MERGE_REGISTER_ORIGINAL_RECEIPT_CHANGED')
        return {'operationId':ctx.step_id,'kind':'MERGE','parentRequestId':ctx.parent_id,
                'proposal':ctx.params['proposal'],'observation':receipt['observation'],
                'evidenceDigest':sc.digest(receipt),'transition':None}

    def dispatch(self,ctx):
        self._check(ctx)
        sc.need(self.effect_guard(ctx) is True,'MERGE_REGISTER_EFFECT_DENIED')
        if ctx.ordinal==0:
            proposal=ctx.params['proposal']
            sc.need(self.registry.source_preflight(proposal)==self.source_expected(proposal),
                    'MERGE_REGISTER_SOURCE_PREVIEW_CHANGED')
            from .native_merge_receipt import NativeMergeProvider
            if type(self.provider) is NativeMergeProvider:
                observation=self.adapter._observation.get()
                sc.need(observation is not None and observation[0]==ctx.actor
                        and observation[2]==ctx.policy_version and observation[3] is None
                        and sc.loads_strict(observation[1])['requestId']==ctx.parent_id,
                        'MERGE_REGISTER_PREOBSERVATION_REQUIRED')
                captured=observation[4]
                self._check_registration_size(ctx,proposal)
            else:
                captured=self.provider.capture(ctx)
            material=merge_capture.validate(captured,proposal)
            sc.need(self.provider.verify_capture(ctx,material) is True,
                    'MERGE_CAPTURE_EVIDENCE_UNVERIFIED')
            with self.adapter.core._db() as db:
                db.execute('BEGIN IMMEDIATE')
                retained=merge_capture.retain(db,ctx.parent_id,ctx.step_id,material)
            # Original capture transaction has committed before provider
            # effect. Recheck scope and mutable PR edge after retention.
            self._check(ctx)
            sc.need(self.effect_guard(ctx) is True,'MERGE_REGISTER_EFFECT_DENIED')
            if (type(self.provider) is not NativeMergeProvider and
                    self.preview(ctx.actor,ctx.params['proposal'])!=ctx.params['proposal']):
                raise Stale('MERGE_REGISTER_PREVIEW_CHANGED')
            return self._merge_receipt(ctx,self.provider.merge(ctx,retained['materialDigest']))
        req=self._register_request(ctx)
        return self._write_source(ctx,req)

    def _write_source(self,ctx,req):
        return self.registry.register_source(req)

    def _lookup_source(self,ctx):
        return self.registry.source_operation(ctx.step_id)

    def lookup(self,ctx):
        self._check(ctx,lookup=True)
        if ctx.ordinal==0:
            return self.provider.lookup(ctx)
        return self._lookup_source(ctx)

    def verify(self,ctx,receipt):
        if ctx.ordinal==0:
            return self._merge_receipt(ctx,receipt)==self.lookup(ctx)
        req=self._register_request(ctx)
        return (type(receipt) is dict and receipt.get('operationId')==ctx.step_id
                and receipt.get('requestDigest')==sc.digest(req)
                and receipt.get('sourceCursor')==req['observation']['mergeSha']
                and self.lookup(ctx)==receipt)

class TransportMergeRegisterBinding(MergeRegisterBinding):
    """Source effects use the private Registry peer, not its DB or a fake child request."""
    def __init__(self,*,provider,registry,admission,effect_guard,gate,policy_authority_digest):
        from .semantic_gateway import GatewayRegistrySemanticTransport
        from .maintenance_gate import MaintenanceGate
        sc.need(type(registry) is GatewayRegistrySemanticTransport and type(gate) is MaintenanceGate)
        super().__init__(provider=provider,registry=registry,admission=admission,effect_guard=effect_guard)
        self.gate=gate
        sc.hex_id(policy_authority_digest,64)
        self.policy_authority_digest=policy_authority_digest
        from .native_merge_receipt import NativeMergeProvider
        if type(provider) is NativeMergeProvider:
            sc.need(provider.binding is None,'SUCCESSOR_NATIVE_ALREADY_BOUND')
            provider.binding=self

    def _source_context(self,ctx):
        return {'parentId':ctx.parent_id,'stepId':ctx.step_id,
                'definitionDigest':ctx.definition_digest,'authorityDigest':ctx.authority_digest,
                'policyAuthorityDigest':self.policy_authority_digest,
                'fingerprint':ctx.fingerprint,'policyVersion':ctx.policy_version,
                'owner':ctx.owner,'target':ctx.target}

    def _check_registration_size(self,ctx,p):
        from ..integrations.registry_contracts import semantic_wire
        exp=lc.merge_expansion(ctx.parent_id,p)
        obs={k:p[k] for k in ('repository','number','headSha','treeSha','catalogSha256',
                              'bodyDigest','impactDigest','pathsDigest','ciDigest')}
        merge_id=next(d*40 for d in '012' if d*40 not in (p['baseSha'],p['headSha']))
        obs.update(mergeSha=merge_id,mainSha=merge_id,parents=[p['baseSha'],p['headSha']])
        receipt={'operationId':ctx.step_id,'parentRequestId':ctx.parent_id,
                 'proposalDigest':sc.digest(p),'captureDigest':'0'*64,'observation':obs}
        operation=exp['steps'][1]['stepId']
        request={'operationId':operation,'kind':'MERGE','parentRequestId':ctx.parent_id,
                 'proposal':p,'observation':obs,'evidenceDigest':sc.digest(receipt),'transition':None}
        context={**self._source_context(ctx),'stepId':operation}
        body={'context':context,'request':request,'mergeReceipt':receipt}
        transport=self.registry
        pins={'instance':transport.peer._instance,'scope':transport.peer._scope,
              'generation':transport.generation}
        semantic_wire.request({'schemaVersion':2,'requestId':operation,
            'instanceId':pins['instance'],'scopeDigest':pins['scope'],'generation':pins['generation'],
            'actor':ctx.actor,'action':'SOURCE_REGISTER','body':body},**pins)

    def _write_source(self,ctx,req):
        from .maintenance_gate import Coordinate
        row,expansion,authority,_=self._check(ctx)
        first=self.adapter._context(row,expansion['steps'][0],authority)
        receipt=self._merge_receipt(first,self.provider.lookup(first))
        body=lc.merge_registration({'context':self._source_context(ctx),'request':req,
                                    'mergeReceipt':receipt})
        with self.gate.reserve(Coordinate('registry','register_merge')) as token:
            with self.gate.effect(token):
                self._check(ctx)
                sc.need(self.effect_guard(ctx) is True,'MERGE_REGISTER_EFFECT_DENIED')
                return self.registry.register_source(ctx.actor,body['context'],body['request'],receipt)

    def _lookup_source(self,ctx):
        self._check(ctx,lookup=True)
        return self.registry.source_operation(ctx.actor,self._source_context(ctx),ctx.params['proposal'])

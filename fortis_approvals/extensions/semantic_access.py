"""Opt-in semantic ingress composition, same Core and typed Repo envelope.

All authorization and transport dependencies are installed by reviewed
composition. Not registered by R7, no live grant or new provider credential.
"""
from threading import RLock
from contextvars import ContextVar
import uuid
from ..core import Denied, Conflict, Stale
from ..repo_action_contract import RepoIntentBroker, _envelope, _checked_copy
from ..integrations.registry_contracts import semantic_contract as sc
from ..integrations.registry_contracts.source_lineage_contract import proposal
from .maintenance_gate import Coordinate

SUBMIT_ACTOR=ContextVar('semantic_submit_actor',default=None)

READ=frozenset(('registry',op) for op in sc.READ_METHODS)
WRITE=frozenset(('registry',op) for op in sc.WRITE_METHODS)|{('release','merge_and_register')}


def validate(value, *, read):
    action,params=_envelope(value,READ if read else WRITE)
    if action[0]=='registry':
        sc.validate_params(action[1],params)
    else:
        proposal(params)
    return _checked_copy(value)


def subjects(request):
    p=request['params']
    if request['service']=='release':
        return [{'repository':p['repository']}]+[r['subject'] for r in p['targets']]
    if 'subject' in p:return [p['subject']]
    if 'items' in p:return [r['subject'] for r in p['items']]
    return [{'repository':p['repository']}]


class SemanticAccess:
    def __init__(self,core,transport,gate,*,grant,owner_actor,ready,read_approval=None):
        sc.need(all(callable(f) for f in (grant,owner_actor,ready)))
        self.core,self.transport,self.gate=core,transport,gate
        self.grant,self.owner_actor,self.ready=grant,owner_actor,ready
        self.read_approval=read_approval
        self.lock=RLock()

    @classmethod
    def from_reviewed(cls,core,transport,gate,*,enrollment,ready):
        from .semantic_enrollment import SemanticEnrollment,OwnerPrincipalAuth
        from .composite_successor import is_reviewed_successor
        sc.need(is_reviewed_successor(core) and type(enrollment) is SemanticEnrollment
                and type(core.auth) is OwnerPrincipalAuth and
                core.authority.scope_binding.get('semanticScope')==enrollment.sha
                and core._gate() is gate,'SEMANTIC_REVIEWED_COMPOSITION_REQUIRED')
        def grant(actor,service,operation,target,subject):
            coord=(actor,service,operation,target)
            return (core.auth.active(actor) and core.authority.scope_binding.get('semanticScope')==enrollment.sha
                    and coord in core.authority.choices and enrollment.allows(*coord,subject))
        return cls(core,transport,gate,grant=grant,owner_actor=core.auth.owner_actor,ready=ready)

    def bind_existing_read_approval(self,adapter):
        from ..read_approval import OwnerReadApprovalAdapter
        sc.need(type(adapter) is OwnerReadApprovalAdapter and adapter.core is self.core
                and getattr(self.core,'_owner_read_approval',None) is adapter
                and self.read_approval is None and not hasattr(adapter,'semantic_access'),
                'READ_APPROVAL_BINDING_REQUIRED')
        adapter.semantic_access=self
        def consume(actor,query,credential):
            if credential is not None:
                return adapter.begin_or_consume(credential,actor,query)
            return adapter._begin_or_consume_actor(actor,query)
        self.read_approval=consume

    def authorize(self,actor,request,*,read):
        sc.need(self.core.auth.active(actor),'POLICY_DENIED')
        for s in subjects(request):
            sc.need(self.grant(actor,request['service'],request['operation'],request['target'],s) is True,
                    'POLICY_DENIED')
        policy=self.core._policy(actor,request)
        sc.need(policy in ('ALLOW','ASK'),'POLICY_DENIED')
        if request['service']=='release':
            sc.need(policy=='ASK','MERGE_REGISTER_OWNER_ASK_REQUIRED')
        sc.need(self.ready(actor,request) is True,'PROVIDER_UNAVAILABLE')
        return policy

    def read(self,actor,query,*,credential=None):
        q=validate(query,read=True)
        policy=self.authorize(actor,q,read=True)
        version=self.core.policy_version
        if policy=='ASK':
            sc.need(self.read_approval is not None,'READ_APPROVAL_UNAVAILABLE')
            with self.gate.reserve(Coordinate('registry',q['operation'])):
                state=self.read_approval(actor,q,credential)
            if state!='CONSUMED':
                return {'requestId':q['requestId'],'service':'registry','operation':q['operation'],'state':state}
        # Only the installed semantic transport is invoked; ALLOW does not
        # write Core/audit. Scope/policy are rechecked before releasing data.
        self.gate.passive_read(Coordinate('registry',q['operation']))
        result=self.transport.read(actor,q['operation'],q['params'])
        self.gate.passive_read(Coordinate('registry',q['operation']))
        sc.need(self.authorize(actor,q,read=True)==policy and self.core.policy_version==version,
                'POLICY_CHANGED')
        sc.fields(result,('schemaVersion','instanceId','snapshotRevision','eventDigest',
                         'sourceRevision','sourceCursor','catalogSha256','sourceTransitionPending',
                         'runtimeAdmissionAllowed','data'))
        sc.need(result['schemaVersion']==1 and result['runtimeAdmissionAllowed'] is False)
        sc.uuid_id(result['instanceId']);sc.revision(result['snapshotRevision'])
        sc.revision(result['sourceRevision']);sc.hex_id(result['eventDigest'],64)
        sc.hex_id(result['sourceCursor'],40);sc.hex_id(result['catalogSha256'],64)
        sc.need(type(result['sourceTransitionPending']) is bool and type(result['data']) is dict)
        data=result['data']
        op=q['operation']
        def visible(subject):
            sc.subject(subject)
            sc.need(self.grant(actor,'registry',op,q['target'],subject) is True,'POLICY_DENIED')
        if op in ('list_components','list_active_releases'):
            sc.fields(data,('items','nextCursor','complete'))
            sc.need(type(data['items']) is list and len(data['items'])<=q['params']['page']['limit'])
            for row in data['items']:visible(row['subject'])
        elif op=='get_component':
            sc.need(data['subject']==q['params']['subject'])
            visible(data['subject'])
        elif op=='get_maintenance_status':
            for hold in data.get('holds') or []:
                visible(hold['subject'])
        elif op=='plan_batch':
            for row in data['targets']:visible(row['subject'])
            for s in data['order']:visible(s)
            for group in data['buildGroups']:
                for s in group['subjects']+group['affectedUnselected']:visible(s)
            for conflict in data['windowConflicts']:
                for s in conflict['subjects']:visible(s)
            for check in data['checks']:
                if check['subject'] is not None:visible(check['subject'])
        if op=='get_maintenance_status' and data.get('holds') is not None:
            effective=self.gate.effective_status()
            if effective['snapshotRevision']==result['snapshotRevision'] and (
                    effective['eventDigest']==result['eventDigest']):
                data.update(status=effective['phase'],stateFreeze=effective['stateFreeze'],
                            blockedOperations=effective['blockedOperations'])
        self._incident_overlay(q,data)
        sc.need(self.authorize(actor,q,read=True)==policy and self.core.policy_version==version,
                'POLICY_CHANGED')
        sc.need(len(sc.canonical(result).encode())<=262144)
        return {'requestId':q['requestId'],'service':'registry','operation':q['operation'],'data':result}

    def _active_semantic(self):
        # Local Core incident index, not a second journal. No public raw
        # incident rows; conservative bound and fail closed on overflow.
        with self.core._db() as db:
            rows=db.execute("""SELECT id FROM requests WHERE state IN
                ('PENDING','APPROVED','DISPATCHED','UNCERTAIN') AND
                (json_extract(payload,'$.service')='registry' OR
                 json_extract(payload,'$.service')='release') ORDER BY id LIMIT 201""").fetchall()
        sc.need(len(rows)<=200,'SEMANTIC_INCIDENT_SCOPE_UNKNOWN')
        result=[]
        for row in rows:
            value=self.core._read(row[0])
            p=value['request']
            if (p['service'],p['operation']) in WRITE:
                result.append(value)
        return result

    @staticmethod
    def _overlaps(a,b):
        aa,bb=subjects(a),subjects(b)
        return any(x['repository']==y['repository'] and
                   ('targetId' not in x or 'targetId' not in y or x==y)
                   for x in aa for y in bb)

    def _incident_overlay(self,q,data):
        if q['operation'] not in ('list_components','get_component','list_active_releases','plan_batch'):
            return
        incidents=[r for r in self._active_semantic() if r['state'] in ('DISPATCHED','UNCERTAIN')]
        if q['operation']=='plan_batch':
            if any(self._overlaps(q,r['request']) for r in incidents):
                data['checks'].append({'code':'UNRESOLVED_RESULT','status':'FAIL','subject':None})
                if data['status']!='STALE':data['status']='BLOCKED'
                data.pop('planFingerprint',None)
                data['planFingerprint']=sc.digest(data)
            return
        rows=[data] if q['operation']=='get_component' else data['items']
        for row in rows:
            subject=row['subject']
            if any(any(s['repository']==subject['repository'] and
                       ('targetId' not in s or s==subject) for s in subjects(r['request']))
                       for r in incidents):
                row['planningState']='UNKNOWN'
                row['incidentStatus']='UNRESOLVED_RESULT'
            else:
                row['incidentStatus']=None

    def _existing_merge(self,request,*,reproposal=False):
        p=request['params']
        with self.core._db() as db:
            rows=db.execute("""SELECT id FROM requests WHERE
                json_extract(payload,'$.service')='release' AND
                json_extract(payload,'$.operation')='merge_and_register' AND
                json_extract(payload,'$.params.repository')=? AND
                json_extract(payload,'$.params.number')=? AND
                json_extract(payload,'$.params.headSha')=? ORDER BY rowid DESC LIMIT 33""",
                (p['repository'],p['number'],p['headSha'])).fetchall()
        sc.need(len(rows)<=32 and (not reproposal or len(rows)<32),
                'MERGE_PROPOSAL_HISTORY_LIMIT')
        if not rows:
            return None
        recent=self.core._read(rows[0][0])
        if reproposal:
            sc.need(recent['state'] in ('REJECTED','EXPIRED','STALE'),
                    'MERGE_REPROPOSAL_NOT_AVAILABLE')
        return recent

    def _settle_pending_merge(self,old,proposal,*,external_merge=None):
        p=old['request']['params']
        if old['state']!='PENDING':
            return old
        now=int(self.core.clock())
        expired=now>=old['expiresAt']
        changed=external_merge is not None or p!=proposal or old['policyVersion']!=self.core.policy_version
        if not (expired or changed):
            return old
        state='EXPIRED' if expired and external_merge is None else 'STALE'
        failure=('MERGE_ALREADY_EXTERNAL' if external_merge is not None else
                 'MERGE_REVIEW_EXPIRED' if expired else 'MERGE_REVIEW_CHANGED')
        with self.gate.reserve(Coordinate('release','merge_and_register')):
            with self.core._db() as db:
                db.execute('BEGIN IMMEDIATE')
                updated=db.execute("UPDATE requests SET state=?,failure=? WHERE id=? "
                                   "AND state='PENDING' AND fingerprint=?",
                                   (state,failure,old['requestId'],old['fingerprint'])).rowcount
                if updated:
                    detail={'reason':failure}
                    if external_merge is not None:
                        detail['mergeSha']=external_merge
                    self.core._event(db,old['requestId'],state,detail)
        return self.core._read(old['requestId'])

    def repropose(self,actor,*,request_id,repository,target,reader):
        from .native_merge_discovery import NativeMergeDiscovery
        sc.uuid_id(request_id)
        sc.need(type(reader) is NativeMergeDiscovery and reader.repository==repository,
                'DISCOVERY_UNAVAILABLE')
        old=self.core._read(request_id)
        request=old['request']
        sc.need(request['service']=='release' and request['operation']=='merge_and_register'
                and request['target']==target and request['params']['repository']==repository,
                'MERGE_REPROPOSAL_NOT_AVAILABLE')
        self.authorize(actor,request,read=False)
        with self.gate.reserve(Coordinate('release','merge_and_register')):
            current=reader.review_same_head(actor,request['params'])
            intent={k:request[k] for k in ('service','operation','target')}
            intent.update(requestId=str(uuid.uuid4()),params=current,reason='Owner requested a new PR review')
            return self.submit(actor,intent,reproposal=request_id)

    def submit(self,actor,intent,*,discovered=False,reproposal=None):
        q=validate(intent,read=False)
        self.authorize(actor,q,read=False)
        with self.lock:
            if q['service']=='release':
                old=self._existing_merge(q,reproposal=reproposal is not None)
                if reproposal is not None:
                    sc.need(old is not None and old['requestId']==reproposal,
                            'MERGE_REPROPOSAL_NOT_AVAILABLE')
                elif old:
                    if discovered:
                        old=self._settle_pending_merge(old,q['params'])
                    if old['request']['params']!=q['params']:
                        if discovered and old['state'] in ('REJECTED','EXPIRED','STALE'):
                            return self.public(old)
                        raise Stale('MERGE_PROPOSAL_REVIEW_CHANGED')
                    # Authorization to propose the same exact PR allows only
                    # its public request ID/state; the original actor owns it.
                    return self.public(old)
            for old in self._active_semantic():
                original=old['request']
                if not self._overlaps(q,original):continue
                if (discovered and q['service']==original['service']=='release'
                        and original['params']['number']==q['params']['number']
                        and original['params']['headSha']!=q['params']['headSha']):
                    old=self._settle_pending_merge(old,q['params'])
                    if old['state'] in ('STALE','EXPIRED'):
                        continue
                if old['actor']==actor and all(original[k]==q[k] for k in ('service','operation','target','params')):
                    return self.public(old)
                sc.need(old['state'] not in ('DISPATCHED','UNCERTAIN'),'UNRESOLVED_RESULT')
                # Pending conflicting ordinary writes require explicit
                # resolution first, not another owner prompt.
                if q['service']=='registry' and original['service']=='registry':
                    raise Conflict('SEMANTIC_PENDING_CONFLICT')
            body={**q,'expectedVersion':0}
            with self.gate.reserve(Coordinate(q['service'],q['operation'])):
                token=SUBMIT_ACTOR.set((actor,q['requestId']))
                try:
                    row=self.core.submit(actor,body)
                finally:
                    SUBMIT_ACTOR.reset(token)
            return self.public(row)

    @staticmethod
    def public(row):
        return {'requestId':row['requestId'],'state':row['state']}

    def owner(self,session):
        actor=self.owner_actor(session['owner'])
        sc.need(type(actor) is str and self.core.auth.active(actor),'POLICY_DENIED')
        return actor

    def discover(self,actor,*,repository,target,reader):
        """Bounded automatic proposals, no merge; read is independently scoped.

        No trusted PR author field is required. Reader supplies validated
        complete same-repository proposal snapshots, not browser claims.
        No background poll or retry. Terminal history prevents auto recreation.
        """
        from ..integrations.github.contract import validate_github_read
        github_target=repository.split('/')[1]
        query={'requestId':str(uuid.uuid4()),'service':'github','operation':'list_pull_requests',
               'target':github_target,'params':{'page':1,'perPage':20,'state':'open'},'reason':'Owner refresh'}
        validate_github_read('list_pull_requests',github_target,query['params'])
        def allowed():
            return (self.core.auth.active(actor) and
                    self.grant(actor,'github','list_pull_requests',github_target,{'repository':repository}) is True
                    and self.core._policy(actor,query)=='ALLOW')
        sc.need(allowed(),'POLICY_DENIED')
        with self.gate.reserve():
            rows=reader(actor,repository)
            sc.need(allowed(),'POLICY_DENIED')
            sc.need(type(rows) is list and len(rows)<=20,'DISCOVERY_INCOMPLETE')
            from .native_merge_discovery import BLOCKED_CODES,NativeMergeDiscovery
            # Validate the entire bounded inventory before any Core write.
            # Blocked summaries only originate in the trusted native reader.
            checked=[];numbers=set()
            for item in rows:
                if type(reader) is NativeMergeDiscovery and type(item) is dict and item.get('state')=='BLOCKED':
                    sc.fields(item,('number','state','reason'))
                    sc.need(type(item['number']) is int and 0<item['number']<=1000000
                            and item['reason'] in BLOCKED_CODES,'DISCOVERY_BLOCKED_ROW_INVALID')
                    value=sc.loads_strict(sc.canonical(item))
                else:
                    value=proposal(item)
                    sc.need(value['repository']==repository,'DISCOVERY_SCOPE_CHANGED')
                sc.need(value['number'] not in numbers,'DISCOVERY_INVENTORY_CHANGED')
                numbers.add(value['number']);checked.append(value)
            external=[]
            if type(reader) is NativeMergeDiscovery:
                for old in self._active_semantic():
                    request=old['request']
                    p=request['params']
                    if (old['state']!='PENDING' or old['actor']!=actor
                            or (request['service'],request['operation'])!=('release','merge_and_register')
                            or request['target']!=target or p['repository']!=repository
                            or p['number'] in numbers):
                        continue
                    sc.need(allowed(),'POLICY_DENIED')
                    self.authorize(actor,request,read=False)
                    merge_sha=reader.external_merge(actor,p)
                    if merge_sha is not None:
                        external.append((old,merge_sha))
            result=[]
            for old,merge_sha in external:
                sc.need(allowed(),'POLICY_DENIED')
                request=old['request']
                self.authorize(actor,request,read=False)
                row=self._settle_pending_merge(old,request['params'],external_merge=merge_sha)
                if row['state']=='STALE' and row['failure']=='MERGE_ALREADY_EXTERNAL':
                    result.append({'number':request['params']['number'],'state':'BLOCKED',
                                   'reason':'EXTERNAL_MERGE'})
            for p in checked:
                sc.need(allowed(),'POLICY_DENIED')
                if p.get('state')=='BLOCKED':
                    result.append(p);continue
                intent={'requestId':str(uuid.uuid4()),'service':'release','operation':'merge_and_register',
                        'target':target,'params':p,'reason':'Owner refresh: exact PR review'}
                try:
                    result.append({'number':p['number'],**self.submit(actor,intent,discovered=True)})
                except Stale:
                    result.append({'number':p['number'],'state':'BLOCKED','reason':'REVIEW_CHANGED'})
                except (Denied,Conflict):
                    result.append({'number':p['number'],'state':'BLOCKED','reason':'PROPOSAL_UNAVAILABLE'})
            sc.need(allowed(),'POLICY_DENIED')
            return result


class SemanticRepoBroker(RepoIntentBroker):
    """Wrap existing broker; legacy contracts/grants remain untouched."""
    def __init__(self,base,access):
        sc.need(base.core is access.core)
        self.base,self.access,self.core=base,access,base.core
        self.__dict__.update({k:v for k,v in vars(base).items() if k not in vars(self)})

    def read(self,credential,query):
        if type(query) is dict and all(type(query.get(k)) is str for k in ('service','operation')) and (query.get('service'),query.get('operation')) in READ:
            # Legacy reserved get_operation has a distinct old DTO; do not
            # reinterpret old coordinates or silently broaden old READs.
            if query['operation']=='get_operation' and type(query.get('params')) is dict and set(query['params'])=={'repository','operationId'}:
                return self.base.read(credential,query)
            return self.access.read(self.core.auth.authenticate(credential),query,credential=credential)
        return self.base.read(credential,query)

    def submit(self,credential,intent):
        if type(intent) is dict and all(type(intent.get(k)) is str for k in ('service','operation')) and (intent.get('service'),intent.get('operation')) in WRITE:
            return self.access.submit(self.core.auth.authenticate(credential),intent)
        return self.base.submit(credential,intent)

    def status(self,credential,ident):
        actor=self.core.auth.authenticate(credential)
        row=self.core.client(credential,'status',ident)
        q=row['request']
        if (q['service'],q['operation']) in WRITE:
            for s in subjects(q):
                sc.need(self.access.grant(actor,q['service'],q['operation'],q['target'],s) is True,
                        'POLICY_DENIED')
            return self.access.public(row)
        return self.base.status(credential,ident)

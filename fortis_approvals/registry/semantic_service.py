"""Scoped local semantic Registry service (not exposed by live ingress).

Trusted composition supplies authenticated principal, exact per-operation
scope guard, current effect-time guard and clock. No caller-supplied actor,
policy or credential in DTO. Real admission and source transition pending.
"""
from ..core import Denied, Stale, canonical
from ..integrations.registry_contracts import semantic_contract as sc
from .release_domain import ReleaseDomain, key, restriction_digest
from .release_planner import plan

_MAX_RESPONSE = 262144


class SemanticRegistry:
    def __init__(self, domain, *, authorize, clock):
        sc.need(type(domain) is ReleaseDomain and callable(authorize) and callable(clock))
        self.domain,self.authorize,self.clock=domain,authorize,clock

    def _allowed(self, actor, operation, subject):
        return self.authorize(actor,operation,subject) is True

    def _require(self, actor, operation, subject):
        sc.need(self._allowed(actor,operation,subject),'REGISTRY_SEMANTIC_SCOPE_DENIED')

    def _repo(self, actor, operation, repo):
        sc.need(repo == self.domain.store.scope['repository'],'REGISTRY_SEMANTIC_SCOPE_DENIED')
        self._require(actor,operation,{'repository':repo})

    def _component(self, state, profile, profile_digest):
        return {**{k:v for k,v in state.items() if k not in ('history','sourceRequirements')},
                'maintenanceProfile':profile['maintenance'],
                'restrictionDigest':restriction_digest(profile_digest,profile)
                                    if profile['maintenance'] is not None else None,
                'deploymentProcedure':profile['procedure'],
                'deployable':profile['deployable']}

    def _page(self, rows, page, binding):
        cursor=page['cursor']
        offset=0
        if cursor is not None:
            parts=cursor.split('_')
            if len(parts)!=2 or not parts[0].isdigit():
                raise Stale('REGISTRY_PAGE_STALE')
            offset=int(parts[0])
            if not (0 < offset < len(rows)) or sc.digest([binding,offset]) != parts[1]:
                raise Stale('REGISTRY_PAGE_STALE')
        end=min(offset+page['limit'],len(rows))
        return {'items':rows[offset:end],'nextCursor':None if end==len(rows)
                else str(end)+'_'+sc.digest([binding,end]),'complete':end==len(rows)}

    def read(self, actor, operation, params):
        sc.need(operation in sc.READ_METHODS)
        p=sc.validate_params(operation,params)
        repo = p.get('repository') or (p['subject']['repository'] if 'subject' in p
                                       else p['items'][0]['subject']['repository'])
        self._repo(actor,operation,repo)
        view=self.domain.snapshot()
        states,profiles=view['states'],view['profiles']
        profile_digest=view['profileDigest']
        bound=[actor,operation,view['eventDigest'],profile_digest]
        if operation=='plan_batch':
            for item in p['items']:
                self._require(actor,operation,item['subject'])
            result=plan(view,p['items'],visible=lambda subject:self._allowed(actor,operation,subject))
            for target in result['targets']:
                profile=profiles[key(target['subject'])]
                target['restrictionDigest']=(restriction_digest(profile_digest,profile)
                                             if profile['maintenance'] is not None else None)
        elif 'subject' in p:
            subject=p['subject']
            self._require(actor,operation,subject)
            k=key(subject)
            sc.need(k in states and states[k]['subject']==subject,'REGISTRY_SEMANTIC_SUBJECT_UNKNOWN')
            state=states[k]
            if operation=='get_component':
                result=self._component(state,profiles[k],profile_digest)
            elif operation=='list_history':
                result=self._page(state['history'],p['page'],bound+[subject])
            else:
                found=view['operations'].get(p['operationId'])
                source=view['sourceOperations'].get(p['operationId'])
                receipt=None
                if found and found[0]['params']['subject']==subject:
                    receipt=found[1]
                elif source and any(r['subject']==subject for r in source[0]['proposal']['targets']):
                    receipt=source[1]
                result={'found':receipt is not None,'receipt':receipt}
        else:
            visible=[s for _,s in sorted(states.items()) if self._allowed(actor,operation,s['subject'])]
            if operation=='get_maintenance_status':
                # Hidden active holds must not leak via aggregate selector lists.
                if len(visible)!=len(states):
                    result={'status':'UNKNOWN','stateFreeze':None,'blockedOperations':None,'holds':None}
                else:
                    holds=[s['activeAttempt'] for s in visible if s['activeAttempt'] is not None]
                    ops={canonical(op):op for h in holds for op in h['maintenance']['blockedOperations']}
                    # Local candidate restrictions are not actual effective
                    # enforcement or a protected controller interlock.
                    result={'status':'UNKNOWN','stateFreeze':None,'blockedOperations':None,
                            'holds':holds,'candidateRestrictions':{
                                'stateFreeze':any(h['maintenance']['stateFreeze'] for h in holds),
                                'blockedOperations':[ops[k] for k in sorted(ops)]}}
            else:
                rows=[self._component(s,profiles[key(s['subject'])],profile_digest) for s in visible
                      if operation!='list_active_releases' or s['activeAttempt'] is not None]
                result=self._page(rows,p['page'],bound+[repo,sc.digest([s['subject'] for s in visible])])
        output={'schemaVersion':1,'instanceId':self.domain.store.instance_id,
                'snapshotRevision':view['snapshotRevision'],'eventDigest':view['eventDigest'],
                'sourceRevision':view['sourceRevision'],'sourceCursor':view['sourceCursor'],
                'catalogSha256':view['catalogSha256'],
                'sourceTransitionPending':view['sourceTransitionPending'],
                'runtimeAdmissionAllowed':False,'data':result}
        sc.need(len(canonical(output).encode('utf-8')) <= _MAX_RESPONSE,'REGISTRY_SEMANTIC_RESPONSE_LIMIT')
        return output

    def owner_write(self, actor, operation, params, *, operation_id, assertion_source, parent_id=None):
        sc.need(operation in ('begin_release','report_release_result'))
        p=sc.validate_params(operation,params)
        self._repo(actor,operation,p['subject']['repository'])
        self._require(actor,operation,p['subject'])
        # This is the local trusted service boundary only. The real provider
        # must enforce current protected interlock and grant at effect time.
        return self.domain.owner_event(operation,p,actor=actor,assertion_source=assertion_source,
                   operation_id=operation_id,parent_id=parent_id,recorded_at=int(self.clock()))

    def begin_group(self, actor, params, *, operation_ids, parent_id, assertion_source):
        p=sc.validate_params('begin_release_group',params)
        for item in p['items']:
            subject=item['subject']
            self._repo(actor,'begin_release_group',subject['repository'])
            self._require(actor,'begin_release_group',subject)
            self._require(actor,'begin_release',subject)
        return self.domain.begin_group(p['items'],actor=actor,assertion_source=assertion_source,
                operation_ids=operation_ids,parent_id=parent_id,recorded_at=int(self.clock()))

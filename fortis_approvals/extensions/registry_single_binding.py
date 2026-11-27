"""Standalone begin/report adapter using the same scoped local transport.

Trusted preview/receipt readers only. Never substitutes for production
peer admission, protected evidence, or current effect-time checks.
"""
from ..core import Denied
from ..integrations.registry_contracts import semantic_contract as sc
from .semantic_access import SUBMIT_ACTOR


class RegistrySingleAdapter:
    def __init__(self,transport,*,authorize,provenance,profile_reader,ordinary=None):
        self.transport,self.authorize,self.provenance=transport,authorize,provenance
        self.profile_reader,self.ordinary=profile_reader,ordinary
        self.core=None

    def _single(self,p):
        return p.get('service')=='registry' and p.get('operation') in ('begin_release','report_release_result')

    def inner_policy(self,actor,p):
        try:
            if p.get('operation') in sc.READ_METHODS or self._single(p):
                params=sc.validate_params(p['operation'],p['params'])
                return 'ALLOW' if self.authorize(actor,p) is True else 'DENY'
            if self.ordinary:
                predicate=getattr(self.ordinary,'inner_policy',None)
                return predicate(actor,p) if callable(predicate) else 'ALLOW'
        except (Denied,TypeError,KeyError,ValueError):
            pass
        return 'DENY'

    def _actor(self,p):
        try:
            row=self.core._read(p['requestId'])
        except Denied:
            bound=SUBMIT_ACTOR.get()
            sc.need(bound is not None and bound[1]==p['requestId'],'REGISTRY_ACTOR_REQUIRED')
            return bound[0]
        sc.need(row['request']==p,'REGISTRY_REQUEST_CHANGED')
        return row['actor']

    def prepare(self,p):
        if not self._single(p):
            sc.need(self.ordinary is not None)
            return self.ordinary.prepare(p)
        actor=self._actor(p)
        sc.need(self.inner_policy(actor,p)=='ALLOW','POLICY_DENIED')
        params=sc.validate_params(p['operation'],p['params'])
        result=self.transport.read(actor,'get_component',{'subject':params['subject']})
        st=result['data']
        expected=params['expected']
        sc.need(st['subject']==params['subject'] and st['targetRevision']==expected['targetRevision']
                and (st['desired']['recordId'] if st['desired'] else None)==expected['desiredRecordId'],
                'REGISTRY_PREVIEW_STALE')
        profile=self.profile_reader()
        sc.hex_id(profile,64)
        source=self.provenance(actor)
        sc.need(source in ('OWNER_DIRECT','OWNER_TRANSCRIBED'))
        return {'subject':params['subject'],'expected':expected,'paramsDigest':sc.digest(params),
                'profileDigest':profile,'assertionSource':source,
                'activeAttempt':st['activeAttempt'],'desired':st['desired']}

    def apply(self,p):
        if not self._single(p):return self.ordinary.apply(p)
        row=self.core._read(p['requestId'])
        sc.need(row['state']=='DISPATCHED' and row['request']==p and
                self.core.auth.active(row['actor']) and row['policyVersion']==self.core.policy_version
                and self.core.clock()<row['expiresAt'] and
                self.core._policy(row['actor'],p)==('ASK' if row['decision']=='approve' and row['owner'] else 'ALLOW')
                and self.prepare(p)==row['preview'],'REGISTRY_EFFECT_CONTEXT_CHANGED')
        try:
            return self.transport.owner_write(row['actor'],p['operation'],p['params'],
                    operation_id=p['requestId'],assertion_source=row['preview']['assertionSource'])
        except Exception:
            raise RuntimeError('REGISTRY_OUTCOME_UNCONFIRMED') from None

    def receipt(self,ident):
        row=self.core._read(ident);p=row['request']
        if not self._single(p):return self.ordinary.receipt(ident)
        sc.need(self.core.auth.active(row['actor']) and self.inner_policy(row['actor'],p)=='ALLOW'
                and self.core._policy(row['actor'],p) in ('ALLOW','ASK'),'POLICY_DENIED')
        result=self.transport.read(row['actor'],'get_operation',
             {'subject':p['params']['subject'],'operationId':ident})['data']
        return result['receipt'] if result['found'] else None

    def confirm(self,ident,result):
        row=self.core._read(ident);p=row['request']
        if not self._single(p):return self.ordinary.confirm(ident,result)
        expected={'operationId':ident,'kind':'RELEASE_ATTEMPT_STARTED' if p['operation']=='begin_release'
                  else 'OWNER_RESULT_RECORDED','actor':row['actor'],
                  'assertionSource':row['preview']['assertionSource'],'parentRequestId':None,
                  'profileDigest':row['preview']['profileDigest'],'params':p['params']}
        return type(result) is dict and result.get('requestDigest')==sc.digest(expected) and self.receipt(ident)==result

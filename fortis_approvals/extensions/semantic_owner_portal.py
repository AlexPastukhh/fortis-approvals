"""Thin owner-session semantic route on existing owner origin, opt-in only."""
from ..core import ApprovalError, Denied, Conflict, Stale
from ..integrations.registry_contracts import semantic_contract as sc
from ..owner_portal import OwnerPortal

PREFIX='/v1/owner/registry/semantic'


class SemanticOwnerPortal:
    def __init__(self,base,access,*,repository,target,discovery=None):
        sc.need(base.core is access.core)
        sc.repository(repository)
        self.base,self.access=base,access
        self.repository,self.target,self.discovery=repository,target,discovery
        self.core,self.auth=base.core,base.auth
        # The existing WebAuthn begin/finish path owns the strong decision.
        from .semantic_access import WRITE
        base.strong_operations |= WRITE

    def __call__(self,env,start):
        path=env.get('PATH_INFO','')
        routes={PREFIX+'/capabilities',PREFIX+'/read',PREFIX+'/submit',
                PREFIX+'/discover',PREFIX+'/repropose',
                PREFIX+'/register-confirmed/begin',PREFIX+'/register-confirmed/finish',
                PREFIX+'/register-external/begin',PREFIX+'/register-external/finish'}
        if path not in routes:return self.base(env,start)
        reply=OwnerPortal._reply
        try:
            sc.need(env.get('HTTP_HOST')==self.base.host and not env.get('QUERY_STRING') and
                not any(env.get(k) for k in ('HTTP_X_FORWARDED_HOST','HTTP_FORWARDED',
                    'HTTP_AUTHORIZATION','HTTP_PROXY_AUTHORIZATION','HTTP_X_HTTP_METHOD_OVERRIDE')),
                'HOST_DENIED')
            token=self.base._cookie(env)
            if path.endswith('/capabilities'):
                sc.need(env.get('REQUEST_METHOD')=='GET' and env.get('CONTENT_LENGTH') in (None,'','0'))
                actor=self.access.owner(self.auth.session(token))
                sc.need(self.access.grant(actor,'registry','list_components',self.target,
                        {'repository':self.repository}) is True,'POLICY_DENIED')
                return reply(start,200,{'configured':True,'repository':self.repository,
                      'target':self.target,'discoveryConfigured':self.discovery is not None})
            sc.need(env.get('REQUEST_METHOD')=='POST' and env.get('HTTP_ORIGIN')==self.base.origin,
                    'ORIGIN_DENIED')
            csrf=env.get('HTTP_X_FORTIS_CSRF')
            sc.need(bool(csrf),'CSRF_REQUIRED')
            actor=self.access.owner(self.auth.session(token,csrf))
            body=self.base._json(env)
            sc.need(not self.base.read_only_banner,'OWNER_OPERATION_WRITE_NOT_ENABLED')
            if path.endswith('/discover'):
                sc.need(body=={} and callable(self.discovery),'DISCOVERY_UNAVAILABLE')
                result=self.access.discover(actor,repository=self.repository,target=self.target,reader=self.discovery)
            elif path.startswith((PREFIX+'/register-confirmed/',PREFIX+'/register-external/')):
                from .maintenance_gate import Coordinate
                from .merge_register import MergeRegisterAdapter
                owner=self.auth.session(token,csrf)['owner']
                fields=('requestId',) if path.endswith('/begin') else (
                    'requestId','fingerprint','ceremonyId','response')
                sc.fields(body,fields)
                ident=body['requestId']
                sc.uuid_id(ident)
                row=self.core._read(ident)
                request=row['request']
                adapter=self.core.adapters.get('release')
                sc.need(type(adapter) is MergeRegisterAdapter and adapter.is_group(request)
                        and request['target']==self.target and request['params']['repository']==self.repository
                        and row['actor']==actor,'MERGE_REGISTRATION_NOT_AVAILABLE')
                self.access.authorize(actor,request,read=False)
                with self.access.gate.reserve(Coordinate('registry','register_merge')):
                    if path.startswith(PREFIX+'/register-external/'):
                        if path.endswith('/begin'):
                            result=adapter.external_context(ident,actor,owner)
                            if 'state' not in result:
                                fingerprint=result['fingerprint']
                                result={**self.auth.begin_decision(token,ident,fingerprint,'approve'),
                                        'fingerprint':fingerprint,
                                        'mergeSha':result['observation']['mergeSha']}
                        else:
                            result=adapter.register_external(ident,actor,owner,body['fingerprint'],
                                {'session':token,'ceremonyId':body['ceremonyId'],'response':body['response']})
                    elif path.endswith('/begin'):
                        _,req,fingerprint=adapter.registration_context(ident,owner)
                        result={**self.auth.begin_decision(token,ident,fingerprint,'approve'),
                                'fingerprint':fingerprint,'mergeSha':req['observation']['mergeSha']}
                    else:
                        updated=adapter.register_confirmed(ident,owner,body['fingerprint'],
                            {'session':token,'ceremonyId':body['ceremonyId'],'response':body['response']})
                        result=self.access.public(updated)
            elif path.endswith('/repropose'):
                sc.fields(body,('requestId',))
                result=self.access.repropose(actor,request_id=body['requestId'],
                    repository=self.repository,target=self.target,reader=self.discovery)
            else:
                sc.need(body.get('target')==self.target,'POLICY_DENIED')
                result=(self.access.read(actor,body) if path.endswith('/read') else
                        self.access.submit(actor,body))
            return reply(start,200,result)
        except (Conflict,Stale):
            return reply(start,409,{'error':'REQUEST_CHANGED'})
        except Denied as exc:
            code=str(exc)
            return reply(start,403,{'error':code if code in ('POLICY_DENIED','PROVIDER_UNAVAILABLE',
                'RELEASE_MAINTENANCE','MAINTENANCE_STATE_UNKNOWN','OWNER_SESSION_REQUIRED',
                'READ_APPROVAL_UNAVAILABLE','CSRF_REQUIRED','ORIGIN_DENIED',
                'MERGE_REPROPOSAL_NOT_AVAILABLE','MERGE_REGISTRATION_NOT_AVAILABLE',
                'MERGE_EXTERNAL_NOT_AVAILABLE','SEMANTIC_EXTERNAL_SOURCE_SCOPE_DENIED') else 'REGISTRY_DENIED'})
        except (ApprovalError,ValueError,TypeError,KeyError,UnicodeError):
            return reply(start,400,{'error':'REQUEST_INVALID'})
        except Exception:
            return reply(start,500,{'error':'OUTCOME_UNCONFIRMED'})

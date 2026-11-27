"""Typed semantic client on existing machine TLS routes; no provider secrets."""
from ..extensions.semantic_access import validate
from ..integrations.registry_contracts import semantic_contract as sc
from .gateway_transport import GatewayTransport


class RegistrySemanticClient:
    def __init__(self,gateway):
        sc.need(type(gateway) is GatewayTransport)
        self.gateway=gateway

    def read(self,operation,target,params,*,request_id,reason):
        q=validate(dict(requestId=request_id,service='registry',operation=operation,
                        target=target,params=params,reason=reason),read=True)
        # One-shot READ ASK may already be consumed if response is lost.
        # Do not use generic automatic read retry for this semantic surface.
        result=self.gateway._open_once('POST','/v1/reads',q,accept_202=True)
        sc.need(result.get('requestId')==request_id and result.get('service')=='registry'
                and result.get('operation')==operation)
        return result

    def submit(self,service,operation,target,params,*,request_id,reason):
        q=validate(dict(requestId=request_id,service=service,operation=operation,
                        target=target,params=params,reason=reason),read=False)
        result=self.gateway.post('/v1/actions',q,accept_202=True)
        sc.fields(result,('requestId','state'))
        sc.uuid_id(result['requestId'])
        return result

"""One Repo client for all declared integrations; provider credentials never enter it."""
import uuid
from ..clients.gateway_transport import GatewayTransport
from .ingress import PATHS
from .model import check


class IntegrationTransport(GatewayTransport):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.post_paths |= PATHS


class IntegrationClient:
    def __init__(self, *, gateway):
        self.gateway = gateway

    def catalog(self):
        return self.gateway.post('/v1/integrations/catalog', {})

    def call(self, service, operation, target, params, *, reason, request_id=None):
        request_id = str(uuid.uuid4()) if request_id is None else request_id
        return self.gateway.post('/v1/integrations/call', dict(requestId=request_id,
            service=service, operation=operation, target=target, params=params, reason=reason), accept_202=True)

    def result(self, request_id, *, reconcile=False):
        check(type(reconcile) is bool, 'INTEGRATION_RESULT_SCHEMA')
        return self.gateway.post('/v1/integrations/result', dict(requestId=request_id, reconcile=reconcile), accept_202=True)


def default_client(endpoint='https://host.docker.internal:19204'):
    return IntegrationClient(gateway=IntegrationTransport(endpoint=endpoint,
        max_response_bytes=262144))

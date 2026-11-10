"""Typed analysis client using only the existing Gateway machine transport."""
import uuid
from ....clients.gateway_transport import GatewayTransport
from ....core import Denied
from ....repo_action_contract import validate_read_query, validate_intent
from ..analysis_contract import READ_NAMES, ACTION_NAMES
from ..gateway.analysis_reader import validate_result


class SonarAnalysisClient:
    def __init__(self, gateway=None):
        self.gateway = gateway or GatewayTransport(max_response_bytes=262144)

    def read(self, operation, project, params):
        if operation not in READ_NAMES: raise Denied('SONAR_ANALYSIS_OPERATION_DENIED')
        body = dict(requestId=str(uuid.uuid4()), service='sonarcloud', operation=operation,
                    target=project, params=params, reason='Inspect Sonar analysis evidence')
        validate_read_query(body)
        result = self.gateway.post('/v1/reads', body)
        if type(result) is not dict or set(result) != {'requestId', 'service', 'operation', 'data'}:
            raise Denied('SONAR_ANALYSIS_RESPONSE_INVALID')
        if any(result[k] != body[k] for k in ('requestId', 'service', 'operation')):
            raise Denied('SONAR_ANALYSIS_RESPONSE_MISMATCH')
        validate_result(operation, result['data'])
        if result['data']['projectKey'] != project or result['data']['context'] != params.get('context', {}):
            raise Denied('SONAR_ANALYSIS_CONTEXT_MISMATCH')
        return result['data']['data']

    def propose(self, operation, issue, params, *, request_id, reason):
        if operation not in ACTION_NAMES | {'accept_issue'}: raise Denied('SONAR_ANALYSIS_OPERATION_DENIED')
        if operation == 'accept_issue' and 'comment' not in params:
            params = dict(params, comment=reason)
        body = dict(requestId=request_id, service='sonarcloud', operation=operation,
                    target=issue, params=params, reason=reason)
        validate_intent(body)
        result = self.gateway.post('/v1/actions', body, accept_202=True)
        if (type(result) is not dict or set(result) != {'requestId', 'state'} or result['requestId'] != request_id or
                type(result['state']) is not str or result['state'] not in
                {'PENDING', 'APPROVED', 'DISPATCHED', 'EXECUTED', 'REJECTED', 'DENIED', 'EXPIRED', 'STALE', 'UNCERTAIN', 'REVOKED', 'CANCELLED_BEFORE_DISPATCH'}):
            raise Denied('SONAR_ANALYSIS_RESPONSE_INVALID')
        return result

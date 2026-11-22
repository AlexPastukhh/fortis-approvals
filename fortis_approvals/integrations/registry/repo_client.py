"""Typed Repo-side client of the existing *candidate-only* Registry READ path.

The caller supplies an authenticated Gateway transport. This never creates
grants, credentials, a runtime listener or Registry write authority.
Unreachable/denied/ASK reads remain errors, not an empty release queue.
"""
import uuid

from ...core import Denied
from ...repo_action_contract import validate_read_query
from .read_contract import (
    GATEWAY_TARGET, REPOSITORY, validate_gateway_read_projection,
)

_OPS = frozenset((
    'candidate_head', 'candidate_list_desired',
    'candidate_original_operation',
))


class RegistryCandidateClient:
    """Read only SOURCE_ONLY_CANDIDATE_READ via Gateway /v1/reads."""

    def __init__(self, gateway):
        if not callable(getattr(gateway, 'post', None)):
            raise Denied('REGISTRY_CLIENT_GATEWAY_REQUIRED')
        self._gateway = gateway

    def _read(self, operation, params):
        if operation not in _OPS:
            raise Denied('REGISTRY_CLIENT_OPERATION_DISABLED')
        request = {
            'requestId': str(uuid.uuid4()), 'service': 'registry',
            'operation': operation, 'target': GATEWAY_TARGET,
            'params': {'repository': REPOSITORY, **params},
            'reason': 'Read bounded local Registry candidate, not live desired',
        }
        validate_read_query(request)
        result = self._gateway.post('/v1/reads', request, accept_202=True)
        if (type(result) is not dict
                or set(result) != {'requestId', 'service', 'operation', 'data'}
                or result['requestId'] != request['requestId']
                or result['service'] != 'registry'
                or result['operation'] != operation):
            raise Denied('REGISTRY_CLIENT_RESPONSE_DENIED')
        return validate_gateway_read_projection(operation, result['data'])

    def head(self):
        return self._read('candidate_head', {})

    def list_desired(self, *, limit=20, cursor=None):
        """Bounded candidate page, never registry.list_records."""
        result = self._read('candidate_list_desired', {
            'limit': limit, 'cursor': cursor,
        })
        if len(result['data']['records']) > limit:
            raise Denied('REGISTRY_CLIENT_PAGE_LIMIT_DENIED')
        return result

    def original_operation(self, operation_id):
        """Recover only the original local UUID result (not a write receipt)."""
        return self._read('candidate_original_operation', {
            'operationId': operation_id,
        })

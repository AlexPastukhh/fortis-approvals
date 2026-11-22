"""Typed Repo-side client of the existing *candidate-only* Registry READ path.

The caller supplies an authenticated Gateway transport. This never creates
grants, credentials, a runtime listener or Registry write authority.
Unreachable/denied/ASK reads remain errors, not an empty release queue.
"""
import re
import uuid

from ...core import Denied, Stale
from ...repo_action_contract import validate_read_query
from .read_contract import (
    GATEWAY_TARGET, REPOSITORY, _uuid, validate_gateway_read_projection,
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

    def observe_e1_candidate(self, *, expected_source_sha, original_operation_id,
                             page_limit=20):
        """Bounded live READ chain; NOT host acceptance or a Registry queue.

        Caller pins the intended source and original UUID independently.
        Any source/revision drift, truncated page, or absence of a real
        persisted candidate record is STOP, never 'nothing to deploy'.
        """
        if (type(expected_source_sha) is not str or
                re.fullmatch(r'[0-9a-f]{40}', expected_source_sha) is None or
                not _uuid(original_operation_id) or
                type(page_limit) is not int or not 1 <= page_limit <= 100):
            raise Denied('REGISTRY_E1_READBACK_INPUT_DENIED')
        head = self.head()
        cp = head['data']['localCheckpoint']
        if (cp['revision'] == 0 or
                head['data']['candidateCursor'] != expected_source_sha):
            raise Denied('REGISTRY_E1_READBACK_SOURCE_MISMATCH')
        operation = self.original_operation(original_operation_id)['data']
        if (operation['localCheckpoint'] != cp or
                operation['candidateSourceSha'] != expected_source_sha):
            raise Stale('REGISTRY_E1_READBACK_OPERATION_STALE')
        records, cursors = set(), set()
        cursor = None
        pages = 0
        while True:
            if pages >= 10:
                raise Denied('REGISTRY_E1_READBACK_PAGE_BOUND')
            page = self.list_desired(limit=page_limit, cursor=cursor)['data']
            pages += 1
            if (page['localRevision'] != cp['revision'] or
                    page['localEventDigest'] != cp['eventDigest'] or
                    page['candidateSourceSha'] != expected_source_sha):
                raise Stale('REGISTRY_E1_READBACK_PAGE_STALE')
            for row in page['records']:
                if row['recordId'] in records:
                    raise Denied('REGISTRY_E1_READBACK_DUPLICATE_RECORD')
                records.add(row['recordId'])
            next_cursor = page['nextCursor']
            if next_cursor is None:
                break
            if next_cursor in cursors or not page['records']:
                raise Denied('REGISTRY_E1_READBACK_CURSOR_CYCLE')
            cursors.add(next_cursor)
            cursor = next_cursor
        after = self.head()
        if (after['data']['localCheckpoint'] != cp or
                after['data']['candidateCursor'] != expected_source_sha or
                after['instanceId'] != head['instanceId'] or
                after['scopeDigest'] != head['scopeDigest']):
            raise Stale('REGISTRY_E1_READBACK_HEAD_CHANGED')
        if (not records or not operation['recordIds'] or
                not set(operation['recordIds']) <= records):
            raise Denied('REGISTRY_E1_READBACK_NO_MATCHING_CANDIDATES')
        return {
            'result': 'SOURCE_ONLY_E1_GATEWAY_READ_OBSERVED',
            'repository': REPOSITORY,
            'selectedMainSha': expected_source_sha,
            'localRevision': cp['revision'],
            'localEventDigest': cp['eventDigest'],
            'originalOperationId': original_operation_id,
            'candidateCount': len(records), 'pages': pages,
            'crossUidHostVerified': False, 'evidenceVerified': False,
            'admissionAllowed': False, 'writeEnabled': False,
            'functionalV1Accepted': False,
        }

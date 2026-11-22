"""Shared P5 Registry READ method/DTO contract for the Gateway image.

A source-only schema is NOT a method grant, runtime listener, writer or
owner authorization. Gateway imports this small contract; the Registry
source-only implementation itself stays outside the current Gateway image.
"""
import re
import uuid

from ...core import Denied, canonical

REPOSITORY = 'AlexPastukhh/fortis-approvals'
GATEWAY_TARGET = 'fortis-approvals'
READS = {
    'registry.capabilities': ('repository',),
    'registry.preview_merged': ('repository', 'evidenceId', 'evidenceDigest'),
    'registry.get_operation': ('repository', 'operationId'),
    'registry.get_record': ('repository', 'recordId'),
    'registry.list_records': ('repository', 'limit', 'cursor'),
}
GATEWAY_READ_OPERATIONS = frozenset(
    ('registry', name.removeprefix('registry.')) for name in READS
)
MISSING = (
    'HISTORICAL_EFFECTIVE_POLICY_AND_MERGE_CUTOFF',
    'COMPLETE_BASELINE_AND_SELECTED_SOURCE_COVERAGE',
    'DEPENDENCY_CLOSURE_PROVENANCE',
    'OWNER_COMPONENT_ENVIRONMENT_BINDINGS',
    'AUTHENTICATED_PROTECTED_COLLECTOR',
    'PROTECTED_REGISTRY_STATE_AND_RECOVERY',
)


def _need(condition, code):
    if not condition:
        raise Denied(code)


def _uuid(value):
    try:
        return type(value) is str and str(uuid.UUID(value)) == value
    except (TypeError, ValueError, AttributeError):
        return False


def _hex(value, size):
    return type(value) is str and re.fullmatch(
        '[0-9a-f]{' + str(size) + '}', value) is not None


def validate_gateway_read_query(operation, target, params):
    """Closed registry target and typed payload; no actor, path or credentials."""
    name = ('registry.' + operation) if type(operation) is str else None
    _need(target == GATEWAY_TARGET and type(target) is str
          and name in READS, 'REGISTRY_GATEWAY_SCOPE_DENIED')
    _need(type(params) is dict and set(params) == set(READS[name])
          and params.get('repository') == REPOSITORY,
          'REGISTRY_PARAMS_INVALID')
    for field in ('operationId', 'evidenceId'):
        if field in params:
            _need(_uuid(params[field]), 'REGISTRY_PARAMS_INVALID')
    for field in ('evidenceDigest', 'recordId'):
        if field in params:
            _need(_hex(params[field], 64), 'REGISTRY_PARAMS_INVALID')
    if operation == 'list_records':
        _need(type(params['limit']) is int and 1 <= params['limit'] <= 100
              and (params['cursor'] is None
                   or type(params['cursor']) is str
                   and re.fullmatch('[A-Za-z0-9_-]{1,256}',
                                    params['cursor']) is not None),
              'REGISTRY_PARAMS_INVALID')
    try:
        _need(len(canonical({'operation': name, 'params': params}).encode('utf-8'))
              <= 4096, 'REGISTRY_PARAMS_INVALID')
    except (TypeError, ValueError, UnicodeError, RecursionError, OverflowError):
        raise Denied('REGISTRY_PARAMS_INVALID') from None
    return name, params


def validate_gateway_read_projection(operation, data):
    """Allow only explicit SOURCE_ONLY capabilities or blocked evidence.

    A future authoritative queue/result needs its own reviewed contract.
    """
    _need(type(operation) is str and type(data) is dict,
          'REGISTRY_GATEWAY_PROJECTION_DENIED')
    if operation == 'capabilities':
        _need(set(data) == {'schemaVersion', 'repository', 'activationState',
                           'liveOperations', 'candidateReadOperations',
                           'writeEnabled', 'storeAvailable',
                           'authenticatedCollectorAvailable'}
              and type(data['schemaVersion']) is int and data['schemaVersion'] == 1
              and data['repository'] == REPOSITORY
              and data['activationState'] == 'SOURCE_ONLY'
              and data['liveOperations'] == []
              and data['candidateReadOperations'] == sorted(READS)
              and data['writeEnabled'] is False
              and data['storeAvailable'] is False
              and data['authenticatedCollectorAvailable'] is False,
              'REGISTRY_GATEWAY_PROJECTION_DENIED')
    elif operation == 'preview_merged':
        allowed = set(MISSING) | {'PROTECTED_REGISTRY_REVIEW_POLICY_ACCEPTANCE',
                                  'EXTERNAL_TARGET_DEPENDENCY_UNRESOLVED',
                                  'PR_DEPENDENCY_UNRESOLVED'}
        gaps = data.get('missingProofs')
        _need(set(data) == {'result', 'evidenceClass', 'repository',
                           'evidenceId', 'evidenceDigest', 'selectedMainSha',
                           'number', 'observedClassification', 'missingProofs',
                           'evidenceVerified', 'admissionAllowed',
                           'deploymentAllowed'}
              and data['result'] == 'BLOCKED_EVIDENCE_GAP'
              and data['evidenceClass'] == 'SOURCE_CANDIDATE_ONLY'
              and data['repository'] == REPOSITORY
              and _uuid(data['evidenceId'])
              and _hex(data['evidenceDigest'], 64)
              and _hex(data['selectedMainSha'], 40)
              and type(data['number']) is int and 0 < data['number'] <= 1_000_000
              and data['observedClassification'] in ('deployment', 'no-deployment')
              and type(gaps) is list and all(type(g) is str for g in gaps)
              and gaps == sorted(set(gaps)) and set(MISSING) <= set(gaps)
              and set(gaps) <= allowed
              and data['evidenceVerified'] is False
              and data['admissionAllowed'] is False
              and data['deploymentAllowed'] is False,
              'REGISTRY_GATEWAY_PROJECTION_DENIED')
    else:
        # get/list must not fabricate NOT_FOUND, a record or an empty queue.
        raise Denied('REGISTRY_STORAGE_UNAVAILABLE')
    _need(len(canonical(data).encode('utf-8')) <= 8192,
          'REGISTRY_GATEWAY_PROJECTION_DENIED')
    return data

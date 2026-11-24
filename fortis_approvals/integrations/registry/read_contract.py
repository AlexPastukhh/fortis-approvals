"""Shared P5 Registry READ method/DTO contract for the Gateway image.

A source-only schema is NOT a method grant, runtime listener, writer or
owner authorization. Gateway imports this small contract; the Registry
source-only implementation itself stays outside the current Gateway image.
"""
import hashlib
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
    # Explicit diagnostics. NEVER alias candidate_* to authoritative
    # registry.list_records/get_operation or grant the methods by default.
    'registry.candidate_head': ('repository',),
    'registry.candidate_list_desired': ('repository', 'limit', 'cursor'),
    'registry.candidate_original_operation': ('repository', 'operationId'),
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
    if operation in ('list_records', 'candidate_list_desired'):
        _need(type(params['limit']) is int and 1 <= params['limit'] <= 100
              and (params['cursor'] is None
                   or type(params['cursor']) is str
                   and re.fullmatch(
                       ('[0-9a-f]{64}_[0-9a-f]{64}'
                        if operation == 'candidate_list_desired'
                        else '[A-Za-z0-9_-]{1,256}'),
                       params['cursor']) is not None),
              'REGISTRY_PARAMS_INVALID')
    try:
        _need(len(canonical({'operation': name, 'params': params}).encode('utf-8'))
              <= 4096, 'REGISTRY_PARAMS_INVALID')
    except (TypeError, ValueError, UnicodeError, RecursionError, OverflowError):
        raise Denied('REGISTRY_PARAMS_INVALID') from None
    return name, params



_CANDIDATE_FLAGS = (
    'authenticatedCollectorAvailable', 'admissionAllowed',
    'deploymentAllowed', 'writeEnabled', 'liveRegistryAvailable',
    'rollbackProtected',
)
_CANDIDATE_ACTIONS = frozenset((
    'image-rebuild', 'config-deploy', 'windows-update',
    'package-build', 'migration-required',
))


def _candidate_checkpoint(cp, instance, scope):
    return (type(cp) is dict and set(cp) == {
        'schemaVersion', 'instanceId', 'scopeDigest', 'revision',
        'eventDigest',
    } and type(cp['schemaVersion']) is int
        and cp['schemaVersion'] == 1
        and cp['instanceId'] == instance
        and cp['scopeDigest'] == scope
        and type(cp['revision']) is int
        and 0 <= cp['revision'] <= 64
        and _hex(cp['eventDigest'], 64))


def _candidate_record(row):
    if type(row) is not dict or set(row) != {
        'recordId', 'identity', 'requiredActions', 'planningState',
        'actual', 'evidenceVerified',
    }:
        return False
    identity = row['identity']
    if type(identity) is not dict or set(identity) != {
        'repository', 'targetId', 'environment', 'desiredSourceSha',
        'catalogCommitSha', 'catalogSha256',
    }:
        return False
    actions = row['requiredActions']
    return (
        identity['repository'] == REPOSITORY
        and all(type(identity[k]) is str
                and re.fullmatch(r'[a-z0-9][a-z0-9._/-]{0,127}', identity[k])
                and '..' not in identity[k] and '//' not in identity[k]
                for k in ('targetId', 'environment'))
        and all(_hex(identity[k], 40) for k in (
            'desiredSourceSha', 'catalogCommitSha'))
        and _hex(identity['catalogSha256'], 64)
        and _hex(row['recordId'], 64)
        and row['recordId'] == hashlib.sha256(
            canonical(identity).encode('utf-8')).hexdigest()
        and type(actions) is list and bool(actions)
        and len(actions) <= len(_CANDIDATE_ACTIONS)
        and all(type(action) is str for action in actions)
        and actions == sorted(set(actions))
        and set(actions) <= _CANDIDATE_ACTIONS
        and row['planningState'] == 'PLANNED_UNVERIFIED'
        and row['actual'] is None
        and row['evidenceVerified'] is False
    )


def _validate_candidate_projection(operation, result):
    """Never promote local SQLite candidate into installed/admitted records."""
    _need(set(result) == {
        'schemaVersion', 'result', 'candidateOperation', 'repository',
        'instanceId', 'scopeDigest', 'data', *_CANDIDATE_FLAGS,
    } and type(result['schemaVersion']) is int
        and result['schemaVersion'] == 1
        and result['result'] == 'SOURCE_ONLY_CANDIDATE_READ'
        and result['candidateOperation'] == operation
        and result['repository'] == REPOSITORY
        and _uuid(result['instanceId'])
        and _hex(result['scopeDigest'], 64)
        and all(result[field] is False for field in _CANDIDATE_FLAGS),
        'REGISTRY_GATEWAY_PROJECTION_DENIED')
    data = result['data']
    _need(type(data) is dict and data.get('integrityModel') ==
          'LOCAL_EVENT_CHAIN_ONLY',
          'REGISTRY_GATEWAY_PROJECTION_DENIED')
    if operation == 'candidate_head':
        _need(set(data) == {
            'result', 'localCheckpoint', 'candidateCursor',
            'integrityModel', 'evidenceVerified', 'admissionAllowed',
            'deploymentAllowed',
        } and data['result'] == 'LOCAL_SOURCE_CANDIDATE_HEAD'
            and _candidate_checkpoint(
                data['localCheckpoint'], result['instanceId'],
                result['scopeDigest'])
            and _hex(data['candidateCursor'], 40)
            and all(data[f] is False for f in (
                'evidenceVerified', 'admissionAllowed', 'deploymentAllowed')),
              'REGISTRY_GATEWAY_PROJECTION_DENIED')
    elif operation == 'candidate_list_desired':
        rows = data.get('records')
        _need(set(data) == {
            'result', 'localRevision', 'localEventDigest',
            'candidateSourceSha', 'records', 'nextCursor', 'integrityModel',
            'evidenceVerified', 'admissionAllowed', 'deploymentVerified',
            'writeEnabled',
        } and data['result'] == 'LOCAL_DESIRED_CANDIDATE_PAGE'
            and type(data['localRevision']) is int
            and 0 <= data['localRevision'] <= 64
            and _hex(data['localEventDigest'], 64)
            and _hex(data['candidateSourceSha'], 40)
            and type(rows) is list and len(rows) <= 100
            and all(_candidate_record(row) for row in rows)
            and len({row['recordId'] for row in rows}) == len(rows)
            and (data['nextCursor'] is None or
                 type(data['nextCursor']) is str and
                 re.fullmatch(r'[0-9a-f]{64}_[0-9a-f]{64}',
                              data['nextCursor']) is not None)
            and all(data[f] is False for f in (
                'evidenceVerified', 'admissionAllowed', 'deploymentVerified',
                'writeEnabled')),
              'REGISTRY_GATEWAY_PROJECTION_DENIED')
    elif operation == 'candidate_original_operation':
        cp = data.get('localCheckpoint')
        ids = data.get('recordIds')
        links = data.get('supersessions')
        _need(set(data) == {
            'result', 'operationId', 'localCheckpoint',
            'candidateSourceSha', 'recordIds', 'supersessions',
            'receiptDigest', 'integrityModel', 'evidenceVerified',
            'admissionAllowed', 'deploymentAllowed',
        } and data['result'] == 'LOCAL_DESIRED_CANDIDATE_COMMITTED'
            and _uuid(data['operationId'])
            and _candidate_checkpoint(cp, result['instanceId'],
                                      result['scopeDigest'])
            and cp['revision'] > 0
            and _hex(data['candidateSourceSha'], 40)
            and _hex(data['receiptDigest'], 64)
            and type(ids) is list and len(ids) <= 200
            and all(_hex(row, 64) for row in ids)
            and ids == sorted(set(ids))
            and type(links) is list and len(links) <= 200
            and all(type(link) is dict and set(link) == {
                'fromRecordId', 'toRecordId'}
                and all(_hex(link[k], 64) for k in link)
                for link in links)
            and all(data[f] is False for f in (
                'evidenceVerified', 'admissionAllowed', 'deploymentAllowed')),
              'REGISTRY_GATEWAY_PROJECTION_DENIED')
    else:
        raise Denied('REGISTRY_GATEWAY_PROJECTION_DENIED')


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
    elif operation.startswith('candidate_'):
        _validate_candidate_projection(operation, data)
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


# Internal Functional V1 planner handoff. Never a public READ or Repo action.
# HMAC authenticates the private Gateway/Registry pair in this limited local
# trust model; it is not an independent owner signature or rollback witness.
PLANNER_OPERATION = 'registry.ingest_merged'
PLANNER_ACTOR = 'release-registry-planner-v1'
PLANNER_FRAME_LIMIT = 262144


def planner_params(params):
    _need(type(params) is dict and set(params) == {
        'repository', 'operationId', 'evidenceId', 'evidenceDigest', 'expectedRevision'}
        and params['repository'] == REPOSITORY
        and _uuid(params['operationId']) and _uuid(params['evidenceId'])
        and _hex(params['evidenceDigest'], 64)
        and type(params['expectedRevision']) is int
        and 0 <= params['expectedRevision'] < 64,
        'REGISTRY_PLANNER_PARAMS_DENIED')
    return params


def planner_mac(key, value):
    import hmac
    _need(type(key) is bytes and len(key) == 32, 'REGISTRY_PLANNER_KEY_DENIED')
    return hmac.new(key, b'fortis-functional-v1-planner\0' +
                    canonical(value).encode('utf-8'), hashlib.sha256).hexdigest()


def planner_frame(key, *, instance_id, scope_digest, params, evidence):
    """Create private authenticated transport, never accept a caller plan."""
    planner_params(params)
    _need(_uuid(instance_id) and _hex(scope_digest, 64), 'REGISTRY_PLANNER_SCOPE_DENIED')
    body = {'schemaVersion': 1, 'operation': PLANNER_OPERATION,
            'instanceId': instance_id, 'scopeDigest': scope_digest,
            'requestId': params['operationId'], 'params': params, 'evidence': evidence}
    frame = {**body, 'mac': planner_mac(key, body)}
    _need(len(canonical(frame).encode('utf-8')) <= PLANNER_FRAME_LIMIT,
          'REGISTRY_PLANNER_FRAME_LIMIT')
    return frame


def verify_planner_frame(key, frame, *, instance_id, scope_digest):
    import hmac
    _need(type(frame) is dict and set(frame) == {
        'schemaVersion', 'operation', 'instanceId', 'scopeDigest',
        'requestId', 'params', 'evidence', 'mac'}
        and _hex(frame['mac'], 64), 'REGISTRY_PLANNER_FRAME_DENIED')
    body = {k:v for k,v in frame.items() if k != 'mac'}
    _need(hmac.compare_digest(frame['mac'], planner_mac(key, body)),
          'REGISTRY_PLANNER_AUTHENTICATION_DENIED')
    params = planner_params(body['params'])
    _need(type(body['schemaVersion']) is int and body['schemaVersion'] == 1
          and body['operation'] == PLANNER_OPERATION
          and body['instanceId'] == instance_id
          and body['scopeDigest'] == scope_digest
          and body['requestId'] == params['operationId'],
          'REGISTRY_PLANNER_SCOPE_DENIED')
    evidence = body['evidence']
    try:
        audit = evidence['plan']['observation']['mergeAudit']
        _need(type(audit) is list and len(audit) == 1
              and audit[0]['evidenceId'] == params['evidenceId']
              and audit[0]['evidenceDigest'] == params['evidenceDigest']
              and evidence['evidenceId'] == params['evidenceId'],
              'REGISTRY_PLANNER_ORIGINAL_EVIDENCE_DENIED')
    except (KeyError, TypeError, IndexError):
        raise Denied('REGISTRY_PLANNER_ORIGINAL_EVIDENCE_DENIED') from None
    return params, evidence


def private_planner_key(path, expected_digest=None):
    """Read only an owner-provisioned exact 32-byte private key, never log it."""
    import os
    import stat
    from pathlib import Path
    path = Path(path)
    _need(path.is_absolute() and path.parent.resolve() == path.parent,
          'REGISTRY_PLANNER_KEY_PATH')
    try:
        parent = path.parent.lstat()
        _need(stat.S_ISDIR(parent.st_mode) and parent.st_uid == os.geteuid()
              and stat.S_IMODE(parent.st_mode) == 0o700, 'REGISTRY_PLANNER_KEY_PATH')
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        with os.fdopen(fd, 'rb') as stream:
            row = os.fstat(stream.fileno())
            _need(stat.S_ISREG(row.st_mode) and row.st_uid == os.geteuid()
                  and stat.S_IMODE(row.st_mode) == 0o600 and row.st_nlink == 1
                  and row.st_size == 32, 'REGISTRY_PLANNER_KEY_DENIED')
            key = stream.read(33)
        _need(len(key) == 32 and (expected_digest is None or
              hashlib.sha256(key).hexdigest() == expected_digest),
              'REGISTRY_PLANNER_KEY_DENIED')
        return key
    except OSError:
        raise Denied('REGISTRY_PLANNER_KEY_UNAVAILABLE') from None

"""Registry semantic v1 input contracts, shared by Gateway and Registry.

Validation is not authorization, source coverage, evidence verification or
permission to execute. The historical candidate READ DTOs are unchanged.
"""
import hashlib
import re
import uuid

from ...core import Denied, canonical, loads_strict

VERSION = 1
MAX_GROUP = 20
MAX_READ_BYTES = 4096
MAX_WRITE_BYTES = 32768
MAX_REVISION = 2**63 - 1
READ_METHODS = frozenset({
    'list_components', 'get_component', 'plan_batch', 'list_history',
    'get_operation', 'list_active_releases', 'get_maintenance_status',
})
WRITE_METHODS = frozenset({
    'begin_release', 'report_release_result',
    'begin_release_group', 'report_release_results',
})
_NAME = re.compile(r'[a-z0-9][a-z0-9._-]{0,127}\Z')
_REPO_PART = re.compile(r'[A-Za-z0-9][A-Za-z0-9._-]{0,99}\Z')
_CONTEXTS = frozenset({'initial', 'release', 'external', 'historical', 'rollback'})
_OUTCOMES = frozenset({'REPORTED_COMPLETE', 'REPORTED_FAILED', 'UNKNOWN'})


def need(condition, code='REGISTRY_SEMANTIC_PARAMS_INVALID'):
    if not condition:
        raise Denied(code)


def fields(value, expected):
    need(type(value) is dict and set(value) == set(expected))


def digest(value):
    return hashlib.sha256(canonical(value).encode('utf-8')).hexdigest()


def hex_id(value, size):
    need(type(value) is str and re.fullmatch('[0-9a-f]{%d}' % size, value))


def uuid_id(value):
    try:
        valid = type(value) is str and str(uuid.UUID(value)) == value
    except (ValueError, TypeError, AttributeError):
        valid = False
    need(valid)


def revision(value):
    need(type(value) is int and 0 <= value <= MAX_REVISION)


def name(value):
    need(type(value) is str and _NAME.fullmatch(value) and '..' not in value)


def repository(value):
    need(type(value) is str and len(value) <= 201)
    parts = value.split('/')
    need(len(parts) == 2 and all(_REPO_PART.fullmatch(x) and '..' not in x for x in parts))


def subject(value):
    fields(value, ('repository', 'targetId', 'environment'))
    repository(value['repository'])
    name(value['targetId'])
    name(value['environment'])


def subject_key(value):
    subject(value)
    return (value['repository'].lower(), value['targetId'], value['environment'])


def source(value):
    fields(value, ('sourceSha', 'catalogCommitSha', 'catalogSha256', 'artifactSha256'))
    hex_id(value['sourceSha'], 40)
    hex_id(value['catalogCommitSha'], 40)
    hex_id(value['catalogSha256'], 64)
    if value['artifactSha256'] is not None:
        hex_id(value['artifactSha256'], 64)


def guard(value):
    fields(value, ('targetRevision', 'desiredRecordId', 'catalogSha256'))
    revision(value['targetRevision'])
    if value['desiredRecordId'] is not None:
        hex_id(value['desiredRecordId'], 64)
    hex_id(value['catalogSha256'], 64)


def begin_item(value):
    fields(value, ('subject', 'source', 'expected'))
    subject(value['subject'])
    source(value['source'])
    guard(value['expected'])
    need(value['expected']['desiredRecordId'] is not None)
    need(value['expected']['catalogSha256'] == value['source']['catalogSha256'])


def report_item(value):
    fields(value, ('subject', 'source', 'expected', 'attemptId', 'context', 'outcome',
                   'assertion', 'observedAt', 'evidenceDigests'))
    subject(value['subject'])
    # An unknown source must be represented explicitly, never guessed.
    # An attempt-linked report still needs its exact pinned source.
    if value['source'] is None:
        need(value['outcome'] == 'UNKNOWN' and value['attemptId'] is None
             and value['context'] in ('initial', 'external'))
    else:
        source(value['source'])
    guard(value['expected'])
    if value['attemptId'] is not None:
        uuid_id(value['attemptId'])
    need(type(value['context']) is str and value['context'] in _CONTEXTS)
    need(type(value['outcome']) is str and value['outcome'] in _OUTCOMES)
    # Caller describes an assertion, never a verified identity or authorization.
    need(type(value['assertion']) is str and 0 < len(value['assertion']) <= 2000)
    # UTC epoch seconds, observation time is an assertion, not causal proof.
    if value['observedAt'] is not None:
        revision(value['observedAt'])
    refs = value['evidenceDigests']
    need(type(refs) is list and len(refs) <= 16)
    for ref in refs:
        hex_id(ref, 64)
    need(refs == sorted(set(refs)))
    need(value['context'] != 'historical' or value['attemptId'] is None)


def group_items(items, validator):
    need(type(items) is list and 2 <= len(items) <= MAX_GROUP)
    for item in items:
        validator(item)
    keys = [subject_key(item['subject']) for item in items]
    need(keys == sorted(set(keys)), 'REGISTRY_GROUP_SUBJECT_ORDER_OR_DUPLICATE')


def _page(value):
    fields(value, ('limit', 'cursor'))
    need(type(value['limit']) is int and 1 <= value['limit'] <= 100)
    cursor = value['cursor']
    need(cursor is None or type(cursor) is str and re.fullmatch('[A-Za-z0-9_-]{1,256}', cursor))


def _read(operation, params):
    if operation in ('list_components', 'list_active_releases'):
        fields(params, ('repository', 'page'))
        repository(params['repository'])
        _page(params['page'])
    elif operation == 'get_component':
        fields(params, ('subject',))
        subject(params['subject'])
    elif operation == 'plan_batch':
        fields(params, ('items',))
        items = params['items']
        need(type(items) is list and 1 <= len(items) <= MAX_GROUP)
        for item in items:
            fields(item, ('subject', 'source'))
            subject(item['subject'])
            source(item['source'])
        keys = [subject_key(item['subject']) for item in items]
        need(keys == sorted(set(keys)))
    elif operation == 'list_history':
        fields(params, ('subject', 'page'))
        subject(params['subject'])
        _page(params['page'])
    elif operation == 'get_operation':
        fields(params, ('subject', 'operationId'))
        subject(params['subject'])
        uuid_id(params['operationId'])
    elif operation == 'get_maintenance_status':
        fields(params, ('repository',))
        repository(params['repository'])
    else:
        raise Denied('REGISTRY_SEMANTIC_OPERATION_UNKNOWN')


def validate_params(operation, params):
    """Return a detached canonical JSON object; do not mutate caller input."""
    need(type(operation) is str and operation in READ_METHODS | WRITE_METHODS,
         'REGISTRY_SEMANTIC_OPERATION_UNKNOWN')
    try:
        # Exact JSON roundtrip prevents mutable aliasing; shape checks below
        # reject unexpected fields, not just known sensitive field names.
        raw = canonical(params).encode('utf-8')
        need(len(raw) <= (MAX_READ_BYTES if operation in READ_METHODS else MAX_WRITE_BYTES),
             'REGISTRY_SEMANTIC_SIZE_LIMIT')
        # Validate original Python shape (e.g. tuple is not a JSON list).
        if operation in READ_METHODS:
            _read(operation, params)
        elif operation == 'begin_release':
            begin_item(params)
        elif operation == 'report_release_result':
            report_item(params)
        else:
            fields(params, ('items',))
            group_items(params['items'], begin_item if operation == 'begin_release_group' else report_item)
        return loads_strict(raw)
    except (TypeError, ValueError, UnicodeError, RecursionError, OverflowError) as exc:
        if isinstance(exc, Denied):
            raise
        raise Denied('REGISTRY_SEMANTIC_PARAMS_INVALID') from None

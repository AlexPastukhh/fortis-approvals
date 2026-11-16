"""Closed v2 READ provider definitions; no effects or legacy receipt access.

Uses the existing trusted-code schema helpers and pinned Mirror transport.
Public params never select upstream identity, scope, URL, headers or policy.
"""
from datetime import datetime
from functools import partial
import hashlib
import re

from fortis_approvals.core import canonical
from fortis_approvals.extensions.model import Operation, bounded, check
from fortis_approvals.integrations.review_schema import (
    array, boolean, nullable, number, object_schema, sha)

# Source-owned proposed pilot scope. Enabling any v2 operation, changing this
# finite mapping, or configuring Windows scope still requires owner review.
INVENTORIES = {'mirror-pilot': ('fortis-approvals',)}
READS = ('list_repositories_v2', 'get_repository_v2', 'list_worktrees_v2',
         'get_github_status_v2', 'get_available_actions_v2', 'get_capabilities_v2')
BOUND_READS = ('preview_windows_pull_v2', 'get_windows_pull_result_v2')
READS = READS + BOUND_READS
DEFERRED = ('check_windows_history_v2', 'execute_windows_pull_v2')
ERRORS = frozenset(('SOURCE_UNAVAILABLE', 'NOT_CHECKED', 'PERMISSION_DENIED', 'TIMEOUT',
    'LIMIT_EXCEEDED', 'REPOSITORY_NOT_ALLOWED', 'SCHEMA_INVALID', 'PREVIEW_EXPIRED',
    'PREVIEW_STALE', 'REQUEST_ID_CONFLICT', 'SIGNATURE_INVALID', 'UNKNOWN_KEY', 'PROOF_REQUIRED',
    'WRITER_BUSY', 'OUTCOME_UNCONFIRMED', 'WINDOWS_NOT_CLEAN', 'WINDOWS_NOT_ON_MAIN',
    'ORIGIN_MISMATCH', 'GITHUB_MAIN_UNVERIFIED', 'DOCKER_MAIN_MISMATCH', 'NOT_FAST_FORWARD',
    'READBACK_UNCONFIRMED', 'POLICY_DENIED', 'INVENTORY_CHANGED', 'WINDOWS_ALREADY_CURRENT'))


def pattern(value, expression):
    check(type(value) is str and re.fullmatch(expression, value), 'MIRROR_V2_SCHEMA_INVALID')
    return value


def choice(value, values):
    check(value in values and type(value) is type(values[0]), 'MIRROR_V2_SCHEMA_INVALID')
    return value


def repo(value):
    return pattern(value, r'[A-Za-z0-9_][A-Za-z0-9_.-]{0,119}')


def branch(value):
    return pattern(value, r'[A-Za-z0-9_][A-Za-z0-9_./-]{0,159}')


def timestamp(value):
    return pattern(value, r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:Z|\+00:00)')


def revision(value):
    return pattern(value, r'[0-9a-f]{64}')


def error_code(value):
    check(type(value) is str and value in ERRORS, 'MIRROR_V2_SCHEMA_INVALID')
    return value


_source_shape = object_schema({'verification': partial(choice, values=('VERIFIED', 'NOT_CHECKED', 'UNKNOWN', 'ERROR')),
    'checkedAt': nullable(timestamp), 'head': nullable(sha), 'branch': nullable(branch),
    'clean': nullable(boolean), 'errorCode': nullable(error_code)})


def source(value):
    _source_shape(value)
    if value['verification'] == 'VERIFIED':
        check(value['head'] is not None and value['checkedAt'] is not None and
              value['errorCode'] is None, 'MIRROR_V2_EVIDENCE_INVALID')
    elif value['verification'] == 'NOT_CHECKED':
        check(all(value[key] is None for key in ('head', 'branch', 'clean', 'checkedAt')) and
              value['errorCode'] == 'NOT_CHECKED', 'MIRROR_V2_EVIDENCE_INVALID')
    else:
        check(value['errorCode'] is not None, 'MIRROR_V2_EVIDENCE_INVALID')
    return value

action = object_schema({'operation': partial(choice, values=READS + DEFERRED),
    'available': boolean, 'blockers': array(error_code, 32)})
repository = object_schema({'repoId': repo, 'docker': source, 'windows': source, 'github': source,
    'relation': partial(choice, values=('equal', 'behind', 'ahead', 'diverged', 'unknown')),
    'actions': array(action, 10)})
worktree = object_schema({'task': repo, 'branch': branch, 'head': nullable(sha),
    'clean': nullable(boolean), 'targetEligible': boolean})
pr = object_schema({'number': partial(number, maximum=1000000), 'head': sha, 'base': sha,
    'state': partial(choice, values=('OPEN', 'CLOSED', 'MERGED')), 'draft': boolean})
run = object_schema({'id': number, 'head': sha,
    'state': partial(choice, values=('QUEUED', 'IN_PROGRESS', 'COMPLETED', 'UNKNOWN')),
    'conclusion': nullable(partial(choice, values=('SUCCESS', 'FAILURE', 'CANCELLED', 'SKIPPED', 'UNKNOWN')))})
next_offset = nullable(partial(number, maximum=10000, minimum=0))
capability = object_schema({'operation': partial(choice, values=READS + DEFERRED),
    'version': partial(choice, values=('2',)), 'available': boolean, 'blockers': array(error_code, 32)})


def listed(item):
    return object_schema({'items': array(item, 128), 'nextOffset': next_offset,
                          'inventoryRevision': revision, 'truncated': boolean})


github = object_schema({'main': source, 'pullRequests': array(pr, 100), 'runs': array(run, 100),
    'requiredCI': partial(choice, values=('VERIFIED', 'NOT_VERIFIED')), 'truncated': boolean,
    'nextOffset': next_offset, 'inventoryRevision': revision})
DATA = {'list_repositories_v2': listed(repo), 'get_repository_v2': repository,
        'list_worktrees_v2': listed(worktree), 'get_github_status_v2': github,
        'get_available_actions_v2': array(action, 10), 'get_capabilities_v2': array(capability, 10)}


uuid4 = partial(pattern, expression=r'[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}')
_preview_shape = object_schema({'repoId': repo, 'previewId': nullable(uuid4),
    'expectedHead': nullable(sha), 'targetSha': nullable(sha), 'dockerHead': nullable(sha),
    'originIdentity': nullable(partial(pattern, expression=r'AlexPastukhh/[A-Za-z0-9_][A-Za-z0-9_.-]{0,119}')),
    'sourceEvidence': object_schema({'windows': source, 'docker': source, 'github': source}),
    'checkedAt': timestamp, 'expiresAt': timestamp, 'configGeneration': revision,
    'blockers': array(error_code, 32)})



def preview(value):
    _preview_shape(value)
    check((datetime.fromisoformat(value['expiresAt'].replace('Z', '+00:00')) -
           datetime.fromisoformat(value['checkedAt'].replace('Z', '+00:00'))).total_seconds() == 120,
          'MIRROR_V2_PREVIEW_TTL_INVALID')
    if not value['blockers']:
        evidence = value['sourceEvidence']
        check(value['previewId'] is not None and value['originIdentity'] is not None and
              value['expectedHead'] is not None and value['targetSha'] is not None and
              value['expectedHead'] != value['targetSha'] and value['dockerHead'] == value['targetSha'] and
              value['expectedHead'] == evidence['windows']['head'] and
              value['targetSha'] == evidence['github']['head'] == evidence['docker']['head'] and
              all(item['verification'] == 'VERIFIED' and item['branch'] == 'main' for item in evidence.values()) and
              evidence['windows']['clean'] is True and evidence['docker']['clean'] is True,
              'MIRROR_V2_EVIDENCE_INVALID')
    else:
        check(value['previewId'] is None, 'MIRROR_V2_EVIDENCE_INVALID')
    return value


def receipt(value):
    object_schema({'requestId': uuid4, 'repoId': repo,
        'workerState': partial(choice, values=('NOT_FOUND', 'DISPATCHED', 'EXECUTED', 'FAILED', 'UNCERTAIN', 'ALREADY_CURRENT')),
        'effect': partial(choice, values=('NONE', 'CONFIRMED', 'UNKNOWN')), 'observedHead': nullable(sha),
        'expectedTarget': nullable(sha), 'checkedAt': timestamp, 'errorCode': nullable(error_code),
        'evidence': partial(choice, values=('NONE', 'WORKER_RECEIPT', 'TARGET_READBACK'))})(value)
    state = value['workerState']
    if state in ('NOT_FOUND', 'DISPATCHED', 'UNCERTAIN'):
        check(value['effect'] == 'UNKNOWN', 'MIRROR_V2_EVIDENCE_INVALID')
    elif state in ('FAILED', 'ALREADY_CURRENT'):
        check(value['effect'] == 'NONE', 'MIRROR_V2_EVIDENCE_INVALID')
    else:
        check(value['effect'] == 'CONFIRMED' and value['observedHead'] is not None and
              value['expectedTarget'] is not None and value['observedHead'] == value['expectedTarget'] and value['errorCode'] is None and
              value['evidence'] in ('WORKER_RECEIPT', 'TARGET_READBACK'), 'MIRROR_V2_EVIDENCE_INVALID')
    return value


DATA.update(preview_windows_pull_v2=preview, get_windows_pull_result_v2=receipt)


def trusted_identity(ctx):
    # Core has persisted authenticated actor before executing this READ. No
    # caller identity is added to public params or to the generic framework.
    check(ctx.phase in ('execute', 'reconcile'), 'MIRROR_V2_PRINCIPAL_UNAVAILABLE')
    row = ctx.runtime.core._read(ctx.request_id)
    request = row['request']
    check(row['state'] in ('DISPATCHED', 'UNCERTAIN') and request['requestId'] == ctx.request_id and
          request['service'] == 'mirror' and request['operation'] == ctx.operation.name and
          request['target'] == ctx.target and request['params'] == ctx.params,
          'MIRROR_V2_PRINCIPAL_UNAVAILABLE')
    actor = pattern(row['actor'], r'[A-Za-z0-9_.:-]{1,120}')
    check(type(ctx.generation) is str and 0 < len(ctx.generation) <= 128, 'MIRROR_V2_GENERATION_UNAVAILABLE')
    generation = hashlib.sha256(canonical({'definition': ctx.runtime.digest,
        'policy': row['policyVersion'], 'credential': ctx.generation}).encode()).hexdigest()
    return actor, generation


def validate_params(operation, value):
    if operation == 'get_windows_pull_result_v2':
        return object_schema({'requestId': uuid4})(value)
    if operation not in ('list_repositories_v2', 'list_worktrees_v2', 'get_github_status_v2'):
        return object_schema({})(value)
    object_schema({'offset': partial(number, maximum=10000, minimum=0),
        'limit': partial(number, maximum=100 if operation == 'get_github_status_v2' else 128),
        'inventoryRevision': nullable(revision)})(value)
    check(value['offset'] == 0 or value['inventoryRevision'] is not None, 'MIRROR_V2_REVISION_REQUIRED')
    return value


def validate_result(operation, value):
    check(type(value) is dict and set(value) ==
          {'schemaVersion', 'operation', 'target', 'checkedAt', 'data', 'error'}, 'MIRROR_V2_RESULT_INVALID')
    check(type(value['schemaVersion']) is int and value['schemaVersion'] == 2 and
          value['operation'] == operation, 'MIRROR_V2_RESULT_INVALID')
    repo(value['target']); timestamp(value['checkedAt'])
    if value['error'] is None:
        DATA[operation](value['data'])
    else:
        check(value['data'] is None, 'MIRROR_V2_RESULT_INVALID')
        object_schema({'code': error_code, 'retryable': partial(choice, values=(False,))})(value['error'])
    # Existing extension Core has a stricter 64 KiB audited-result limit than
    # the 256 KiB upstream wire. Keep that bound; do not broaden shared Core.
    bounded(value, 65536)


def execute(operation, ctx):
    repo(ctx.target)
    params = validate_params(operation, ctx.params)
    query, path = {}, {}
    if operation in ('list_repositories_v2', 'get_capabilities_v2'):
        check(ctx.target in INVENTORIES, 'MIRROR_V2_INVENTORY_DENIED')
        members = INVENTORIES[ctx.target]
        query = {'inventory': ctx.target, 'scope_digest': hashlib.sha256(canonical(sorted(members)).encode()).hexdigest()}
    else:
        path = {'repo_id': ctx.target}
    if operation in BOUND_READS:
        actor, generation = trusted_identity(ctx)
        query['principal'] = actor
        if operation == 'preview_windows_pull_v2':
            uuid4(ctx.request_id)
            query.update(request_id=ctx.request_id, gateway_generation=generation)
        else:
            path['request_id'] = params['requestId']
    elif params:
        query.update(offset=params['offset'], limit=params['limit'])
        if params['inventoryRevision'] is not None:
            query['revision'] = params['inventoryRevision']
    value = ctx.call(operation, path=path, query=query)
    validate_result(operation, value)
    check(value['target'] == ctx.target, 'MIRROR_V2_TARGET_MISMATCH')
    if value['error'] is None:
        data = value['data']
        if operation in ('list_worktrees_v2', 'get_github_status_v2'):
            arrays = [data['items']] if operation == 'list_worktrees_v2' else [data['pullRequests'], data['runs']]
            check(all(len(items) <= params['limit'] for items in arrays), 'MIRROR_V2_PAGE_INVALID')
            check(params['inventoryRevision'] in (None, data['inventoryRevision']), 'MIRROR_V2_PAGE_INVALID')
            if data['nextOffset'] is not None:
                check(data['nextOffset'] == params['offset'] + params['limit'] and data['truncated'] and
                      max(map(len, arrays)) == params['limit'], 'MIRROR_V2_PAGE_INVALID')
        if operation in ('get_repository_v2', 'get_available_actions_v2', 'get_capabilities_v2'):
            available = data['actions'] if operation == 'get_repository_v2' else data
            check(len(available) == 10 and {item['operation'] for item in available} == set(READS + DEFERRED),
                  'MIRROR_V2_CAPABILITIES_INVALID')
            check(all(item['available'] is False and item['blockers'] == ['POLICY_DENIED']
                      for item in available if item['operation'] in DEFERRED), 'MIRROR_V2_CAPABILITIES_INVALID')
        if operation in BOUND_READS:
            check(data['repoId'] == ctx.target, 'MIRROR_V2_TARGET_MISMATCH')
            if operation == 'get_windows_pull_result_v2':
                check(data['requestId'] == params['requestId'], 'MIRROR_V2_TARGET_MISMATCH')
        if operation == 'get_repository_v2':
            check(data['repoId'] == ctx.target, 'MIRROR_V2_TARGET_MISMATCH')
            check(data['github']['verification'] == 'NOT_CHECKED' and data['relation'] == 'unknown',
                  'MIRROR_V2_EVIDENCE_INVALID')
        if operation == 'list_repositories_v2':
            check(data['inventoryRevision'] == query['scope_digest'], 'MIRROR_V2_SCOPE_MISMATCH')
            offset, limit = params['offset'], params['limit']
            expected = list(members)[offset:offset + limit]
            end = min(offset + limit, len(members))
            check(data['items'] == expected and
                  data['nextOffset'] == (end if end < len(members) else None) and
                  data['truncated'] is (end < len(members)), 'MIRROR_V2_SCOPE_MISMATCH')
            check(len(set(data['items'])) == len(data['items']) and data['items'] == sorted(data['items']),
                  'MIRROR_V2_PAGE_INVALID')
        if operation == 'get_github_status_v2':
            check(data['main']['verification'] == 'VERIFIED', 'MIRROR_V2_EVIDENCE_INVALID')
            check(data['requiredCI'] == 'NOT_VERIFIED', 'MIRROR_V2_EVIDENCE_INVALID')
    return value


OPERATIONS = tuple(Operation(name, 'Bounded Mirror READ v2: ' + name, 'read',
    partial(validate_params, name), partial(validate_result, name), partial(execute, name),
    credential='link', routes=(name,), version='2',
    lookup=partial(execute, name) if name in BOUND_READS else None) for name in READS)

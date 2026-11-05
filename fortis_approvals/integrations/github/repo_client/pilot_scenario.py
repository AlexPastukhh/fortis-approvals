"""Resumable Repo-side branch E2E. Only GitHubClient -> Gateway is used.

Input/output is non-secret JSON run state. Owner decisions happen only in the
separate browser portal. Every proposal keeps its original request ID/reason.
"""
from copy import deepcopy
import json
import re
import sys
import uuid

from ....clients.gateway_transport import GatewayTransport
from ....core import Denied
from ..pilot import GitHubPilotConfig
from .client import GitHubClient


PHASES = frozenset({'READ', 'SUBMIT_REJECT', 'WAIT_REJECT', 'SUBMIT_APPROVE', 'WAIT_APPROVE', 'DONE'})


def new_run(owner, repository, *, run_id=None, branch_prefix='fortis-e2e/'):
    config = GitHubPilotConfig(owner, repository, branch_prefix)
    ident = str(uuid.UUID(run_id)) if run_id is not None else str(uuid.uuid4())
    return {'format': 'fortis-github-pilot-run-v1', 'runId': ident,
            'owner': config.owner, 'repository': config.repository, 'branchPrefix': config.branch_prefix,
            'phase': 'READ', 'sourceSha': None,
            'reject': {'requestId': str(uuid.uuid4()), 'branch': branch_prefix + ident + '-reject'},
            'approve': {'requestId': str(uuid.uuid4()), 'branch': branch_prefix + ident + '-approve'}}


def check_state(state):
    if (type(state) is not dict or set(state) != {'format', 'runId', 'owner', 'repository',
            'branchPrefix', 'phase', 'sourceSha', 'reject', 'approve'} or
            state['format'] != 'fortis-github-pilot-run-v1' or state['phase'] not in PHASES):
        raise ValueError('PILOT_RUN_STATE_INVALID')
    GitHubPilotConfig(state['owner'], state['repository'], state['branchPrefix'])
    if str(uuid.UUID(state['runId'])) != state['runId']:
        raise ValueError('PILOT_RUN_ID_INVALID')
    for case in ('reject', 'approve'):
        item = state[case]
        if (type(item) is not dict or set(item) != {'requestId', 'branch'} or
                str(uuid.UUID(item['requestId'])) != item['requestId'] or
                item['branch'] != state['branchPrefix'] + state['runId'] + '-' + case):
            raise ValueError('PILOT_RUN_CASE_INVALID')
    if state['reject']['requestId'] == state['approve']['requestId']:
        raise ValueError('PILOT_DUPLICATE_REQUEST_ID')
    if state['sourceSha'] is None:
        if state['phase'] != 'READ': raise ValueError('PILOT_SOURCE_SHA_REQUIRED')
    elif type(state['sourceSha']) is not str or not re.fullmatch('[0-9a-f]{40}', state['sourceSha']):
        raise ValueError('PILOT_SOURCE_SHA_INVALID')


def branches(client, repository):
    result = {}
    for page in range(1, 101):
        rows = client.list_branches(repository, page=page, per_page=100)['items']
        for row in rows:
            if row['name'] in result: raise Denied('PILOT_BRANCH_PAGINATION_CHANGED')
            result[row['name']] = row['sha']
        if len(rows) < 100: return result
    raise Denied('PILOT_BRANCH_INVENTORY_LIMIT')


def reason(case):
    return ('GitHub pilot REJECT test: reject this exact branch creation; do not approve.' if case == 'reject'
            else 'GitHub pilot APPROVE test: owner WebAuthn may create this exact test branch at the frozen SHA.')


def advance(saved, client):
    check_state(saved)
    state = deepcopy(saved)
    repo, phase = state['repository'], state['phase']
    waiting = None
    if phase == 'READ':
        metadata = client.get_repository(repo)['repository']
        if metadata['full_name'] != state['owner'] + '/' + repo or metadata['archived'] or metadata['disabled']:
            raise Denied('PILOT_REPOSITORY_NOT_ACTIVE_OR_WRONG_OWNER')
        refs = branches(client, repo)
        if state['reject']['branch'] in refs or state['approve']['branch'] in refs:
            raise Denied('PILOT_TEST_BRANCH_ALREADY_EXISTS')
        state['sourceSha'] = refs.get(metadata['default_branch'])
        if state['sourceSha'] is None: raise Denied('PILOT_DEFAULT_BRANCH_NOT_FOUND')
        state['phase'] = 'SUBMIT_REJECT'
    elif phase.startswith('SUBMIT_'):
        case = 'reject' if phase == 'SUBMIT_REJECT' else 'approve'
        item = state[case]
        result = client.create_branch(repo, item['branch'], state['sourceSha'],
            request_id=item['requestId'], reason=reason(case))
        if result['state'] not in ('PENDING', 'REJECTED', 'EXECUTED', 'APPROVED', 'DISPATCHED', 'UNCERTAIN'):
            raise Denied('PILOT_SUBMISSION_STOP_' + result['state'])
        state['phase'] = 'WAIT_' + case.upper()
    elif phase.startswith('WAIT_'):
        case = 'reject' if phase == 'WAIT_REJECT' else 'approve'
        item = state[case]
        status = client.status(item['requestId'])['state']
        if status == 'PENDING':
            waiting = {'decision': case, 'requestId': item['requestId'], 'branch': item['branch']}
        elif status in ('APPROVED', 'DISPATCHED'):
            waiting = {'decision': 'execution', 'requestId': item['requestId'], 'branch': item['branch']}
        elif status == 'UNCERTAIN':
            raise Denied('PILOT_UNCERTAIN_RECONCILIATION_REQUIRED')
        elif case == 'reject' and status == 'REJECTED':
            if item['branch'] in branches(client, repo): raise Denied('PILOT_REJECT_BRANCH_EXISTS')
            state['phase'] = 'SUBMIT_APPROVE'
        elif case == 'approve' and status == 'EXECUTED':
            refs = branches(client, repo)
            if refs.get(item['branch']) != state['sourceSha'] or state['reject']['branch'] in refs:
                raise Denied('PILOT_FINAL_READBACK_MISMATCH')
            replay = client.create_branch(repo, item['branch'], state['sourceSha'],
                request_id=item['requestId'], reason=reason(case))
            if replay['state'] != 'EXECUTED': raise Denied('PILOT_COMPLETED_REPLAY_FAILED')
            state['phase'] = 'DONE'
        else:
            raise Denied('PILOT_DECISION_OR_STATUS_MISMATCH_' + status)
    return {'state': state, 'awaitOwner': waiting, 'complete': state['phase'] == 'DONE'}


def main():
    saved = json.load(sys.stdin)
    client = GitHubClient(gateway=GatewayTransport(endpoint='https://host.docker.internal:19204',
        allow_test_endpoint=True))
    print(json.dumps(advance(saved, client), sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except (Denied, ValueError, KeyError, TypeError, OSError) as error:
        code = str(error)
        print(json.dumps({'error': code if re.fullmatch('[A-Z0-9_]+', code) else 'PILOT_SCENARIO_FAILED'}), file=sys.stderr)
        raise SystemExit(1)

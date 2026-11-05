"""Bounded file + draft PR E2E through the actual Repo Gateway client only."""
from copy import deepcopy
import hashlib
import json
import re
import sys
import uuid

from ....core import Denied
from ....clients.gateway_transport import GatewayTransport
from ..pilot import GitHubPilotConfig
from .client import GitHubClient
from .pilot_scenario import branches

PHASES = {'READ', 'SUBMIT_PUSH', 'WAIT_PUSH', 'SUBMIT_PR', 'WAIT_PR', 'DONE'}
FIELDS = {'format', 'runId', 'owner', 'repository', 'branch', 'path', 'expectedHeadSha',
          'baseSha', 'pushRequestId', 'prRequestId', 'phase', 'commitSha', 'pullRequestNumber'}


def new_run(owner, repository, branch, expected_head_sha, *, run_id=None):
    config = GitHubPilotConfig(owner, repository, file_pr_branch=branch)
    ident = str(uuid.UUID(run_id)) if run_id else str(uuid.uuid4())
    result = dict(format='fortis-github-file-pr-v1', runId=ident, owner=owner,
        repository=repository, branch=branch, path=config.file_path, expectedHeadSha=expected_head_sha,
        baseSha=None, pushRequestId=str(uuid.uuid4()), prRequestId=str(uuid.uuid4()),
        phase='READ', commitSha=None, pullRequestNumber=None)
    check_state(result)
    return result


def check_state(state):
    if type(state) is not dict or set(state) != FIELDS or state['format'] != 'fortis-github-file-pr-v1' or state['phase'] not in PHASES:
        raise ValueError('FILE_PR_STATE_INVALID')
    config = GitHubPilotConfig(state['owner'], state['repository'], file_pr_branch=state['branch'])
    if state['path'] != config.file_path: raise ValueError('FILE_PR_PATH_INVALID')
    for key in ('runId', 'pushRequestId', 'prRequestId'):
        if str(uuid.UUID(state[key])) != state[key]: raise ValueError('FILE_PR_ID_INVALID')
    if state['pushRequestId'] == state['prRequestId']: raise ValueError('FILE_PR_ID_INVALID')
    for key in ('expectedHeadSha', 'baseSha', 'commitSha'):
        value = state[key]
        if key != 'expectedHeadSha' and value is None: continue
        if type(value) is not str or not re.fullmatch('[0-9a-f]{40}', value): raise ValueError('FILE_PR_SHA_INVALID')
    if state['phase'] != 'READ' and state['baseSha'] is None: raise ValueError('FILE_PR_BASE_REQUIRED')
    if state['phase'] in ('SUBMIT_PR', 'WAIT_PR', 'DONE') and state['commitSha'] is None: raise ValueError('FILE_PR_COMMIT_REQUIRED')
    n = state['pullRequestNumber']
    if n is not None and (type(n) is not int or not 1 <= n <= 1000000): raise ValueError('FILE_PR_NUMBER_INVALID')
    if state['phase'] == 'DONE' and n is None: raise ValueError('FILE_PR_NUMBER_REQUIRED')


def content(state):
    return 'Fortis Gateway file/PR E2E\nRun: ' + state['runId'] + '\nBranch: ' + state['branch'] + '\n'


def params(state, kind):
    if kind == 'push':
        return dict(branch=state['branch'], expectedHeadSha=state['expectedHeadSha'],
            message='test: add Gateway file/PR E2E evidence', files=[dict(path=state['path'], content=content(state))])
    return dict(head=state['branch'], base='main', title='[Gateway E2E] ' + state['runId'],
        body='Gateway E2E evidence only. Do not merge. Opening this draft triggers the existing pull_request CI.', draft=True)


def reason(kind):
    return ('Gateway file E2E: approve one bounded UTF-8 test file on the exact pilot branch.' if kind == 'push' else
            'Gateway draft PR E2E: approve opening this draft against main; existing pull_request CI will run. Do not merge.')


def submit(state, client, kind):
    return client.action('push_files' if kind == 'push' else 'create_pull_request', state['repository'],
                         params(state, kind), request_id=state[kind + 'RequestId'], reason=reason(kind))


def pulls(state, client):
    result = []
    for page in range(1, 101):
        rows = client.list_pull_requests(state['repository'], state='all', page=page, per_page=100)['items']
        result.extend(p for p in rows if p['head']['ref'] == state['branch'] and p['base']['ref'] == 'main')
        if len(rows) < 100: return result
    raise Denied('FILE_PR_INVENTORY_LIMIT')


def verify_file(state, client, sha):
    item = client.get_file(state['repository'], state['path'], sha)['file']
    data = content(state).encode('utf-8')
    blob = hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()
    if (not item['exists'] or item['sha'] != blob or item['size'] != len(data) or
            item['contentSha256'] != hashlib.sha256(data).hexdigest()):
        raise Denied('FILE_PR_CONTENT_READBACK_MISMATCH')


def verify_pr(state, row):
    if (row['state'] != 'open' or row['draft'] is not True or row['merged'] or
            row['head'] != dict(ref=state['branch'], sha=state['commitSha']) or
            row['base'] != dict(ref='main', sha=state['baseSha']) or row['title'] != params(state, 'pr')['title']):
        raise Denied('FILE_PR_PULL_READBACK_MISMATCH')


def advance(saved, client):
    check_state(saved)
    state = deepcopy(saved)
    repo, phase = state['repository'], state['phase']
    waiting = None
    if phase == 'READ':
        metadata = client.get_repository(repo)['repository']
        if metadata['full_name'] != state['owner'] + '/' + repo or metadata['default_branch'] != 'main' or metadata['archived'] or metadata['disabled']:
            raise Denied('FILE_PR_REPOSITORY_INVALID')
        refs = branches(client, repo)
        if refs.get(state['branch']) != state['expectedHeadSha']: raise Denied('FILE_PR_INITIAL_HEAD_CHANGED')
        if client.get_file(repo, state['path'], state['expectedHeadSha'])['file']['exists']:
            raise Denied('FILE_PR_TEST_FILE_ALREADY_EXISTS')
        if pulls(state, client): raise Denied('FILE_PR_EXISTING_PULL_REQUIRES_INSPECTION')
        state['baseSha'] = refs['main']
        state['phase'] = 'SUBMIT_PUSH'
    elif phase.startswith('SUBMIT_'):
        kind = 'push' if phase == 'SUBMIT_PUSH' else 'pr'
        if kind == 'pr':
            refs = branches(client, repo)
            if refs.get(state['branch']) != state['commitSha'] or refs.get('main') != state['baseSha']:
                raise Denied('FILE_PR_BRANCH_CHANGED_BEFORE_PROPOSAL')
        result = submit(state, client, kind)
        if result['state'] not in ('PENDING', 'APPROVED', 'DISPATCHED', 'EXECUTED', 'UNCERTAIN'):
            raise Denied('FILE_PR_SUBMISSION_STOP_' + result['state'])
        state['phase'] = 'WAIT_' + kind.upper()
    elif phase.startswith('WAIT_'):
        kind = 'push' if phase == 'WAIT_PUSH' else 'pr'
        ident = state[kind + 'RequestId']
        status = client.status(ident)['state']
        if status in ('PENDING', 'APPROVED', 'DISPATCHED'):
            waiting = dict(decision='approve' if status == 'PENDING' else 'execution',
                           operation='push_files' if kind == 'push' else 'create_pull_request', requestId=ident)
        elif status == 'UNCERTAIN': raise Denied('FILE_PR_UNCERTAIN_RECONCILIATION_REQUIRED')
        elif status != 'EXECUTED': raise Denied('FILE_PR_DECISION_STOP_' + status)
        elif kind == 'push':
            state['commitSha'] = branches(client, repo).get(state['branch'])
            if state['commitSha'] is None or state['commitSha'] == state['expectedHeadSha']:
                raise Denied('FILE_PR_COMMIT_READBACK_MISSING')
            verify_file(state, client, state['commitSha'])
            if submit(state, client, 'push')['state'] != 'EXECUTED': raise Denied('FILE_PR_REPLAY_FAILED')
            state['phase'] = 'SUBMIT_PR'
        else:
            rows = pulls(state, client)
            if len(rows) != 1: raise Denied('FILE_PR_PULL_COUNT_MISMATCH')
            state['pullRequestNumber'] = rows[0]['number']
            verify_pr(state, client.get_pull_request(repo, state['pullRequestNumber'])['pullRequest'])
            verify_file(state, client, state['commitSha'])
            if submit(state, client, 'pr')['state'] != 'EXECUTED': raise Denied('FILE_PR_REPLAY_FAILED')
            state['phase'] = 'DONE'
    elif phase == 'DONE':
        if branches(client, repo).get(state['branch']) != state['commitSha']:
            raise Denied('FILE_PR_COMPLETED_BRANCH_CHANGED')
        verify_file(state, client, state['commitSha'])
        verify_pr(state, client.get_pull_request(repo, state['pullRequestNumber'])['pullRequest'])
    return dict(state=state, awaitOwner=waiting, complete=state['phase'] == 'DONE')


def main():
    saved = json.load(sys.stdin)
    client = GitHubClient(gateway=GatewayTransport(endpoint='https://host.docker.internal:19204', allow_test_endpoint=True))
    print(json.dumps(advance(saved, client), sort_keys=True))


if __name__ == '__main__':
    try: main()
    except (Denied, ValueError, KeyError, TypeError, OSError) as error:
        code = str(error)
        print(json.dumps({'error': code if re.fullmatch('[A-Z0-9_]+', code) else 'FILE_PR_SCENARIO_FAILED'}), file=sys.stderr)
        raise SystemExit(1)

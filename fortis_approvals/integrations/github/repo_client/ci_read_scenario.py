"""Read the exact accepted PR/head/run through Gateway; no mutation methods."""
import json
import re
import sys
import uuid
from ....core import Denied
from ....clients.gateway_transport import GatewayTransport
from ..pilot import GitHubPilotConfig
from .client import GitHubClient
from .pilot_scenario import branches

FIELDS = {'format', 'runId', 'owner', 'repository', 'branch', 'headSha', 'pullRequestNumber', 'workflowRunId', 'phase'}


def check_state(state):
    if (type(state) is not dict or set(state) != FIELDS or state['format'] != 'fortis-github-ci-read-v1' or
            state['phase'] not in ('READ', 'DONE')):
        raise ValueError('CI_READ_STATE_INVALID')
    GitHubPilotConfig(state['owner'], state['repository'], file_pr_branch=state['branch'], ci_reads=True)
    if str(uuid.UUID(state['runId'])) != state['runId']: raise ValueError('CI_READ_ID_INVALID')
    if type(state['headSha']) is not str or not re.fullmatch('[0-9a-f]{40}', state['headSha']): raise ValueError('CI_READ_SHA_INVALID')
    for key, limit in [('pullRequestNumber',1000000),('workflowRunId',9223372036854775807)]:
        if type(state[key]) is not int or not 1 <= state[key] <= limit: raise ValueError('CI_READ_TARGET_ID_INVALID')


def read_ci(state, client):
    check_state(state)
    repo = state['repository']
    metadata = client.get_repository(repo)['repository']
    if metadata['full_name'] != state['owner'] + '/' + repo or metadata['archived'] or metadata['disabled']:
        raise Denied('CI_READ_REPOSITORY_MISMATCH')
    pr = client.get_pull_request(repo, state['pullRequestNumber'])['pullRequest']
    if (pr['number'] != state['pullRequestNumber'] or pr['head'] != dict(ref=state['branch'],sha=state['headSha']) or
            pr['base']['ref'] != 'main' or pr['state'] != 'open' or pr['merged'] or not pr['draft']):
        raise Denied('CI_READ_PR_HEAD_MISMATCH')
    if branches(client, repo).get(state['branch']) != state['headSha']:
        raise Denied('CI_READ_BRANCH_HEAD_MISMATCH')
    selected = None
    for page in range(1, 101):
        rows = client.list_workflow_runs(repo, page=page, per_page=100)['items']
        for row in rows:
            if row['id'] == state['workflowRunId']:
                if selected is not None: raise Denied('CI_READ_DUPLICATE_RUN')
                selected = row
        if selected is not None or len(rows) < 100: break
    else: raise Denied('CI_READ_INVENTORY_LIMIT')
    if selected is None: raise Denied('CI_READ_EXPECTED_RUN_NOT_FOUND')
    if (selected['headSha'] != state['headSha'] or selected['headBranch'] != state['branch'] or
            selected['event'] != 'pull_request' or selected['name'] != 'Source CI' or
            selected['url'] != 'https://github.com/' + state['owner'] + '/' + repo + '/actions/runs/' + str(state['workflowRunId'])):
        raise Denied('CI_READ_RUN_IDENTITY_MISMATCH')
    return dict(repository=metadata['full_name'], pullRequestNumber=pr['number'], headSha=state['headSha'],
                workflowRun=selected, ciPassed=selected['status'] == 'completed' and selected['conclusion'] == 'success')


def main():
    state = json.load(sys.stdin)
    client = GitHubClient(gateway=GatewayTransport(endpoint='https://host.docker.internal:19204',allow_test_endpoint=True))
    print(json.dumps(read_ci(state, client), sort_keys=True))


if __name__ == '__main__':
    try: main()
    except (Denied, ValueError, KeyError, TypeError, OSError) as error:
        code = str(error)
        print(json.dumps({'error':code if re.fullmatch('[A-Z0-9_]+',code) else 'CI_READ_SCENARIO_FAILED'}),file=sys.stderr)
        raise SystemExit(1)

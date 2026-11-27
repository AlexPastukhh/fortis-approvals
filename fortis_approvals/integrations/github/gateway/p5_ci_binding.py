"""Fixed P5 source policy candidate; not historical branch authority."""
from datetime import datetime
from dataclasses import asdict

from ....core import Denied, Stale
from ..release_label_ci import WORKFLOWS, Workflow, ServerCIReader, _collect_workflow_evidence, _inventory, _latest
from .review_capture import _hash, _need

P5_WORKFLOWS = WORKFLOWS + (
    Workflow('P5 Retained Impact', 425664934, '.github/workflows/p5-retained-impact.yml',
             ('p5-retained-impact',), '546f1f641551cbf22e57458f548cc98152b7d840328632b4d736b6b1439c0062'),)
APP_ID = 15368
APP_SLUG = 'github-actions'


class P5CIReader(ServerCIReader):
    # Separate budget; the publisher reader retains 18 GET / 20 seconds.
    max_reads = 32
    read_seconds = 30


def policy():
    return {'schemaVersion': 1, 'kind': 'P5_SOURCE_POLICY_CANDIDATE',
            'repository': 'fortis-approvals', 'baseRef': 'main',
            'workflows': [{**asdict(w), 'jobs': list(w.jobs)} for w in P5_WORKFLOWS],
            'appId': APP_ID, 'appSlug': APP_SLUG}


def _instant(value):
    try:
        parsed = datetime.fromisoformat(value)
        _need(parsed.utcoffset() is not None, 'P5_CI_TIME_INVALID')
        return parsed
    except (ValueError, TypeError):
        raise Denied('P5_CI_TIME_INVALID') from None


def observe_check_witnesses(reader, *, owner, head, expected):
    """Exact latest check/App/job projection; no historical policy assertion."""
    names = set(expected)
    # Default latest checks, independently selected exact attempt jobs.
    raw = reader.get('commits/'+head+'/check-runs', {'page': 1, 'per_page': 100})
    _need(type(raw) is dict and type(raw.get('total_count')) is int and
          type(raw.get('check_runs')) is list and
          len(raw['check_runs']) == raw['total_count'] < 100,
          'P5_CI_CHECK_INVENTORY_INCOMPLETE')
    selected, ids = {}, set()
    for row in raw['check_runs']:
        _need(type(row) is dict and type(row.get('id')) is int and row['id'] > 0
              and row['id'] not in ids and row.get('head_sha') == head
              and type(row.get('name')) is str, 'P5_CI_CHECK_INVALID')
        ids.add(row['id'])
        name = row['name']
        if name not in expected:
            continue
        run, job = expected[name]
        app = row.get('app')
        _need(name not in selected and row['id'] == job['id'] and
              type(app) is dict and app.get('id') == APP_ID and app.get('slug') == APP_SLUG and
              row.get('status') == 'completed' and row.get('conclusion') == 'success' and
              row.get('details_url') == 'https://github.com/'+owner+'/fortis-approvals/actions/runs/'+
                str(run['runId'])+'/job/'+str(job['id']),
              'P5_CI_CHECK_JOB_APP_MISMATCH')
        start, end = row.get('started_at'), row.get('completed_at')
        _need(_instant(start) <= _instant(end), 'P5_CI_TIME_INVALID')
        selected[name] = {'name': name, 'headSha': head, 'checkRunId': row['id'],
                          'appId': APP_ID, 'appSlug': APP_SLUG, 'runId': run['runId'],
                          'attempt': run['attempt'], 'workflowId': run['workflowId'],
                          'startedAt': start, 'completedAt': end, 'conclusion': 'success'}
    _need(set(selected) == names, 'P5_CI_CHECK_INVENTORY_INCOMPLETE')
    statuses = reader.get('commits/'+head+'/status', {'page':1,'per_page':100})
    _need(type(statuses) is dict and statuses.get('sha') == head and
          type(statuses.get('total_count')) is int and type(statuses.get('statuses')) is list and
          len(statuses['statuses']) == statuses['total_count'] < 100 and
          all(type(s) is dict and type(s.get('context')) is str and
              s['context'] not in names for s in statuses['statuses']),
          'P5_CI_LEGACY_STATUS_AMBIGUOUS')
    return [selected[n] for n in sorted(names)]


def collect_policy_ci(reader, *, owner, head, base, number, branch, rules):
    """Bind source-policy pins, exact PR/base/head attempts and check App IDs."""
    names = {n for w in P5_WORKFLOWS for n in w.jobs}
    contexts = rules['requiredContexts']
    _need(all(x['name'] in names and x['appId'] in (None, APP_ID) for x in contexts),
          'P5_CI_RULE_CONTEXT_UNSUPPORTED')
    runs = _collect_workflow_evidence(reader, owner=owner, head=head, number=number,
                                      branch=branch, workflows=P5_WORKFLOWS, base=base)
    expected = {}
    for workflow, run in zip(P5_WORKFLOWS, runs):
        _need({j['name'] for j in run['jobs']} == set(workflow.jobs), 'P5_CI_JOB_SET_CHANGED')
        for job in run['jobs']:
            _need(job['name'] not in expected, 'P5_CI_JOB_SET_CHANGED')
            expected[job['name']] = (run, job)

    first = observe_check_witnesses(reader, owner=owner, head=head, expected=expected)
    if observe_check_witnesses(reader, owner=owner, head=head, expected=expected) != first:
        raise Stale('P5_CI_CHECK_OBSERVATION_CHANGED')
    again = _inventory(reader, head)
    for workflow, run in zip(P5_WORKFLOWS, runs):
        latest = _latest(again, workflow)
        if (latest['id'], latest['runAttempt'], latest['runNumber']) != (
                run['runId'], run['attempt'], run['runNumber']):
            raise Stale('P5_CI_ATTEMPT_CHANGED')
    profile = policy()
    return runs, {'policy': profile, 'policySha256': _hash(profile),
                  'rulesSha256': rules['rulesSha256'], 'repository': owner+'/fortis-approvals',
                  'number': number, 'baseSha': base, 'headSha': head, 'checks': first,
                  'candidateChecksMatched': True, 'historicalPolicyVerified': False,
                  'requiredPolicySatisfied': False}

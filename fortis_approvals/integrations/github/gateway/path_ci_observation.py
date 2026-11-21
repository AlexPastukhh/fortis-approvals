"""Unregistered pre-merge path/CI observation; no historical review authority."""
import hashlib
import time

from ....core import Denied, Stale, canonical
from ..release_label_ci import ServerCIReader, collect_workflow_evidence
from ..post_merge_proof_bindings import _path
from .post_merge_reader import PILOT_REPOSITORY
from .review_capture import _need, _hex

# GitHub compare files are capped at 300. Refuse even an exact cap count.
MAX_FILES = 299
MAX_RULES = 199
MAX_SECONDS = 60


def _digest(value):
    return hashlib.sha256(canonical(value).encode('utf-8')).hexdigest()


def _safe_path(value):
    return (_path(value) and not value.startswith('~') and
            not any(c in value for c in ':*?[]') and
            all(ord(c) >= 32 and ord(c) != 127 for c in value))


def observe_path_ci(adapter, *, number, expected_head_sha, expected_base_sha,
                    expected_body_sha256, clock=time.monotonic, policy_bound=False):
    """Fixed pilot; only current open-PR observations, never a merge decision.

    The adapter must be owner-composed with existing CI workflow bindings.
    The current rules API is not a historical or exhaustive protection proof.
    """
    _need(type(number) is int and 0 < number <= 1_000_000 and
          _hex(expected_head_sha, 40) and _hex(expected_base_sha, 40) and
          expected_head_sha != expected_base_sha and _hex(expected_body_sha256, 64),
          'P5_PATH_CI_REQUEST_INVALID')
    repo = adapter._repo(PILOT_REPOSITORY)
    origin = adapter.owner + '/' + repo
    started = clock()

    def budget():
        _need(clock()-started < MAX_SECONDS, 'P5_PATH_CI_BUDGET')

    def get(suffix, params=None):
        budget()
        result = adapter._api('GET', adapter._path(repo, suffix), params=params)
        budget()
        return result

    def pr():
        raw = get('pulls/'+str(number))
        _need(type(raw) is dict and type(raw.get('number')) is int and raw['number'] == number
              and raw.get('state') == 'open' and raw.get('draft') is False
              and raw.get('merged') is False and raw.get('merged_at') is None,
              'P5_PATH_CI_PR_NOT_OPEN')
        head, base = raw.get('head'), raw.get('base')
        _need(all(type(part) is dict and type(part.get('repo')) is dict and
                  part['repo'].get('full_name') == origin for part in (head, base)),
              'P5_PATH_CI_REPO_MISMATCH')
        _need(type(head.get('ref')) is str and 5 < len(head['ref']) <= 240
              and head['ref'].startswith('task/') and base.get('ref') == 'main'
              and head.get('sha') == expected_head_sha and base.get('sha') == expected_base_sha,
              'P5_PATH_CI_REF_MISMATCH')
        body = raw.get('body')
        _need(type(body) is str and 0 < len(body) <= 20000, 'P5_PATH_CI_BODY_INVALID')
        try:
            data = body.encode('utf-8')
        except UnicodeError:
            raise Denied('P5_PATH_CI_BODY_INVALID') from None
        _need(len(data) <= 20000 and hashlib.sha256(data).hexdigest() == expected_body_sha256,
              'P5_PATH_CI_BODY_CHANGED')
        count = raw.get('changed_files')
        _need(type(count) is int and 0 < count <= MAX_FILES, 'P5_PATH_CI_FILE_COUNT_INVALID')
        return {'headSha': expected_head_sha, 'baseSha': expected_base_sha,
                'branch': head['ref'], 'bodySha256': expected_body_sha256,
                'changedFiles': count}

    def main():
        row = adapter._project_branch(get('branches/main'))
        if row['name'] != 'main' or row['sha'] != expected_base_sha:
            raise Stale('P5_PATH_CI_MAIN_CHANGED')

    def paths(count):
        row = get('compare/'+expected_base_sha+'...'+expected_head_sha,
                  {'page': 1, 'per_page': 1})
        _need(type(row) is dict and type(row.get('base_commit')) is dict
              and row['base_commit'].get('sha') == expected_base_sha
              and type(row.get('merge_base_commit')) is dict
              and row.get('status') in ('ahead', 'diverged')
              and type(row.get('ahead_by')) is int and row['ahead_by'] > 0,
              'P5_PATH_CI_COMPARE_INVALID')
        merge_base = adapter._sha(row['merge_base_commit'].get('sha'))
        raw = row.get('files')
        _need(type(raw) is list and len(raw) == count <= MAX_FILES,
              'P5_PATH_CI_FILES_INCOMPLETE')
        records, seen, old_paths = [], set(), set()
        for entry in raw:
            _need(type(entry) is dict, 'P5_PATH_CI_FILE_INVALID')
            path, status, previous = entry.get('filename'), entry.get('status'), entry.get('previous_filename')
            _need(_safe_path(path) and status in ('added','modified','removed','renamed')
                  and path not in seen, 'P5_PATH_CI_FILE_INVALID')
            _need((status == 'renamed' and _safe_path(previous) and previous != path and previous not in old_paths)
                  or (status != 'renamed' and previous is None), 'P5_PATH_CI_RENAME_INVALID')
            seen.add(path)
            if previous is not None:
                old_paths.add(previous)
            records.append({'path': path, 'status': 'deleted' if status == 'removed' else status,
                            'previousPath': previous})
        _need(not seen.intersection(old_paths), 'P5_PATH_CI_PATH_OVERLAP')
        records.sort(key=lambda item: item['path'])
        return {'mergeBaseSha': merge_base, 'count': count, 'records': records,
                'sha256': _digest(records), 'impactPaths': sorted(seen | old_paths)}

    def rules():
        rows = []
        for page in (1, 2):
            batch = get('rules/branches/main', {'page': page, 'per_page': 100})
            _need(type(batch) is list and len(batch) <= 100 and
                  all(type(x) is dict and type(x.get('type')) is str for x in batch),
                  'P5_PATH_CI_RULES_INVALID')
            rows.extend(batch)
            if len(batch) < 100:
                break
        _need(0 < len(rows) <= MAX_RULES, 'P5_PATH_CI_RULES_INCOMPLETE')
        checks = {}
        for row in rows:
            kind = row['type']
            _need(kind not in ('workflows','required_workflows','required_deployments'),
                  'P5_PATH_CI_UNSUPPORTED_RULE')
            if kind != 'required_status_checks':
                continue
            params = row.get('parameters')
            _need(type(params) is dict and type(params.get('required_status_checks')) is list,
                  'P5_PATH_CI_RULES_INVALID')
            for check in params['required_status_checks']:
                _need(type(check) is dict and type(check.get('context')) is str and
                      0 < len(check['context']) <= 200, 'P5_PATH_CI_RULES_INVALID')
                name = check['context']
                app = check.get('integration_id')
                _need(app is None or type(app) is int and (app > 0 or app == -1),
                      'P5_PATH_CI_RULES_INVALID')
                app = None if app == -1 else app
                _need(name not in checks or checks[name] == app, 'P5_PATH_CI_RULES_AMBIGUOUS')
                checks[name] = app
        _need(0 < len(checks) <= 100, 'P5_PATH_CI_REQUIRED_CHECKS_MISSING')
        return {'rulesSha256': _digest(sorted(rows, key=canonical)),
                'requiredContexts': [{'name': name, 'appId': checks[name]} for name in sorted(checks)]}

    main()
    first = pr()
    files = paths(first['changedFiles'])
    policy = rules()
    binding = None
    if policy_bound:
        from .p5_ci_binding import P5CIReader, collect_policy_ci
        ci, binding = collect_policy_ci(P5CIReader(adapter, clock=clock), owner=adapter.owner, head=expected_head_sha,
                                        base=expected_base_sha, number=number,
                                        branch=first['branch'], rules=policy)
    else:
        ci = collect_workflow_evidence(ServerCIReader(adapter, clock=clock), owner=adapter.owner,
                                       head=expected_head_sha, number=number, branch=first['branch'])
    # Compare rule and path projections again; current rule names are NOT assumed
    # to be satisfied by similarly named workflow jobs or legacy statuses.
    if rules() != policy or paths(first['changedFiles']) != files or pr() != first:
        raise Stale('P5_PATH_CI_OBSERVATION_CHANGED')
    main()
    observation = {'repository': origin, 'number': number, 'pr': first,
                   'paths': files, 'currentRules': policy, 'pinnedWorkflowCI': ci}
    if binding is not None:
        observation['ciPolicyBinding'] = binding
    return {'result':'PRE_MERGE_PATH_CI_OBSERVED', 'observation':observation,
            'observationDigest':_digest(observation), 'historicalPolicyVerified':False,
            'requiredPolicySatisfied':False, 'reviewAttested':False,
            'evidenceVerified':False, 'admissionAllowed':False, 'deploymentAllowed':False}

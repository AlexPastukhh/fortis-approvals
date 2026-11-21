"""Internal P5 provider observation candidate. Not registered or reachable via ingress.

The adapter must be composed by the Gateway owner with its pinned transport.
Do not pass a Repo-supplied adapter, token, URL, scope, or alleged proof bundle.
This is a partial observation, never authorization, admission or deployment.
"""
import base64
import binascii
import hashlib
from datetime import datetime, timezone

from ....core import Denied, Stale, canonical

PILOT_REPOSITORY = 'fortis-approvals'
MAX_FIRST_PARENT_NODES = 64
MAX_CATALOG_BYTES = 250_000


def _require(condition, code):
    if not condition:
        raise Denied(code)


def _timestamp(value):
    _require(type(value) is str and len(value) <= 40, 'P5_MERGE_TIME_INVALID')
    try:
        parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
        if parsed.tzinfo is None:
            raise ValueError()
        return parsed.astimezone(timezone.utc).isoformat()
    except (ValueError, OverflowError):
        raise Denied('P5_MERGE_TIME_INVALID') from None


def observe_post_merge(adapter, *, number, expected_head_sha,
                       expected_merge_sha, selected_main_sha):
    """Retrieve bounded source observations via existing Gateway GET routes.

    Fixed pilot repository; no params may select paths, refs, upstream host,
    principal or credentials. No new route or grant is installed by this code.
    """
    repo = adapter._repo(PILOT_REPOSITORY)
    expected_head_sha = adapter._sha(expected_head_sha)
    expected_merge_sha = adapter._sha(expected_merge_sha)
    selected_main_sha = adapter._sha(selected_main_sha)
    _require(expected_head_sha != expected_merge_sha, 'P5_HEAD_EQUALS_MERGE')
    _require(type(number) is int and 0 < number <= 1_000_000, 'P5_PR_NUMBER_INVALID')
    origin = adapter.owner + '/' + repo

    def get(suffix, **kw):
        return adapter._api('GET', adapter._path(repo, suffix), **kw)

    def read_main():
        branch = adapter._project_branch(get('branches/main'))
        if branch['name'] != 'main' or branch['sha'] != selected_main_sha:
            raise Stale('P5_SELECTED_MAIN_CHANGED')
        return branch

    def read_pr():
        row = get('pulls/' + str(number))
        _require(type(row) is dict and type(row.get('number')) is int and
                 row['number'] == number and row.get('state') == 'closed' and
                 row.get('merged') is True and row.get('draft') is False,
                 'P5_PR_NOT_MERGED')
        head, base = row.get('head'), row.get('base')
        _require(type(head) is dict and type(base) is dict, 'P5_PR_PROVENANCE_INVALID')
        for entry in (head, base):
            project = entry.get('repo')
            _require(type(project) is dict and project.get('full_name') == origin,
                     'P5_PR_PROVENANCE_INVALID')
        _require(type(head.get('ref')) is str and head['ref'].startswith('task/') and
                 5 < len(head['ref']) <= 240 and base.get('ref') == 'main',
                 'P5_PR_PROVENANCE_INVALID')
        if adapter._sha(head.get('sha')) != expected_head_sha or adapter._sha(row.get('merge_commit_sha')) != expected_merge_sha:
            raise Stale('P5_PR_HEAD_OR_MERGE_CHANGED')
        return {'number': number, 'headSha': expected_head_sha,
                'mergeSha': expected_merge_sha, 'headBranch': head['ref'],
                'baseSha': adapter._sha(base.get('sha')), 'mergedAt': _timestamp(row.get('merged_at'))}

    def read_commit(sha):
        value = get('git/commits/' + sha)
        _require(type(value) is dict and value.get('sha') == sha and
                 type(value.get('tree')) is dict and type(value.get('parents')) is list and
                 len(value['parents']) <= 8, 'P5_COMMIT_PROJECTION_INVALID')
        tree = adapter._sha(value['tree'].get('sha'))
        parents = []
        for entry in value['parents']:
            _require(type(entry) is dict, 'P5_COMMIT_PROJECTION_INVALID')
            parents.append(adapter._sha(entry.get('sha')))
        _require(len(parents) == len(set(parents)) and sha not in parents,
                 'P5_COMMIT_PROJECTION_INVALID')
        return {'sha': sha, 'treeSha': tree, 'parents': parents}

    read_main()
    pr = read_pr()
    seen = set()
    chain = []
    cursor = selected_main_sha
    for _ in range(MAX_FIRST_PARENT_NODES):
        _require(cursor not in seen, 'P5_FIRST_PARENT_CYCLE')
        seen.add(cursor)
        node = read_commit(cursor)
        chain.append(node)
        if cursor == expected_merge_sha:
            _require(len(node['parents']) == 2 and node['parents'][1] == expected_head_sha,
                     'P5_MERGE_METHOD_OR_HEAD_MISMATCH')
            break
        _require(bool(node['parents']), 'P5_MERGE_NOT_IN_FIRST_PARENT')
        cursor = node['parents'][0]
    else:
        raise Denied('P5_FIRST_PARENT_BOUND_EXCEEDED')
    head = read_commit(expected_head_sha)
    # This fixed contents route is already allowed by pinned transport. A
    # provider projection pinned to ref is not an independent Git tree proof.
    content = get('contents/release/targets.yaml', params={'ref': selected_main_sha})
    _require(type(content) is dict and content.get('type') == 'file' and
             content.get('path') == 'release/targets.yaml' and content.get('encoding') == 'base64' and
             type(content.get('size')) is int and 0 < content['size'] <= MAX_CATALOG_BYTES and
             type(content.get('content')) is str and len(content['content']) <= 2 * MAX_CATALOG_BYTES,
             'P5_CATALOG_PROJECTION_INVALID')
    try:
        raw = base64.b64decode(content['content'].replace('\n', ''), validate=True)
        raw.decode('utf-8')
    except (ValueError, UnicodeError, binascii.Error):
        raise Denied('P5_CATALOG_ENCODING_INVALID') from None
    _require(len(raw) == content['size'], 'P5_CATALOG_SIZE_MISMATCH')
    blob = adapter._sha(content.get('sha'))
    _require(hashlib.sha1(b'blob ' + str(len(raw)).encode('ascii') + b'\0' + raw).hexdigest() == blob,
             'P5_CATALOG_BLOB_MISMATCH')
    # Detect current PR/ref races; do not claim atomic GitHub snapshot or use
    # current mutable PR body as historical reviewed bytes.
    if read_pr() != pr:
        raise Stale('P5_PR_OBSERVATION_CHANGED')
    read_main()
    observation = {'repository': origin, 'selectedMainSha': selected_main_sha,
                   'pullRequest': pr, 'firstParent': chain, 'headCommit': head,
                   'catalog': {'path': 'release/targets.yaml', 'ref': selected_main_sha,
                               'gitBlobSha': blob, 'contentSha256': hashlib.sha256(raw).hexdigest(),
                               'size': len(raw)}}
    return {'result': 'PARTIAL_PROVIDER_OBSERVATION', 'observation': observation,
            'observationDigest': hashlib.sha256(canonical(observation).encode('utf-8')).hexdigest(),
            'evidenceVerified': False, 'admissionAllowed': False, 'deploymentAllowed': False,
            'missingProofs': ['OWNER_REVIEW_CUTOFF', 'COMPLETE_CHANGED_PATHS',
                              'HISTORICAL_REQUIRED_CI_POLICY_AND_ATTEMPTS',
                              'CATALOG_TREE_AND_COMPONENT_BINDINGS', 'DEPENDENCY_CLOSURE',
                              'PROTECTED_CAPTURE_AND_AUTHENTICATED_COLLECTOR']}

"""Fixed HTTPS READ-only Windows Mirror status integration.

The Windows Gateway GET invokes Mirror.inventory(remote=False): GitHub main,
PRs, CI and ancestry are NOT checked by this operation. Native typed GitHub
reads are separate. This package intentionally does not register pull_main.
"""
import re

from fortis_approvals.integrations.mirror.tls import MirrorPinnedAPI
from fortis_approvals.integrations.mirror.read_v2 import OPERATIONS as V2_READS
from fortis_approvals.extensions.model import Operation, Provider, bounded, check
from fortis_approvals.integrations.review_schema import object_schema

REPO = re.compile(r'[A-Za-z0-9_][A-Za-z0-9_.-]{0,119}\Z')
SHA = re.compile(r'[0-9a-f]{40}\Z')
BRANCH = re.compile(r'[A-Za-z0-9_][A-Za-z0-9_./-]{0,159}\Z')
UTC = re.compile(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\+00:00\Z')
ERROR = re.compile(r'[A-Z][A-Z0-9_]{0,99}\Z')
# v1 includes exactly one primary in the upstream inventory. The count
# ceiling is independent of the 256 KiB wire and 64 KiB projection bounds.
MAX_WORKTREES = 256


def _head(value):
    check(value is None or type(value) is str and SHA.fullmatch(value),
          'MIRROR_HEAD_INVALID')
    return value


def _branch(value):
    check(value is None or type(value) is str and BRANCH.fullmatch(value),
          'MIRROR_BRANCH_INVALID')
    return value


def _clean(value):
    check(value is None or type(value) is bool, 'MIRROR_CLEAN_INVALID')
    return value


def _docker(row, repo, kind):
    check(type(row) is dict and row.get('repoId') == repo and
          row.get('kind') == kind and type(row.get('targetEligible')) is bool,
          'MIRROR_DOCKER_INVALID')
    result = {'branch': _branch(row.get('branch')),
              'head': _head(row.get('head')),
              'clean': _clean(row.get('clean')),
              'targetEligible': row['targetEligible']}
    if kind == 'worktree':
        task = row.get('task')
        check(task is None or type(task) is str and REPO.fullmatch(task),
              'MIRROR_TASK_INVALID')
        result['task'] = task
    return result


def _windows(row, repo):
    check(type(row) is dict and row.get('repoId') == repo and
          row.get('source') == 'windows' and
          type(row.get('checkedAt')) is str and UTC.fullmatch(row['checkedAt']) and
          type(row.get('exists')) is bool and type(row.get('originValid')) is bool,
          'MIRROR_WINDOWS_INVALID')
    relation, error = row.get('relation'), row.get('error')
    check(relation in ('equal', 'behind', 'ahead', 'diverged', 'unknown') and
          (error is None or type(error) is str and ERROR.fullmatch(error)),
          'MIRROR_WINDOWS_INVALID')
    return {'source': 'windows', 'checkedAt': row['checkedAt'],
            'exists': row['exists'], 'branch': _branch(row.get('branch')),
            'head': _head(row.get('head')), 'clean': _clean(row.get('clean')),
            'originValid': row['originValid'], 'relation': relation,
            'error': error}


def validate_result(value):
    check(type(value) is dict and set(value) == {'schemaVersion','repository'} and
          value['schemaVersion'] == 1 and type(value['repository']) is dict,
          'MIRROR_RESULT_INVALID')
    r = value['repository']
    check(set(r) == {'repoId','docker','windows','github'} and
          type(r['repoId']) is str and REPO.fullmatch(r['repoId']) and
          r['github'] == {'verification': 'NOT_CHECKED'} and
          type(r['docker']) is dict and
          set(r['docker']) == {'primary','worktrees'} and
          type(r['docker']['worktrees']) is list and
          len(r['docker']['worktrees']) <= MAX_WORKTREES,
          'MIRROR_RESULT_INVALID')
    p = r['docker']['primary']
    check(type(p) is dict and set(p) == {'branch','head','clean','targetEligible'} and
          type(p['targetEligible']) is bool, 'MIRROR_RESULT_INVALID')
    _branch(p['branch']); _head(p['head']); _clean(p['clean'])
    for t in r['docker']['worktrees']:
        check(type(t) is dict and
              set(t) == {'task','branch','head','clean','targetEligible'} and
              type(t['targetEligible']) is bool and
              (t['task'] is None or type(t['task']) is str and REPO.fullmatch(t['task'])),
              'MIRROR_RESULT_INVALID')
        _branch(t['branch']); _head(t['head']); _clean(t['clean'])
    w = r['windows']
    check(type(w) is dict and
          set(w) == {'source','checkedAt','exists','branch','head','clean',
                     'originValid','relation','error'} and
          w['source'] == 'windows' and type(w['checkedAt']) is str and
          UTC.fullmatch(w['checkedAt']) and type(w['exists']) is bool and
          type(w['originValid']) is bool and
          w['relation'] in ('equal','behind','ahead','diverged','unknown') and
          (w['error'] is None or type(w['error']) is str and ERROR.fullmatch(w['error'])),
          'MIRROR_RESULT_INVALID')
    _branch(w['branch']); _head(w['head']); _clean(w['clean'])
    bounded(value,65536)


def read_repository(ctx):
    check(type(ctx.target) is str and REPO.fullmatch(ctx.target),
          'MIRROR_TARGET_INVALID')
    raw = ctx.call('get_repo', path={'repo_id':ctx.target})
    check(type(raw) is dict and set(raw) == {'schemaVersion','repository'} and
          raw['schemaVersion'] == 1 and type(raw['repository']) is dict,
          'MIRROR_UPSTREAM_INVALID')
    r = raw['repository']
    check(set(r) == {'repoId','docker','windows','github','actions','readTimingsMs'} and
          r['repoId'] == ctx.target and type(r['docker']) is dict and
          set(r['docker']) == {'primary','worktrees'} and
          type(r['docker']['worktrees']) is list and
          len(r['docker']['worktrees']) <= MAX_WORKTREES and
          type(r['github']) is dict and
          r['github'].get('error') == 'NOT_CHECKED' and
          r['github'].get('checkedAt') is None and
          type(r['actions']) is dict and
          type(r['actions'].get('pull_main')) is dict and
          r['actions']['pull_main'].get('available') is False and
          type(r['readTimingsMs']) is dict,
          'MIRROR_UPSTREAM_INVALID')
    primary = r['docker']['primary']
    projected_primary = _docker(primary, ctx.target, 'primary')
    # Windows Mirror exports the *complete* registered Git worktree inventory:
    # docker.primary is also included exactly once in docker.worktrees. Match
    # that row to the authoritative primary before excluding it from our
    # separately projected ordinary worktree list. Never silently drop an
    # extra, mismatched or forged primary row.
    projected_worktrees = []
    primary_count = 0
    for entry in r['docker']['worktrees']:
        if type(entry) is dict and entry.get('kind') == 'primary':
            check(primary_count == 0 and entry == primary, 'MIRROR_DOCKER_INVALID')
            primary_count += 1
        else:
            projected_worktrees.append(_docker(entry, ctx.target, 'worktree'))
    check(primary_count == 1, 'MIRROR_DOCKER_INVALID')
    result={'schemaVersion':1,'repository':{
        'repoId':ctx.target,
        'docker':{'primary':projected_primary,'worktrees':projected_worktrees},
        'windows':_windows(r['windows'],ctx.target),
        'github':{'verification':'NOT_CHECKED'}}}
    validate_result(result)
    return result


PROVIDER=Provider('mirror',(
    Operation('get_repository','Read fixed Windows/Docker Git status (GitHub NOT_CHECKED)',
              'read',object_schema({}),validate_result,read_repository,
              credential='link',routes=('get_repo',)),
) + V2_READS,api=MirrorPinnedAPI())

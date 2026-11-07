"""Trusted opt-in GitHub branch pilot in the existing shared Gateway.

No grants or token reads occur until a validated pilot configuration is passed.
This module owns pilot scope; Core, owner authentication and ingress stay shared.
"""
from dataclasses import dataclass
import re
import uuid

from ...core import Denied
from .gateway.adapter import GitHubAdapter
from .gateway.transport import GitHubHTTPTransport
from .registration import register_github_integration

READS = frozenset({('github', 'get_repository'), ('github', 'list_branches')})
ACTION = ('github', 'create_branch')
FILE_PR_READS = frozenset({('github', 'get_file'), ('github', 'list_pull_requests'), ('github', 'get_pull_request')})
FILE_PR_ACTIONS = frozenset({('github', 'push_files'), ('github', 'create_pull_request')})
CI_READS = frozenset({('github', 'list_workflow_runs')})
CONFIG_KEYS = ('FORTIS_GITHUB_OWNER', 'FORTIS_GITHUB_REPOSITORY', 'FORTIS_GITHUB_BRANCH_PREFIX', 'FORTIS_GITHUB_FILE_PR_BRANCH', 'FORTIS_GITHUB_CI_READS', 'FORTIS_GITHUB_NATIVE_WORKTREE', 'FORTIS_GITHUB_REQUIRED_WORKFLOWS', 'FORTIS_GITHUB_BOOTSTRAP_TASK', 'FORTIS_GITHUB_NATIVE_MULTI_REPO')


@dataclass(frozen=True)
class GitHubPilotConfig:
    owner: str
    repository: str
    branch_prefix: str = 'fortis-e2e/'
    file_pr_branch: str = ''
    ci_reads: bool = False
    native_worktree: bool = False
    required_workflows: tuple = ()
    bootstrap_task: str = ''
    dynamic_repositories: bool = False  # Trusted opt-in, not part of legacy review profiles.

    def __post_init__(self):
        if type(self.owner) is not str or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,99}', self.owner):
            raise ValueError('GITHUB_PILOT_OWNER_INVALID')
        if (type(self.repository) is not str or
                not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,99}', self.repository) or
                self.repository in ('.', '..')):
            raise ValueError('GITHUB_PILOT_REPOSITORY_INVALID')
        if (type(self.branch_prefix) is not str or
                not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,31}/', self.branch_prefix) or
                self.branch_prefix[:-1].lower() in ('main', 'master')):
            raise ValueError('GITHUB_PILOT_BRANCH_PREFIX_INVALID')

        if self.file_pr_branch:
            if type(self.file_pr_branch) is not str or not self.file_pr_branch.startswith(self.branch_prefix):
                raise ValueError('GITHUB_PILOT_FILE_PR_BRANCH_INVALID')
            tail = self.file_pr_branch[len(self.branch_prefix):]
            try:
                ident = tail.removesuffix('-approve')
                if str(uuid.UUID(ident)) != ident or tail != ident + '-approve': raise ValueError()
            except (ValueError, AttributeError):
                raise ValueError('GITHUB_PILOT_FILE_PR_BRANCH_INVALID') from None
        elif self.file_pr_branch != '':
            raise ValueError('GITHUB_PILOT_FILE_PR_BRANCH_INVALID')

        if type(self.ci_reads) is not bool or (self.ci_reads and not self.file_pr_branch):
            raise ValueError('GITHUB_PILOT_CI_OPT_IN_INVALID')

        if type(self.native_worktree) is not bool or type(self.required_workflows) is not tuple:
            raise ValueError('GITHUB_NATIVE_CONFIG_INVALID')
        if self.native_worktree:
            if (not self.ci_reads or not 1 <= len(self.required_workflows) <= 10 or
                    any(type(x) is not int or not 0 < x < 2**63 for x in self.required_workflows) or
                    len(set(self.required_workflows)) != len(self.required_workflows)):
                raise ValueError('GITHUB_NATIVE_REQUIRED_CI_INVALID')
        elif self.required_workflows:
            raise ValueError('GITHUB_NATIVE_PARTIAL_CONFIG')

        if type(self.dynamic_repositories) is not bool or (self.dynamic_repositories and not self.native_worktree):
            raise ValueError('GITHUB_DYNAMIC_REPOS_REQUIRES_NATIVE')

        if (type(self.bootstrap_task) is not str or
                (self.bootstrap_task and (not self.native_worktree or not re.fullmatch('[a-z0-9][a-z0-9-]{0,99}',self.bootstrap_task)))):
            raise ValueError('GITHUB_BOOTSTRAP_TASK_INVALID')

    @property
    def file_path(self):
        if not self.file_pr_branch: return None
        return 'docs/fortis-e2e/' + self.file_pr_branch[len(self.branch_prefix):].removesuffix('-approve') + '.txt'

    def check_endpoints(self, owner_origin, ingress_host):
        if owner_origin != 'http://localhost:19203' or ingress_host != 'host.docker.internal:19204':
            raise Denied('GITHUB_PILOT_REVIEW_ENDPOINTS_REQUIRED')


def config_from_environment(environment):
    enabled = environment.get('FORTIS_GITHUB_PILOT', '0')
    if enabled not in ('0', '1'):
        raise ValueError('GITHUB_PILOT_EXPLICIT_OPT_IN_REQUIRED')
    if enabled == '0':
        if any(key in environment for key in CONFIG_KEYS):
            raise ValueError('GITHUB_PILOT_PARTIAL_CONFIGURATION')
        return None
    ci = environment.get(CONFIG_KEYS[4], '0')
    if ci not in ('0', '1'): raise ValueError('GITHUB_PILOT_CI_OPT_IN_INVALID')
    native = environment.get(CONFIG_KEYS[5], '0')
    if native not in ('0','1'): raise ValueError('GITHUB_NATIVE_OPT_IN_INVALID')
    multi = environment.get('FORTIS_GITHUB_NATIVE_MULTI_REPO', '0')
    if multi not in ('0','1'):raise ValueError('GITHUB_DYNAMIC_REPOS_OPT_IN_INVALID')
    required = environment.get(CONFIG_KEYS[6], '')
    if required and not re.fullmatch('[1-9][0-9]*(?:,[1-9][0-9]*){0,9}',required):
        raise ValueError('GITHUB_NATIVE_REQUIRED_CI_INVALID')
    return GitHubPilotConfig(
        owner=environment.get(CONFIG_KEYS[0], ''),
        repository=environment.get(CONFIG_KEYS[1], ''),
        branch_prefix=environment.get(CONFIG_KEYS[2], 'fortis-e2e/'),
        file_pr_branch=environment.get(CONFIG_KEYS[3], ''), ci_reads=ci == '1',
        native_worktree=native == '1', required_workflows=tuple(map(int,required.split(','))) if required else (),
        bootstrap_task=environment.get(CONFIG_KEYS[7],''),dynamic_repositories=multi == '1')


class GitHubPilotAdapter(GitHubAdapter):
    def __init__(self, transport, *, config, receipt_store):
        if not isinstance(config, GitHubPilotConfig):
            raise ValueError('GITHUB_PILOT_CONFIG_REQUIRED')
        self.pilot = config
        super().__init__(transport, owner=config.owner, repositories=(config.repository,),
                         receipt_store=receipt_store)

    def _action_scope(self, request):
        if type(request) is not dict or request.get('service') != 'github':
            raise Denied('GITHUB_PILOT_ACTION_DENIED')
        operation, params = request.get('operation'), request.get('params')
        self._repo(request.get('target'))
        if type(params) is not dict: raise Denied('GITHUB_PILOT_ACTION_DENIED')
        if operation == 'create_branch':
            branch = params.get('branch')
            if (type(branch) is not str or not branch.startswith(self.pilot.branch_prefix) or
                    len(branch) <= len(self.pilot.branch_prefix)):
                raise Denied('GITHUB_PILOT_BRANCH_SCOPE_DENIED')
        elif self.pilot.file_pr_branch and operation == 'push_files':
            files = params.get('files')
            if (params.get('branch') != self.pilot.file_pr_branch or type(files) is not list or len(files) != 1 or
                    type(files[0]) is not dict or files[0].get('path') != self.pilot.file_path or
                    type(files[0].get('content')) is not str or len(files[0]['content'].encode('utf-8')) > 4096):
                raise Denied('GITHUB_PILOT_FILE_SCOPE_DENIED')
        elif self.pilot.file_pr_branch and operation == 'create_pull_request':
            if params.get('head') != self.pilot.file_pr_branch or params.get('base') != 'main' or params.get('draft') is not True:
                raise Denied('GITHUB_PILOT_DRAFT_PR_SCOPE_DENIED')
        else:
            raise Denied('GITHUB_PILOT_ACTION_DENIED')

    def read(self, request):
        operations = {name for _, name in READS | (FILE_PR_READS if self.pilot.file_pr_branch else frozenset()) |
                      (CI_READS if self.pilot.ci_reads else frozenset())}
        if (type(request) is not dict or request.get('service') != 'github' or
                request.get('operation') not in operations):
            raise Denied('GITHUB_PILOT_READ_DENIED')
        self._repo(request.get('target'))
        if request['operation'] == 'get_file' and request.get('params', {}).get('path') != self.pilot.file_path:
            raise Denied('GITHUB_PILOT_FILE_SCOPE_DENIED')
        if request['operation'] == 'list_pull_requests':
            from .contract import validate_github_read, validate_github_read_projection
            validate_github_read(request['operation'], request['target'], request['params'])
            p = request['params']
            raw = self._api('GET', self._path(request['target'], 'pulls'), params={
                'state': p['state'], 'page': p['page'], 'per_page': p['perPage'],
                'head': self.pilot.owner + ':' + self.pilot.file_pr_branch, 'base': 'main'})
            if type(raw) is not list or len(raw) > 100: raise Denied('GITHUB_PULLS_RESPONSE_INVALID')
            result = dict(operation='list_pull_requests', items=[self._project_pull(x) for x in raw],
                          page=p['page'], perPage=p['perPage'])
            if any(x['head']['ref'] != self.pilot.file_pr_branch or x['base']['ref'] != 'main' for x in result['items']):
                raise Denied('GITHUB_PILOT_PR_SCOPE_DENIED')
            validate_github_read_projection('list_pull_requests', result)
            return result
        result = super().read(request)
        if request['operation'] == 'get_pull_request':
            p = result['pullRequest']
            if p['head']['ref'] != self.pilot.file_pr_branch or p['base']['ref'] != 'main':
                raise Denied('GITHUB_PILOT_PR_SCOPE_DENIED')
        return result

    def prepare(self, request):
        self._action_scope(request)
        snapshot = super().prepare(request)
        # Changing trusted owner/repository/prefix invalidates an old preview
        # without changing Sonar's existing policy version or pending requests.
        return {**snapshot, 'pilotOwner': self.pilot.owner,
                'pilotBranchPrefix': self.pilot.branch_prefix,
                'pilotFilePrBranch': self.pilot.file_pr_branch, 'pilotFilePath': self.pilot.file_path}

    def apply(self, request):
        self._action_scope(request)
        return super().apply(request)


def install_pilot(*, core, portal, broker, config, root, actor, transport=None):
    if not isinstance(config, GitHubPilotConfig):
        raise ValueError('GITHUB_PILOT_CONFIG_REQUIRED')
    if portal.core is not core or broker.core is not core:
        raise ValueError('GITHUB_PILOT_SHARED_CORE_REQUIRED')
    adapter = GitHubPilotAdapter(
        transport if transport is not None else GitHubHTTPTransport.from_file(),
        config=config, receipt_store=root / 'github-receipts.sqlite')
    register_github_integration(core=core, broker=broker, adapter=adapter)
    reads = READS | (FILE_PR_READS if config.file_pr_branch else frozenset()) | (CI_READS if config.ci_reads else frozenset())
    actions = {ACTION} | (FILE_PR_ACTIONS if config.file_pr_branch else frozenset())
    for service, operation in reads:
        core.policies[(actor, service, operation)] = 'ALLOW'
    for service, operation in actions:
        core.policies[(actor, service, operation)] = 'ASK'
    broker.actor_read_operations[actor] = broker.actor_read_operations.get(actor, frozenset()) | reads
    broker.actor_operations[actor] = broker.actor_operations.get(actor, frozenset()) | actions
    portal.strong_operations = portal.strong_operations | actions
    return adapter

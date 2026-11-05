"""Trusted opt-in GitHub branch pilot in the existing shared Gateway.

No grants or token reads occur until a validated pilot configuration is passed.
This module owns pilot scope; Core, owner authentication and ingress stay shared.
"""
from dataclasses import dataclass
import re

from ...core import Denied
from .gateway.adapter import GitHubAdapter
from .gateway.transport import GitHubHTTPTransport
from .registration import register_github_integration

READS = frozenset({('github', 'get_repository'), ('github', 'list_branches')})
ACTION = ('github', 'create_branch')
CONFIG_KEYS = ('FORTIS_GITHUB_OWNER', 'FORTIS_GITHUB_REPOSITORY', 'FORTIS_GITHUB_BRANCH_PREFIX')


@dataclass(frozen=True)
class GitHubPilotConfig:
    owner: str
    repository: str
    branch_prefix: str = 'fortis-e2e/'

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
    return GitHubPilotConfig(
        owner=environment.get(CONFIG_KEYS[0], ''),
        repository=environment.get(CONFIG_KEYS[1], ''),
        branch_prefix=environment.get(CONFIG_KEYS[2], 'fortis-e2e/'))


class GitHubPilotAdapter(GitHubAdapter):
    def __init__(self, transport, *, config, receipt_store):
        if not isinstance(config, GitHubPilotConfig):
            raise ValueError('GITHUB_PILOT_CONFIG_REQUIRED')
        self.pilot = config
        super().__init__(transport, owner=config.owner, repositories=(config.repository,),
                         receipt_store=receipt_store)

    def _action_scope(self, request):
        if (type(request) is not dict or request.get('service') != 'github' or
                request.get('operation') != 'create_branch'):
            raise Denied('GITHUB_PILOT_ACTION_DENIED')
        self._repo(request.get('target'))
        params = request.get('params')
        if (type(params) is not dict or type(params.get('branch')) is not str or
                not params['branch'].startswith(self.pilot.branch_prefix) or
                len(params['branch']) <= len(self.pilot.branch_prefix)):
            raise Denied('GITHUB_PILOT_BRANCH_SCOPE_DENIED')

    def read(self, request):
        if (type(request) is not dict or request.get('service') != 'github' or
                request.get('operation') not in ('get_repository', 'list_branches')):
            raise Denied('GITHUB_PILOT_READ_DENIED')
        self._repo(request.get('target'))
        return super().read(request)

    def prepare(self, request):
        self._action_scope(request)
        snapshot = super().prepare(request)
        # Changing trusted owner/repository/prefix invalidates an old preview
        # without changing Sonar's existing policy version or pending requests.
        return {**snapshot, 'pilotOwner': self.pilot.owner,
                'pilotBranchPrefix': self.pilot.branch_prefix}

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
    for service, operation in READS:
        core.policies[(actor, service, operation)] = 'ALLOW'
    core.policies[(actor, *ACTION)] = 'ASK'
    broker.actor_read_operations[actor] = broker.actor_read_operations.get(actor, frozenset()) | READS
    broker.actor_operations[actor] = broker.actor_operations.get(actor, frozenset()) | {ACTION}
    portal.strong_operations = portal.strong_operations | {ACTION}
    return adapter

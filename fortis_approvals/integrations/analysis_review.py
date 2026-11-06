"""Explicit trusted configuration for the analysis-review profile; no deployment."""
import re
from pathlib import Path

from ..core import Denied
from .review_schema import require, fields, ident, text, boolean, strict_json
from .sonarcloud.analysis_contract import READS as SONAR_READS, ACTIONS as SONAR_ACTIONS
from .github.analysis_contract import READS as GITHUB_READS, ACTIONS as GITHUB_ACTIONS
from .sonarcloud.gateway.review_actions import SonarReviewAdapter
from .github.gateway.analysis_adapter import AnalysisGitHubAdapter, GitHubReviewRouter
from .github.gateway.transport import GitHubHTTPTransport


class AnalysisReviewConfig:
    def __init__(self, *, owner, bindings, sonar_mutations=False):
        text(owner, 100, empty=False)
        require(re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.-]{0,99}', owner))
        boolean(sonar_mutations)
        require(type(bindings) is dict and 1 <= len(bindings) <= 20)
        checked = {}
        for repo, binding in bindings.items():
            require(type(repo) is str and re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.-]{0,99}', repo))
            fields(binding, ('projectKey', 'workflows', 'allowCiControl'))
            ident(binding['projectKey']); boolean(binding['allowCiControl'])
            workflows = binding['workflows']
            require(type(workflows) is dict and 1 <= len(workflows) <= 10)
            for workflow_id, path in workflows.items():
                require(type(workflow_id) is str and re.fullmatch('[1-9][0-9]{0,17}', workflow_id))
                require(type(path) is str and re.fullmatch(r'\.github/workflows/[A-Za-z0-9_-]+\.ya?ml', path))
            checked[repo] = dict(projectKey=binding['projectKey'], workflows=dict(workflows),
                                 allowCiControl=binding['allowCiControl'])
        self.owner, self.bindings, self.sonar_mutations = owner, checked, sonar_mutations

    def check_endpoints(self, owner_origin, ingress_host):
        require(owner_origin == 'http://localhost:19203' and ingress_host == 'host.docker.internal:19204',
                'ANALYSIS_REVIEW_ISOLATED_ENDPOINTS_REQUIRED')

    @classmethod
    def from_environment(cls, env):
        raw = env.get('FORTIS_ANALYSIS_REVIEW_CONFIG')
        if raw is None: return None
        require(type(raw) is str and 1 <= len(raw.encode()) <= 16000)
        try:
            value = strict_json(raw)
        except (ValueError, TypeError):
            raise Denied('ANALYSIS_REVIEW_CONFIG_INVALID') from None
        fields(value, ('owner', 'bindings', 'sonarMutations'))
        return cls(owner=value['owner'], bindings=value['bindings'], sonar_mutations=value['sonarMutations'])


def install(*, core, portal, broker, config, root, actor, github_transport=None):
    require(isinstance(config, AnalysisReviewConfig), 'ANALYSIS_REVIEW_CONFIG_REQUIRED')
    require(portal.core is core and broker.core is core)
    reader = broker.read_adapters['sonarcloud']
    allowed = reader._allowed_projects
    require(allowed is not None and {b['projectKey'] for b in config.bindings.values()} <= allowed,
            'ANALYSIS_REVIEW_PROJECT_NOT_PINNED')
    from .sonarcloud.gateway.read_adapter import SonarReadOnlyTransport
    from .sonarcloud.gateway.sonar import SonarHTTPTransport
    from .sonarcloud.gateway.analysis_transport import SonarAnalysisTransport
    old = core.adapters['sonarcloud']
    upstream_sonar = old.transport
    if isinstance(upstream_sonar, SonarHTTPTransport) and not isinstance(upstream_sonar, SonarAnalysisTransport):
        upstream_sonar = SonarAnalysisTransport(upstream_sonar)
    reader._reader = SonarReadOnlyTransport(upstream_sonar, analysis_review=True)
    if not isinstance(old, SonarReviewAdapter):
        core.adapters['sonarcloud'] = SonarReviewAdapter(upstream_sonar, project_keys=tuple(old.projects),
            organization_keys=tuple(old.organizations), receipt_store=old.store, region=old.region)
    existing = core.adapters.get('github')
    if isinstance(existing, GitHubReviewRouter): raise Denied('ANALYSIS_REVIEW_ALREADY_INSTALLED')
    if existing is not None:
        require(existing.owner == config.owner, 'ANALYSIS_REVIEW_OWNER_MISMATCH')
    upstream = github_transport or (existing.transport if existing is not None else GitHubHTTPTransport.from_file())
    review = AnalysisGitHubAdapter(upstream, owner=config.owner, repositories=tuple(config.bindings),
        receipt_store=Path(root)/'analysis-github-receipts.sqlite', bindings=config.bindings)
    router = GitHubReviewRouter(review, existing)
    core.adapters['github'] = router; broker.read_adapters['github'] = router
    reads = SONAR_READS | GITHUB_READS
    actions = (SONAR_ACTIONS if config.sonar_mutations else frozenset())
    # These actor-wide grants are narrowed again by the trusted adapter's exact
    # repository/workflow binding and per-repository control switch.
    if any(x['allowCiControl'] for x in config.bindings.values()): actions |= GITHUB_ACTIONS
    for service, op in reads: core.policies[(actor, service, op)] = 'ALLOW'
    for service, op in actions: core.policies[(actor, service, op)] = 'ASK'
    broker.actor_read_operations[actor] = broker.actor_read_operations.get(actor, frozenset()) | reads
    broker.actor_operations[actor] = broker.actor_operations.get(actor, frozenset()) | actions
    portal.strong_operations = portal.strong_operations | actions
    return router

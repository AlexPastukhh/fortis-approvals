"""Owner-composed P3 publisher scope. No credential, grant or activation side effect."""
from dataclasses import dataclass
import hashlib
import re

from ...core import Conflict, Denied, canonical

ACTOR = 'release-label-publisher-v1'
REPOSITORY = 'fortis-approvals'
WRITES = frozenset({'add_pr_release_labels', 'remove_pr_release_label'})
LABEL_WRITES = WRITES | {'create_release_label'}
READS = frozenset({'get_branch', 'get_pull_request', 'get_pr_release_impact_evidence',
    'list_repository_labels', 'list_pr_labels', 'get_pr_release_label_context',
    'list_head_workflow_runs', 'get_workflow_run', 'list_workflow_jobs'})


def require(value, code='GITHUB_PUBLISHER_SCOPE_DENIED'):
    if not value:
        raise Denied(code)


@dataclass(frozen=True)
class PublisherProfile:
    enabled: bool = False
    revision: str = ''
    validator_revision: str = ''
    registry_delegation: bool = False

    def __post_init__(self):
        if type(self.enabled) is not bool or type(self.registry_delegation) is not bool:
            raise ValueError('GITHUB_PUBLISHER_CONFIG_INVALID')
        if (type(self.revision) is not str or type(self.validator_revision) is not str or
                (self.revision and not re.fullmatch(r'[0-9a-f]{64}', self.revision)) or
                (self.validator_revision and not re.fullmatch(r'[0-9a-f]{40}', self.validator_revision)) or
                self.enabled and (not self.revision or not self.validator_revision or
                                  not self.registry_delegation)):
            raise ValueError('GITHUB_PUBLISHER_REVIEW_PINS_REQUIRED')

    def policy(self, actor, request):
        if (not self.enabled or actor != ACTOR or request.get('service') != 'github' or
                request.get('target') != REPOSITORY):
            return 'DENY'
        op = request.get('operation')
        return 'ASK' if op in WRITES else 'ALLOW' if op in READS else 'DENY'

    def owner_policy_map(self):
        """Pure blueprint; trusted owner must explicitly compose policies/grants."""
        return {(ACTOR, 'github', op): self.policy for op in READS | WRITES}

    def validate_composition(self, core, broker, registry_actor, config):
        if registry_actor == ACTOR:
            raise ValueError('GITHUB_PUBLISHER_MUST_NOT_BORROW_REPO_ACTOR')
        if not self.enabled:
            return
        if (type(getattr(broker, 'actor_authorizers', None)) is not dict or
                config is None or config.repository != REPOSITORY or
                not config.native_worktree or not config.ci_reads or
                not core.auth.active(ACTOR) or
                broker.actor_operations.get(ACTOR) != frozenset(('github', x) for x in WRITES) or
                broker.actor_read_operations.get(ACTOR) != frozenset(('github', x) for x in READS)):
            raise ValueError('GITHUB_PUBLISHER_EXPLICIT_OWNER_GRANTS_REQUIRED')
        for op in READS | WRITES:
            request = dict(service='github', operation=op, target=REPOSITORY, params={})
            if core._policy(ACTOR, request) != ('ASK' if op in WRITES else 'ALLOW'):
                raise ValueError('GITHUB_PUBLISHER_EXPLICIT_OWNER_POLICY_REQUIRED')

    def bind_guards(self, core, broker, adapter):
        """Install deny/validation guards only. Never add credentials or grants."""
        guards = getattr(broker, 'actor_authorizers', None)
        if guards is None and not self.enabled:
            # Historical metadata/policy-only composition has no action hooks.
            # It is compatible only while no publisher grant is present.
            if (ACTOR not in getattr(broker, 'actor_operations', {}) and
                    ACTOR not in getattr(broker, 'actor_read_operations', {})):
                return
        if type(guards) is not dict:
            raise ValueError('GITHUB_PUBLISHER_BROKER_GUARDS_REQUIRED')
        def guard(who, request, kind):
            if kind != 'status':
                try:
                    self.validate_composition(core, broker, adapter.actor, adapter.config)
                except ValueError:
                    raise Denied('GITHUB_PUBLISHER_COMPOSITION_CHANGED') from None
            return self.authorize(who, request, kind, core, adapter)
        guards[ACTOR] = guard
        adapter.publisher_broker = broker

    def fingerprint(self, registry_actor):
        return hashlib.sha256(canonical(dict(version=1, actor=ACTOR, repository=REPOSITORY,
            enabled=self.enabled, revision=self.revision, validatorRevision=self.validator_revision,
            registryDelegation=self.registry_delegation, registryActor=registry_actor,
            trigger='owner-one-shot', writes=sorted(WRITES), reads=sorted(READS))).encode()).hexdigest()

    @staticmethod
    def own_row(row):
        request = row.get('request', {})
        require(row.get('actor') == ACTOR and request.get('service') == 'github' and
                request.get('target') == REPOSITORY and request.get('operation') in WRITES,
                'GITHUB_PUBLISHER_OWN_REQUEST_REQUIRED')
        return row

    def authorize(self, actor, request, kind, core, adapter=None):
        require(actor == ACTOR)
        # Existing own receipts remain readable when future admission is disabled.
        if kind == 'status':
            require(request.get('service') == 'github' and request.get('target') == REPOSITORY
                    and request.get('operation') in WRITES)
            return
        require(self.enabled, 'GITHUB_PUBLISHER_DISABLED')
        require(request.get('service') == 'github' and request.get('target') == REPOSITORY)
        op = request.get('operation')
        require(kind in ('read', 'action') and op in (READS if kind == 'read' else WRITES))
        require(core._policy(actor, request) == ('ALLOW' if kind == 'read' else 'ASK'),
                'GITHUB_PUBLISHER_POLICY_REQUIRED')
        if kind == 'read' and op == 'get_branch':
            branch = request['params']['branch']
            if branch != 'main':
                require(adapter is not None and self.registry_delegation)
                adapter.task_branch(REPOSITORY, branch)  # existing Repo registration, read only

    def gated(self, request):
        return (self.enabled and request.get('service') == 'github' and
                type(request.get('target')) is str and request['target'].casefold() == REPOSITORY
                and request.get('operation') in LABEL_WRITES)

    def admission_guard(self, adapter, request):
        core = adapter.observation_core
        if core is None:
            require(not self.gated(request), 'GITHUB_PUBLISHER_CORE_REQUIRED')
            return
        with core._db() as db:
            own = db.execute('SELECT actor,state FROM requests WHERE id=?',
                             (request['requestId'],)).fetchone()
            # The actor is server evidence on existing requests, never payload data.
            if own is not None and own['actor'] == ACTOR:
                require(hasattr(adapter, 'publisher_broker'), 'GITHUB_PUBLISHER_COMPOSITION_REQUIRED')
                try:
                    self.validate_composition(core, adapter.publisher_broker, adapter.actor, adapter.config)
                except ValueError:
                    raise Denied('GITHUB_PUBLISHER_COMPOSITION_CHANGED') from None
                self.authorize(ACTOR, request, 'action', core, adapter)
            if not self.gated(request):
                return
            # Core.submit/execute hold BEGIN IMMEDIATE while calling prepare.
            # This read connection sees the committed inventory while every
            # competing Core writer is serialized by that existing transaction.
            other = db.execute("""SELECT id FROM requests WHERE id != ?
                AND state IN ('PENDING','APPROVED','DISPATCHED')
                AND json_extract(payload,'$.service')='github'
                AND lower(json_extract(payload,'$.target'))=?
                AND json_extract(payload,'$.operation') IN
                    ('create_release_label','add_pr_release_labels','remove_pr_release_label')
                LIMIT 1""", (request['requestId'], REPOSITORY)).fetchone()
        if other is not None:
            if own is not None:
                from ...core import Stale
                raise Stale('GITHUB_RELEASE_LABEL_ACTIVE_REQUEST')
            raise Conflict('GITHUB_RELEASE_LABEL_ACTIVE_REQUEST')

    def capabilities(self, owner, registry_actor, *, available=None):
        active = self.enabled and (available is None or available is True)
        return dict(owner=owner, repository=REPOSITORY, dynamicRepositories=False,
            branchPrefix='task/', workspaceOperations=[], allowGitHub=[],
            askGitHub=sorted(WRITES) if active else [], gitHubCredentialInRepo=False,
            githubReleaseImpactReads=['get_pr_release_impact_evidence'] if active else [],
            githubReleaseLabelReads=['list_repository_labels','list_pr_labels',
                'get_pr_release_label_context'] if active else [],
            githubCiReads=['get_workflow_run','list_workflow_jobs'] if active else [],
            githubHeadWorkflowReads=dict(version=1, operation='list_head_workflow_runs',
                maxRuns=100, pageSize=20) if active else None,
            githubReleaseLabelWrites=dict(policy='ASK' if active else 'DENY',
                commands=sorted(WRITES), scope='registered-open-same-repo-task-PR-only',
                unknownEffect='STOP', automaticPublisher='OWNER_ONE_SHOT_ASK' if active else 'NOT_ACTIVE'),
            requestEvidence=dict(version=1, scope='own-release-label-requests', actor=ACTOR,
                repository=REPOSITORY, operations=sorted(WRITES), readOnly=True, crossActorDetails=False),
            publisherProfile=dict(version=1, enabled=active, configured=self.enabled, actor=ACTOR, repository=REPOSITORY,
                profileSha256=self.fingerprint(registry_actor), validatorRevision=self.validator_revision,
                trigger='owner-one-shot', ciAdmission='preview-and-before-write-v1',
                activeRequestGuard='repository-wide-v1', registryDelegation=self.registry_delegation))

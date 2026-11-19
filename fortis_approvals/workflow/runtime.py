"""Trusted opt-in native Git/worktree composition, one existing Core/portal."""
from .adapters import NativeGitHubAdapter, WorkspaceAdapter
from .common import WORKSPACE_OPS
from .git_backend import GitHubGitBackend
from .ingress import NativeIngress
from .store import Store
from ..integrations.github.publisher_profile import PublisherProfile
from ..integrations.github.contract import LEGACY_READ_OPERATIONS, DEPLOYMENT_READ_OPERATIONS
from ..integrations.github.analysis_contract import READS as CI_READS, ACTIONS as CI_ACTIONS
from ..integrations.github.gateway.transport import GitHubHTTPTransport
from ..integrations.github.registration import register_github_integration


def install(*,core,portal,broker,config,root,actor,transport=None,backend=None,worker_wait=90,
            publisher_profile=None, machine_shell=None):
    # Default is disabled; production controller must independently provision
    # reviewed protected machine keys/config and opt in after Windows proof tests.
    if machine_shell is not None:
        from ..powershell_machine import MachinePowerShellAdapter
        if type(machine_shell) is not MachinePowerShellAdapter or machine_shell.actor != actor:
            raise ValueError('MACHINE_POWERSHELL_COMPOSITION_DENIED')
        machine_shell.bind_core(core)
        # Every machine PowerShell ASK requires a fresh WebAuthn ceremony.
        # Existing owner session/CSRF alone must NEVER approve this effect.
        portal.strong_operations = portal.strong_operations | {
            ('powershell', 'execute')}
    publisher = PublisherProfile() if publisher_profile is None else publisher_profile
    if type(publisher) is not PublisherProfile:
        raise ValueError('GITHUB_PUBLISHER_CONFIG_INVALID')
    publisher.validate_composition(core, broker, actor, config)
    store=Store(root/'native-git')
    adapter=NativeGitHubAdapter(transport or GitHubHTTPTransport.from_file(),config=config,root=root,actor=actor,
        backend=backend or GitHubGitBackend(store.root/'git',owner=config.owner,repositories=None if config.dynamic_repositories else (config.repository,)),store=store,observation_core=core,
        publisher_profile=publisher)
    register_github_integration(core=core,broker=broker,adapter=adapter)
    reads=(LEGACY_READ_OPERATIONS|CI_READS)-{('github','list_repositories')}
    if config.dynamic_repositories:
        reads=reads|{('github','list_repositories')}
    writes={('github',x) for x in ('push_commits','create_pull_request','mark_pr_ready','merge_pull_request','update_pull_request','update_workflow_file','publish_visual_review','append_visual_revision','create_release_label','add_pr_release_labels','remove_pr_release_label')}
    for service,operation in reads:core.policies[(actor,service,operation)]='ALLOW'
    for service,operation in writes:core.policies[(actor,service,operation)]='ASK'
    core.policies[(actor,'github','push_commits')]=adapter.push_policy
    # Only this admitted actor AND exact configured repository receive PR ALLOW.
    # The generic ASK and all other actor/repository scopes remain unchanged.
    if config.dynamic_repositories:
        core.policies[(actor,'github','create_pull_request')]='ALLOW'
    else:
        core.policies[(actor,'github','create_pull_request',config.repository)]='ALLOW'
    # Exact target only; the generic Github ASK remains for other actions.
    core.policies[(actor,'github','publish_visual_review')]='DENY'
    # Owner-approved scoped autonomy: visual PNG publication only in the pinned
    # private visual-workspace repository. GitHub merges and other writes stay ASK.
    core.policies[(actor,'github','publish_visual_review','visual-workspace')]='ALLOW'
    # A bounded append-only revision is allowed ONLY for this private repo,
    # and ONLY after the adapter verifies the original Fortis-created Issue,
    # durable version chain and one-shot Core dispatch. Generic comments DENY.
    core.policies[(actor,'github','append_visual_revision')]='DENY'
    core.policies[(actor,'github','append_visual_revision','visual-workspace')]='ALLOW'
    # CI control stays DENY until the operator explicitly pins repositories.
    if config.ci_control_repositories:
        writes=writes|CI_ACTIONS
        for service,operation in CI_ACTIONS:
            for ci_repo in config.ci_control_repositories:
                core.policies[(actor,service,operation,ci_repo)]='ASK'
    # P4: these READs never inherit legacy/dynamic-Repo access. A trusted,
    # owner-reviewed exact repository list is necessary to add broker grants.
    # The per-actor generic policy stays DENY even when repository opt-in exists.
    for service,operation in DEPLOYMENT_READ_OPERATIONS:
        core.policies[(actor,service,operation)]='DENY'
    cd_repos=config.cd_read_repositories
    if cd_repos:
        reads=reads|DEPLOYMENT_READ_OPERATIONS
        for service,operation in DEPLOYMENT_READ_OPERATIONS:
            for repository in cd_repos:
                core.policies[(actor,service,operation,repository)]='ALLOW'
    broker.actor_read_operations[actor]=broker.actor_read_operations.get(actor,frozenset())|reads
    broker.actor_operations[actor]=broker.actor_operations.get(actor,frozenset())|writes
    workspace=WorkspaceAdapter(core=core,github=adapter,store=store,actor=actor,wait_seconds=worker_wait)
    core.adapters['workspace']=workspace
    for operation in WORKSPACE_OPS:core.policies[(actor,'workspace',operation)]='ALLOW'
    core.policies[(actor,'workspace','cleanup_task')]=workspace.cleanup_policy
    portal.strong_operations=portal.strong_operations|writes|{('workspace','cleanup_task')}
    # Deny guards exist even without an enabled profile. These do not issue a
    # credential or install publisher grants/ALLOW/ASK policy. Owner composition
    # must supply those explicitly before opting in to the reviewed profile.
    publisher.bind_guards(core, broker, adapter)
    return dict(adapter=adapter,workspace=workspace,store=store,actor=actor,publisher=publisher)


def wrap(ingress,installed):
    return NativeIngress(ingress,github=installed['adapter'],workspace=installed['workspace'],
                         store=installed['store'],actor=installed['actor'],publisher_profile=installed.get('publisher'))

"""Trusted opt-in native Git/worktree composition, one existing Core/portal."""
from .adapters import NativeGitHubAdapter, WorkspaceAdapter
from .common import WORKSPACE_OPS
from .git_backend import GitHubGitBackend
from .ingress import NativeIngress
from .store import Store
from ..integrations.github.contract import LEGACY_READ_OPERATIONS
from ..integrations.github.analysis_contract import READS as CI_READS, ACTIONS as CI_ACTIONS
from ..integrations.github.gateway.transport import GitHubHTTPTransport
from ..integrations.github.registration import register_github_integration


def install(*,core,portal,broker,config,root,actor,transport=None,backend=None,worker_wait=90):
    store=Store(root/'native-git')
    adapter=NativeGitHubAdapter(transport or GitHubHTTPTransport.from_file(),config=config,root=root,actor=actor,
        backend=backend or GitHubGitBackend(store.root/'git',owner=config.owner,repositories=None if config.dynamic_repositories else (config.repository,)),store=store,observation_core=core)
    register_github_integration(core=core,broker=broker,adapter=adapter)
    reads=(LEGACY_READ_OPERATIONS|CI_READS)-{('github','list_repositories')}
    if config.dynamic_repositories:
        reads=reads|{('github','list_repositories')}
    writes={('github',x) for x in ('push_commits','create_pull_request','mark_pr_ready','merge_pull_request','update_pull_request','update_workflow_file','publish_visual_review','create_release_label','add_pr_release_labels','remove_pr_release_label')}
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
    # CI control stays DENY until the operator explicitly pins repositories.
    if config.ci_control_repositories:
        writes=writes|CI_ACTIONS
        for service,operation in CI_ACTIONS:
            for ci_repo in config.ci_control_repositories:
                core.policies[(actor,service,operation,ci_repo)]='ASK'
    broker.actor_read_operations[actor]=broker.actor_read_operations.get(actor,frozenset())|reads
    broker.actor_operations[actor]=broker.actor_operations.get(actor,frozenset())|writes
    workspace=WorkspaceAdapter(core=core,github=adapter,store=store,actor=actor,wait_seconds=worker_wait)
    core.adapters['workspace']=workspace
    for operation in WORKSPACE_OPS:core.policies[(actor,'workspace',operation)]='ALLOW'
    core.policies[(actor,'workspace','cleanup_task')]=workspace.cleanup_policy
    portal.strong_operations=portal.strong_operations|writes|{('workspace','cleanup_task')}
    return dict(adapter=adapter,workspace=workspace,store=store,actor=actor)


def wrap(ingress,installed):
    return NativeIngress(ingress,github=installed['adapter'],workspace=installed['workspace'],
                         store=installed['store'],actor=installed['actor'])

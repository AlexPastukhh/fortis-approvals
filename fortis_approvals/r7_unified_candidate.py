"""R7 unified Sonar READ + owner-WebAuthn ASK/APPROVE/EXECUTE candidate.

ONE Core, ONE owner WebAuthn portal/queue, ONE authenticated machine ingress.
The machine may submit a typed accept_issue ASK proposal; it cannot approve,
execute, choose a transport, or access owner routes. Sonar POST is available
only through Core.execute after an exact owner WebAuthn approval. Project
scope is pinned by trusted deployment configuration. SOURCE ONLY, NO DEPLOYMENT.
Never adopt A3/R5/G2/G4 identity or state; R7 requires a NEW private root.
"""
import os
from pathlib import Path
import re
import stat
from urllib.parse import urlsplit

from .core import Authenticator, Core, Denied
from .owner_auth import OwnerWebAuthn
from .owner_portal import OwnerPortal
from .incidents import IncidentCore, IncidentOwnerWebAuthn, IncidentOwnerPortal
from .repo_action_contract import RepoIntentBroker
from .integrations.sonarcloud.contract import LEGACY_READ_OPERATIONS as SONAR_READ_OPERATIONS
from .repo_ingress import RepoIngress
from .r5_read_candidate import _GRANT, _RESERVED_OWNER_ORIGINS
from .integrations.github.publisher_profile import (
    ACTOR as PUBLISHER_ACTOR, READS as PUBLISHER_READS,
    WRITES as PUBLISHER_WRITES, PublisherProfile,
)
from .integrations.sonarcloud.gateway.sonar import SonarIssueAdapter
from .integrations.sonarcloud.gateway.read_adapter import SonarReadAdapter


ACTOR = 'repo-sonar-read-proposal-actor'
G4_OPERATION = ('sonarcloud', 'accept_issue')


MARKER = '.fortis-r7-unified-v1'
_MARKER_CONTENT = b'fortis-r7-unified-v1\n'


def _fresh_r7_state(path):
    root = Path(path)
    if not root.is_absolute() or root.is_symlink() or not root.is_dir():
        raise Denied('R7_NEW_PRIVATE_STATE_REQUIRED')
    info = root.stat()
    real = root.resolve()
    forbidden = (Path('/workspace/repo'), Path('/workspace/repos'))
    if (info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700 or
            any(real == p or p in real.parents for p in forbidden) or
            real in (Path('/state'), Path('/run'))):
        raise Denied('R7_NEW_PRIVATE_STATE_REQUIRED')
    marker = root / MARKER
    if marker.is_symlink():
        raise Denied('R7_STATE_MARKER_INVALID')
    if marker.exists():
        status = marker.stat()
        if (not stat.S_ISREG(status.st_mode) or
                status.st_uid != os.geteuid() or
                stat.S_IMODE(status.st_mode) != 0o600 or
                marker.read_bytes() != _MARKER_CONTENT):
            raise Denied('R7_STATE_MARKER_INVALID')
        return root
    if any(root.iterdir()):
        raise Denied('R7_FRESH_STATE_ONLY_NO_ADOPTION')
    fd = os.open(marker, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(_MARKER_CONTENT)
        stream.flush()
        os.fsync(stream.fileno())
    return root


def build_r7_unified_candidate(*, state, owner_origin, ingress_host,
                              ingress_grant, sonar_transport,
                              organizations, region='eu', actor_grants=None,
                              project_keys=None, github_pilot=None,
                              github_transport=None, analysis_review=None, extensions=None, extension_providers=None, credential_vault=None,
                              publisher_profile=None, publisher_grant=None,
                              machine_shell=None, local_deny_source_opt_in=None,
                              unified_policy_source_opt_in=None,
                              registry_candidate_reader=None):
    """Return (core, owner, portal, ingress), no listeners or token provisioning.

    Restricted machine actor is authorized for four READ + one ASK proposal;
    the same actor NEVER receives owner decisions, raw service token or POST.
    """
    # Explicit trusted composition selector. The normal server only creates
    # the restricted variant for the reviewed owner release config.
    if unified_policy_source_opt_in is not None:
        from .extensions.owner_policy_r7_v2 import R7UnifiedPolicySourceOptIn
        if (type(unified_policy_source_opt_in) is not R7UnifiedPolicySourceOptIn or
                local_deny_source_opt_in is not None):
            raise Denied('R7_UNIFIED_POLICY_SOURCE_OPT_IN_REJECTED')
    if local_deny_source_opt_in is not None:
        from .extensions.owner_policy_r7_optin_phase6c4 import R7LocalDenySourceOptIn
        if type(local_deny_source_opt_in) is not R7LocalDenySourceOptIn:
            raise Denied('R7_LOCAL_DENY_SOURCE_OPT_IN_REJECTED')
    if (type(owner_origin) is not str or
            owner_origin in _RESERVED_OWNER_ORIGINS or
            not re.fullmatch(r'http://localhost:[0-9]{4,5}', owner_origin) or
            type(ingress_host) is not str or
            not re.fullmatch(r'host\.docker\.internal:[0-9]{4,5}', ingress_host) or
            urlsplit(owner_origin).netloc == ingress_host):
        raise Denied('R7_DISTINCT_OWNER_INGRESS_REQUIRED')
    if type(ingress_grant) is not str or not _GRANT.fullmatch(ingress_grant):
        raise Denied('R7_MACHINE_GRANT_INVALID')
    if analysis_review is not None:
        from .integrations.analysis_review import AnalysisReviewConfig
        if not isinstance(analysis_review, AnalysisReviewConfig):
            raise ValueError('ANALYSIS_REVIEW_CONFIG_REQUIRED')
        analysis_review.check_endpoints(owner_origin, ingress_host)
    if github_pilot is not None:
        from .integrations.github.pilot import GitHubPilotConfig
        if not isinstance(github_pilot, GitHubPilotConfig):
            raise ValueError('GITHUB_PILOT_CONFIG_REQUIRED')
        github_pilot.check_endpoints(owner_origin, ingress_host)
    if machine_shell is not None:
        from .powershell_machine import MachinePowerShellAdapter
        from .integrations.github.pilot import GitHubPilotConfig
        if (type(machine_shell) is not MachinePowerShellAdapter or
                type(github_pilot) is not GitHubPilotConfig or
                github_pilot.native_worktree is not True):
            raise Denied('MACHINE_POWERSHELL_NATIVE_COMPOSITION_REQUIRED')
    # A separately mounted owner principal is NEVER part of the legacy actor
    # list: those actors inherit Sonar READ/ASK and optional extension scopes.
    # In particular, accepting a publisher in actor_grants would silently
    # grant it the wrong powers before the native guards were installed.
    grants = ({ingress_grant: ACTOR} if actor_grants is None else actor_grants)
    if (type(grants) is not dict or not grants or
            any(type(grant) is not str or not _GRANT.fullmatch(grant) or
                type(actor) is not str or not actor
                for grant, actor in grants.items()) or
            len(set(grants.values())) != len(grants) or
            ingress_grant not in grants):
        raise Denied('R7_MACHINE_GRANTS_INVALID')
    internal_actors=('release-registry-collector-v1','release-registry-planner-v1')
    if any(actor in grants.values() for actor in internal_actors):
        raise Denied('R7_REGISTRY_INTERNAL_ACTOR_LEGACY_GRANT_DENIED')
    if PUBLISHER_ACTOR in grants.values():
        raise Denied('R7_PUBLISHER_LEGACY_GRANT_DENIED')
    if publisher_profile is not None and type(publisher_profile) is not PublisherProfile:
        raise Denied('R7_PUBLISHER_PROFILE_INVALID')
    profile = PublisherProfile() if publisher_profile is None else publisher_profile
    enabled = profile.enabled
    if (enabled != (publisher_grant is not None) or
            publisher_profile is not None and not enabled):
        raise Denied('R7_PUBLISHER_ACTIVATION_PAIR_REQUIRED')
    if enabled:
        if (type(publisher_grant) is not str or
                not _GRANT.fullmatch(publisher_grant) or
                publisher_grant in grants or
                github_pilot is None or
                not github_pilot.native_worktree or not github_pilot.ci_reads):
            raise Denied('R7_PUBLISHER_TRUSTED_COMPOSITION_REQUIRED')
    # The existing Repo/Sonar/extension actors remain unchanged.
    legacy_actors = tuple(grants.values())
    auth_grants = dict(grants)
    if enabled:
        auth_grants[publisher_grant] = PUBLISHER_ACTOR
    if (type(organizations) not in (tuple,list,set,frozenset) or
            not organizations or len(organizations) > 20 or
            any(type(org) is not str for org in organizations) or
            len(set(organizations)) != len(organizations)):
        raise ValueError('R7_ORGANIZATIONS_INVALID')
    if (machine_shell is not None and
            machine_shell.actor != grants[ingress_grant]):
        raise Denied('MACHINE_POWERSHELL_ACTOR_SCOPE_DENIED')
    # Registry source packaging alone does not activate it: the reviewed
    # extension requires the host-owned Unix reader before any Core state.
    from .extensions.runtime import ExtensionConfig
    extension_registry = (type(extensions) is ExtensionConfig and
                          'registry' in extensions.value['providers'])
    if extension_registry and (registry_candidate_reader is None or
                               extension_providers is not None):
        # Registry is image-discovered only, not a test/user-selected
        # provider object that could bypass the packaged executable.
        raise Denied('R7_REGISTRY_EXTENSION_TRUSTED_BINDING_REQUIRED')
    if registry_candidate_reader is not None:
        from .integrations.registry.candidate_gateway import GatewayRegistryUnixCandidateRead
        if type(registry_candidate_reader) is not GatewayRegistryUnixCandidateRead:
            raise Denied('R7_REGISTRY_CANDIDATE_READER_INVALID')
        registry_candidate_reader._check_identity()
    functional=getattr(registry_candidate_reader,'_functional_config',None)
    if functional is not None:
        import secrets
        from .integrations.github.gateway.functional_review_runtime import FunctionalRegistryConfiguration
        if (type(functional) is not FunctionalRegistryConfiguration
                or not extension_registry or unified_policy_source_opt_in is None
                or github_pilot is None or not github_pilot.native_worktree):
            raise Denied('R7_REGISTRY_FUNCTIONAL_OWNER_COMPOSITION_REQUIRED')
        # Non-exported per-process credentials keep the two internal
        # principals active in Core; never part of machine actor/grant lists.
        for principal in internal_actors:
            credential=secrets.token_urlsafe(48)
            if credential in auth_grants:
                raise Denied('R7_REGISTRY_INTERNAL_GRANT_COLLISION')
            auth_grants[credential]=principal
    # Construct adapters *before* modifying state: invalid org/region fail closed.
    reader = SonarReadAdapter(sonar_transport,
                              organization_keys=organizations, region=region,
                              allowed_project_keys=project_keys)
    root = _fresh_r7_state(state)
    if local_deny_source_opt_in is None and unified_policy_source_opt_in is None:
        # A new plain R7 worker must not silently ignore an opt-in local
        # DENY database left by an earlier guarded worker. Fail closed before
        # constructing receipts, owner credentials or broker/ingress.
        from .extensions.owner_policy_legacy_fence_phase6c5 import refuse_legacy_core_with_local_policy
        refuse_legacy_core_with_local_policy(root)
    writer = SonarIssueAdapter(
        sonar_transport,
        project_keys=() if project_keys is None else tuple(project_keys),
        organization_keys=tuple(organizations) if project_keys is None else (),
        receipt_store=root/'sonar-receipts.sqlite',region=region)
    owner = IncidentOwnerWebAuthn(root/'owner.sqlite',origin=owner_origin)
    auth = Authenticator(auth_grants)
    actors = legacy_actors
    policies = {(actor, service, operation): 'ALLOW'
                for actor in actors
                for service, operation in SONAR_READ_OPERATIONS}
    policies.update({(actor, *G4_OPERATION): 'ASK' for actor in actors})
    if enabled:
        policies.update(profile.owner_policy_map())
    if unified_policy_source_opt_in is not None:
        from .extensions.owner_policy_engine_v2 import UnifiedPolicyCore
        core_type = UnifiedPolicyCore
    elif local_deny_source_opt_in is not None:
        from .extensions.owner_policy_local_core_phase6c import LocalDenyCore
        core_type = LocalDenyCore
    else:
        core_type = IncidentCore
    core = core_type(root/'approvals.sqlite',adapters={'sonarcloud':writer},
                policies=policies,authenticator=auth,owner_verifier=owner,
                policy_version='r7-p1-sonar-accept-issue-write-v1')
    if local_deny_source_opt_in is not None and local_deny_source_opt_in.runtime_sonar_only:
        with core._db() as db:
            if db.execute("SELECT 1 FROM owner_local_denials WHERE service!='sonarcloud' OR operation!='accept_issue'").fetchone():
                raise Denied('R7_LOCAL_DENY_RUNTIME_SCOPE_INVALID')
    from .owner_shell import OwnerShellClient
    if unified_policy_source_opt_in is not None:
        from .extensions.owner_policy_editor_v2 import UnifiedPolicyPortal
        # Trusted composition only. No listeners or ingress calls yet.
        core._composing = True
        portal = UnifiedPolicyPortal(core,owner,strong_operations={G4_OPERATION},
            read_only_banner=False,owner_shell=OwnerShellClient.from_environment())
    elif local_deny_source_opt_in is None:
        portal = IncidentOwnerPortal(core,owner,strong_operations={G4_OPERATION},
                                 read_only_banner=False,
                                 owner_shell=OwnerShellClient.from_environment())
    else:
        from .extensions.owner_policy_local_deny_apply_phase6c1 import OwnerLocalDenyApply
        from .extensions.owner_policy_local_bundle_phase6c3 import OwnerLocalDenyInventoryPortal
        apply_adapter = OwnerLocalDenyApply(
            core,owner,source_digest=local_deny_source_opt_in.source_digest,
            credential_generation_digest=local_deny_source_opt_in.credential_generation_digest,
            runtime_sonar_only=local_deny_source_opt_in.runtime_sonar_only)
        portal = OwnerLocalDenyInventoryPortal(
            core,owner,local_deny_apply=apply_adapter,
            strong_operations={G4_OPERATION},read_only_banner=False,
            owner_shell=OwnerShellClient.from_environment())
    broker_actions = {actor:{G4_OPERATION} for actor in actors}
    broker_reads = {actor: SONAR_READ_OPERATIONS for actor in actors}
    if enabled:
        broker_actions[PUBLISHER_ACTOR] = frozenset(('github', op) for op in PUBLISHER_WRITES)
        broker_reads[PUBLISHER_ACTOR] = frozenset(('github', op) for op in PUBLISHER_READS)
    broker = RepoIntentBroker(
        core,actor_operations=broker_actions,
        actor_read_operations=broker_reads,read_adapter=reader,
        read_adapters=({'registry':registry_candidate_reader}
                       if registry_candidate_reader is not None
                       and not extension_registry else None))
    native = None
    if github_pilot is not None:
        if github_pilot.native_worktree:
            from .workflow.runtime import install
            native = install(core=core,portal=portal,broker=broker,config=github_pilot,
                root=root,actor=grants[ingress_grant],transport=github_transport,
                publisher_profile=profile,machine_shell=machine_shell)
        else:
            from .integrations.github.pilot import install_pilot
            install_pilot(core=core, portal=portal, broker=broker, config=github_pilot,
                          root=root, actor=grants[ingress_grant], transport=github_transport)
    if analysis_review is not None:
        from .integrations.analysis_review import install
        install(core=core, portal=portal, broker=broker, config=analysis_review, root=root,
                actor=grants[ingress_grant], github_transport=github_transport)
    ingress = RepoIngress(broker,host=ingress_host,max_bytes=524288,
        max_read_response_bytes=262144 if analysis_review is not None else 65536)
    machine_base = ingress
    if native is not None:
        from .workflow.runtime import wrap
        ingress = wrap(ingress,native)
    runtime = None
    if extensions is not None:
        from .extensions.runtime import ExtensionRuntime
        from .extensions.model import discover
        from .extensions.ingress import ExtensionIngress
        installed_providers = (discover(tuple(extensions.value['providers']))
                               if extension_providers is None else extension_providers)
        if extension_registry:
            from .integrations.registry.extension import bind_reader
            installed_providers = tuple(
                bind_reader(provider, registry_candidate_reader)
                if provider.name == 'registry' else provider
                for provider in installed_providers)
        runtime = ExtensionRuntime(extensions, providers=installed_providers,
            actors=actors, default_actor=grants[ingress_grant], vault=credential_vault).install(core, portal)
        ingress = ExtensionIngress(machine_base, runtime, delegate=ingress)
        portal._extension_runtime = runtime
    if functional is not None:
        functional.install(core=core,portal=portal,reader=registry_candidate_reader,
                           native=native,root=root)
        core._baseline_policy_version+=':registry-functional-'+functional.digest
    if unified_policy_source_opt_in is not None:
        from .extensions.owner_policy_r7_v2 import (
            derive_admission, trusted_scope_binding, reviewed_mirror_v1_previous_scope,
            RegistryAuthorityPredecessor)
        from .extensions.owner_policy_editor_v2 import OwnerPolicyEditor
        core._composing = False
        scope_binding=trusted_scope_binding(organizations=organizations,
            region=region,project_keys=project_keys,github_pilot=github_pilot,
            analysis_review=analysis_review,profile=profile,machine_shell=machine_shell,
            runtime=runtime,broker=broker)
        if functional is not None:
            scope_binding['registryFunctional']=functional.digest
        upgrade=unified_policy_source_opt_in.allow_label_policy_upgrade
        all_methods=unified_policy_source_opt_in.allow_all_method_policy_upgrade
        choices=derive_admission(core,broker,native=native,extension_runtime=runtime,
                             allow_label_policy_upgrade=upgrade,
                             allow_all_method_policy_upgrade=all_methods)
        predecessor=None
        if functional is not None:
            # First activation is an explicitly owner-reviewed all-methods
            # release. Existing authority may not be silently recreated.
            if not all_methods:
                raise Denied('R7_REGISTRY_REVIEWED_AUTHORITY_UPGRADE_REQUIRED')
            predecessor=RegistryAuthorityPredecessor(
                core,scope_binding,choices,
                previous_functional_digest=functional.reviewed_authority_predecessor_digest())
        core.install_policy_authority(
            choices, scope_binding=scope_binding,
            reviewed_previous_scope=reviewed_mirror_v1_previous_scope(
                scope_binding, all_methods=all_methods),
            reviewed_registry_predecessor=predecessor,
            reviewed_upgrade_from=(predecessor.choices if predecessor is not None else
                derive_admission(core,broker,native=native,
                 extension_runtime=runtime,allow_label_policy_upgrade=all_methods)
                 if upgrade or all_methods else None))
        # New ASK transitions must use strong owner proof even where the
        # baseline was ALLOW. Keep existing stronger independent checks.
        portal.strong_operations |= frozenset((key[1],key[2]) for key,values
            in core.authority.choices.items() if 'ASK' in values)
        portal.bind_editor(OwnerPolicyEditor(core,owner,
            source_digest=unified_policy_source_opt_in.source_digest,
            credential_generation=unified_policy_source_opt_in.credential_generation))
        if all_methods:
            from .read_approval import install_owner_read_approval
            install_owner_read_approval(core,broker,portal)
    return core,owner,portal,ingress

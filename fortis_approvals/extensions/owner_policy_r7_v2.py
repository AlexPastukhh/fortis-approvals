"""Trusted R7 composition for explicit owner-reviewed policy editor V2.

No machine request or unreviewed environment flag selects this candidate.
Only the owner release configuration and trusted builder bind identities.
Native synchronous READ and mandatory ASK execution contracts remain intact.
"""
from dataclasses import asdict, dataclass
import re

from ..core import Denied
from .owner_policy_engine_v2 import POLICIES, UnifiedPolicyCore


@dataclass(frozen=True)
class R7UnifiedPolicySourceOptIn:
    source_digest: str
    credential_generation: object
    allow_label_policy_upgrade: bool = False
    allow_all_method_policy_upgrade: bool = False

    def __post_init__(self):
        if (type(self.source_digest) is not str or
                not re.fullmatch(r"[a-f0-9]{64}",self.source_digest) or
                not callable(self.credential_generation) or
                type(self.allow_label_policy_upgrade) is not bool or
                type(self.allow_all_method_policy_upgrade) is not bool):
            raise Denied("R7_UNIFIED_POLICY_IDENTITY_REQUIRED")


# Explicit effect ceilings, not guessed from the current ASK/ALLOW string.
# These operations keep existing typed adapter validation and Core dispatch.
# Mandatory release-label/CI/merge/workflow controls never auto-approve.
_GITHUB_FLEXIBLE = frozenset(("create_pull_request","publish_visual_review",
                             "append_visual_revision"))
_GITHUB_ASK_ONLY = frozenset(("mark_pr_ready","merge_pull_request","update_pull_request",
    "update_workflow_file","create_release_label","add_pr_release_labels",
    "remove_pr_release_label"))


def derive_admission(core, broker, *, native, extension_runtime,
                     allow_label_policy_upgrade=False,
                     allow_all_method_policy_upgrade=False):
    """Only installed, actor-granted, literal policy rows may become editable.

    READ-ASK needs a new deferred result protocol, not a misleading selector.
    Conditional push/cleanup and publisher profile guards are not replaced.
    Exact configuration DENY is not a new grant: leave it fixed.
    """
    if type(core) is not UnifiedPolicyCore or broker.core is not core:
        raise Denied("R7_UNIFIED_POLICY_COMPOSITION_REQUIRED")
    from ..workflow.common import WORKSPACE_OPS
    from ..integrations.github.analysis_contract import ACTIONS as CI_ACTIONS
    from ..integrations.github.publisher_profile import ACTOR as PUBLISHER_ACTOR
    if (type(allow_label_policy_upgrade) is not bool or
            type(allow_all_method_policy_upgrade) is not bool):
        raise Denied("R7_UNIFIED_POLICY_UPGRADE_FLAG_INVALID")
    if allow_all_method_policy_upgrade:
        return _derive_registered_method_admission(core,broker,native=native,
                                                    extension_runtime=extension_runtime)
    rt = extension_runtime
    choices = {}
    for key, baseline in core.policies.items():
        if (len(key) not in (3,4) or type(baseline) is not str or
                baseline not in ("ASK","ALLOW") or not core.auth.active(key[0]) or
                key[0]==PUBLISHER_ACTOR or key[1] not in core.adapters):
            continue
        actor, service, operation = key[:3]
        pair = (service,operation)
        permitted = None
        if rt is not None and service in rt.credentials:
            if len(key)!=4 or rt.rules.get(key)!=baseline:
                continue
            op = rt.operations[pair]
            aliases = rt.credentials[service]
            if not op.ready or any(role and role not in aliases for role in
                                   (op.credential,op.signing_credential)):
                continue
            # An extension-specific WRITE may enforce mandatory owner proof
            # or narrower host authority beyond the generic Core contract.
            # Only existing ALLOW (restrict/restore) or READ can gain ALLOW.
            if op.signing_credential:
                permitted = {"DENY","ASK"}
            elif op.kind=="read" or baseline=="ALLOW":
                permitted = POLICIES
            else:
                permitted = {"DENY","ASK"}
        elif pair in broker.actor_read_operations.get(actor,()):
            # Direct synchronous read cannot execute an ASK ceremony.
            if baseline=="ALLOW" and service in broker.read_adapters:
                permitted = {"DENY","ALLOW"}
        elif pair in broker.actor_operations.get(actor,()):
            if service=="sonarcloud":
                permitted = {"DENY","ASK"}
            elif service=="github" and native is not None:
                if operation in _GITHUB_FLEXIBLE:
                    permitted = POLICIES
                elif operation in _GITHUB_ASK_ONLY or pair in CI_ACTIONS:
                    permitted = (POLICIES if allow_label_policy_upgrade and
                        operation in ("create_release_label","add_pr_release_labels",
                                      "remove_pr_release_label") and
                        actor == native["actor"] else {"DENY","ASK"})
        elif native is not None and actor==native["actor"]:
            if service=="workspace" and operation in WORKSPACE_OPS:
                # All literal operations use Core's DISPATCHED worker contract.
                # cleanup_task is conditional and already excluded above.
                permitted = POLICIES
            elif service=="powershell" and operation=="execute" and len(key)==4:
                permitted = {"DENY","ASK"}
        if permitted is not None and baseline in permitted:
            choices[key] = frozenset(permitted)
    return choices


def _derive_registered_method_admission(core,broker,*,native,extension_runtime):
    """Outer owner policy: choice is NOT keyed to the method's name.

    Actor grants, exact configured extension target, installed handler and
    provider readiness are mandatory. The inner executor and provider still
    validate every request independently, including conditional callbacks.
    A missing actor grant is NEVER created by making an existing rule editable.
    """
    from ..workflow.common import WORKSPACE_OPS
    rt = extension_runtime
    choices = {}
    for key, baseline in core.policies.items():
        if (type(key) is not tuple or len(key) not in (3,4)
                or not all(type(x) is str for x in key)
                or not core.auth.active(key[0]) or key[1] not in core.adapters
                or not (baseline in POLICIES if type(baseline) is str
                        else callable(baseline))):
            continue
        actor, service, operation = key[:3]
        pair=(service,operation)
        enrolled=False
        if rt is not None and service in rt.credentials:
            if len(key)!=4 or key not in rt.rules or rt.rules[key]!=baseline:
                continue
            op=rt.operations.get(pair)
            aliases=rt.credentials[service]
            enrolled=(op is not None and op.ready and
                      all(not role or role in aliases
                          for role in (op.credential,op.signing_credential)))
        elif (pair in broker.actor_read_operations.get(actor,())
                and service in broker.read_adapters):
            enrolled=True
        elif pair in broker.actor_operations.get(actor,()):
            enrolled=True
        elif (native is not None and actor==native["actor"] and
                service=="workspace" and native.get("workspace") is not None
                and operation in WORKSPACE_OPS):
            # Workspace's native typed ingress is a separate registered path
            # from the generic RepoIntentBroker action grant.
            enrolled=True
        elif (native is not None and actor==native["actor"] and
                service=="powershell" and len(key)==4
                and getattr(core.adapters[service],"actor",None)==actor
                and getattr(core.adapters[service],"target",None)==key[3]):
            enrolled=True
        if enrolled:
            choices[key]=POLICIES
    return choices


def trusted_scope_binding(*,organizations,region,project_keys,github_pilot,
                          analysis_review,profile,machine_shell,runtime,broker):
    """Persist only the authority digest, not secrets or mutable host paths.

    A changed owner/repo/project/actor/definition scope must not inherit
    a previously approved ALLOW silently. A reviewed migration is required.
    """
    github = asdict(github_pilot) if github_pilot is not None else None
    if github is not None:
        # Bootstrap task is lifecycle metadata, not provider authority.
        github.pop("bootstrap_task",None)
    review = None if analysis_review is None else {
        "owner":analysis_review.owner,"bindings":analysis_review.bindings,
        "sonarMutations":analysis_review.sonar_mutations}
    machine = None if machine_shell is None else {
        "actor":machine_shell.actor,"target":machine_shell.target,
        "executorGitSha":machine_shell.executor_git_sha,
        "executorIdentity":machine_shell.executor_identity}
    extensions = None if runtime is None else {
        "credentials":runtime.credentials,
        "definitions":{name:{"source":provider.source_digest,
            "operations":[[op.name,op.version,op.kind,op.ready,op.credential,op.signing_credential]
                          for op in sorted(provider.operations,key=lambda item:item.name)]}
            for name,provider in runtime.providers.items()}}
    return {"region":region,"organizations":sorted(organizations),
            "projects":None if project_keys is None else sorted(project_keys),
            "github":github,"analysis":review,"publisher":asdict(profile),
            "machineShell":machine,"extensions":extensions,
            "readGrants":{a:sorted(ops) for a,ops in broker.actor_read_operations.items()},
            "writeGrants":{a:sorted(ops) for a,ops in broker.actor_operations.items()}}


# Reviewed one-release compatibility pair for the Mirror v1 inventory ceiling.
# The exact provider source digest changes, but operations, routes, grants,
# credentials and every other scope field must remain identical.
_MIRROR_V1_CAPACITY_SOURCE_BEFORE = "9671fbcb7c457dfa0be94339a5ecf61fba12ea95e8acabb4e48046eb20356bb0"
_MIRROR_V1_CAPACITY_SOURCE_AFTER = "cee77ef6c7913f25f4d74114e8c741a64f43ea1ae2b821ca1f31f734d734c239"


def reviewed_mirror_v1_previous_scope(scope, *, all_methods):
    """Reconstruct only the exact reviewed predecessor, never ambient drift."""
    if not all_methods or scope.get("extensions") is None:
        return None
    mirror = scope["extensions"]["definitions"].get("mirror")
    if mirror is None or mirror["source"] != _MIRROR_V1_CAPACITY_SOURCE_AFTER:
        return None
    from copy import deepcopy
    previous = deepcopy(scope)
    previous["extensions"]["definitions"]["mirror"]["source"] = (
        _MIRROR_V1_CAPACITY_SOURCE_BEFORE)
    return previous


class RegistryAuthorityPredecessor:
    """Finite source-derived predecessors of owner-sealed Registry activation.

    Only remove the exact new Registry READ and internal ASK coordinates;
    all previous actors, providers, credentials, rules and ceilings stay
    unchanged. Stored authority SHA is still the decisive comparison.
    No caller or DB supplies a historical scope/baseline.
    """
    def __init__(self, core, scope, choices, *, previous_functional_digests=()):
        from copy import deepcopy
        from ..integrations.github.gateway.review_attestation import ACTOR, SERVICE, BUNDLE_OPERATION
        from ..integrations.registry.read_contract import PLANNER_ACTOR
        self._scope=deepcopy(scope)
        self._baseline=dict(core.policies)
        new_asks={(ACTOR,SERVICE,BUNDLE_OPERATION,'fortis-approvals'),
                  (PLANNER_ACTOR,'registry','ingest_merged','fortis-approvals')}
        read_ops={'candidate_head','candidate_list_desired','candidate_original_operation'}
        definitions=self._scope['extensions']['definitions']
        credentials=self._scope['extensions']['credentials']
        registry=definitions.get('registry')
        if (type(self._scope.get('registryFunctional')) is not str
                or not re.fullmatch('[0-9a-f]{64}',self._scope['registryFunctional'])
                or registry is None or credentials.get('registry')!={}
                or {row[0] for row in registry['operations']}!=read_ops
                or any(row[2]!='read' or row[3] is not True or row[4:]!=[None,None]
                       for row in registry['operations'])
                or not new_asks <= set(self._baseline)):
            raise Denied('OWNER_POLICY_REGISTRY_PREDECESSOR_INVALID')
        removed=set()
        for k,v in self._baseline.items():
            if k in new_asks:
                if not callable(v) or k in choices:
                    raise Denied('OWNER_POLICY_REGISTRY_PREDECESSOR_INVALID')
                removed.add(k)
            elif k[1]=='registry':
                if len(k)!=4 or k[2] not in read_ops or k[3]!='fortis-approvals' or v not in POLICIES:
                    raise Denied('OWNER_POLICY_REGISTRY_PREDECESSOR_INVALID')
                removed.add(k)
            elif k[0] in (ACTOR,PLANNER_ACTOR) or k[1]==SERVICE:
                raise Denied('OWNER_POLICY_REGISTRY_PREDECESSOR_INVALID')
        if not removed-new_asks:
            raise Denied('OWNER_POLICY_REGISTRY_PREDECESSOR_INVALID')
        self._baseline={k:v for k,v in self._baseline.items() if k not in removed}
        self.choices={k:v for k,v in choices.items() if k in self._baseline}
        self._scope.pop('registryFunctional')
        definitions.pop('registry'); credentials.pop('registry')
        # Registry is an extension, not an additional broker machine grant.
        if any(any(op[0] in ('registry',SERVICE) for op in ops)
               for name in ('readGrants','writeGrants') for ops in self._scope[name].values()):
            raise Denied('OWNER_POLICY_REGISTRY_PREDECESSOR_INVALID')

        if (type(previous_functional_digests) is not tuple
                or len(previous_functional_digests)>2
                or any(type(digest) is not str or not re.fullmatch('[0-9a-f]{64}',digest)
                       or digest==scope['registryFunctional'] for digest in previous_functional_digests)
                or len(set(previous_functional_digests))!=len(previous_functional_digests)):
            raise Denied('OWNER_POLICY_REGISTRY_PREDECESSOR_INVALID')
        # The immediate predecessor and older functional epochs can both
        # include Registry. Keep the same baseline and every other scope
        # field. The policy engine matches each stored hash independently.
        self._functional_predecessors = []
        for digest in previous_functional_digests:
            previous_scope = deepcopy(scope)
            previous_scope['registryFunctional'] = digest
            self._functional_predecessors.append((previous_scope, dict(core.policies)))
        if self._functional_predecessors:
            self.choices = dict(choices)

    def variants(self):
        from copy import deepcopy
        scopes=[self._scope]
        old=reviewed_mirror_v1_previous_scope(self._scope,all_methods=True)
        if old is not None:
            scopes.append(old)
        variants = [(deepcopy(scope), dict(self._baseline)) for scope in scopes]
        variants.extend((deepcopy(scope),dict(baseline))
                        for scope,baseline in self._functional_predecessors)
        return variants

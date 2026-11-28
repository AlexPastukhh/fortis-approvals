"""Explicit, opt-in successor composition for additive composite authority.

The R7 builder may select this path only with reviewed source-owned inputs
and independent pins on a verified staged clone.
The actual #286 source/scope/authority and controller transition still need
their reviewed release-specific binding.
"""
from copy import deepcopy
import hashlib
from types import MappingProxyType

from ..core import Denied, canonical, loads_strict
from ..integrations.registry_contracts.semantic_contract import digest, hex_id, need
from .composite_authority import reviewed_additive_authority
from .composite_executor import CompositeCoreMixin, GroupAdapter
from .maintenance_core import MaintenanceCoreMixin
from .composite_preservation import inspect_companion
from .owner_policy_engine_v2 import PolicyAdmission, UnifiedPolicyCore
from .transition_authority import (
    authority_witness, compare_authority_epoch, stored_authority_witness, _rows_digest)

_MAX_EPOCHS = 64


class ReviewedHistory:
    """Finite exact prior admissions reconstructed by the old trusted Core.

    The stored epoch choices are replayed by the incumbent's own reviewed
    resolver, not used to invent a scope or baseline. The independent
    witness pin must match the validated incumbent snapshot. Historical
    callbacks remain the original trusted source identities.
    """
    def __init__(self, incumbent, db, *, expected_witness_digest):
        from .owner_policy_engine_v2 import _EPOCHS, _names
        need(type(incumbent) is UnifiedPolicyCore, 'COMPOSITE_INCUMBENT_REQUIRED')
        hex_id(expected_witness_digest, 64)
        witness = authority_witness(incumbent, db)
        need(digest(witness) == expected_witness_digest,
             'COMPOSITE_INCUMBENT_WITNESS_CHANGED')
        rows = list(db.execute(
            'SELECT * FROM owner_local_policy_v2_authority_epochs ORDER BY id LIMIT ?',
            (_MAX_EPOCHS + 1,))) if _EPOCHS in _names(db) else []
        need(len(rows) <= _MAX_EPOCHS, 'COMPOSITE_HISTORY_LIMIT')
        self._initialize(incumbent.authority, witness, rows,
                         resolver=incumbent._historical_admission,
                         policy_events=self._policy_prefix(db, witness['policy']['revision']),
                         legacy_digest=db.execute(
                            'SELECT legacy_digest FROM owner_local_policy_v2_meta').fetchone()[0])

    def _initialize(self, current, witness, rows, *, resolver, policy_events, legacy_digest):
        from .owner_policy_engine_v2 import _coordinate
        admissions = {}
        for row in rows:
            choices = {_coordinate(tuple(k)): tuple(v)
                       for k, v in loads_strict(row['old_choices'])}
            prior = resolver(choices, current, row['old_authority'])
            self._remember(admissions, prior)
        self._remember(admissions, current)
        self._admissions = MappingProxyType(admissions)
        self._witness = deepcopy(witness)
        self._current = current
        self._policy_events = policy_events
        self._legacy_digest = legacy_digest

    @staticmethod
    def _policy_prefix(db, revision):
        return _rows_digest(db.execute(
            'SELECT * FROM owner_local_policy_v2_events WHERE revision<=? ORDER BY revision',
            (revision,)))

    def seal(self):
        """Evidence for the existing protected release mount from verified history."""
        return {'schemaVersion': 1, 'witness': self.witness,
                'policyEvents': dict(self._policy_events), 'legacyDigest': self._legacy_digest}

    @staticmethod
    def _remember(admissions, authority):
        need(type(authority) is PolicyAdmission, 'COMPOSITE_HISTORY_ADMISSION_INVALID')
        admissions[authority.sha] = (
            deepcopy(authority.scope_binding), MappingProxyType(dict(authority.baseline)),
            MappingProxyType(dict(authority.choices)))

    @property
    def witness(self):
        return deepcopy(self._witness)

    @property
    def incumbent(self):
        return self._current

    @staticmethod
    def _verify_prefix(db, *, witness, policy_events, legacy_digest, successor_digest):
        # The protected history already pins the canonical incumbent choices.
        # Share the exact epoch/prefix check with the read-only delivery
        # preflight; startup additionally performs the compiled policy replay.
        need(db.in_transaction and db.execute('PRAGMA query_only').fetchone()[0] == 1,
             'TRANSITION_READ_ONLY_WITNESS_REQUIRED')
        rev = witness['policy']['revision']
        count = witness['epochCount']
        prefix = ReviewedHistory._policy_prefix(db, rev)
        epochs = [list(row) for row in db.execute(
            'SELECT * FROM owner_local_policy_v2_authority_epochs ORDER BY id LIMIT ?',
            (count+2,))]
        tail = [count+1, rev, witness['policy']['authorityDigest'], successor_digest]
        meta = [tuple(row) for row in db.execute(
            'SELECT revision,authority,legacy_digest FROM owner_local_policy_v2_meta')]
        need(prefix == policy_events and len(epochs) == count+1
             and digest(epochs[:-1]) == witness['epochDigest']
             and epochs[-1][:4] == tail and type(epochs[-1][4]) is str
             and hashlib.sha256(epochs[-1][4].encode()).hexdigest() == witness['choicesDigest']
             and len(meta) == 1 and meta[0][0] >= rev
             and meta[0][1:] == (successor_digest, legacy_digest),
             'COMPOSITE_HISTORICAL_PREFIX_CHANGED')

    def verify_prefix(self, db, successor_digest):
        """Check old immutable policy bytes even after new owner edits."""
        self._verify_prefix(db, witness=self._witness, policy_events=self._policy_events,
                            legacy_digest=self._legacy_digest, successor_digest=successor_digest)

    def reconstruct(self, core, choices, expected):
        item = self._admissions.get(expected)
        need(item is not None, 'COMPOSITE_HISTORICAL_AUTHORITY_UNKNOWN')
        scope, baseline, prior_choices = item
        need({key: frozenset(values) for key, values in choices.items()} == prior_choices,
             'COMPOSITE_HISTORICAL_CHOICES_CHANGED')
        admission = PolicyAdmission(core, dict(choices), scope_binding=deepcopy(scope),
                                    historical_baseline=dict(baseline))
        need(admission.sha == expected, 'COMPOSITE_HISTORICAL_AUTHORITY_CHANGED')
        return admission


class ReviewedHistoryEvidence:
    """Protected incumbent evidence, replayed against the composed Gateway."""

    def __init__(self, value, *, expected_digest):
        from ..integrations.registry_contracts.semantic_contract import fields, revision
        fields(value, ('schemaVersion', 'witness', 'policyEvents', 'legacyDigest'))
        hex_id(expected_digest, 64)
        need(type(value['schemaVersion']) is int and value['schemaVersion'] == 1
             and digest(value) == expected_digest, 'COMPOSITE_HISTORY_EVIDENCE_CHANGED')
        witness = value['witness']
        fields(witness, ('coreHistoryDigest', 'policy', 'unchangedPolicyDigest', 'choicesDigest',
                         'epochCount', 'epochDigest', 'previousEpochDigest', 'lastEpoch'))
        policy = witness['policy']
        fields(policy, ('revision', 'authorityDigest', 'historyDigest'))
        for field in ('coreHistoryDigest', 'unchangedPolicyDigest', 'choicesDigest', 'epochDigest'):
            hex_id(witness[field], 64)
        for field in ('authorityDigest', 'historyDigest'):
            hex_id(policy[field], 64)
        revision(policy['revision'])
        count = witness['epochCount']
        need(type(count) is int and 0 <= count <= _MAX_EPOCHS,
             'COMPOSITE_HISTORY_LIMIT')
        events = value['policyEvents']
        fields(events, ('count', 'digest'))
        need(type(events['count']) is int and events['count'] == policy['revision'],
             'COMPOSITE_HISTORY_EVIDENCE_CHANGED')
        hex_id(events['digest'], 64)
        if value['legacyDigest'] != 'NONE':
            hex_id(value['legacyDigest'], 64)
        self._raw = canonical(value)

    def verify_incumbent_storage(self, db):
        """Before cutover, match the exact owner-reviewed incumbent bytes."""
        value = loads_strict(self._raw)
        stored = stored_authority_witness(db)
        expected = {k:v for k,v in value['witness'].items() if k != 'choicesDigest'}
        meta = db.execute('SELECT legacy_digest FROM owner_local_policy_v2_meta').fetchall()
        need(stored == expected
             and [tuple(row) for row in meta] == [(value['legacyDigest'],)]
             and ReviewedHistory._policy_prefix(db, stored['policy']['revision']) == value['policyEvents'],
             'COMPOSITE_INCUMBENT_CLONE_CHANGED')

    def verify_successor_storage(self, db, successor_digest):
        """Read the already-installed successor; never append another epoch."""
        value = loads_strict(self._raw)
        stored = stored_authority_witness(db)
        need(stored['policy']['authorityDigest'] == successor_digest,
             'COMPOSITE_SUCCESSOR_MODE_MISMATCH')
        ReviewedHistory._verify_prefix(db, witness=value['witness'],
            policy_events=value['policyEvents'], legacy_digest=value['legacyDigest'],
            successor_digest=successor_digest)
        return stored

    def restore(self, core, db, *, current, previous_scope, predecessor):
        from .owner_policy_engine_v2 import _EPOCHS, _names

        need(db.in_transaction and db.execute('PRAGMA query_only').fetchone()[0] == 1,
             'TRANSITION_READ_ONLY_WITNESS_REQUIRED')
        value = loads_strict(self._raw)
        witness = value['witness']
        need(current.sha == witness['policy']['authorityDigest'],
             'R7_REGISTRY_INCUMBENT_AUTHORITY_CHANGED')
        count = witness['epochCount']
        rows = list(db.execute(
            'SELECT * FROM owner_local_policy_v2_authority_epochs WHERE id<=? ORDER BY id',
            (count,))) if _EPOCHS in _names(db) else []
        meta = db.execute('SELECT legacy_digest FROM owner_local_policy_v2_meta').fetchall()
        need(len(rows) == count and digest([list(row) for row in rows]) == witness['epochDigest']
             and [tuple(row) for row in meta] == [(value['legacyDigest'],)]
             and ReviewedHistory._policy_prefix(db, witness['policy']['revision']) == value['policyEvents'],
             'COMPOSITE_HISTORICAL_PREFIX_CHANGED')

        def resolve(choices, authority, expected):
            return core._compiled_historical_admission(
                choices, authority, expected, previous_scope=previous_scope, predecessor=predecessor)

        history = object.__new__(ReviewedHistory)
        history._initialize(current, witness, rows, resolver=resolve,
                            policy_events=value['policyEvents'], legacy_digest=value['legacyDigest'])
        return history


class CompositeUnifiedCore(MaintenanceCoreMixin, CompositeCoreMixin, UnifiedPolicyCore):
    """Exact source-owned successor type selected only by reviewed R7 composition.

    Not usable for serving until a checked companion schema and reviewed
    policy epoch have both been validated. Callers must discard a staged
    clone on failed transition; no fallback to partially migrated state.
    """
    def __init__(self, *args, **kwargs):
        self._successor_ready = False
        self._reviewed_history = None
        super().__init__(*args, **kwargs)

    @property
    def successor_ready(self):
        return self._successor_ready

    def _historical_admission(self, choices, authority, expected):
        need(self._reviewed_history is not None, 'COMPOSITE_HISTORY_NOT_BOUND')
        return self._reviewed_history.reconstruct(self, choices, expected)

    def install_policy_authority(self, *args, **kwargs):
        # Do not expose a generic alternative installation path.
        raise Denied('COMPOSITE_REVIEWED_INSTALL_REQUIRED')

    def _read_only(self, reader):
        with self._db() as db:
            db.execute('PRAGMA query_only=ON')
            db.execute('BEGIN')
            return reader(db)

    def install_reviewed(self, *, history, enrollment, choices, scope_binding,
                         expected_predecessor_digest, expected_successor_digest,
                         expected_companion_digest, transition, semantic_enrollment=None,
                         release_active=False):
        """Install/reopen the exact reviewed additive epoch on a clone.

        Companion schema must already be explicitly installed and checked.
        Independent pins and trusted incumbent history are supplied by the
        reviewed release builder, never a request. The transition flag permits
        the first epoch only; persisted authority selects transition or reopen.
        Failed candidate must not serve or be reused as an authorized source.
        No host operations here.
        """
        need(type(transition) is bool and type(release_active) is bool
             and type(history) is ReviewedHistory
             and not self._successor_ready and self.authority is None
             and type(self.adapters.get('registry')) is GroupAdapter
             and self.adapters['registry'].core is self
             and self.adapters['registry'].ordinary is not None,
             'COMPOSITE_SUCCESSOR_COMPOSITION_REQUIRED')
        self._gate()  # Explicit maintenance composition; absence is not NORMAL.
        hex_id(expected_companion_digest, 64)
        candidate = reviewed_additive_authority(
            self, predecessor=history.incumbent, enrollment=enrollment, choices=choices,
            scope_binding=scope_binding, expected_predecessor_digest=expected_predecessor_digest,
            expected_successor_digest=expected_successor_digest,semantic_enrollment=semantic_enrollment)
        self._reviewed_history = history
        # Use the same read snapshot for the authority, history and companion.
        # An already activated release cannot install a predecessor again.
        with self._db() as db:
            db.execute('PRAGMA query_only=ON')
            db.execute('BEGIN')
            meta = [tuple(r) for r in db.execute(
                'SELECT authority FROM owner_local_policy_v2_meta')]
            first_transition = (transition and not release_active and
                                meta == [(expected_predecessor_digest,)])
            need(first_transition or meta == [(candidate.sha,)],
                 'COMPOSITE_SUCCESSOR_MODE_MISMATCH')
            companion = inspect_companion(db)
            # Exact sealed copy until activation. An active successor's
            # journal can legitimately grow; retain full schema, replay,
            # coverage and receipt validation, not equality to old data.
            if not release_active or not companion['parents']:
                need(digest(companion) == expected_companion_digest,
                     'COMPOSITE_COMPANION_PIN_CHANGED')
            if first_transition:
                need(companion['parents'] == 0, 'COMPOSITE_TRANSITION_COMPANION_NOT_EMPTY')
                previous = history.reconstruct(self, history.incumbent.choices,
                                               expected_predecessor_digest)
                # Compare the actual clone's old history before any epoch
                # write. Temporary trusted authority only for this check.
                self.authority = previous
                try:
                    before = authority_witness(self, db)
                finally:
                    self.authority = None
                need(before == history.witness, 'COMPOSITE_INCUMBENT_CLONE_CHANGED')
        UnifiedPolicyCore.install_policy_authority(
            self, choices, scope_binding=deepcopy(scope_binding),
            reviewed_upgrade_from=dict(history.incumbent.choices) if first_transition else None)
        need(self.authority.sha == candidate.sha, 'COMPOSITE_SUCCESSOR_PIN_MISMATCH')
        if first_transition:
            after = self._read_only(lambda db: authority_witness(self, db))
            compare_authority_epoch(history.witness, after,
                                    expected_successor_digest=candidate.sha)
        # Revalidate the companion and actual policy replay before serving.
        self._read_only(lambda db: history.verify_prefix(db, candidate.sha))
        self._read_only(inspect_companion)
        # Read-model metadata comes only from the same verified enrollment.
        # It is not a new policy authority or a provider readiness decision.
        context = enrollment.metadata()['grants']
        self._inventory_coordinates = frozenset(
            tuple(row[key]) for row in context for key in ('parent', 'child')
        ) | (frozenset(semantic_enrollment.coordinates()) if semantic_enrollment else frozenset())
        self._inventory_context = tuple(sorted({
            (tuple(row['child']), tuple(row['parent'][1:])) for row in context
        }))
        self._successor_ready = True

    def reviewed_inventory(self):
        need(self._successor_ready, 'COMPOSITE_SUCCESSOR_NOT_READY')
        return self._inventory_coordinates, self._inventory_context

    def submit(self, actor, payload):
        need(self._successor_ready, 'COMPOSITE_SUCCESSOR_NOT_READY')
        return super().submit(actor, payload)

    def execute(self, ident):
        need(self._successor_ready, 'COMPOSITE_SUCCESSOR_NOT_READY')
        return super().execute(ident)

    def reconcile(self, ident):
        need(self._successor_ready, 'COMPOSITE_SUCCESSOR_NOT_READY')
        return super().reconcile(ident)

    def owner_decide(self, *args, **kwargs):
        need(self._successor_ready, 'COMPOSITE_SUCCESSOR_NOT_READY')
        return super().owner_decide(*args, **kwargs)

    def commit_verified_change(self, *args, **kwargs):
        need(self._successor_ready, 'COMPOSITE_SUCCESSOR_NOT_READY')
        return super().commit_verified_change(*args, **kwargs)


def is_reviewed_successor(core):
    return type(core) is CompositeUnifiedCore and core.successor_ready


class ReviewedRegistrySuccessor:
    """Protected builder inputs for an already staged Registry/Gateway pair.

    Host provisioning and evidence acquisition are separate. This object
    does not select paths or grant authority from environment or HTTP.
    """

    def __init__(self, *, history, context, semantic, owner_principal, repository, target,
                 build_native_provider, transport, gate, profile_digest, successor_digest,
                 companion_digest, transition, provider_guard, effect_guard, ready,
                 frozen_handoff=None, verify_delivery=None):
        from .composite_authority import ContextEnrollment
        from .maintenance_gate import MaintenanceGate
        from .semantic_enrollment import SemanticEnrollment
        from .semantic_gateway import GatewayRegistrySemanticTransport
        from ..integrations.registry_contracts import semantic_contract as sc
        from ..integrations.registry_contracts.maintenance_contract import startup_handoff

        need(type(history) in (ReviewedHistory, ReviewedHistoryEvidence)
             and type(context) is ContextEnrollment
             and type(semantic) is SemanticEnrollment and type(gate) is MaintenanceGate
             and callable(build_native_provider) and type(transition) is bool
             and type(transport) is GatewayRegistrySemanticTransport
             and all(callable(f) for f in (provider_guard,effect_guard,ready))
             and (verify_delivery is None or callable(verify_delivery)),
             'R7_REGISTRY_SUCCESSOR_REVIEWED_BINDING_REQUIRED')
        sc.repository(repository)
        sc.name(target)
        need(type(owner_principal) is str and bool(owner_principal)
             and gate.instance_id==transport.peer._instance
             and gate.scope_digest==transport.peer._scope
             and gate.generation==transport.generation
             and gate._holds==transport.maintenance_snapshot,
             'R7_REGISTRY_SUCCESSOR_PEER_BINDING_CHANGED')
        merge=('release','merge_and_register')
        for row in context.metadata()['grants']:
            parent,child=row['parent'],row['child']
            if tuple(parent[1:3])==merge:
                need(parent[0]==owner_principal and parent[3]==target
                     and row['repository']==repository
                     and child[3]==(repository.split('/')[1] if child[1]=='github' else target),
                     'R7_REGISTRY_MERGE_CONTEXT_SCOPE_CHANGED')
        for row in semantic.metadata()['grants']:
            if (row['service'],row['operation'])==merge:
                need(row['actor']==owner_principal and row['target']==target
                     and row['subject']['repository']==repository,
                     'R7_REGISTRY_MERGE_PROPOSER_SCOPE_CHANGED')
        for pin in (profile_digest, successor_digest, companion_digest):
            hex_id(pin,64)
        self.history,self.context,self.semantic=history,context,semantic
        self.owner_principal,self.repository,self.target=owner_principal,repository,target
        self.build_native_provider,self.transport,self.gate=build_native_provider,transport,gate
        self.profile_digest,self.successor_digest,self.companion_digest=(
            profile_digest,successor_digest,companion_digest)
        self.transition=transition
        if frozen_handoff is not None:
            need(not transition,'R7_REGISTRY_FROZEN_STATE_PREPARATION_REQUIRED')
        self.frozen_handoff=None if frozen_handoff is None else startup_handoff(frozen_handoff)
        self.provider_guard,self.effect_guard,self.ready=provider_guard,effect_guard,ready
        self._verify_delivery = verify_delivery

    def verify_startup(self,reader,*,release_active=None):
        need(reader is self.transport.peer and
             getattr(reader,'_semantic_transport',self.transport) is self.transport and
             getattr(reader, '_policy_history', self.history) is self.history,
             'R7_REGISTRY_SUCCESSOR_PEER_BINDING_CHANGED')
        self.gate.verify_startup(self.frozen_handoff,release_active=release_active)
        need(self.transport.profile_digest()==self.profile_digest,
             'R7_REGISTRY_SUCCESSOR_PEER_BINDING_CHANGED')
        if self._verify_delivery is not None:
            self._verify_delivery()

    def owner_auth(self, machine, owner):
        from .semantic_enrollment import OwnerPrincipalAuth

        def active(name):
            with owner._db() as db:
                db.execute('PRAGMA query_only=ON')
                return name==owner.owner and db.execute(
                    'SELECT 1 FROM credentials WHERE active=1 LIMIT 1').fetchone() is not None
        return OwnerPrincipalAuth(machine,owners={owner.owner:self.owner_principal},
                                  active_owner=active)

    def install(self, *, core, portal, ingress, machine_base, native, reader,
                incumbent_choices, incumbent_scope, opt_in, registry_predecessor=None,
                release_active=False):
        from .composite_authority import ContextAdmission
        from .maintenance_ingress import MaintenanceIngress, RouteAdmission, owner_passive_route
        from .maintenance_transport import MaintenanceRegistryTransport
        from .merge_register import MergeRegisterAdapter, TransportMergeRegisterBinding
        from .native_merge_receipt import NativeMergeProvider
        from .owner_policy_editor_v2 import OwnerPolicyEditor
        from .registry_group_binding import RegistryGroupBinding
        from .registry_single_binding import RegistrySingleAdapter
        from .semantic_access import SemanticAccess, SemanticRepoBroker, subjects
        from .semantic_owner_portal import PREFIX, SemanticOwnerPortal
        from ..read_approval import install_owner_read_approval

        from .semantic_enrollment import OwnerPrincipalAuth
        need(type(core) is CompositeUnifiedCore and machine_base.broker.core is core
             and type(core.auth) is OwnerPrincipalAuth
             and core.auth.owner_actor(portal.auth.owner)==self.owner_principal
             and native is not None
             and self.transport.peer is reader,
             'R7_REGISTRY_SUCCESSOR_PEER_BINDING_CHANGED')
        self.verify_startup(reader,release_active=release_active)
        provider=self.build_native_provider(native['adapter'])
        need(type(provider) is NativeMergeProvider and provider.reader.adapter is native['adapter']
             and provider.discovery.repository==self.repository,
             'SUCCESSOR_NATIVE_COMPOSITION_REQUIRED')
        # Keep the independently reconstructed incumbent policy and source
        # coordinates. New exact coordinates start DENY for owner review.
        current = PolicyAdmission(core, incumbent_choices, scope_binding=incumbent_scope)
        history = self.history
        if type(history) is ReviewedHistoryEvidence:
            from .owner_policy_r7_v2 import reviewed_mirror_v1_previous_scope
            with core._db() as db:
                db.execute('PRAGMA query_only=ON')
                db.execute('BEGIN')
                history = history.restore(
                    core, db, current=current, predecessor=registry_predecessor,
                    previous_scope=reviewed_mirror_v1_previous_scope(
                        incumbent_scope, all_methods=opt_in.allow_all_method_policy_upgrade))
        need(current.sha == history.incumbent.sha, 'R7_REGISTRY_INCUMBENT_AUTHORITY_CHANGED')
        coords=self.semantic.coordinates() | {
            tuple(row[key]) for row in self.context.metadata()['grants']
            for key in ('parent','child')}
        choices=dict(incumbent_choices)
        for coord in coords-set(core.policies):
            core.policies[coord]='DENY'
            choices[coord]={'DENY','ASK','ALLOW'}

        def grant(actor,operation,subject):
            return (core.auth.active(actor) and self.semantic.allows(
                    actor,'registry',operation,self.target,subject))

        def scoped(actor, request):
            return request['target']==self.target and all(
                grant(actor,request['operation'],s) for s in subjects(request))

        def preflight(actor,operation,params):
            return scoped(actor,{'service':'registry','operation':operation,
                                 'target':self.target,'params':params})

        def provenance(actor):
            return 'OWNER_DIRECT' if actor==self.owner_principal else 'OWNER_TRANSCRIBED'

        core.bind_maintenance(self.gate)
        transport=MaintenanceRegistryTransport(self.transport,self.gate,preflight=preflight)
        admission=ContextAdmission(core,self.context,guard=self.provider_guard)
        group_binding=RegistryGroupBinding(transport=transport,admission=admission.admit,
                         provenance=provenance,profile_digest=self.profile_digest)
        single=RegistrySingleAdapter(transport,authorize=scoped,provenance=provenance,
                         profile_reader=self.transport.profile_digest,ordinary=core.adapters['registry'])
        group=GroupAdapter(binding=group_binding,ordinary=single)
        merge_binding=TransportMergeRegisterBinding(provider=provider,registry=self.transport,
                         admission=admission.admit,effect_guard=self.effect_guard,gate=self.gate,
                         policy_authority_digest=self.successor_digest)
        merge=MergeRegisterAdapter(binding=merge_binding)
        group_binding.adapter,merge_binding.adapter=group,merge
        group.core=merge.core=single.core=core
        core.adapters.update(registry=group,release=merge)
        scope={**incumbent_scope,'compositeContext':self.context.sha,'semanticScope':self.semantic.sha}
        core.install_reviewed(history=history,enrollment=self.context,
            semantic_enrollment=self.semantic,choices=choices,scope_binding=scope,
            expected_predecessor_digest=history.incumbent.sha,
            expected_successor_digest=self.successor_digest,
            expected_companion_digest=self.companion_digest,transition=self.transition,
            release_active=release_active)

        portal.strong_operations |= frozenset((key[1],key[2]) for key,values
            in core.authority.choices.items() if 'ASK' in values)
        portal.bind_editor(OwnerPolicyEditor(core,portal.auth,source_digest=opt_in.source_digest,
                           credential_generation=opt_in.credential_generation))
        access=SemanticAccess.from_reviewed(core,transport,self.gate,
                                            enrollment=self.semantic,ready=self.ready)
        approval=install_owner_read_approval(core,machine_base.broker,portal)
        access.bind_existing_read_approval(approval)
        machine_base.broker=SemanticRepoBroker(machine_base.broker,access)
        owner=SemanticOwnerPortal(portal,access,repository=self.repository,target=self.target,
                                  discovery=provider.discovery)

        # Known passive routes only. SemanticAccess separately reserves READ
        # ASK before writing Core. All legacy ingress remains conservative.
        def owner_route(env):
            from .maintenance_gate import Coordinate
            path,method=env.get('PATH_INFO'),env.get('REQUEST_METHOD')
            # OwnerPortal performs the exact typed suffix validation.
            if owner_passive_route(env) or (path==PREFIX+'/read' and method=='POST') or (
                    method=='GET' and (path in (PREFIX+'/capabilities','/v1/owner/pending',
                                                '/v1/owner/history','/v1/owner/unresolved',
                                                '/v1/owner/session')
                    or (type(path) is str and path.startswith('/v1/owner/requests/')))):
                return RouteAdmission(True)
            if path in (PREFIX+'/discover',PREFIX+'/repropose') and method=='POST':
                return RouteAdmission(False,Coordinate('release','merge_and_register'))
            if path in (PREFIX+'/register-confirmed/begin',PREFIX+'/register-confirmed/finish',
                        PREFIX+'/register-external/begin',PREFIX+'/register-external/finish') and method=='POST':
                return RouteAdmission(False,Coordinate('registry','register_merge'))
            return RouteAdmission(False)

        def machine_route(env):
            from io import BytesIO
            from .maintenance_gate import Coordinate
            from .semantic_access import validate
            from ..core import ApprovalError

            path=env.get('PATH_INFO')
            if path not in ('/v1/reads','/v1/actions','/v1/integrations/catalog') or env.get('REQUEST_METHOD')!='POST':
                return RouteAdmission(False)
            # Validate the existing listener boundary before interpreting
            # any operation coordinate or disclosing maintenance state.
            need(machine_base._environment(env),'REPO_ROUTE_DENIED')
            machine_base._credential(env)
            length=env.get('CONTENT_LENGTH','')
            if (type(length) is not str or not length.isdecimal() or len(length)>8
                    or not 0<int(length)<=machine_base.max_bytes):
                return RouteAdmission(False)
            try:
                raw=env['wsgi.input'].read(int(length))
                env['wsgi.input']=BytesIO(raw)
                query=machine_base._body({**env,'wsgi.input':BytesIO(raw)})
                if path=='/v1/integrations/catalog':
                    # The exact authenticated catalog projects current
                    # policy/credential readiness, not Core requests.
                    return RouteAdmission(query=={})
                if (path=='/v1/reads' and type(query) is dict
                        and (query.get('service'),query.get('operation'))==('github','list_branches')):
                    from ..workflow.adapters import NativeGitHubAdapter
                    from ..repo_action_contract import validate_read_query
                    if type(machine_base.broker.base.read_adapters.get('github')) is NativeGitHubAdapter:
                        validate_read_query(query)
                        # SemanticRepoBroker rechecks ALLOW and passive
                        # restrictions at execution; ASK is still reserved.
                        return RouteAdmission(True)
                if path=='/v1/reads' and type(query) is dict and query.get('service')=='registry':
                    try:
                        validate(query,read=True)
                    except Denied:
                        pass  # Legacy read shapes keep their existing path.
                    else:
                        return RouteAdmission(True)
                return RouteAdmission(False,Coordinate(query['service'],query['operation']))
            except (ApprovalError,OSError,TypeError,KeyError,ValueError):
                return RouteAdmission(False)

        owner_guard=MaintenanceIngress(owner,self.gate,classify=owner_route)
        owner_guard._reply=portal._reply
        owner_guard._extension_runtime=portal._extension_runtime
        machine_guard=MaintenanceIngress(ingress,self.gate,classify=machine_route)
        machine_guard.base=machine_base
        return owner_guard,machine_guard

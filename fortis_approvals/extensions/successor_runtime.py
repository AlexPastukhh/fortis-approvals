"""Compose the exact owner-mounted Registry successor for ordinary R7 startup."""
from pathlib import Path

from ..core import Denied
from ..integrations.registry.read_contract import REPOSITORY
from ..integrations.registry_contracts import semantic_contract as sc
from ..integrations.registry_contracts.maintenance_contract import startup_handoff
from .composite_authority import ContextEnrollment, ProviderGuard
from .composite_successor import ReviewedHistoryEvidence, ReviewedRegistrySuccessor
from .maintenance_gate import MaintenanceGate
from .maintenance_interlock_reader import InterlockReservations, read_owner_interlock
from .semantic_enrollment import SemanticEnrollment


class ProtectedRegistrySuccessor:
    def __init__(self, value, *, source_digest):
        sc.fields(value, ('schemaVersion', 'repository', 'target', 'ownerPrincipal',
                          'context', 'contextDigest', 'semantic', 'semanticDigest',
                          'successorDigest', 'companionDigest', 'interlockDigest',
                          'transition', 'frozenHandoff', 'validatorRevision',
                          'impactBinding', 'buildPins', 'ciPolicy', 'ciPolicyDigest'))
        sc.need(type(value['schemaVersion']) is int and value['schemaVersion'] == 1
                and value['repository'] == REPOSITORY and type(value['transition']) is bool,
                'R7_REGISTRY_SUCCESSOR_PROFILE_DENIED')
        for name in ('target', 'ownerPrincipal'):
            sc.name(value[name])
        for pin in ('successorDigest', 'companionDigest', 'interlockDigest', 'ciPolicyDigest'):
            sc.hex_id(value[pin], 64)
        sc.hex_id(value['validatorRevision'], 40)
        sc.need(type(value['impactBinding']) is dict and type(value['buildPins']) is dict
                and sc.digest(value['ciPolicy']) == value['ciPolicyDigest'],
                'R7_REGISTRY_SUCCESSOR_PROFILE_DENIED')
        handoff = value['frozenHandoff']
        if handoff is not None:
            handoff = startup_handoff(handoff)
            sc.need(handoff['role'] == 'staged_target' and not value['transition']
                    and handoff['interlockDigest'] == value['interlockDigest'],
                    'R7_REGISTRY_SUCCESSOR_PROFILE_DENIED')
        self._raw = sc.canonical(value)
        self._source_digest = source_digest
        self.context = ContextEnrollment.from_reviewed_rows(
            value['context'], source_digest=source_digest, expected_digest=value['contextDigest'])
        self.semantic = SemanticEnrollment(value['semantic'], source_digest=source_digest,
                                           expected_digest=value['semanticDigest'])
        sc.need(all(row.get('repository', row.get('subject', {}).get('repository')) == REPOSITORY
                    for row in self.context.metadata()['grants'])
                and all(row['subject']['repository'] == REPOSITORY
                        for row in self.semantic.metadata()['grants']),
                'R7_REGISTRY_SUCCESSOR_PROFILE_DENIED')

    def _maintenance_gate(self, reader, config):
        transport = reader._semantic_transport
        pins = dict(instance_id=reader._instance, scope_digest=reader._scope,
                    generation=transport.generation)
        phase_pin = config['interlockDigest']

        def read_phase():
            return read_owner_interlock(**pins, expected_digest=phase_pin), phase_pin

        return MaintenanceGate(**pins, read_interlock=read_phase,
                               read_holds=transport.maintenance_snapshot,
                               shared_reservations=InterlockReservations())

    def _delivery(self, reader, config, *, readonly):
        from ..integrations.registry_contracts import merge_evidence
        binding = merge_evidence.mount_binding(
            merge_evidence.MOUNT, uid=reader._reader[0], gid=reader._registry[2], readonly=readonly)
        expected = {**binding, 'policyAuthorityDigest':config['successorDigest'],
                    'interlockDigest':config['interlockDigest']}
        sc.need(reader._semantic_transport.profile().get('sourceDelivery') == expected,
                'SOURCE_EVIDENCE_BINDING_CHANGED')
        return expected

    def checked_delivery(self, reader, *, expected_interlock_digest, incumbent_core=None, scratch_root=None):
        """Existing Check/Apply read-only helper. Performs no startup or write."""
        from .composite_preservation import project_staged_companion

        config = sc.loads_strict(self._raw)
        sc.need(reader._successor_config is self and config['interlockDigest'] == expected_interlock_digest,
                'R7_REGISTRY_SUCCESSOR_CONTROLLER_PIN_CHANGED')
        gate = self._maintenance_gate(reader, config)
        handoff = config['frozenHandoff']
        gate.verify_startup(handoff)
        binding = self._delivery(reader, config, readonly=True)
        receipt = {'sourceDelivery':binding, 'companionDigest':config['companionDigest'],
                   'generation':reader._semantic_transport.generation}
        if incumbent_core is not None:
            sc.need(config['transition'] and handoff is None, 'R7_REGISTRY_SUCCESSOR_TRANSITION_REQUIRED')
            history = reader._policy_history
            sc.need(type(history) is ReviewedHistoryEvidence, 'R7_REGISTRY_SUCCESSOR_PROFILE_DENIED')
            receipt['legacyCompanion'] = project_staged_companion(
                incumbent_core, expected_digest=config['companionDigest'],
                verify_history=history.verify_incumbent_storage, scratch_root=scratch_root)
            gate.verify_startup(handoff)
            sc.need(self._delivery(reader, config, readonly=True) == binding, 'SOURCE_EVIDENCE_BINDING_CHANGED')
        return receipt

    def compose(self, reader, *, state, project_key, github_pilot, credential_generation):
        from ..integrations.github.gateway.analysis_adapter import AnalysisGitHubAdapter
        from ..workflow.adapters import NativeGitHubAdapter
        from ..workflow.common import branch
        from .native_merge_discovery import NativeMergeDiscovery
        from .native_merge_receipt import NativeMergeProvider, NativeMergeReceiptReader
        from .successor_ci import SuccessorCI
        from .successor_impact import SuccessorImpact
        from .successor_projector import SuccessorProjector
        from .successor_source_delivery import SuccessorSourceDelivery

        config = sc.loads_strict(self._raw)
        transport, history = reader._semantic_transport, reader._policy_history
        repository, repo_name = REPOSITORY, REPOSITORY.split('/')[1]
        owner, target = config['ownerPrincipal'], config['target']
        profile = reader._semantic_profile_digest
        sc.need(type(history) is ReviewedHistoryEvidence and reader._successor_config is self
                and reader._gateway_source_digest == self._source_digest
                and github_pilot.owner == repository.split('/')[0]
                and (github_pilot.dynamic_repositories or github_pilot.repository == repo_name),
                'R7_REGISTRY_SUCCESSOR_PROFILE_DENIED')
        gate = self._maintenance_gate(reader, config)

        def verify_delivery():
            self._delivery(reader, config, readonly=False)

        state_root = Path(state)/'registry-functional-v1'
        source = state_root/'source.git'
        impact = SuccessorImpact(validator_repository=state_root/'validator.git',
            validator_revision=config['validatorRevision'], source_repository=source,
            state_root=state_root, repository=repository, binding=config['impactBinding'],
            build_pins=config['buildPins'], profile_digest=profile)
        ci_policy = config['ciPolicy']
        sc.fields(ci_policy, ('schemaVersion', 'repository', 'rulesDigest', 'workflows'))
        sc.need(ci_policy['repository'] == repository and type(ci_policy['workflows']) is list
                and 2 <= len(ci_policy['workflows']) <= 4,
                'SUCCESSOR_CI_POLICY_CHANGED')
        for row in ci_policy['workflows']:
            sc.fields(row, ('name', 'id', 'path', 'jobs', 'sha256'))

        core = None

        def source_revision():
            view = transport.profile()
            sc.need(view['profileDigest'] == profile, 'SOURCE_PROFILE_CHANGED')
            return view['sourceRevision']

        def current_generation():
            generation = credential_generation()
            sc.hex_id(generation, 64)
            return generation

        def active(actor):
            return core is not None and core.auth.active(actor)

        def owner_scope(actor, candidate):
            return actor == owner and candidate == repository and active(actor)

        def native_provider(native):
            nonlocal core
            sc.need(core is None and type(native) is NativeGitHubAdapter
                    and native.config == github_pilot and native.observation_core is not None,
                    'SUCCESSOR_NATIVE_COMPOSITION_REQUIRED')
            core = native.observation_core
            native._repo(repo_name)

            def read_guard(actor, candidate, operation, _params):
                if not owner_scope(actor, candidate) or operation not in (
                        'list_pull_requests', 'successor_pr_evidence', 'successor_ci_evidence'):
                    return False
                subject = {'repository': repository}
                if not self.semantic.allows(actor, 'github', 'list_pull_requests', repo_name, subject):
                    return False
                if operation != 'list_pull_requests' and not self.semantic.allows(
                        actor, 'release', 'merge_and_register', target, subject):
                    return False
                current_generation()
                return core._policy(actor, {
                    'service':'github', 'operation':'list_pull_requests', 'target':repo_name,
                    'params':{'page':1, 'perPage':20, 'state':'open'}}) == 'ALLOW'

            def branch_guard(actor, candidate, head):
                if not owner_scope(actor, candidate):
                    return False
                try:
                    return branch(head) == head
                except Denied:
                    return False

            workflows = {str(row['id']): row['path'] for row in ci_policy['workflows']}
            ci_adapter = AnalysisGitHubAdapter(
                native.transport, owner=native.owner, repositories=(repo_name,),
                receipt_store=native.store, bindings={repo_name:{
                    'workflows': workflows, 'projectKey': project_key, 'allowCiControl': False}})
            ci = SuccessorCI(ci_adapter, policy=ci_policy, expected_digest=config['ciPolicyDigest'],
                             read_guard=read_guard)
            pin = sc.digest({'repository':repository, 'validatorRevision':impact.revision,
                             'ciPolicyDigest':ci.pin, 'profileDigest':profile})
            delivery = SuccessorSourceDelivery(
                backend=native.backend, repository=repository, state_root=state_root,
                producer_uid=reader._reader[0], registry_gid=reader._registry[2])
            projector = SuccessorProjector(impact, ci, source_revision=source_revision,
                                           expected_composition_digest=pin, source_view=delivery.review)
            discovery = NativeMergeDiscovery(native, repository=repository, read_guard=read_guard,
                                              branch_guard=branch_guard, project=projector)

            def receipt_guard(ctx, _kind, identity):
                if not owner_scope(ctx.actor, identity['repository']) or ctx.target != target:
                    return False
                current_generation()
                return True

            receipt = NativeMergeReceiptReader(native, source_repository=source,
                                               state_root=state_root, read_guard=receipt_guard,
                                               evidence=delivery)
            return NativeMergeProvider(discovery, receipt)

        def provider_guard(actor, row, _step):
            generation = current_generation()
            github = row['child'][1:3] == ['github', 'merge_pull_request']
            registered = row['child'][1] == 'registry'
            granted = active(actor) and (registered or (github and actor == owner))
            ready = granted and (github or transport.profile_digest() == profile)
            return ProviderGuard(ready, granted, 'ASK' if github else 'ALLOW', generation)

        def effect_guard(ctx):
            if ctx.target != target or not owner_scope(ctx.actor, ctx.params['proposal']['repository']):
                return False
            current_generation()
            verify_delivery()
            return True

        def ready(actor, _request):
            return active(actor) and transport.profile_digest() == profile

        return ReviewedRegistrySuccessor(
            history=history, context=self.context, semantic=self.semantic, owner_principal=owner,
            repository=repository, target=target, build_native_provider=native_provider,
            transport=transport, gate=gate, profile_digest=profile,
            successor_digest=config['successorDigest'], companion_digest=config['companionDigest'],
            transition=config['transition'], provider_guard=provider_guard, effect_guard=effect_guard,
            ready=ready, frozen_handoff=config['frozenHandoff'], verify_delivery=verify_delivery)

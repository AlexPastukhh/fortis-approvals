"""Compose the exact owner-mounted Registry successor for ordinary R7 startup."""
from pathlib import Path

from ..core import Denied
from ..integrations.registry.read_contract import REPOSITORY
from ..integrations.registry_contracts import semantic_contract as sc
from ..integrations.registry_contracts.maintenance_contract import (
    bind_startup_handoff, startup_handoff, staged_registry_profile)
from .composite_authority import ContextEnrollment, ProviderGuard
from .composite_successor import ReviewedHistoryEvidence, ReviewedRegistrySuccessor
from .maintenance_gate import MaintenanceGate
from .maintenance_interlock_reader import InterlockReservations, read_owner_interlock, read_latest_interlock
from .semantic_enrollment import SemanticEnrollment

# Exact reviewed #288 enrollment source; not a new-image identity or a
# wildcard for authority migration. The outer profile still pins the actual
# installed Gateway source independently.
_RETAINED_288_ENROLLMENT_SOURCE = 'df205501660cfc92619bb7bbda1e52df3e207a29fba9ef37a2b9fdadf7a6ac14'


def project_corrective_profiles(gateway, registry, composition, *,
                                expected_gateway_digest, expected_registry_digest,
                                new_source_digest, nonce, peer_key_digest,
                                frame_key_digest, expected_gateway_source_digest=None):
    return _project_retained_profiles(gateway,registry,composition,
        expected_gateway_digest=expected_gateway_digest,expected_registry_digest=expected_registry_digest,
        new_source_digest=new_source_digest,nonce=nonce,peer_key_digest=peer_key_digest,
        frame_key_digest=frame_key_digest,expected_gateway_source_digest=expected_gateway_source_digest,
        staged=False)


def _project_retained_profiles(gateway, registry, composition, *,
                                expected_gateway_digest, expected_registry_digest,
                                new_source_digest, nonce, peer_key_digest,
                                frame_key_digest, expected_gateway_source_digest, staged):
    """Project the paired owner seals without changing the retained enrollment.

    The original invocation takes the exact recovered #288 profile. An
    installed successor requires an independently checked source digest and
    retains its stored enrollment source. The caller verifies the incumbent
    image, stored authority and protected profile pins before writing volumes.
    """
    for value in (expected_gateway_digest, expected_registry_digest,
                  new_source_digest, peer_key_digest, frame_key_digest):
        sc.hex_id(value,64)
    sc.uuid_id(nonce)
    if expected_gateway_source_digest is None:
        expected_gateway_source_digest = _RETAINED_288_ENROLLMENT_SOURCE
        expected_composition_versions = (1,)
    else:
        sc.hex_id(expected_gateway_source_digest,64)
        expected_composition_versions = (2,3) if staged else (2,)
    sc.need(sc.digest(gateway)==expected_gateway_digest
            and sc.digest(registry)==expected_registry_digest
            and gateway['schemaVersion']==5 and registry['schemaVersion']==3
            and gateway['gatewaySourceDigest']==expected_gateway_source_digest
            and new_source_digest!=expected_gateway_source_digest
            and sc.digest(composition)==gateway['successorSha256']
            and composition['schemaVersion'] in expected_composition_versions
            and composition['transition'] is False
            and (composition['frozenHandoff'] is None or (staged and composition['schemaVersion']==3))
            and nonce!=gateway['releaseNonce'],
            'R7_REGISTRY_CORRECTIVE_SOURCE_SEAL_CHANGED')
    _assert_retained_profile_pair(gateway,registry,composition)
    pins=registry['semantic']
    sc.need(peer_key_digest!=frame_key_digest
            and not {peer_key_digest,frame_key_digest}&{pins['peerKeyDigest'],pins['frameKeyDigest']},
            'R7_REGISTRY_CORRECTIVE_PAIR_CHANGED')
    ProtectedRegistrySuccessor(composition,source_digest=expected_gateway_source_digest)
    successor={**composition,'schemaVersion':composition['schemaVersion'] if composition['schemaVersion']==3 else 2,
               'retainedEnrollmentSourceDigest':composition.get(
                   'retainedEnrollmentSourceDigest',expected_gateway_source_digest)}
    ProtectedRegistrySuccessor(successor,source_digest=new_source_digest)
    target_gateway={**gateway,'releaseNonce':nonce,'gatewaySourceDigest':new_source_digest,
                    'plannerKeySha256':peer_key_digest,'semanticFrameKeySha256':frame_key_digest,
                    'successorSha256':sc.digest(successor)}
    target_registry={**registry,'semantic':{**pins,'peerKeyDigest':peer_key_digest,
                                            'frameKeyDigest':frame_key_digest}}
    return {'gateway':target_gateway,'registry':target_registry,'successor':successor}


def _assert_retained_profile_pair(gateway,registry,composition):
    pins=registry['semantic']
    writer=registry['sourceWrite']
    sc.need(gateway['instanceId']==registry['instanceId']
            and gateway['scopeDigest']==sc.digest(registry['scope'])
            and gateway['semanticProfileDigest']==pins['successorProfileDigest']
            and gateway['semanticGeneration']==pins['generation']
            and gateway['semanticInternalActor']==pins['internalActor']
            and gateway['socketPath']==registry['socketPath']
            and gateway['plannerKeySha256']==pins['peerKeyDigest']
            and gateway['semanticFrameKeySha256']==pins['frameKeyDigest']
            and writer['ownerActor']==composition['ownerPrincipal']
            and writer['policyAuthorityDigest']==composition['successorDigest']
            and ('latestPin' in writer)==(composition['schemaVersion']==3)
            and ('latestPin' not in writer or writer['latestPin'] is True)
            and all(writer[key]==composition[key] for key in
                    ('target','interlockDigest','validatorRevision','impactBinding','buildPins')),
            'R7_REGISTRY_CORRECTIVE_PAIR_CHANGED')


def project_staged_profiles(gateway, registry, composition, *,
                            expected_gateway_digest, expected_registry_digest,
                            expected_gateway_source_digest, new_source_digest,
                            nonce, peer_key_digest, frame_key_digest,
                            handoff, staged_record, staged_companion_digest):
    """Project a frozen receiver from independently checked controller pins.

    This is only material projection: the controller must authenticate the
    phase/hold and companion pins and verify actual image/source, mounts and
    lineage. The receiving runtime still checks the exact Registry hold.
    No authority change or phase publication is performed here.
    """
    projected = _project_retained_profiles(
        gateway, registry, composition,
        expected_gateway_digest=expected_gateway_digest,
        expected_registry_digest=expected_registry_digest,
        expected_gateway_source_digest=expected_gateway_source_digest,
        new_source_digest=new_source_digest, nonce=nonce,
        peer_key_digest=peer_key_digest, frame_key_digest=frame_key_digest, staged=True)
    return _bind_staged_profiles(projected,handoff=handoff,staged_record=staged_record,
                                 staged_companion_digest=staged_companion_digest)


def _bind_staged_profiles(projected,*,handoff,staged_record,staged_companion_digest):
    gateway=projected['gateway']
    new_source_digest=gateway['gatewaySourceDigest']
    handoff = startup_handoff(handoff)
    record = bind_startup_handoff(handoff, staged_record)
    sc.hex_id(staged_companion_digest,64)
    sc.need(handoff['role']=='staged_target'
            and record['registryInstanceId']==gateway['instanceId']
            and record['scopeDigest']==gateway['scopeDigest']
            and record['attempt']['sourceGeneration']==gateway['semanticGeneration'],
            'R7_REGISTRY_STAGED_PAIR_CHANGED')
    generation, pin = record['generation'], handoff['interlockDigest']
    successor = projected['successor']
    successor.update(schemaVersion=3,latestPin=True,frozenHandoff=handoff,interlockDigest=pin,
                     companionDigest=staged_companion_digest)
    ProtectedRegistrySuccessor(successor,source_digest=new_source_digest)
    projected['gateway'].update(semanticGeneration=generation,
                                successorSha256=sc.digest(successor))
    projected['registry']=staged_registry_profile(projected['registry'],
        handoff=handoff,staged_record=record)
    return projected


def project_bootstrap_final_profiles(gateway, registry, composition, *, checked,
                                     authorization, seed, begin, publication):
    """Bind already-reviewed fresh #289 successor material to the frozen phase.

    The host must independently replay the original begin and authenticate
    the current APPLY_STOP publication before using this projection.
    Reuse the staged profile binder; do not generate another nonce/key pair
    or re-enroll authority. The preliminary profiles are exact Check pins.
    """
    from ..integrations.registry_contracts.maintenance_contract import bootstrap_final_handoff
    final=bootstrap_final_handoff(checked,authorization,seed,begin,publication)
    return _project_prepared_profiles(gateway,registry,composition,checked=checked,final=final,ordinary=False)


def _project_prepared_profiles(gateway,registry,composition,*,checked,final,ordinary):
    handoff,staged_record=final['handoff'],final['record']
    g,r=checked['gateway'],checked['registry']
    sc.need(sc.digest(gateway)==g['profileDigest']
            and sc.digest(registry)==r['profileDigest']
            and gateway['schemaVersion']==5 and registry['schemaVersion']==3
            and composition['schemaVersion']==(3 if ordinary else 2) and composition['transition'] is False
            and (ordinary or composition['frozenHandoff'] is None)
            and sc.digest(composition)==gateway['successorSha256']
            and gateway['releaseNonce']==g['releaseNonce']
            and gateway['gatewaySourceDigest']==g['sourceDigest'],
            'R7_REGISTRY_BOOTSTRAP_FINAL_PROFILE_CHANGED')
    _assert_retained_profile_pair(gateway,registry,composition)
    pins=registry['semantic']
    binding={'instanceId':registry['instanceId'],'scopeDigest':sc.digest(registry['scope']),
        'profileDigest':pins['successorProfileDigest'],'generation':pins['generation'],
        'internalActor':pins['internalActor'],'peerKeyDigest':pins['peerKeyDigest'],
        'frameKeyDigest':pins['frameKeyDigest'],'socketPath':registry['socketPath'],
        'readerUid':registry['readerUid'],'readerGid':registry['readerGid'],
        'authorityDigest':registry['sourceWrite']['policyAuthorityDigest'],
        'interlockDigest':registry['sourceWrite']['interlockDigest']}
    sc.need(binding==r['binding'] and pins['peerKeyDigest']!=pins['frameKeyDigest']
            and gateway['readerUid']==registry['readerUid'] and gateway['readerGid']==registry['readerGid']
            and staged_record['attempt']['subject']==r['items']['gateway']['subject']
            and staged_record['attempt']['source']==r['items']['gateway']['source'],
            'R7_REGISTRY_BOOTSTRAP_FINAL_PROFILE_CHANGED')
    ProtectedRegistrySuccessor(composition,source_digest=g['sourceDigest'])
    # Deep canonical copy: do not mutate a nested original profile/pin.
    projected=sc.loads_strict(sc.canonical({'gateway':gateway,'registry':registry,'successor':composition}))
    return _bind_staged_profiles(projected,handoff=handoff,staged_record=staged_record,
                                 staged_companion_digest=composition['companionDigest'])


class ProtectedRegistrySuccessor:
    def __init__(self, value, *, source_digest):
        sc.need(type(value) is dict and type(value.get('schemaVersion')) is int
                and value['schemaVersion'] in (1, 2, 3), 'R7_REGISTRY_SUCCESSOR_PROFILE_DENIED')
        retained = value['schemaVersion'] in (2,3)
        dynamic = value['schemaVersion']==3
        fields = ('schemaVersion', 'repository', 'target', 'ownerPrincipal',
                  'context', 'contextDigest', 'semantic', 'semanticDigest',
                  'successorDigest', 'companionDigest', 'interlockDigest',
                  'transition', 'frozenHandoff', 'validatorRevision',
                  'impactBinding', 'buildPins', 'ciPolicy', 'ciPolicyDigest')
        sc.fields(value, fields + (('retainedEnrollmentSourceDigest',) if retained else ())
                  + (('latestPin',) if dynamic else ()))
        sc.need(not dynamic or (value['latestPin'] is True and value['frozenHandoff'] is not None),
                'R7_REGISTRY_SUCCESSOR_PROFILE_DENIED')
        sc.need(value['repository'] == REPOSITORY and type(value['transition']) is bool,
                'R7_REGISTRY_SUCCESSOR_PROFILE_DENIED')
        sc.hex_id(source_digest, 64)
        enrollment_source = source_digest
        if retained:
            enrollment_source = value['retainedEnrollmentSourceDigest']
            # No first transition or new authority epoch may use this path.
            # install_reviewed still requires the exact stored successor
            # authority, original history and both exact enrollment digests.
            sc.need(enrollment_source == _RETAINED_288_ENROLLMENT_SOURCE
                    and source_digest != enrollment_source and not value['transition'],
                    'R7_REGISTRY_RETAINED_ENROLLMENT_DENIED')
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
            value['context'], source_digest=enrollment_source, expected_digest=value['contextDigest'])
        self.semantic = SemanticEnrollment(value['semantic'], source_digest=enrollment_source,
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

        dynamic=config.get('latestPin') is True
        def read_latest():return read_latest_interlock(**pins)
        def read_phase():
            if dynamic:
                record,projection=read_latest()
                return record,projection['interlockDigest']
            return read_owner_interlock(**pins, expected_digest=phase_pin), phase_pin

        return MaintenanceGate(**pins, read_interlock=read_phase,
                               read_holds=transport.maintenance_snapshot,
                               shared_reservations=InterlockReservations(),
                               read_latest=read_latest if dynamic else None)

    def _delivery(self, reader, config, *, readonly, profile=None):
        from ..integrations.registry_contracts import merge_evidence
        binding = merge_evidence.mount_binding(
            merge_evidence.MOUNT, uid=reader._reader[0], gid=reader._registry[2], readonly=readonly)
        dynamic=config.get('latestPin') is True
        def phase_pin():
            if not dynamic:return config['interlockDigest']
            _,projection=read_latest_interlock(instance_id=reader._instance,scope_digest=reader._scope,
                                                generation=reader._semantic_transport.generation)
            return projection['interlockDigest']
        expected = {**binding, 'policyAuthorityDigest':config['successorDigest'],
                    'interlockDigest':phase_pin()}
        if profile is None:
            profile = reader._semantic_transport.profile()
        sc.need(profile.get('sourceDelivery') == expected and
                (not dynamic or phase_pin()==expected['interlockDigest']), 'SOURCE_EVIDENCE_BINDING_CHANGED')
        return expected

    def inspect_existing_companion(self, reader, path):
        """Check the exact retained source or its untouched staged copy."""
        from .composite_preservation import inspect_staged_successor

        config = sc.loads_strict(self._raw)
        history = reader._policy_history
        sc.need(reader._successor_config is self and config['schemaVersion'] in (2,3)
                and not config['transition'] and type(history) is ReviewedHistoryEvidence,
                'R7_REGISTRY_SUCCESSOR_TRANSITION_REQUIRED')
        return inspect_staged_successor(
            path, expected_digest=config['companionDigest'],
            verify_history=lambda db: history.verify_successor_storage(db, config['successorDigest']),
            require_empty=config['frozenHandoff'] is None)

    def checked_delivery(self, reader, *, expected_interlock_digest, incumbent_core=None,
                         scratch_root=None, running_source=False):
        """Existing Check/Apply read-only helper. Performs no startup or write."""
        from .composite_preservation import project_staged_companion

        config = sc.loads_strict(self._raw)
        dynamic=config.get('latestPin') is True
        sc.need(type(running_source) is bool and (not running_source or
                (dynamic and incumbent_core is None)),'R7_REGISTRY_SUCCESSOR_CONTROLLER_PIN_CHANGED')
        sc.hex_id(expected_interlock_digest,64)
        sc.need(reader._successor_config is self and
                (dynamic or config['interlockDigest']==expected_interlock_digest),
                'R7_REGISTRY_SUCCESSOR_CONTROLLER_PIN_CHANGED')
        gate = self._maintenance_gate(reader, config)
        handoff = config['frozenHandoff']
        transport = reader._semantic_transport

        def read_delivery():
            verified=(gate.verify_running_source_delivery() if running_source
                      else gate.verify_startup(handoff))
            expected_registry=None
            if dynamic:
                record,holds,projection=verified
                sc.need(projection['interlockDigest']==expected_interlock_digest,
                        'R7_REGISTRY_SUCCESSOR_CONTROLLER_PIN_CHANGED')
                expected_registry=sc.digest(holds)
            elif handoff is not None:
                expected_registry=handoff['registryDigest']
            profile = transport.profile(source_checkpoint=True) if expected_registry is not None else transport.profile()
            delivery = {'sourceDelivery': self._delivery(reader, config, readonly=True, profile=profile)}
            sc.need(delivery['sourceDelivery']['interlockDigest']==expected_interlock_digest,
                    'R7_REGISTRY_SUCCESSOR_CONTROLLER_PIN_CHANGED')
            if expected_registry is not None:
                checkpoint = profile['sourceCheckpoint']
                # Bind to the current authenticated replay, not the original
                # staged handoff after a lawful completion/source advance.
                sc.need(profile['profileDigest'] == reader._semantic_profile_digest
                        and checkpoint['registryDigest'] == expected_registry,
                        'R7_REGISTRY_SUCCESSOR_CHECKPOINT_CHANGED')
                delivery['registryCheckpoint'] = {
                    'profileDigest': profile['profileDigest'], 'sourceRevision': profile['sourceRevision'],
                    **checkpoint,
                }
            if dynamic:
                delivery.update(latestPin=True,maintenancePhase=record['phase'])
            return delivery

        delivery = read_delivery()
        receipt = {**delivery, 'companionDigest':config['companionDigest'],
                   'generation':transport.generation}
        if incumbent_core is not None:
            history = reader._policy_history
            sc.need(type(history) is ReviewedHistoryEvidence, 'R7_REGISTRY_SUCCESSOR_PROFILE_DENIED')
            if config['transition']:
                receipt['legacyCompanion'] = project_staged_companion(
                    incumbent_core, expected_digest=config['companionDigest'],
                    verify_history=history.verify_incumbent_storage, scratch_root=scratch_root)
            else:
                receipt['existingCompanion'] = self.inspect_existing_companion(reader, incumbent_core)
            sc.need(read_delivery() == delivery, 'SOURCE_EVIDENCE_BINDING_CHANGED')
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

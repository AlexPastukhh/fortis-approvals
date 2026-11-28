"""E1.3b SOURCE-ONLY: exact Gateway pilot admission of two Registry mounts.

Owner Check/Apply uses an explicit opt-in. These tests cover source gates only,
not PowerShell 5.1 or independent owner Docker/host acceptance.
"""
from pathlib import Path
import unittest
import copy

from fortis_approvals.deploy import github_pilot_helpers as helper
from fortis_approvals.tests import test_github_pilot_package as fixture

_ROOT=Path(__file__).resolve().parents[2]
_PS=(_ROOT/'fortis_approvals/deploy/Manage-Integrations.ps1').read_text()
_NONCE='11111111-1111-4111-8111-111111111111'
_PROFILE='fortis-r7-registry-reader-'+_NONCE.replace('-','')
_SOCKET='fortis-registry-read'


def _mount(name, destination, rw=False):
    return dict(Type='volume',Name=name,Destination=destination,RW=rw,
                Source='/var/lib/docker/volumes/'+name+'/_data')


class RegistryExactMountAdmissionTests(unittest.TestCase):
    def setUp(self):
        self.container,self.expected=fixture.AdmissionTests().fixture()
        self.container=copy.deepcopy(self.container)
        self.expected=copy.deepcopy(self.expected)

    def activate(self):
        self.expected['registryReaderVolume']=_PROFILE
        self.expected['registryReleaseNonce']=_NONCE
        self.expected['registrySocketVolume']=_SOCKET
        self.container['Mounts'].extend((
            _mount(_PROFILE,'/run/r7-registry-reader'),
            _mount(_SOCKET,'/run/fortis-registry-read')))

    def test_legacy_without_registry_volume_remains_accepted(self):
        self.assertEqual(helper.admit(self.container,self.expected,pilot=True),
                         {'admission':'PASS'})

    def test_explicit_exact_pair_is_readonly_and_pilot_only(self):
        self.activate()
        self.assertEqual(helper.admit(self.container,self.expected,pilot=True),
                         {'admission':'PASS'})
        self.expected['registryReaderVolume']=''
        with self.assertRaises(RuntimeError):
            helper.admit(self.container,self.expected,pilot=True)
        self.expected['registryReaderVolume']=_PROFILE
        self.expected['registrySocketVolume']=''
        with self.assertRaises(RuntimeError):
            helper.admit(self.container,self.expected,pilot=True)

    def test_nonce_must_derive_exact_versioned_profile_volume(self):
        self.activate()
        for wrong in ('',None,True,'not-uuid',
                      '22222222-2222-4222-8222-222222222222',
                      'AAAA1111-1111-4111-8111-111111111111',
                      '11111111-1111-1111-8111-111111111111',
                      '11111111-1111-4111-1111-111111111111'):
            with self.subTest(wrong=wrong):
                self.expected['registryReleaseNonce']=wrong
                with self.assertRaises(RuntimeError):
                    helper.admit(self.container,self.expected,pilot=True)
        self.expected['registryReleaseNonce']=_NONCE
        self.assertEqual(helper.admit(self.container,self.expected,pilot=True),
                         {'admission':'PASS'})

    def test_wrong_names_and_extra_or_missing_mounts_denied(self):
        for field in ('registryReaderVolume','registrySocketVolume'):
            for wrong in (None, True, '../../secrets', '/run/r7-registry-reader',
                          'fortis-review-secrets', 'fortis-registry-read-other'):
                self.setUp()
                self.activate()
                self.expected[field]=wrong
                with self.subTest(field=field,wrong=wrong), self.assertRaises(RuntimeError):
                    helper.admit(self.container,self.expected,pilot=True)
        self.setUp();self.activate();self.container['Mounts'].pop()
        with self.assertRaises(RuntimeError):
            helper.admit(self.container,self.expected,pilot=True)
        self.setUp();self.activate()
        self.container['Mounts'].append(_mount('fortis-rogue','/run/arbitrary'))
        with self.assertRaises(RuntimeError):
            helper.admit(self.container,self.expected,pilot=True)

    def test_wrong_mount_type_permission_destination_source_denied(self):
        for index in (-1,-2):
            for field,wrong in (('RW',True),('Type','bind'),
                                ('Destination','/run/r7-identity'),
                                ('Source','/var/lib/host/private'),
                                ('Name','fortis-gateway-root')):
                self.setUp();self.activate()
                self.container['Mounts'][index][field]=wrong
                with self.subTest(index=index,field=field),self.assertRaises(RuntimeError):
                    helper.admit(self.container,self.expected,pilot=True)

    def test_successor_mounts_use_a_separate_socket_and_exact_roles(self):
        self.activate()
        suffix = _NONCE.replace('-', '')
        self.expected['registrySuccessorDelivery'] = True
        self.expected['registrySocketVolume'] = 'fortis-registry-read-'+suffix
        self.container['Mounts'][-1] = _mount(self.expected['registrySocketVolume'], '/run/fortis-registry-read')
        evidence = 'fortis-registry-source-evidence-'+suffix
        self.container['Mounts'].extend((
            _mount(evidence, '/run/fortis-registry-source-evidence', rw=True),
            _mount('fortis-r7-maintenance-interlock', '/run/r7-maintenance')))
        self.assertEqual(helper.admit(self.container,self.expected,pilot=True), {'admission':'PASS'})
        for index in (-1,-2):
            self.container['Mounts'][index]['RW'] = not self.container['Mounts'][index]['RW']
            with self.assertRaisesRegex(RuntimeError,'MOUNT_CONFIGURATION_MISMATCH'):
                helper.admit(self.container,self.expected,pilot=True)
            self.container['Mounts'][index]['RW'] = not self.container['Mounts'][index]['RW']

    def test_dynamic_successor_requires_both_exact_readonly_operational_mounts(self):
        self.activate()
        suffix=_NONCE.replace('-', '')
        self.expected.update(registrySuccessorDelivery=True,registryLatestPin=True,
                             registrySocketVolume='fortis-registry-read-'+suffix)
        self.container['Mounts'][-1]=_mount(self.expected['registrySocketVolume'],'/run/fortis-registry-read')
        self.container['Mounts'].extend((
            _mount('fortis-registry-source-evidence-'+suffix,'/run/fortis-registry-source-evidence',True),
            _mount('fortis-r7-maintenance-interlock-v2','/run/r7-maintenance'),
            _mount('fortis-r7-maintenance-anchor','/run/r7-maintenance-anchor')))
        self.assertEqual(helper.admit(self.container,self.expected,pilot=True),{'admission':'PASS'})
        for index in (-1,-2):
            original=copy.deepcopy(self.container['Mounts'][index])
            for field,value in (('RW',True),('Source','/var/lib/host/private'),('Name','fortis-r7-maintenance-interlock')):
                self.container['Mounts'][index]={**original,field:value}
                with self.assertRaises(RuntimeError):helper.admit(self.container,self.expected,pilot=True)
            self.container['Mounts'][index]=original
        self.expected['registryLatestPin']=False
        with self.assertRaisesRegex(RuntimeError,'MOUNT_CONFIGURATION_MISMATCH'):
            helper.admit(self.container,self.expected,pilot=True)
        self.expected.update(registryLatestPin=True,registrySuccessorDelivery=False)
        with self.assertRaisesRegex(RuntimeError,'PILOT_REGISTRY_SUCCESSOR_VOLUME_DENIED'):
            helper.admit(self.container,self.expected,pilot=True)

    def test_bootstrap_check_is_offline_and_cannot_authorize_apply(self):
        start=_PS.index('\nfunction Read-PairedGatewayMaterial {')
        end=_PS.index('function Read-OrdinarySuccessorSource {',start)
        check=_PS[start:end]
        for marker in ('reviewed_bootstrap_gateway','inspect_bootstrap_pair','verify_bootstrap_backup',
                       'bootstrap_compatibility_digest','--network','none','--read-only',
                       'Assert-CorrectiveTargetHolders','Read-BootstrapSeedSource'):
            self.assertIn(marker,check)
        self.assertNotIn("target=/run/fortis-registry-read,",check)
        self.assertNotIn('begin_bootstrap_pair',check)
        # Python-Code supplies the entire executable and args (not an
        # entrypoint override followed by a duplicate python argument).
        self.assertNotIn("'--entrypoint','python'",check)
        self.assertIn('Config.Entrypoint',check)
        # Both actual Check invocations must mount the final empty root.
        gateway_args=check.split('$GatewayArgs=@(',1)[1].split('$GatewayInput=',1)[0]
        registry_args=check.split('$RegistryArgs=@(',1)[1].split('$Artifacts=',1)[0]
        self.assertEqual(gateway_args.count('target=/target,'),1)
        self.assertEqual(registry_args.count('target=/target,'),1)
        self.assertIn("source='+$script:RegistryReaderVolume+',target=/target,readonly,volume-nocopy",gateway_args)
        self.assertIn("source=fortis-registry-config-e13b-'+$Id+',target=/target,readonly,volume-nocopy",registry_args)
        gate=_PS.index("if($Bootstrap289 -and $Action -ceq 'Apply'){")
        block=_PS[gate:_PS.index("if($Action -eq 'Check' -and $OrdinaryPairRequested)",gate)]
        self.assertIn('if(-not $CheckedImageRecord -or -not $script:BootstrapPair -or -not $BootstrapReviewProofRecord)',block)
        self.assertNotIn('RELEASE_SUCCESSOR_STAGED_HANDOVER_UNAVAILABLE',block)
        self.assertIn("throw 'RELEASE_SUCCESSOR_BOOTSTRAP_EXACT_CHECK_REQUIRED'",block)
        dispatch=_PS[_PS.index("Step 'BOOTSTRAP_PREPARED_TRANSITION'"):]
        self.assertLess(dispatch.index('Save-BootstrapPreparedAttempt'),dispatch.index('Invoke-BootstrapPreparedTransition'))
        self.assertLess(dispatch.index('Save-BootstrapPreparedAttempt'),dispatch.index('$SourceStopAttempted=$true'))
        self.assertLess(gate,_PS.index("Step 'PREPARED_RECORD_SAVED'"))
        self.assertIn('Read-BootstrapOwnerReviewProof $BootstrapReviewProofRecord $Pair',check)
        self.assertIn("$Binding['bootstrapPair']=$script:BootstrapPair",_PS)
        self.assertIn("$FreshBootstrap=Read-BootstrapCompatibility $Source -Recheck",_PS)
        self.assertIn("$Report.status='BOOTSTRAP_CHECKED_ONLY'",_PS)
        self.assertIn('deploymentAuthorized -NotePropertyValue $false',_PS)
        self.assertIn('RELEASE_SUCCESSOR_BOOTSTRAP_ALREADY_SEEDED',_PS)

    def test_bootstrap_private_writer_binds_durable_go_and_frozen_source(self):
        start=_PS.index('function Invoke-BootstrapFrozenPair {')
        stop=_PS.index('function Save-BootstrapPreparedAttempt {',start)
        writer=_PS[start:stop]
        self.assertLess(writer.index('Read-BootstrapFrozenIntent'),writer.index('Initialize-SuccessorBootstrapInterlock'))
        self.assertLess(writer.index('Initialize-SuccessorBootstrapInterlock'),writer.index('begin_bootstrap_pair'))
        self.assertIn('bootstrap_pair_authorization',writer)
        self.assertIn('sourceReceipt=$Intent.check.sourceReceipt',writer)
        self.assertIn('Assert-CorrectiveTargetHolders',writer)
        self.assertNotIn('target=/run/fortis-registry-read',writer)
        self.assertIn('target=/run/r7-maintenance,readonly',writer)
        self.assertIn('target=/run/r7-maintenance-anchor,readonly',writer)
        self.assertIn('bootstrapBegin -NotePropertyValue $Result',writer)
        self.assertIn('Save -FlushToDisk',writer)
        self.assertNotIn('Publish-SuccessorInterlock',writer)
        self.assertIn('read_bootstrap_pair',writer)
        self.assertIn('target=/run/fortis-registry-state,readonly',writer)

    def test_bootstrap_prepared_pair_uses_existing_attempt_and_protected_return(self):
        start=_PS.index('function Save-BootstrapPreparedAttempt {')
        stop=_PS.index('function Publish-BootstrapFrozenPhases {',start)
        prepared=_PS[start:stop]
        self.assertLess(prepared.index('New-BootstrapOwnerGo'),prepared.index('Verify-Checked-Image'))
        self.assertLess(prepared.index('Save -FlushToDisk'),prepared.index('Write-Private $AttemptPointer'))
        self.assertIn('Read-BootstrapFrozenIntent',prepared)
        self.assertIn('Stop-BootstrapSourcePair $Source $Path $Hash',prepared)
        self.assertIn('Invoke-BootstrapFrozenPair $Source $Path $Hash',prepared)
        self.assertIn('Publish-BootstrapFrozenPhases $Source $Path $Hash',prepared)
        self.assertIn('if($Bootstrap){Return-BootstrapPreparedPair;return}',_PS)
        self.assertIn('Assert-BootstrapNoReceiver $Intent',_PS)
        self.assertIn('Assert-CorrectiveGateAbsent $P',_PS)

    def test_bootstrap_final_material_uses_two_exact_inactive_config_pairs(self):
        start=_PS.index('\nfunction Invoke-BootstrapFinalMaterialHelper {')
        stop=_PS.index('\nfunction Read-BootstrapReceiver {',start)
        part=_PS[start:stop]
        self.assertIn("target=/run/fortis-registry-state,readonly",part)
        self.assertIn("-prepared,target=/run/fortis-registry-runtime,readonly",part)
        self.assertIn("-prepared,target=/run/r7-registry-reader,readonly",part)
        self.assertIn("targetRoot=$Pair.finalRoots.$Role",part)
        self.assertNotIn("target=/run/fortis-registry-read,",part)
        self.assertIn('seal_bootstrap_registry_material',part)
        self.assertIn('seal_bootstrap_gateway_material',part)
        self.assertIn(' -VerifyOnly',part)
        self.assertIn('Save -FlushToDisk',part)
        self.assertIn('$Actual.registryProfileDigest -cne $Results.Registry.profileDigest',part)
        self.assertNotIn('Publish-SuccessorInterlock',part)

    def test_bootstrap_connected_apply_and_receiver_order(self):
        driver=_PS.split('\nfunction Invoke-BootstrapPreparedTransition {',1)[1].split('\nfunction Publish-BootstrapFrozenPhases {',1)[0]
        self.assertLess(driver.index('Seal-BootstrapFinalProfiles'),driver.index('Start-BootstrapReceiver'))
        self.assertIn('$script:RegistryDelivery=$Delivery',driver)
        receiver=_PS.split('\nfunction Start-BootstrapReceiver {',1)[1].split('\nfunction Assert-BootstrapNoReceiver {',1)[0]
        self.assertLess(receiver.index('bootstrapReceiver -NotePropertyValue'),receiver.index("Step 'BOOTSTRAP_CREATE_REGISTRY_RECEIVER'"))
        self.assertLess(receiver.index('$Saved.id=$C.Id'),receiver.index('Publish-SuccessorInterlock'))
        self.assertLess(receiver.index('Publish-SuccessorInterlock'),receiver.index('Set-BootstrapContainerState $C Start'))
        self.assertLess(receiver.index('Image-RegistrySuccessor-Preflight'),receiver.index('bootstrapDelivery -NotePropertyValue'))
        apply=_PS.split("Step 'BOOTSTRAP_PREPARED_TRANSITION'",1)[1]
        self.assertLess(apply.index('Save-BootstrapPreparedAttempt'),apply.index('Invoke-BootstrapPreparedTransition'))
        self.assertLess(apply.index('Invoke-BootstrapPreparedTransition'),apply.index("Step 'CLONE_STATE'"))
        self.assertIn('Read-BootstrapGatewayCandidate $Intent',apply)
        resume=_PS.split('\nfunction Resume-Target {',1)[1].split('\nfunction Read-RegistryReturnSourceDigest {',1)[0]
        self.assertLess(resume.index('Read-BootstrapReceiver'),resume.index('Set-BootstrapContainerState $C Start'))
        self.assertLess(resume.index('$ActualGate=Image-CLI'),resume.index('Set-BootstrapContainerState $Receiver RestoreRestart'))
        returned=_PS.split('\nfunction Return-BootstrapPreparedPair {',1)[1].split('\nfunction Assert-BootstrapReceiverSelfTest {',1)[0]
        self.assertLess(returned.index('Assert-CorrectiveGateAbsent'),returned.index('Set-BootstrapContainerState $Candidate Stop'))
        self.assertLess(returned.index('Set-BootstrapContainerState $Candidate Stop'),returned.index('Set-BootstrapContainerState $Receiver Stop'))

    def test_successor_recheck_and_companion_preparation_are_on_ordinary_path(self):
        check = _PS.index("Step 'REGISTRY_READER_SEAL_AND_PEER_PREFLIGHT'")
        save = _PS.index('Save-Checked-Image $Source $Report',check)
        final = _PS.index("Step 'REGISTRY_SUCCESSOR_FINAL_PREFLIGHT'")
        stop = _PS.index("Write-ReleaseTiming 'APPLY_STOP_REQUEST'",final)
        self.assertIn('Read-RegistrySuccessorDelivery $SourceForOwnerShell',_PS[check:save])
        self.assertIn('Read-RegistrySuccessorDelivery $Source',_PS[final:stop])
        self.assertIn('Same-Json $FinalDelivery $script:RegistryDelivery',_PS[final:stop])
        self.assertGreater(_PS.index('$SourceStopAttempted=$true',stop),stop)
        self.assertIn('(-not $script:RegistryDelivery -or $SourceStopAttempted)',_PS[stop:])
        clone = _PS.index("Step 'CLONE_STATE'",stop)
        start = _PS.index("Step 'CREATE_STAGED'",clone)
        self.assertIn('Initialize-StagedRegistryCollector $Runtime',_PS[clone:start])
        self.assertIn("prepare_staged_companion('/state/private/approvals.sqlite'",_PS)

    def test_shared_pid_host_pid_or_other_privileged_access_still_denied(self):
        for field,value in (('PidMode','container:another'),('PidMode','host'),
                            ('UsernsMode','host'),('Privileged',True),
                            ('CapAdd',['SYS_ADMIN'])):
            self.setUp();self.activate()
            self.container['HostConfig'][field]=value
            with self.subTest(field=field),self.assertRaises(RuntimeError):
                helper.admit(self.container,self.expected,pilot=True)

    def test_controller_requires_explicit_exact_check_apply_and_nonce(self):
        self.assertIn('[switch]$EnableRegistryMount',_PS)
        self.assertIn("[string]$RegistryReleaseNonce=''",_PS)
        self.assertIn('RELEASE_REGISTRY_REQUIRES_OWNER_CHECKED_IMAGE_AND_NONCE',_PS)
        self.assertIn('RELEASE_REGISTRY_NONCE_WITHOUT_EXPLICIT_ACTIVATION',_PS)
        self.assertIn("$Action -cnotin @('Check','Apply')",_PS)
        self.assertIn("($Action -eq 'Check' -and -not $Build)",_PS)
        self.assertIn("($Action -eq 'Apply' -and (-not $CheckedImageRecord -or $Build))",_PS)
        self.assertIn('$EnableRegistryMount -or $RegistryReleaseNonce',_PS)
        self.assertIn('RELEASE_REGISTRY_MOUNT_DOWNGRADE_REQUIRES_OWNER_REVIEW',_PS)
        self.assertIn('RELEASE_REGISTRY_NONCE_REUSE_DENIED',_PS)
        self.assertIn('RELEASE_REGISTRY_PROVIDER_AND_OWNER_MOUNT_MISMATCH',_PS)

    def test_corrective_apply_reuses_checked_attempt_and_owner_go(self):
        self.assertIn('[switch]$Corrective288',_PS)
        self.assertIn("($Action -ceq 'Apply' -and $CheckedImageRecord)",_PS)
        self.assertIn('APPLY CORRECTIVE T4 288',_PS)
        apply=_PS.split("Step 'PREPARED_RECORD_SAVED'",1)[1]
        ordered=("APPLY CORRECTIVE T4 288","Verify-Checked-Image $Source $Report",
                 "Write-Private $AttemptPointer","STOP_SOURCE",
                 "Switch-CorrectiveRegistryPair","Step 'CLONE_STATE'")
        # STOP_SOURCE is the preflight label, not a Docker effect. Check
        # actual stop is after the protected attempt pointer.
        for marker in ordered:
            self.assertIn(marker,apply)
        self.assertLess(apply.index("Write-Private $AttemptPointer"),
                        apply.index("Docker-Text @('stop','--timeout','20',$Old.Id)"))
        self.assertLess(apply.index("Assert-Checked-Source-Receipt $script:R.sourceReceipt"),
                        apply.index("Switch-CorrectiveRegistryPair"))
        self.assertLess(apply.index("Switch-CorrectiveRegistryPair"),apply.index("Step 'CLONE_STATE'"))

    def test_check_binding_exact_profile_digest_and_nonce_in_runtime(self):
        checked=_PS.split('\nfunction Checked-Image-Binding {',1)[1].split(
            'function Save-Checked-Image {',1)[0]
        for name in ('registryReaderVolume','registrySocketVolume',
                     'registryReleaseNonce','registryProfileDigest',
                     'enableRegistryMount'):
            self.assertIn(name+'=$script:',checked) if name!='enableRegistryMount' else \
                self.assertIn('enableRegistryMount=[bool]$EnableRegistryMount',checked)
        prepare=_PS.split("$Nonce=$(if($EnableRegistryMount)",1)[1].split(
            "if($EnableActionCoreNetwork)",1)[0]
        self.assertIn('$RegistryReleaseNonce}',prepare)
        self.assertIn('registryReaderVolume=$script:RegistryReaderVolume',prepare)
        self.assertIn('registrySocketVolume=$script:RegistrySocketVolume',prepare)
        self.assertIn('registryProfileDigest=$script:RegistryProfileDigest',prepare)
        self.assertIn('registryReleaseNonce=$script:RegistryBoundReleaseNonce',prepare)
        self.assertIn('Checked-Image-Binding $Source $Report',_PS)
        self.assertIn('Assert-Checked-Image-Binding $Record.binding $Expected',_PS)

    def test_preflight_no_docker_pull_network_secret_or_implicit_seal(self):
        part=_PS.split('function Image-RegistryMount-Preflight {',1)[1].split(
            'function Initialize-StagedRegistryCollector {',1)[0]
        self.assertIn("'run','--rm','-i','--pull=never','--network','none','--read-only'",part)
        self.assertIn("'--user','10001:10001','--cap-drop','ALL'",part)
        self.assertIn('reviewed_registry_reader_mount_digest',part)
        self.assertIn('_installed_policy_source_digest',part)
        self.assertIn('expected_release_nonce=nonce',part)
        self.assertIn('Assert-Volume $ReaderVolume',part)
        self.assertIn("Assert-Volume 'fortis-registry-read'",part)
        self.assertIn('Assert-OnlyWriter $ReaderVolume',part)
        self.assertIn('target=/run/r7-registry-reader,readonly',part)
        self.assertIn('target=/run/fortis-registry-read,readonly',part)
        self.assertIn('$Result=Private-Process $Args $ReleaseNonce',part)
        self.assertNotIn("'--cap-add'",part)
        self.assertNotIn("volume','create'",part)

    def test_registry_prebuilt_check_and_staged_clone_initialization(self):
        self.assertIn('$script:RegistryPrebuiltCheck=',_PS)
        self.assertIn("if($CheckedImageRecord -or $script:RegistryPrebuiltCheck)",_PS)
        self.assertIn('if($Build -or $script:RegistryPrebuiltCheck){',_PS)
        part=_PS.split('function Initialize-StagedRegistryCollector {',1)[1].split(
            'function Get-SourceRecord {',1)[0]
        self.assertIn('prepare_staged_functional_state',part)
        self.assertIn('Assert-OnlyWriter $Runtime.stateVolume',part)
        self.assertIn('target=/state,volume-nocopy',part)
        self.assertIn('target=/run/r7-registry-reader,readonly',part)
        self.assertNotIn("'--cap-add'",part)
        clone=_PS.split("Step 'CLONE_STATE'",1)[1].split("Step 'CREATE_STAGED'",1)[0]
        self.assertIn('Initialize-StagedRegistryCollector $Runtime',clone)
        self.assertIn('RELEASE_STATE_CLONE_MISMATCH',clone)
        self.assertIn('Assert-SourceUnchanged',clone)

    def test_accepted_source_and_new_candidate_exact_recheck(self):
        admission=_PS.split('\nfunction Admit {',1)[1].split('\nfunction Admit-Source {',1)[0]
        self.assertIn('Read-RegistryMountBinding $P',admission)
        self.assertIn('$Expected.registryReaderVolume=$RegistryProtected.readerVolume',admission)
        self.assertIn('$Expected.registrySocketVolume=$RegistryProtected.socketVolume',admission)
        self.assertIn('$Expected.registryReleaseNonce=$RegistryProtected.releaseNonce',admission)
        self.assertIn('Image-RegistryMount-Preflight -ImageId $MountImage',admission)
        self.assertIn('RELEASE_REGISTRY_PROFILE_OR_PEER_CHANGED',admission)
        self.assertIn('RELEASE_REGISTRY_RUNTIME_NONCE_MISMATCH',admission)
        create=_PS.split("Step 'CREATE_STAGED'",1)[1].split(
            "$script:R.runtime.pilotId=Docker-Text $Arguments",1)[0]
        self.assertIn('if($Runtime.registryReaderVolume)',create)
        self.assertIn('target=/run/r7-registry-reader,readonly',create)
        self.assertIn('target=/run/fortis-registry-read,readonly',create)
        self.assertNotIn("'--pid'",create)
        self.assertNotIn("'--privileged'",create)

    def test_owner_preseal_digest_is_image_only_and_checked_again(self):
        self.assertIn("'RegistrySourceDigest'", _PS.splitlines()[3])
        digest=_PS.split('function Image-Registry-Source-Digest {',1)[1].split(
            'function Image-RegistryMount-Preflight {',1)[0]
        self.assertIn('_installed_policy_source_digest',digest)
        for guard in ("'--pull=never'", "'--network','none'", "'--read-only'",
                      "'--user','10001:10001'", "'--cap-drop','ALL'",
                      "'no-new-privileges:true'"):
            self.assertIn(guard,digest)
        for forbidden in ('--mount','vault','--env-file','volume create'):
            self.assertNotIn(forbidden,digest)
        self.assertIn("$Action -eq 'RegistrySourceDigest'",_PS)
        self.assertIn("throw 'RELEASE_REGISTRY_DIGEST_ARGUMENTS_INVALID'",_PS)
        self.assertIn("imageId=$script:Image;gatewaySourceDigest=$Digest",_PS)
        self.assertIn("$RegistryExpectedSourceDigest -cnotmatch '^[0-9a-f]{64}$'",_PS)
        self.assertIn("$script:RegistryGatewaySourceDigest -cne $RegistryExpectedSourceDigest",_PS)
        self.assertIn('registryGatewaySourceDigest=$script:RegistryGatewaySourceDigest',_PS)
        self.assertIn("throw 'RELEASE_REGISTRY_SOURCE_DIGEST_MISMATCH'",_PS)
        self.assertIn("$ImageInfo.Config.Labels.'org.opencontainers.image.revision' -cne $SourceSha",_PS)

    def test_nonce_binding_never_overwrites_script_parameter(self):
        self.assertNotIn('$script:RegistryReleaseNonce', _PS)
        self.assertIn('Initialize-RegistryReleaseBinding -Enabled ([bool]$EnableRegistryMount) -RequestedNonce $RegistryReleaseNonce', _PS)
        self.assertIn('FORTIS_REGISTRY_NONCE_SCOPE_SELFTEST_PASS', _PS)
        helper = _PS.split('function Initialize-RegistryReleaseBinding {', 1)[1].split('function Assert-Registry-HistoryRecord {', 1)[0]
        self.assertIn('$script:RegistryBoundReleaseNonce=$RequestedNonce', helper)

    def test_nonce_history_and_pre_stop_return_gate(self):
        history=_PS.split('function Assert-Registry-Nonce-Fresh {',1)[1].split(
            'function Image-Registry-Source-Digest {',1)[0]
        self.assertIn('Assert-DirectoryAcl $ReleaseBase',history)
        self.assertIn('Get-ChildItem -LiteralPath $ReleaseBase -Directory -Force',history)
        self.assertIn('Read-Private $RecordPath',history)
        self.assertIn('AllowedCheckRecord',history)
        self.assertIn('RELEASE_REGISTRY_HISTORY_RECORD_MISSING',history)
        self.assertIn('RELEASE_REGISTRY_HISTORY_REPARSE_DENIED',history)
        self.assertIn('Test-Path -LiteralPath $RecordPath -PathType Leaf',history)
        self.assertIn('Assert-Registry-HistoryRecord -Record $Record',history)
        self.assertNotIn("if(-not (Test-Path -LiteralPath $RecordPath)){continue}",history)
        validator=_PS.split('function Assert-Registry-HistoryRecord {',1)[1].split(
            'function Assert-Registry-Nonce-Fresh {',1)[0]
        self.assertIn("RELEASE_REGISTRY_NONCE_REUSE_DENIED",validator)
        self.assertIn("RELEASE_REGISTRY_HISTORY_RECORD_INVALID",validator)
        self.assertIn("$Schema -ceq 'fortis-extension-image-check-v1'",validator)
        self.assertIn("$Schema -ceq 'fortis-extension-release-v1'",validator)
        self.assertIn("$Record.PSObject.Properties['schema']",validator)
        self.assertIn("$Record.PSObject.Properties['binding']",validator)
        self.assertIn("$Record.PSObject.Properties['runtime']",validator)
        self.assertIn(".PSObject.Properties['registryReleaseNonce']",validator)
        self.assertNotIn('$Record.runtime.registryReleaseNonce',validator)
        self.assertNotIn('$Record.binding.registryReleaseNonce',validator)
        self.assertIn("AllowOriginalCheck",validator)
        self.assertIn("function Assert-Registry-HistoryRecord",_PS)
        self.assertIn("RELEASE_REGISTRY_NONCE_HISTORY_SELFTEST_FAILED",_PS)
        self.assertIn('Assert-Registry-Nonce-Fresh -Nonce $RegistryReleaseNonce',_PS)
        rollback=_PS.split('function Return-Source {',1)[1].split(
            'function Complete-ActionCoreNetwork {',1)[0]
        pre=rollback.index('Admit $Original $script:R.source.runtime')
        stop=rollback.index("Docker-Text @('stop','--timeout','20',$C.Id)")
        self.assertLess(pre,stop)
        self.assertLess(rollback.index('Assert-SourceUnchanged'),stop)
        self.assertIn('Admit $Old $script:R.source.runtime',rollback[stop:])

    def test_protected_runtime_record_validator_rejects_bad_source(self):
        validator=_PS.split('function Read-RegistryMountBinding {',1)[1].split(
            'function Image-RegistryMount-Preflight {',1)[0]
        self.assertIn("$Volume -cne ('fortis-r7-registry-reader-'+$Nonce.Replace('-',''))",validator)
        self.assertIn("$Socket -cne 'fortis-registry-read'",validator)
        self.assertIn("$Digest -cnotmatch '^[0-9a-f]{64}$'",validator)
        self.assertIn("throw 'RELEASE_REGISTRY_RECORD_INVALID'",validator)
        self.assertIn("$RegistryPrior=Read-RegistryMountBinding $SourceForOwnerShell.runtime",_PS)


if __name__=='__main__': unittest.main()

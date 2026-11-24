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

    def test_check_binding_exact_profile_digest_and_nonce_in_runtime(self):
        checked=_PS.split('function Checked-Image-Binding {',1)[1].split(
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
        admission=_PS.split('function Admit {',1)[1].split('function Admit-Source {',1)[0]
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

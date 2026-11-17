"""P3.4 owner-checked publisher mount: offline release and runtime admission.

Windows PowerShell 5.1 parser, SelfTest and real Docker checks remain
owner-only; source tests do not claim host Docker isolation.
"""
import json
import os
from pathlib import Path
import tempfile
import unittest

from fortis_approvals.integrations.github.publisher_mount_digest import reviewed_mount_digest

ROOT = Path(__file__).resolve().parents[2]
PS = (ROOT / 'fortis_approvals/deploy/Manage-Integrations.ps1').read_text()
HELPER_SOURCE = (ROOT / 'fortis_approvals/deploy/github_pilot_helpers.py').read_text()

CONFIG = dict(schemaVersion=1, enabled=True,
              actor='release-label-publisher-v1',repository='fortis-approvals',
              revision='d'*64,validatorRevision='a'*40,registryDelegation=True)
GRANT = 'SYNTHETIC_PUBLISHER_MACHINE_GRANT_FOR_OFFLINE_TEST_0001'
VOLUME = 'fortis-r7-publisher-activation'


class OwnerVolumeDigestTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / 'owned'
        self.root.mkdir(mode=0o700)
        self.profile = self.root / 'profile.json'
        self.grant = self.root / 'grant'
        self.profile.write_text(json.dumps(CONFIG))
        self.grant.write_text(GRANT+'\n')
        self.profile.chmod(0o600)
        self.grant.chmod(0o600)

    def test_digest_is_stable_and_does_not_contain_secret(self):
        first=reviewed_mount_digest(self.root)
        self.assertRegex(first,r'^[0-9a-f]{64}$')
        self.assertEqual(first,reviewed_mount_digest(self.root))
        self.assertNotIn(GRANT, first)

    def test_even_same_semantic_profile_bytes_are_bound(self):
        first=reviewed_mount_digest(self.root)
        self.profile.write_text(json.dumps(CONFIG,indent=2))
        self.assertNotEqual(first,reviewed_mount_digest(self.root))

    def test_grant_rotation_changes_digest(self):
        first=reviewed_mount_digest(self.root)
        self.grant.write_text('SYNTHETIC_PUBLISHER_MACHINE_GRANT_FOR_OFFLINE_TEST_0002\n')
        self.assertNotEqual(first,reviewed_mount_digest(self.root))

    def test_mount_denies_missing_invalid_or_public_files(self):
        self.grant.unlink()
        with self.assertRaises(RuntimeError):reviewed_mount_digest(self.root)
        self.grant.write_text(GRANT+'\n')
        self.grant.chmod(0o644)
        with self.assertRaises(RuntimeError):reviewed_mount_digest(self.root)
        self.grant.chmod(0o600)
        (self.root/'extra').write_text('not allowed')
        with self.assertRaises(RuntimeError):reviewed_mount_digest(self.root)

    def test_mount_denies_symlink_replacement(self):
        self.grant.unlink()
        self.grant.symlink_to(self.profile)
        with self.assertRaises(RuntimeError):reviewed_mount_digest(self.root)

    def test_absent_mount_is_not_an_activation(self):
        with self.assertRaisesRegex(RuntimeError,'ACTIVATION_VOLUME_EMPTY'):
            reviewed_mount_digest(self.root/'absent')


class DockerAdmissionTests(unittest.TestCase):
    def fixture(self):
        import test_github_pilot_package as pilot
        return pilot.AdmissionTests().fixture(),pilot.HELPERS

    def test_default_disabled_and_exact_readonly_mount(self):
        (container,expected), helpers=self.fixture()
        self.assertEqual(helpers.admit(container,expected,pilot=True),{'admission':'PASS'})
        expected['publisherActivationVolume']=VOLUME
        with self.assertRaisesRegex(RuntimeError,'MOUNT_CONFIGURATION_MISMATCH'):
            helpers.admit(container,expected,pilot=True)
        volume=dict(Type='volume',Name=VOLUME,
                    Destination='/run/r7-publisher-activation',RW=False,
                    Source='/var/lib/docker/volumes/'+VOLUME+'/_data')
        container['Mounts'].append(volume)
        self.assertEqual(helpers.admit(container,expected,pilot=True),{'admission':'PASS'})
        expected['publisherActivationVolume']=''
        with self.assertRaisesRegex(RuntimeError,'MOUNT_CONFIGURATION_MISMATCH'):
            helpers.admit(container,expected,pilot=True)

    def test_wrong_volume_host_access_or_rw_denied(self):
        (container,expected), helpers=self.fixture()
        expected['publisherActivationVolume']=VOLUME
        v=dict(Type='volume',Name=VOLUME,Destination='/run/r7-publisher-activation',
               RW=False,Source='/var/lib/docker/volumes/'+VOLUME+'/_data')
        container['Mounts'].append(v)
        self.assertEqual(helpers.admit(container,expected,pilot=True),{'admission':'PASS'})
        for field,wrong in (('RW',True),('Name','other-volume'),
                            ('Source','/tmp/fortis-publisher'),
                            ('Destination','/run/r7-identity')):
            with self.subTest(field=field):
                original=v[field];v[field]=wrong
                with self.assertRaises(RuntimeError):
                    helpers.admit(container,expected,pilot=True)
                v[field]=original
        expected['publisherActivationVolume']='fortis-r7-publisher-activation-evil'
        with self.assertRaisesRegex(RuntimeError,'PUBLISHER_VOLUME_INVALID'):
            helpers.admit(container,expected,pilot=True)

    def test_wrong_expected_type_or_unreviewed_alias_denied(self):
        (container,expected), helpers=self.fixture()
        for value in (None,True,3,'/run/r7-publisher-activation','../../secrets','fortis-review-secrets'):
            with self.subTest(value=value):
                expected['publisherActivationVolume']=value
                with self.assertRaisesRegex(RuntimeError,'PUBLISHER_VOLUME_INVALID'):
                    helpers.admit(container,expected,pilot=True)


class CheckedReleaseSourceTests(unittest.TestCase):
    def test_explicit_manual_owner_opt_in_only(self):
        self.assertIn('[switch]$EnablePublisherMount',PS)
        self.assertIn('RELEASE_PUBLISHER_REQUIRES_EXACT_OWNER_CHECKED_IMAGE',PS)
        self.assertIn('$Action -cnotin @(',PS)
        self.assertIn("-not $ConfirmWorkerQuiescent",PS)
        self.assertIn("$Action -eq 'Check' -and -not $Build",PS)
        self.assertIn("$Action -eq 'Apply' -and (-not $CheckedImageRecord -or $Build)",PS)
        self.assertIn("$VaultVolume -cne 'fortis-review-secrets' -or $EnablePublisherMount",PS)
        self.assertIn("$SourceSha -cnotmatch '^[0-9a-f]{40}$'",PS)

    def test_inherited_volume_and_digest_pinned_to_protected_records(self):
        self.assertIn('Read-PublisherActivationVolume $SourceForOwnerShell.runtime',PS)
        self.assertIn('Read-PublisherActivationDigest $SourceForOwnerShell.runtime',PS)
        self.assertIn('publisherActivationVolume=$script:PublisherActivationVolume',PS)
        self.assertIn('publisherActivationDigest=$script:PublisherActivationDigest',PS)
        self.assertIn('publisherActivationVolume=(Read-PublisherActivationVolume $P)',PS)
        self.assertIn('$script:PublisherActivationDigest -cne $PreviousPublisherDigest',PS)
        self.assertIn('RELEASE_PUBLISHER_SOURCE_MATERIAL_CHANGED',PS)
        self.assertIn('RELEASE_PUBLISHER_VOLUME_CONTENT_CHANGED',PS)
        self.assertIn('RELEASE_CHECKED_IMAGE_BINDING_CHANGED',PS)

    def test_offline_credential_material_preflight_and_final_mount_order(self):
        self.assertIn("Assert-Volume $Name",PS)
        self.assertIn("Assert-OnlyWriter $Name",PS)
        preflight=PS.split('function Image-PublisherMount-Preflight {',1)[1].split('function Get-SourceRecord {',1)[0]
        self.assertIn("'--network','none','--read-only'",preflight)
        self.assertIn("'--user','10001:10001','--cap-drop','ALL'",preflight)
        self.assertIn('publisher_mount_digest import reviewed_mount_digest',preflight)
        self.assertIn('target=/run/r7-publisher-activation,readonly',preflight)
        self.assertIn("'--entrypoint','python',$ImageId",preflight)
        create=PS.split("Step 'CREATE_STAGED'",1)[1].split("$script:R.runtime.pilotId=Docker-Text $Arguments",1)[0]
        self.assertIn("if($Runtime.publisherActivationVolume)",create)
        self.assertIn('target=/run/r7-publisher-activation,readonly',create)
        self.assertIn('$Arguments+=@($script:Image)',create)
        self.assertLess(create.index("target=/run/r7-publisher-activation,readonly"),create.index('$Arguments+=@($script:Image)'))
        self.assertNotIn('docker cp',create)

    def test_no_new_credential_embedding_or_environment_toggle(self):
        self.assertNotIn('FORTIS_PUBLISHER_GRANT=',PS)
        self.assertNotIn('FORTIS_PUBLISHER_ENABLED=',PS)
        self.assertNotIn("volume','create','fortis-r7-publisher-activation'",PS)
        self.assertIn("publisher_volume = expected.get('publisherActivationVolume', '')",HELPER_SOURCE)


if __name__=='__main__':
    unittest.main()

"""P4 owner-only CD READ activation guard, never a live deployment.

Windows PowerShell 5.1 AST parse and controller SelfTest are mandatory in CI.
This Python suite tests container admission and source safety without Docker.
"""
from pathlib import Path
import unittest

from fortis_approvals.deploy import github_pilot_helpers as helpers
import test_github_pilot_package as pilot

ROOT=Path(__file__).resolve().parents[2]
SCRIPT=(ROOT/'fortis_approvals/deploy/Manage-Integrations.ps1').read_text()
HELPER=(ROOT/'fortis_approvals/deploy/github_pilot_helpers.py').read_text()
ENV='FORTIS_GITHUB_CD_READ_REPOSITORIES='


class P4CdOwnerSourceTests(unittest.TestCase):
    def test_owner_flag_requires_manual_checked_image_quiescence(self):
        self.assertIn("[string]$CdReadRepositories=''",SCRIPT)
        self.assertIn("RELEASE_CD_READ_REQUIRES_EXACT_OWNER_CHECKED_IMAGE",SCRIPT)
        guard=SCRIPT.split('if($CdReadRepositories -and ($Auto',1)[1].split(
            "throw 'RELEASE_CD_READ_REQUIRES_EXACT_OWNER_CHECKED_IMAGE'",1)[0]
        for marker in ("$Action -cnotin @('Check','Apply')",
                       "$SourceSha -cnotmatch '^[0-9a-f]{40}$'",
                       '$CurrentRecord', '$AttemptRecord', '-not $ConfirmWorkerQuiescent',
                       "$Action -eq 'Check' -and -not $Build",
                       "$Action -eq 'Apply' -and (-not $CheckedImageRecord -or $Build)"):
            self.assertIn(marker,guard)
        auto=SCRIPT.split('if($Auto){',1)[1].split("RELEASE_AUTO_MANUAL_ARGUMENTS_DENIED",1)[0]
        self.assertIn('$CdReadRepositories',auto)
        self.assertIn('-or $CdReadRepositories -or $PreserveUncertainRequests',SCRIPT)

    def test_protected_record_check_binding_and_env_projection(self):
        for marker in (
            'function Read-CdReadRepositories {',
            "if($null -eq $Record){throw 'RELEASE_CD_READ_RECORD_INVALID'}",
            "if($Value -isnot [string]){throw 'RELEASE_CD_READ_RECORD_INVALID'}",
            'cdReadRepositories=$CdReadRepositories',
            'cdReadRepositories=(Read-CdReadRepositories $P)',
            'cdReadRepositories=$(if($CdReadRepositories){$CdReadRepositories}else{Read-CdReadRepositories $Source.runtime})',
            "-not $_.StartsWith('FORTIS_GITHUB_CD_READ_REPOSITORIES=')",
            "if($Runtime.cdReadRepositories){$EnvLines+='FORTIS_GITHUB_CD_READ_REPOSITORIES='+$Runtime.cdReadRepositories}",
            "RELEASE_CD_READ_RECORD_COMPATIBILITY_SELFTEST_FAILED",
            "RELEASE_CD_READ_RECORD_VALIDATION_SELFTEST_FAILED",
            "RELEASE_CD_READ_FLAG_FORWARDING_SELFTEST_FAILED",
        ):
            with self.subTest(marker=marker):
                self.assertIn(marker,SCRIPT)
        binding=SCRIPT.split('\nfunction Checked-Image-Binding',1)[1].split('function Save-Checked-Image',1)[0]
        self.assertIn('cdReadRepositories=$CdReadRepositories',binding)
        self.assertIn('PILOT_CD_READ_CONFIG_INVALID',HELPER)
        self.assertIn('PILOT_CD_READ_REQUIRES_NATIVE_SCOPE',HELPER)
        self.assertIn("required['FORTIS_GITHUB_CD_READ_REPOSITORIES']=cd_repos",HELPER)

    def test_source_never_automatically_executes_release(self):
        self.assertNotIn('docker run',SCRIPT.split('function Read-CdReadRepositories',1)[1].split(
            '# Optional Action Core network identity',1)[0])
        self.assertIn("RELEASE_AUTO_MANUAL_ARGUMENTS_DENIED",SCRIPT)
        self.assertIn("PRIMARY_PROMOTION_ARGUMENTS_INVALID",SCRIPT)
        self.assertIn("RELEASE_CD_READ_REPOSITORIES_INVALID",SCRIPT)
        self.assertIn("PILOT_PUBLIC_CONFIGURATION_MISMATCH",HELPER)


class P4CdAdmissionTests(unittest.TestCase):
    @staticmethod
    def fixture():
        return pilot.AdmissionTests().fixture()

    @staticmethod
    def native(container,expected):
        expected.update(
            filePrBranch='fortis-e2e/11111111-1111-4111-8111-111111111111-approve',
            ciReads=True,nativeWorktree=True,requiredWorkflows='408327525',
            bootstrapTask='source-bootstrap')
        container['Config']['Env'] += [
            'FORTIS_GITHUB_FILE_PR_BRANCH='+expected['filePrBranch'],
            'FORTIS_GITHUB_CI_READS=1','FORTIS_GITHUB_NATIVE_WORKTREE=1',
            'FORTIS_GITHUB_REQUIRED_WORKFLOWS=408327525',
            'FORTIS_GITHUB_BOOTSTRAP_TASK=source-bootstrap']

    def test_legacy_absent_scope_compatible_unexpected_env_denied(self):
        c,e=self.fixture()
        self.assertEqual(helpers.admit(c,e,pilot=True),{'admission':'PASS'})
        c['Config']['Env'].append(ENV+'sandbox')
        with self.assertRaisesRegex(RuntimeError,'PILOT_PUBLIC_CONFIGURATION_MISMATCH'):
            helpers.admit(c,e,pilot=True)
        c['Config']['Env'].pop()
        e['cdReadRepositories']='sandbox'
        with self.assertRaisesRegex(RuntimeError,'PILOT_CD_READ_REQUIRES_NATIVE_SCOPE'):
            helpers.admit(c,e,pilot=True)

    def test_native_scope_requires_exact_protected_env(self):
        c,e=self.fixture()
        self.native(c,e)
        self.assertEqual(helpers.admit(c,e,pilot=True),{'admission':'PASS'})
        e['cdReadRepositories']='sandbox'
        with self.assertRaisesRegex(RuntimeError,'PILOT_PUBLIC_CONFIGURATION_MISMATCH'):
            helpers.admit(c,e,pilot=True)
        c['Config']['Env'].append(ENV+'sandbox')
        self.assertEqual(helpers.admit(c,e,pilot=True),{'admission':'PASS'})
        c['Config']['Env'][-1]=ENV+'tunnel'
        with self.assertRaisesRegex(RuntimeError,'PILOT_PUBLIC_CONFIGURATION_MISMATCH'):
            helpers.admit(c,e,pilot=True)
        c['Config']['Env'][-1]=ENV+'sandbox'
        c['Config']['Env'].append(ENV+'sandbox')
        with self.assertRaisesRegex(RuntimeError,'PILOT_DUPLICATE_ENVIRONMENT'):
            helpers.admit(c,e,pilot=True)

    def test_repository_scope_cannot_expand_to_second_repo_in_single_mode(self):
        c,e=self.fixture()
        self.native(c,e)
        e['cdReadRepositories']='sandbox,rd-graphs'
        with self.assertRaisesRegex(RuntimeError,'PILOT_CD_READ_REQUIRES_NATIVE_SCOPE'):
            helpers.admit(c,e,pilot=True)
        e['dynamicRepositories']=True
        c['Config']['Env'].append('FORTIS_GITHUB_NATIVE_MULTI_REPO=1')
        c['Config']['Env'].append(ENV+'sandbox,rd-graphs')
        self.assertEqual(helpers.admit(c,e,pilot=True),{'admission':'PASS'})
        c['Config']['Env'][-1]=ENV+'rd-graphs,sandbox'
        with self.assertRaisesRegex(RuntimeError,'PILOT_PUBLIC_CONFIGURATION_MISMATCH'):
            helpers.admit(c,e,pilot=True)

    def test_invalid_protected_scope_denied_before_env(self):
        c,e=self.fixture()
        self.native(c,e)
        for value in (None,True,1,['sandbox'],'../secrets','sandbox/',
                      'sandbox,sandbox','sandbox,SANDBOX','sandbox,',
                      ',sandbox','sandbox,rd-graphs,','a'*101,
                      ','.join('r'+str(i) for i in range(11))):
            with self.subTest(value=value):
                e['cdReadRepositories']=value
                with self.assertRaisesRegex(RuntimeError,'PILOT_CD_READ_CONFIG_INVALID'):
                    helpers.admit(c,e,pilot=True)
        e.pop('cdReadRepositories')
        self.assertEqual(helpers.admit(c,e,pilot=True),{'admission':'PASS'})


if __name__=='__main__':
    unittest.main()

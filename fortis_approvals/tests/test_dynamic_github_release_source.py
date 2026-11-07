"""Source-level regression guards for the Windows owner release opt-in.

Windows PowerShell parser + -Action SelfTest are mandatory in GitHub CI; these
checks catch policy drift in the source before Windows owner execution.
"""
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[2]

class ReleaseOptInSourceTests(unittest.TestCase):
    def setUp(self):
        self.script=(ROOT/'fortis_approvals/deploy/Manage-Integrations.ps1').read_text()
        self.helper=(ROOT/'fortis_approvals/deploy/github_pilot_helpers.py').read_text()

    def test_explicit_opt_in_never_accepted_for_unpinned_image(self):
        self.assertIn('[switch]$EnableDynamicGitHubRepositories',self.script)
        self.assertIn('RELEASE_DYNAMIC_REPOSITORIES_REQUIRES_APPROVED_IMAGE_BUILD',self.script)
        self.assertIn('-not $Build',self.script)
        self.assertIn("$SourceSha -cnotmatch '^[0-9a-f]{40}$'",self.script)
        self.assertIn("$Action -cnotin @('Apply','Check')",self.script)

    def test_flag_is_derived_from_protected_record_and_not_inherited_unchecked(self):
        self.assertIn('dynamicRepositories=([bool]$Source.runtime.dynamicRepositories -or [bool]$EnableDynamicGitHubRepositories)',self.script)
        self.assertIn('dynamicRepositories=([bool]$P.dynamicRepositories)',self.script)
        self.assertIn("-not $_.StartsWith('FORTIS_GITHUB_NATIVE_MULTI_REPO=')",self.script)
        self.assertIn("if($Runtime.dynamicRepositories){$EnvLines+='FORTIS_GITHUB_NATIVE_MULTI_REPO=1'}",self.script)
        self.assertIn("if multi:required['FORTIS_GITHUB_NATIVE_MULTI_REPO']='1'",self.helper)

    def test_selftest_and_primary_promotion_are_separate(self):
        self.assertIn('RELEASE_DYNAMIC_FLAG_FORWARDING_SELFTEST_FAILED',self.script)
        self.assertIn('$Service -or $CredentialName -or $Probes -or $EnableDynamicGitHubRepositories',self.script)

if __name__=='__main__': unittest.main()

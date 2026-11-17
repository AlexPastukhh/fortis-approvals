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
        self.assertIn('dynamicRepositories=((Read-DynamicRepositoriesFlag $Source.runtime) -or [bool]$EnableDynamicGitHubRepositories)',self.script)
        self.assertIn('dynamicRepositories=(Read-DynamicRepositoriesFlag $P)',self.script)
        self.assertIn("-not $_.StartsWith('FORTIS_GITHUB_NATIVE_MULTI_REPO=')",self.script)
        self.assertIn("if($Runtime.dynamicRepositories){$EnvLines+='FORTIS_GITHUB_NATIVE_MULTI_REPO=1'}",self.script)
        self.assertIn("if multi:required['FORTIS_GITHUB_NATIVE_MULTI_REPO']='1'",self.helper)

    def test_ci_controls_are_optional_and_release_record_pinned(self):
        self.assertIn("[string]$CiControlRepositories=''",self.script)
        self.assertIn('RELEASE_CI_CONTROL_REQUIRES_APPROVED_IMAGE_BUILD',self.script)
        self.assertIn('ciControlRepositories=(Read-CiControlRepositories $P)',self.script)
        self.assertIn('ciControlRepositories=$(if($CiControlRepositories)',self.script)
        self.assertIn('FORTIS_GITHUB_CI_CONTROL_REPOSITORIES=',self.script)
        self.assertIn('PILOT_CI_CONTROL_CONFIG_INVALID',self.helper)
        self.assertIn('PILOT_CI_CONTROL_REQUIRES_NATIVE',self.helper)
        self.assertIn('RELEASE_CI_CONTROL_FLAG_FORWARDING_SELFTEST_FAILED',self.script)

    def test_uncertain_recovery_scope_is_explicit_retained_and_only_subset_later(self):
        script=self.script
        primary=(ROOT/'fortis_approvals/deploy/Primary-Gateway.ps1').read_text()
        self.assertIn("[string]$PreserveUncertainRequests=''",script)
        self.assertIn('RELEASE_UNCERTAIN_REQUIRES_APPROVED_SOURCE_BUILD',script)
        self.assertIn('RELEASE_UNCERTAIN_RECORD_SCOPE_CHANGED',script)
        self.assertIn('RELEASE_UNCERTAIN_SCOPE_INVALID',script)
        self.assertIn('RELEASE_UNCERTAIN_RECORD_SELFTEST_FAILED',script)
        self.assertIn('preserveUncertainRequests=$script:PreserveUncertainRequests',script)
        self.assertIn('preserveUncertainIds=$Ids;requireExactUncertain=([bool]$Exact)',script)
        self.assertIn('Receipt $Source.runtime.stateVolume -Exact:$script:PreserveUncertainExact',script)
        self.assertIn('$script:R.sourceReceipt=Receipt $Source.runtime.stateVolume -Exact:$script:PreserveUncertainExact -ExactClaimed:$script:PreserveClaimedExact -ExactApproved:$script:PreserveApprovedExact',script)
        self.assertIn('Save\n    # Close the final race:',script)
        self.assertIn('preserveUncertainIds=@(Effective-Uncertain-Ids)',script)
        self.assertIn('function Effective-Uncertain-Ids {',script)
        self.assertIn('preserveUncertainIds=@(Parse-PreservedUncertainRequests $script:PreserveUncertainRequests)',primary)
        self.assertIn('$script:PreserveUncertainRequests=$Stored',script)
        self.assertIn('$script:PreserveUncertainExact=$false',script)
        self.assertIn('if(-not $script:PreserveUncertainExact){',script)
        self.assertIn("-or $CiControlRepositories -or $PreserveUncertainRequests -or $PreserveClaimedJobs -or $PreserveApprovedRequest -or $CheckedImageRecord -or $AllowUncertainGrowth)",script)
        self.assertIn('PILOT_REVIEW_HAS_UNREVIEWED_UNCERTAIN',self.helper)
        self.assertIn('PILOT_REVIEW_UNCERTAIN_SET_CHANGED',self.helper)
        self.assertIn('PILOT_REVIEW_HAS_UNFINISHED_REQUESTS',self.helper)
        self.assertNotIn('UPDATE requests SET state',self.helper)

    def test_claimed_worker_carryover_is_exact_pinned_owner_attested_and_not_auto_terminalized(self):
        script=self.script
        primary=(ROOT/'fortis_approvals/deploy/Primary-Gateway.ps1').read_text()
        self.assertIn("[string]$PreserveClaimedJobs=''",script)
        self.assertIn('[switch]$ConfirmWorkerQuiescent',script)
        self.assertIn('RELEASE_CLAIMED_REQUIRES_OWNER_REVIEW_AND_QUIESCENCE',script)
        self.assertIn('RELEASE_CLAIMED_BACKUP_PROMOTE_REQUIRES_QUIESCENCE',script)
        self.assertIn('RELEASE_CLAIMED_RESUME_REQUIRES_QUIESCENCE',script)
        self.assertIn('RELEASE_CLAIMED_RECORD_SCOPE_CHANGED',script)
        self.assertIn('RELEASE_CLAIMED_RECORD_SELFTEST_FAILED',script)
        self.assertIn('preserveClaimedJobs=$script:PreserveClaimedJobs',script)
        self.assertIn('preserveClaimedIds=$Claims;requireExactClaimed=([bool]$ExactClaimed)',script)
        self.assertIn('preserveClaimedIds=@(Parse-PreservedUncertainRequests $script:PreserveClaimedJobs)',script)
        self.assertIn('preserveClaimedIds=@(Parse-PreservedUncertainRequests $script:PreserveClaimedJobs)',primary)
        self.assertIn('$script:PreserveClaimedJobs=$StoredClaimed',script)
        self.assertIn('$script:PreserveClaimedExact=$false',script)
        self.assertIn('PILOT_NATIVE_HAS_UNREVIEWED_CLAIMED_JOBS',self.helper)
        self.assertIn('PILOT_CLAIMED_APPROVAL_NOT_UNCERTAIN',self.helper)
        self.assertIn('PILOT_CLAIMED_JOB_RECORD_INVALID',self.helper)
        self.assertIn("get('operation')=='create_task'",self.helper)
        self.assertNotIn('UPDATE jobs SET state',self.helper)

    def test_selftest_and_primary_promotion_are_separate(self):
        self.assertIn('RELEASE_DYNAMIC_FLAG_FORWARDING_SELFTEST_FAILED',self.script)
        self.assertIn('RELEASE_DYNAMIC_RECORD_COMPATIBILITY_SELFTEST_FAILED',self.script)
        self.assertIn('RELEASE_DYNAMIC_RECORD_TYPE_SELFTEST_FAILED',self.script)
        self.assertIn('if($null -eq $Property){return $false}',self.script)
        self.assertIn("if($Value -isnot [bool]){throw 'RELEASE_DYNAMIC_RECORD_INVALID'}",self.script)
        self.assertIn('$Service -or $CredentialName -or $Probes -or $EnableDynamicGitHubRepositories',self.script)

if __name__=='__main__': unittest.main()

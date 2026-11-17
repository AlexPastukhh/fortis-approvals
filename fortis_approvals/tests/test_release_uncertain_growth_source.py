"""Owner-only source controls for monotone Core UNCERTAIN growth.

This proves the source structure on Linux, not PowerShell 5.1 execution,
Docker volumes, live quiescence, or an owner-approved release.
"""
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[2]
SCRIPT=(ROOT/'fortis_approvals/deploy/Manage-Integrations.ps1').read_text()
HELPER=(ROOT/'fortis_approvals/deploy/github_pilot_helpers.py').read_text()


class GrowthGuardSourceTests(unittest.TestCase):
    def test_explicit_owner_switch_only_on_sha_pinned_manual_check_apply(self):
        for marker in (
            '[switch]$AllowUncertainGrowth',
            'RELEASE_UNCERTAIN_GROWTH_REQUIRES_OWNER_CHECKED_IMAGE',
            'if($AllowUncertainGrowth -and ($Auto',
            '-not $ConfirmWorkerQuiescent',
            "($Action -eq 'Check' -and -not $Build)",
            "($Action -eq 'Apply' -and (-not $CheckedImageRecord -or $Build))",
            '$PreserveApprovedRequest -or $AllowUncertainGrowth -or',
            'RELEASE_GROWTH_FLAG_FORWARDING_SELFTEST_FAILED',
            'PRIMARY_PROMOTION_ARGUMENTS_INVALID'):
            with self.subTest(marker=marker):self.assertIn(marker,SCRIPT)

    def test_original_check_binding_and_witness_are_not_overwritten(self):
        self.assertIn('allowUncertainGrowth=[bool]$AllowUncertainGrowth',SCRIPT)
        self.assertIn('growthWitness=$script:GrowthWitness',SCRIPT)
        self.assertIn('original=$Checked.sourceReceipt;witness=$Checked.growthWitness',SCRIPT)
        self.assertIn('RELEASE_GROWTH_WITNESS_MISSING',SCRIPT)
        self.assertIn('Assert-Checked-Image-Binding $Record.binding $Expected',SCRIPT)
        self.assertNotIn('Write-Private $CheckedImageRecord',SCRIPT)
        self.assertIn('RELEASE_CHECKED_IMAGE_BINDING_CHANGED',SCRIPT)
        self.assertIn('RELEASE_CHECKED_IMAGE_SOURCE_STATE_CHANGED',SCRIPT)

    def test_check_uses_offline_witness_before_save(self):
        entry=SCRIPT.index("if($Action -eq 'Check'){",SCRIPT.index("if($CheckedImageRecord){Verify-Checked-Image $SourceForOwnerShell $Report}"))
        snapshot=SCRIPT.index('Snapshot-Uncertain-Growth $Source.runtime.stateVolume',entry)
        witnessed=SCRIPT.index('$script:GrowthWitness=$GrowthSnapshot.witness',snapshot)
        save=SCRIPT.index('Save-Checked-Image $Source $Report $CheckReceipt',witnessed)
        self.assertLess(entry,snapshot)
        self.assertLess(snapshot,witnessed)
        self.assertLess(witnessed,save)

    def test_apply_rechecks_growth_and_freezes_actual_ids_after_source_stop(self):
        scope=SCRIPT.index('function Receipt {')
        self.assertIn('Review-Uncertain-Growth $Volume',SCRIPT[scope:scope+750])
        self.assertIn('preserveUncertainIds=$Ids',SCRIPT[scope:scope+900])
        self.assertIn('Effective-Uncertain-Ids',SCRIPT[scope:scope+900])
        stop=SCRIPT.index("Docker-Text @('stop','--timeout','20',$Old.Id)",SCRIPT.index("Step 'STOP_SOURCE'"))
        frozen=SCRIPT.index('$script:R.runtime.preserveUncertainRequests=$script:GrowthEffectiveUncertainRequests',stop)
        saved=SCRIPT.index('    Save'+chr(10),frozen)
        cloned=SCRIPT.index("Step 'CLONE_STATE'",saved)
        self.assertLess(stop,frozen)
        self.assertLess(frozen,saved)
        self.assertLess(saved,cloned)
        self.assertIn('preserveUncertainIds=@(Effective-Uncertain-Ids)',SCRIPT[cloned:cloned+500])
        self.assertIn('RELEASE_GROWTH_SOURCE_STATE_CHANGED',SCRIPT)

    def test_approved_claimed_and_native_gate_still_strict(self):
        for marker in ('preserveApprovedIds=@(Approved-Ids)',
                       'requireExactApproved=([bool]$script:PreserveApprovedExact)',
                       'preserveClaimedIds=@(Parse-PreservedUncertainRequests $script:PreserveClaimedJobs)',
                       'requireExactClaimed=([bool]$script:PreserveClaimedExact)',
                       'RELEASE_APPROVED_REQUIRES_EXACT_OWNER_BUILD_AND_QUIESCENCE',
                       'RELEASE_CLAIMED_REQUIRES_OWNER_REVIEW_AND_QUIESCENCE',
                       'Assert-Previous-Image-Retained $Source'):
            with self.subTest(marker=marker):self.assertIn(marker,SCRIPT)
        for marker in ('PILOT_GROWTH_CORE_PREFIX_CHANGED',
                       'PILOT_GROWTH_OTHER_STATE_CHANGED',
                       'PILOT_GROWTH_NEW_REQUEST_NOT_UNCERTAIN',
                       'PILOT_GROWTH_NEW_AUDIT_INVALID',
                       'PILOT_GROWTH_REQUIRES_FULL_STATE',
                       "len(ids)<=20",
                       "require_exact_approved=require_exact_approved",
                       "require_exact_claimed=require_exact_claimed"):
            with self.subTest(marker=marker):self.assertIn(marker,HELPER)

    def test_default_nonoptin_remains_exact(self):
        self.assertIn('} elseif(-not (Same-Json $Record.sourceReceipt $Now))',SCRIPT)
        self.assertIn('} elseif(-not (Same-Json $Stored.sourceReceipt $Receipt))',SCRIPT)
        self.assertIn('require(unresolved <= permitted',HELPER)
        self.assertIn("require(unresolved == permitted,'PILOT_REVIEW_UNCERTAIN_SET_CHANGED')",HELPER)


if __name__=='__main__':
    unittest.main()

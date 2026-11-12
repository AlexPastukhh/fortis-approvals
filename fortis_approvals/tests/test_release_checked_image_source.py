"""Source regression gates for Check-once / pinned-image Apply.

These Linux tests do not execute Windows PowerShell or change Docker. The
PowerShell 5.1 parser and actual -Action SelfTest remain mandatory in CI.
"""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = (ROOT / "fortis_approvals/deploy/Manage-Integrations.ps1").read_text()
PRIMARY = (ROOT / "fortis_approvals/deploy/Primary-Gateway.ps1").read_text()


class CheckedImageSourceTests(unittest.TestCase):
    def test_new_pinned_path_requires_approved_check_receipt_and_sha(self):
        self.assertIn("[string]$CheckedImageRecord=''", SCRIPT)
        self.assertIn("RELEASE_CHECKED_IMAGE_APPLY_ARGUMENTS_INVALID", SCRIPT)
        self.assertIn("$Action -cne 'Apply' -or $Build -or $Pull", SCRIPT)
        self.assertIn("$Image -cnotmatch '^sha256:[0-9a-f]{64}$'", SCRIPT)
        self.assertIn("$SourceSha -cnotmatch '^[0-9a-f]{40}$'", SCRIPT)
        self.assertIn("$ApprovedImageSource=($Build -or [bool]$CheckedImageRecord)", SCRIPT)
        self.assertIn("$Action -cnotin @('Apply','Check') -or -not $ApprovedImageSource", SCRIPT)

    def test_bare_image_does_not_bypass_preservation_guards(self):
        for marker in (
            "RELEASE_UNCERTAIN_REQUIRES_APPROVED_SOURCE_BUILD",
            "RELEASE_CLAIMED_REQUIRES_OWNER_REVIEW_AND_QUIESCENCE",
            "RELEASE_APPROVED_REQUIRES_EXACT_OWNER_BUILD_AND_QUIESCENCE",
            "RELEASE_OWNER_SHELL_REQUIRES_APPROVED_IMAGE_BUILD",
            "RELEASE_DYNAMIC_REPOSITORIES_REQUIRES_APPROVED_IMAGE_BUILD",
            "RELEASE_CI_CONTROL_REQUIRES_APPROVED_IMAGE_BUILD",
        ):
            self.assertIn(marker, SCRIPT)
        self.assertGreaterEqual(SCRIPT.count("-not $ApprovedImageSource"), 6)
        self.assertIn("-not $ConfirmWorkerQuiescent", SCRIPT)
        self.assertIn("RELEASE_CLAIMED_BACKUP_PROMOTE_REQUIRES_QUIESCENCE", SCRIPT)
        self.assertIn("RELEASE_APPROVED_BACKUP_PROMOTE_REQUIRES_QUIESCENCE", SCRIPT)

    def test_check_writes_protected_record_only_after_ready_and_state_read(self):
        ready = SCRIPT.index("if($Report.status -cne 'READY')")
        check = SCRIPT.index("if($Action -eq 'Check'){", ready)
        state = SCRIPT.index("SOURCE_STATE_PREFLIGHT_READ_ONLY", check)
        save = SCRIPT.index("Save-Checked-Image $Source $Report $CheckReceipt", check)
        finish = SCRIPT.index("$Report|ConvertTo-Json -Depth 12;return", check)
        self.assertLess(ready, check)
        self.assertLess(state, save)
        self.assertLess(save, finish)
        self.assertIn("$Path=Join-Path $Directory 'record.json'", SCRIPT)
        self.assertIn("Protect-Directory $Directory", SCRIPT)
        self.assertIn("Write-Private $Path ([ordered]@", SCRIPT)
        self.assertIn("checkedImageId", SCRIPT)
        self.assertIn("checkedImageRecord", SCRIPT)

    def test_record_binds_exact_image_inputs_source_and_state(self):
        for marker in (
            "schema='fortis-extension-image-check-v1'",
            "sourceReceipt=$Receipt",
            "image=$script:Image;sourceSha=$SourceSha",
            "sourceRecord=$Source.path;sourceHash=$Source.hash",
            "sourceContainerId=$Source.runtime.pilotId",
            "sourceImage=$Source.runtime.image",
            "sourceStateVolume=$Source.runtime.stateVolume",
            "sourceRunId=$Source.runtime.runId",
            "currentPointerHash=$CurrentHash;primaryPointerHash=$PrimaryHash",
            "publicConfigHash=$ConfigHash;probeHash=$ProbeHash",
            "configurationDigest=$Report.configurationDigest",
            "vaultVolume=$VaultVolume",
            "enableOwnerShell=[bool]$EnableOwnerShell",
            "enableDynamicGitHubRepositories=[bool]$EnableDynamicGitHubRepositories",
            "ciControlRepositories=$CiControlRepositories",
            "preserveUncertainRequests=$script:PreserveUncertainRequests",
            "preserveClaimedJobs=$script:PreserveClaimedJobs",
            "preserveApprovedRequest=$script:PreserveApprovedRequest",
            "requireExactApproved=$script:PreserveApprovedExact",
            "confirmWorkerQuiescent=[bool]$ConfirmWorkerQuiescent",
        ):
            with self.subTest(marker=marker):
                self.assertIn(marker, SCRIPT)

    def test_apply_verifies_protected_binding_and_fresh_state(self):
        for marker in (
            "$Record=Read-Private $CheckedImageRecord",
            "RELEASE_CHECKED_IMAGE_RECORD_INVALID",
            "Assert-Checked-Image-Binding $Record.binding $Expected",
            "RELEASE_CHECKED_IMAGE_BINDING_CHANGED",
            "RELEASE_CHECKED_IMAGE_SOURCE_STATE_CHANGED",
            "Receipt $Source.runtime.stateVolume -Exact:$script:PreserveUncertainExact",
            "RELEASE_WINDOWS_SOURCE_DIRTY",
            "RELEASE_WINDOWS_MAIN_REQUIRED",
            "RELEASE_WINDOWS_SHA_MISMATCH",
            "RELEASE_CHECKED_IMAGE_CREDENTIAL_CHANGED",
            "Verify-Checked-Image $SourceForOwnerShell $Report",
            "if($CheckedImageRecord){Verify-Checked-Image $Source $Report}",
        ):
            self.assertIn(marker, SCRIPT)

    def test_previous_image_is_pre_stop_precondition(self):
        self.assertIn("RELEASE_PREVIOUS_IMAGE_MISSING", SCRIPT)
        admission = SCRIPT.index("Step 'SOURCE_ADMISSION'")
        previous = SCRIPT.index("Step 'PREVIOUS_IMAGE_RETENTION_PREFLIGHT'", admission)
        original_stop = SCRIPT.index("Docker-Text @('stop','--timeout','20',$Old.Id)", admission)
        self.assertLess(admission, previous)
        self.assertLess(previous, original_stop)
        stop_marker = SCRIPT.index("Step 'STOP_SOURCE'", admission)
        self.assertLess(stop_marker, original_stop)
        self.assertIn("Assert-Previous-Image-Retained $Source", SCRIPT[stop_marker:original_stop])

    def test_no_second_build_on_checked_apply(self):
        build = SCRIPT.index("if($Build){\n    Step 'BUILD_IMAGE'")
        pinned = SCRIPT.index("if($CheckedImageRecord){\n    # Pinned Apply")
        self.assertLess(build, pinned)
        self.assertIn("Docker-Json @('image','inspect',$script:Image)", SCRIPT)
        self.assertIn("RELEASE_IMAGE_REVISION_MISMATCH", SCRIPT)
        self.assertIn("RELEASE_BUILD_ACTION_INVALID", SCRIPT)

    def test_unrelated_backup_and_promote_paths_stay_guarded(self):
        self.assertIn("-or $PreserveApprovedRequest -or $CheckedImageRecord)", SCRIPT)
        self.assertIn("if($Action -eq 'Backup'){Backup-Primary;return}", SCRIPT)
        self.assertIn("if($Action -eq 'Promote'){Promote-Primary;return}", SCRIPT)
        self.assertIn("PRIMARY_VERIFIED_BACKUP_REQUIRED", PRIMARY)
        self.assertIn("PRIMARY_BACKUP_RECEIPT_INVALID", PRIMARY)

    def test_powershell_selftest_covers_bound_image_and_quiescence_mismatch(self):
        self.assertIn("RELEASE_CHECKED_IMAGE_BINDING_SELFTEST_FAILED", SCRIPT)
        self.assertIn("RELEASE_CHECKED_IMAGE_QUIESCENCE_SELFTEST_FAILED", SCRIPT)
        self.assertIn("FORTIS_INTEGRATIONS_SELFTEST_PASS", SCRIPT)


if __name__ == "__main__":
    unittest.main()

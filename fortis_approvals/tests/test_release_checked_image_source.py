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
        self.assertIn("$ApprovedImageSource=($Build -or [bool]$CheckedImageRecord -or $script:RegistryPrebuiltCheck)", SCRIPT)
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
        saver = SCRIPT.split("function Save-Checked-Image {", 1)[1].split("function Assert-Checked-Image-Binding {", 1)[0]
        record = saver.index("$Record=[ordered]@")
        write = saver.index("if($Maintenance -or $script:CorrectivePair -or $script:BootstrapPair){Write-Private $Path $Record -FlushToDisk}else{Write-Private $Path $Record}")
        self.assertIn("sourceReceipt=$Receipt", saver[record:write])
        self.assertLess(saver.index("Protect-Directory $Directory"), write)
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
            "attemptPointerHash=$AttemptHash;backupPointerHash=$BackupHash",
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

    def test_auto_combines_initial_receipt_with_preflight_without_skipping_final_guard(self):
        verify = SCRIPT.split('function Verify-Checked-Image {', 1)[1].split('function Assert-CheckedImagePreflightSelfTest {', 1)[0]
        self.assertLess(verify.index('Assert-Checked-Image-Binding $Record.binding $Expected'),
                        verify.index('if($BindingOnly){return}'))
        acquire = verify.index('$Now=if($Maintenance)')
        frozen = verify.index('Read-SuccessorFreezeSeal $Maintenance', acquire)
        receipt = verify.index('Receipt $Source.runtime.stateVolume -Exact:', frozen)
        verify_state = verify.index('RELEASE_GROWTH_SOURCE_STATE_CHANGED', receipt)
        self.assertLess(verify.index('if($BindingOnly){return}'), acquire)
        self.assertIn('$Frozen.sourceReceipt', verify[frozen:receipt])
        self.assertLess(verify_state, verify.index('if($ReturnReceipt){return $Now}'))
        self.assertLess(verify.index('RELEASE_CHECKED_IMAGE_SOURCE_STATE_CHANGED'), verify.index('if($ReturnReceipt){return $Now}'))
        early = SCRIPT.index('Verify-Checked-Image $SourceForOwnerShell $Report -BindingOnly:$Auto')
        admission = SCRIPT.index("Step 'SOURCE_ADMISSION'", early)
        preflight = SCRIPT.index("Step 'SOURCE_STATE_PREFLIGHT'", admission)
        merged = SCRIPT.index('Verify-Checked-Image $Source $Report -ReturnReceipt', preflight)
        proof = SCRIPT.index('Assert-Release-Receipt-Serializable $script:R $PreStopReceipt', merged)
        final = SCRIPT.index('if($CheckedImageRecord){Verify-Checked-Image $Source $Report}', proof)
        stop = SCRIPT.index("Docker-Text @('stop','--timeout','20',$Old.Id)", final)
        self.assertTrue(early < admission < preflight < merged < proof < final < stop)
        self.assertIn('elseif($Auto -and $CheckedImageRecord)', SCRIPT[preflight:merged])
        self.assertIn('FORTIS_CHECKED_IMAGE_PREFLIGHT_SELFTEST_PASS', SCRIPT)

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
        # The pre-stop check cannot prevent a request racing with docker stop.
        post_stop = SCRIPT.index("Assert-Checked-Source-Receipt $script:R.sourceReceipt", original_stop)
        clone = SCRIPT.index("Step 'CLONE_STATE'", original_stop)
        self.assertLess(original_stop, post_stop)
        self.assertLess(post_stop, clone)
        self.assertIn("RELEASE_CHECKED_IMAGE_SOURCE_STATE_CHANGED", SCRIPT)

    def test_own_attempt_pointer_is_published_only_after_final_binding_audit(self):
        """Regression: applying a checked image cannot invalidate its own
        attemptPointerHash before the pre-stop binding verification. Owner
        incident stopped at STOP_SOURCE with RELEASE_CHECKED_IMAGE_BINDING_CHANGED
        because ATTEMPT_POINTER_SAVED previously preceded that recheck.
        """
        admission = SCRIPT.index("Step 'SOURCE_ADMISSION'")
        prepared = SCRIPT.index("Step 'PREPARED_RECORD_SAVED'", admission)
        public_env = SCRIPT.index("Step 'PUBLIC_ENV_PREFLIGHT'", prepared)
        stop_step = SCRIPT.index("Step 'STOP_SOURCE'", public_env)
        frozen = SCRIPT.index("if($CheckedImageRecord){Verify-Checked-Image $Source $Report}", stop_step)
        old_image = SCRIPT.index("Assert-Previous-Image-Retained $Source", frozen)
        save_attempt = SCRIPT.index("Write-Private $AttemptPointer @{schema=1;record=$script:RecordPath}", frozen)
        attempt_marker = SCRIPT.index("Step 'ATTEMPT_POINTER_SAVED'", save_attempt)
        docker_stop = SCRIPT.index("Docker-Text @('stop','--timeout','20',$Old.Id)", attempt_marker)
        self.assertLess(prepared, public_env)
        self.assertLess(public_env, stop_step)
        self.assertLess(stop_step, frozen)
        self.assertLess(frozen, old_image)
        self.assertLess(old_image, save_attempt)
        self.assertLess(save_attempt, attempt_marker)
        self.assertLess(attempt_marker, docker_stop)
        self.assertNotIn("Write-Private $AttemptPointer", SCRIPT[prepared:frozen])
        # Full protected binding still includes the old attempt-pointer hash,
        # and the source state receipt is independently checked AFTER stop.
        self.assertIn("attemptPointerHash=$AttemptHash", SCRIPT)
        assert_frozen = SCRIPT.index("Assert-Checked-Source-Receipt $script:R.sourceReceipt", docker_stop)
        self.assertLess(docker_stop, assert_frozen)

    def test_no_second_build_on_checked_apply(self):
        build = SCRIPT.index("if($Build){\n    Step 'BUILD_IMAGE'")
        pinned = SCRIPT.index("if($CheckedImageRecord -or $script:RegistryPrebuiltCheck){\n    # Pinned Apply")
        self.assertLess(build, pinned)
        self.assertIn("Docker-Json @('image','inspect',$script:Image)", SCRIPT)
        self.assertIn("RELEASE_IMAGE_REVISION_MISMATCH", SCRIPT)
        self.assertIn("RELEASE_BUILD_ACTION_INVALID", SCRIPT)

    def test_unrelated_backup_and_promote_paths_stay_guarded(self):
        self.assertIn("-or $PreserveApprovedRequest -or $CheckedImageRecord -or $AllowUncertainGrowth)", SCRIPT)
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

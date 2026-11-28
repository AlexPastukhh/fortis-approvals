"""Fail-closed regression: missing original image cannot weaken source admission.

These tests inspect the exact Windows PowerShell controller source. They do
NOT execute owner Windows Docker, use credentials or prove rescue/restore.
Owner Windows PowerShell 5.1 syntax/SelfTest and an isolated synthetic missing-
image scenario are still required before a real UC-GW-013 release.
"""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
PS = (ROOT / "fortis_approvals/deploy/Manage-Integrations.ps1").read_text()
RECOVERY = (ROOT / "docs/use-cases/recovery.md").read_text()


def section(start, end):
    return PS.split("\n"+start, 1)[1].split("\n"+end, 1)[0]


class EmergencyMountAdmissionSourceTests(unittest.TestCase):
    def test_check_build_never_reports_ready_without_original_or_verified_rescue(self):
        start = PS.index("if($Action -eq 'Check'){",
                         PS.index("if($Report.status -cne 'READY')"))
        check = PS[start:PS.index("if(Test-Path -LiteralPath $AttemptPointer)", start)]
        # Both built and owner-pinned prebuilt images must pass the same
        # unconditional previous-image/rescue gate before Check reports READY.
        build = check.index("if($Build -or $script:RegistryPrebuiltCheck){")
        preflight = check.index("Assert-Previous-Image-Retained $Source", build)
        save = check.index("Save-Checked-Image $Source $Report $CheckReceipt", build)
        done = check.index("$Report|ConvertTo-Json -Depth 12;return", build)
        self.assertLess(preflight, save)
        self.assertLess(save, done)
        self.assertNotIn("if($EmergencyRequested){Assert-Previous-Image-Retained $Source}",
                         check[build:done])

    def test_only_exact_old_or_owner_attested_rescue_can_run_mount_digest(self):
        admit = section("function Admit {", "function Admit-Source {")
        for required in (
            "[string]$MountPreflightImageId=''",
            "$MountImage=$P.image",
            "$MountPreflightImageId -cne $P.image",
            "-not $AcceptUnverifiedRestore",
            "$MountPreflightImageId -cne $EmergencyRescueImage",
            "$P.image -ceq $script:Image",
            "$C.Image -cne $P.image",
            "RELEASE_EMERGENCY_SOURCE_MOUNT_IMAGE_DENIED",
            "State-Helper @{action='admit';container=$Public;expected=$Expected;pilot=$true}",
            "image=$P.image",
            "Read-PublisherActivationDigest $P",
            "Read-MachinePowerShellDigest $P",
            "Image-PublisherMount-Preflight -ImageId $MountImage",
            "Image-MachinePowerShell-Preflight -ImageId $MountImage",
            "RELEASE_PUBLISHER_VOLUME_CONTENT_CHANGED",
            "RELEASE_MACHINE_POWERSHELL_CONTENT_CHANGED",
        ):
            with self.subTest(required=required):
                self.assertIn(required, admit)
        self.assertLess(admit.index("State-Helper @{action='admit'"),
                        admit.index("Image-PublisherMount-Preflight -ImageId $MountImage"))
        self.assertLess(admit.index("State-Helper @{action='admit'"),
                        admit.index("Image-MachinePowerShell-Preflight -ImageId $MountImage"))
        self.assertNotIn("image=$MountImage", admit)
        self.assertNotIn("expected.image=$MountImage", admit)

    def test_emergency_source_admission_verifies_owner_gate_before_selecting_rescue(self):
        source = section("function Admit-Source {", "function Admit-ReturnCandidate {")
        self.assertIn("Assert-Previous-Image-Retained $Source", source)
        self.assertIn("$MountImage=$Source.runtime.image", source)
        self.assertIn("if($AcceptUnverifiedRestore){$MountImage=$EmergencyRescueImage}", source)
        self.assertIn("Admit $C $Source.runtime -MountPreflightImageId $MountImage", source)
        self.assertLess(source.index("Assert-Previous-Image-Retained $Source"),
                        source.index("if($AcceptUnverifiedRestore)"))
        gate = section("function Assert-Previous-Image-Retained {", "function Admit {")
        for required in (
            "Docker-Json @('image','inspect',$Source.runtime.image)",
            "RELEASE_PREVIOUS_IMAGE_MISSING",
            "RELEASE_EMERGENCY_UNNECESSARY",
            "Assert-Emergency-Rescue $Source",
        ):
            self.assertIn(required, gate)
        rescue = section("function Assert-Emergency-Rescue {",
                         "function Assert-Previous-Image-Retained {")
        for required in (
            "$EmergencyRescueImage -ceq $Source.runtime.image",
            "$EmergencyRescueImage -ceq $script:Image",
            "Get-FileHash -LiteralPath $Archive -Algorithm SHA256",
            "Docker-Json @('image','inspect',$EmergencyRescueImage)",
            "RELEASE_EMERGENCY_STATE_BACKUP_INVALID",
            "Same-Json (Receipt $Backup.backupVolume) $Backup.receipt",
            "RELEASE_EMERGENCY_RESCUE_SMOKE_FAILED",
            "'--network','none','--read-only'",
            "'--pull=never'",
        ):
            self.assertIn(required, rescue)

    def test_both_source_admission_and_last_pre_stop_admission_use_guard(self):
        first = PS.index("Step 'SOURCE_ADMISSION'")
        original = PS.index("$Old=Container $Source.runtime.pilotId;Admit-Source $Old $Source",
                            first)
        prestop = PS.index("Step 'PREVIOUS_IMAGE_RETENTION_PREFLIGHT'", original)
        stop_marker = PS.index("Step 'STOP_SOURCE'", prestop)
        last = PS.index("Admit-Source (Container $Old.Id) $Source", stop_marker)
        receipt = PS.index("Assert-Previous-Image-Retained $Source", last)
        pointer = PS.index("Write-Private $AttemptPointer @{schema=1;record=$script:RecordPath}",
                           receipt)
        stop_effect = PS.index("Docker-Text @('stop','--timeout','20',$Old.Id)", pointer)
        self.assertLess(first, original)
        self.assertLess(original, prestop)
        self.assertLess(prestop, stop_marker)
        self.assertLess(stop_marker, last)
        self.assertLess(last, receipt)
        self.assertLess(receipt, pointer)
        self.assertLess(pointer, stop_effect)
        self.assertNotIn("Admit $Old $Source.runtime", PS[first:stop_effect])
        self.assertNotIn("Admit (Container $Old.Id) $Source.runtime", PS[first:stop_effect])

    def test_no_emergency_exemption_on_return_or_new_candidate(self):
        source = section("function Admit-ReturnCandidate {", "function Snapshot-Uncertain-Growth {")
        self.assertIn("Admit $C $P -AllowUnhealthy", source)
        self.assertNotIn("-MountPreflightImageId", source)
        ret = section("function Return-Source {", "function Complete-ActionCoreNetwork {")
        self.assertIn("Admit $Old $script:R.source.runtime", ret)
        self.assertNotIn("Admit-Source $Old", ret)
        self.assertIn("RESTORE_TESTED", RECOVERY)
        self.assertIn("SOURCE_ADMISSION", RECOVERY)
        self.assertIn("RELEASE_PREVIOUS_IMAGE_MISSING", RECOVERY)

    def test_does_not_substitute_rescue_into_runtime_or_protected_source(self):
        stop = PS.index("Step 'STOP_SOURCE'")
        saved = PS.index("Step 'PREPARE_RECORD_MODEL'")
        record = PS[saved:stop]
        self.assertIn("image=$script:Image", record)
        self.assertIn("source=$Source", record)
        self.assertIn("rescueImage=$EmergencyRescueImage", record)
        self.assertIn("isolatedRestoreTested=$false", record)
        self.assertNotIn("image=$EmergencyRescueImage", record)
        self.assertNotIn("source=$EmergencyRescueImage", record)


if __name__ == "__main__":
    unittest.main()

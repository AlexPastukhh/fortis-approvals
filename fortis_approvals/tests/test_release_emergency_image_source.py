"""Source-only regression: narrow owner-accepted emergency recovery gate.

No Windows container, private state, Docker image or external effect is touched.
Windows PowerShell parser and owner SelfTest remain separate mandatory CI/host gates.
"""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = (ROOT / 'fortis_approvals/deploy/Manage-Integrations.ps1').read_text()
RECOVERY = (ROOT / 'docs/use-cases/recovery.md').read_text()


class EmergencyImageSourceTests(unittest.TestCase):
    def test_explicit_owner_risk_ack_and_image_archive_identity(self):
        self.assertIn("[switch]$AcceptUnverifiedRestore", SCRIPT)
        self.assertIn("[string]$EmergencyRescueImage=''", SCRIPT)
        self.assertIn("[string]$EmergencyRescueArchiveSha256=''", SCRIPT)
        self.assertIn("RELEASE_EMERGENCY_EXPLICIT_CHECKED_SOURCE_REQUIRED", SCRIPT)
        self.assertIn("-not $AcceptUnverifiedRestore", SCRIPT)
        self.assertIn("-not $ConfirmWorkerQuiescent", SCRIPT)
        self.assertIn("$Action -cnotin @('Check','Apply')", SCRIPT)
        self.assertIn("($Action -eq 'Check' -and -not $Build)", SCRIPT)
        self.assertIn("($Action -eq 'Apply' -and (-not $CheckedImageRecord -or $Build))", SCRIPT)
        self.assertIn("$EmergencyRescueImage -cnotmatch '^sha256:[0-9a-f]{64}$'", SCRIPT)

    def test_rescue_is_bound_to_private_immutable_check_receipt(self):
        for value in ('emergencyRescueImage=$EmergencyRescueImage',
                      'emergencyRescueArchiveSha256=$EmergencyRescueArchiveSha256.ToUpperInvariant()',
                      'acceptUnverifiedRestore=[bool]$AcceptUnverifiedRestore',
                      'Assert-Checked-Image-Binding $Record.binding $Expected',
                      'Verify-Checked-Image $SourceForOwnerShell $Report',
                      'Assert-Checked-Source-Receipt $script:R.sourceReceipt'):
            self.assertIn(value, SCRIPT)
        check = SCRIPT.index("Step 'SOURCE_STATE_PREFLIGHT_READ_ONLY'")
        verify = SCRIPT.index("if($EmergencyRequested){Assert-Previous-Image-Retained $Source}", check)
        save = SCRIPT.index("Save-Checked-Image $Source $Report $CheckReceipt", verify)
        self.assertLess(check, verify)
        self.assertLess(verify, save)

    def test_default_image_missing_still_stops_and_invalid_not_accepted(self):
        fn = SCRIPT.split('function Assert-Previous-Image-Retained {', 1)[1].split('function Admit {', 1)[0]
        self.assertIn("if(-not $AcceptUnverifiedRestore){throw 'RELEASE_PREVIOUS_IMAGE_MISSING'}", fn)
        self.assertIn("if($Info.Id -cne $Source.runtime.image){throw 'RELEASE_PREVIOUS_IMAGE_MISSING'}", fn)
        self.assertIn("if($AcceptUnverifiedRestore){throw 'RELEASE_EMERGENCY_UNNECESSARY'}", fn)
        self.assertIn('Assert-Emergency-Rescue $Source', fn)
        before_stop = SCRIPT.index("Step 'PREVIOUS_IMAGE_RETENTION_PREFLIGHT'")
        actual_stop = SCRIPT.index("Docker-Text @('stop','--timeout','20',$Old.Id)", before_stop)
        self.assertLess(before_stop, actual_stop)
        self.assertIn('Assert-Previous-Image-Retained $Source',
                      SCRIPT[SCRIPT.index("Step 'STOP_SOURCE'"):actual_stop])

    def test_backup_file_image_and_no_network_smoke_guard(self):
        fn = SCRIPT.split('function Assert-Emergency-Rescue {', 1)[1].split('function Assert-Previous-Image-Retained {', 1)[0]
        for value in (
            'fortis-gateway-rescue-', 'Get-FileHash -LiteralPath $Archive -Algorithm SHA256',
            'ReparsePoint', "Docker-Json @('image','inspect',$EmergencyRescueImage)",
            "'--network','none'", "'--read-only'", "'--pull=never'",
            "'--cap-drop','ALL'", "'--user','10001:10001'",
            'os.environ.pop("FORTIS_OWNER_SHELL_CONFIG",None)',
            'IMAGE_OWNER_INCIDENT_IMPORT_PASS', 'IMAGE_GITHUB_NOT_REGISTERED_PASS',
            'RELEASE_EMERGENCY_RESCUE_SMOKE_FAILED',
            'RELEASE_EMERGENCY_STATE_BACKUP_REQUIRED',
            'RELEASE_EMERGENCY_STATE_BACKUP_INVALID',
            'Same-Json (Receipt $Backup.backupVolume) $Backup.receipt',
            "FORTIS_EMERGENCY_UNVERIFIED_RESTORE_OWNER_ACCEPTED",
        ):
            self.assertIn(value, fn)
        for forbidden in ("Docker-Text @('load'", "Docker-Text @('stop'", "Docker-Text @('restart'",
                          "Docker-Text @('rm'", "Docker-Text @('volume'"):
            self.assertNotIn(forbidden, fn)

    def test_protected_release_records_do_not_claim_restore_tested(self):
        self.assertIn('ownerAcceptedUnverifiedRestore=[bool]$AcceptUnverifiedRestore', SCRIPT)
        self.assertIn('isolatedRestoreTested=$false', SCRIPT)
        self.assertIn("Не считать восстановление проверенным", RECOVERY)


if __name__ == '__main__':
    unittest.main()

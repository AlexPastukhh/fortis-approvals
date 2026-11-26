"""UC-GW-013 guarded Promote continuation, source-only / no Docker effects.

The owner Windows 5.1 SelfTest additionally executes pure positive/negative
binding fixtures. CI text checks do not prove isolated restore or live Promote.
"""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
MANAGE = (ROOT / "fortis_approvals/deploy/Manage-Integrations.ps1").read_text()
PRIMARY = (ROOT / "fortis_approvals/deploy/Primary-Gateway.ps1").read_text()
RECOVERY = (ROOT / "docs/use-cases/recovery.md").read_text()
RUNBOOK = (ROOT / "docs/PRIMARY-GATEWAY-OPERATIONS.md").read_text()


def section(script, begin, end):
    return script.split(begin, 1)[1].split(end, 1)[0]


class BackupCleanupSourceTests(unittest.TestCase):
    def test_owner_action_is_separate_from_release_and_vault(self):
        dispatch = section(MANAGE, "if($Action -eq 'BackupCleanup'){", "\nif(-not (Test-Path -LiteralPath $ReleaseBase))")
        for token in ("@('Action','BackupIds','Preview','SourceSha')", "RELEASE_WINDOWS_SOURCE_DIRTY",
                      "RELEASE_WINDOWS_MAIN_REQUIRED", "RELEASE_WINDOWS_SHA_MISMATCH",
                      "Assert-DirectoryAcl $ReleaseBase", "Open-ReleaseControllerLock",
                      "Backup-Cleanup $BackupIds -PreviewOnly:$Preview", "$ControllerLock.Dispose()"):
            self.assertIn(token, dispatch)
        self.assertLess(dispatch.index("RELEASE_WINDOWS_SHA_MISMATCH"), dispatch.index("Backup-Cleanup $BackupIds"))
        self.assertNotIn("Ensure-Vault", dispatch)
        self.assertEqual(MANAGE.count("Backup-Cleanup $BackupIds"), 1)
        self.assertIn("Assert-BackupCleanupSelectionSelfTest", MANAGE)

    def test_exact_registered_ids_and_protected_recovery_scope(self):
        ids = section(PRIMARY, "function Get-BackupCleanupIds {", "function Assert-BackupCleanupCandidate {")
        self.assertIn("^[0-9a-f]{32}$", ids)
        self.assertIn("BACKUP_CLEANUP_ID_DUPLICATE", ids)
        candidate = section(PRIMARY, "function Assert-BackupCleanupCandidate {", "function Assert-BackupCleanupSelectionSelfTest {")
        self.assertIn("'fortis-primary-backup-v1'", candidate)
        self.assertIn("$ProtectedSources -contains $Record.sourceRecord", candidate)
        self.assertIn("$RecordPath -ieq $ProtectedBackupPath", candidate)
        plan = section(PRIMARY, "function Get-BackupCleanupPlan {", "function Backup-Cleanup {")
        for token in ("$Primary.previousPrimaryRecord", "BACKUP_CLEANUP_PROTECTED_BACKUP_MISSING",
                      "BACKUP_CLEANUP_PRIOR_ATTEMPT_REQUIRES_READBACK", "BACKUP_CLEANUP_ID_ALREADY_RETIRED", "Receipt $CurrentBackup.backupVolume",
                      "BACKUP_CLEANUP_RELEASE_RECORD_REFERENCE", "Get-BackupCleanupIncidentHolds $C.Id $Ids",
                      "Assert-BackupCleanupUnheld $Volume.name $Holders", "BACKUP_CLEANUP_POINTER_CHANGED",
                      "BACKUP_CLEANUP_HISTORICAL_SOURCE_CHANGED", "$HistoricalCleanupRecords -contains $File.FullName"):
            self.assertIn(token, plan)
        self.assertLess(plan.index("Get-BackupCleanupVolumeIdentity $CurrentBackupId"), plan.index("Receipt $CurrentBackup.backupVolume"))
        self.assertNotIn("('volume','rm'", plan)

    def test_preview_and_confirmation_precede_only_exact_effect_and_readback(self):
        action = section(PRIMARY, "function Backup-Cleanup {", "function Promote-Primary {")
        tokens = ("Get-BackupCleanupPlan $Ids", "if($PreviewOnly){return}", "Read-Host",
                  "BACKUP_CLEANUP_OWNER_GO_REQUIRED", "Same-Json (Get-BackupCleanupPlan $Ids) $Plan",
                  "Write-Private $ResultPath $Result", "Get-BackupCleanupVolumeIdentity $Row.id",
                  "Docker-Text @('volume','rm',$Row.volume)", "BACKUP_CLEANUP_VOLUME_STILL_PRESENT",
                  "BACKUP_CLEANUP_PROTECTED_CHANGED_AFTER_EFFECT", "$Result.phase='Complete'",
                  "FORTIS_BACKUP_CLEANUP_VERIFIED")
        positions = [action.index(token) for token in tokens]
        self.assertEqual(positions, sorted(positions))
        self.assertEqual(action.count("Docker-Text @('volume','rm',"), 1)
        self.assertNotIn("'-f'", action)
        self.assertNotIn("'--force'", action)
        self.assertNotIn("Remove-Item", action)
        self.assertIn("$Result.phase='RecoveryRequired'", action)
        self.assertNotIn("Write-Private $PrimaryPointer", action)
        self.assertNotIn("Write-Private $BackupPointer", action)

    def test_holder_and_incident_guards_are_not_effects(self):
        held = section(PRIMARY, "function Assert-BackupCleanupUnheld {", "function Get-BackupCleanupIncidentHolds {")
        self.assertIn("$Holder.Mounts", held)
        self.assertIn("$Root.StartsWith($MountSource.TrimEnd('/')+'/'", held)
        self.assertNotIn("State.Status", held)  # stopped/created holders count too
        incidents = section(PRIMARY, "function Get-BackupCleanupIncidentHolds {", "function Get-BackupCleanupPlan {")
        self.assertIn("mode=ro", incidents)
        self.assertIn("PRAGMA query_only=ON", incidents)
        self.assertIn("backupVolumeOwnerAttested", incidents)
        self.assertIn("BACKUP_CLEANUP_INCIDENT_HOLD", incidents)
        import ast
        code = incidents.split("$Code=@'\n", 1)[1].split("\n'@", 1)[0]
        ast.parse(code)

    def test_incident_reader_finds_selected_holds_without_changing_fixture(self):
        import contextlib
        import io
        import json
        import sqlite3
        import tempfile
        from unittest.mock import patch

        incidents = section(PRIMARY, "function Get-BackupCleanupIncidentHolds {", "function Get-BackupCleanupPlan {")
        code = incidents.split("$Code=@'\n", 1)[1].split("\n'@", 1)[0]
        selected = "a" * 32
        other = "b" * 32
        with tempfile.TemporaryDirectory() as directory:
            db_path = Path(directory) / "approvals.sqlite"
            with sqlite3.connect(db_path) as db:
                db.execute("CREATE TABLE events (state TEXT, detail TEXT)")
                db.executemany("INSERT INTO events VALUES (?, ?)", [
                    ("CLOSED_UNCONFIRMED", json.dumps({"backupVolumeOwnerAttested": "fortis-gateway-backup-" + selected})),
                    ("CLOSED_UNCONFIRMED", json.dumps({"backupVolumeOwnerAttested": "fortis-gateway-backup-" + other})),
                    ("APPROVED", json.dumps({"backupVolumeOwnerAttested": "fortis-gateway-backup-" + selected})),
                    ("CLOSED_UNCONFIRMED", "{}"),
                ])
            before = db_path.read_bytes()
            fixture = code.replace("file:/state/private/approvals.sqlite?mode=ro", db_path.as_uri() + "?mode=ro")
            for ids, expected in (([selected], [selected]), (["c" * 32], [])):
                output = io.StringIO()
                with patch("sys.stdin", io.StringIO(json.dumps(ids))), contextlib.redirect_stdout(output):
                    exec(compile(fixture, "<incident-read-fixture>", "exec"), {})
                self.assertEqual(json.loads(output.getvalue()), {"holds": expected})
                self.assertEqual(db_path.read_bytes(), before)


class EmergencyPromoteSourceTests(unittest.TestCase):
    def test_ordinary_image_path_still_uses_unmodified_admission(self):
        promote = section(PRIMARY, "function Promote-Primary {", "\n}")
        self.assertIn("Docker-Json @('image','inspect',$Prior.runtime.image)", promote)
        self.assertIn("if($null -ne $OldImageInfo)", promote)
        self.assertIn("Admit $Prev $Prior.runtime -AllowUnhealthy\n", promote)
        self.assertIn("Assert-Emergency-Promote-Rescue $Source $Prior $Prev", promote)
        self.assertNotIn("Admit-Source $Prev", promote)

    def test_only_complete_immutable_emergency_release_can_authorize(self):
        bind = section(PRIMARY, "function Read-Emergency-Promote-Binding {",
                       "function Assert-Emergency-Promote-BindingSelfTest {")
        for expected in (
            "phase -cne 'Complete'",
            "activated -isnot [bool]",
            "probesPassed -isnot [bool]",
            "ownerAcceptedUnverifiedRestore -isnot [bool]",
            "isolatedRestoreTested -isnot [bool]",
            "isolatedRestoreTested -ne $false",
            "rescueImage -cnotmatch '^sha256:[0-9a-f]{64}$'",
            "archiveSha256 -cnotmatch '^[0-9A-F]{64}$'",
            "$Release.source.path -cne $Prior.sourceRecord",
            "$Release.source.hash -cne $Prior.sourceHash",
            "Same-Json $Release.source.runtime $Prior.runtime",
            "$Gate.rescueImage -ceq $Prior.runtime.image",
            "$Gate.rescueImage -ceq $Release.runtime.image",
            "$Prior.runtime.pilotName -cne 'fortis-gateway'",
            "RELEASE_EMERGENCY_PROMOTE_SOURCE_CHANGED",
        ):
            with self.subTest(expected=expected):
                self.assertIn(expected, bind)

    def test_emergency_preflights_two_separate_protected_backups(self):
        fn = section(PRIMARY, "function Assert-Emergency-Promote-Rescue {",
                     "function Get-PrimaryRegistryHandover {")
        promote = section(PRIMARY, "function Promote-Primary {", "\n}")
        self.assertIn("Same-Json (Receipt $Backup.backupVolume) $Backup.receipt", promote)
        self.assertIn("$Backup.sourceRecord -cne $Source.path", promote)
        for required in (
            "$Action -cne 'Promote'",
            "$Auto",
            "-not $ConfirmWorkerQuiescent",
            "$AcceptUnverifiedRestore",
            "$Previous.Id -cne $Prior.runtime.pilotId",
            "$Previous.Image -cne $Prior.runtime.image",
            "$Previous.State.Status -cne 'exited'",
            "Read-Private $Source.path",
            "Read-Emergency-Promote-Binding $Release $Prior",
            "Get-FileHash -LiteralPath $Prior.sourceRecord -Algorithm SHA256",
            "Get-ChildItem -LiteralPath $ReleaseBase -Directory -Filter 'primary-backup-*'",
            "$Candidate.sourceRecord -cne $Prior.sourceRecord",
            "$Candidate.sourceHash -cne $Prior.sourceHash",
            "$Candidate.image -cne $Prior.runtime.image",
            "Same-Json (Receipt $Candidate.backupVolume) $Candidate.receipt",
            "RELEASE_EMERGENCY_PROMOTE_OLD_BACKUP_MISSING",
            "Assert-DirectoryAcl $RecoveryDir",
            "Get-FileHash -LiteralPath $Archive -Algorithm SHA256",
            "Docker-Json @('image','inspect',$Binding.rescueImage)",
            "'--pull=never','--network','none','--read-only'",
            "'--user','10001:10001','--cap-drop','ALL'",
            "Emergency-Rescue-Smoke-Argument",
            "FORTIS_EMERGENCY_PROMOTE_RESCUE_VERIFIED",
        ):
            with self.subTest(required=required):
                self.assertIn(required, fn)
        for forbidden in ("Docker-Text @('stop'", "Docker-Text @('rename'",
                          "Docker-Text @('update'", "Write-Private $PrimaryPointer",
                          "Docker-Text @('start'"):
            self.assertNotIn(forbidden, fn)
        self.assertNotIn("Assert-Emergency-Rescue $Source", fn)
        self.assertNotIn("Read-Private $BackupPointer", fn)

    def test_no_mutating_promotion_effect_before_emergency_admission(self):
        promote = section(PRIMARY, "function Promote-Primary {", "\n}")
        old = promote.index("$Prev=Container $Prior.runtime.pilotId")
        before = promote.index("Assert-Emergency-Promote-Rescue $Source $Prior $Prev", old)
        admission = promote.index("Admit $Prev $Prior.runtime -AllowUnhealthy -MountPreflightImageId $Rescue", before)
        proof = promote.index("FORTIS_EMERGENCY_PROMOTE_PREVIOUS_ADMISSION_PASS", admission)
        effect = promote.index("Docker-Text @('update','--restart=no',$Prev.Id)", proof)
        rename = promote.index("Docker-Text @('rename',$Prev.Id,$Prior.runtime.originalPilotName)", effect)
        pointer = promote.index("Write-Private $PrimaryPointer $Record", rename)
        self.assertLess(old, before)
        self.assertLess(before, admission)
        self.assertLess(admission, proof)
        self.assertLess(proof, effect)
        self.assertLess(rename, pointer)

    def test_admit_keeps_real_image_identity_and_only_offline_mount_substitution(self):
        admit = section(MANAGE, "function Admit {", "function Admit-Source {")
        self.assertIn("[string]$VerifiedPromoteRescueImage=''", admit)
        self.assertIn("$Action -cne 'Promote'", admit)
        self.assertIn("$MountPreflightImageId -cne $VerifiedPromoteRescueImage", admit)
        self.assertIn("-not $VerifiedPromoteMount", admit)
        self.assertIn("$P.image -ceq $script:Image", admit)
        self.assertIn("$C.Image -cne $P.image", admit)
        self.assertIn("image=$P.image", admit)
        self.assertNotIn("image=$MountImage", admit)
        self.assertIn("State-Helper @{action='admit';container=$Public;expected=$Expected;pilot=$true}", admit)
        self.assertIn("Image-PublisherMount-Preflight -ImageId $MountImage", admit)
        self.assertIn("Image-MachinePowerShell-Preflight -ImageId $MountImage", admit)

    def test_no_new_promote_public_flags_or_restore_authority(self):
        head = MANAGE.split("$ForwardParameters=", 1)[0]
        self.assertNotIn("[switch]$EmergencyPromote", head)
        self.assertIn("$Action -cnotin @('Check','Apply')", MANAGE)
        self.assertIn("if($Action -eq 'Promote'){Promote-Primary;return}", MANAGE)
        ret = section(MANAGE, "function Return-Source {",
                      "function Complete-ActionCoreNetwork {")
        self.assertIn("Admit $Old $script:R.source.runtime", ret)
        self.assertNotIn("-VerifiedPromoteRescueImage", ret)

    def test_pure_windows_selftest_and_use_case_documented(self):
        fixture = section(PRIMARY, "function Assert-Emergency-Promote-BindingSelfTest {",
                          "function Assert-Emergency-Promote-Rescue {")
        for case in ("no-consent", "bad-archive", "source-drift",
                     "source-image-substitution", "false-restore-claim"):
            self.assertIn(case, fixture)
        self.assertIn("Assert-Emergency-Promote-BindingSelfTest", MANAGE)
        self.assertIn("FORTIS_EMERGENCY_PROMOTE_BINDING_SELFTEST_PASS", fixture)
        self.assertIn("**Завершение через Backup/Promote", RECOVERY)
        self.assertIn("isolate", RECOVERY.lower())
        self.assertIn("historical", RUNBOOK)
        self.assertIn("UC-GW-013", RUNBOOK)


if __name__ == "__main__":
    unittest.main()

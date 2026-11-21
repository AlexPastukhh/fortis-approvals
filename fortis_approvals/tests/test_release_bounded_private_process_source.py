"""Static Windows source gates for bounded owner-run release preflight."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
DEPLOY = ROOT / "fortis_approvals" / "deploy"


class BoundedReleaseProcessSourceTests(unittest.TestCase):
    def test_child_stdin_and_output_waits_cannot_block_indefinitely(self):
        source = (DEPLOY / "Run-GitHub-Pilot-E2E.ps1").read_text()
        body = source.split("function Private-Process {", 1)[1].split(
            "\nfunction Code64 {", 1
        )[0]
        for marker in (
            "$Started=$false",
            "$Started=$true",
            "$Process.StandardInput.WriteAsync($InputText)",
            "$WriteTask.Wait(30000)",
            "PILOT_PRIVATE_STDIN_TIMEOUT",
            "$Process.WaitForExit($WaitTimeoutMs)",
            "$OutputTask.Wait(15000)",
            "$ErrorTask.Wait(15000)",
            "PILOT_PRIVATE_OUTPUT_PIPE_TIMEOUT",
            "PILOT_PRIVATE_STDIN_WRITE_FAILED",
            "if ($Started)",
            "if (-not $Process.HasExited) { $Process.Kill() }",
        ):
            with self.subTest(marker=marker):
                self.assertIn(marker, body)
        self.assertIn("[ValidateRange(120000,1800000)][int]$WaitTimeoutMs = 120000",body)
        self.assertNotIn("$Process.WaitForExit()",body)
        self.assertNotIn("$Process.WaitForExit(0)",body)
        self.assertNotIn("$Process.WaitForExit(-1)",body)
        self.assertNotIn("$Process.StandardInput.Write($InputText)", body)
        self.assertLess(
            body.index("$WriteTask.Wait(30000)"),
            body.index("$Process.WaitForExit($WaitTimeoutMs)"),
        )

    def test_owner_powershell_selftest_exercises_bounded_wait_argument(self):
        source=(DEPLOY / "Run-GitHub-Pilot-E2E.ps1").read_text()
        self.assertIn("-WaitTimeoutMs 900000",source)
        self.assertIn("PILOT_PRIVATE_BOUNDED_WAIT_SELFTEST_FAILED",source)
        self.assertIn("[ValidateRange(120000,1800000)]",source)

    def test_large_state_has_finite_action_specific_timeout_without_bypass(self):
        source=(DEPLOY / "Manage-Integrations.ps1").read_text()
        helper=source.split("function State-Helper {",1)[1].split("\nfunction Ensure-Vault {",1)[0]
        self.assertIn("$Native=@{}",helper)
        self.assertIn("if($Payload.action -ceq 'clone')",helper)
        self.assertIn("$Native['DiagnosticDockerClone']=$true",helper)
        self.assertIn("$Native['WaitTimeoutMs']=1800000",helper)
        self.assertIn("('inspect','uncertain_growth_snapshot','uncertain_growth_review')",helper)
        self.assertIn("$Native['WaitTimeoutMs']=900000",helper)
        self.assertIn("State-Helper",source)
        self.assertIn("$WaitEcho=Private-Process",source)
        self.assertIn("FORTIS_RELEASE_STATE_HELPER_WAIT_SELFTEST_PASS",source)
        self.assertIn("RELEASE_STATE_HELPER_WAIT_SELFTEST_FAILED",source)
        self.assertIn("ConvertTo-Json -InputObject $Payload -Depth 25 -Compress) @Native",helper)
        self.assertIn("'--network','none'",helper)
        self.assertIn("'--read-only'",helper)
        self.assertIn("'--memory','256m'",helper)
        self.assertIn("'--mount'",source)
        self.assertIn("Step 'SOURCE_STATE_PREFLIGHT_READ_ONLY'",source)
        self.assertLess(source.index("Step 'SOURCE_STATE_PREFLIGHT_READ_ONLY'"),
                        source.index("Step 'STOP_SOURCE'"))
        self.assertIn("Assert-Checked-Source-Receipt $script:R.sourceReceipt",source)
        self.assertIn("Assert-SourceUnchanged",source)

    def test_nonsecret_markers_localize_before_stop_source(self):
        source = (DEPLOY / "Manage-Integrations.ps1").read_text()
        markers = (
            "Step 'SOURCE_STATE_PREFLIGHT'",
            "Step 'SOURCE_STATE_PREFLIGHT_COMPLETE'",
            "Step 'PRODUCTION_BASELINE_CAPTURED'",
            "Step 'RELEASE_DIRECTORY_PROTECTED'",
            "Step 'PREPARED_RECORD_SAVED'",
            "Step 'PUBLIC_ENV_PREFLIGHT'",
            "Step 'STOP_SOURCE'",
            "Step 'ATTEMPT_POINTER_SAVED'",
        )
        offsets = [source.index(marker) for marker in markers]
        self.assertEqual(offsets, sorted(offsets))
        self.assertIn("Save\nStep 'PREPARED_RECORD_SAVED'", source)
        self.assertIn(
            "Write-Private $AttemptPointer @{schema=1;record=$script:RecordPath}",
            source,
        )
        self.assertNotIn("Write-Host $InputText", source)


if __name__ == "__main__":
    unittest.main()

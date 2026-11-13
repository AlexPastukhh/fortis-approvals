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
            "$Process.WaitForExit(120000)",
            "$OutputTask.Wait(15000)",
            "$ErrorTask.Wait(15000)",
            "PILOT_PRIVATE_OUTPUT_PIPE_TIMEOUT",
            "PILOT_PRIVATE_STDIN_WRITE_FAILED",
            "if ($Started)",
            "if (-not $Process.HasExited) { $Process.Kill() }",
        ):
            with self.subTest(marker=marker):
                self.assertIn(marker, body)
        self.assertNotIn("$Process.StandardInput.Write($InputText)", body)
        self.assertLess(
            body.index("$WriteTask.Wait(30000)"),
            body.index("$Process.WaitForExit(120000)"),
        )

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

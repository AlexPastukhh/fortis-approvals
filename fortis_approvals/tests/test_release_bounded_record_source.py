"""Offline source gates for incident: PowerShell >6GB before PREPARED_RECORD_SAVED.

Windows PowerShell 5.1 executes the real bounded JSON fixture via
Manage-Integrations.ps1 -Action SelfTest in source-ci.yml.
"""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
DEPLOY = ROOT / "fortis_approvals" / "deploy"
MANAGER = (DEPLOY / "Manage-Integrations.ps1").read_text()
PILOT = (DEPLOY / "Run-GitHub-Pilot-E2E.ps1").read_text()
BOUNDED = MANAGER
WORKFLOW = (ROOT / ".github" / "workflows" / "source-ci.yml").read_text()


class BoundedReleaseRecordSourceTests(unittest.TestCase):
    def test_bounded_serializer_used_only_for_integration_release_record(self):
        self.assertIn("function ConvertTo-BoundedReleaseJson {", MANAGER)
        self.assertIn("function Save {", MANAGER)
        self.assertIn("$JsonText=ConvertTo-BoundedReleaseJson $script:R", MANAGER)
        self.assertIn("Save-Record -SerializedJson $JsonText", MANAGER)
        self.assertIn("param([string]$SerializedJson='')", PILOT)
        self.assertIn("if(-not $JsonText){$JsonText=ConvertTo-Json -InputObject $script:R -Depth 25}", PILOT)
        self.assertIn("try {$script:R=$Value;$script:RecordPath=$Path;Save-Record}", MANAGER)

    def test_no_unbounded_powershell_object_graph_serializer_in_apply(self):
        self.assertIn("RELEASE_RECORD_JSON_UNSUPPORTED_TYPE", BOUNDED)
        self.assertIn("RELEASE_RECORD_JSON_WORK_BUDGET_EXCEEDED", BOUNDED)
        self.assertIn("RELEASE_RECORD_JSON_DEPTH_EXCEEDED", BOUNDED)
        self.assertIn("RELEASE_RECORD_JSON_OUTPUT_TOO_LARGE", BOUNDED)
        self.assertIn("[Collections.IDictionary]", BOUNDED)
        self.assertIn("[pscustomobject]", BOUNDED)
        self.assertIn("[Collections.IList]", BOUNDED)
        self.assertIn("System.Web.Script.Serialization.JavaScriptSerializer", BOUNDED)
        self.assertIn("$Encoder.MaxJsonLength = 1048576", BOUNDED)
        self.assertIn("$Encoder.RecursionLimit = 32", BOUNDED)
        self.assertNotIn("ConvertTo-Json -InputObject $script:R", BOUNDED)

    def test_before_source_stop_mandatory_markers(self):
        first = MANAGER.index("Step 'RELEASE_DIRECTORY_PROTECTED'")
        prep = MANAGER.index("Step 'PREPARE_RECORD_MODEL'", first)
        ready = MANAGER.index("Step 'PREPARE_RECORD_MODEL_READY'", prep)
        serialize = MANAGER.index("Write-Host 'FORTIS_INTEGRATIONS_RECORD_BOUNDED_SERIALIZE_START'")
        persist = MANAGER.index("Write-Host 'FORTIS_INTEGRATIONS_RECORD_PERSISTED'")
        saved = MANAGER.index("Step 'PREPARED_RECORD_SAVED'", ready)
        stop = MANAGER.index("Step 'STOP_SOURCE'", saved)
        self.assertLess(first, prep)
        self.assertLess(prep, ready)
        self.assertLess(serialize, persist)
        self.assertLess(ready, saved)
        self.assertLess(saved, stop)

    def test_actual_receipt_serialization_is_proved_before_stop_and_pointer_write(self):
        """Fail closed on untrusted PSObject receipt members before any source effect.

        Production 42873eb... stopped the old Gateway then first attempted to
        serialize its real sourceReceipt; INVALID_PROPERTY blocked both failure
        recording and durable Return. The static gate protects the live source.
        """
        source_probe=MANAGER.index("Step 'SOURCE_STATE_PREFLIGHT';$PreStopReceipt=Receipt")
        model=MANAGER.index("Step 'PREPARE_RECORD_MODEL_READY'", source_probe)
        proof=MANAGER.index("Step 'SOURCE_RECEIPT_SERIALIZATION_PREFLIGHT'", model)
        actual=MANAGER.index("Assert-Release-Receipt-Serializable $script:R $PreStopReceipt", proof)
        passed=MANAGER.index("Step 'SOURCE_RECEIPT_SERIALIZATION_PREFLIGHT_PASS'", actual)
        saved=MANAGER.index("Step 'PREPARED_RECORD_SAVED'", passed)
        stopped=MANAGER.index("Step 'STOP_SOURCE'", saved)
        pointer=MANAGER.index("Write-Private $AttemptPointer @{schema=1;record=$script:RecordPath}", stopped)
        docker_stop=MANAGER.index("Docker-Text @('stop','--timeout','20',$Old.Id)", stopped)
        self.assertLess(source_probe, model)
        self.assertLess(model, proof)
        self.assertLess(proof, actual)
        self.assertLess(actual, passed)
        self.assertLess(passed, saved)
        self.assertLess(saved, stopped)
        self.assertLess(stopped, pointer)
        self.assertLess(pointer, docker_stop)
        self.assertIn("$Record['sourceReceipt']=$Prior", MANAGER)
        self.assertIn("$null=ConvertTo-BoundedReleaseJson $Record", MANAGER)
        self.assertIn("$PoisonedReceipt|Add-Member -MemberType ScriptProperty", MANAGER)
        self.assertIn("RELEASE_RECEIPT_PREFLIGHT_FAIL_CLOSED_SELFTEST_FAILED", MANAGER)

    def test_windows_51_selftest_with_large_fixture_negative_guards(self):
        self.assertIn("if($Action -eq 'SelfTest'){", MANAGER)
        self.assertIn("Assert-BoundedReleaseJsonSelfTest", MANAGER)
        self.assertIn("& $files[4] -Action SelfTest", WORKFLOW)
        for marker in (
            "FORTIS_RELEASE_BOUNDED_JSON_SELFTEST_PASS",
            "52000",
            "preserveUncertainRequests=$Uncertain",
            "preserveClaimedJobs=$Claimed",
            "preserveApprovedRequest=$Uncertain",
            "workerQuiescenceOwnerAttested=$true",
            "RELEASE_RECORD_JSON_CYCLE_SELFTEST_FAILED",
            "RELEASE_RECORD_JSON_SIZE_SELFTEST_FAILED",
            "RELEASE_RECORD_JSON_TYPE_SELFTEST_FAILED",
            "RELEASE_REAL_RECEIPT_SHAPE_SELFTEST_FAILED",
            "RELEASE_RECEIPT_PREFLIGHT_FAIL_CLOSED_SELFTEST_FAILED",
            "RELEASE_RECORD_JSON_PERSIST_SELFTEST_FAILED",
            "RELEASE_RECORD_JSON_REPLACE_SELFTEST_FAILED",
            "Save-Record -SerializedJson $Json",
            "Assert-RecordAcl",
        ):
            with self.subTest(marker=marker):
                self.assertIn(marker, BOUNDED)


if __name__ == "__main__":
    unittest.main()

"""Offline source gates for the >256-entry per-file receipt hash map.

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
RUNBOOK = (ROOT / "docs" / "PRIMARY-GATEWAY-OPERATIONS.md").read_text()


class BoundedReleaseRecordSourceTests(unittest.TestCase):
    def test_bounded_serializer_used_only_for_integration_release_record(self):
        self.assertIn("function ConvertTo-BoundedReleaseJson {", MANAGER)
        self.assertIn("function Save {", MANAGER)
        self.assertIn("$JsonText=ConvertTo-BoundedReleaseJson $script:R", MANAGER)
        self.assertIn("Save-Record -SerializedJson $JsonText", MANAGER)
        save_record = PILOT.split("function Save-Record {", 1)[1].split("function Assert-PreparedResume {", 1)[0]
        self.assertIn("[string]$SerializedJson=''", save_record.split("$JsonText=", 1)[0])
        self.assertIn("$JsonText=$SerializedJson", save_record)
        self.assertIn("if(-not $JsonText){$JsonText=ConvertTo-Json -InputObject $script:R -Depth 25}", save_record)
        private_writer = MANAGER.split("function Write-Private {", 1)[1].split("\nfunction ", 1)[0]
        bind = private_writer.index("$script:R=$Value;$script:RecordPath=$Path")
        save = private_writer.index("if($FlushToDisk){Save-Record -FlushToDisk}else{Save-Record}")
        self.assertLess(bind, save)

    def test_record_context_exists_before_selftest_and_auto_private_reads(self):
        # Parent profile/interactive Windows owner sessions can enable
        # Set-StrictMode -Version Latest. The old SelfTest attempted
        # $PreviousPath=$script:RecordPath before it was initialized, and
        # Check -Auto could similarly encounter Read/Write-Private.
        bootstrap=MANAGER.index("$PrimaryPointer=Join-Path $ReleaseBase 'primary.json'")
        path=MANAGER.index("$script:RecordPath=''",bootstrap)
        model=MANAGER.index("$script:R=$null",path)
        runtime=MANAGER.index("$script:Step='PREFLIGHT';$script:Image=$Image",model)
        selftest=MANAGER.index("if($Action -eq 'SelfTest'){",runtime)
        previous=MANAGER.index("$PreviousPath=$script:RecordPath")
        read=MANAGER.index("function Read-Private {")
        write=MANAGER.index("function Write-Private {")
        prepare=MANAGER.index("$script:RecordPath=Join-Path $Directory 'record.json'")
        self.assertLess(bootstrap,path)
        self.assertLess(path,model)
        self.assertLess(model,runtime)
        self.assertLess(path,selftest)
        strict=MANAGER.index("Set-StrictMode -Version Latest",selftest)
        actual_fixture=MANAGER.index("    Assert-BoundedReleaseJsonSelfTest",strict)
        self.assertLess(selftest,strict)
        self.assertLess(strict,actual_fixture)
        self.assertEqual(MANAGER.count("Set-StrictMode -Version Latest"),1)
        # Function definitions can precede or follow the bootstrap; the
        # important ordering is the top-level initialization before the
        # first SelfTest / release action dispatch.
        self.assertLess(path,prepare)
        self.assertIn('$PreviousPath=$script:RecordPath',MANAGER)
        self.assertIn('function Read-Private {',MANAGER)
        self.assertIn('function Write-Private {',MANAGER)
        self.assertLess(runtime,prepare)
        self.assertEqual(MANAGER.count("$script:RecordPath=''"),1)
        self.assertEqual(MANAGER.count("$script:R=$null"),1)
        self.assertIn("$script:RecordPath=$PreviousPath",MANAGER)
        self.assertIn("finally {$script:RecordPath=$Saved}",MANAGER)
        self.assertIn("finally {$script:R=$SavedR;$script:RecordPath=$SavedPath}",MANAGER)
        # The SelfTest still uses isolated temporary state and must never
        # write the global production attempt/current pointers.
        local=MANAGER[MANAGER.index("function Assert-BoundedReleaseJsonSelfTest {"):MANAGER.index("$ErrorActionPreference='Stop'")]
        self.assertIn("$TestDirectory=Join-Path $env:TEMP",local)
        self.assertNotIn("Write-Private $AttemptPointer",local)
        self.assertNotIn("Write-Private $Pointer",local)

    def test_owner_auto_release_runbook_requires_successful_selftest(self):
        section=RUNBOOK.split('## Lightweight owner release path',1)[1]
        start=section.index('$manager = Join-Path')
        selftest=section.index('& $manager -Action SelfTest',start)
        check=section.index('& $manager -Action Check -Auto',selftest)
        apply=section.index('& $manager -Action Apply -Auto',check)
        self.assertLess(start,selftest)
        self.assertLess(selftest,check)
        self.assertLess(check,apply)
        for marker in ('FORTIS_RELEASE_BOUNDED_JSON_SELFTEST_PASS',
                       'FORTIS_INTEGRATIONS_SELFTEST_PASS',
                       'count=257 limit=256','VariableIsUndefined',
                       'hard STOP'):
            self.assertIn(marker,section)
        self.assertIn("Write-Host 'FORTIS_INTEGRATIONS_SELFTEST_PASS';return",MANAGER)

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
        self.assertGreaterEqual(BOUNDED.count("$ObjectLimit=8192"), 2)
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

    def test_exact_long_visual_receipt_sha256_key_is_only_scoped_exception(self):
        # Inspect_state hashes every file, including canonical visual-media
        # paths of 131 characters. The general release JSON limit is 128.
        from fortis_approvals.deploy.github_pilot_helpers import VISUAL_MEDIA_DIR
        name=(VISUAL_MEDIA_DIR + '/248affc3-536f-4100-b4bc-bd166c3989be'
              + '-0-' + 'a'*64 + '.png')
        self.assertEqual(len(name),131)
        self.assertIn("if ($Name.Length -le 128) { return $true }", MANAGER)
        self.assertIn("$Scope -ceq 'receipt-hashes' -and $Name.Length -eq 131", MANAGER)
        self.assertIn("-Scope $NextScope", MANAGER)
        self.assertIn("-Scope 'root'", MANAGER)
        self.assertIn("RELEASE_VISUAL_KEY_SCOPE_SELFTEST_FAILED", MANAGER)
        self.assertIn("RELEASE_VISUAL_KEY_PATTERN_SELFTEST_FAILED", MANAGER)
        self.assertIn("RELEASE_VISUAL_RECEIPT_PERSIST_SELFTEST_FAILED", MANAGER)
        self.assertIn("$Prop.MemberType -ne [Management.Automation.PSMemberTypes]::NoteProperty", MANAGER)

    def test_actual_receipt_serialization_is_proved_before_stop_and_pointer_write(self):
        """Fail closed on untrusted PSObject receipt members before any source effect.

        Production 42873eb... stopped the old Gateway then first attempted to
        serialize its real sourceReceipt; INVALID_PROPERTY blocked both failure
        recording and durable Return. The static gate protects the live source.
        """
        source_probe=MANAGER.index("Step 'SOURCE_STATE_PREFLIGHT'\n$PreStopReceipt=if")
        combined=MANAGER.index('Verify-Checked-Image $Source $Report -ReturnReceipt',source_probe)
        self.assertLess(source_probe,combined)
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
            "RELEASE_LARGE_RECEIPT_HASH_MAP_SELFTEST_FAILED",
            "RELEASE_LARGE_RECEIPT_PERSIST_SELFTEST_FAILED",
            "RELEASE_RECEIPT_OBJECT_LIMIT_SCOPE_SELFTEST_FAILED",
            "RELEASE_VISUAL_RECEIPT_KEY_LENGTH_SELFTEST_FAILED",
            "RELEASE_VISUAL_KEY_SCOPE_SELFTEST_FAILED",
            "RELEASE_VISUAL_KEY_PATTERN_SELFTEST_FAILED",
            "RELEASE_VISUAL_RECEIPT_PERSIST_SELFTEST_FAILED",
            "RELEASE_RECEIPT_PREFLIGHT_FAIL_CLOSED_SELFTEST_FAILED",
            "RELEASE_RECORD_JSON_PERSIST_SELFTEST_FAILED",
            "RELEASE_RECORD_JSON_REPLACE_SELFTEST_FAILED",
            "Save-Record -SerializedJson $LargeJson",
            "Save-Record -SerializedJson $Json",
            "FORTIS_RELEASE_RECEIPT_HASH_MAP_COUNT",
            "FORTIS_RELEASE_JSON_OBJECT_LIMIT",
            "Assert-RecordAcl",
        ):
            with self.subTest(marker=marker):
                self.assertIn(marker, BOUNDED)


if __name__ == "__main__":
    unittest.main()

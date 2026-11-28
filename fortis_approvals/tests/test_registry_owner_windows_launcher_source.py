"""Static, source-only Windows launcher guardrails (not PowerShell runtime)."""
from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[2]
LAUNCHER = ROOT / 'fortis_approvals' / 'deploy' / 'Registry-Owner-Bootstrap.ps1'
RUNBOOK = ROOT / 'docs' / 'RELEASE-REGISTRY-FUNCTIONAL-V1-PILOT.md'
CATALOG = ROOT / 'release' / 'targets.yaml'


class RegistryOwnerWindowsLauncherSourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = LAUNCHER.read_text(encoding='utf-8')

    def test_source_and_target_inventory(self):
        self.assertIn('Registry-Owner-Bootstrap.ps1', CATALOG.read_text())
        self.assertIn('## Windows owner bootstrap launcher', RUNBOOK.read_text())
        self.assertIn('[CmdletBinding()]', self.source)
        self.assertIn("[ValidateSet('Plan','Preview','Provision','Verify','PrepareSuccessor','AccountDeliveryRepair','AccountBootstrapMigration','StartManaged')]", self.source)

    def test_no_hidden_admin_or_second_service_effect(self):
        src='\n'.join(line for line in self.source.lower().splitlines() if not line.lstrip().startswith('#'))
        self.assertNotIn('docker volume create',src)
        self.assertNotIn('docker stop',src)
        self.assertNotIn('docker rm ',src)
        self.assertNotIn('docker exec ',src)
        self.assertNotIn('docker build',src)
        self.assertNotIn('cap-add',src)
        self.assertNotIn('--privileged',src)
        self.assertNotIn('pid=host',src)
        self.assertNotIn('/var/run/docker.sock',src)
        self.assertNotIn('chown ',src)
        self.assertNotIn('force-with-lease',src)
        self.assertIn("--network=none",self.source)
        self.assertIn("--read-only",self.source)
        self.assertIn("--cap-drop",self.source)
        self.assertIn("no-new-privileges:true",self.source)
        self.assertIn("--pull=never",self.source)
        self.assertEqual(self.source.count("'run','-i','--rm'"),1)

    def test_separate_go_and_no_false_pass(self):
        self.assertIn("$Action -ceq 'Provision' -and -not $ConfirmProvision",self.source)
        self.assertIn('REGISTRY_BOOTSTRAP_INDEPENDENT_PROVISION_GO_REQUIRED',self.source)
        self.assertIn('REGISTRY_BOOTSTRAP_SPEC_PIN_CHANGED',self.source)
        self.assertIn('REGISTRY_BOOTSTRAP_WINDOWS_SOURCE_SHA_MISMATCH',self.source)
        self.assertIn('REGISTRY_BOOTSTRAP_WINDOWS_SOURCE_DIRTY',self.source)
        self.assertIn('REGISTRY_BOOTSTRAP_VOLUME_ALREADY_ATTACHED_',self.source)
        self.assertIn('REGISTRY_BOOTSTRAP_RESULT_INVARIANT_FAILED_STOP',self.source)
        self.assertIn('$RunExit -ne 0',self.source)
        self.assertRegex(self.source,r'if \(\$RunExit -ne 0\)[\s\S]*?throw[\s\S]*?SOURCE_ONLY_PASS')

    def test_exact_mounts_and_stdin_tmpfs(self):
        self.assertIn('REGISTRY_BOOTSTRAP_SPEC_ASCII_SINGLE_LINE_REQUIRED',self.source)
        self.assertIn('sys.stdin.buffer.read(4098)',self.source)
        self.assertIn("/run/fortis-registry-bootstrap/spec.json",self.source)
        self.assertIn('uid=20002,gid=20002,mode=0700',self.source)
        self.assertIn('dst=/run/fortis-registry-state',self.source)
        self.assertIn('dst=/run/fortis-registry-runtime',self.source)
        self.assertIn('dst=/run/fortis-registry-read',self.source)
        self.assertIn('volume-nocopy',self.source)
        self.assertIn("$StateFlag='readonly'",self.source)
        self.assertIn("$ConfigFlag='readonly'",self.source)
        self.assertIn('separate',RUNBOOK.read_text().lower())
        self.assertEqual(self.source.count("& docker @DockerArgs"),1)

    def test_powershell_herestring_syntax_static_only(self):
        self.assertEqual(len(re.findall(r"^ *\$PythonRunner=@'$",self.source,re.M)),2)
        self.assertEqual(len(re.findall(r"^'@$",self.source,re.M)),2)
        self.assertEqual(self.source.count('Invoke-Registry-Bootstrap-DockerRead -Arguments @('),10)

    def test_successor_preparation_is_bound_to_a_dedicated_inactive_clone(self):
        self.assertIn('$SuccessorWrite -and -not $ConfirmProvision', self.source)
        self.assertIn("('fortis-registry-state-e13b-'+$Id)", self.source)
        self.assertIn("$ExpectedConfig='fortis-registry-config-e13b-'+$Id", self.source)
        self.assertIn("if($AccountBootstrap){$ExpectedConfig+='-prepared'}",self.source)
        self.assertIn('$ConfigVolume -cne $ExpectedConfig',self.source)
        self.assertIn("if($SuccessorWrite){$VolumeNames=@($StateVolume,$ConfigVolume)}", self.source)
        self.assertIn("$Name='fortis-registry-successor-'+$Id", self.source)
        cmd = self.source.split("$DockerArgs+=@('--name',('fortis-registry-successor-'+$Id),", 1)[1]
        cmd = cmd.split("$SpecLine=if($AccountBootstrap)", 1)[0]
        self.assertIn("'--mount',$StateMount,'--mount',$ConfigMount", cmd)
        self.assertNotIn('$SocketMount', cmd)
        self.assertIn("$Receipt.sourceTransitionPending -ne (-not $AccountTransition)", self.source)
        self.assertIn("$Receipt.sourceTransitionReceipt.sourceCursor -cne $SourceSha", self.source)

    def test_delivery_repair_requires_exact_pins_and_source_only_receipt(self):
        self.assertIn('REGISTRY_BOOTSTRAP_REPAIR_EVIDENCE_REQUIRED', self.source)
        self.assertIn('REGISTRY_BOOTSTRAP_REPAIR_IMAGE_SOURCE_CHANGED', self.source)
        self.assertIn("('type=volume,src='+$ValidatorVolume+", self.source)
        self.assertIn("[ValidateSet('1','2')][int]$RepairPredecessorRevision=1", self.source)
        self.assertIn("REGISTRY_BOOTSTRAP_REPAIR_REVISION_ACTION_DENIED", self.source)
        self.assertIn("$Receipt.predecessorReceipt.sourceRevision -ne $RepairPredecessorRevision", self.source)
        self.assertIn("$Receipt.sourceRepairReceipt.sourceRevision -ne ($RepairPredecessorRevision+1)", self.source)
        self.assertIn("$Receipt.sourceRepairReceipt.deploymentAuthorized -ne $false", self.source)

    def test_bootstrap_migration_is_distinct_inactive_accounting(self):
        for marker in ('REGISTRY_BOOTSTRAP_MIGRATION_PINS_REQUIRED',
                       '$SuccessorWrite=$PrepareSuccessor -or $RepairDelivery -or $AccountBootstrap',
                       '$RepairDelivery -or $AccountBootstrap -or $CorrectivePreview',
                       'account_bootstrap_migration(profile, review_sha256=review',
                       '$DockerArgs+=@($BootstrapReviewSha256,$BootstrapEvidenceSha256,$SourceSha)',
                       "$Receipt.sourceMigrationReceipt.kind -cne 'BOOTSTRAP_MIGRATION'",
                       '$Receipt.prefix.predecessorReceipt.sourceRevision -ne 3',
                       '$Receipt.checkpoint.snapshotRevision -ne 4',
                       '$Receipt.sourceMigrationReceipt.deploymentAuthorized -ne $false',
                       'REGISTRY_BOOTSTRAP_MIGRATION_RESULT_INVARIANT_FAILED_STOP',
                       'REGISTRY_BOOTSTRAP_MIGRATION_INCUMBENT_HOLDER_CHANGED',
                       'dst=/run/fortis-registry-incumbent-state,volume-nocopy,readonly',
                       'dst=/run/fortis-registry-incumbent-runtime,volume-nocopy,readonly'):
            self.assertIn(marker,self.source)
        self.assertIn('if($SuccessorWrite){$VolumeNames=@($StateVolume,$ConfigVolume)}',self.source)

    def test_corrective_preview_is_readonly_no_restart_and_explicit(self):
        self.assertIn('REGISTRY_BOOTSTRAP_CORRECTIVE_PREVIEW_DENIED',self.source)
        self.assertIn('REGISTRY_BOOTSTRAP_CORRECTIVE_PREVIEW_VOLUME_ATTACHED',self.source)
        self.assertIn("$Name+='-preview'",self.source)
        self.assertIn("$Restart='--restart=no'",self.source)
        self.assertIn("$StateAccess=',readonly'",self.source)
        self.assertIn("volume-nocopy'+$StateAccess",self.source)
        self.assertIn("'--corrective-preview-sha',$SourceSha",self.source)
        self.assertIn("$Verb=@('create')",self.source)
        self.assertIn('REGISTRY_BOOTSTRAP_CORRECTIVE_WRITER_NOT_PRISTINE',self.source)
        self.assertIn('created|no|0001-01-01T00:00:00Z',self.source)
        self.assertIn('$CorrectivePreview -and $CorrectiveWriter',self.source)

    def test_managed_start_is_explicit_and_preserves_private_volumes(self):
        self.assertIn('REGISTRY_BOOTSTRAP_MANAGED_START_CONFIRMATION_REQUIRED', self.source)
        self.assertIn("'--restart=unless-stopped'", self.source)
        self.assertIn("'--managed-startup'", self.source)
        self.assertIn("$SocketMount[0].RW -ne $false", self.source)
        self.assertEqual(self.source.count('& docker @StartArgs'), 1)
        self.assertIn('REGISTRY_BOOTSTRAP_MANAGED_START_UNKNOWN_INSPECT_ORIGINAL', self.source)


if __name__ == '__main__':
    unittest.main()

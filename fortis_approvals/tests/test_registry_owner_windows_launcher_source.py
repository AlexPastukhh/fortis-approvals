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
        self.assertIn("[ValidateSet('Plan','Preview','Provision','Verify')]", self.source)

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
        self.assertEqual(len(re.findall(r'^\$PythonRunner=@\'$',self.source,re.M)),1)
        self.assertEqual(len(re.findall(r"^'@$",self.source,re.M)),1)
        self.assertEqual(self.source.count('Invoke-Registry-Bootstrap-DockerRead -Arguments @('),4)


if __name__ == '__main__':
    unittest.main()

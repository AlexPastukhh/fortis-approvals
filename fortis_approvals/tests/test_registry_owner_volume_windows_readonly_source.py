"""Static source-only Windows PS5.1 preflight boundary tests (not host runtime)."""
from pathlib import Path
import re
import unittest

ROOT=Path(__file__).resolve().parents[2]
SOURCE=ROOT / 'scripts' / 'registry_owner_volume_preflight.ps1'
OWNER=ROOT / 'docs' / 'RELEASE-REGISTRY-OWNER-VOLUMES.md'
CATALOG=ROOT / 'release' / 'targets.yaml'


class OwnerVolumeWindowsReadOnlySourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.code=SOURCE.read_text(encoding='utf-8')

    def test_exact_actions_and_no_mutations(self):
        s=self.code
        self.assertIn("[ValidateSet('Plan','Inventory')]",s)
        self.assertIn('Set-StrictMode -Version 2',s)
        self.assertIn("$Action -ceq 'Plan'",s)
        self.assertIn('E13B_OWNER_VOLUME_SOURCE_PLAN_ONLY',s)
        self.assertIn('E13B_OWNER_VOLUME_METADATA_READONLY_PASS',s)
        self.assertIn('E13B_USERNS_GROUPS_OWNERSHIP_WRITER_FENCE_UNKNOWN_STOP_BEFORE_CREATE',s)
        self.assertEqual(s.count("Write-Host 'E13B_OWNER_VOLUME_METADATA_READONLY_PASS'"),1)
        # Inspect code, not plain English comments, for mutations.
        code='\n'.join(line.split('#',1)[0].strip() for line in s.splitlines()
                       if line.strip() and not line.lstrip().startswith('#') and
                       not line.lstrip().lower().startswith('write-host')).lower()
        for forbidden in ('docker run', 'docker exec', 'docker volume create',
                          'docker volume rm', 'docker build', 'docker stop',
                          'docker restart', 'docker cp', 'docker pull',
                          '--privileged', 'cap-add', 'chown ', 'chmod ',
                          'set-acl', 'new-item', 'remove-item', 'invoke-expression'):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden,code)
        self.assertNotIn('host.docker.internal',code)
        self.assertNotIn('/var/run/docker.sock',code)

    def test_exact_guarded_source_and_image(self):
        s=self.code
        for marker in ('main', 'SOURCE_SHA_MISMATCH','SOURCE_NOT_CLEAN',
                       'SCRIPT_ORIGIN_NOT_MERGED_MAIN', 'desktop-linux',
                       'REGISTRY_IMAGE_IDENTITY_CHANGED', '20002:20002',
                       '10001:10001','1000:1000',
                       'org.opencontainers.image.revision',
                       'GATEWAY_NOT_HEALTHY', 'CONTAINER_BASELINE_CHANGED_',
                       'POSTREADBACK_CONTAINER_CHANGED',
                       'CONTAINER_SCAN_ID_CHANGED'):
            self.assertIn(marker,s)

    def test_exact_local_names_stop_before_creation(self):
        s=self.code
        for marker in ('fortis-registry-state-e13b-',
                       'fortis-registry-config-e13b-',
                       'fortis-registry-read',
                       "'^[0-9a-f]{8,32}$'", 'REGISTRY_VOLUME_NAME_ALREADY_RESERVED',
                       'EXISTING_CONTAINER_REGISTRY_MOUNT_CONFLICT',
                       'TARGET_VOLUME_ATTACHED',
                       "@('ps','-aq','--no-trunc')",
                       "@('volume','ls','--format','{{.Name}}')"):
            self.assertIn(marker,s)
        self.assertIn('scripts/**', CATALOG.read_text(encoding='utf-8'))
        self.assertNotIn('registry_owner_volume_preflight.ps1',
                         (ROOT / 'fortis_approvals' / 'deploy' /
                          'Dockerfile-Registry-Read-Candidate').read_text())

    def test_plan_never_leaks_docker_or_git_metadata(self):
        s=self.code
        plan=s.split("if ($Action -ceq 'Plan') {",1)[1].split('\n}',1)[0]
        self.assertNotIn('& docker',plan)
        self.assertNotIn('& git',plan)
        self.assertIn('return',plan)
        # Only emit bounded summary fields, not raw Docker JSON or environment.
        for marker in ('E13B_SELECTED_STATE_VOLUME=',
                       'E13B_SELECTED_CONFIG_VOLUME=',
                       'E13B_SELECTED_SOCKET_VOLUME=',
                       'E13B_CONTAINER_METADATA_SCANNED='):
            self.assertIn(marker,s)
        self.assertIn('NO HOST GO',OWNER.read_text(encoding='utf-8'))


if __name__ == '__main__':
    unittest.main()

"""Source-only volume planning guards; NOT a Windows/Docker host test."""
import ast
from pathlib import Path
import unittest
from unittest.mock import patch

from scripts.registry_owner_volume_contract import (
    PrivateVolumeRoot, plan_private_volume_roots,
)
from fortis_approvals.registry import owner_functional_v1_bootstrap as boot

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / 'scripts' / 'registry_owner_volume_contract.py'
LAUNCHER = ROOT / 'fortis_approvals' / 'deploy' / 'Registry-Owner-Bootstrap.ps1'
RUNBOOK = ROOT / 'docs' / 'RELEASE-REGISTRY-OWNER-VOLUMES.md'


class RegistryOwnerVolumeContractSourceTests(unittest.TestCase):
    def test_exact_three_distinct_mounts_and_identities(self):
        plan = plan_private_volume_roots('01234567abcdef89')
        self.assertEqual(len(plan), 3)
        self.assertEqual(len({v.name for v in plan}), 3)
        self.assertEqual(len({v.mount for v in plan}), 3)
        self.assertTrue(all(isinstance(v, PrivateVolumeRoot) for v in plan))
        self.assertEqual([(v.name, v.mount, v.uid, v.gid, v.mode) for v in plan], [
            ('fortis-registry-state-e13b-01234567abcdef89',
             str(boot.STATE_PATH.parent), 20002, 20002, 0o700),
            ('fortis-registry-config-e13b-01234567abcdef89',
             str(boot.CONFIG_PATH.parent), 20002, 20002, 0o700),
            ('fortis-registry-read', str(boot.SOCKET_PATH.parent), 20002, 10001, 0o2710),
        ])

    def test_rejects_ambiguous_or_invalid_owner_suffix(self):
        for value in ('', 'abc', '0123456', '0' * 33, 'AAAAAAAA', 'abCD1234',
                      'deadbeef/..', '../deadbeef', 'de-ad-beef',
                      ' deadbeef', 'deadbeef ', 'deadbeef\n', None, 1, True, [], {}):
            with self.subTest(value=value):
                with self.assertRaisesRegex(ValueError, 'REGISTRY_OWNER_VOLUME_SUFFIX_INVALID'):
                    plan_private_volume_roots(value)
        self.assertEqual(plan_private_volume_roots('a' * 8)[0].name,
                         'fortis-registry-state-e13b-' + 'a' * 8)
        self.assertEqual(plan_private_volume_roots('b' * 32)[1].name,
                         'fortis-registry-config-e13b-' + 'b' * 32)

    def test_has_no_host_or_filesystem_side_effects(self):
        # Restrict implementation to data definitions and pure deterministic validation.
        tree = ast.parse(SOURCE.read_text(encoding='utf-8'))
        imports = [a.name for node in tree.body
                   if isinstance(node, (ast.Import, ast.ImportFrom))
                   for a in node.names]
        self.assertEqual(set(imports), {'dataclass', 're'})
        code = SOURCE.read_text(encoding='utf-8').lower()
        for forbidden in ('subprocess', 'chown(', 'chmod(', 'os.open',
                          'pathlib', 'requests', 'shutil', 'mkdir('):
            self.assertNotIn(forbidden, code)
        with patch('builtins.open', side_effect=AssertionError('I/O denied')):
            rows = plan_private_volume_roots('01234567')
        self.assertEqual(len(rows), 3)

    def test_launcher_is_separate_and_requires_preexisting_volumes(self):
        launcher = LAUNCHER.read_text(encoding='utf-8')
        self.assertIn('^fortis-registry-state-e13b-[0-9a-f]{8,32}$', launcher)
        self.assertIn('^fortis-registry-config-e13b-[0-9a-f]{8,32}$', launcher)
        self.assertIn("'fortis-registry-read'", launcher)
        self.assertIn("'volume','inspect'", launcher)
        self.assertIn('REGISTRY_BOOTSTRAP_VOLUME_ALREADY_ATTACHED_', launcher)
        self.assertIn('volume-nocopy', launcher)
        self.assertNotIn("'volume','create'", launcher)
        catalog = (ROOT / 'release' / 'targets.yaml').read_text(encoding='utf-8')
        self.assertIn('  - scripts/**', catalog)
        self.assertNotIn('  - scripts/registry_owner_volume_contract.py', catalog)
        dockerfile = (ROOT / 'fortis_approvals' / 'deploy' /
                      'Dockerfile-Registry-Read-Candidate').read_text(encoding='utf-8')
        self.assertNotIn('registry_owner_volume_contract.py', dockerfile)

    def test_owner_provisioning_contract_is_explicitly_unapproved(self):
        body = RUNBOOK.read_text(encoding='utf-8')
        for marker in ('SOURCE-ONLY', 'NO HOST GO', '0700', '02710',
                       '20002:20002', '20002:10001', 'STOP',
                       'no automatic cleanup', 'fortis-registry-read',
                       'UC-CONT-021', 'UC-CONT-022', 'UC-CONT-025'):
            self.assertIn(marker, body)


if __name__ == '__main__':
    unittest.main()

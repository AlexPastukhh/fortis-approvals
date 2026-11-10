"""Offline Owner Shell release material preflight: no Windows/Docker effects."""
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock
from types import SimpleNamespace

from fortis_approvals.core import Denied
from fortis_approvals.owner_shell_release import verify_material, NAMES


class OwnerShellMaterialPreflightTests(unittest.TestCase):
    def setUp(self):
        root=tempfile.TemporaryDirectory()
        self.addCleanup(root.cleanup)
        self.root=Path(root.name)/'owner-shell'
        self.root.mkdir(mode=0o700)
        for name in NAMES:
            p=self.root/name
            p.write_text('s'*40)
            p.chmod(0o600)
        self.uid,self.gid=os.geteuid(),os.getegid()

    def verify(self):
        with mock.patch('fortis_approvals.owner_shell_release.OwnerShellClient',
                        return_value=SimpleNamespace(origin='https://host.docker.internal:10443')) as client:
            self.assertTrue(verify_material(self.root,uid=self.uid,gid=self.gid))
            self.assertEqual(client.call_args.kwargs['port'],10443)
            self.assertTrue(client.call_args.kwargs['client_key'].endswith('/client.key'))

    def test_exact_private_material_passes(self):
        self.verify()

    def test_parent_volume_root_may_remain_root_accessible(self):
        # The existing volume root is root:root/0755, whereas owner-shell is 0700.
        self.root.parent.chmod(0o755)
        self.verify()

    def test_non_private_root_mode_is_rejected(self):
        self.root.chmod(0o755)
        with self.assertRaisesRegex(RuntimeError,'OWNER_SHELL_DIRECTORY_INVALID'):
            self.verify()

    def test_non_private_client_key_is_rejected(self):
        (self.root/'client.key').chmod(0o644)
        with self.assertRaisesRegex(RuntimeError,'OWNER_SHELL_FILE_INVALID'):
            self.verify()

    def test_extra_files_are_rejected(self):
        (self.root/'extra').write_text('surprise')
        with self.assertRaisesRegex(RuntimeError,'OWNER_SHELL_FILES_CHANGED'):
            self.verify()

    def test_missing_files_are_rejected(self):
        (self.root/'secret.txt').unlink()
        with self.assertRaisesRegex(RuntimeError,'OWNER_SHELL_FILES_CHANGED'):
            self.verify()

    def test_symlink_is_rejected(self):
        target=self.root/'client.pem'
        (self.root/'client.key').unlink()
        (self.root/'client.key').symlink_to(target)
        with self.assertRaisesRegex(RuntimeError,'OWNER_SHELL_FILE_INVALID'):
            self.verify()

    def test_root_identity_drift_is_rejected(self):
        with self.assertRaisesRegex(RuntimeError,'OWNER_SHELL_DIRECTORY_INVALID'):
            verify_material(self.root,uid=self.uid+1,gid=self.gid)

    def test_bad_client_bearer_fails_closed(self):
        (self.root/'secret.txt').write_text('bad')
        with mock.patch('fortis_approvals.owner_shell.ssl.create_default_context') as context, \
                mock.patch('fortis_approvals.owner_shell.request.build_opener'):
            with self.assertRaisesRegex(Denied,'OWNER_SHELL_SECRET_INVALID'):
                verify_material(self.root,uid=self.uid,gid=self.gid)
            self.assertTrue(context.called)

    def test_invalid_ca_material_does_not_skip_tls_parsing(self):
        # Real SSL context must reject synthetic certificates; this is offline.
        with self.assertRaises(Exception):
            verify_material(self.root,uid=self.uid,gid=self.gid)


if __name__=='__main__':
    unittest.main()

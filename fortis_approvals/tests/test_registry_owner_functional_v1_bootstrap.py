"""Offline bootstrap-core tests: no Docker or host acceptance implied."""
import hashlib
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch

from fortis_approvals.core import Denied, canonical
from fortis_approvals.registry import owner_functional_v1_bootstrap as boot
from fortis_approvals.registry.state_journal import _scope
from fortis_approvals.tests.test_registry_state_journal import uid
from fortis_approvals.registry.boundary import REPOSITORY


class OwnerFunctionalV1BootstrapTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.spec_parent = root / 'input'
        self.state_parent = root / 'state'
        self.config_parent = root / 'config'
        self.socket_parent = root / 'socket'
        for directory in (self.spec_parent, self.state_parent,
                          self.config_parent, self.socket_parent):
            directory.mkdir(mode=0o700)
        self.spec_path = self.spec_parent / 'spec.json'
        self.state_path = self.state_parent / 'registry.sqlite'
        self.config_path = self.config_parent / 'profile.json'
        self.socket_path = self.socket_parent / 'reader.sock'
        self.uid = os.geteuid()
        self.gid = os.getegid()
        self.spec = {
            'schemaVersion': 1, 'instanceId': uid(),
            'scope': {'repository': REPOSITORY, 'enrollmentId': uid(),
                      'baselineSha': 'a' * 40, 'baselineDigest': 'a' * 64,
                      'catalogSha256': 'b' * 64, 'bindingDigest': 'c' * 64,
                      'policyReferenceDigest': 'd' * 64},
            'registryUid': self.uid, 'registryGid': self.gid,
            'readerUid': 10001 if self.uid != 10001 else 10002,
            'readerGid': 10001 if self.gid != 10001 else 10002,
        }
        for attr, path in (('STATE_PATH', self.state_path),
                           ('CONFIG_PATH', self.config_path),
                           ('SOCKET_PATH', self.socket_path)):
            patcher = patch.object(boot, attr, path)
            patcher.start()
            self.addCleanup(patcher.stop)
        # The test is a single-UID source fixture. No test process may chgrp
        # to the actual separately mapped reader GID; this bypass only keeps
        # socket-directory provisioning OUTSIDE the local test.
        self.real_directories = boot._directories
        def check_local_dirs(spec):
            boot._private_directory(self.state_parent, self.uid, self.gid, 0o700)
            boot._private_directory(self.config_parent, self.uid, self.gid, 0o700)
        patcher = patch.object(boot, '_directories', side_effect=check_local_dirs)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.write_spec()

    def write_spec(self):
        data = canonical(self.spec).encode('utf-8')
        self.spec_path.write_bytes(data)
        self.spec_path.chmod(0o600)
        self.digest = hashlib.sha256(data).hexdigest()

    def run_action(self, action, digest=None):
        return boot.run(action, spec_path=self.spec_path,
                        expected_spec_sha256=digest)

    def test_preview_is_read_only_and_reports_no_host_acceptance(self):
        before = set(self.spec_parent.iterdir())
        result = self.run_action('Preview')
        self.assertEqual(result['result'], 'SOURCE_ONLY_REGISTRY_BOOTSTRAP_PREVIEW')
        self.assertEqual(result['specSha256'], self.digest)
        self.assertFalse(result['hostAccepted'])
        self.assertFalse(result['admissionAllowed'])
        self.assertEqual(set(self.spec_parent.iterdir()), before)
        self.assertFalse(self.state_path.exists())
        self.assertFalse(self.config_path.exists())

    def test_provision_once_then_independent_verify(self):
        self.run_action('Preview')
        result = self.run_action('Provision', self.digest)
        self.assertEqual(result['result'], 'SOURCE_ONLY_REGISTRY_BOOTSTRAP_PROVISIONED')
        self.assertFalse(result['registryServiceStarted'])
        self.assertEqual(stat.S_IMODE(self.state_path.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(self.config_path.stat().st_mode), 0o600)
        self.assertEqual(self.config_path.read_bytes(), canonical({
            'schemaVersion': 1, 'instanceId': self.spec['instanceId'],
            'scope': _scope(self.spec['scope']),
            'registryStatePath': str(self.state_path),
            'socketPath': str(self.socket_path),
            'readerUid': self.spec['readerUid'],
            'readerGid': self.spec['readerGid'],
        }).encode('utf-8'))
        result = self.run_action('Verify', self.digest)
        self.assertEqual(result['result'], 'SOURCE_ONLY_REGISTRY_BOOTSTRAP_VERIFIED')
        self.assertFalse(result['hostAccepted'])
        with self.assertRaisesRegex(Denied, 'EXISTING_STATE_STOP'):
            self.run_action('Provision', self.digest)
        with self.assertRaisesRegex(Denied, 'EXISTING_STATE_STOP'):
            self.run_action('Preview')

    def test_provision_pin_wrong_no_effect(self):
        with self.assertRaisesRegex(Denied, 'SPEC_PIN_CHANGED'):
            self.run_action('Provision', '0' * 64)
        with self.assertRaisesRegex(Denied, 'SPEC_PIN_REQUIRED'):
            self.run_action('Provision')
        self.assertFalse(self.state_path.exists())

    def test_fails_closed_on_existing_profile_or_database(self):
        self.config_path.write_text('do-not-overwrite')
        with self.assertRaisesRegex(Denied, 'EXISTING_STATE_STOP'):
            self.run_action('Provision', self.digest)
        self.assertEqual(self.config_path.read_text(), 'do-not-overwrite')
        self.assertFalse(self.state_path.exists())

    def test_spec_rejects_unknown_fields_and_noncanonical_bytes(self):
        self.spec['newGrant'] = True
        self.write_spec()
        with self.assertRaisesRegex(Denied, 'SPEC_INVALID'):
            self.run_action('Preview')
        del self.spec['newGrant']
        self.write_spec()
        self.spec_path.write_bytes(self.spec_path.read_bytes() + b'\n')
        with self.assertRaises(Denied):
            self.run_action('Preview')

    def test_spec_rejects_wrong_uid_and_wide_permissions(self):
        self.spec['registryUid'] = self.uid + 1
        self.write_spec()
        with self.assertRaisesRegex(Denied, 'IDENTITY_DENIED'):
            self.run_action('Preview')
        self.spec['registryUid'] = self.uid
        self.write_spec()
        self.spec_path.chmod(0o644)
        with self.assertRaisesRegex(Denied, 'FILE_INVALID'):
            self.run_action('Preview')

    def test_verify_fails_closed_on_config_tamper(self):
        self.run_action('Provision', self.digest)
        self.config_path.write_bytes(b'{}')
        with self.assertRaisesRegex(Denied, 'CONFIG_CHANGED'):
            self.run_action('Verify', self.digest)

    def test_verify_fails_closed_on_schema_downgrade(self):
        self.run_action('Provision', self.digest)
        import sqlite3
        with sqlite3.connect(self.state_path) as con:
            con.execute('PRAGMA user_version=2')
        with self.assertRaises(Denied):
            self.run_action('Verify', self.digest)

    def test_directory_owner_mode_fail_closed(self):
        self.assertIsNotNone(self.real_directories)
        self.state_parent.chmod(0o755)
        with self.assertRaisesRegex(Denied, 'DIRECTORY_INVALID'):
            self.run_action('Provision', self.digest)
        self.assertFalse(self.state_path.exists())


if __name__ == '__main__':
    unittest.main()

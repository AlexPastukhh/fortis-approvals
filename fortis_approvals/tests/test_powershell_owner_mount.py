"""Owner mount safety; no real TLS secrets or Windows execution."""
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from fortis_approvals.powershell_machine import (
    ACCEPTED_EXECUTOR_GIT_SHA, EXECUTOR_IDENTITY, MachinePowerShellAdapter,
)
from fortis_approvals.powershell_owner_mount import FILES, load_machine_shell_mount

ACTOR="repo-sonar-read-proposal-actor"
PROFILE={
    "version":1, "enabled":True, "actor":ACTOR, "target":"windows-owner",
    "executorGitSha":ACCEPTED_EXECUTOR_GIT_SHA, "executorIdentity":EXECUTOR_IDENTITY,
    "mode":"ASK_ONLY",
}


class FakeTransport:
    key=b"test-only-key-shared-with-fixture-32bytes"
    def execute(self, *args, **kwargs):
        raise AssertionError("MOUNT_MUST_NOT_DISPATCH")
    def status(self, *args, **kwargs):
        raise AssertionError("MOUNT_MUST_NOT_QUERY_EXECUTOR")


class MachineMountTests(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root=Path(tmp.name)/"mount"
        self.root.mkdir(mode=0o700)
        for name in FILES:
            path=self.root/name
            data=(json.dumps(PROFILE).encode() if name=="profile.json" else
                  b"synthetic-stand-in")
            path.write_bytes(data)
            path.chmod(0o600)

    def read(self):
        with patch("fortis_approvals.powershell_owner_mount.MachineShellTransport",
                   return_value=FakeTransport()):
            return load_machine_shell_mount(expected_actor=ACTOR,root=self.root)

    def test_absent_mount_disabled_not_error(self):
        self.assertIsNone(load_machine_shell_mount(
            expected_actor=ACTOR,root=self.root/"nonexistent"))

    def test_valid_mount_returns_disabled_until_explicit_composition(self):
        adapter=self.read()
        self.assertIs(type(adapter), MachinePowerShellAdapter)
        self.assertIsNone(adapter.core)
        self.assertEqual(adapter.target, "windows-owner")

    def test_missing_or_extra_file_denied(self):
        (self.root/"bearer").unlink()
        with self.assertRaises(RuntimeError):
            self.read()
        (self.root/"extra").write_text("unexpected")
        with self.assertRaises(RuntimeError):
            self.read()

    def test_wrong_actor_and_configurable_allow_denied(self):
        with self.assertRaises(RuntimeError):
            load_machine_shell_mount(expected_actor="foreign-ai",root=self.root)
        for value in (False, "ASK_ONLY", None):
            bad=dict(PROFILE,enabled=value)
            (self.root/"profile.json").write_text(json.dumps(bad))
            with self.assertRaises(RuntimeError):
                self.read()
        (self.root/"profile.json").write_text(json.dumps(dict(PROFILE,mode="ALLOW")))
        with self.assertRaises(RuntimeError):
            self.read()

    def test_unpinned_executor_commit_and_claimed_identity_denied(self):
        original=(self.root/"profile.json").read_bytes()
        for change in (
            {"executorGitSha":"0"*40},
            {"executorGitSha":"0"*64},
            {"executorGitSha":"BAD"},
            {"executorIdentity":"another-windows-account"},
            {"target":"other-target"},
            {"sourceSha256":"0"*64},
        ):
            bad=dict(PROFILE,**change)
            if "sourceSha256" in change:
                bad.pop("executorGitSha")
            with self.subTest(change=change), self.assertRaises(RuntimeError):
                (self.root/"profile.json").write_text(json.dumps(bad))
                self.read()
        (self.root/"profile.json").write_bytes(original)

    def test_wrong_ownership_modes_and_symlink_denied(self):
        self.root.chmod(0o755)
        with self.assertRaises(RuntimeError):
            self.read()
        self.root.chmod(0o700)
        (self.root/"proof-key").chmod(0o644)
        with self.assertRaises(RuntimeError):
            self.read()
        (self.root/"proof-key").chmod(0o600)
        (self.root/"proof-key").unlink()
        (self.root/"proof-key").symlink_to(self.root/"bearer")
        with self.assertRaises(RuntimeError):
            self.read()

    def test_duplicate_json_keys_denied(self):
        (self.root/"profile.json").write_text(
            json.dumps(PROFILE).replace('"enabled": true',
               '"enabled": true,"enabled": true'))
        with self.assertRaises(RuntimeError):
            self.read()


if __name__ == "__main__":
    unittest.main()

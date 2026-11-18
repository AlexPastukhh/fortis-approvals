"""Offline contract checks: no Gateway installation or PowerShell execution."""
import hashlib
import unittest

from scripts.powershell_machine_contract import (
    ACCEPTED_EXECUTOR_GIT_SHA, EXECUTOR_IDENTITY,
    MachineShellContractError, canonical, frozen_preview, validate_submit,
)

UUID4 = "01234567-89ab-4def-8abc-0123456789ab"
TARGETS = frozenset({"windows-owner"})
CTX = {
    "actor": "fortis-repo", "contractVersion": 1, "contractDigest": "a" * 64,
    "profile": "ps-literals-v1", "executorIdentity": EXECUTOR_IDENTITY,
    "workingDirectory": "%USERPROFILE%", "executorGitSha": ACCEPTED_EXECUTOR_GIT_SHA,
    "timeoutSeconds": 60, "outputLimitBytes": 65536,
}


class MachinePowerShellContractTests(unittest.TestCase):
    def body(self, command="Get-Date"):
        return {"requestId": UUID4, "target": "windows-owner", "command": command}

    def deny(self, body, expected=None):
        with self.assertRaises(MachineShellContractError) as error:
            validate_submit(body, registered_targets=TARGETS)
        if expected is not None:
            self.assertEqual(str(error.exception), expected)

    def test_valid_request_is_only_syntax_not_permission(self):
        self.assertEqual(validate_submit(self.body(), registered_targets=TARGETS), self.body())
        self.assertEqual(frozen_preview(self.body(), registered_targets=TARGETS,
                                        trusted_context=CTX)["preview"]["disposition"], "ASK_ONLY")

    def test_arbitrary_command_syntax_still_requires_ask(self):
        # Syntax alone cannot determine which owner-managed rules permit ASK.
        submitted = self.body("Remove-Item foo")
        self.assertEqual(validate_submit(submitted, registered_targets=TARGETS), submitted)
        self.assertEqual(frozen_preview(submitted, registered_targets=TARGETS,
                          trusted_context=CTX)["preview"]["disposition"], "ASK_ONLY")

    def test_reject_extra_fields_that_choose_executor_authority(self):
        for name, value in [
            ("url", "http://evil"), ("port", 9999), ("bearer", "secret"),
            ("policy", {"allow": True}), ("proof", "fake"),
            ("actor", "owner"), ("cwd", "C:\\"),
            ("execute", True), ("allow", True),
        ]:
            with self.subTest(name=name):
                self.deny({**self.body(), name: value}, "MACHINE_SHELL_SUBMIT_SCHEMA_DENIED")

    def test_reject_missing_and_wrong_submit_shape(self):
        self.deny({"target": "windows-owner", "command": "Get-Date"})
        self.deny(["Get-Date"])
        self.deny(None)
        self.deny({**self.body(), "requestId": 42}, "MACHINE_SHELL_UUID_DENIED")

    def test_reject_uuid_version_case_and_format(self):
        for ident in [
            "00000000-0000-1000-8000-000000000000",
            "01234567-89AB-4DEF-8ABC-0123456789AB", "x",
            "{01234567-89ab-4def-8abc-0123456789ab}",
        ]:
            with self.subTest(ident=ident):
                self.deny({**self.body(), "requestId": ident}, "MACHINE_SHELL_UUID_DENIED")

    def test_target_must_come_from_explicit_trusted_registry(self):
        for bad in ["windows-other", "https://127.0.0.1:10443", "localhost",
                    "../windows-owner", "Windows-Owner"]:
            with self.subTest(bad=bad):
                self.deny({**self.body(), "target": bad}, "MACHINE_SHELL_TARGET_DENIED")
        with self.assertRaises(MachineShellContractError):
            validate_submit(self.body(), registered_targets=frozenset())

    def test_reject_invalid_commands(self):
        for bad in ["", "  \r\n  ", "\x00", "Get-Date\x00", 25, None,
                    "x" * 8193, "\ud800"]:
            with self.subTest(repr=repr(bad)):
                self.deny(self.body(bad), "MACHINE_SHELL_COMMAND_DENIED")

    def test_command_byte_ceiling_is_utf8(self):
        valid = "а" * 4096
        self.assertEqual(len(valid.encode("utf-8")), 8192)
        self.assertEqual(validate_submit(self.body(valid), registered_targets=TARGETS)["command"], valid)
        self.deny(self.body(valid + "а"), "MACHINE_SHELL_COMMAND_DENIED")

    def test_exact_command_bytes_and_identity_bound_in_preview(self):
        a = frozen_preview(self.body("Get-Date"), registered_targets=TARGETS, trusted_context=CTX)
        b = frozen_preview(self.body("Get-Date\r\n"), registered_targets=TARGETS, trusted_context=CTX)
        self.assertNotEqual(a["previewSha256"], b["previewSha256"])
        self.assertEqual(a["preview"]["commandSha256"],
                         hashlib.sha256(b"Get-Date").hexdigest())
        self.assertEqual(a["previewSha256"], hashlib.sha256(canonical(a["preview"])).hexdigest())
        self.assertNotIn("proof", a["preview"])
        self.assertNotIn("credential", a["preview"])

    def test_contract_actor_target_and_source_binding_changes_fingerprint(self):
        base = frozen_preview(self.body(), registered_targets=TARGETS, trusted_context=CTX)
        for name, value in [
            ("actor", "other-actor"), ("contractVersion", 2),
            ("contractDigest", "0" * 64), ("profile", "other-profile"),
            ("workingDirectory", "X:\\"), ("timeoutSeconds", 1),
            ("outputLimitBytes", 100),
        ]:
            with self.subTest(name=name):
                altered = {**CTX, name: value}
                newer = frozen_preview(self.body(), registered_targets=TARGETS,
                                       trusted_context=altered)
                self.assertNotEqual(base["previewSha256"], newer["previewSha256"])

    def test_reject_untrusted_or_invalid_context(self):
        for bad in [
            {**CTX, "bearer": "x"}, {**CTX, "contractDigest": "BAD"},
            {**CTX, "contractVersion": 0}, {**CTX, "timeoutSeconds": 61},
            {**CTX, "outputLimitBytes": 65537}, {**CTX, "actor": ""},
            {**CTX, "executorGitSha": "abc"}, {**CTX, "executorGitSha": "0"*40},
            {**CTX, "executorGitSha": "0"*64},
            {**CTX, "executorIdentity": "another-user"}, {**CTX, "executorIdentity": ""},
            {**CTX, "sourceSha256": "a"*64},
            {**CTX, "profile": "../bad"},
        ]:
            with self.subTest(keys=list(bad)):
                with self.assertRaises(MachineShellContractError):
                    frozen_preview(self.body(), registered_targets=TARGETS,
                                   trusted_context=bad)

    def test_offline_contract_pin_matches_runtime_source(self):
        from fortis_approvals.powershell_machine import (
            ACCEPTED_EXECUTOR_GIT_SHA as runtime_sha,
            EXECUTOR_IDENTITY as runtime_identity,
        )
        self.assertEqual(ACCEPTED_EXECUTOR_GIT_SHA, runtime_sha)
        self.assertEqual(EXECUTOR_IDENTITY, runtime_identity)
        self.assertEqual(
            frozen_preview(self.body(), registered_targets=TARGETS,
                           trusted_context=CTX)["preview"]["executorGitSha"],
            runtime_sha)

    def test_schema_error_never_includes_command(self):
        sensitive = "password-only-in-test-marker-" + "x" * 8193
        with self.assertRaises(MachineShellContractError) as error:
            validate_submit(self.body(sensitive), registered_targets=TARGETS)
        self.assertNotIn(sensitive[:30], str(error.exception))

    def test_canonical_json_rejects_unsafe_nonfinite(self):
        with self.assertRaises(MachineShellContractError):
            canonical({"value": float("nan")})


if __name__ == "__main__":
    unittest.main()

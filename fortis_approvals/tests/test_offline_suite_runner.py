"""Offline runner contract: mandatory suite membership and fail-closed results."""
import contextlib
import importlib.util
import io
import json
from unittest.mock import patch
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("offline_runner", ROOT / "scripts/run-offline-suites.py")
RUNNER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RUNNER)


class OfflineRunnerTests(unittest.TestCase):
    def test_provider_and_explicit_suite_membership(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "fortis_approvals/tests").mkdir(parents=True)
            (root / "fortis_approvals/tests/test_x.py").touch()
            for name in ("b", "a"):
                (root / "fortis_approvals/integrations" / name / "tests").mkdir(parents=True)
            commands = RUNNER.suite_commands(root, sys.executable, ["test_x.py"])
            self.assertEqual([label for label, _ in commands], [
                "fortis_approvals/integrations/a/tests",
                "fortis_approvals/integrations/b/tests", "test_x.py"])
            self.assertEqual(commands[-1][1][-3:], ["-p", "test_x.py", "-v"])
            with self.assertRaises(ValueError):
                RUNNER.suite_commands(root, sys.executable, ["test_missing.py"])
            with self.assertRaises(ValueError):
                RUNNER.suite_commands(root, sys.executable, ["test_x.py", "test_x.py"])

    def test_expansion_preserves_exact_membership_and_module_boundaries(self):
        github = ["test_a.C.test_a", "test_a.C.test_b", "test_b.C.test_a"]
        native = ["test_native_workflow.C.test_a", "test_native_workflow.C.test_b"]
        commands = [
            ("fortis_approvals/integrations/github/tests", ["old-github"]),
            ("test_native_workflow.py", ["old-native"]),
            ("test_other.py", ["other"]),
        ]
        with patch.object(RUNNER.subprocess, "check_output",
                          side_effect=[json.dumps(github), json.dumps(native)]):
            expanded = RUNNER.expanded_commands(ROOT, sys.executable, commands)
        flat = RUNNER.ordered_commands(expanded)
        self.assertEqual(flat, RUNNER.ordered_commands(list(reversed(expanded))))
        self.assertEqual(len(flat), 5)
        self.assertEqual(set(label for label, _ in flat),
                         {label for _, label, _ in expanded})
        selected = [name for label, cmd in flat if ":" in label for name in cmd[4:]]
        self.assertCountEqual(selected, github + native)
        self.assertEqual(dict(flat)["github:test_a"][4:], github[:2])
        with self.assertRaises(ValueError):
            RUNNER.ordered_commands(expanded + [expanded[0]])

    def test_invalid_discovery_fails_closed(self):
        commands = [("test_native_workflow.py", ["old-native"])]
        for ids in ([], ["duplicate", "duplicate"]):
            with patch.object(RUNNER.subprocess, "check_output", return_value=json.dumps(ids)):
                with self.assertRaises(ValueError):
                    RUNNER.expanded_commands(ROOT, sys.executable, commands)

    def test_failure_and_empty_suite_cannot_pass(self):
        commands = [
            ("pass", [sys.executable, "-c", "print('PASS')"]),
            ("failure", [sys.executable, "-c", "raise SystemExit(7)"]),
            ("empty", [sys.executable, "-c", "print('Ran 0 tests')"]),
        ]
        for workers in (1, 2, 4):
            with self.subTest(workers=workers):
                output = io.StringIO()
                with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
                    result = RUNNER.run_all(ROOT, commands, workers)
                self.assertEqual(result, 1)
                self.assertIn("suites=3/3", output.getvalue())
                self.assertIn("failed=2", output.getvalue())
                self.assertIn("PASS", output.getvalue())

    def test_all_pass_and_no_suites(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(RUNNER.run_all(ROOT, [
                ("pass", [sys.executable, "-c", "print('ok')"])
            ], 2), 0)
            self.assertEqual(RUNNER.run_all(ROOT, [], 2), 1)

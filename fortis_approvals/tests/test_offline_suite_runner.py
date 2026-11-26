"""Offline runner contract: mandatory suite membership and fail-closed results."""
import contextlib
import importlib.util
import io
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

    def test_failure_and_empty_suite_cannot_pass(self):
        commands = [
            ("pass", [sys.executable, "-c", "print('PASS')"]),
            ("failure", [sys.executable, "-c", "raise SystemExit(7)"]),
            ("empty", [sys.executable, "-c", "print('Ran 0 tests')"]),
        ]
        for workers in (1, 2):
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

"""Extraction source safety and reproducibility; only temporary local Git fixtures."""
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "executor_extraction", ROOT / "scripts/extract-powershell-executor.py")
TOOL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(TOOL)


class ExtractionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.source = self.root / "source"
        self.source.mkdir()
        self.run_git("init", "--initial-branch=main")
        self.run_git("config", "user.name", "Extraction fixture")
        self.run_git("config", "user.email", "fixture@example.invalid")
        self.run_git("remote", "add", "origin",
                     "https://github.com/AlexPastukhh/docke-windows-mirror.git")
        fixtures = {
            "mirror_api/owner_shell.py": b'"""Fixture runner, unchanged by extraction."""\nX = 1\n',
            "Start-OwnerPowerShellExecutor.ps1":
                b"#requires -Version 5.1\n& $py -3 -m mirror_api.owner_shell\n",
            "test_mirror_owner_shell.py":
                b"import mirror_api.owner_shell\nTARGET = 'mirror_api.owner_shell.os.name'\n",
            ".github/workflows/release-impact.yml": b"name: Fixture release impact\n",
        }
        for name, data in fixtures.items():
            p = self.source / name
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(data)
        self.commit()
        self.output = self.root / "candidate"

    def run_git(self, *args):
        return subprocess.check_output(
            ["git", "-c", "core.hooksPath=/dev/null", "-C", str(self.source), *args],
            stderr=subprocess.DEVNULL).decode().strip()

    def commit(self):
        self.run_git("add", ".")
        self.run_git("commit", "-m", "fixture source")
        self.sha = self.run_git("rev-parse", "HEAD")

    def export(self, **kw):
        return TOOL.export_source(
            kw.get("source", self.source), kw.get("output", self.output),
            kw.get("sha", self.sha))

    def test_worker_unchanged_and_only_module_references_relocated(self):
        receipt = self.export()
        worker = self.output / "fortis_powershell_executor/owner_shell.py"
        self.assertEqual((self.source / TOOL.INPUTS[0]).read_bytes(), worker.read_bytes())
        self.assertEqual(
            (self.source / TOOL.INPUTS[1]).read_bytes().replace(
                b"-m mirror_api.owner_shell", b"-m fortis_powershell_executor.owner_shell"),
            (self.output / TOOL.INPUTS[1]).read_bytes())
        self.assertNotIn(
            b"mirror_api.owner_shell", (self.output / "tests/test_owner_shell.py").read_bytes())
        self.assertEqual("SOURCE_CANDIDATE_NOT_INSTALLED", receipt["status"])
        self.assertFalse(receipt["hostChanged"])
        self.assertFalse(receipt["machineExecutionAdded"])
        self.assertEqual([], receipt["licenseFiles"])
        self.assertFalse((self.output / "LICENSE").exists())
        for name, digest in receipt["outputs"].items():
            self.assertEqual(digest, hashlib.sha256((self.output / name).read_bytes()).hexdigest())
        self.assertFalse((self.output / ".git").exists())

    def test_outputs_are_reproducible_without_absolute_paths(self):
        first = self.export()
        second = self.export(output=self.root / "candidate-two")
        self.assertEqual(first, second)
        for name in [*first["outputs"], "SOURCE-PROVENANCE.json"]:
            self.assertEqual((self.output / name).read_bytes(),
                             (self.root / "candidate-two" / name).read_bytes())
        self.assertNotIn(str(self.root), json.dumps(first))

    def test_wrong_sha_is_rejected_before_output(self):
        with self.assertRaisesRegex(TOOL.ExtractionError, "SOURCE_SHA_CHANGED"):
            self.export(sha="0" * 40)
        self.assertFalse(self.output.exists())

    def test_wrong_origin_is_rejected_before_output(self):
        self.run_git("remote", "set-url", "origin", "https://example.invalid/other.git")
        with self.assertRaisesRegex(TOOL.ExtractionError, "SOURCE_ORIGIN_DENIED"):
            self.export()
        self.assertFalse(self.output.exists())

    def test_dirty_source_is_rejected_without_losing_its_changes(self):
        p = self.source / TOOL.INPUTS[0]
        p.write_text("owner changes\n")
        with self.assertRaisesRegex(TOOL.ExtractionError, "SOURCE_DIRTY"):
            self.export()
        self.assertEqual("owner changes\n", p.read_text())
        self.assertFalse(self.output.exists())

    def test_untracked_source_is_rejected(self):
        (self.source / "notes.txt").write_text("fixture")
        with self.assertRaisesRegex(TOOL.ExtractionError, "SOURCE_DIRTY"):
            self.export()

    def test_non_main_is_rejected(self):
        self.run_git("switch", "-c", "feature")
        with self.assertRaisesRegex(TOOL.ExtractionError, "SOURCE_NOT_MAIN"):
            self.export()

    def test_existing_destination_is_preserved(self):
        self.output.mkdir()
        marker = self.output / "owner.txt"
        marker.write_text("preserve")
        with self.assertRaisesRegex(TOOL.ExtractionError, "OUTPUT_MUST_BE_NEW"):
            self.export()
        self.assertEqual("preserve", marker.read_text())

    def test_tracked_unrelated_private_file_is_not_exported(self):
        (self.source / "fixture.secret").write_text("synthetic-private-fixture")
        self.commit()
        result = self.export()
        self.assertNotIn("fixture.secret", result["outputs"])
        self.assertFalse((self.output / "fixture.secret").exists())

    def test_source_symlink_is_rejected(self):
        alias = self.root / "alias"
        try:
            alias.symlink_to(self.source, target_is_directory=True)
        except OSError:
            self.skipTest("symlink unavailable")
        with self.assertRaisesRegex(TOOL.ExtractionError, "SOURCE_ROOT_INVALID"):
            self.export(source=alias)

    def test_symlink_input_is_rejected(self):
        p = self.source / TOOL.INPUTS[0]
        p.unlink()
        try:
            p.symlink_to(self.source / TOOL.INPUTS[1])
        except OSError:
            self.skipTest("symlink unavailable")
        self.commit()
        with self.assertRaisesRegex(TOOL.ExtractionError, "SOURCE_FILE_NOT_REGULAR"):
            self.export()


if __name__ == "__main__":
    unittest.main()

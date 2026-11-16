#!/usr/bin/env python3
"""Prepare standalone Windows Executor source; no GitHub or host effects."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

SOURCE_REPOSITORY = "AlexPastukhh/docke-windows-mirror"
INPUTS = ("mirror_api/owner_shell.py", "Start-OwnerPowerShellExecutor.ps1",
          "test_mirror_owner_shell.py", ".github/workflows/release-impact.yml")
PACKAGE = "fortis_powershell_executor"


class ExtractionError(ValueError):
    pass


def git(root, *args):
    result = subprocess.run(
        ["git", "--no-pager", "-c", "core.fsmonitor=false", "-c",
         "core.hooksPath=/dev/null", "-C", str(root), *args],
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env={**os.environ, "GIT_TERMINAL_PROMPT": "0"})
    if result.returncode:
        raise ExtractionError("SOURCE_GIT_CHECK_FAILED")
    return result.stdout


def read_blob(root, name):
    row = git(root, "ls-tree", "HEAD", "--", name).decode().strip()
    if not row or row.split()[0] not in ("100644", "100755"):
        raise ExtractionError("SOURCE_FILE_NOT_REGULAR")
    path = root / name
    if path.is_symlink() or not path.is_file():
        raise ExtractionError("SOURCE_FILE_NOT_REGULAR")
    return git(root, "show", "HEAD:" + name)


def templates():
    return {
        ".gitignore": """__pycache__/
*.py[cod]
.venv/
.env
.env.*
private/
state/
*.key
*.pem
*.pfx
*.p12
*.token
*.secret
*.sqlite*
*.db
*.db-*
""",
        ".gitattributes": "* text=auto eol=lf\n",
        PACKAGE + "/__init__.py": '"""Standalone owner-only Fortis Windows PowerShell Executor."""\n',
        "README.md": """# Fortis PowerShell Executor

Standalone source for the existing Windows PowerShell 5.1 Executor.
Source extraction is not installation or live acceptance.

## Scope

The baseline accepts only the trusted Owner Portal transport using mTLS and
an independent bearer. It is one-shot, noninteractive and non-admin.
It does not yet implement Repo machine ASK, an approval proof or command rules.
Those are the next stages in the [Gateway plan](https://github.com/AlexPastukhh/fortis-approvals/blob/main/docs/BACKLOG-IMPROVEMENTS.md#powershell-plan).

The runner is byte-identical to its recorded original Git blob.
Only package/test imports and the launcher module name are relocated.
Mirror, Browser Pull and Git synchronization are not runtime dependencies.
Gateway continues to use the same HTTPS API, not this Python package.

Run offline tests from this source root:

§python -B -m unittest discover -s tests -v§

Use the existing certificates, protected settings and SAME EXISTING receipt DB.
Do not start this candidate next to the old listener or create a replacement DB.
See [API](docs/API.md), [migration](docs/MIGRATION.md) and
[SOURCE-PROVENANCE.json](SOURCE-PROVENANCE.json).

No license is selected by this extraction tool. The owner controls repository
visibility and licensing during bootstrap. Historical source remains attributable
to the original repository/commit recorded in the provenance document.
""",
        "AGENTS.md": """# Fortis PowerShell Executor

Start with /workspace/repo/README.md and /workspace/repo/AGENTS.md, the short
Fortis container registry entry and mandatory UC-CONT-002/003 and UC-GW-009.
Primary stays on clean main; edits/tests/commits use a registered task worktree.
GitHub operations use only the supported typed Fortis Gateway.
Source/CI does not install a Windows listener or grant machine execution.
Preserve installed TLS material, protected configuration and existing receipts.
Current code is the owner-only baseline; Repo AI execution remains unavailable
until the separately reviewed ASK-only contract/release/live acceptance.
""",
        "docs/API.md": """# Owner-only Executor baseline API

This source move preserves the existing protocol. It does not add a machine API.

- Owner-managed Windows bind: 127.0.0.1:10443; Gateway uses
  https://host.docker.internal:10443 with the existing server identity.
- Mandatory TLS client certificate and independent Bearer credential.
- GET /owner-shell/v1/capabilities and /owner-shell/v1/results/<UUID>.
- POST /owner-shell/v1/execute accepts exactly command and requestId.
- Idempotency-Key must equal requestId. UUID binds the exact command digest.
- Command limit 8192 UTF-8 bytes, timeout 60 seconds, output bound 65536 bytes
  for each stdout/stderr stream. One PowerShell 5.1 process, no profile/stdin.
- Durable reserve before launch. Same UUID never launches a second execution;
  different content under that UUID is a conflict. UNCERTAIN/DISPATCHED blocks
  another effect on that receipt store until reviewed recovery.
- Nonzero exit is not proof that no side effect occurred.

The current Windows process has its user's ordinary permissions; this is not
a sandbox. The API itself cannot independently prove human approval.
Keep its TLS client key and bearer away from Repo machine callers.
Full Windows session/TLS/receipt/restart acceptance is separate from offline CI.
Gateway owner-session/Host/Origin/CSRF checks remain owned by fortis-approvals.
""",
        "docs/MIGRATION.md": """# Source extraction and Windows handoff

Status: SOURCE CANDIDATE; no host installation/cutover is implied.

1. Owner creates the agreed repository with an initial main commit, chooses
   visibility/license, then provides its HTTPS URL. Follow UC-CONT-027 and
   typed Gateway bootstrap before importing this candidate into a task.
2. Import the exact reviewed candidate, preserve provenance, run source CI and
   Release Impact, obtain owner merge and sync the new Windows primary clone.
3. Update the Script Center adapter/resolver to validate the canonical
   %USERPROFILE%\\Repos\\fortis-powershell-executor clone and approved origin/main.
   It must retain existing setup/config/ACL/non-admin/port/source-change checks.
4. Keep the same cert/key/client CA/bearer files and SAME EXISTING SQLite DB,
   including historical receipts and unresolved states. Keep protected launch
   settings. No new empty DB, certificate issuance or forced setup.
5. Record the actual old source/identity/bind/config and in-flight/unresolved
   state. Perform reviewed quiescence and an owner-controlled switch with only
   one listener. Do not infer that a missing parent means no detached child.
6. Probe the unchanged API from Gateway, verify historical receipt reads and
   replay/conflict/timeout/restart behavior. A new harmless command uses a new
   UUID from the existing authenticated owner Portal.
7. Retire the old implementation only after live acceptance and retained
   rollback. Do not develop two authoritative copies.

Rollback stops the new listener before returning to the old source/launcher.
Use the same CURRENT receipt DB and TLS/config. Do not restore an older DB
snapshot that forgets newly reserved UUIDs or results. Ambiguity requires
reviewed recovery, not replay or manual ledger editing.

A source move with unchanged API/config does not need a Gateway image rebuild.
Machine ASK and owner-editable restrictions remain separate subsequent stages.
See the authoritative plan in fortis-approvals for owner release/acceptance.
""",
        "release/targets.yaml": """schemaVersion: 1
repository: fortis-powershell-executor
buildUnits: []
targets:
  - id: windows-powershell-executor
    inputs:
      - "*.ps1"
      - fortis_powershell_executor/**
    deployment:
      kind: windows-source
      procedure: docs/MIGRATION.md
      environments: [windows-owner]
    verification:
      - source-ci
      - windows-powershell-parse
      - owner-exact-source-cutover
      - existing-receipt-readback
noDeploymentPaths:
  - README.md
  - AGENTS.md
  - docs/**
  - tests/**
  - .github/**
  - .gitignore
  - .gitattributes
  - release/**
  - SOURCE-PROVENANCE.json
""",
        ".github/workflows/source-ci.yml": """name: Executor source CI
on:
  pull_request:
    branches: [main]
  push:
    branches: [main]
permissions:
  contents: read
jobs:
  source:
    strategy:
      matrix:
        os: [ubuntu-latest, windows-latest]
    runs-on: MATRIX_OS
    timeout-minutes: 5
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      - name: Offline worker and receipt compatibility
        run: python -B -m unittest discover -s tests -v
      - name: Windows PowerShell 5.1 parse only
        if: runner.os == 'Windows'
        shell: powershell
        run: |
          $tokens = $null
          $errors = $null
          [void][System.Management.Automation.Language.Parser]::ParseFile(
            (Join-Path $PWD 'Start-OwnerPowerShellExecutor.ps1'),
            [ref]$tokens, [ref]$errors)
          if (@($errors).Count -ne 0) { throw 'EXECUTOR_POWERSHELL_PARSE_FAILED' }
          Write-Host 'EXECUTOR_POWERSHELL_PARSE_PASS'
""",
        "tests/test_receipt_compatibility.py": r'''"""Legacy ledger fixtures: no PowerShell or installed data is used."""
import hashlib
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest

from fortis_powershell_executor.owner_shell import ShellDenied, ShellWorker

RID = "12345678-1234-4234-8234-123456789abc"
OTHER = "22345678-1234-4234-8234-123456789abc"


class LegacyReceipts(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db = Path(self.tmp.name) / "existing.sqlite"
        self.calls = []
        with sqlite3.connect(self.db) as conn:
            conn.execute("CREATE TABLE shell_receipts (request_id TEXT PRIMARY KEY, "
                         "command_sha256 TEXT NOT NULL,state TEXT NOT NULL,result TEXT)")

    def worker(self):
        def runner(command):
            self.calls.append(command)
            raise AssertionError("legacy replay must not execute")
        return ShellWorker(self.db, runner=runner)

    def seed(self, state, result=None):
        digest = hashlib.sha256(b"Get-Date").hexdigest()
        with sqlite3.connect(self.db) as conn:
            conn.execute("INSERT INTO shell_receipts VALUES (?,?,?,?)",
                         (RID, digest, state, json.dumps(result) if result else None))

    def test_existing_receipt_is_returned_after_relocation_and_restart(self):
        result = {"requestId": RID, "state": "EXECUTED", "exitCode": 0,
                  "commandSha256": hashlib.sha256(b"Get-Date").hexdigest(),
                  "stdout": "old Windows result", "stderr": ""}
        self.seed("EXECUTED", result)
        self.assertEqual(result, self.worker().status(RID))
        self.assertEqual(result, self.worker().run(
            {"requestId": RID, "command": "Get-Date"}))
        with self.assertRaisesRegex(ShellDenied, "REQUEST_ID_CONFLICT"):
            self.worker().run({"requestId": RID, "command": "Get-Process"})
        self.assertEqual([], self.calls)

    def test_existing_unresolved_reservation_still_blocks_new_effect(self):
        for state in ("DISPATCHED", "UNCERTAIN"):
            with self.subTest(state=state):
                with sqlite3.connect(self.db) as conn:
                    conn.execute("DELETE FROM shell_receipts")
                self.seed(state)
                self.assertEqual(state, self.worker().status(RID)["state"])
                with self.assertRaisesRegex(ShellDenied, "SHELL_OPERATION_UNRESOLVED"):
                    self.worker().run({"requestId": OTHER, "command": "Get-Date"})
        self.assertEqual([], self.calls)


if __name__ == "__main__":
    unittest.main()
''',
    }


def export_source(source_root, output_root, expected_sha):
    source = Path(source_root).absolute()
    output = Path(output_root).absolute()
    if not source.is_dir() or source != source.resolve() or source.is_symlink():
        raise ExtractionError("SOURCE_ROOT_INVALID")
    if not re.fullmatch(r"[0-9a-f]{40}", expected_sha):
        raise ExtractionError("SOURCE_SHA_INVALID")
    if git(source, "rev-parse", "HEAD").decode().strip() != expected_sha:
        raise ExtractionError("SOURCE_SHA_CHANGED")
    if git(source, "symbolic-ref", "--short", "HEAD").decode().strip() != "main":
        raise ExtractionError("SOURCE_NOT_MAIN")
    if git(source, "status", "--porcelain=v1", "--untracked-files=all").strip():
        raise ExtractionError("SOURCE_DIRTY")
    origin = git(source, "remote", "get-url", "origin").decode().strip()
    if origin not in ("https://github.com/" + SOURCE_REPOSITORY,
                      "https://github.com/" + SOURCE_REPOSITORY + ".git",
                      "git@github.com:" + SOURCE_REPOSITORY + ".git"):
        raise ExtractionError("SOURCE_ORIGIN_DENIED")
    if (output.exists() or output.is_symlink() or output != output.resolve()
            or output == source or output.is_relative_to(source)):
        raise ExtractionError("OUTPUT_MUST_BE_NEW_SEPARATE_DIRECTORY")
    if not output.parent.is_dir():
        raise ExtractionError("OUTPUT_PARENT_REQUIRED")
    blobs = {name: read_blob(source, name) for name in INPUTS}
    payloads = {
        name: value.replace("§", chr(96)).replace(
            "MATRIX_OS", chr(36) + "{{ matrix.os }}").encode("utf-8")
        for name, value in templates().items()
    }
    payloads[PACKAGE + "/owner_shell.py"] = blobs[INPUTS[0]]
    launcher = blobs[INPUTS[1]]
    marker = b"-m mirror_api.owner_shell"
    if launcher.count(marker) != 1:
        raise ExtractionError("LAUNCHER_MODULE_REFERENCE_CHANGED")
    payloads[INPUTS[1]] = launcher.replace(marker, b"-m " + PACKAGE.encode() + b".owner_shell")
    test_source = blobs[INPUTS[2]]
    if b"mirror_api.owner_shell" not in test_source:
        raise ExtractionError("TEST_MODULE_REFERENCE_CHANGED")
    payloads["tests/test_owner_shell.py"] = test_source.replace(
        b"mirror_api.owner_shell", PACKAGE.encode() + b".owner_shell")
    payloads[".github/workflows/release-impact.yml"] = blobs[INPUTS[3]]
    for name in ("LICENSE", "LICENSE.md", "LICENSE.txt", "COPYING", "NOTICE"):
        if git(source, "ls-tree", "HEAD", "--", name).strip():
            payloads[name] = read_blob(source, name)
    provenance = {
        "schemaVersion": 1, "status": "SOURCE_CANDIDATE_NOT_INSTALLED",
        "sourceRepository": SOURCE_REPOSITORY, "sourceCommit": expected_sha,
        "targetRepository": "fortis-powershell-executor",
        "inputs": {name: hashlib.sha256(value).hexdigest() for name, value in blobs.items()},
        "outputs": {name: hashlib.sha256(value).hexdigest()
                    for name, value in sorted(payloads.items())},
        "transformations": ["worker bytes unchanged", "launcher module relocated",
                            "test imports/mock target relocated", "standalone packaging added"],
        "licenseFiles": sorted(name for name in payloads if name.startswith(
            ("LICENSE", "COPYING", "NOTICE"))),
        "hostChanged": False, "machineExecutionAdded": False,
    }
    payloads["SOURCE-PROVENANCE.json"] = (
        json.dumps(provenance, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    staging = Path(tempfile.mkdtemp(prefix="." + output.name + "-", dir=output.parent))
    try:
        for name, data in sorted(payloads.items()):
            dest = staging / name
            dest.parent.mkdir(parents=True, exist_ok=True)
            with dest.open("wb") as stream:
                for i in range(0, len(data), 32768):
                    stream.write(data[i:i + 32768])
        if output.exists() or output.is_symlink():
            raise ExtractionError("OUTPUT_ALREADY_EXISTS")
        staging.rename(output)
    finally:
        if staging.exists():
            shutil.rmtree(staging)
    return provenance


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", required=True)
    parser.add_argument("--expected-source-sha", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    try:
        result = export_source(args.source_root, args.output, args.expected_source_sha)
    except ExtractionError as exc:
        parser.exit(2, str(exc) + "\n")
    print(json.dumps({"status": result["status"], "sourceCommit": result["sourceCommit"],
                      "output": str(Path(args.output).absolute()),
                      "files": len(result["outputs"]) + 1}, ensure_ascii=False))


if __name__ == "__main__":
    main()

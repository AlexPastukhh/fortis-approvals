#!/usr/bin/env python3
"""Refresh deterministic source manifests; --check verifies without writing."""
import argparse
import hashlib
import re
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"
ORIGINAL = DOCS / "SOURCE-MANIFEST.sha256"
CURRENT = DOCS / "CURRENT-SOURCE-MANIFEST.sha256"
FULL = DOCS / "MODULARIZED-SOURCE-MANIFEST.sha256"

EXCLUDED_DIRS = {
    ".git", ".venv", "venv", "__pycache__", ".pytest_cache", ".mypy_cache",
    ".ruff_cache", "build", "dist", "node_modules", "state", "private",
}
EXCLUDED_SUFFIXES = {
    ".pyc", ".pyo", ".log", ".sqlite", ".sqlite3", ".db", ".key", ".pem",
    ".p12", ".pfx", ".token", ".secret", ".credential", ".sqlite-shm",
    ".sqlite-wal", ".sqlite3-shm", ".sqlite3-wal", ".db-shm", ".db-wal",
}
SENSITIVE_NAMES = {
    ".netrc", ".npmrc", ".pypirc", "id_rsa", "id_ed25519",
    "token", "github-token", "sonar-token", "machine-grant",
}
def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def render(rows):
    return "".join(f"{value}  {name}\n" for name, value in rows)


def original_rows():
    rows = []
    for line in ORIGINAL.read_text(encoding="utf-8").splitlines():
        expected, name = line.split("  ", 1)
        path = ROOT / name
        if not path.is_file() or path.is_symlink():
            raise SystemExit(f"missing/non-regular original source: {name}")
        rows.append((name, digest(path)))
    return rows


def full_rows():
    rows = []
    for path in ROOT.rglob("*"):
        if not path.is_file() or path.is_symlink():
            continue
        rel = path.relative_to(ROOT)
        # Non-release data produced by the live file/PR pilot; no executable/source paths.
        if re.fullmatch(r'docs/fortis-e2e/[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}\.txt', rel.as_posix()):
            continue
        if any(part in EXCLUDED_DIRS for part in Path(rel).parts):
            continue
        if path.suffix.lower() in EXCLUDED_SUFFIXES:
            continue
        lower_name = path.name.lower()
        if (lower_name in SENSITIVE_NAMES or path.stem.lower() in SENSITIVE_NAMES or
                lower_name == ".env" or
                (lower_name.startswith(".env.") and lower_name != ".env.example") or
                lower_name == "credentials" or lower_name.startswith("credentials.")):
            continue
        if rel.as_posix() == FULL.relative_to(ROOT).as_posix():
            continue
        rows.append((rel.as_posix(), digest(path)))
    rows.sort(key=lambda item: item[0])
    return rows


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    current_content = render(original_rows())
    stale = []
    if args.check:
        if not CURRENT.is_file() or CURRENT.read_text(encoding="utf-8") != current_content:
            stale.append(CURRENT.relative_to(ROOT).as_posix())
    else:
        CURRENT.write_text(current_content, encoding="utf-8", newline="\n")
        print(f"updated {CURRENT.relative_to(ROOT)}")

    full_content = render(full_rows())
    if args.check:
        if not FULL.is_file() or FULL.read_text(encoding="utf-8") != full_content:
            stale.append(FULL.relative_to(ROOT).as_posix())
    else:
        FULL.write_text(full_content, encoding="utf-8", newline="\n")
        print(f"updated {FULL.relative_to(ROOT)}")

    if stale:
        for name in stale:
            print(f"stale manifest: {name}", file=sys.stderr)
        return 1
    if args.check:
        print("source manifests: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

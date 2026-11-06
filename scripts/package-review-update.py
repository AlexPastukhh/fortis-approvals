#!/usr/bin/env python3
"""Build a standalone owner-run copy; no credentials, Docker or runtime access."""
import argparse
import base64
import hashlib
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[1]
DEPLOY = 'fortis_approvals/deploy/'
FUNCTIONS = ('Docker-Text', 'Container', 'Private-Process', 'Code64', 'Helper',
    'Public-Inspect', 'Production-Baseline', 'Assert-Production', 'Assert-Volume',
    'Assert-OnlyWriter', 'Wait-Healthy', 'Protect-Directory', 'Assert-RecordAcl', 'Save-Record')


def substitute(text, old, new):
    if text.count(old) != 1:
        raise ValueError('PACKAGE_SOURCE_SHAPE_CHANGED')
    return text.replace(old, new)


def build(root, commit):
    if not re.fullmatch('[0-9a-f]{40}', commit):
        raise ValueError('PACKAGE_COMMIT_INVALID')
    directory = root / DEPLOY
    text = (directory / 'Update-NativeReview.ps1').read_text()
    library = (directory / 'Run-GitHub-Pilot-E2E.ps1').read_text()
    library = library[:library.index("if ($Mode -ceq 'Functions') { return }")]
    selected = []
    for name in FUNCTIONS:
        match = re.search(r'^function ' + re.escape(name) + r' \{.*?(?=^function |\Z)', library, re.S | re.M)
        if not match:
            raise ValueError('PACKAGE_FUNCTION_MISSING')
        selected.append(match.group())
    old = "$RequestedMode=$Mode; $RequestedRecord=$Record; $RequestedConfig=$AnalysisConfig\n. (Join-Path $PSScriptRoot 'Run-GitHub-Pilot-E2E.ps1') -Mode Functions\n$Mode=$RequestedMode; $Record=$RequestedRecord; $AnalysisConfig=$RequestedConfig"
    production = re.search(r'^\$ProductionImage = .*$', library, re.M).group()
    text = substitute(text, old, "$ErrorActionPreference='Stop'\n" + production + '\n\n' + '\n'.join(selected))
    for filename in ('github_pilot_helpers.py', 'image_offline_smoke.py'):
        data = (directory / filename).read_bytes()
        encoded = base64.b64encode(data).decode('ascii')
        old = "(Get-Content -LiteralPath (Join-Path $PSScriptRoot '" + filename + "') -Raw)"
        text = substitute(text, old, "([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('" + encoded + "')))")
    return (f'# GENERATED OWNER REVIEW COPY; source commit {commit}\n'
            '# Reproduce with scripts/package-review-update.py; source assets are embedded byte-for-byte.\n' + text).encode('utf-8')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    def git(*values):
        return subprocess.check_output(['git', '-c', 'core.fsmonitor=false', *values], cwd=ROOT, text=True).strip()
    if git('status', '--porcelain'):
        raise SystemExit('PACKAGE_REQUIRES_CLEAN_COMMITTED_SOURCE')
    commit = git('rev-parse', 'HEAD')
    content = build(ROOT, commit)
    with args.output.open('xb') as output:
        output.write(content)
    args.output.chmod(0o600)
    print(f'sourceCommit={commit}\nsha256={hashlib.sha256(content).hexdigest()}\noutput={args.output}')


if __name__ == '__main__':
    main()

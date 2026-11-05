#!/usr/bin/env python3
"""Package a manifested uncommitted review snapshot. Never includes Git/state/secrets."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import zipfile

ROOT = Path(__file__).resolve().parents[1]


def digest(data):
    return hashlib.sha256(data).hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    subprocess.run(['python3', '-B', str(ROOT / 'scripts/update-source-manifests.py'), '--check'], check=True)
    base = subprocess.check_output(['git', '-C', str(ROOT), 'rev-parse', 'HEAD'], text=True).strip()
    manifest = ROOT / 'docs/MODULARIZED-SOURCE-MANIFEST.sha256'
    files = {}
    contents = {}
    for line in manifest.read_text().splitlines():
        expected, name = line.split('  ', 1)
        data = (ROOT / name).read_bytes()
        if digest(data) != expected:
            raise SystemExit('SOURCE_CHANGED_DURING_PACKAGING:' + name)
        files[name], contents[name] = expected, data
    name = manifest.relative_to(ROOT).as_posix()
    files[name], contents[name] = digest(manifest.read_bytes()), manifest.read_bytes()
    metadata = {'baseCommit': base, 'sourceTreeSha256': files[name], 'files': files}
    contents['review-source.json'] = (json.dumps(metadata, sort_keys=True, indent=2) + '\n').encode()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(args.output, 'x', compression=zipfile.ZIP_DEFLATED) as archive:
        for name, data in sorted(contents.items()):
            info = zipfile.ZipInfo(name, date_time=(2026, 11, 5, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            archive.writestr(info, data)
    with zipfile.ZipFile(args.output) as archive:
        if archive.testzip() is not None or set(archive.namelist()) != set(contents):
            raise SystemExit('ZIP_VERIFICATION_FAILED')
        for name, data in contents.items():
            if archive.read(name) != data:
                raise SystemExit('ZIP_CONTENT_MISMATCH')
    print('ARCHIVE=' + str(args.output))
    print('ARCHIVE_SHA256=' + digest(args.output.read_bytes()))
    print('SNAPSHOT_SHA256=' + digest(contents['review-source.json']))
    print('SOURCE_BASE_COMMIT=' + base)
    print('FILES=' + str(len(contents)))


if __name__ == '__main__':
    main()

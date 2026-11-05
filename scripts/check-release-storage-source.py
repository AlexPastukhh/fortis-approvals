#!/usr/bin/env python3
"""Check this release's persistence source against the immutable extraction.

No Docker, database, credential, upstream or lifecycle access. Actual image
source hashes and database schemas remain separate host release preflights.
"""
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def require(condition, code):
    if not condition:
        raise RuntimeError(code)


def verify(root=ROOT):
    root = Path(root)
    descriptor = json.loads((root / 'fortis_approvals/deploy/release-storage-source-hashes.json').read_text())
    baseline = {line.split('  ', 1)[1]: line.split('  ', 1)[0]
                for line in (root / 'docs/SOURCE-MANIFEST.sha256').read_text().splitlines()}
    snapshot = json.loads((root / 'fortis_approvals/deploy/review-repo-source-hashes-20261105.json').read_text())
    require(descriptor['format'] == 'fortis-storage-source-compatibility-v1', 'STORAGE_FORMAT_INVALID')
    require(set(descriptor['files']) == {'core.py', 'owner_auth.py', 'owner_portal.py',
            'gateway.py', 'runtime.py', 'sonar.py'}, 'STORAGE_FILE_SET_INVALID')
    for name, entry in descriptor['files'].items():
        original = baseline[entry['originalPath']]
        require(original == entry['originalSha256'], 'STORAGE_BASELINE_HASH_MISMATCH')
        require(snapshot[entry['candidatePath']] == entry['candidateSha256'], 'STORAGE_IMAGE_SNAPSHOT_HASH_MISMATCH')
        data = (root / entry['candidatePath']).read_bytes()
        require(hashlib.sha256(data).hexdigest() == entry['candidateSha256'], 'STORAGE_CANDIDATE_SOURCE_CHANGED')
        if name == 'core.py':
            old = b"        limit = 524288 if value['service'] == 'github' else 32768\n        if len(encoded) > limit:\n"
            require(data.count(old) == 1, 'STORAGE_CORE_TRANSFORM_INVALID')
            data = data.replace(old, b'        if len(encoded) > 32768:\n')
        elif name == 'sonar.py':
            for old, new in ((b'from ....core import Denied, Stale, canonical', b'from .core import Denied, Stale, canonical'),
                             (b'from .inventory import discover', b'from .sonar_inventory import discover')):
                require(data.count(old) == 1, 'STORAGE_SONAR_TRANSFORM_INVALID')
                data = data.replace(old, new)
        require(hashlib.sha256(data).hexdigest() == original, 'STORAGE_PERSISTENCE_SOURCE_DIFFERENCE')
    return {'sourceCompatibility': 'PASS', 'files': len(descriptor['files']),
            'limits': 'Source equivalence only; actual image files and database schemas require release preflight'}


if __name__ == '__main__':
    print(json.dumps(verify(), sort_keys=True))

"""Release source gate rejects storage drift even if the candidate hash is updated."""
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('release_storage', ROOT / 'scripts/check-release-storage-source.py')
CHECK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECK)


class ReleaseStorageSourceTests(unittest.TestCase):
    def fixture(self):
        temporary = tempfile.TemporaryDirectory(prefix='release-source-offline-')
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        descriptor = json.loads((ROOT / 'fortis_approvals/deploy/release-storage-source-hashes.json').read_text())
        paths = ['fortis_approvals/deploy/release-storage-source-hashes.json', 'docs/SOURCE-MANIFEST.sha256',
                 'fortis_approvals/deploy/review-repo-source-hashes-20261105.json']
        paths += [entry['candidatePath'] for entry in descriptor['files'].values()]
        for name in paths:
            target = root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, target)
        return root, descriptor

    def write_descriptor(self, root, descriptor):
        (root / 'fortis_approvals/deploy/release-storage-source-hashes.json').write_text(json.dumps(descriptor))

    def test_current_persistence_source_has_only_reviewed_non_storage_differences(self):
        self.assertEqual(CHECK.verify()['sourceCompatibility'], 'PASS')

    def test_changed_owner_storage_source_is_rejected(self):
        root, descriptor = self.fixture()
        with (root / descriptor['files']['owner_auth.py']['candidatePath']).open('ab') as file:
            file.write(b'\n# unexpected owner storage change\n')
        with self.assertRaisesRegex(RuntimeError, 'CANDIDATE_SOURCE_CHANGED'):
            CHECK.verify(root)

    def test_updating_candidate_hash_cannot_hide_unreviewed_storage_source_change(self):
        root, descriptor = self.fixture()
        entry = descriptor['files']['core.py']
        path = root / entry['candidatePath']
        path.write_bytes(path.read_bytes() + b'\n# unexpected persistence difference\n')
        entry['candidateSha256'] = hashlib.sha256(path.read_bytes()).hexdigest()
        self.write_descriptor(root, descriptor)
        snapshot_path = root / 'fortis_approvals/deploy/review-repo-source-hashes-20261105.json'
        snapshot = json.loads(snapshot_path.read_text())
        snapshot[entry['candidatePath']] = entry['candidateSha256']
        snapshot_path.write_text(json.dumps(snapshot))
        with self.assertRaisesRegex(RuntimeError, 'PERSISTENCE_SOURCE_DIFFERENCE'):
            CHECK.verify(root)

    def test_original_hash_cannot_be_redefined_by_descriptor(self):
        root, descriptor = self.fixture()
        descriptor['files']['owner_auth.py']['originalSha256'] = '0' * 64
        self.write_descriptor(root, descriptor)
        with self.assertRaisesRegex(RuntimeError, 'BASELINE_HASH_MISMATCH'):
            CHECK.verify(root)

    def test_missing_storage_file_is_rejected(self):
        root, descriptor = self.fixture()
        del descriptor['files']['sonar.py']
        self.write_descriptor(root, descriptor)
        with self.assertRaisesRegex(RuntimeError, 'FILE_SET_INVALID'):
            CHECK.verify(root)

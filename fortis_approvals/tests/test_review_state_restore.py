"""Synthetic backup restore and existing test-key Origin migration. No live state."""
import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch
from fortis_approvals.owner_auth import OwnerWebAuthn
from fortis_approvals.core import Denied
from test_r5_lifecycle_offline import R5VirtualKey

HELPER = Path(__file__).resolve().parents[1] / 'deploy/restore_review_state.py'
spec = importlib.util.spec_from_file_location('review_restore', HELPER)
helper = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helper)


VERIFIER = HELPER.with_name('verify_review_state.py')
verify_spec = importlib.util.spec_from_file_location('review_verify', VERIFIER)
verifier = importlib.util.module_from_spec(verify_spec)
verify_spec.loader.exec_module(verifier)


class ReviewStateRestoreTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix='fortis-review-synthetic-')
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.backup = self.root / 'backup'
        self.target = self.root / 'target'
        self.backup.mkdir()
        self.target.mkdir()
        (self.backup / '.fortis-r7-unified-v1').write_bytes(b'fortis-r7-unified-v1\n')
        with sqlite3.connect(self.backup / 'approvals.sqlite') as db:
            db.executescript('CREATE TABLE requests(state TEXT); CREATE TABLE events(value TEXT);')
            db.executemany('INSERT INTO requests VALUES (?)', [('EXECUTED',), ('REJECTED',)])
            db.executemany('INSERT INTO events VALUES (?)', [('first',), ('second',)])
        self.auth = OwnerWebAuthn(self.backup / 'owner.sqlite', origin=helper.SOURCE_ORIGIN)
        self.key = R5VirtualKey()
        begin = self.auth.begin_enrollment(self.auth.issue_invitation())
        self.auth.finish_enrollment(begin['ceremonyId'], self.key.enroll(begin))
        with sqlite3.connect(self.backup / 'sonar-receipts.sqlite') as db:
            db.execute('CREATE TABLE receipts(value TEXT)')
            db.execute("INSERT INTO receipts VALUES ('offline receipt')")
        self.manifest = {'ownerBindingPass': True, 'databases': {
            'approvals.sqlite': {'integrity': 'ok', 'requestStates': {'EXECUTED': 1, 'REJECTED': 1}, 'events': 2},
            'owner.sqlite': {'integrity': 'ok', 'credentialsActive': 1, 'credentialsTotal': 1, 'invitationsTotal': 1},
            'sonar-receipts.sqlite': {'integrity': 'ok', 'receipts': 1}}}
        self.refresh_manifest()

    def refresh_manifest(self):
        self.manifest['sha256'] = {name: helper.sha256(self.backup / name) for name in helper.FILES}
        p = self.backup / 'manifest.json'
        p.write_text(json.dumps(self.manifest))
        self.manifest_hash = helper.sha256(p)

    def restore(self):
        return helper.restore(self.backup, self.target, target_uid=os.geteuid(),
            target_gid=os.getegid(), expected_manifest_sha256=self.manifest_hash)

    def test_readonly_verifier_checks_permissions_hashes_and_counts(self):
        receipt = self.restore()
        original = {p.name: p.read_bytes() for p in (self.target / 'private').iterdir()}
        result = verifier.verify(self.target, receipt, uid=os.geteuid(), gid=os.getegid())
        self.assertEqual(result['verification'], 'PASS')
        self.assertEqual(result['requests'], 2)
        self.assertEqual(original, {p.name: p.read_bytes() for p in (self.target / 'private').iterdir()})
        path = self.target / 'private/approvals.sqlite'
        path.chmod(0o644)
        with self.assertRaisesRegex(RuntimeError, 'PERMISSIONS'):
            verifier.verify(self.target, receipt, uid=os.geteuid(), gid=os.getegid())
        path.chmod(0o600)
        with path.open('ab') as f:
            f.write(b'tamper')
        with self.assertRaisesRegex(RuntimeError, 'HASH_MISMATCH'):
            verifier.verify(self.target, receipt, uid=os.geteuid(), gid=os.getegid())

    def test_readonly_verifier_rejects_wrong_runtime_identity(self):
        receipt = self.restore()
        with self.assertRaisesRegex(RuntimeError, 'WRONG_IDENTITY'):
            verifier.verify(self.target, receipt, uid=os.geteuid() + 1, gid=os.getegid())

    def test_manifest_counts_and_existing_key_login_at_new_origin(self):
        original = {p.name: p.read_bytes() for p in self.backup.iterdir()}
        before = helper.owner_snapshot(self.backup / 'owner.sqlite')
        result = self.restore()
        self.assertEqual((result['requests'], result['events'], result['receipts']), (2, 2, 1))
        clone = self.target / 'private/owner.sqlite'
        after = helper.owner_snapshot(clone)
        self.assertEqual(after['credentials'], before['credentials'])
        self.assertEqual(after['invitations'], before['invitations'])
        auth = OwnerWebAuthn(clone, origin=helper.TARGET_ORIGIN)
        begin = auth.begin_login()
        auth.finish_login(begin['ceremonyId'], self.key.assert_(begin, origin=helper.TARGET_ORIGIN))
        begin = auth.begin_login()
        with self.assertRaises(Denied):
            auth.finish_login(begin['ceremonyId'], self.key.assert_(begin, origin=helper.SOURCE_ORIGIN))
        self.assertEqual(original, {p.name: p.read_bytes() for p in self.backup.iterdir()})
        self.assertEqual(auth.rp_id, 'localhost')
        with self.assertRaisesRegex(RuntimeError, 'NOT_EMPTY'):
            self.restore()

    def test_corrupt_hash_stops_before_target_writes(self):
        with (self.backup / 'approvals.sqlite').open('ab') as f:
            f.write(b'tamper')
        with self.assertRaisesRegex(RuntimeError, 'HASH_MISMATCH'):
            self.restore()
        self.assertEqual(list(self.target.iterdir()), [])

    def test_pinned_manifest_tampering_stops_before_target_writes(self):
        (self.backup / 'manifest.json').write_text('{}')
        with self.assertRaisesRegex(RuntimeError, 'PINNED_MANIFEST_HASH'):
            self.restore()
        self.assertEqual(list(self.target.iterdir()), [])

    def test_manifest_counts_must_match_history(self):
        self.manifest['databases']['approvals.sqlite']['events'] = 99
        self.refresh_manifest()
        with self.assertRaisesRegex(RuntimeError, 'HISTORY_MISMATCH'):
            self.restore()
        self.assertEqual(list(self.target.iterdir()), [])

    def test_wrong_binding_is_not_migrated(self):
        with sqlite3.connect(self.backup / 'owner.sqlite') as db:
            db.execute("UPDATE config SET value='wrong' WHERE setting='rpId'")
        self.refresh_manifest()
        with self.assertRaisesRegex(RuntimeError, 'BINDING_MISMATCH'):
            self.restore()
        self.assertEqual(list(self.target.iterdir()), [])

    def test_chmod_finishes_before_ownership_is_relinquished(self):
        chowned = set()
        chmod, chown = os.chmod, os.chown
        def restricted_chmod(path, mode):
            if Path(path) in chowned:
                raise PermissionError('No CAP_FOWNER after CHOWN')
            return chmod(path, mode)
        def observed_chown(path, uid, gid):
            chown(path, uid, gid)
            chowned.add(Path(path))
        with patch.object(helper.os, 'chmod', side_effect=restricted_chmod), patch.object(
                helper.os, 'chown', side_effect=observed_chown):
            self.restore()
        self.assertEqual(len(chowned), 5)

    def test_existing_target_and_backup_sidecars_rejected(self):
        (self.target / 'keep').write_text('existing clone')
        with self.assertRaisesRegex(RuntimeError, 'NOT_EMPTY'):
            self.restore()
        self.assertEqual((self.target / 'keep').read_text(), 'existing clone')
        (self.target / 'keep').unlink()
        (self.backup / 'owner.sqlite-wal').write_text('incomplete backup')
        with self.assertRaisesRegex(RuntimeError, 'SIDECAR'):
            self.restore()
        self.assertEqual(list(self.target.iterdir()), [])

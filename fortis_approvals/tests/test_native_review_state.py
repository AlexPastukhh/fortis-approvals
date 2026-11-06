"""Native state preservation using real Store/Git-runner layout, no host/API mocks."""
import hashlib
import os
from pathlib import Path
import sqlite3
import unittest

import test_github_pilot_package as pilot
from fortis_approvals.workflow.store import Store
from fortis_approvals.workflow.git_backend import GitHubGitBackend

H = pilot.HELPERS


class NativeStateTests(unittest.TestCase):
    def setUp(self):
        pilot.StateTests.setUp(self)
        self.private = self.source / 'private'
        with sqlite3.connect(self.private / 'github-receipts.sqlite') as db:
            db.execute('CREATE TABLE receipts(value TEXT)')
        (self.private / 'github-receipts.sqlite').chmod(0o600)
        self.store = Store(self.private / 'native-git')
        GitHubGitBackend(self.store.root / 'git', owner='OfflineOwner', repositories=('sandbox',))
        data = b'OFFLINE immutable Git artifact bytes'
        self.digest = hashlib.sha256(data).hexdigest()
        self.artifact = self.store.artifacts / (self.digest + '.bundle')
        self.artifact.write_bytes(data); self.artifact.chmod(0o600)
        self.store.save_artifact('offline-actor', self.digest, {'preserve': 'metadata'})
        self.store.register('offline-actor', 'sandbox', 'saved-task', {'headSha': 'a' * 40})
        self.options = dict(github=True, native=True, **self.identity)

    def test_legacy_check_reproduces_owner_failure_before_target_write(self):
        with self.assertRaisesRegex(RuntimeError, 'SOURCE_UNKNOWN_FILES_OR_JOURNAL'):
            H.clone_state(self.source, self.target, github=True, **self.identity)
        self.assertEqual(list(self.target.iterdir()), [])

    def test_native_clone_preserves_tasks_artifacts_receipts_and_permissions(self):
        receipt = H.clone_state(self.source, self.target, **self.options)
        self.assertEqual(receipt, H.inspect_state(self.source, **self.options))
        self.assertEqual(receipt, H.inspect_state(self.target, **self.options))
        self.assertEqual(receipt['summary']['native'], {'tasks': 1, 'artifacts': 1, 'jobStates': {}})
        for name in receipt['sha256']:
            self.assertEqual((self.private / name).read_bytes(), (self.target / 'private' / name).read_bytes())
        for name in H.NATIVE_DIRS:
            self.assertEqual((self.target / 'private' / name).stat().st_mode & 0o777, 0o700)
        self.assertEqual(Store(self.target / 'private/native-git').task('offline-actor', 'sandbox', 'saved-task'),
                         {'headSha': 'a' * 40})

    def test_pending_and_claimed_jobs_deny_clone_before_any_write(self):
        self.store.enqueue('offline-actor', {'requestId': 'offline-job'})
        for state in ('QUEUED', 'CLAIMED'):
            if state == 'CLAIMED': self.store.claim('offline-actor', 'offline-job')
            with self.assertRaisesRegex(RuntimeError, 'NATIVE_HAS_UNFINISHED_JOBS'):
                H.clone_state(self.source, self.target, **self.options)
            self.assertEqual(list(self.target.iterdir()), [])

    def test_finished_job_is_retained(self):
        self.store.enqueue('offline-actor', {'requestId': 'offline-job'})
        claim = self.store.claim('offline-actor', 'offline-job')['claim']
        self.store.finish('offline-actor', 'offline-job', claim, {'receipt': 'retained'}, None)
        receipt = H.clone_state(self.source, self.target, **self.options)
        self.assertEqual(receipt['summary']['native']['jobStates'], {'DONE': 1})
        self.assertEqual(Store(self.target / 'private/native-git').job('offline-job')['result'],
                         '{"receipt":"retained"}')

    def test_auth_directory_journal_and_unknown_files_deny_before_copy(self):
        for name, directory in (('native-git/git/git-auth-interrupted', True),
                                ('native-git/workflow.sqlite-journal', False),
                                ('native-git/git/runner/home/.gitconfig', False)):
            path = self.private / name
            if directory: path.mkdir(mode=0o700)
            else: path.write_bytes(b'OFFLINE unknown data')
            try:
                with self.assertRaisesRegex(RuntimeError, 'NATIVE_UNKNOWN_FILES_OR_TEMPORARY_GIT_STATE'):
                    H.clone_state(self.source, self.target, **self.options)
                self.assertEqual(list(self.target.iterdir()), [])
            finally:
                path.rmdir() if directory else path.unlink()

    def test_artifact_corruption_missing_metadata_reference_and_permissions_deny(self):
        original = self.artifact.read_bytes()
        self.artifact.write_bytes(b'changed')
        with self.assertRaisesRegex(RuntimeError, 'ARTIFACT_DIGEST_MISMATCH'):
            H.clone_state(self.source, self.target, **self.options)
        self.artifact.write_bytes(original)
        self.artifact.chmod(0o644)
        with self.assertRaisesRegex(RuntimeError, 'SOURCE_FILE_INVALID'):
            H.clone_state(self.source, self.target, **self.options)
        self.artifact.chmod(0o600); self.artifact.unlink()
        with self.assertRaisesRegex(RuntimeError, 'ARTIFACT_UNAVAILABLE'):
            H.clone_state(self.source, self.target, **self.options)
        self.assertEqual(list(self.target.iterdir()), [])

    def test_symlink_and_hardlink_artifacts_are_rejected(self):
        extra = self.store.artifacts / ('b' * 64 + '.bundle')
        extra.symlink_to(self.artifact.name)
        with self.assertRaisesRegex(RuntimeError, 'SOURCE_FILE_INVALID'):
            H.clone_state(self.source, self.target, **self.options)
        extra.unlink(); os.link(self.artifact, extra)
        with self.assertRaisesRegex(RuntimeError, 'NATIVE_HARDLINK_DENIED'):
            H.clone_state(self.source, self.target, **self.options)
        self.assertEqual(list(self.target.iterdir()), [])

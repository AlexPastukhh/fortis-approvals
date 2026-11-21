"""Private temporary DB and fake GitHub only; no runtime placement or grants."""
from contextlib import closing
import hashlib
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
import uuid
from unittest.mock import patch

from fortis_approvals.core import Conflict, Denied, Stale
from fortis_approvals.integrations.github.gateway.adapter import GitHubAdapter
from fortis_approvals.integrations.github.gateway.review_capture import ReviewCaptureStore
from fortis_approvals.integrations.github.tests.test_post_merge_reader import FakeProvider, HEAD, BASE, REPO

BODY = 'Exact reviewed candidate body\n<!-- fortis-release-impact:start -->\n```yaml\nreleaseImpact: {}\n```\n<!-- fortis-release-impact:end -->'
DIGEST = hashlib.sha256(BODY.encode()).hexdigest()


class CaptureTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.path = self.root / 'capture.sqlite'
        self.store = ReviewCaptureStore.initialize(self.path)
        self.provider = FakeProvider()
        self.provider.pr.update(state='open', merged=False, merged_at=None, body=BODY)
        self.adapter = GitHubAdapter(self.provider, owner='Alex', repositories=[REPO],
                                     receipt_store=self.root / 'receipts.sqlite')
        self.args = dict(operation_id=str(uuid.uuid4()), expected_revision=0, number=42,
                         expected_head_sha=HEAD, expected_body_sha256=DIGEST)

    def append(self, **kw):
        return self.store.capture(self.adapter, **(self.args | kw))

    def test_retained_exact_body_no_authority_or_body_in_receipt(self):
        r = self.append()
        self.assertEqual(r['revision'], 1)
        self.assertEqual(r['bodySha256'], DIGEST)
        for flag in ('reviewAttested', 'evidenceVerified', 'admissionAllowed', 'deploymentAllowed'):
            self.assertIs(r[flag], False)
        self.assertNotIn(BODY, repr(r))
        self.assertEqual(len(self.provider.calls), 2)
        cp = self.store.checkpoint()
        self.assertEqual(cp, {'revision': 1, 'eventDigest': r['eventDigest']})
        self.assertEqual(self.store.retained_material(self.args['operation_id'],
                                                     expected_checkpoint=cp)['body'], BODY)

    def test_reopen_and_replay_after_merge_without_provider(self):
        r = self.append()
        self.store = ReviewCaptureStore(self.path)
        self.provider.pr.update(state='closed', merged=True)
        self.assertEqual(self.append(), r)
        self.assertEqual(self.store.operation(self.args['operation_id']), r)
        self.assertEqual(len(self.provider.calls), 2)

    def test_replay_different_input_conflicts(self):
        self.append()
        with self.assertRaisesRegex(Conflict, 'P5_CAPTURE_OPERATION_CONFLICT'):
            self.append(expected_body_sha256='a'*64)
        self.assertEqual(len(self.provider.calls), 2)

    def test_stale_other_operation_no_provider(self):
        self.append()
        with self.assertRaisesRegex(Stale, 'P5_CAPTURE_REVISION_STALE'):
            self.append(operation_id=str(uuid.uuid4()))
        self.assertEqual(len(self.provider.calls), 2)

    def test_second_snapshot_preserves_original(self):
        r = self.append()
        body = BODY + '\nLater content'
        self.provider.pr['body'] = body
        newer = self.append(operation_id=str(uuid.uuid4()), expected_revision=1,
                            expected_body_sha256=hashlib.sha256(body.encode()).hexdigest())
        self.assertEqual(newer['revision'], 2)
        self.assertNotEqual(newer['eventDigest'], r['eventDigest'])
        self.assertEqual(self.store.operation(self.args['operation_id']), r)
        self.assertEqual(self.store.retained_material(self.args['operation_id'],
                         expected_checkpoint=self.store.checkpoint())['body'], BODY)

    def test_current_body_mismatch(self):
        self.provider.pr['body'] = BODY + 'changed'
        with self.assertRaisesRegex(Denied, 'P5_CAPTURE_BODY_CHANGED'):
            self.append()
        self.assertEqual(self.store.checkpoint()['revision'], 0)

    def test_already_merged_or_fork_rejected(self):
        with patch.dict(self.provider.pr, {'state':'closed','merged':True}), self.assertRaises(Denied):
            self.append()
        self.provider.pr['head']['repo']['full_name'] = 'Other/' + REPO
        with self.assertRaises(Denied):
            self.append()
        self.assertEqual(self.store.checkpoint()['revision'], 0)

    def test_race_body_between_reads(self):
        original = self.adapter._release_impact_pr_evidence
        def race(*a):
            value = original(*a)
            self.provider.pr['body'] += 'changed'
            return value
        with patch.object(self.adapter, '_release_impact_pr_evidence', side_effect=race), self.assertRaises(Denied):
            self.append()
        self.assertEqual(self.store.checkpoint()['revision'], 0)

    def test_race_base_between_reads(self):
        original = self.adapter._release_impact_pr_evidence
        def race(*a):
            value = original(*a)
            self.provider.pr['base']['sha'] = HEAD
            return value
        with patch.object(self.adapter, '_release_impact_pr_evidence', side_effect=race), self.assertRaisesRegex(Stale, 'P5_CAPTURE_OBSERVATION_CHANGED'):
            self.append()
        self.assertEqual(self.store.checkpoint()['revision'], 0)

    def test_provider_failure_no_capture(self):
        from fortis_approvals.integrations.github.gateway.transport import GitHubTransportError
        self.provider.raise_provider = 'pulls/42'
        with self.assertRaises(GitHubTransportError):
            self.append()
        self.assertEqual(self.store.checkpoint()['revision'], 0)

    def test_invalid_params_before_provider(self):
        for bad in ({'number':True}, {'expected_revision':True}, {'expected_head_sha':'main'},
                    {'operation_id':'bad'}, {'expected_body_sha256':'bad'}):
            with self.subTest(bad=bad), self.assertRaises(Denied):
                self.append(**bad)
        self.assertFalse(self.provider.calls)

    def test_storage_missing_not_recreated(self):
        self.path.unlink()
        with self.assertRaises(Denied):
            self.store.checkpoint()
        self.assertFalse(self.path.exists())

    def test_storage_existing_not_overwritten(self):
        self.append()
        prior = self.store.checkpoint()
        with self.assertRaises(FileExistsError):
            ReviewCaptureStore.initialize(self.path)
        self.assertEqual(self.store.checkpoint(), prior)

    def test_insecure_mode_and_symlink_rejected(self):
        self.path.chmod(0o644)
        with self.assertRaisesRegex(Denied, 'P5_CAPTURE_STORAGE_PERMISSIONS'):
            self.store.checkpoint()
        self.path.chmod(0o600)
        link=self.root/'link.sqlite'; link.symlink_to(self.path)
        with self.assertRaises(Denied):
            ReviewCaptureStore(link)

    def test_local_tampering_detected(self):
        self.append()
        with sqlite3.connect(self.path) as db:
            db.execute("UPDATE captures SET payload='{}'")
        with self.assertRaisesRegex(Denied, 'P5_CAPTURE_INTEGRITY_INVALID'):
            self.store.checkpoint()

    def test_rollback_detected_with_external_checkpoint(self):
        self.append()
        cp=self.store.checkpoint()
        with sqlite3.connect(self.path) as db:
            db.execute('DELETE FROM captures')
        self.assertEqual(self.store.checkpoint()['revision'], 0)
        with self.assertRaisesRegex(Denied, 'P5_CAPTURE_CHECKPOINT_MISMATCH'):
            self.store.checkpoint(expected=cp)

    def test_restore_copy_inactive_with_checkpoint(self):
        self.append()
        cp = self.store.checkpoint()
        target=self.root/'inactive.sqlite'
        fd=os.open(target,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
        os.close(fd)
        with closing(sqlite3.connect(self.path)) as source, closing(sqlite3.connect(target)) as dest:
            source.backup(dest)
        restored=ReviewCaptureStore(target)
        self.assertEqual(restored.checkpoint(expected=cp),cp)
        self.assertEqual(restored.operation(self.args['operation_id']),self.store.operation(self.args['operation_id']))

    def test_material_requires_checkpoint_and_known_id(self):
        self.append()
        with self.assertRaises(Denied):
            self.store.retained_material(self.args['operation_id'],expected_checkpoint={})
        with self.assertRaisesRegex(Denied,'P5_CAPTURE_NOT_FOUND'):
            self.store.retained_material(str(uuid.uuid4()),expected_checkpoint=self.store.checkpoint())

    def test_concurrent_revision_change_between_reads_and_append(self):
        original = self.adapter._release_impact_pr_evidence
        other = dict(self.args, operation_id=str(uuid.uuid4()))
        fired = False
        def race(*a):
            nonlocal fired
            if not fired:
                fired=True
                with patch.object(self.adapter, '_release_impact_pr_evidence', side_effect=original):
                    self.store.capture(self.adapter, **other)
            return original(*a)
        with patch.object(self.adapter, '_release_impact_pr_evidence', side_effect=race), self.assertRaisesRegex(Stale,'P5_CAPTURE_REVISION_STALE'):
            self.append()
        self.assertEqual(self.store.checkpoint()['revision'],1)
        self.assertIsNone(self.store.operation(self.args['operation_id']))


if __name__=='__main__': unittest.main()

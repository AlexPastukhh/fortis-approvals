"""Actual Git/Core capture and private SQLite; independent synthetic witness."""
import copy
from pathlib import Path
import sqlite3
import unittest
import uuid
from unittest.mock import patch

from fortis_approvals.core import Authenticator, Conflict, Denied, Stale, canonical
from fortis_approvals.integrations.github.gateway import collector_snapshot as c
from fortis_approvals.integrations.github.tests import test_selected_main_binding as fixture
from fortis_approvals.registry import boundary as b
from fortis_approvals.workflow.common import secure_dir


class CollectorSnapshotTests(unittest.TestCase):
    def setUp(self):
        self.fixture=fixture.SelectedMainTests()
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.setup_case()
        self.fixture.approve()
        self.enterContext(patch.object(c,'REPOSITORY',self.fixture.api.head_repo))
        self.enterContext(patch.object(b,'REPOSITORY',c.REPOSITORY))
        self.instance=str(uuid.uuid4())
        self.evidence=str(uuid.uuid4())
        self.anchor=c.genesis(self.instance)
        self.path=secure_dir(self.fixture.root/'collector-journal')/'snapshots.sqlite'
        self.reader=lambda:copy.deepcopy(self.anchor)
        self.journal=c.CollectorSnapshotStore.initialize(
            self.path,instance_id=self.instance,anchor_reader=self.reader)
        self.args=dict(evidence_id=self.evidence,expected_revision=0,
                       owner_request_id=self.fixture.payload['requestId'],
                       selected_main_sha=self.fixture.selected,adapter=self.fixture.adapter,
                       store=self.fixture.store,core=self.fixture.core,
                       checkpoint_reader=lambda:self.fixture.anchor,owner='test-owner',
                       validator=self.fixture.validator)

    def retain(self,**overrides):
        return self.journal.retain(**(self.args|overrides))

    def restart(self):
        self.journal=c.CollectorSnapshotStore(self.path,instance_id=self.instance,
                                             anchor_reader=self.reader)

    def confirm(self,r):
        # Test witness, NOT an implemented/provisioned anchor writer.
        self.assertEqual(self.anchor,r['previousCheckpoint'])
        self.anchor=copy.deepcopy(r['checkpoint'])

    def test_pending_commit_restart_anchor_and_original_receipt(self):
        pending=self.retain()
        self.assertEqual(pending['result'],'LOCAL_EVIDENCE_PENDING_ANCHOR')
        with self.assertRaisesRegex(Denied,'P5_SNAPSHOT_ANCHOR_MISMATCH'):
            self.journal.receipt(self.evidence)
        self.restart()
        with patch.object(c,'observe_selected_main',side_effect=AssertionError('must not recollect')):
            self.assertEqual(self.retain(),pending)
            self.confirm(pending)
            receipt=self.retain()
        self.assertEqual(receipt['result'],'ANCHORED_CANDIDATE_EVIDENCE_RETAINED')
        self.assertEqual(self.journal.receipt(self.evidence),receipt)
        self.assertEqual(receipt['evidenceDigest'],pending['evidenceDigest'])
        self.assertEqual(receipt['ownerRequestId'],self.args['owner_request_id'])
        self.assertFalse(receipt['evidenceVerified'])

    def test_registry_reader_stays_blocked_even_when_anchored(self):
        receipt=self.retain()
        boundary=b.RegistryBoundary(authenticator=Authenticator({'reader':b.READER}),
                                    evidence_reader=self.journal.read)
        raw=canonical({'operation':'registry.preview_merged','params':{
            'repository':c.REPOSITORY,'evidenceId':self.evidence,
            'evidenceDigest':receipt['evidenceDigest']}}).encode()
        with self.assertRaisesRegex(Denied,'REGISTRY_EVIDENCE_UNAVAILABLE'):
            boundary.dispatch('reader',raw)
        self.confirm(receipt)
        preview=boundary.dispatch('reader',raw)
        self.assertEqual(preview['result'],'BLOCKED_EVIDENCE_GAP')
        self.assertFalse(preview['admissionAllowed'])
        self.assertNotIn('records',preview)

    def test_conflicting_replay_and_pending_new_append(self):
        pending=self.retain()
        for overrides in ({'owner_request_id':str(uuid.uuid4())},{'expected_revision':1},
                          {'selected_main_sha':'f'*40}):
            with self.assertRaises(Conflict):self.retain(**overrides)
        with self.assertRaisesRegex(Denied,'P5_SNAPSHOT_ANCHOR_MISMATCH'):
            self.retain(evidence_id=str(uuid.uuid4()),expected_revision=1)
        self.confirm(pending)
        with self.assertRaises(Stale):self.retain(evidence_id=str(uuid.uuid4()))

    def test_anchor_rollback_and_wrong_instance(self):
        r=self.retain();self.confirm(r)
        self.anchor=r['previousCheckpoint']
        with self.assertRaisesRegex(Denied,'P5_SNAPSHOT_ANCHOR_MISMATCH'):self.journal.read(self.evidence)
        self.anchor={**r['checkpoint'],'instanceId':str(uuid.uuid4())}
        with self.assertRaisesRegex(Denied,'P5_SNAPSHOT_ANCHOR_INVALID'):self.journal.read(self.evidence)

    def test_tampered_storage_and_missing_store(self):
        r=self.retain();self.confirm(r)
        with sqlite3.connect(self.path) as db:
            db.execute("UPDATE snapshots SET snapshot_digest=?",('f'*64,))
        with self.assertRaisesRegex(Denied,'P5_SNAPSHOT_INTEGRITY_INVALID'):self.journal.read(self.evidence)
        self.path.unlink()
        with self.assertRaisesRegex(Denied,'P5_SNAPSHOT_STORAGE_UNAVAILABLE'):self.journal.read(self.evidence)

    def test_anchor_change_during_collection_no_append(self):
        original=c.observe_selected_main
        def changing(**kw):
            result=original(**kw)
            self.anchor={**self.anchor,'eventDigest':'f'*64}
            return result
        with patch.object(c,'observe_selected_main',side_effect=changing),self.assertRaises(Denied):
            self.retain()
        self.anchor=c.genesis(self.instance)
        with self.assertRaisesRegex(Denied,'P5_SNAPSHOT_NOT_FOUND'):self.journal.read(self.evidence)
        self.assertEqual(self.retain()['result'],'LOCAL_EVIDENCE_PENDING_ANCHOR')

    def test_source_binding_rejects_wrong_core_identity(self):
        original=c.observe_selected_main
        def wrong(**kw):
            result=original(**kw)
            result['observation']['reviewedMerge']['ownerDecision']['requestId']=str(uuid.uuid4())
            return result
        with patch.object(c,'observe_selected_main',side_effect=wrong),self.assertRaises(Denied):
            self.retain()
        with self.assertRaisesRegex(Denied,'P5_SNAPSHOT_NOT_FOUND'):self.journal.receipt(self.evidence)

    def test_duplicate_initialized_path_and_sidecar_denied(self):
        with self.assertRaises(FileExistsError):
            c.CollectorSnapshotStore.initialize(self.path,instance_id=self.instance,anchor_reader=self.reader)
        Path(str(self.path)+'-journal').symlink_to(self.path)
        with self.assertRaises(Denied):self.retain()

    def test_anchor_unavailable_not_reconstructed(self):
        self.journal.anchor_reader=lambda:None
        with self.assertRaisesRegex(Denied,'P5_SNAPSHOT_ANCHOR_INVALID'):self.retain()

    def test_next_anchored_revision_preserves_older_receipt(self):
        first=self.retain();self.confirm(first)
        # A second evidence ID can retain a fresh source read; it is not a
        # duplicate desired release, and no Registry record is created.
        eid=str(uuid.uuid4())
        second=self.retain(evidence_id=eid,expected_revision=1)
        self.assertEqual(second['previousCheckpoint'],first['checkpoint'])
        with self.assertRaises(Denied):self.journal.receipt(self.evidence)
        self.confirm(second)
        old=self.journal.receipt(self.evidence)
        self.assertEqual(old['checkpoint'],first['checkpoint'])
        self.assertEqual(old['result'],'ANCHORED_CANDIDATE_EVIDENCE_RETAINED')
        self.assertEqual(self.journal.receipt(eid)['checkpoint'],second['checkpoint'])

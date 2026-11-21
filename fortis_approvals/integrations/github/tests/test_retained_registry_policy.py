"""Retained policy/source pairing, original replay and forward-range binding."""
import copy
import hashlib
import sqlite3
import uuid
import unittest
from unittest.mock import patch

from fortis_approvals.core import Authenticator, Conflict, Denied, canonical
from fortis_approvals.integrations.github.gateway import collector_snapshot as c
from fortis_approvals.integrations.github.gateway import forward_lineage as f
from fortis_approvals.integrations.github.gateway import registry_review_policy as p
from fortis_approvals.integrations.github.tests import test_registry_review_policy as fixture
from fortis_approvals.registry import boundary as b
from fortis_approvals.workflow.common import secure_dir


class RetainedRegistryPolicyTests(unittest.TestCase):
    setUp=fixture.RegistryReviewPolicyTests.setUp
    prepare=fixture.RegistryReviewPolicyTests.prepare
    approve=fixture.RegistryReviewPolicyTests.approve
    set_merge=fixture.RegistryReviewPolicyTests.set_merge

    def journal_setup(self,*,bound=True):
        self.approve(bound=bound)
        for module in (c,f,b):
            self.enterContext(patch.object(module,'REPOSITORY',p.REPOSITORY))
        self.eid=str(uuid.uuid4());self.instance=str(uuid.uuid4())
        self.anchor=c.genesis(self.instance)
        self.path=secure_dir(self.fixture.root/'policy-journal')/'snapshots.sqlite'
        self.witness=lambda:copy.deepcopy(self.anchor)
        self.journal=c.CollectorSnapshotStore.initialize(self.path,instance_id=self.instance,anchor_reader=self.witness)
        self.kw=dict(evidence_id=self.eid,expected_revision=0,owner_request_id=self.fixture.payload['requestId'],
                     selected_main_sha=self.fixture.selected,adapter=self.fixture.adapter,store=self.fixture.store,
                     core=self.fixture.core,checkpoint_reader=lambda:self.fixture.anchor,owner='test-owner',
                     validator=self.fixture.validator,policy_reader=self.reader,expected_policy_digest=self.pin,
                     clock=lambda:self.now)
        self.baseline={'schemaVersion':1,'repository':p.REPOSITORY,'enrollmentId':self.ref['enrollmentId'],
                       'baselineSha':self.ref['baselineSha'],'acceptanceReceiptDigest':self.ref['acceptanceReceiptDigest'],
                       'catalogSha256':hashlib.sha256(self.fixture.api.sources['release/targets.yaml']).hexdigest(),
                       'bindingDigest':'b'*64}

    def retain(self,**overrides):
        return self.journal.retain(**(self.kw|overrides))

    def confirm(self,r):
        self.assertEqual(self.anchor,r['previousCheckpoint'])
        self.anchor=copy.deepcopy(r['checkpoint'])

    def forward(self,**overrides):
        kw=dict(adapter=self.fixture.adapter,journal=self.journal,validator=self.fixture.validator,
                baseline_reader=lambda:copy.deepcopy(self.baseline),expected_baseline_digest=c._hash(self.baseline),
                selected_main_sha=self.fixture.selected,evidence_ids=[self.eid],
                policy_reader=self.reader,expected_policy_digest=self.pin)
        return f.observe_forward_lineage(**(kw|overrides))

    def test_atomic_retention_restart_and_forward(self):
        self.journal_setup()
        with patch.object(p,'observe_selected_main',wraps=p.observe_selected_main) as collect:
            pending=self.retain()
            self.assertEqual(collect.call_count,1)
        self.assertEqual(pending['result'],'LOCAL_EVIDENCE_PENDING_ANCHOR')
        self.assertEqual(pending['policyReferenceDigest'],self.pin)
        with self.assertRaisesRegex(Denied,'P5_SNAPSHOT_ANCHOR_MISMATCH'):
            self.journal.anchored_batch([self.eid])
        self.journal=c.CollectorSnapshotStore(self.path,instance_id=self.instance,anchor_reader=self.witness)
        with patch.object(p,'_observe_registry_review_pair',side_effect=AssertionError('must not recollect')):
            self.assertEqual(self.retain(),pending)
            self.confirm(pending);receipt=self.retain()
        snapshot=self.journal.read(self.eid)
        self.assertEqual(snapshot['schemaVersion'],2)
        self.assertEqual(snapshot['registryPolicy'],self.ref)
        self.assertEqual(c._hash(snapshot),receipt['evidenceDigest'])
        self.assertEqual(snapshot['registryReview']['observationDigest'],receipt['registryReviewDigest'])
        self.assertEqual(snapshot['registryReview']['observation']['selectedMainObservationDigest'],
                         snapshot['result']['observationDigest'])
        r=self.forward()
        self.assertEqual(r['observation']['policyReferenceDigest'],self.pin)
        self.assertEqual(r['observation']['merges'][0]['registryReviewDigest'],receipt['registryReviewDigest'])
        self.assertFalse(r['admissionAllowed'])
        # Registry remains offline and blocked, even after source matching.
        boundary=b.RegistryBoundary(authenticator=Authenticator({'reader':b.READER}),
                                    evidence_reader=self.journal.read)
        raw=canonical({'operation':'registry.preview_merged','params':{'repository':p.REPOSITORY,
             'evidenceId':self.eid,'evidenceDigest':receipt['evidenceDigest']}}).encode()
        preview=boundary.dispatch('reader',raw)
        self.assertEqual(preview['result'],'BLOCKED_EVIDENCE_GAP')
        self.assertIn('PROTECTED_REGISTRY_REVIEW_POLICY_ACCEPTANCE',preview['missingProofs'])
        self.assertFalse(preview['admissionAllowed'])

    def test_legacy_review_cannot_be_upgraded(self):
        self.journal_setup(bound=False)
        with self.assertRaisesRegex(Denied,'P5_REGISTRY_POLICY_REVIEW_NOT_BOUND'):self.retain()
        old=self.retain(policy_reader=None,expected_policy_digest=None);self.confirm(old)
        with self.assertRaises(Conflict):self.retain()
        with self.assertRaisesRegex(Denied,'P5_FORWARD_POLICY_EVIDENCE_REQUIRED'):self.forward()

    def test_policy_mode_and_pin_are_original_fingerprint(self):
        self.journal_setup();self.confirm(self.retain())
        with self.assertRaises(Conflict):self.retain(policy_reader=None,expected_policy_digest=None)
        with self.assertRaises(Conflict):self.retain(expected_policy_digest='f'*64)
        with self.assertRaisesRegex(Denied,'P5_FORWARD_POLICY_MODE_REQUIRED'):
            self.forward(policy_reader=None,expected_policy_digest=None)

    def test_baseline_claim_cannot_change_policy_enrollment(self):
        self.journal_setup();self.confirm(self.retain())
        self.baseline['enrollmentId']=str(uuid.uuid4())
        with self.assertRaisesRegex(Denied,'P5_FORWARD_POLICY_BASELINE_MISMATCH'):self.forward()

    def test_composed_review_mismatch_no_append(self):
        self.journal_setup()
        original=p._observe_registry_review_pair
        def mix(**kw):
            selected,review=original(**kw)
            review['observation']['selectedMainObservationDigest']='f'*64
            review['observationDigest']=c._hash(review['observation'])
            return selected,review
        with patch.object(p,'_observe_registry_review_pair',side_effect=mix):
            with self.assertRaisesRegex(Denied,'P5_SNAPSHOT_POLICY_BINDING_MISMATCH'):self.retain()
        with self.assertRaisesRegex(Denied,'P5_SNAPSHOT_NOT_FOUND'):self.journal.read(self.eid)

    def test_source_flags_cannot_be_promoted(self):
        self.journal_setup();self.confirm(self.retain())
        snap=self.journal.read(self.eid);snap['registryReview']['registryReviewPolicyVerified']=True
        with self.assertRaisesRegex(Denied,'P5_SNAPSHOT_POLICY_INVALID'):
            c._source(snap,{'evidenceId':self.eid,'ownerRequestId':self.kw['owner_request_id'],
                            'selectedMainSha':self.fixture.selected,'policyReferenceDigest':self.pin})

    def test_tampered_pair_detected_even_with_recomputed_local_hash(self):
        self.journal_setup();r=self.retain();self.confirm(r)
        with sqlite3.connect(self.path) as db:
            raw,fp,prev=db.execute('SELECT snapshot,fingerprint,previous_digest FROM snapshots').fetchone()
            snap=c.loads_strict(raw);rr=snap['registryReview']
            rr['observation']['ownerRequestFingerprint']='f'*64
            rr['observationDigest']=c._hash(rr['observation'])
            sd=c._hash(snap);event=c._hash([self.instance,1,self.eid,fp,sd,prev])
            db.execute('UPDATE snapshots SET snapshot=?,snapshot_digest=?,event_digest=?',
                       (canonical(snap),sd,event))
        with self.assertRaises(Denied):self.journal.read(self.eid)

    def test_policy_receipt_drift_before_append(self):
        self.journal_setup()
        original=p._observe_registry_review_pair
        def drift(**kw):
            pair=original(**kw)
            self.ref['maxReviewToMergeSeconds']+=1
            return pair
        with patch.object(p,'_observe_registry_review_pair',side_effect=drift):
            with self.assertRaises(Denied):self.retain()
        with self.assertRaisesRegex(Denied,'P5_SNAPSHOT_NOT_FOUND'):self.journal.read(self.eid)

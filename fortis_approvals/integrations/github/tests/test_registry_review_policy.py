"""Offline policy/cutoff binding with real Core, Git and retained capture."""
import copy
from datetime import datetime, timezone
import unittest
import uuid
from unittest.mock import patch

from fortis_approvals.core import Denied, Stale
from fortis_approvals.integrations.github.gateway import registry_review_policy as p
from fortis_approvals.integrations.github.tests import test_selected_main_binding as fixture


class RegistryReviewPolicyTests(unittest.TestCase):
    def setUp(self):
        self.fixture=fixture.SelectedMainTests()
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.setup_case()
        self.enterContext(patch.object(p,'REPOSITORY',self.fixture.api.head_repo))
        self.ref={'schemaVersion':1,'repository':p.REPOSITORY,'enrollmentId':str(uuid.uuid4()),
                  'baselineSha':self.fixture.kw['expected_base_sha'],'revision':1,
                  'previousDigest':'0'*64,'acceptanceReceiptDigest':'a'*64,
                  'effectiveAt':int(datetime.now(timezone.utc).timestamp())-60,
                  'maxReviewToMergeSeconds':300,'clockToleranceSeconds':0,'profile':p.policy()}
        self.pin=p._hash(self.ref)
        self.reader=lambda:copy.deepcopy(self.ref)

    def prepare(self,*,bound=True,revision2=True):
        captured=self.fixture.capture() if revision2 else self.fixture.store.capture_bundle(
            self.fixture.adapter,**self.fixture.kw)
        # Keep the entire synthetic Core request lifecycle on the same
        # capture-relative clock; slow fixture preparation cannot make
        # owner approval precede its PENDING audit event.
        self.captured=p._epoch(captured['capturedAt'])
        self.approved=int(self.captured)+2
        def make(**kwargs):
            return p.RegistryPolicyReviewAdapter(policy_reader=self.reader,
                expected_policy_digest=self.pin,**kwargs)
        core_factory=fixture.fixture.Core
        def core_at_capture(*args,**kwargs):
            return core_factory(*args,**kwargs,clock=lambda:int(self.captured)+1)
        with patch.object(fixture.fixture,'Core',side_effect=core_at_capture):
            if bound:
                with patch.object(fixture.fixture,'ReviewAttestationAdapter',side_effect=make):
                    row=self.fixture.prepare(captured)
            else:
                row=self.fixture.prepare(captured)
        self.fixture.core.clock=lambda:self.approved
        return row

    def approve(self,*,bound=True):
        row=self.prepare(bound=bound)
        self.assertEqual(self.fixture.decide(row)['state'],'EXECUTED')
        self.fixture.merge()
        self.set_merge(self.approved+10)

    def set_merge(self,epoch):
        self.fixture.api.merged_at=datetime.fromtimestamp(epoch,timezone.utc).isoformat()
        self.now=epoch+1

    def observe(self,**changes):
        opts=dict(adapter=self.fixture.adapter,store=self.fixture.store,core=self.fixture.core,
                  checkpoint_reader=lambda:self.fixture.anchor,owner='test-owner',
                  owner_request_id=self.fixture.payload['requestId'],
                  validator=self.fixture.validator,selected_main_sha=self.fixture.selected,
                  policy_reader=self.reader,expected_policy_digest=self.pin,clock=lambda:self.now)
        return p.observe_registry_review(**(opts|changes))

    def test_original_policy_review_and_cutoff(self):
        self.approve();r=self.observe()
        self.assertEqual(r['result'],'REGISTRY_REVIEW_POLICY_MATCH_CANDIDATE')
        o=r['observation'];self.assertEqual(o['policyBinding']['policyReferenceDigest'],self.pin)
        self.assertEqual(o['ownerRequestId'],self.fixture.payload['requestId'])
        self.assertEqual(o['ownerDecisionAt'],self.approved)
        self.assertEqual(r,self.observe())
        self.assertNotIn(self.fixture.api.body,repr(r))
        for k,v in r.items():
            if k.endswith(('Verified','Allowed')):self.assertIs(v,False)

    def test_original_review_without_policy_pin_not_retroactive(self):
        self.approve(bound=False)
        with self.assertRaisesRegex(Denied,'P5_REGISTRY_POLICY_REVIEW_NOT_BOUND'):self.observe()

    def test_policy_drift_during_owner_approval(self):
        row=self.prepare()
        self.ref['maxReviewToMergeSeconds']+=1
        self.assertNotEqual(self.fixture.decide(row)['state'],'EXECUTED')

    def test_policy_replacement_cannot_reuse_original_review(self):
        self.approve();self.ref['enrollmentId']=str(uuid.uuid4());self.pin=p._hash(self.ref)
        with self.assertRaisesRegex(Denied,'P5_REGISTRY_POLICY_REVIEW_NOT_BOUND'):self.observe()

    def test_unsupported_profile_and_lifecycle(self):
        original=copy.deepcopy(self.ref)
        for changes in ({'revision':2},{'previousDigest':'f'*64},{'clockToleranceSeconds':61},
                        {'maxReviewToMergeSeconds':0},{'profile':{}}):
            self.ref=original|changes
            with self.subTest(changes=changes),self.assertRaisesRegex(Denied,'P5_REGISTRY_POLICY_REFERENCE_MISMATCH'):
                p.policy_reference(self.reader,p._hash(self.ref))

    def test_v1_bundle_is_not_accepted(self):
        with self.assertRaises(Denied):self.prepare(revision2=False)

    def test_post_review_body_change(self):
        self.approve();self.fixture.api.body='changed body'
        with self.assertRaisesRegex(Denied,'P5_REGISTRY_POST_REVIEW_BODY_OR_MERGE_DRIFT'):self.observe()

    def test_rerun_after_review_blocks(self):
        self.approve();self.fixture.api.attempts[p.P5_WORKFLOWS[0].ident]=2
        with self.assertRaisesRegex(Denied,'P5_REGISTRY_POST_REVIEW_ATTEMPT_DRIFT'):self.observe()

    def test_changed_original_check_blocks(self):
        self.approve();self.fixture.checks[0]['completed_at']='2026-11-16T01:02:00Z'
        with self.assertRaisesRegex(Denied,'P5_REGISTRY_POST_REVIEW_CHECK_DRIFT'):self.observe()

    def test_future_or_expired_cutoff(self):
        self.approve()
        with self.assertRaisesRegex(Denied,'P5_REGISTRY_REVIEW_CUTOFF_UNPROVEN'):
            self.observe(clock=lambda:self.approved)
        self.set_merge(self.approved+301)
        with self.assertRaisesRegex(Denied,'P5_REGISTRY_REVIEW_CUTOFF_UNPROVEN'):self.observe()

    def test_lost_postmerge_association_does_not_replace_original(self):
        self.approve()
        for w in p.P5_WORKFLOWS:
            self.fixture.run_changes[w.ident]={'pull_requests':[]}
        self.assertEqual(self.observe()['result'],'REGISTRY_REVIEW_POLICY_MATCH_CANDIDATE')

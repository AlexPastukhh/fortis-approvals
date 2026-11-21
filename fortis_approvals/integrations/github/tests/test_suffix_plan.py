"""Post-initial range planning using actual anchored state-journal cursor.

A second Git merge and second retained candidate are synthesized, not a
second live Core approval. No admitting or writing the suffix is tested.
"""
import copy
import uuid
import unittest
from unittest.mock import patch

from fortis_approvals.core import Denied, Stale
from fortis_approvals.registry import state_journal as state
from fortis_approvals.integrations.github.gateway import admission_plan as planner
from fortis_approvals.integrations.github.gateway import forward_lineage as f
from fortis_approvals.integrations.github.gateway import component_bindings as components
from fortis_approvals.integrations.github.tests import test_admission_plan as fixture
from fortis_approvals.workflow.common import secure_dir


class SuffixPlanTests(unittest.TestCase):
    setUp=fixture.AdmissionPlanTests.setUp
    prepare=fixture.AdmissionPlanTests.prepare
    approve=fixture.AdmissionPlanTests.approve
    set_merge=fixture.AdmissionPlanTests.set_merge
    journal_setup=fixture.AdmissionPlanTests.journal_setup
    retain=fixture.AdmissionPlanTests.retain
    confirm=fixture.AdmissionPlanTests.confirm
    build=fixture.AdmissionPlanTests.build
    repin=fixture.AdmissionPlanTests.repin
    setup_plan=fixture.AdmissionPlanTests.setup_plan
    args=fixture.AdmissionPlanTests.args
    observe=fixture.AdmissionPlanTests.observe

    def setup_suffix(self):
        self.setup_plan()
        self.enterContext(patch.object(state,'REPOSITORY',planner.REPOSITORY))
        initial=self.observe()
        o=initial['observation']
        scope={k:o[k] for k in state.SCOPE_FIELDS}
        self.initial=initial
        self.state_id=str(uuid.uuid4());self.op_id=str(uuid.uuid4());self.plan_id=str(uuid.uuid4())
        self.state_anchor=state.genesis(self.state_id,scope)
        self.plan_snapshot={'schemaVersion':1,'issuer':state.COLLECTOR,'repository':state.REPOSITORY,
                            'evidenceId':self.plan_id,'plan':initial}
        path=secure_dir(self.fixture.root/'registry-state')/'registry.sqlite'
        def load(eid):
            self.assertEqual(eid,self.plan_id)
            return copy.deepcopy(self.plan_snapshot)
        self.state=state.RegistryStateJournal.initialize(path,instance_id=self.state_id,scope=scope,
                          anchor_reader=lambda:copy.deepcopy(self.state_anchor),plan_reader=load)
        pending=self.state.append_initial(actor=state.PLANNER,operation_id=self.op_id,
                  evidence_id=self.plan_id,evidence_digest=state._hash(self.plan_snapshot),expected_revision=0)
        self.assertEqual(pending['result'],'UNKNOWN_OUTCOME')
        self.state_anchor=copy.deepcopy(pending['pendingCheckpoint'])
        self.assertEqual(self.state.checkpoint()['candidateCursor'],self.fixture.selected)

    def second(self):
        """Real second merge object plus coherent synthetic second retained pair."""
        git=self.fixture.git;source=self.fixture.validator.source
        base=self.fixture.selected
        tree=git.text(['rev-parse',base+'^{tree}'],cwd=source)
        head=git.text(['commit-tree',tree,'-p',base,'-m','suffix head'],cwd=source)
        merge=git.text(['commit-tree',tree,'-p',base,'-p',head,'-m','suffix merge'],cwd=source)
        original=self.journal.anchored_batch([self.eid])
        entry=copy.deepcopy(original['entries'][0]);snap=entry['snapshot'];receipt=entry['receipt']
        obs=snap['result']['observation'];review=obs['reviewedMerge'];decision=review['ownerDecision']
        provider=review['mergeObservation'];impact=obs['retainedImpact']
        policy= snap['registryReview'];ro=policy['observation']
        new_eid=str(uuid.uuid4());new_owner=str(uuid.uuid4())
        node=f._commit(git,source,merge);h=f._commit(git,source,head);b=f._commit(git,source,base)
        snap['evidenceId']=new_eid
        obs.update(selectedMainSha=merge,number=8,rawCommitBindingSha256=f._hash([b,h,node]))
        decision.update(requestId=new_owner,number=8,headSha=head)
        provider.update(selectedMainSha=merge,firstParent=[node],headCommit=h)
        provider['pullRequest'].update(number=8,mergeSha=merge,headSha=head,baseSha=base)
        impact.update(number=8,headSha=head,baseSha=base)
        for requirement in obs['selectedMainLocalDependencies']:requirement['sourceSha']=merge
        obs.update(reviewedMergeSha256=f._hash(review),retainedImpactSha256=f._hash(impact))
        snap['result']['observationDigest']=f._hash(obs)
        ro.update(selectedMainSha=merge,ownerRequestId=new_owner,
                  selectedMainObservationDigest=snap['result']['observationDigest'])
        policy['observationDigest']=f._hash(ro)
        next_cp={**original['checkpoint'],'revision':2,'eventDigest':'f'*64}
        receipt.update(evidenceId=new_eid,ownerRequestId=new_owner,selectedMainSha=merge,
                       registryReviewDigest=policy['observationDigest'],
                       evidenceDigest=f._hash(snap),checkpoint=next_cp)
        suffix={'checkpoint':next_cp,'entries':[entry]}
        read_batch=self.journal.anchored_batch
        def batch(eids):
            if eids==[new_eid]:return copy.deepcopy(suffix)
            return read_batch(eids)
        return merge,new_eid,suffix,batch

    def query(self,merge,eid,*,batch,**kwargs):
        args=self.args()|{'selected_main_sha':merge,'evidence_ids':[eid]}
        with patch.object(self.fixture.adapter,'_project_branch',
                          return_value={'name':'main','sha':merge}):
            with patch.object(self.journal,'anchored_batch',side_effect=batch):
                return planner.observe_suffix_plan(cursor_reader=self.state.checkpoint,**(args|kwargs))

    def test_only_new_merge_actions_and_new_record_id(self):
        self.setup_suffix();merge,eid,suffix,batch=self.second()
        result=self.query(merge,eid,batch=batch);o=result['observation']
        self.assertEqual(result['result'],'SUFFIX_RANGE_PLAN_CANDIDATE')
        self.assertEqual(o['startCursorSha'],self.fixture.selected)
        self.assertEqual(o['registryCursorCheckpoint'],self.state_anchor)
        self.assertEqual([m['mergeSha'] for m in o['mergeAudit']],[merge])
        self.assertEqual([m['evidenceId'] for m in o['mergeAudit']],[eid])
        self.assertEqual(len(o['recordCandidates']),1)
        self.assertEqual(o['recordCandidates'][0]['evidenceIds'],[eid])
        self.assertNotEqual(o['recordCandidates'][0]['recordId'],
                            self.initial['observation']['recordCandidates'][0]['recordId'])
        self.assertEqual(o['recordCandidates'][0]['identity']['desiredSourceSha'],merge)
        self.assertEqual(result,self.query(merge,eid,batch=batch))
        self.assertFalse(result['admissionAllowed'])

    def test_missing_suffix_or_old_merge_cannot_be_replayed(self):
        self.setup_suffix();merge,eid,suffix,batch=self.second()
        with self.assertRaisesRegex(Denied,'P5_FORWARD_MISSING_MERGE_EVIDENCE'):
            self.query(merge,eid,batch=batch,evidence_ids=[])
        def both(eids):
            if eids==[self.eid,eid]:
                old=self.journal.anchored_batch([self.eid])['entries'][0]
                return {'checkpoint':suffix['checkpoint'],'entries':[old,*suffix['entries']]}
            return batch(eids)
        with self.assertRaisesRegex(Denied,'P5_FORWARD_UNUSED_EVIDENCE'):
            self.query(merge,eid,batch=both,evidence_ids=[self.eid,eid])

    def test_empty_suffix_and_nonmerge_blocked(self):
        self.setup_suffix()
        with self.assertRaisesRegex(Denied,'P5_PLAN_EMPTY_SUFFIX'):
            self.query(self.fixture.selected,self.eid,batch=self.journal.anchored_batch,evidence_ids=[])
        git=self.fixture.git;source=self.fixture.validator.source
        tree=git.text(['rev-parse',self.fixture.selected+'^{tree}'],cwd=source)
        direct=git.text(['commit-tree',tree,'-p',self.fixture.selected,'-m','unreviewed'],cwd=source)
        with self.assertRaisesRegex(Denied,'P5_FORWARD_UNATTRIBUTED_NON_MERGE'):
            self.query(direct,self.eid,batch=self.journal.anchored_batch,evidence_ids=[])

    def test_unanchored_cursor_and_wrong_scope_block(self):
        self.setup_suffix();merge,eid,suffix,batch=self.second()
        good=copy.deepcopy(self.state_anchor)
        self.state_anchor={**good,'eventDigest':'0'*64}
        with self.assertRaisesRegex(Denied,'REGISTRY_STATE_ANCHOR_MISMATCH'):
            self.query(merge,eid,batch=batch)
        self.state_anchor=copy.deepcopy(self.state.initial)
        with self.assertRaisesRegex(Denied,'REGISTRY_STATE_ANCHOR_MISMATCH'):
            self.query(merge,eid,batch=batch)
        self.state_anchor=good
        with self.assertRaisesRegex(Denied,'P5_FORWARD_CURSOR_READER_REQUIRED'):
            args=self.args()|{'selected_main_sha':merge,'evidence_ids':[eid]}
            planner.observe_suffix_plan(cursor_reader=lambda:self.state.checkpoint(),**args)

    def test_cursor_change_during_capture(self):
        self.setup_suffix();merge,eid,suffix,batch=self.second()
        before=copy.deepcopy(self.state_anchor)
        original=f.observe_forward_lineage
        def drift(**kw):
            result=original(**kw)
            self.state_anchor={**before,'eventDigest':'0'*64}
            return result
        with patch.object(components,'observe_forward_lineage',side_effect=drift):
            with self.assertRaises(Denied):self.query(merge,eid,batch=batch)

    def test_cross_enrollment_state_reader_not_accepted(self):
        self.setup_suffix()
        other_scope={**self.state.scope,'enrollmentId':str(uuid.uuid4())}
        other_instance=str(uuid.uuid4())
        other_anchor=state.genesis(other_instance,other_scope)
        path=secure_dir(self.fixture.root/'other-registry')/'state.sqlite'
        other=state.RegistryStateJournal.initialize(path,instance_id=other_instance,scope=other_scope,
                    anchor_reader=lambda:copy.deepcopy(other_anchor),plan_reader=lambda eid:None)
        with self.assertRaisesRegex(Denied,'P5_FORWARD_CURSOR_SCOPE_MISMATCH'):
            planner.observe_suffix_plan(cursor_reader=other.checkpoint,**self.args())

    def test_cannot_treat_suffix_as_initial_or_advance_journal(self):
        self.setup_suffix();merge,eid,suffix,batch=self.second()
        self.assertEqual(self.state.checkpoint()['candidateCursor'],self.fixture.selected)
        result=self.query(merge,eid,batch=batch)
        self.assertEqual(result['observation']['recordCandidates'][0]['identity']['desiredSourceSha'],merge)
        self.assertEqual(self.state.checkpoint()['candidateCursor'],self.fixture.selected)
        self.assertNotIn('supersedesRecordId',result['observation']['recordCandidates'][0])
        with self.assertRaisesRegex(Denied,'P5_PLAN_CURSOR_NOT_ALLOWED_FOR_INITIAL'):
            planner.observe_initial_plan(**(self.args()|{'cursor_reader':self.state.checkpoint}))

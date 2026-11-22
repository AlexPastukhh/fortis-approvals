"""Offline P5 collector/plan → SQLite schema-3 integration, not live trust."""
import copy
from unittest.mock import patch
import unittest
import uuid

from fortis_approvals.core import Denied, Stale
from fortis_approvals.registry import functional_v1_journal as local
from fortis_approvals.registry import state_journal as state
from fortis_approvals.integrations.github.gateway import admission_plan as planner
from fortis_approvals.integrations.github.tests import test_suffix_plan as fixture
from fortis_approvals.workflow.common import secure_dir


class OfflineSourceCompositionTests(unittest.TestCase):
    # Use original Git/Core/collector fixture plumbing without inheriting its
    # unrelated test methods. The second retained merge remains synthetic.
    setUp=fixture.SuffixPlanTests.setUp
    prepare=fixture.SuffixPlanTests.prepare
    approve=fixture.SuffixPlanTests.approve
    set_merge=fixture.SuffixPlanTests.set_merge
    journal_setup=fixture.SuffixPlanTests.journal_setup
    retain=fixture.SuffixPlanTests.retain
    confirm=fixture.SuffixPlanTests.confirm
    build=fixture.SuffixPlanTests.build
    repin=fixture.SuffixPlanTests.repin
    setup_plan=fixture.SuffixPlanTests.setup_plan
    args=fixture.SuffixPlanTests.args
    observe=fixture.SuffixPlanTests.observe
    setup_suffix=fixture.SuffixPlanTests.setup_suffix
    second=fixture.SuffixPlanTests.second

    def compose(self):
        self.setup_suffix()
        self.instance=str(uuid.uuid4())
        self.scope=copy.deepcopy(self.state.scope)
        path=secure_dir(self.fixture.root/'registry-source-composition')/'state.sqlite'
        local.FunctionalV1CandidateJournal.initialize(
            path,instance_id=self.instance,scope=self.scope,
            plan_reader=lambda _:self.fail('source callback must be sealed'))
        args=self.args()
        self.collector_checkpoint=copy.deepcopy(
            self.journal.anchored_batch([])['checkpoint'])
        self.inputs={name:args[name] for name in (
            'adapter','journal','validator','baseline_reader',
            'expected_baseline_digest','policy_reader',
            'expected_policy_digest','binding_reader')}
        self.inputs['expected_collector_checkpoint']=self.collector_checkpoint
        self.composition=local.OfflineSourceRangeComposition(
            path=path,instance_id=self.instance,scope=self.scope,
            **self.inputs)
        self.path=path
        return self.composition

    def append_initial(self):
        self.first_op=str(uuid.uuid4())
        response=self.composition.compose_and_append(
            operation_id=self.first_op,expected_revision=0,
            selected_main_sha=self.fixture.selected,
            evidence_ids=[self.eid])
        self.assertEqual(response['result'],'INACTIVE_SOURCE_RANGE_CANDIDATE')
        self.assertEqual(response['storage']['result'],
                         'LOCAL_DESIRED_CANDIDATE_COMMITTED')
        self.assertEqual(response['selectedMainSha'],self.fixture.selected)
        self.assertFalse(response['evidenceVerified'])
        self.assertFalse(response['admissionAllowed'])
        self.assertFalse(response['deploymentAllowed'])
        self.assertFalse(response['writeEnabled'])
        return response

    def append_suffix(self):
        merge,eid,_,batch=self.second()
        with patch.object(self.fixture.adapter,'_project_branch',
                          return_value={'name':'main','sha':merge}):
            with patch.object(self.journal,'anchored_batch',side_effect=batch):
                response=self.composition.compose_and_append(
                    operation_id=str(uuid.uuid4()),expected_revision=1,
                    selected_main_sha=merge,evidence_ids=[eid])
        return merge,response

    def test_github_core_original_persisted_collector_plan_into_desired(self):
        comp=self.compose()
        first=self.append_initial()
        original=first['storage']['receipt']
        self.assertEqual(first['collectorCheckpointCandidate'],
                         self.collector_checkpoint)
        self.assertIs(first['collectorProvenanceVerified'],False)
        latest=comp.candidate_page(limit=10)
        self.assertEqual(latest['candidateSourceSha'],self.fixture.selected)
        self.assertEqual(latest['localRevision'],1)
        self.assertEqual(latest['integrityModel'],'LOCAL_EVENT_CHAIN_ONLY')
        self.assertEqual([x['recordId'] for x in latest['records']],
                         original['recordIds'])
        self.assertIsNone(latest['records'][0]['actual'])
        self.assertFalse(latest['deploymentVerified'])
        with __import__('sqlite3').connect(self.path) as db:
            self.assertEqual(db.execute('SELECT COUNT(*) FROM records').fetchone()[0],1)
            self.assertEqual(db.execute('SELECT COUNT(*) FROM operations').fetchone()[0],1)

    def test_fake_second_retained_receipt_cannot_supersede_original(self):
        comp=self.compose()
        first=self.append_initial()
        # The old source-only test monkeypatched journal.anchored_batch to
        # invent a second retained receipt and advance desired. The pinned
        # original method must now ignore the patch and refuse this event.
        with self.assertRaisesRegex(Denied,'P5_SNAPSHOT_NOT_FOUND'):
            self.append_suffix()
        latest=comp.candidate_page(limit=10)
        self.assertEqual(latest['localRevision'],1)
        self.assertEqual(latest['records'][0]['recordId'],
                         first['storage']['receipt']['recordIds'][0])
        self.assertIsNone(latest['records'][0]['actual'])


    def test_requires_real_original_collector_and_exact_bound_method(self):
        comp=self.compose()
        real=dict(self.inputs)
        fake=type('SelfConsistentJournal',(),{
            'instance_id':self.journal.instance_id,
            'anchored_batch':lambda _self,eids:self.journal.anchored_batch(eids),
        })()
        with self.assertRaisesRegex(
                Denied,'REGISTRY_SOURCE_ORIGINAL_COLLECTOR_REQUIRED'):
            local.OfflineSourceRangeComposition(
                path=self.path,instance_id=self.instance,
                scope=self.scope,**(real|{'journal':fake}))
        with patch.object(self.journal,'anchored_batch',
                          return_value=self.journal.anchored_batch([])):
            with self.assertRaisesRegex(
                    Denied,'REGISTRY_SOURCE_ORIGINAL_COLLECTOR_REQUIRED'):
                local.OfflineSourceRangeComposition(
                    path=self.path,instance_id=self.instance,
                    scope=self.scope,**real)
        self.assertEqual(comp.candidate_page(limit=2)['localRevision'],0)

    def test_collector_checkpoint_is_host_pinned_not_self_selected(self):
        self.compose()
        cases=(
            {**self.collector_checkpoint,'instanceId':str(uuid.uuid4())},
            {**self.collector_checkpoint,'revision':0},
            {**self.collector_checkpoint,'eventDigest':'f'*64},
            {**self.collector_checkpoint,'revision':True},
            {'schemaVersion':1},
        )
        for candidate in cases:
            with self.subTest(candidate=candidate),self.assertRaises(Denied):
                local.OfflineSourceRangeComposition(
                    path=self.path,instance_id=self.instance,
                    scope=self.scope,
                    **(self.inputs|{
                        'expected_collector_checkpoint':candidate}))
        self.assertEqual(
            local.OfflineSourceRangeComposition(
                path=self.path,instance_id=self.instance,
                scope=self.scope,**self.inputs).candidate_page(limit=2)
                 ['localRevision'],0)

    def test_original_collector_anchor_drift_after_plan_cannot_commit(self):
        comp=self.compose()
        real=planner.observe_initial_plan
        initial=copy.deepcopy(self.anchor)
        def drift(**kwargs):
            plan=real(**kwargs)
            self.anchor={**self.anchor,'eventDigest':'f'*64}
            return plan
        try:
            with patch.object(planner,'observe_initial_plan',side_effect=drift):
                with self.assertRaisesRegex(
                        Denied,'P5_SNAPSHOT_ANCHOR_MISMATCH'):
                    comp.compose_and_append(
                        operation_id=str(uuid.uuid4()),expected_revision=0,
                        selected_main_sha=self.fixture.selected,
                        evidence_ids=[self.eid])
        finally:
            self.anchor=initial
        self.assertEqual(comp.candidate_page(limit=2)['localRevision'],0)

    def test_replacing_collector_method_after_constructor_does_not_forge_evidence(self):
        comp=self.compose()
        # The bound method was already captured by the pinned adapter.
        with patch.object(self.journal,'anchored_batch',
                          side_effect=AssertionError('forged batch called')):
            result=comp.compose_and_append(
                operation_id=str(uuid.uuid4()),expected_revision=0,
                selected_main_sha=self.fixture.selected,evidence_ids=[self.eid])
        self.assertEqual(result['result'],'INACTIVE_SOURCE_RANGE_CANDIDATE')
        self.assertFalse(result['collectorProvenanceVerified'])
        self.assertEqual(comp.candidate_page(limit=2)['localRevision'],1)

    def test_corrupt_persisted_collector_snapshot_cannot_create_desired(self):
        import sqlite3
        comp=self.compose()
        with sqlite3.connect(self.journal.path) as db:
            db.execute("UPDATE snapshots SET snapshot_digest=?",('f'*64,))
        with self.assertRaisesRegex(Denied,'P5_SNAPSHOT_INTEGRITY_INVALID'):
            comp.compose_and_append(
                operation_id=str(uuid.uuid4()),expected_revision=0,
                selected_main_sha=self.fixture.selected,
                evidence_ids=[self.eid])
        self.assertEqual(comp.candidate_page(limit=2)['localRevision'],0)

    def test_exact_operation_lookup_after_commit_without_collector_or_effect(self):
        comp=self.compose()
        first=self.append_initial()
        with self.assertRaises(TypeError):
            comp.sources['journal']=object()
        with patch.object(self.journal,'anchored_batch',
                          side_effect=AssertionError('must not recollect')):
            original=comp.operation(operation_id=self.first_op)
            self.assertEqual(original,first['storage'])
            self.assertEqual(comp.candidate_page(limit=3)['localRevision'],1)
        with self.assertRaisesRegex(Stale,'REGISTRY_SOURCE_REVISION_STALE'):
            comp.compose_and_append(
                operation_id=self.first_op,expected_revision=0,
                selected_main_sha=self.fixture.selected,evidence_ids=[self.eid])
        self.assertEqual(comp.operation(operation_id=self.first_op),original)

    def test_reject_missing_evidence_invalid_requests_and_fake_direct_plan(self):
        comp=self.compose()
        for changed in ({'operation_id':'not-uuid'},
                        {'selected_main_sha':'bad'},
                        {'evidence_ids':['not-uuid']},
                        {'evidence_ids':[self.eid,self.eid]},
                        {'expected_revision':True},
                        {'expected_revision':-1}):
            with self.subTest(changed=changed),self.assertRaisesRegex(
                    Denied,'REGISTRY_SOURCE_REQUEST_INVALID'):
                comp.compose_and_append(**({
                    'operation_id':str(uuid.uuid4()),
                    'expected_revision':0,
                    'selected_main_sha':self.fixture.selected,
                    'evidence_ids':[self.eid],
                }|changed))
        with self.assertRaises(Denied):
            comp.compose_and_append(
                operation_id=str(uuid.uuid4()),expected_revision=0,
                selected_main_sha=self.fixture.selected,evidence_ids=[])
        with self.assertRaises(TypeError):
            comp.compose_and_append(
                operation_id=str(uuid.uuid4()),expected_revision=0,
                selected_main_sha=self.fixture.selected,evidence_ids=[self.eid],
                plan={'admissionAllowed':True})
        self.assertEqual(comp.candidate_page(limit=10)['localRevision'],0)

    def test_wrong_scope_and_unproven_main_cannot_write(self):
        comp=self.compose()
        with self.assertRaisesRegex(Denied,'REGISTRY_SOURCE_COMPOSITION_INVALID'):
            local.OfflineSourceRangeComposition(
                path=self.path,instance_id=self.instance,
                scope={**self.scope,'policyReferenceDigest':'0'*64},
                **self.inputs)
        with self.assertRaises((Denied,Stale)):
            comp.compose_and_append(
                operation_id=str(uuid.uuid4()),expected_revision=0,
                selected_main_sha='f'*40,evidence_ids=[self.eid])
        self.assertEqual(comp.candidate_page(limit=10)['localRevision'],0)

    def test_competing_state_advance_during_capture_causes_stale_stop(self):
        comp=self.compose()
        real=planner.observe_initial_plan
        def drift(**kwargs):
            plan=real(**kwargs)
            evidence_id=str(uuid.uuid4())
            evidence={'schemaVersion':1,'issuer':state.COLLECTOR,
                      'repository':state.REPOSITORY,
                      'evidenceId':evidence_id,'plan':plan}
            writer=local.FunctionalV1CandidateJournal(
                self.path,instance_id=self.instance,scope=self.scope,
                plan_reader=lambda eid:copy.deepcopy(evidence))
            accepted=writer.append_range(
                actor=state.PLANNER,operation_id=str(uuid.uuid4()),
                evidence_id=evidence_id,evidence_digest=state._hash(evidence),
                expected_revision=0)
            self.assertEqual(accepted['result'],'LOCAL_DESIRED_CANDIDATE_COMMITTED')
            return plan
        with patch.object(planner,'observe_initial_plan',side_effect=drift):
            with self.assertRaisesRegex(Stale,'REGISTRY_SOURCE_CURSOR_CHANGED'):
                comp.compose_and_append(
                    operation_id=str(uuid.uuid4()),expected_revision=0,
                    selected_main_sha=self.fixture.selected,
                    evidence_ids=[self.eid])
        self.assertEqual(comp.candidate_page(limit=10)['localRevision'],1)

    def test_lost_postcommit_ack_is_unknown_until_original_uuid_readback(self):
        comp=self.compose()
        operation_id=str(uuid.uuid4())
        with patch.object(local.FunctionalV1CandidateJournal,'operation',
                          side_effect=Denied('INJECTED_READBACK_UNAVAILABLE')):
            result=comp.compose_and_append(
                operation_id=operation_id,expected_revision=0,
                selected_main_sha=self.fixture.selected,
                evidence_ids=[self.eid])
        self.assertEqual(result['result'],'UNKNOWN_OUTCOME')
        self.assertEqual(result['storage']['result'],'UNKNOWN_OUTCOME')
        self.assertFalse(result['admissionAllowed'])
        recovered=comp.operation(operation_id=operation_id)
        self.assertEqual(recovered['result'],'LOCAL_DESIRED_CANDIDATE_COMMITTED')
        self.assertEqual(comp.candidate_page(limit=10)['localRevision'],1)
        with self.assertRaisesRegex(Stale,'REGISTRY_SOURCE_REVISION_STALE'):
            comp.compose_and_append(
                operation_id=operation_id,expected_revision=0,
                selected_main_sha=self.fixture.selected,
                evidence_ids=[self.eid])

    def test_read_missing_database_and_unknown_operation_do_not_forge_queue(self):
        comp=self.compose()
        lookup=comp.operation(operation_id=str(uuid.uuid4()))
        self.assertEqual(lookup['result'],'LOCAL_CANDIDATE_OPERATION_NOT_FOUND')
        self.assertFalse(lookup['admissionAllowed'])
        self.path.rename(self.path.with_name('removed.sqlite'))
        with self.assertRaises(Denied):
            comp.candidate_page(limit=5)


if __name__=='__main__':
    unittest.main()

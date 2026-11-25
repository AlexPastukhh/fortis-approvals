"""Functional V1 local Registry desired candidate journal, no witness/GO.

These are offline trust-boundary tests. Never assert that a locally matching
event chain is an owner acceptance, verified merge, installed version or
adversarial rollback proof.
"""
import copy
import os
from pathlib import Path
import sqlite3
import tempfile
import threading
from concurrent.futures import ThreadPoolExecutor
import unittest

from fortis_approvals.core import Conflict, Denied, Stale
from fortis_approvals.registry import functional_v1_journal as local
from fortis_approvals.registry import state_journal_v2 as v2
from fortis_approvals.tests.test_registry_state_journal import sample, uid
from fortis_approvals.tests.test_registry_state_journal_v2 import next_evidence


class FunctionalV1JournalTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.path = Path(temp.name) / 'functional.sqlite'
        self.scope = {
            'repository': local.REPOSITORY, 'enrollmentId': uid(),
            'baselineSha': 'a'*40, 'baselineDigest': 'a'*64,
            'catalogSha256': 'b'*64, 'bindingDigest': 'c'*64,
            'policyReferenceDigest': 'd'*64,
        }
        self.instance = uid()
        self.current = sample(self.scope)
        self.reads = 0
        self.state = local.FunctionalV1CandidateJournal.initialize(
            self.path, instance_id=self.instance,
            scope=self.scope, plan_reader=self.read,
        )
        self.operations = []

    def read(self, evidence_id):
        self.reads += 1
        self.assertEqual(evidence_id, self.current['evidenceId'])
        return copy.deepcopy(self.current)

    def args(self, *, op=None, revision=None):
        return {
            'actor': local.PLANNER,
            'operation_id': op or uid(),
            'evidence_id': self.current['evidenceId'],
            'evidence_digest': local._hash(self.current),
            'expected_revision': len(self.operations)
            if revision is None else revision,
        }

    def append(self, **changes):
        return self.state.append_range(**(self.args() | changes))

    def accept(self):
        args = self.args()
        result = self.state.append_range(**args)
        self.assertEqual(result['result'], 'LOCAL_DESIRED_CANDIDATE_COMMITTED')
        receipt = result['receipt']
        self.operations.append((args, receipt))
        return receipt

    def suffix(self, *, target='app', deploy=True):
        receipt = self.operations[-1][1]
        self.current = next_evidence(
            self.scope, receipt, receipt['checkpoint'],
            self.current['plan']['observation']['collectorCheckpoint'],
            target=target, deploy=deploy,
        )

    def count(self, table):
        with sqlite3.connect(self.path) as db:
            return db.execute('SELECT COUNT(*) FROM '+table).fetchone()[0]

    def test_local_bootstrap_private_versioned_no_external_witness(self):
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.count('operations'), 0)
        head=self.state.checkpoint()
        self.assertEqual(head['result'], 'LOCAL_SOURCE_CANDIDATE_HEAD')
        self.assertEqual(head['localCheckpoint']['revision'], 0)
        self.assertEqual(head['integrityModel'], 'LOCAL_EVENT_CHAIN_ONLY')
        self.assertFalse(head['admissionAllowed'])
        self.assertFalse(head['evidenceVerified'])
        self.assertFalse(head['deploymentAllowed'])
        self.assertEqual(self.state.list_desired_candidates(limit=1)['records'],[])
        with sqlite3.connect(self.path) as db:
            self.assertEqual(db.execute('PRAGMA user_version').fetchone(),(3,))
        with self.assertRaisesRegex(Denied, 'NO_EXTERNAL_ANCHOR'):
            self.state._anchor()
        with self.assertRaisesRegex(Denied, 'REGISTRY_LOCAL_ALREADY_EXISTS'):
            local.FunctionalV1CandidateJournal.initialize(
                self.path,instance_id=self.instance,scope=self.scope,
                plan_reader=self.read)

    def test_initial_commit_and_restart_replay_same_original_uuid(self):
        operation = self.args()
        response=self.state.append_range(**operation)
        self.assertEqual(response['result'],'LOCAL_DESIRED_CANDIDATE_COMMITTED')
        receipt=response['receipt']
        self.assertEqual(receipt['schemaVersion'],3)
        self.assertEqual(receipt['integrityModel'],'LOCAL_EVENT_CHAIN_ONLY')
        self.assertFalse(receipt['evidenceVerified'])
        self.assertFalse(receipt['admissionAllowed'])
        self.assertFalse(receipt['deploymentAllowed'])
        self.assertEqual(self.count('operations'),1)
        self.assertEqual(self.count('records'),1)
        self.current={'plan':{}}
        self.state = local.FunctionalV1CandidateJournal(
            self.path,instance_id=self.instance,scope=self.scope,
            plan_reader=lambda _:self.fail('replay must not call reader'))
        self.assertEqual(self.state.operation(
            actor=local.PLANNER,operation_id=operation['operation_id']),response)
        self.assertEqual(self.state.append_range(**operation),response)
        self.assertEqual(self.count('operations'),1)
        page=self.state.list_desired_candidates(limit=10)
        self.assertEqual(page['result'],'LOCAL_DESIRED_CANDIDATE_PAGE')
        self.assertEqual(len(page['records']),1)
        self.assertIsNone(page['records'][0]['actual'])
        self.assertEqual(page['records'][0]['identity']['desiredSourceSha'],'b'*40)
        self.assertFalse(page['deploymentVerified'])
        self.assertFalse(page['writeEnabled'])

    def test_cutover_gap_is_retained_only_with_first_real_ingestion(self):
        plan = self.current['plan']
        observation = plan['observation']
        gap = {'disposition': 'OWNER_REVIEWED_PRE_CAPTURE_GAP', 'merges': [
            {'number': 253, 'headSha': '1'*40, 'mergeSha': '2'*40,
             'impact': {'gateway-owner-controller': ['windows-update']}},
            {'number': 254, 'headSha': '3'*40, 'mergeSha': '4'*40,
             'impact': {'fortis-registry-pilot': ['image-rebuild']}},
        ]}
        genesis = self.state.checkpoint()
        observation['cutoverGap'] = gap
        plan['observationDigest'] = local._hash(observation)
        with self.assertRaisesRegex(Denied, 'RANGE_INVALID'):
            self.append()
        self.assertEqual(self.state.checkpoint(), genesis)
        observation['mergeAudit'][0]['baseSha'] = gap['merges'][-1]['mergeSha']
        plan['observationDigest'] = local._hash(observation)
        first = self.accept()
        self.assertEqual(first['cutoverGap'], gap)
        self.assertEqual(first['previousCheckpoint'], genesis['localCheckpoint'])
        self.assertEqual(first['startCursorSha'], self.scope['baselineSha'])
        self.assertEqual(len(first['recordIds']), 1)

        self.state = local.FunctionalV1CandidateJournal(
            self.path, instance_id=self.instance, scope=self.scope, plan_reader=self.read)
        self.assertEqual(self.state.append_range(**self.operations[0][0])['receipt'], first)
        self.suffix()
        suffix = self.current['plan']
        suffix['observation']['cutoverGap'] = gap
        suffix['observationDigest'] = local._hash(suffix['observation'])
        with self.assertRaisesRegex(Denied, 'CUTOVER_GAP'):
            self.append()
        self.suffix()
        self.assertNotIn('cutoverGap', self.accept())
        self.assertEqual(self.count('operations'), 2)

    def test_post_255_gap_creates_records_only_for_the_captured_merge(self):
        plan = self.current['plan']
        observation = plan['observation']
        rows = [
            {'number': 253 + index, 'headSha': f'{2 * index + 1:040x}',
             'mergeSha': f'{2 * index + 2:040x}',
             'impact': {'fortis-gateway': ['image-rebuild']}}
            for index in range(5)
        ]
        gap = {'disposition': 'OWNER_REVIEWED_POST_255_CAPTURE_GAP', 'merges': rows[:3]}
        observation['cutoverGap'] = gap
        plan['observationDigest'] = local._hash(observation)
        with self.assertRaisesRegex(Denied, 'CUTOVER_GAP'):
            self.append()
        gap['merges'] = rows
        observation['mergeAudit'][0]['baseSha'] = rows[-1]['mergeSha']
        plan['observationDigest'] = local._hash(observation)
        receipt = self.accept()
        self.assertEqual(receipt['cutoverGap'], gap)
        self.assertEqual(len(receipt['recordIds']), 1)
        self.assertEqual(self.count('records'), 1)

    def test_post_267_gap_keeps_all_uncaptured_merges_out_of_desired(self):
        self.assert_cutover_gap_keeps_uncaptured_merges_out_of_desired(16, 14)

    def test_post_269_gap_keeps_all_uncaptured_merges_out_of_desired(self):
        self.assert_cutover_gap_keeps_uncaptured_merges_out_of_desired(18, 17)

    def test_post_270_gap_keeps_all_uncaptured_merges_out_of_desired(self):
        self.assert_cutover_gap_keeps_uncaptured_merges_out_of_desired(19, 17)

    def test_post_271_gap_keeps_all_uncaptured_merges_out_of_desired(self):
        self.assert_cutover_gap_keeps_uncaptured_merges_out_of_desired(20, 17)

    def assert_cutover_gap_keeps_uncaptured_merges_out_of_desired(self, size, partial_size):
        plan = self.current['plan']
        observation = plan['observation']
        rows = [
            {'number': 253 + index, 'headSha': f'{2 * index + 1:040x}',
             'mergeSha': f'{2 * index + 2:040x}',
             'impact': {'fortis-gateway': ['image-rebuild']}}
            for index in range(size)
        ]
        gap = {'disposition': 'OWNER_REVIEWED_POST_255_CAPTURE_GAP', 'merges': rows[:partial_size]}
        observation['cutoverGap'] = gap
        observation['mergeAudit'][0]['baseSha'] = rows[-1]['mergeSha']
        plan['observationDigest'] = local._hash(observation)
        with self.assertRaisesRegex(Denied, 'CUTOVER_GAP'):
            self.append()
        gap['merges'] = rows
        plan['observationDigest'] = local._hash(observation)
        receipt = self.accept()
        self.assertEqual(receipt['cutoverGap'], gap)
        self.assertEqual(len(receipt['recordIds']), 1)
        self.assertEqual(self.count('records'), 1)

    def test_suffix_supersession_and_persistent_history(self):
        first=self.accept()
        self.suffix()
        second=self.accept()
        self.assertNotEqual(first['recordIds'],second['recordIds'])
        self.assertEqual(second['supersessions'],[{
            'fromRecordId':first['recordIds'][0],
            'toRecordId':second['recordIds'][0]}])
        self.assertEqual(self.count('records'),2)
        self.assertEqual(self.count('supersessions'),1)
        page=self.state.list_desired_candidates(limit=10)
        self.assertEqual(len(page['records']),1)
        self.assertEqual(page['records'][0]['recordId'],second['recordIds'][0])
        self.assertEqual(page['records'][0]['identity']['desiredSourceSha'],'c'*40)
        self.assertIsNone(page['records'][0]['actual'])
        self.assertEqual(
            self.state.operation(actor=local.PLANNER,
                                 operation_id=self.operations[0][0]['operation_id'])
                ['receipt'],first)

    def test_no_deployment_suffix_keeps_desired_and_updates_source_cursor(self):
        first=self.accept();self.suffix(deploy=False)
        second=self.accept()
        self.assertEqual(second['recordIds'],[])
        self.assertEqual(second['supersessions'],[])
        self.assertEqual(self.count('records'),1)
        page=self.state.list_desired_candidates(limit=2)
        self.assertEqual(page['candidateSourceSha'],'c'*40)
        self.assertEqual(page['records'][0]['recordId'],first['recordIds'][0])

    def test_multiple_targets_pagination_and_stale_cursor(self):
        self.accept();self.suffix(target='worker');self.accept()
        first=self.state.list_desired_candidates(limit=1)
        self.assertIsNotNone(first['nextCursor'])
        second=self.state.list_desired_candidates(
            limit=1,cursor=first['nextCursor'])
        self.assertEqual(len(second['records']),1)
        self.assertIsNone(second['nextCursor'])
        ids={x['recordId'] for x in first['records']+second['records']}
        self.assertEqual(len(ids),2)
        self.suffix(deploy=False);self.accept()
        with self.assertRaisesRegex(Denied,'REGISTRY_LOCAL_PAGE_CURSOR_STALE'):
            self.state.list_desired_candidates(
                limit=1,cursor=first['nextCursor'])
        new=self.state.list_desired_candidates(limit=10)
        self.assertEqual(new['candidateSourceSha'],'d'*40)
        self.assertEqual(len(new['records']),2)

    def test_invalid_limits_cursor_and_scope_are_denied(self):
        for limit in (0,-1,101,True,1.0,None):
            with self.subTest(limit=limit),self.assertRaises(Denied):
                self.state.list_desired_candidates(limit=limit)
        for cursor in ('../test','',3,'f'*64+'_'+ 'a'*64):
            with self.subTest(cursor=cursor),self.assertRaises(Denied):
                self.state.list_desired_candidates(limit=1,cursor=cursor)
        with self.assertRaises(Denied):
            local.FunctionalV1CandidateJournal(
                self.path,instance_id=self.instance,
                scope={**self.scope,'repository':'Other/repo'},
                plan_reader=self.read)

    def test_cas_stale_revision_and_original_uuid_conflict(self):
        args=self.args()
        self.state.append_range(**args)
        with self.assertRaisesRegex(Stale,'REGISTRY_LOCAL_REVISION_STALE'):
            self.state.append_range(**(self.args()|{'operation_id':uid()}))
        with self.assertRaisesRegex(Conflict,'REGISTRY_LOCAL_OPERATION_CONFLICT'):
            self.state.append_range(**{**args,'evidence_digest':'a'*64})
        self.assertEqual(self.count('operations'),1)

    def test_missing_or_invalid_plan_never_commits(self):
        original=self.current
        for replacement in (None,{}, {'schemaVersion':1,'plan':{}},'bad'):
            self.current=replacement
            with self.subTest(replacement=replacement),self.assertRaises(
                    (Denied,TypeError,ValueError)):
                self.state.append_range(
                    actor=local.PLANNER,operation_id=uid(),
                    evidence_id=original['evidenceId'],
                    evidence_digest=local._hash(original),
                    expected_revision=0)
        self.current=original
        self.assertEqual(self.count('operations'),0)
        self.assertEqual(self.count('records'),0)

    def test_not_a_live_actor_or_installed_state_authority(self):
        args=self.args()
        for changed in ({'actor':'owner'},{'actor':'repo'},
                        {'expected_revision':True},
                        {'operation_id':'x'}):
            with self.subTest(changed=changed),self.assertRaises(Denied):
                self.state.append_range(**(args|changed))
        fake=copy.deepcopy(self.current)
        fake['plan']['observation']['recordCandidates'][0]['actual']={
            'sourceSha':'b'*40}
        fake['plan']['observationDigest']=local._hash(fake['plan']['observation'])
        self.current=fake
        with self.assertRaises(Denied):
            self.state.append_range(**(self.args()))
        self.assertEqual(self.count('operations'),0)

    def test_full_chain_tamper_is_detected_not_empty_queue(self):
        self.accept()
        with sqlite3.connect(self.path) as db:
            old=db.execute('SELECT payload FROM records LIMIT 1').fetchone()[0]
            db.execute("UPDATE records SET payload='{}'")
        with self.assertRaisesRegex(Denied,'REGISTRY_STATE_CORRUPT'):
            self.state.list_desired_candidates(limit=5)
        with self.assertRaisesRegex(Denied,'REGISTRY_STATE_CORRUPT'):
            self.state.operation(actor=local.PLANNER,
                                 operation_id=self.operations[0][0]['operation_id'])
        with sqlite3.connect(self.path) as db:
            db.execute('UPDATE records SET payload=?',(old,))
        self.assertEqual(len(self.state.list_desired_candidates(limit=5)['records']),1)

    def test_no_fallback_to_schema_v2_or_automatic_migration(self):
        self.accept()
        with self.assertRaises(Denied):
            v2.RegistryStateJournalV2(
                self.path,instance_id=self.instance,scope=self.scope,
                anchor_reader=lambda:self.state.initial,plan_reader=self.read
            ).checkpoint()
        with self.assertRaises(Denied):
            local.FunctionalV1CandidateJournal(
                self.path,instance_id=uid(),scope=self.scope,
                plan_reader=self.read).checkpoint()

    def test_missing_sqlite_and_permission_changes_are_denied(self):
        missing=self.path.parent/'missing.sqlite'
        with self.assertRaises(Denied):
            local.FunctionalV1CandidateJournal(
                missing,instance_id=self.instance,scope=self.scope,
                plan_reader=self.read)
        os.chmod(self.path,0o644)
        with self.assertRaisesRegex(Denied,'PERMISSIONS'):
            self.state.checkpoint()
        os.chmod(self.path,0o600)

    def test_competing_CAS_only_one_writer_succeeds(self):
        self.accept();self.suffix()
        barrier=threading.Barrier(2)
        def read(eid):
            item=self.read(eid)
            barrier.wait(timeout=5)
            return item
        self.state.plan_reader=read
        base=self.args()
        def writer(op):
            try:
                return self.state.append_range(**{**base,'operation_id':op})['result']
            except (Denied,Stale,Conflict) as e:
                return str(e)
        with ThreadPoolExecutor(max_workers=2) as pool:
            results=list(pool.map(writer,(uid(),uid())))
        self.assertEqual(results.count('LOCAL_DESIRED_CANDIDATE_COMMITTED'),1)
        self.assertEqual(results.count('REGISTRY_LOCAL_CONCURRENT_CHANGE'),1)
        self.assertEqual(self.count('operations'),2)


    def test_ambiguous_postcommit_readback_recovers_original_operation(self):
        operation=self.args()
        def unreadable(**_):
            raise Denied('INJECTED_OPERATION_READ_UNAVAILABLE')
        self.state.operation=unreadable
        response=self.state.append_range(**operation)
        self.assertEqual(response['result'],'UNKNOWN_OUTCOME')
        self.assertEqual(response['operationId'],operation['operation_id'])
        self.assertEqual(self.count('operations'),1)
        reopened=local.FunctionalV1CandidateJournal(
            self.path,instance_id=self.instance,scope=self.scope,
            plan_reader=lambda _:self.fail('must not recollect after uncertain ACK'))
        exact=reopened.operation(actor=local.PLANNER,
                                  operation_id=operation['operation_id'])
        self.assertEqual(exact['result'],'LOCAL_DESIRED_CANDIDATE_COMMITTED')
        self.assertEqual(reopened.append_range(**operation),exact)
        self.assertEqual(self.count('operations'),1)

    def test_schema_v2_does_not_automigrate_to_local_v1(self):
        other=self.path.parent/'old-v2.sqlite'
        anchor=v2.genesis_v2(self.instance,self.scope)
        v2.RegistryStateJournalV2.initialize(
            other,instance_id=self.instance,scope=self.scope,
            anchor_reader=lambda:anchor,plan_reader=self.read)
        with self.assertRaisesRegex(Denied,'REGISTRY_LOCAL_SCHEMA_MISMATCH'):
            local.FunctionalV1CandidateJournal(
                other,instance_id=self.instance,scope=self.scope,
                plan_reader=self.read).checkpoint()
        with sqlite3.connect(other) as db:
            self.assertEqual(db.execute('PRAGMA user_version').fetchone(),(2,))

    def test_bad_init_does_not_create_placeholder_database(self):
        absent=self.path.parent/'invalid-init.sqlite'
        with self.assertRaises(Denied):
            local.FunctionalV1CandidateJournal.initialize(
                absent,instance_id='bad',scope=self.scope,
                plan_reader=self.read)
        self.assertFalse(absent.exists())
        with self.assertRaises(Denied):
            local.FunctionalV1CandidateJournal.initialize(
                absent,instance_id=uid(),
                scope={**self.scope,'repository':'Wrong/repo'},
                plan_reader=self.read)
        self.assertFalse(absent.exists())

    def test_local_rollback_limit_is_explicit(self):
        receipt=self.accept()
        # A byte-for-byte restored old local DB+WAL can pass local checks;
        # this test asserts the *absence* of anti-rollback claims, not safety.
        out=self.state.checkpoint()
        self.assertEqual(out['integrityModel'],'LOCAL_EVENT_CHAIN_ONLY')
        self.assertFalse(out['admissionAllowed'])
        self.assertFalse(out['evidenceVerified'])
        self.assertNotIn('witness',out)
        self.assertEqual(out['localCheckpoint'],receipt['checkpoint'])


if __name__ == '__main__':
    unittest.main()

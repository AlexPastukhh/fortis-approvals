"""Two independent original pre-merge Core approvals -> retained collector
snapshots -> local Registry initial/suffix CAS, with synthetic GitHub host.

This tests the genuine source methods and original Core journal rather than
fabricating a second anchored_batch JSON object. It does NOT imply a live
trusted provider/host, enrolled Registry, owner GO or deployment.
"""
import copy
import hashlib
import uuid
import unittest
from unittest.mock import patch

from fortis_approvals.core import Denied
from fortis_approvals.registry import functional_v1_journal as registry
from fortis_approvals.registry import recovery_snapshot as backup
from fortis_approvals.workflow.common import secure_dir
from fortis_approvals.tests import test_registry_source_composition as source_fixture
from fortis_approvals.integrations.github.tests import test_retained_impact as impact_fixture
from fortis_approvals.integrations.github.tests import test_integrated_capture as integrated
from fortis_approvals.integrations.github.tests import test_path_ci_observation as path_fixture
from fortis_approvals.integrations.github.tests import publisher_fixture
from fortis_approvals.integrations.github.gateway import collector_snapshot as original_collector
from fortis_approvals.integrations.github.gateway.review_attestation import (
    read_bound_owner_decision,
)


class TwoOriginalMergeTests(unittest.TestCase):
    def setUp(self):
        # Pin a *single* shared fixture validator revision BEFORE the
        # original code repository is committed by the embedded setUp.
        old=impact_fixture.STUB
        revised=old.replace(
            "assert paths==['src/new.py','src/old.py']",
            "assert paths==sorted(set(paths)) and paths")
        self.assertNotEqual(revised,old)
        self.enterContext(patch.object(impact_fixture,'STUB',revised))
        source_fixture.OfflineSourceCompositionTests.setUp(self)
    prepare=source_fixture.OfflineSourceCompositionTests.prepare
    approve=source_fixture.OfflineSourceCompositionTests.approve
    set_merge=source_fixture.OfflineSourceCompositionTests.set_merge
    journal_setup=source_fixture.OfflineSourceCompositionTests.journal_setup
    retain=source_fixture.OfflineSourceCompositionTests.retain
    confirm=source_fixture.OfflineSourceCompositionTests.confirm
    build=source_fixture.OfflineSourceCompositionTests.build
    repin=source_fixture.OfflineSourceCompositionTests.repin
    setup_plan=source_fixture.OfflineSourceCompositionTests.setup_plan
    args=source_fixture.OfflineSourceCompositionTests.args
    observe=source_fixture.OfflineSourceCompositionTests.observe
    setup_suffix=source_fixture.OfflineSourceCompositionTests.setup_suffix
    compose=source_fixture.OfflineSourceCompositionTests.compose
    append_initial=source_fixture.OfflineSourceCompositionTests.append_initial

    def setup_original_range(self):
        # The fixture validator is pinned to the same single code commit
        # across both PRs; actual Git path comparison still runs separately.
        comp=self.compose()
        initial=self.append_initial()
        self.assertEqual(
            initial['storage']['receipt']['candidateCursor'],
            self.fixture.selected)
        return comp,initial

    def capture_original_second(self, *, deny_core_readback=False):
        """Make Git merge2 and run a NEW pre-merge capture/Core ASK/retain."""
        git=self.fixture.git;source=self.fixture.validator.source
        base=self.fixture.selected
        git.run(['checkout','--quiet','--detach',base],cwd=source)
        self.fixture.write(source,'src/new.py','VALUE = 2\n')
        head=self.fixture.commit(source)
        tree=git.text(['rev-parse',head+'^{tree}'],cwd=source)
        merge=git.text(['commit-tree',tree,'-p',base,'-p',head,
                        '-m','owner second fixture merge'],cwd=source)

        # The following fake provider is allowed to represent a *second*
        # GitHub PR, while the real source validators/Core/review/collector
        # functions all execute unmocked. No original batch is constructed
        # or returned by a Python mock.
        for module in (integrated,publisher_fixture,path_fixture):
            self.enterContext(patch.object(module,'HEAD',head))
            self.enterContext(patch.object(module,'BASE',base))
        self.enterContext(patch.object(integrated,'MERGE',merge))
        self.enterContext(patch.object(integrated,'TREE',tree))
        api=self.fixture.api
        api.state='open';api.merged=False
        api.head=head;api.base=base;api.ci_head=head
        api.merge_parent=base
        api.changed_count=1
        api.files=[{'filename':'src/new.py','status':'modified'}]
        api.check_count=None
        old_pr=api.pr
        def pr8():
            return {**old_pr(),'number':8,
                    'html_url':'https://github.com/'+api.head_repo+'/pull/8'}
        api.pr=pr8

        old_runs=api.runs
        def runs8():
            rows=old_runs()
            for row in rows:
                old_id=row['id'];row['id']=old_id+100
                row['html_url']=row['html_url'].replace(
                    '/runs/'+str(old_id),'/runs/'+str(row['id']))
                row['head_sha']=head
                row['pull_requests']=[{
                    'number':8,'head':{'sha':head},'base':{'sha':base}}]
            return rows
        api.runs=runs8
        new_checks=[]
        for row in self.fixture.checks:
            old_id=row['id'];new_id=old_id+1000
            new_row=copy.deepcopy(row)
            new_row.update(id=new_id,head_sha=head,
                details_url=row['details_url'].replace(
                    '/runs/'+str((old_id-1000)//10)+'/job/'+str(old_id),
                    '/runs/'+str((old_id-1000)//10+100)+'/job/'+str(new_id)))
            new_checks.append(new_row)
        self.fixture.checks=new_checks

        old_req=api.request
        def request8(method,path,**kw):
            if path.endswith('/pulls/8'):
                path=path[:-1]+'7'
            if '/compare/' in path:
                assert path.endswith('/compare/'+base+'...'+head)
                return {'status':'ahead','ahead_by':1,
                        'base_commit':{'sha':base},
                        'merge_base_commit':{'sha':base},'files':api.files}
            return old_req(method,path,**kw)
        api.request=request8
        self.fixture.kw={
            'operation_id':str(uuid.uuid4()),'expected_revision':1,
            'number':8,'expected_head_sha':head,'expected_base_sha':base,
            'expected_body_sha256':hashlib.sha256(api.body.encode()).hexdigest(),
        }
        self.fixture.selected=merge
        self.second_capture_operation_id=self.fixture.kw['operation_id']
        # Original ReviewCaptureStore.capture_bundle -> full Core owner
        # policy-bound approval -> observed provider merge -> persisted
        # CollectorSnapshotStore.retain. No manually forged owner receipt.
        # The shared legacy Core-fixture helper builds a PR #7 request by
        # default. Retarget only its *new* submitted Core request to PR #8;
        # Core still executes real prepare/ASK/approve/dispatch/audit logic.
        client=integrated.Core.client
        def next_pr(core, credential, action, payload):
            if action=='submit' and payload.get('service')==integrated.SERVICE:
                payload['params']['number']=8
            return client(core,credential,action,payload)
        with patch.object(integrated.Core,'client',next_pr):
            self.approve()
        eid=str(uuid.uuid4())
        self.kw.update(
            evidence_id=eid,expected_revision=1,
            owner_request_id=self.fixture.payload['requestId'],
            selected_main_sha=merge,adapter=self.fixture.adapter,
            store=self.fixture.store,core=self.fixture.core,
            checkpoint_reader=lambda:self.fixture.anchor,
            owner='test-owner',validator=self.fixture.validator,
            clock=lambda:self.now,
        )
        if deny_core_readback:
            # Executed Core ASK is not sufficient if the protected original
            # Core record is unavailable at the *collector* read boundary.
            with patch.object(self.fixture.core,'_read',
                              side_effect=Denied('ORIGINAL_CORE_UNAVAILABLE')):
                with self.assertRaisesRegex(Denied,'ORIGINAL_CORE_UNAVAILABLE'):
                    self.retain()
            self.assertEqual(self.journal.anchored_batch([])
                             ['checkpoint']['revision'],1)
            return merge,eid,None
        pending=self.retain()
        self.assertEqual(pending['result'],'LOCAL_EVIDENCE_PENDING_ANCHOR')
        self.assertEqual(pending['selectedMainSha'],merge)
        self.assertEqual(pending['ownerRequestId'],
                         self.fixture.payload['requestId'])
        self.confirm(pending)
        receipt=self.journal.receipt(eid)
        self.assertEqual(receipt['result'],
                         'ANCHORED_CANDIDATE_EVIDENCE_RETAINED')
        self.assertEqual(receipt['evidenceDigest'],
                         original_collector._hash(self.journal.read(eid)))
        self.assertEqual(self.journal.anchored_batch([eid])['entries'][0]
                         ['receipt'],receipt)
        return merge,eid,receipt

    def latest_original_composition(self):
        inputs=dict(self.inputs)
        inputs['expected_collector_checkpoint']=copy.deepcopy(
            self.journal.anchored_batch([])['checkpoint'])
        return registry.OfflineSourceRangeComposition(
            path=self.path,instance_id=self.instance,
            scope=self.scope,**inputs)

    def test_two_original_core_events_append_suffix_to_local_registry(self):
        first_comp,first=self.setup_original_range()
        first_receipt=first['storage']['receipt']
        original_owner_id=self.journal.receipt(self.eid)['ownerRequestId']
        merge,eid,second_receipt=self.capture_original_second()
        self.assertNotEqual(eid,self.eid)
        self.assertNotEqual(second_receipt['ownerRequestId'],original_owner_id)
        original_owner=read_bound_owner_decision(
            self.fixture.core,original_owner_id,owner='test-owner')
        second_owner=read_bound_owner_decision(
            self.fixture.core,second_receipt['ownerRequestId'],
            owner='test-owner')
        self.assertEqual((original_owner['number'],second_owner['number']),
                         (7,8))
        self.assertNotEqual(original_owner['captureOperationId'],
                            second_owner['captureOperationId'])
        self.assertEqual(second_owner['captureOperationId'],
                         self.second_capture_operation_id)
        self.assertEqual(second_owner['result'],'OWNER_BUNDLE_DECISION_BOUND')
        original_batch=self.journal.anchored_batch([self.eid,eid])
        self.assertEqual(original_batch['checkpoint']['revision'],2)
        self.assertEqual(
            [v['receipt']['selectedMainSha'] for v in original_batch['entries']],
            [first_receipt['candidateCursor'],merge])
        # Host must deliberately repin the *real* collector head.
        with self.assertRaises(Denied):
            first_comp.compose_and_append(
                operation_id=str(uuid.uuid4()),expected_revision=1,
                selected_main_sha=merge,evidence_ids=[eid])
        second_comp=self.latest_original_composition()
        operation_id=str(uuid.uuid4())
        second=second_comp.compose_and_append(
            operation_id=operation_id,expected_revision=1,
            selected_main_sha=merge,evidence_ids=[eid])
        self.assertEqual(second['result'],'INACTIVE_SOURCE_RANGE_CANDIDATE')
        self.assertEqual(second['storage']['result'],
                         'LOCAL_DESIRED_CANDIDATE_COMMITTED')
        receipt=second['storage']['receipt']
        self.assertEqual(receipt['startCursorSha'],
                         first_receipt['candidateCursor'])
        self.assertEqual(receipt['candidateCursor'],merge)
        self.assertEqual(receipt['supersessions'],[{
            'fromRecordId':first_receipt['recordIds'][0],
            'toRecordId':receipt['recordIds'][0]}])
        self.assertEqual(second_comp.candidate_page(limit=10)['localRevision'],2)
        self.assertFalse(second['collectorProvenanceVerified'])
        self.assertFalse(second['deploymentAllowed'])
        self.assertFalse(second['admissionAllowed'])
        # Retained original UUID receipt survives without provider/Core
        # recollection. The accepted schema-3 backup source also replays
        # both captured Git/Core-driven candidate events in a separate DB.
        self.assertEqual(second_comp.operation(operation_id=operation_id),
                         second['storage'])
        destination=secure_dir(self.fixture.root/'real-pair-backups')
        bid=str(uuid.uuid4())
        snapshot=backup.create_inactive_local_backup(
            store=second_comp._store(),directory=destination,backup_id=bid)
        self.assertEqual(snapshot['candidateCursor'],merge)
        self.assertEqual(snapshot['localCheckpoint']['revision'],2)
        self.assertEqual(snapshot['integrityModel'],'LOCAL_EVENT_CHAIN_ONLY')
        self.assertFalse(snapshot['restoreAllowed'])
        self.assertFalse(snapshot['rollbackProtected'])
        self.assertEqual(snapshot,backup.verify_inactive_local_backup(
            directory=destination,backup_id=bid,
            instance_id=self.instance,scope=self.scope,
            plan_reader=lambda _:None))


    def test_complete_original_range_required_for_second_merge(self):
        self.setup_original_range()
        merge,eid,_=self.capture_original_second()
        comp=self.latest_original_composition()
        with self.assertRaisesRegex(
                Denied,'P5_FORWARD_MISSING_MERGE_EVIDENCE'):
            comp.compose_and_append(
                operation_id=str(uuid.uuid4()),expected_revision=1,
                selected_main_sha=merge,evidence_ids=[self.eid])
        with self.assertRaisesRegex(
                Denied,'P5_FORWARD_UNUSED_EVIDENCE'):
            comp.compose_and_append(
                operation_id=str(uuid.uuid4()),expected_revision=1,
                selected_main_sha=merge,evidence_ids=[self.eid,eid])
        # No fabricated empty queue or interim revision on rejected range.
        latest=comp.candidate_page(limit=10)
        self.assertEqual(latest['localRevision'],1)
        self.assertIsNone(latest['records'][0]['actual'])
        self.assertFalse(latest['deploymentVerified'])

    def test_unavailable_original_core_receipt_denies_second_collector_write(self):
        comp,first=self.setup_original_range()
        merge,eid,receipt=self.capture_original_second(
            deny_core_readback=True)
        self.assertIsNone(receipt)
        self.assertEqual(
            self.journal.anchored_batch([])['checkpoint']['revision'],1)
        with self.assertRaisesRegex(Denied,'P5_SNAPSHOT_NOT_FOUND'):
            comp.compose_and_append(
                operation_id=str(uuid.uuid4()),expected_revision=1,
                selected_main_sha=merge,evidence_ids=[eid])
        self.assertEqual(comp.candidate_page(limit=10)['localRevision'],1)
        self.assertEqual(
            comp.candidate_page(limit=10)['candidateSourceSha'],
            first['storage']['receipt']['candidateCursor'])

if __name__=='__main__':
    unittest.main()

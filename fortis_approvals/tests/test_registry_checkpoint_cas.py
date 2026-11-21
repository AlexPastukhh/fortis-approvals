"""Offline owner-side checkpoint CAS tied to original Registry pending receipts.

The backing file and Registry test store share a test UID. The tests do not
establish independent privilege, protected enrollment, live API or admission.
"""
import copy
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import os
import sqlite3
import threading
import unittest
import uuid

from fortis_approvals.core import Conflict, Denied, Stale
from fortis_approvals.registry import checkpoint_cas as a
from fortis_approvals.registry import state_journal_v2 as v2
from fortis_approvals.tests import test_registry_state_journal_v2 as fixture


class CheckpointCASTests(unittest.TestCase):
    setUp=fixture.RegistryStateV2Tests.setUp
    witness=fixture.RegistryStateV2Tests.witness
    read=fixture.RegistryStateV2Tests.read
    args=fixture.RegistryStateV2Tests.args
    prepare_suffix=fixture.RegistryStateV2Tests.prepare_suffix

    def setup_anchor(self):
        self.anchor_dir=self.root/'independent-owner-namespace'
        self.anchor_dir.mkdir(mode=0o700)
        self.path_anchor=self.anchor_dir/'owner-checkpoint.sqlite'
        self.enrollment='e'*64
        self.authority=a.OfflineCheckpointCAS.initialize(self.path_anchor,
                  instance_id=self.instance,scope=self.scope,
                  enrollment_receipt_digest=self.enrollment,
                  registered_registry_path=self.state.path)
        self.state.anchor_reader=self.authority.read_checkpoint
        self.assertEqual(self.authority.read_checkpoint(),self.anchor)

    def candidate(self,*,operation_id=None):
        args=self.args(op=operation_id)
        outcome=self.state.append_range(**args)
        self.assertEqual(outcome['result'],'UNKNOWN_OUTCOME')
        return args,outcome

    def advance(self,args,outcome):
        return self.authority.advance(operation_id=args['operation_id'],
             previous_checkpoint=outcome['previousCheckpoint'],
             next_checkpoint=outcome['pendingCheckpoint'],
             pending_reader=self.state.operation)

    def accept(self):
        args,pending=self.candidate()
        advanced=self.advance(args,pending)
        self.assertEqual(advanced['result'],'CHECKPOINT_CAS_CANDIDATE')
        self.assertFalse(advanced['protectedAnchorVerified'])
        self.assertFalse(advanced['admissionAllowed'])
        self.anchor=copy.deepcopy(self.authority.read_checkpoint())
        stored=self.state.operation(actor=v2.PLANNER,operation_id=args['operation_id'])['receipt']
        self.operations.append((args,stored))
        return args,pending,advanced,stored

    def test_first_transaction_owner_cas_and_original_receipt(self):
        self.setup_anchor()
        args,pending=self.candidate()
        self.assertEqual(self.authority.read_checkpoint(),self.anchor)
        with self.assertRaisesRegex(Denied,'REGISTRY_STATE_ANCHOR_MISMATCH'):
            self.state.checkpoint()
        result=self.advance(args,pending)
        self.assertEqual(result['receipt']['checkpoint'],pending['pendingCheckpoint'])
        self.assertEqual(result['receipt']['previousCheckpoint'],pending['previousCheckpoint'])
        self.assertEqual(result['receipt']['pendingDigest'],a._hash({
            'result':'UNKNOWN_OUTCOME',**{k:pending[k] for k in
             ('previousCheckpoint','pendingCheckpoint','operationId')}}))
        self.assertEqual(self.authority.read_checkpoint(),pending['pendingCheckpoint'])
        self.assertEqual(self.authority.original(args['operation_id']),result)
        self.assertEqual(self.advance(args,pending),result)
        self.assertEqual(self.state.operation(actor=v2.PLANNER,
              operation_id=args['operation_id'])['result'],'ANCHORED_CANDIDATE_TRANSACTION')
        self.assertFalse(self.state.operation(actor=v2.PLANNER,
              operation_id=args['operation_id'])['receipt']['admissionAllowed'])
        self.assertEqual(self.authority.read_checkpoint()['revision'],1)

    def test_second_transaction_and_exact_cursor(self):
        self.setup_anchor()
        _,_,first,first_source=self.accept()
        self.prepare_suffix()
        args,pending,second,second_source=self.accept()
        self.assertEqual(second['receipt']['previousCheckpoint'],first['receipt']['checkpoint'])
        self.assertEqual(second['receipt']['checkpoint'],second_source['checkpoint'])
        self.assertEqual(self.authority.read_checkpoint()['revision'],2)
        self.assertEqual(self.state.checkpoint()['candidateCursor'],'c'*40)
        self.assertEqual(self.authority.original(self.operations[0][0]['operation_id']),first)
        self.assertEqual(self.state.operation(actor=v2.PLANNER,
            operation_id=self.operations[0][0]['operation_id'])['receipt'],first_source)

    def test_missing_or_forged_original_operation_denied(self):
        self.setup_anchor()
        args,pending=self.candidate()
        with self.assertRaises(Denied):
            self.authority.advance(operation_id=str(uuid.uuid4()),
                previous_checkpoint=pending['previousCheckpoint'],
                next_checkpoint=pending['pendingCheckpoint'],
                pending_reader=self.state.operation)
        wrong={**pending['pendingCheckpoint'],'eventDigest':'f'*64}
        with self.assertRaisesRegex(Denied,'REGISTRY_CHECKPOINT_ORIGINAL_OPERATION_REQUIRED'):
            self.authority.advance(operation_id=args['operation_id'],
                previous_checkpoint=pending['previousCheckpoint'],
                next_checkpoint=wrong,pending_reader=self.state.operation)
        self.assertEqual(self.authority.read_checkpoint()['revision'],0)

    def test_source_closure_and_same_directory_denied(self):
        self.setup_anchor();args,pending=self.candidate()
        with self.assertRaisesRegex(Denied,'REGISTRY_CHECKPOINT_SOURCE_BOUNDARY_REQUIRED'):
            self.authority.advance(operation_id=args['operation_id'],
                previous_checkpoint=pending['previousCheckpoint'],
                next_checkpoint=pending['pendingCheckpoint'],
                pending_reader=lambda **kw:self.state.operation(**kw))
        old=self.state.anchor_reader
        self.state.anchor_reader=lambda:self.authority.read_checkpoint()
        with self.assertRaisesRegex(Denied,'REGISTRY_CHECKPOINT_SOURCE_BOUNDARY_REQUIRED'):
            self.authority.advance(operation_id=args['operation_id'],
                previous_checkpoint=pending['previousCheckpoint'],
                next_checkpoint=pending['pendingCheckpoint'],
                pending_reader=self.state.operation)
        self.state.anchor_reader=old
        # Merely using another filename in the Registry volume is not separate.
        with self.assertRaisesRegex(Denied,'REGISTRY_CHECKPOINT_SOURCE_PATH_INVALID'):
            a.OfflineCheckpointCAS.initialize(
                self.root/'same-volume-anchor.sqlite',instance_id=self.instance,
                scope=self.scope,enrollment_receipt_digest=self.enrollment,
                registered_registry_path=self.state.path)

    def test_stale_competitor_and_different_uuid_conflicts(self):
        self.setup_anchor();args,pending=self.candidate()
        self.advance(args,pending)
        same={**pending['pendingCheckpoint'],'eventDigest':'a'*64}
        with self.assertRaises((Denied,Conflict)):
            self.authority.advance(operation_id=args['operation_id'],
                previous_checkpoint=pending['previousCheckpoint'],
                next_checkpoint=same,pending_reader=self.state.operation)
        self.assertEqual(self.authority.read_checkpoint()['revision'],1)

    def test_concurrent_exact_cas_is_idempotent(self):
        self.setup_anchor();args,pending=self.candidate()
        def submit(_):
            return self.advance(args,pending)
        with ThreadPoolExecutor(max_workers=2) as pool:
            result=list(pool.map(submit,[0,1]))
        self.assertEqual(result[0],result[1])
        with sqlite3.connect(self.path_anchor) as db:
            self.assertEqual(db.execute('SELECT COUNT(*) FROM advances').fetchone()[0],1)

    def test_persisted_owner_ledger_readback_after_restart(self):
        self.setup_anchor();args,pending,first,_=self.accept()
        self.authority=a.OfflineCheckpointCAS(self.path_anchor,instance_id=self.instance,
              scope=self.scope,enrollment_receipt_digest=self.enrollment,
                  registered_registry_path=self.state.path)
        self.state.anchor_reader=self.authority.read_checkpoint
        self.assertEqual(self.authority.read_checkpoint(),first['receipt']['checkpoint'])
        self.assertEqual(self.authority.original(args['operation_id']),first)
        self.assertEqual(self.advance(args,pending),first)

    def test_wrong_enrollment_and_schema_never_auto_recreated(self):
        self.setup_anchor()
        with self.assertRaises(Denied):
            a.OfflineCheckpointCAS(self.path_anchor,instance_id=self.instance,
                 scope=self.scope,enrollment_receipt_digest='f'*64,registered_registry_path=self.state.path).read_checkpoint()
        with self.assertRaises(FileExistsError):
            a.OfflineCheckpointCAS.initialize(self.path_anchor,instance_id=self.instance,
                 scope=self.scope,enrollment_receipt_digest=self.enrollment,
                  registered_registry_path=self.state.path)
        with self.assertRaises(Denied):
            a.OfflineCheckpointCAS(self.root/'absent.sqlite',instance_id=self.instance,
                 scope=self.scope,enrollment_receipt_digest=self.enrollment,
                  registered_registry_path=self.state.path)
        self.assertFalse((self.root/'absent.sqlite').exists())
        with sqlite3.connect(self.path_anchor) as db:db.execute('CREATE TABLE surprise(x)')
        with self.assertRaisesRegex(Denied,'REGISTRY_CHECKPOINT_SCHEMA_MISMATCH'):
            self.authority.read_checkpoint()

    def test_tampered_ledger_detected_and_no_owner_auto_rollback(self):
        self.setup_anchor();args,pending,first,_=self.accept()
        with sqlite3.connect(self.path_anchor) as db:
            db.execute("UPDATE advances SET pending_digest=?",('f'*64,))
        with self.assertRaisesRegex(Denied,'REGISTRY_CHECKPOINT_CORRUPT'):
            self.authority.read_checkpoint()
        self.assertFalse(first['admissionAllowed'])

    def test_lost_ack_reconciled_by_exact_original_operation(self):
        self.setup_anchor();args,pending=self.candidate()
        # Simulate losing advance's return after it committed.
        self.advance(args,pending)
        self.assertEqual(self.authority.original(args['operation_id'])['receipt']['operationId'],
                         args['operation_id'])
        self.assertEqual(self.advance(args,pending)['receipt'],
                         self.authority.original(args['operation_id'])['receipt'])
        self.assertEqual(self.authority.read_checkpoint()['revision'],1)

    def test_invalid_transition_or_missing_owner_file(self):
        self.setup_anchor();args,pending=self.candidate()
        with self.assertRaisesRegex(Denied,'REGISTRY_CHECKPOINT_TRANSITION_INVALID'):
            self.authority.advance(operation_id=args['operation_id'],
                previous_checkpoint=pending['previousCheckpoint'],
                next_checkpoint=pending['previousCheckpoint'],
                pending_reader=self.state.operation)
        os.chmod(self.path_anchor,0o644)
        with self.assertRaisesRegex(Denied,'REGISTRY_STATE_PERMISSIONS'):
            self.authority.read_checkpoint()
        os.chmod(self.path_anchor,0o600)

    def test_pending_mismatch_from_external_witness_roll_back_blocks(self):
        self.setup_anchor();args,pending,_result,_source=self.accept()
        self.prepare_suffix()
        args2,pending2=self.candidate()
        # Simulate rollback of the separately provisioned owner ledger.
        with sqlite3.connect(self.path_anchor) as db:
            db.execute('DELETE FROM advances')
        with self.assertRaisesRegex(Denied,'REGISTRY_STATE_ANCHOR_MISMATCH'):
            self.state.checkpoint()
        with self.assertRaisesRegex(Denied,'REGISTRY_STATE_ANCHOR_MISMATCH'):
            self.advance(args2,pending2)

    def test_forged_second_registry_path_same_scope_rejected(self):
        self.setup_anchor()
        other_dir=self.root/'unregistered-journal'
        other_dir.mkdir(mode=0o700)
        other=v2.RegistryStateJournalV2.initialize(other_dir/'state.sqlite',
                instance_id=self.instance,scope=self.scope,
                anchor_reader=self.authority.read_checkpoint,plan_reader=self.read)
        args=self.args();pending=other.append_range(**args)
        self.assertEqual(pending['result'],'UNKNOWN_OUTCOME')
        with self.assertRaisesRegex(Denied,'REGISTRY_CHECKPOINT_SOURCE_BOUNDARY_REQUIRED'):
            self.authority.advance(operation_id=args['operation_id'],
                previous_checkpoint=pending['previousCheckpoint'],
                next_checkpoint=pending['pendingCheckpoint'],
                pending_reader=other.operation)
        self.assertEqual(self.authority.read_checkpoint()['revision'],0)

    def test_replay_old_cas_after_new_revision_returns_original(self):
        self.setup_anchor()
        first_args,first_pending,first_advance,first_receipt=self.accept()
        self.prepare_suffix()
        _,_,second_advance,_=self.accept()
        self.assertEqual(self.advance(first_args,first_pending),first_advance)
        self.assertEqual(self.authority.read_checkpoint(),second_advance['receipt']['checkpoint'])
        self.assertEqual(self.state.operation(actor=v2.PLANNER,operation_id=first_args['operation_id'])
                         ['receipt'],first_receipt)

    def test_cannot_open_other_source_path_or_enrollment_after_restart(self):
        self.setup_anchor()
        with self.assertRaisesRegex(Denied,'REGISTRY_CHECKPOINT_SCHEMA_MISMATCH'):
            a.OfflineCheckpointCAS(self.path_anchor,instance_id=self.instance,
                  scope=self.scope,enrollment_receipt_digest=self.enrollment,
                  registered_registry_path=self.root/'alternate-registry.sqlite').read_checkpoint()
        with self.assertRaisesRegex(Denied,'REGISTRY_CHECKPOINT_SCHEMA_MISMATCH'):
            a.OfflineCheckpointCAS(self.path_anchor,instance_id=self.instance,
                  scope={**self.scope,'bindingDigest':'f'*64},
                  enrollment_receipt_digest=self.enrollment,
                  registered_registry_path=self.state.path).read_checkpoint()

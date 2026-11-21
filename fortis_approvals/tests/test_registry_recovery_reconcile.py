"""Read-only state/owner/backup recovery preflight with synthetic owner ledger."""
import copy
from pathlib import Path
import sqlite3
import unittest
import uuid
from unittest.mock import patch

from fortis_approvals.core import Denied, Stale
from fortis_approvals.registry import recovery_reconcile as r
from fortis_approvals.registry import recovery_snapshot
from fortis_approvals.registry import checkpoint_cas as owner_cas
from fortis_approvals.tests import test_registry_checkpoint_cas as fixture


class RegistryRecoveryReconcileTests(unittest.TestCase):
    setUp=fixture.CheckpointCASTests.setUp
    witness=fixture.CheckpointCASTests.witness
    read=fixture.CheckpointCASTests.read
    args=fixture.CheckpointCASTests.args
    setup_anchor=fixture.CheckpointCASTests.setup_anchor
    candidate=fixture.CheckpointCASTests.candidate
    advance=fixture.CheckpointCASTests.advance
    accept=fixture.CheckpointCASTests.accept
    prepare_suffix=fixture.CheckpointCASTests.prepare_suffix

    def setup_pair(self):
        self.setup_anchor()

    def reconcile(self,**kwargs):
        return r.reconcile_inactive(store=self.state,owner=self.authority,**kwargs)

    def backup(self):
        directory=self.root/'offline-backups'
        directory.mkdir(mode=0o700)
        backup_id=str(uuid.uuid4())
        result=recovery_snapshot.create_verified_backup(
            store=self.state,directory=directory,backup_id=backup_id)
        self.assertEqual(result['result'],'INACTIVE_BACKUP_MATCH_CANDIDATE')
        return {'backup_directory':directory,'backup_id':backup_id}

    def test_empty_genesis_no_false_enrollment(self):
        self.setup_pair()
        result=self.reconcile()
        self.assertEqual(result['observation']['status'],'MATCHED_LOCAL_CANDIDATES')
        self.assertEqual(result['observation']['candidateCursor'],self.scope['baselineSha'])
        self.assertEqual(result['observation']['registryOperationCount'],0)
        self.assertEqual(result['observation']['ownerAdvanceCount'],0)
        self.assertEqual(result['observationDigest'],r._hash(result['observation']))
        self.assertEqual(self.reconcile(),result)
        for k in ('protectedCheckpointVerified','enrollmentVerified','backupRestorable',
                  'restoreAllowed','admissionAllowed','deploymentAllowed'):
            self.assertIs(result[k],False)

    def test_two_committed_transactions_and_backup(self):
        self.setup_pair()
        self.accept()
        self.prepare_suffix()
        self.accept()
        backup=self.backup()
        before=self.state.checkpoint()
        result=self.reconcile(**backup)
        self.assertEqual(result['observation']['status'],'MATCHED_LOCAL_CANDIDATES')
        self.assertEqual(result['observation']['candidateCursor'],'c'*40)
        self.assertEqual(result['observation']['registryOperationCount'],2)
        self.assertEqual(result['observation']['ownerAdvanceCount'],2)
        self.assertEqual(result['observation']['backup']['backupId'],backup['backup_id'])
        self.assertEqual(self.state.checkpoint(),before)
        self.assertEqual(self.authority.read_checkpoint(),before['checkpoint'])
        self.assertFalse(result['restoreAllowed'])
        self.assertFalse(result['admissionAllowed'])

    def test_pending_local_commit_is_unresolved_not_auto_cas(self):
        self.setup_pair()
        args,pending=self.candidate()
        result=self.reconcile()
        self.assertEqual(result['observation']['status'],
                         'UNRESOLVED_LOCAL_COMMIT_OR_OWNER_ROLLBACK')
        self.assertEqual(result['observation']['pendingOperation'],pending)
        self.assertIsNone(result['observation']['candidateCursor'])
        self.assertEqual(self.authority.read_checkpoint()['revision'],0)
        self.assertEqual(result,self.reconcile())
        with self.assertRaisesRegex(Denied,'REGISTRY_RECOVERY_PENDING_BACKUP_BLOCKED'):
            self.reconcile(backup_directory=self.root,backup_id=str(uuid.uuid4()))
        self.assertFalse(result['protectedCheckpointVerified'])

    def test_owner_rollback_indistinguishable_from_pending(self):
        self.setup_pair()
        self.accept()
        with sqlite3.connect(self.path_anchor) as db:db.execute('DELETE FROM advances')
        result=self.reconcile()
        self.assertEqual(result['observation']['status'],
                         'UNRESOLVED_LOCAL_COMMIT_OR_OWNER_ROLLBACK')
        self.assertIsNone(result['observation']['candidateCursor'])
        self.assertFalse(result['restoreAllowed'])

    def test_multiple_missing_owner_advances_is_stopped(self):
        self.setup_pair()
        self.accept();self.prepare_suffix();self.accept()
        with sqlite3.connect(self.path_anchor) as db:db.execute('DELETE FROM advances')
        with self.assertRaisesRegex(Denied,'REGISTRY_RECOVERY_GAP_UNSUPPORTED'):
            self.reconcile()

    def test_backup_behind_owner_checkpoint_is_never_current(self):
        self.setup_pair()
        self.accept()
        backup=self.backup()
        self.prepare_suffix();self.accept()
        with self.assertRaises(Denied):
            self.reconcile(**backup)
        self.assertEqual(self.reconcile()['observation']['ownerAdvanceCount'],2)

    def test_wrong_owner_journal_or_reader_binding(self):
        self.setup_pair()
        original=self.state.anchor_reader
        self.state.anchor_reader=lambda:self.authority.read_checkpoint()
        with self.assertRaisesRegex(Denied,'REGISTRY_RECOVERY_SOURCE_BOUNDARY_REQUIRED'):
            self.reconcile()
        self.state.anchor_reader=original
        self.authority.registered_registry_path=self.root/'different.sqlite'
        with self.assertRaisesRegex(Denied,'REGISTRY_RECOVERY_SOURCE_BOUNDARY_REQUIRED'):
            self.reconcile()

    def test_missing_or_partial_backup_arguments(self):
        self.setup_pair()
        with self.assertRaisesRegex(Denied,'REGISTRY_RECOVERY_BACKUP_ARGUMENTS_INVALID'):
            self.reconcile(backup_directory=self.root)
        with self.assertRaisesRegex(Denied,'REGISTRY_RECOVERY_BACKUP_ARGUMENTS_INVALID'):
            self.reconcile(backup_id=str(uuid.uuid4()))

    def test_owner_ahead_in_projection_fails_closed(self):
        self.setup_pair();self.accept()
        registry=r._read_registry(self.state)
        owner=r._read_owner(self.authority)
        behind=(self.state.initial,self.scope['baselineSha'],{})
        with self.assertRaisesRegex(Denied,'REGISTRY_RECOVERY_OWNER_AHEAD'):
            r._compare(owner,behind)
        self.assertEqual(r._compare(owner,registry)['status'],
                         'MATCHED_LOCAL_CANDIDATES')

    def test_checkpoint_race_between_reads_rejected(self):
        self.setup_pair();self.accept()
        original=r._compare
        def changed(left,right):
            result=original(left,right)
            self.prepare_suffix()
            self.accept()
            return result
        with patch.object(r,'_compare',side_effect=changed):
            with self.assertRaisesRegex(Stale,'REGISTRY_RECOVERY_CHANGED_DURING_READ'):
                self.reconcile()

    def test_owner_operation_chain_tampering_denied(self):
        self.setup_pair();self.accept()
        with sqlite3.connect(self.path_anchor) as db:
            db.execute("UPDATE advances SET pending_digest='f'")
        with self.assertRaisesRegex(Denied,'REGISTRY_CHECKPOINT_CORRUPT'):
            self.reconcile()

    def test_no_write_on_reconcile_and_original_receipts_stable(self):
        self.setup_pair();args,_,_,first=self.accept()
        before=self.authority.original(args['operation_id'])
        with sqlite3.connect(self.path_anchor) as db:
            count=db.execute('SELECT COUNT(*) FROM advances').fetchone()[0]
        for _ in range(3):
            self.assertEqual(self.reconcile()['observation']['status'],
                             'MATCHED_LOCAL_CANDIDATES')
        with sqlite3.connect(self.path_anchor) as db:
            self.assertEqual(db.execute('SELECT COUNT(*) FROM advances').fetchone()[0],count)
        self.assertEqual(self.authority.original(args['operation_id']),before)
        self.assertEqual(self.state.operation(actor=owner_cas.PLANNER,
              operation_id=args['operation_id'])['receipt'],first)


    def test_sqlite_transient_sidecar_unlink_is_not_false_corruption(self):
        from unittest.mock import patch
        from fortis_approvals.registry import checkpoint_cas, state_journal
        self.setup_pair()
        for obj,module in ((self.authority,checkpoint_cas),(self.state,state_journal)):
            transient=Path(str(obj.path)+'-wal')
            # No live connection owns this synthetic sidecar.
            transient.write_bytes(b'temporary')
            transient.chmod(0o600)
            original=module._private
            called=[False]
            def disappear(path,directory=False):
                if Path(path)==transient and not called[0]:
                    called[0]=True
                    transient.unlink()
                    raise FileNotFoundError(str(transient))
                return original(path,directory)
            with self.subTest(target=obj.path),patch.object(module,'_private',side_effect=disappear):
                obj._paths()
            self.assertTrue(called[0])
            self.assertFalse(transient.exists())

    def test_symlink_sidecars_still_fail_closed(self):
        from fortis_approvals.registry import checkpoint_cas, state_journal
        self.setup_pair()
        for obj in (self.authority,self.state):
            side=Path(str(obj.path)+'-shm')
            side.symlink_to(self.root/'forged-shm')
            with self.subTest(target=obj.path),self.assertRaises(Denied):
                obj._paths()
            side.unlink()

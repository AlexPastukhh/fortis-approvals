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

    def startup(self,owner=None,witness=None):
        import copy
        # This witness is a SAME-UID fixture. A matching value cannot
        # authenticate a protected monotonic witness or permit runtime.
        return r.observe_inactive_registry_startup(
            store=self.state,
            owner_checkpoint_reader=owner or self.authority.read_checkpoint,
            witness_checkpoint_reader=witness or
                (lambda:copy.deepcopy(self.authority.read_checkpoint())))

    def test_inactive_startup_genesis_never_enrolls_or_opens_reads(self):
        self.setup_pair()
        result=self.startup()
        self.assertEqual(result['result'],'REGISTRY_RUNTIME_STARTUP_SOURCE_CANDIDATE')
        self.assertEqual(result['status'],'INACTIVE_UNVERIFIED')
        self.assertEqual(result['observation']['operationCount'],0)
        self.assertEqual(result['observation']['activeCandidateCount'],0)
        self.assertEqual(result['observation']['checkpoint'],self.state.initial)
        self.assertEqual(result['observationDigest'],r._hash(result['observation']))
        for flag in ('protectedCheckpointVerified','independentWitnessVerified',
                     'hostIsolationVerified','ownerAcceptanceVerified',
                     'liveReadAllowed','writeAllowed','runtimeActivationAllowed',
                     'admissionAllowed','deploymentAllowed'):
            self.assertIs(result[flag],False)

    def test_inactive_startup_committed_state_remains_non_authoritative(self):
        self.setup_pair();self.accept();self.prepare_suffix();self.accept()
        result=self.startup()
        self.assertEqual(result['observation']['checkpoint']['revision'],2)
        self.assertEqual(result['observation']['operationCount'],2)
        self.assertEqual(result['observation']['candidateCursor'],'c'*40)
        self.assertEqual(result['observation']['activeCandidateCount'],1)
        self.assertFalse(result['liveReadAllowed'])
        self.assertFalse(result['admissionAllowed'])

    def test_inactive_startup_does_not_write_or_directly_read_owner_store(self):
        self.setup_pair();self.accept()
        before_registry=self.state.path.read_bytes()
        before_owner=self.authority.path.read_bytes()
        # A changed owner DB path is not read: the callback may return a
        # remote authenticated checkpoint in the future; this is a fixture.
        with patch.object(self.authority,'_db',side_effect=AssertionError('owner DB accessed')):
            for _ in range(2):
                result=r.observe_inactive_registry_startup(
                    store=self.state,owner_checkpoint_reader=lambda:self.anchor,
                    witness_checkpoint_reader=lambda:self.anchor)
                self.assertFalse(result['runtimeActivationAllowed'])
        self.assertEqual(before_registry,self.state.path.read_bytes())
        self.assertEqual(before_owner,self.authority.path.read_bytes())
        with self.state._read_only_db() as db:
            with self.assertRaises(sqlite3.OperationalError):
                db.execute("INSERT INTO meta VALUES('forged','forged')")

    def test_inactive_startup_rejects_checkpoint_and_witness_regression(self):
        self.setup_pair();self.accept()
        with self.assertRaisesRegex(Denied,'REGISTRY_RUNTIME_OWNER_CHECKPOINT_MISMATCH'):
            self.startup(owner=lambda:self.state.initial,
                         witness=lambda:self.state.initial)
        with self.assertRaisesRegex(Denied,'REGISTRY_RUNTIME_WITNESS_CHECKPOINT_MISMATCH'):
            self.startup(witness=lambda:self.state.initial)
        bad={**self.anchor,'eventDigest':'f'*64}
        with self.assertRaisesRegex(Denied,'REGISTRY_RUNTIME_WITNESS_CHECKPOINT_MISMATCH'):
            self.startup(witness=lambda:bad)

    def test_inactive_startup_rejects_reader_errors_and_forged_claims(self):
        self.setup_pair()
        with self.assertRaisesRegex(Denied,'REGISTRY_RUNTIME_READERS_REQUIRED'):
            r.observe_inactive_registry_startup(
                store=self.state,owner_checkpoint_reader=None,
                witness_checkpoint_reader=lambda:self.anchor)
        with self.assertRaisesRegex(Denied,'REGISTRY_RUNTIME_READERS_REQUIRED'):
            r.observe_inactive_registry_startup(
                store=self.state,owner_checkpoint_reader=lambda:self.anchor,
                witness_checkpoint_reader=None)
        with self.assertRaisesRegex(Denied,'REGISTRY_RUNTIME_EXTERNAL_READ_UNAVAILABLE'):
            self.startup(owner=lambda:(_ for _ in ()).throw(OSError('socket offline')))
        with self.assertRaisesRegex(Denied,'REGISTRY_CHECKPOINT_INVALID'):
            self.startup(owner=lambda:{**self.anchor,'revision':True})
        with self.assertRaisesRegex(Denied,'REGISTRY_CHECKPOINT_INVALID'):
            self.startup(witness=lambda:{**self.anchor,'ownerAcceptanceVerified':True})

    def test_inactive_startup_detects_claim_change_during_read(self):
        self.setup_pair()
        updates=[self.anchor,{**self.anchor,'eventDigest':'f'*64}]
        def change():
            return updates.pop(0)
        with self.assertRaisesRegex(Stale,'REGISTRY_RUNTIME_CHANGED_DURING_PREFLIGHT'):
            self.startup(owner=change)

    def test_inactive_startup_missing_store_never_creates_one(self):
        self.setup_pair()
        missing=self.root/'not-registered.sqlite'
        original=self.state.path
        self.state.path=missing
        with patch.object(self.authority,'read_checkpoint',
                          side_effect=AssertionError('owner called')) as owner_read:
            with self.assertRaises(Denied):
                self.startup()
            owner_read.assert_not_called()
        self.assertFalse(missing.exists())
        self.state.path=original

    def test_inactive_startup_state_change_between_readbacks_stops(self):
        self.setup_pair()
        called=[0]
        def witness():
            called[0]+=1
            if called[0]==1:
                # Simulate a competing offline candidate commit after the
                # first local read. No startup authority may be inferred.
                before=dict(self.anchor)
                self.accept()
                return before
            return self.anchor
        with self.assertRaisesRegex(Stale,'REGISTRY_RUNTIME_CHANGED_DURING_PREFLIGHT'):
            self.startup(witness=witness)
        self.assertEqual(called[0],2)

    def test_inactive_startup_invalid_schema_never_runs_remote_read(self):
        self.setup_pair()
        with sqlite3.connect(self.state.path) as db:
            db.execute('PRAGMA user_version=99')
        with patch.object(self.authority,'read_checkpoint',
                          side_effect=AssertionError('owner called')) as owner_read:
            with self.assertRaisesRegex(Denied,'REGISTRY_STATE_SCHEMA_MISMATCH'):
                self.startup()
            owner_read.assert_not_called()

    def test_inactive_startup_tampered_sqlite_is_denied(self):
        self.setup_pair();self.accept()
        with sqlite3.connect(self.state.path) as db:
            db.execute("UPDATE operations SET evidence_digest='f'")
        with self.assertRaises(Denied):
            self.startup()

    def test_inactive_startup_wrong_scope_instance_refused(self):
        self.setup_pair()
        old=self.state.instance_id
        self.state.instance_id=str(uuid.uuid4())
        with self.assertRaises(Denied):
            self.startup()
        self.state.instance_id=old

    def test_inactive_startup_source_claims_do_not_ensure_anti_rollback(self):
        self.setup_pair()
        # Even if both externally supplied claims describe the same
        # rolled-back genesis, a matching local DB has NO protected proof.
        result=self.startup(owner=lambda:self.state.initial,
                            witness=lambda:self.state.initial)
        self.assertEqual(result['status'],'INACTIVE_UNVERIFIED')
        self.assertFalse(result['independentWitnessVerified'])
        self.assertFalse(result['runtimeActivationAllowed'])

    def test_symlink_sidecars_still_fail_closed(self):
        from fortis_approvals.registry import checkpoint_cas, state_journal
        self.setup_pair()
        for obj in (self.authority,self.state):
            side=Path(str(obj.path)+'-shm')
            side.symlink_to(self.root/'forged-shm')
            with self.subTest(target=obj.path),self.assertRaises(Denied):
                obj._paths()
            side.unlink()

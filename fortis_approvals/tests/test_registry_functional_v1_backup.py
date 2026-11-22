"""Inactive WAL-consistent local V1 backup, deliberately NO anti-rollback claim."""
import os
from pathlib import Path
import sqlite3
import stat
import uuid
from unittest.mock import patch
import unittest

from fortis_approvals.core import Denied
from fortis_approvals.registry import recovery_snapshot as backup
from fortis_approvals.registry import functional_v1_journal as local
from fortis_approvals.tests import test_registry_functional_v1_journal as fixture


class FunctionalV1BackupTests(unittest.TestCase):
    setUp=fixture.FunctionalV1JournalTests.setUp
    read=fixture.FunctionalV1JournalTests.read
    args=fixture.FunctionalV1JournalTests.args
    append=fixture.FunctionalV1JournalTests.append
    accept=fixture.FunctionalV1JournalTests.accept
    suffix=fixture.FunctionalV1JournalTests.suffix
    count=fixture.FunctionalV1JournalTests.count

    def setup_backup(self):
        self.destination=self.path.parent/'backup-volume'
        self.destination.mkdir(mode=0o700)
        self.backup_id=str(uuid.uuid4())

    def create(self):
        return backup.create_inactive_local_backup(
            store=self.state,directory=self.destination,
            backup_id=self.backup_id)

    def verify(self, **override):
        arguments={
            'directory':self.destination,'backup_id':self.backup_id,
            'instance_id':self.instance,'scope':self.scope,
            'plan_reader':self.read,
        }
        return backup.verify_inactive_local_backup(**(arguments | override))

    def files(self):
        return backup._paths(self.destination,self.backup_id)

    def manifest(self):
        return backup._decode(self.files()[1].read_text('utf-8'))

    def test_genesis_snapshot_has_local_only_explicit_false_authority(self):
        self.setup_backup()
        result=self.create()
        self.assertEqual(result,self.verify())
        self.assertEqual(result['result'],'INACTIVE_LOCAL_BACKUP_MATCH_CANDIDATE')
        self.assertEqual(result['candidateCursor'],self.scope['baselineSha'])
        self.assertEqual(result['localCheckpoint']['revision'],0)
        self.assertEqual(result['integrityModel'],'LOCAL_EVENT_CHAIN_ONLY')
        for key in ('restoreAllowed','admissionAllowed',
                    'deploymentAllowed','rollbackProtected'):
            self.assertIs(result[key],False)
        db,m=self.files()
        self.assertEqual(stat.S_IMODE(db.stat().st_mode),0o600)
        self.assertEqual(stat.S_IMODE(m.stat().st_mode),0o600)
        self.assertEqual(self.manifest()['format'],backup.LOCAL_FORMAT)
        self.assertEqual(self.manifest()['operationCount'],0)
        self.assertEqual(self.manifest()['recordCount'],0)
        self.assertEqual(self.manifest()['supersessionCount'],0)

    def test_two_commits_copy_and_restart_verify_full_history(self):
        self.setup_backup()
        first=self.accept()
        self.suffix()
        second=self.accept()
        result=self.create()
        self.assertEqual(result,self.verify())
        self.assertEqual(result['localCheckpoint'],second['checkpoint'])
        self.assertEqual(result['candidateCursor'],second['candidateCursor'])
        self.assertEqual(self.manifest()['operationCount'],2)
        self.assertEqual(self.manifest()['recordCount'],2)
        self.assertEqual(self.manifest()['supersessionCount'],1)
        self.assertEqual(self.state.checkpoint()['localCheckpoint'],second['checkpoint'])
        db,_=self.files()
        restarted=local.FunctionalV1CandidateJournal(
            db,instance_id=self.instance,scope=self.scope,
            plan_reader=self.read)
        self.assertEqual(restarted.operation(
            actor=local.PLANNER,
            operation_id=self.operations[0][0]['operation_id'])['receipt'],first)
        self.assertEqual(restarted.operation(
            actor=local.PLANNER,
            operation_id=self.operations[1][0]['operation_id'])['receipt'],second)
        self.assertEqual(restarted.list_desired_candidates(limit=5)['localRevision'],2)

    def test_no_deployment_range_keeps_record_but_advances_cursor(self):
        self.setup_backup()
        first=self.accept()
        self.suffix(deploy=False)
        no=self.accept()
        result=self.create()
        self.assertEqual(result['candidateCursor'],no['candidateCursor'])
        self.assertEqual(self.manifest()['recordCount'],1)
        self.assertEqual(self.manifest()['operationCount'],2)
        self.assertEqual(self.manifest()['supersessionCount'],0)
        self.assertEqual(self.verify(),result)
        self.assertNotEqual(result['candidateCursor'],first['candidateCursor'])

    def test_backup_older_than_source_is_snapshot_not_deployment_authority(self):
        self.setup_backup()
        first=self.accept()
        old=self.create()
        self.suffix()
        second=self.accept()
        self.assertNotEqual(first['checkpoint'],second['checkpoint'])
        self.assertEqual(self.verify(),old)
        self.assertEqual(self.verify()['localCheckpoint']['revision'],1)
        self.assertEqual(self.state.checkpoint()['localCheckpoint']['revision'],2)
        self.assertFalse(self.verify()['restoreAllowed'])
        self.assertFalse(self.verify()['rollbackProtected'])

    def test_corrupted_sqlite_or_noncanonical_manifest_denied(self):
        self.setup_backup()
        self.accept();self.create()
        db,m=self.files()
        with db.open('r+b') as handle:
            handle.seek(150)
            one=handle.read(1)
            handle.seek(150)
            handle.write(bytes([one[0]^1]))
        with self.assertRaisesRegex(Denied,'REGISTRY_LOCAL_BACKUP_DIGEST_MISMATCH'):
            self.verify()
        with db.open('r+b') as handle:
            handle.seek(150);handle.write(one)
        self.assertEqual(backup._digest_file(db)[1],self.manifest()['sqliteSha256'])
        original=m.read_text('utf-8')
        m.write_text(original+'\n')
        with self.assertRaises(Denied):self.verify()
        m.write_text('{}')
        with self.assertRaisesRegex(Denied,'REGISTRY_LOCAL_BACKUP_MANIFEST_INVALID'):
            self.verify()

    def test_invalid_instance_scope_cross_schema_and_duplicate_denied(self):
        self.setup_backup()
        self.accept();self.create()
        with self.assertRaises(Denied):
            self.verify(instance_id=str(uuid.uuid4()))
        with self.assertRaises(Denied):
            self.verify(scope={**self.scope,'bindingDigest':'f'*64})
        with self.assertRaisesRegex(Denied,'REGISTRY_LOCAL_BACKUP_ALREADY_EXISTS'):
            self.create()
        with self.assertRaisesRegex(Denied,'REGISTRY_STATE_SCHEMA_MISMATCH'):
            # An ordinary v2 checkpoint journal cannot silently read schema3.
            from fortis_approvals.registry.state_journal_v2 import RegistryStateJournalV2
            store=RegistryStateJournalV2(self.files()[0],instance_id=self.instance,
                         scope=self.scope,anchor_reader=lambda:self.state.initial,
                         plan_reader=self.read)
            store.checkpoint()

    def test_denies_symlink_missing_file_and_broad_acl(self):
        self.setup_backup()
        with self.assertRaises(Denied):self.verify()
        self.create()
        db,m=self.files()
        os.chmod(db,0o644)
        with self.assertRaisesRegex(Denied,'REGISTRY_STATE_PERMISSIONS'):
            self.verify()
        os.chmod(db,0o600)
        os.chmod(m,0o644)
        with self.assertRaisesRegex(Denied,'REGISTRY_STATE_PERMISSIONS'):
            self.verify()
        os.chmod(m,0o600)
        self.assertEqual(self.verify()['result'],'INACTIVE_LOCAL_BACKUP_MATCH_CANDIDATE')

    def test_same_directory_not_allowed_and_wrong_store_denied(self):
        self.setup_backup()
        with self.assertRaisesRegex(Denied,'REGISTRY_LOCAL_BACKUP_STORE_REQUIRED'):
            backup.create_inactive_local_backup(
                store=object(),directory=self.destination,backup_id=self.backup_id)
        with self.assertRaisesRegex(Denied,'REGISTRY_LOCAL_BACKUP_NOT_SEPARATE'):
            backup.create_inactive_local_backup(
                store=self.state,directory=self.path.parent,backup_id=self.backup_id)
        self.assertFalse(self.files()[0].exists())
        self.assertFalse(self.files()[1].exists())

    def test_intervening_write_during_backup_denies_and_no_manifest(self):
        self.setup_backup()
        self.accept()
        original=backup._local_state
        injected=False
        def race(store):
            nonlocal injected
            output=original(store)
            if not injected and store is self.state:
                injected=True
                self.suffix()
                self.accept()
            return output
        with patch.object(backup,'_local_state',side_effect=race):
            with self.assertRaisesRegex(Denied,'REGISTRY_LOCAL_BACKUP_SOURCE_CHANGED'):
                self.create()
        self.assertFalse(self.files()[1].exists())
        self.assertEqual(self.state.checkpoint()['localCheckpoint']['revision'],2)

    def test_corrupt_record_with_matching_new_manifest_hash_still_denied(self):
        self.setup_backup()
        self.accept();self.create()
        db,mpath=self.files()
        with sqlite3.connect(db) as con:
            con.execute("UPDATE records SET payload='{}'")
        manifest=self.manifest()
        size,digest=backup._digest_file(db)
        manifest.update(sqliteBytes=size,sqliteSha256=digest)
        mpath.write_text(backup._raw(manifest),encoding='utf-8')
        with self.assertRaises(Denied):
            self.verify()

    def test_local_manifest_and_db_can_be_rolled_back_together(self):
        self.setup_backup()
        self.accept();created=self.create()
        # Exact same private snapshot can be replayed by a hostile storage
        # controller: local checks cannot prove an externally monotonic head.
        self.suffix()
        self.accept()
        old=self.verify()
        self.assertEqual(old,created)
        self.assertFalse(old['rollbackProtected'])


if __name__=='__main__':
    unittest.main()

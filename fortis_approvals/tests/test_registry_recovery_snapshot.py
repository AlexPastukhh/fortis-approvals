"""Inactive backup/readback of Registry v2 with synthetic owner checkpoint."""
import copy
import os
from pathlib import Path
import sqlite3
import stat
import unittest
import uuid
from unittest.mock import patch

from fortis_approvals.core import Denied
from fortis_approvals.registry import recovery_snapshot as r
from fortis_approvals.registry import state_journal as v1
from fortis_approvals.tests import test_registry_state_journal_v2 as v2_fixture


class RecoverySnapshotTests(unittest.TestCase):
    setUp=v2_fixture.RegistryStateV2Tests.setUp
    witness=v2_fixture.RegistryStateV2Tests.witness
    read=v2_fixture.RegistryStateV2Tests.read
    args=v2_fixture.RegistryStateV2Tests.args
    append=v2_fixture.RegistryStateV2Tests.append
    accept=v2_fixture.RegistryStateV2Tests.accept
    prepare_suffix=v2_fixture.RegistryStateV2Tests.prepare_suffix

    def setup_backup(self):
        self.destination=self.root/'separate-backups'
        self.destination.mkdir(mode=0o700)
        self.bid=str(uuid.uuid4())

    def create(self):
        return r.create_verified_backup(store=self.state,directory=self.destination,backup_id=self.bid)

    def verify(self,**kw):
        args=dict(directory=self.destination,backup_id=self.bid,instance_id=self.instance,
                  scope=self.scope,anchor_reader=self.witness,plan_reader=self.read)
        return r.verify_inactive_backup(**(args|kw))

    def files(self):
        return r._paths(self.destination,self.bid)

    def test_genesis_empty_backup_still_candidate(self):
        self.setup_backup()
        result=self.create()
        self.assertEqual(result['result'],'INACTIVE_BACKUP_MATCH_CANDIDATE')
        self.assertEqual(result['candidateCursor'],self.scope['baselineSha'])
        self.assertFalse(result['restoreAllowed'])
        self.assertFalse(result['admissionAllowed'])
        self.assertEqual(result,self.verify())
        db,manifest=self.files()
        self.assertEqual(stat.S_IMODE(db.stat().st_mode),0o600)
        self.assertEqual(stat.S_IMODE(manifest.stat().st_mode),0o600)
        m=r._decode(manifest.read_text())
        self.assertEqual((m['operationCount'],m['recordCount'],m['supersessionCount']),(0,0,0))
        self.assertEqual(result['manifestDigest'],r._hash(m))

    def test_two_transactions_inactive_backup_no_restore(self):
        self.setup_backup()
        first=self.accept();self.prepare_suffix();last=self.accept()
        before=self.state.checkpoint()
        result=self.create()
        self.assertEqual(result['checkpoint'],last['checkpoint'])
        self.assertEqual(result['candidateCursor'],'c'*40)
        self.assertEqual(result,self.verify())
        self.assertEqual(self.state.checkpoint(),before)
        m=r._decode(self.files()[1].read_text())
        self.assertEqual((m['operationCount'],m['recordCount'],m['supersessionCount']),(2,2,1))
        self.assertEqual(last['supersessions'][0]['fromRecordId'],first['recordIds'][0])
        # Inactive verification must never create a new operation or change source.
        self.assertEqual(self.state.checkpoint(),before)

    def test_pending_anchor_blocks_backup(self):
        self.setup_backup()
        self.append()
        with self.assertRaisesRegex(Denied,'REGISTRY_STATE_ANCHOR_MISMATCH'):self.create()
        self.assertFalse(self.files()[0].exists())
        self.assertFalse(self.files()[1].exists())

    def test_file_and_manifest_tampering_denied(self):
        self.setup_backup();self.accept();self.create()
        db,manifest=self.files()
        with db.open('r+b') as f:
            f.seek(150);byte=f.read(1);f.seek(150)
            f.write(bytes([byte[0]^1]))
        with self.assertRaisesRegex(Denied,'REGISTRY_BACKUP_DIGEST_MISMATCH'):self.verify()
        # Restore original backed-up SQLite byte before testing manifest.
        m=r._decode(manifest.read_text())
        with db.open('r+b') as f:
            f.seek(150);f.write(byte)
        self.assertEqual(r._digest_file(db)[1],m['sqliteSha256'])
        text=manifest.read_text()
        manifest.write_text(text.replace(m['sqliteSha256'],'f'*64))
        with self.assertRaisesRegex(Denied,'REGISTRY_BACKUP_DIGEST_MISMATCH'):self.verify()

    def test_noncanonical_or_modified_manifest_denied(self):
        self.setup_backup();self.create()
        manifest=self.files()[1]
        raw=manifest.read_text()
        manifest.write_text(raw+'\n')
        with self.assertRaises(Denied):self.verify()
        manifest.write_text('{}')
        with self.assertRaisesRegex(Denied,'REGISTRY_BACKUP_MANIFEST_INVALID'):self.verify()

    def test_rollback_anchor_and_cross_instance_denied(self):
        self.setup_backup();self.accept()
        initial=copy.deepcopy(self.anchor)
        self.prepare_suffix();self.accept();self.create()
        self.anchor=initial
        with self.assertRaisesRegex(Denied,'REGISTRY_STATE_ANCHOR_MISMATCH'):self.verify()
        self.anchor=copy.deepcopy(r._decode(self.files()[1].read_text())['checkpoint'])
        with self.assertRaises(Denied):self.verify(instance_id=str(uuid.uuid4()))
        with self.assertRaises(Denied):self.verify(scope={**self.scope,'bindingDigest':'f'*64})
        self.assertEqual(self.verify()['checkpoint'],self.anchor)

    def test_reject_missing_symlink_and_duplicate_destinations(self):
        self.setup_backup()
        with self.assertRaises(Denied):self.verify()
        self.create()
        with self.assertRaisesRegex(Denied,'REGISTRY_BACKUP_ALREADY_EXISTS'):self.create()
        db,manifest=self.files()
        os.chmod(db,0o644)
        with self.assertRaisesRegex(Denied,'REGISTRY_STATE_PERMISSIONS'):self.verify()
        os.chmod(db,0o600)
        os.chmod(manifest,0o644)
        with self.assertRaisesRegex(Denied,'REGISTRY_STATE_PERMISSIONS'):self.verify()
        os.chmod(manifest,0o600)
        self.assertEqual(self.verify()['result'],'INACTIVE_BACKUP_MATCH_CANDIDATE')

    def test_database_changed_while_snapshotting_denied(self):
        self.setup_backup();self.accept()
        original=r._counts;done=False
        def raced(store):
            nonlocal done
            result=original(store)
            if not done:
                done=True
                self.prepare_suffix()
                self.accept()
            return result
        with patch.object(r,'_counts',side_effect=raced):
            with self.assertRaisesRegex(Denied,'REGISTRY_BACKUP_SOURCE_CHANGED'):self.create()
        self.assertFalse(self.files()[1].exists())

    def test_wrong_store_and_same_destination_denied(self):
        self.setup_backup()
        with self.assertRaisesRegex(Denied,'REGISTRY_BACKUP_STORE_REQUIRED'):
            r.create_verified_backup(store=object(),directory=self.destination,backup_id=self.bid)
        with self.assertRaisesRegex(Denied,'REGISTRY_BACKUP_NOT_SEPARATE'):
            r.create_verified_backup(store=self.state,directory=self.root,backup_id=self.bid)
        self.assertFalse(self.files()[0].exists())

    def test_no_authority_from_digest_without_external_checkpoint(self):
        self.setup_backup();self.accept();result=self.create()
        other={'schemaVersion':1,'instanceId':str(uuid.uuid4()),
               'scopeDigest':'f'*64,'revision':1,'eventDigest':'f'*64}
        with self.assertRaises(Denied):
            self.verify(anchor_reader=lambda:other)
        self.assertEqual(result,self.verify())

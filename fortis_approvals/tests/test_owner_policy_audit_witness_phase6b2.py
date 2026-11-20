"""Phase 6B.2 isolated owner audit witness; never an apply ceremony."""
import hashlib
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
import uuid

from fortis_approvals.core import Denied, Stale, canonical, loads_strict
from fortis_approvals.extensions.owner_policy_authority_phase6 import ExactPolicyBaseline
from fortis_approvals.extensions.owner_policy_active_store_phase6b import (
    ProtectedActivePolicyStoreCandidate as Store)
from fortis_approvals.extensions.owner_policy_audit_witness_phase6b2 import (
    OwnerPolicyAuditWitnessCandidate as Witness)

COORD=('repo-ai','github','create_pull_request','fortis-approvals')
SOURCE=hashlib.sha256(b'installed-source').hexdigest()
CREDS=hashlib.sha256(b'owner-credential-generation').hexdigest()
KEY=b'owner-hmac-test-only-not-a-production-secret' * 2
BADKEY=b'wrong-hmac-test-key-not-production-secr' * 2
CHANGE=dict(actor=COORD[0],provider=COORD[1],operation=COORD[2],
            target=COORD[3],expectedPolicy='ASK',desiredPolicy='DENY')


class WitnessTests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root=Path(temp.name)
        self.dbparent=self.root/'protected-store'
        self.anchorparent=self.root/'protected-witness'
        self.dbparent.mkdir(mode=0o700)
        self.anchorparent.mkdir(mode=0o700)
        self.db=self.dbparent/'rules.sqlite'
        self.anchor=self.anchorparent/'witness.json'
        self.base=ExactPolicyBaseline(core_policies={COORD:'ASK'},
                                      loaded_services={'github'})
        self.store=Store(self.db,baseline=self.base,source_digest=SOURCE,
                         credential_generation_digest=CREDS,policy_version='test-v1')
        self.witness=Witness(self.anchor,store=self.store,owner_signing_key=KEY)
        self.request_id=str(uuid.uuid4())

    def prepare(self):
        self.store.prepare_change(dict(CHANGE),request_id=self.request_id,
            expected_revision=0,expected_audit_hash='0'*64,
            expected_source_digest=SOURCE,
            expected_credential_generation_digest=CREDS,
            expected_policy_version='test-v1',reason_code='OWNER_PREPARE')
        return self.store.snapshot()['auditHeadHash']

    def test_missing_anchor_and_ready_store_fail_closed(self):
        with self.assertRaises(Stale):
            self.witness.attest_prepared(request_id=self.request_id,audit_head='0'*64)
        head=self.prepare()
        with self.assertRaisesRegex(Denied,'PHASE6B2_WITNESS_MISSING'):
            self.witness.verify(request_id=self.request_id,audit_head=head)
        self.assertFalse(self.store.snapshot()['canApply'])

    def test_attested_prepared_stays_blocked_and_idempotent(self):
        head=self.prepare()
        first=self.witness.attest_prepared(request_id=self.request_id,audit_head=head)
        self.assertTrue(first['signatureVerified'])
        self.assertTrue(first['databaseMatchesWitness'])
        self.assertFalse(first['canApply'])
        self.assertFalse(first['activePolicyChanged'])
        self.assertFalse(first['alreadyWitnessed'])
        self.assertEqual(0,self.anchor.stat().st_mode & 0o077)
        again=self.witness.attest_prepared(request_id=self.request_id,audit_head=head)
        self.assertTrue(again['alreadyWitnessed'])
        self.assertEqual(first['auditHeadHash'],again['auditHeadHash'])
        self.assertEqual('PREPARED',self.store.snapshot()['gate'])
        self.assertEqual(0,self.store.snapshot()['revision'])
        with sqlite3.connect(self.db) as db:
            self.assertEqual('ASK',db.execute('SELECT policy FROM active_rules').fetchone()[0])

    def test_new_witness_instance_verifies_independent_signed_receipt(self):
        head=self.prepare()
        self.witness.attest_prepared(request_id=self.request_id,audit_head=head)
        reopened=Store(self.db,baseline=self.base,source_digest=SOURCE,
                       credential_generation_digest=CREDS,policy_version='test-v1')
        checker=Witness(self.anchor,store=reopened,owner_signing_key=KEY)
        self.assertTrue(checker.verify(request_id=self.request_id,
                                       audit_head=head)['signatureVerified'])

    def test_wrong_owner_key_invalidates_existing_signature(self):
        head=self.prepare()
        self.witness.attest_prepared(request_id=self.request_id,audit_head=head)
        with self.assertRaisesRegex(Denied,'PHASE6B2_WITNESS_BINDING_OR_SIGNATURE_INVALID'):
            Witness(self.anchor,store=self.store,owner_signing_key=BADKEY).verify(
                request_id=self.request_id,audit_head=head)

    def test_wrong_id_head_and_replay_not_accepted(self):
        head=self.prepare()
        self.witness.attest_prepared(request_id=self.request_id,audit_head=head)
        with self.assertRaises(Stale):
            self.witness.verify(request_id=str(uuid.uuid4()),audit_head=head)
        with self.assertRaises(Stale):
            self.witness.verify(request_id=self.request_id,audit_head='f'*64)
        with self.assertRaises(Denied):
            self.witness.verify(request_id='incorrect-id',audit_head=head)

    def test_untrusted_db_full_chain_rewrite_detected_by_external_anchor(self):
        head=self.prepare()
        self.witness.attest_prepared(request_id=self.request_id,audit_head=head)
        with sqlite3.connect(self.db) as db:
            payload=db.execute('SELECT payload FROM active_events').fetchone()[0]
            p=loads_strict(payload)
            p['change']['desiredPolicy']='ALLOW'
            updated=canonical(p)
            other=hashlib.sha256(('0'*64+'\n'+updated).encode()).hexdigest()
            db.execute('UPDATE active_events SET payload=?,event_hash=?',(updated,other))
            db.execute('UPDATE active_pending SET payload=?,event_hash=?',(updated,other))
            db.execute('UPDATE active_meta SET audit_hash=?',(other,))
        # The DB's own unkeyed digest is not independent anti-tamper proof.
        self.assertEqual(other,self.store.snapshot()['auditHeadHash'])
        with self.assertRaises(Stale):
            self.witness.verify(request_id=self.request_id,audit_head=head)
        with self.assertRaisesRegex(Denied,'PHASE6B2_WITNESS_BINDING_OR_SIGNATURE_INVALID'):
            self.witness.verify(request_id=self.request_id,audit_head=other)

    def test_anchor_tamper_and_truncated_crash_fail_closed(self):
        head=self.prepare()
        self.witness.attest_prepared(request_id=self.request_id,audit_head=head)
        self.anchor.write_text('{"invalid":"tampered"}\n',encoding='utf-8')
        with self.assertRaises(Denied):
            self.witness.verify(request_id=self.request_id,audit_head=head)
        with self.assertRaises(Denied):
            self.witness.attest_prepared(request_id=self.request_id,audit_head=head)
        self.anchor.write_bytes(b'')
        with self.assertRaises(Denied):
            self.witness.attest_prepared(request_id=self.request_id,audit_head=head)
        self.assertEqual('PREPARED',self.store.snapshot()['gate'])

    def test_private_witness_path_and_distinct_root_required(self):
        with self.assertRaisesRegex(Denied,'PHASE6B2_SEPARATE_ANCHOR_PATH_REQUIRED'):
            Witness(self.dbparent/'other.json',store=self.store,owner_signing_key=KEY)
        os.chmod(self.anchorparent,0o755)
        with self.assertRaises(Denied):
            Witness(self.anchor,store=self.store,owner_signing_key=KEY)
        os.chmod(self.anchorparent,0o700)
        alias=self.root/'witness-alias'
        alias.symlink_to(self.anchorparent,target_is_directory=True)
        with self.assertRaises(Denied):
            Witness(alias/'witness.json',store=self.store,owner_signing_key=KEY)

    def test_invalid_key_store_shape_and_hardlink_rejected(self):
        with self.assertRaises(Denied):
            Witness(self.anchor,store=self.store,owner_signing_key=b'short')
        with self.assertRaises(Denied):
            Witness(self.anchor,store=None,owner_signing_key=KEY)
        head=self.prepare()
        self.witness.attest_prepared(request_id=self.request_id,audit_head=head)
        os.link(self.anchor,self.anchorparent/'link.json')
        with self.assertRaisesRegex(Denied,'PHASE6B2_WITNESS_FILE_UNSAFE'):
            self.witness.verify(request_id=self.request_id,audit_head=head)

    def test_no_witness_mutation_of_runtime_or_core(self):
        head=self.prepare()
        self.witness.attest_prepared(request_id=self.request_id,audit_head=head)
        self.assertFalse(hasattr(self.witness,'apply'))
        self.assertFalse(hasattr(self.witness,'activate'))
        self.assertFalse(hasattr(self.witness,'commit'))
        self.assertFalse(hasattr(self.witness,'reset'))
        self.assertEqual('NOT_CONNECTED',self.store.snapshot()['runtimeIntegration'])


if __name__=='__main__':
    unittest.main()

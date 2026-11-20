"""Phase 6B.3 source-only monotonic authority contract tests.

The in-memory test anchor is NOT a trusted monotonic production service.
"""
import hashlib
import hmac
from pathlib import Path
import sqlite3
import tempfile
import unittest
import uuid

from fortis_approvals.core import Denied, Stale, canonical
from fortis_approvals.extensions.owner_policy_authority_phase6 import ExactPolicyBaseline
from fortis_approvals.extensions.owner_policy_active_store_phase6b import (
    ProtectedActivePolicyStoreCandidate as Store)
from fortis_approvals.extensions.owner_policy_audit_witness_phase6b2 import (
    OwnerPolicyAuditWitnessCandidate as Witness)
from fortis_approvals.extensions.owner_policy_monotonic_fence_phase6b3 import (
    MonotonicPolicyFenceCandidate as Fence)

COORD=('repo-ai','github','create_pull_request','fortis-approvals')
SOURCE=hashlib.sha256(b'attested-source').hexdigest()
CREDS=hashlib.sha256(b'attested-credential-generation').hexdigest()
INSTALL=hashlib.sha256(b'attested-owner-installation').hexdigest()
KEY=b'owner-test-quote-key-not-installed-aaaaaa'
WITNESS_KEY=b'owner-test-audit-witness-only-aaaaaaa'
CHANGE=dict(actor=COORD[0],provider=COORD[1],operation=COORD[2],
            target=COORD[3],expectedPolicy='ASK',desiredPolicy='DENY')


class TestOnlyLatestAuthority:
    """Represents an independent latest record; NOT a real secure anchor."""
    def __init__(self, *, key=KEY):
        self.key=key
        self.latest=None
        self.fail=False
        self.replay_nonce=None
        self.changed={}
        self.on_quote=None

    def quote(self, nonce):
        if self.fail:
            raise TimeoutError('owner attestation unavailable')
        if self.on_quote is not None:
            self.on_quote()
        if self.latest is None:
            return None
        payload=dict(self.latest,nonce=self.replay_nonce or nonce,**self.changed)
        msg=('FORTIS_OWNER_MONOTONIC_QUOTE_V1\n'+canonical(payload)).encode()
        return {'payload':payload,
                'hmacSha256':hmac.new(self.key,msg,hashlib.sha256).hexdigest()}


class MonotonicFenceTests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root=Path(temp.name)
        dbparent=root/'db'
        witnessparent=root/'witness'
        dbparent.mkdir(mode=0o700)
        witnessparent.mkdir(mode=0o700)
        self.dbpath=dbparent/'db.sqlite'
        self.wp=witnessparent/'witness.json'
        baseline=ExactPolicyBaseline(core_policies={COORD:'ASK'},
                                     loaded_services={'github'})
        self.store=Store(self.dbpath,baseline=baseline,source_digest=SOURCE,
                         credential_generation_digest=CREDS,policy_version='test-v1')
        self.witness=Witness(self.wp,store=self.store,
                             owner_signing_key=WITNESS_KEY)
        self.authority=TestOnlyLatestAuthority()
        self.fence=Fence(store=self.store,witness=self.witness,
                         installation_digest=INSTALL,
                         quote_latest=self.authority.quote,owner_quote_key=KEY)
        self.req=str(uuid.uuid4())

    def prepared(self):
        self.store.prepare_change(dict(CHANGE),request_id=self.req,
            expected_revision=0,expected_audit_hash='0'*64,
            expected_source_digest=SOURCE,
            expected_credential_generation_digest=CREDS,
            expected_policy_version='test-v1',reason_code='OWNER_PREPARE')
        snap=self.store.snapshot()
        head=snap['auditHeadHash']
        self.witness.attest_prepared(request_id=self.req,audit_head=head)
        self.authority.latest=dict(
            purpose='PHASE6B3_LATEST_PREPARED_CHECKPOINT_V1',
            installationDigest=INSTALL,epoch=1,gate='PREPARED',
            requestId=self.req,auditHeadHash=head,auditSequence=1,
            revision=0,baselineDigest=snap['baselineDigest'],
            sourceDigest=SOURCE,credentialGenerationDigest=CREDS,
            policyVersion='test-v1')
        return head

    def test_positive_latest_attestation_still_never_applies(self):
        head=self.prepared()
        state=self.fence.verify_prepared(request_id=self.req,audit_head=head)
        self.assertTrue(state['latestCheckpointVerified'])
        self.assertEqual(1,state['epoch'])
        self.assertFalse(state['canApply'])
        self.assertFalse(state['activePolicyChanged'])
        self.assertEqual('PREPARED',self.store.snapshot()['gate'])
        with sqlite3.connect(self.dbpath) as db:
            self.assertEqual('ASK',db.execute('SELECT policy FROM active_rules').fetchone()[0])

    def test_missing_anchor_or_timeout_fail_closed(self):
        head=self.prepared()
        self.authority.latest=None
        with self.assertRaises(Denied):
            self.fence.verify_prepared(request_id=self.req,audit_head=head)
        self.authority.fail=True
        with self.assertRaisesRegex(Denied,'PHASE6B3_OWNER_ANCHOR_UNAVAILABLE'):
            self.fence.verify_prepared(request_id=self.req,audit_head=head)

    def test_old_replayed_signed_quote_nonce_fails(self):
        head=self.prepared()
        self.authority.replay_nonce='e'*64
        with self.assertRaises(Stale):
            self.fence.verify_prepared(request_id=self.req,audit_head=head)

    def test_latest_checkpoint_mismatch_blocks_stale_local_pair(self):
        head=self.prepared()
        # Local DB and signed witness are BOTH old and internally consistent;
        # independent authority has advanced to a different latest state.
        self.authority.latest['auditHeadHash']='f'*64
        self.authority.latest['epoch']=2
        with self.assertRaisesRegex(Stale,'PHASE6B3_MONOTONIC_CHECKPOINT_MISMATCH'):
            self.fence.verify_prepared(request_id=self.req,audit_head=head)

    def test_wrong_install_source_credential_actor_and_epoch_fail(self):
        head=self.prepared()
        samples=(
            {'installationDigest':'f'*64},
            {'sourceDigest':'f'*64},
            {'credentialGenerationDigest':'f'*64},
            {'requestId':str(uuid.uuid4())},
            {'auditSequence':0},
            {'revision':1},
            {'gate':'READY'},
            {'epoch':0},
            {'epoch':True},
        )
        for changed in samples:
            with self.subTest(changed=changed):
                self.authority.changed=changed
                with self.assertRaises(Stale):
                    self.fence.verify_prepared(request_id=self.req,audit_head=head)
        self.authority.changed={}

    def test_attestation_signature_is_checked_after_field_validation(self):
        head=self.prepared()
        self.authority.key=b'other-test-quote-key-badbadbadbadbad'
        with self.assertRaisesRegex(Denied,'PHASE6B3_CHECKPOINT_SIGNATURE_INVALID'):
            self.fence.verify_prepared(request_id=self.req,audit_head=head)

    def test_local_witness_missing_or_revoked_blocks_before_quote(self):
        head=self.prepared()
        self.wp.unlink()
        with self.assertRaises(Denied):
            self.fence.verify_prepared(request_id=self.req,audit_head=head)
        self.assertEqual('PREPARED',self.store.snapshot()['gate'])

    def test_after_external_quote_local_database_race_is_detected(self):
        head=self.prepared()
        def mutate():
            self.authority.on_quote=None
            with sqlite3.connect(self.dbpath) as db:
                db.execute("UPDATE active_rules SET policy='DENY'")
        self.authority.on_quote=mutate
        with self.assertRaises(Denied):
            self.fence.verify_prepared(request_id=self.req,audit_head=head)

    def test_malformed_quote_or_unknown_fields_denied(self):
        head=self.prepared()
        self.authority.latest.pop('policyVersion')
        with self.assertRaises(Denied):
            self.fence.verify_prepared(request_id=self.req,audit_head=head)

    def test_wrong_store_witness_or_untrusted_anchor_denied(self):
        for args in (dict(store=None),dict(witness=None),
                     dict(owner_quote_key=b'short'),
                     dict(installation_digest='bad'),
                     dict(quote_latest=None)):
            with self.subTest(args=args),self.assertRaises(Denied):
                Fence(**{**dict(store=self.store,witness=self.witness,
                    installation_digest=INSTALL,quote_latest=self.authority.quote,
                    owner_quote_key=KEY),**args})
        self.assertFalse(hasattr(self.fence,'apply'))
        self.assertFalse(hasattr(self.fence,'activate'))
        self.assertFalse(hasattr(self.fence,'reset'))


if __name__=='__main__':
    unittest.main()

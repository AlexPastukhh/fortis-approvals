"""Phase 6B4 source-only recovery inspector tests."""
import hashlib
import hmac
from pathlib import Path
import sqlite3
import tempfile
import unittest
import uuid

from fortis_approvals.core import Denied, canonical
from fortis_approvals.extensions.owner_policy_authority_phase6 import ExactPolicyBaseline
from fortis_approvals.extensions.owner_policy_active_store_phase6b import ProtectedActivePolicyStoreCandidate as Store
from fortis_approvals.extensions.owner_policy_audit_witness_phase6b2 import OwnerPolicyAuditWitnessCandidate as Witness
from fortis_approvals.extensions.owner_policy_monotonic_fence_phase6b3 import MonotonicPolicyFenceCandidate as Fence
from fortis_approvals.extensions.owner_policy_recovery_evidence_phase6b4 import OwnerPolicyRecoveryInspectorCandidate as Inspector

COORD = ('repo-ai', 'github', 'create_pull_request', 'fortis-approvals')
SOURCE = hashlib.sha256(b'installed').hexdigest()
CREDS = hashlib.sha256(b'credentials').hexdigest()
INSTALL = hashlib.sha256(b'installation').hexdigest()
WITNESS_KEY = b'test-only-witness-0123456789012345'
QUOTE_KEY = b'test-only-quote-012345678901234567'
CHANGE = dict(actor=COORD[0], provider=COORD[1], operation=COORD[2],
              target=COORD[3], expectedPolicy='ASK', desiredPolicy='DENY')


class FakeLatest:
    """In-memory test fixture; NOT a secure monotonic provider."""
    def __init__(self):
        self.payload = None
        self.down = False
        self.replay = False
        self.calls = 0

    def quote(self, nonce):
        self.calls += 1
        if self.down:
            raise TimeoutError('no owner service')
        if self.payload is None:
            return None
        body = dict(self.payload, nonce='f'*64 if self.replay else nonce)
        message = ('FORTIS_OWNER_MONOTONIC_QUOTE_V1\n' + canonical(body)).encode()
        return {'payload': body,
                'hmacSha256': hmac.new(QUOTE_KEY, message, hashlib.sha256).hexdigest()}


class OwnerRecoveryEvidenceTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        dp, wp = root/'db', root/'witness'
        dp.mkdir(mode=0o700)
        wp.mkdir(mode=0o700)
        self.db = dp/'store.sqlite'
        self.wpath = wp/'anchor.json'
        baseline = ExactPolicyBaseline(core_policies={COORD:'ASK'}, loaded_services={'github'})
        self.store = Store(self.db, baseline=baseline, source_digest=SOURCE,
                           credential_generation_digest=CREDS, policy_version='test-v1')
        self.witness = Witness(self.wpath, store=self.store, owner_signing_key=WITNESS_KEY)
        self.latest = FakeLatest()
        self.fence = Fence(store=self.store, witness=self.witness,
                           installation_digest=INSTALL, quote_latest=self.latest.quote,
                           owner_quote_key=QUOTE_KEY)
        self.inspector = Inspector(store=self.store, witness=self.witness,
                                   monotonic_fence=self.fence)
        self.req = str(uuid.uuid4())
        self.head = '0'*64

    def prepare(self, *, witness=True, latest=True):
        self.store.prepare_change(dict(CHANGE), request_id=self.req,
            expected_revision=0, expected_audit_hash='0'*64,
            expected_source_digest=SOURCE, expected_credential_generation_digest=CREDS,
            expected_policy_version='test-v1', reason_code='OWNER_PREPARE')
        snap = self.store.snapshot()
        self.head = snap['auditHeadHash']
        if witness:
            self.witness.attest_prepared(request_id=self.req, audit_head=self.head)
        if latest:
            self.latest.payload = dict(
                purpose='PHASE6B3_LATEST_PREPARED_CHECKPOINT_V1',
                installationDigest=INSTALL, epoch=1, gate='PREPARED',
                requestId=self.req, auditHeadHash=self.head, auditSequence=1, revision=0,
                baselineDigest=snap['baselineDigest'], sourceDigest=SOURCE,
                credentialGenerationDigest=CREDS, policyVersion='test-v1')

    def inspect(self, *, request=None, head=None):
        return self.inspector.inspect(request_id=self.req if request is None else request,
                                      audit_head=self.head if head is None else head)

    def hold(self, row, code):
        self.assertEqual(code, row['classification'])
        self.assertEqual('HOLD_OWNER_REVIEW', row['disposition'])
        for field in ('canApply','canRecoverAutomatically','canResumeDispatch',
                      'activePolicyChanged','inFlightRequestsReconciled',
                      'policyCommitConfirmed'):
            self.assertIs(row[field], False)

    def test_ready_does_not_prove_no_rollback(self):
        self.hold(self.inspect(), 'PHASE6B4_NOT_PREPARED')
        self.assertEqual(0, self.latest.calls)

    def test_missing_witness_blocks_before_remote(self):
        self.prepare(witness=False)
        self.hold(self.inspect(), 'PHASE6B4_WITNESS_UNVERIFIABLE')
        self.assertEqual(0, self.latest.calls)

    def test_missing_or_timeout_external_checkpoint_blocks(self):
        self.prepare(latest=False)
        self.hold(self.inspect(), 'PHASE6B4_EXTERNAL_CHECKPOINT_UNVERIFIABLE')
        self.latest.down = True
        self.hold(self.inspect(), 'PHASE6B4_EXTERNAL_CHECKPOINT_UNVERIFIABLE')

    def test_verified_prepared_never_authorizes_apply(self):
        self.prepare()
        row = self.inspect()
        self.hold(row, 'PHASE6B4_ATTESTED_PREPARED_STILL_BLOCKED')
        self.assertIs(row['latestCheckpointVerified'], True)
        self.assertIs(row['witnessVerified'], True)
        self.assertEqual('PREPARED', self.store.snapshot()['gate'])
        with sqlite3.connect(self.db) as db:
            self.assertEqual('ASK', db.execute('SELECT policy FROM active_rules').fetchone()[0])

    def test_lost_ack_readback_does_not_duplicate_events(self):
        self.prepare()
        self.assertEqual(self.inspect(), self.inspect())
        with sqlite3.connect(self.db) as db:
            self.assertEqual(1, db.execute('SELECT COUNT(*) FROM active_events').fetchone()[0])

    def test_replayed_and_newer_external_quote_block(self):
        self.prepare()
        self.latest.replay = True
        self.hold(self.inspect(), 'PHASE6B4_EXTERNAL_CHECKPOINT_UNVERIFIABLE')
        self.latest.replay = False
        self.latest.payload['auditHeadHash'] = 'f'*64
        self.latest.payload['epoch'] = 2
        self.hold(self.inspect(), 'PHASE6B4_EXTERNAL_CHECKPOINT_UNVERIFIABLE')

    def test_bad_identity_and_head_do_not_contact_external_authority(self):
        self.prepare()
        for request, head in ((self.req,'bad'),('wrong',self.head),
                              (str(uuid.uuid4()),self.head),(self.req,'f'*64)):
            with self.subTest(request=request,head=head):
                self.hold(self.inspect(request=request,head=head),
                          'PHASE6B4_REQUEST_OR_HEAD_MISMATCH')
        self.assertEqual(0,self.latest.calls)

    def test_corrupt_db_never_contacts_external_authority(self):
        self.prepare()
        with sqlite3.connect(self.db) as db:
            db.execute("UPDATE active_rules SET policy='ALLOW'")
        self.hold(self.inspect(), 'PHASE6B4_LOCAL_STORE_UNVERIFIABLE')
        self.assertEqual(0, self.latest.calls)

    def test_corrupt_witness_never_contacts_external_authority(self):
        self.prepare()
        self.wpath.write_bytes(b'incomplete')
        self.hold(self.inspect(), 'PHASE6B4_WITNESS_UNVERIFIABLE')
        self.assertEqual(0, self.latest.calls)

    def test_bad_trusted_component_graph_rejected(self):
        for invalid in (dict(store=None),dict(witness=None),dict(monotonic_fence=None)):
            with self.subTest(invalid=invalid),self.assertRaises(Denied):
                Inspector(**{**dict(store=self.store,witness=self.witness,
                                    monotonic_fence=self.fence),**invalid})

    def test_no_apply_recover_retry_ask_or_mutation_methods(self):
        self.prepare()
        self.inspect()
        for name in ('apply','activate','recover','reconcile','retry','commit',
                     'clear_prepared','approve','submit'):
            self.assertFalse(hasattr(self.inspector,name))
        self.assertEqual('PREPARED', self.store.snapshot()['gate'])


if __name__ == '__main__':
    unittest.main()

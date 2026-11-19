"""No-fido2 tests of exact WebAuthn binding and inert draft ledger readback.

The owner authenticator in these tests is deliberately FAKE: cryptographic UV
coverage is in test_owner_portal.py on CI with VirtualKey.
"""
from pathlib import Path
import hashlib
import tempfile
import threading
from types import MethodType
import unittest
import uuid

from fortis_approvals.core import Denied, Stale
from fortis_approvals.extensions.owner_policy_draft_ledger import PolicyDraftLedger
from fortis_approvals.extensions.owner_policy_change_challenge import (
    PURPOSE, checked_change, OwnerPolicyChangeReview)
from fortis_approvals.owner_auth import OwnerWebAuthn, _hash

BASE = ('repo-ai','github','create_pull_request','fortis-approvals')
SOURCE = hashlib.sha256(b'reviewed-source').hexdigest()
CREDENTIALS = hashlib.sha256(b'credential-generation').hexdigest()
TOKEN = 'session-token-'+('z'*64)
CSRF = 'one-time-session-csrf'


class ChallengeTests(unittest.TestCase):
    def setUp(self):
        self.root=tempfile.TemporaryDirectory()
        self.addCleanup(self.root.cleanup)
        self.now=2000000000
        self.ledger=PolicyDraftLedger(Path(self.root.name)/'drafts.sqlite',
            baseline={BASE:'ASK'},source_digest=SOURCE,
            credential_generation_digest=CREDENTIALS,policy_version='v1',
            clock=lambda:self.now)
        snapshot=self.ledger.snapshot()
        self.change={
            'purpose':PURPOSE,'requestId':str(uuid.uuid4()),
            'actor':BASE[0], 'provider':BASE[1], 'operation':BASE[2], 'target':BASE[3],
            'oldPolicy':'ASK','newPolicy':'DENY','expectedRevision':0,
            'expectedAuditHash':snapshot['auditHash'],
            'baselineDigest':snapshot['baselineDigest'], 'sourceDigest':SOURCE,
            'credentialGenerationDigest':CREDENTIALS,'policyVersion':'v1',
            'reasonCode':'OWNER_DRAFT_CHANGE','expiresAt':self.now+100}
        self.owner=object.__new__(OwnerWebAuthn)
        self.owner.owner='test-owner'
        self.owner.clock=lambda:self.now
        self.owner.lock=threading.RLock()
        self.owner.pending={}
        self.owner.sessions={_hash(TOKEN):{
            'owner':self.owner.owner,'expires':self.now+1000,'csrf':CSRF}}
        self.owner.session_ttl=3600
        self.owner.server=None
        self.owner.rp_id='localhost'
        self.owner.origin='http://localhost:18990'
        self.owner.session_decisions={}
        self.verified=[]
        def fake_begin(obj,kind,**data):
            self.assertEqual('policy_change_review',kind)
            ceremony=obj._remember(kind,{'test-only':'challenge'},**data)
            return {'ceremonyId':ceremony,'options':{'publicKey':{'challenge':'fake-cryptographic-stub'}}}
        def fake_finish(obj,state,data,response):
            if response != {'testStrongUV':True}:
                raise Denied('TEST_REJECTED_PROOF')
            self.verified.append((state,data))
            return obj.owner
        self.owner._begin_assertion=MethodType(fake_begin,self.owner)
        self.owner._finish_assertion=MethodType(fake_finish,self.owner)
        self.review=OwnerPolicyChangeReview(self.owner)

    def begin(self, **overrides):
        return self.review.begin_policy_change_review(TOKEN,CSRF,
            {**self.change,**overrides},self.ledger)

    def finish(self,begin,change=None,session=TOKEN,csrf=CSRF,response=None):
        return self.review.finish_policy_change_review(session,csrf,begin['ceremonyId'],
            {'testStrongUV':True} if response is None else response,
            self.change if change is None else change,self.ledger)

    def test_exact_challenge_binds_to_inactive_ledger_and_strong_proof_only(self):
        first=self.begin()
        result=self.finish(first)
        self.assertEqual('OWNER_POLICY_DRAFT_REVIEW_ONLY',result['kind'])
        self.assertTrue(result['verified'])
        self.assertFalse(result['canApply'])
        self.assertFalse(result['policyActivated'])
        self.assertIsNone(result['authorizationToken'])
        self.assertEqual(first['changeDigest'],result['changeDigest'])
        self.assertEqual(1,len(self.verified))
        self.assertEqual(0,self.ledger.snapshot()['revision'])
        self.assertEqual('ASK',self.ledger.snapshot()['drafts'][0]['draftPolicy'])

    def test_replay_and_cross_session_fails_one_use(self):
        first=self.begin()
        with self.assertRaisesRegex(Denied,'POLICY_CHANGE_ASSERTION_BINDING_MISMATCH'):
            other='session-token-'+('b'*64)
            self.owner.sessions[_hash(other)]={'owner':self.owner.owner,'expires':self.now+1000,'csrf':CSRF}
            self.finish(first,session=other)
        with self.assertRaisesRegex(Denied,'CEREMONY_UNAVAILABLE'):
            self.finish(first)
        second=self.begin()
        self.finish(second)
        with self.assertRaisesRegex(Denied,'CEREMONY_UNAVAILABLE'):
            self.finish(second)

    def test_wrong_change_consumes_challenge(self):
        for updates in ({'newPolicy':'ALLOW'}, {'reasonCode':'ANOTHER_REASON'},
                        {'requestId':str(uuid.uuid4())}, {'expiresAt':self.now+80}):
            with self.subTest(updates=updates):
                start=self.begin()
                with self.assertRaisesRegex(Denied,'POLICY_CHANGE_ASSERTION_BINDING_MISMATCH'):
                    self.finish(start,change={**self.change,**updates})
                with self.assertRaisesRegex(Denied,'CEREMONY_UNAVAILABLE'):
                    self.finish(start)

    def test_csrf_session_and_expiry_fails_closed(self):
        with self.assertRaisesRegex(Denied,'CSRF_DENIED'):
            self.review.begin_policy_change_review(TOKEN,'bad',self.change,self.ledger)
        with self.assertRaisesRegex(Denied,'OWNER_SESSION_REQUIRED'):
            self.review.begin_policy_change_review('other',CSRF,self.change,self.ledger)
        start=self.begin()
        with self.assertRaisesRegex(Denied,'CSRF_DENIED'):
            self.finish(start,csrf='bad')
        self.now+=101
        with self.assertRaisesRegex(Denied,'CEREMONY_UNAVAILABLE|POLICY_CHANGE_EXPIRED_OR_TOO_LONG'):
            self.finish(start)
        with self.assertRaisesRegex(Denied,'POLICY_CHANGE_EXPIRED_OR_TOO_LONG'):
            self.begin()

    def test_stale_ledger_version_or_policy_fails_closed(self):
        start=self.begin()
        self.ledger.stage_draft(BASE,desired_policy='DENY',request_id=str(uuid.uuid4()),
            expected_revision=0,expected_policy='ASK',expected_source_digest=SOURCE,
            expected_credential_generation_digest=CREDENTIALS,
            expected_policy_version='v1',reason_code='OWNER_REVIEW_TEST')
        with self.assertRaisesRegex(Stale,'POLICY_CHANGE_STALE_REVISION'):
            self.finish(start)
        with self.assertRaisesRegex(Denied,'CEREMONY_UNAVAILABLE'):
            self.finish(start)
        self.assertEqual('DENY',self.ledger.snapshot()['drafts'][0]['draftPolicy'])

    def test_invalid_coordinates_purpose_transitions_and_grants(self):
        invalid=[
            ({'actor':'other-ai'},'POLICY_CHANGE_UNKNOWN_EXACT_GRANT'),
            ({'target':'other-repo'},'POLICY_CHANGE_UNKNOWN_EXACT_GRANT'),
            ({'operation':'delete_everything'},'POLICY_CHANGE_UNKNOWN_EXACT_GRANT'),
            ({'purpose':'APPLY_POLICY_V1'},'POLICY_CHANGE_PURPOSE_INVALID'),
            ({'oldPolicy':'ALLOW'},'POLICY_CHANGE_STALE_OLD_POLICY'),
            ({'newPolicy':'ASK'},'POLICY_CHANGE_TRANSITION_INVALID'),
            ({'newPolicy':'SUPERALLOW'},'POLICY_CHANGE_TRANSITION_INVALID'),
            ({'actor':'other/repo'},'POLICY_CHANGE_COORDINATES_INVALID'),
            ({'expectedRevision':True},'POLICY_CHANGE_REVISION_INVALID'),
            ({'reasonCode':'free form secret'},'POLICY_CHANGE_REASON_INVALID'),
            ({'sourceDigest':'A'*64},'POLICY_CHANGE_DIGEST_INVALID'),
            ({'expectedAuditHash':'f'*64},'POLICY_CHANGE_STALE_AUDITHASH'),
            ({'policyVersion':'v0'},'POLICY_CHANGE_STALE_POLICYVERSION'),
            ({'expiresAt':self.now+121},'POLICY_CHANGE_EXPIRED_OR_TOO_LONG'),
            ({'expiresAt':self.now},'POLICY_CHANGE_EXPIRED_OR_TOO_LONG'),
        ]
        for update,expected in invalid:
            with self.subTest(update=update),self.assertRaisesRegex((Denied,Stale),expected):
                self.begin(**update)
        for update in ({'extra':42},{'baselineDigest':None}):
            with self.assertRaises(Denied):
                self.begin(**update)
        self.assertEqual(0,self.ledger.snapshot()['revision'])
        self.assertEqual([],self.verified)

    def test_fake_crypto_failure_consumes_ceremony(self):
        start=self.begin()
        with self.assertRaisesRegex(Denied,'TEST_REJECTED_PROOF'):
            self.finish(start,response={'testStrongUV':False})
        with self.assertRaisesRegex(Denied,'CEREMONY_UNAVAILABLE'):
            self.finish(start)
        self.assertEqual(0,self.ledger.snapshot()['revision'])

    def test_race_after_signature_consumes_challenge_and_denies(self):
        start=self.begin()
        def racing_finish(obj,state,data,response):
            self.ledger.stage_draft(BASE,desired_policy='DENY',request_id=str(uuid.uuid4()),
                expected_revision=0,expected_policy='ASK',expected_source_digest=SOURCE,
                expected_credential_generation_digest=CREDENTIALS,
                expected_policy_version='v1',reason_code='OWNER_RACE_TEST')
            return obj.owner
        self.owner._finish_assertion=MethodType(racing_finish,self.owner)
        with self.assertRaisesRegex(Stale,'POLICY_CHANGE_STALE_REVISION'):
            self.finish(start)
        with self.assertRaisesRegex(Denied,'CEREMONY_UNAVAILABLE'):
            self.finish(start)
        self.assertEqual('DENY',self.ledger.snapshot()['drafts'][0]['draftPolicy'])

    def test_other_webauthn_uses_cannot_be_redeemed_as_policy_proof(self):
        decision=self.owner._remember('decision',{'fake':'state'},session_hash=_hash(TOKEN))
        with self.assertRaisesRegex(Denied,'CEREMONY_UNAVAILABLE'):
            self.review.finish_policy_change_review(TOKEN,CSRF,decision,
                {'testStrongUV':True},self.change,self.ledger)
        with self.assertRaisesRegex(Denied,'CEREMONY_UNAVAILABLE'):
            self.review.finish_policy_change_review(TOKEN,CSRF,decision,
                {'testStrongUV':True},self.change,self.ledger)
        self.assertEqual(0,self.ledger.snapshot()['revision'])

    def test_restart_and_revoked_session_invalidates_challenge(self):
        start=self.begin()
        self.owner.pending.clear() # Restart: active ceremonies are ephemeral.
        with self.assertRaisesRegex(Denied,'CEREMONY_UNAVAILABLE'):
            self.finish(start)
        second=self.begin()
        del self.owner.sessions[_hash(TOKEN)] # Credential/session revocation boundary.
        with self.assertRaisesRegex(Denied,'OWNER_SESSION_REQUIRED'):
            self.finish(second)


if __name__=='__main__':unittest.main()

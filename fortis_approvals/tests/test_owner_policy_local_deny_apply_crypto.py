"""Phase 6C.1 real virtual FIDO2 UV/RP assertion for exact DENY apply.

Source CI lane with fido2+cryptography. Test key does not reach production.
No owner host calls, HTTP route or live policy updates.
"""
import hashlib
from pathlib import Path
import tempfile
import unittest

from fortis_approvals.core import Authenticator, Denied, Stale
from fortis_approvals.owner_auth import OwnerWebAuthn
from fortis_approvals.synthetic import SyntheticAdapter
from fortis_approvals.extensions.owner_policy_local_core_phase6c import LocalDenyCore
from fortis_approvals.extensions.owner_policy_local_deny_apply_phase6c1 import OwnerLocalDenyApply
from test_owner_portal import VirtualKey

COORD=('agent-1','synthetic','set_ask','R3')
SOURCE=hashlib.sha256(b'owner-installed-source-test').hexdigest()
CREDS=hashlib.sha256(b'owner-credential-generation-test').hexdigest()


class LocalDenyRealVirtualWebAuthn(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory(prefix='fortis-local-deny-crypto-')
        self.addCleanup(temp.cleanup)
        root=Path(temp.name)
        self.owner=OwnerWebAuthn(root/'owner-keys.sqlite',origin='http://localhost:18990')
        self.key=VirtualKey()
        self.adapter=SyntheticAdapter(root/'adapter.sqlite')
        self.adapter.seed('R3','before')
        self.core=LocalDenyCore(root/'approvals.sqlite',
            adapters={'synthetic':self.adapter},policies={COORD:'ASK'},
            authenticator=Authenticator({'agent-secret':'agent-1'}),
            owner_verifier=self.owner,policy_version='owner-release-test-v1')
        self.apply=OwnerLocalDenyApply(self.core,self.owner,
            source_digest=SOURCE,credential_generation_digest=CREDS)
        invite=self.owner.issue_invitation()
        enrollment=self.owner.begin_enrollment(invite)
        self.owner.finish_enrollment(enrollment['ceremonyId'],self.key.enroll(enrollment))
        login=self.owner.begin_login()
        self.session,self.csrf=self.owner.finish_login(login['ceremonyId'],
                                                         self.key.assert_(login))

    def candidate(self):
        return dict(actor=COORD[0],provider=COORD[1],operation=COORD[2],
                    target=COORD[3],expectedConfiguredPolicy='ASK',
                    expectedPolicyVersion=self.core.policy_version,
                    expectedRevision=0,reasonCode='OWNER_DENY_EXACT')

    def begin(self):
        return self.apply.begin_deny(self.session,self.csrf,self.candidate())

    def finish(self,begin,response,change=None):
        return self.apply.finish_deny(self.session,self.csrf,begin['ceremonyId'],
            response,begin['change'] if change is None else change)

    def test_real_fido2_uv_activates_only_exact_local_deny(self):
        started=self.begin()
        outcome=self.finish(started,self.key.assert_(started))
        self.assertTrue(outcome['localDenyCommitted'])
        self.assertFalse(outcome['runtimeIntegrated'])
        self.assertFalse(outcome['canGrantAllow'])
        self.assertEqual('DENY',self.core._policy('agent-1',dict(
            service='synthetic',operation='set_ask',target='R3')))
        self.assertEqual('before',self.adapter.get('R3')['value'])
        with self.assertRaises(Denied):
            self.finish(started,self.key.assert_(started))

    def test_real_uv_and_origin_are_mandatory_and_failure_consumes_challenge(self):
        for case in ('uv_missing','wrong_origin','cross_origin','session_permit'):
            with self.subTest(case=case):
                started=self.begin()
                if case=='uv_missing':
                    assertion=self.key.assert_(started,uv=False)
                elif case=='wrong_origin':
                    assertion=self.key.assert_(started,origin='https://evil.example')
                elif case=='cross_origin':
                    assertion=self.key.assert_(started,cross_origin=True)
                else:
                    assertion={'mode':'session','session':self.session,'permit':'not-webauthn'}
                with self.assertRaises(Denied):
                    self.finish(started,assertion)
                with self.assertRaises(Denied):
                    self.finish(started,self.key.assert_(started))
        self.assertEqual('ASK',self.core._policy('agent-1',dict(
            service='synthetic',operation='set_ask',target='R3')))

    def test_real_fido2_proof_cannot_be_repurposed_from_review(self):
        started=self.begin()
        wrong={**started['change'],'purpose':'REVIEW_INACTIVE_POLICY_DRAFT_V1'}
        with self.assertRaises(Denied):
            self.finish(started,self.key.assert_(started),wrong)
        self.assertEqual('ASK',self.core._policy('agent-1',dict(
            service='synthetic',operation='set_ask',target='R3')))

    def test_valid_real_fido2_proof_with_stale_revision_cannot_commit(self):
        started=self.begin()
        with self.core._db() as db:
            db.execute('UPDATE owner_local_policy_meta SET revision=revision+1')
        with self.assertRaises(Stale):
            self.finish(started,self.key.assert_(started))
        self.assertEqual(1,self.core._local_revision(self._one_db()))
        self.assertEqual('ASK',self.core._policy('agent-1',dict(
            service='synthetic',operation='set_ask',target='R3')))

    def _one_db(self):
        db=self.core._db()
        connection=db.__enter__()
        self.addCleanup(db.__exit__,None,None,None)
        return connection


if __name__=='__main__':
    unittest.main()

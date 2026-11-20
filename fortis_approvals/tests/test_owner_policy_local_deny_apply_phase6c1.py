"""Phase 6C.1 owner DENY CAS state-machine tests.

SyntheticWebAuthn is a NON-CRYPTOGRAPHIC fixture; separate VirtualKey tests
exercise the real OwnerWebAuthn UV/RP/signature validation in Source CI.
"""
import hashlib
from pathlib import Path
import sqlite3
import tempfile
import threading
import unittest
import uuid

from fortis_approvals.core import Authenticator, Denied, Stale
from fortis_approvals.owner_auth import OwnerWebAuthn
from fortis_approvals.synthetic import SyntheticAdapter
from fortis_approvals.extensions.owner_policy_local_core_phase6c import LocalDenyCore
from fortis_approvals.extensions.owner_policy_local_deny_apply_phase6c1 import OwnerLocalDenyApply

ACTOR='agent-1'
COORD=(ACTOR,'synthetic','set_ask','record')
SOURCE=hashlib.sha256(b'trusted-operator-source').hexdigest()
CREDS=hashlib.sha256(b'trusted-credential-generation').hexdigest()


class SyntheticWebAuthn(OwnerWebAuthn):
    """Test-only structural simulator: NEVER accepted as a real owner proof."""
    def __init__(self):
        self.lock=threading.RLock()
        self.clock=lambda:1000
        self.pending={}
        self.owner='owner-test'
        self._session='synthetic-session-value-012345678901234567890'
        self._csrf='synthetic-csrf'

    def session(self, token, csrf=None):
        if token != self._session or csrf != self._csrf:
            raise Denied('SYNTHETIC_SESSION_INVALID')
        return {'owner':self.owner}

    def _begin_assertion(self, kind, **data):
        key=str(uuid.uuid4())
        self.pending[key]=(kind,dict(data))
        return {'ceremonyId':key, 'options':{'testOnly':True}}

    def _take(self, ceremony, kind):
        got=self.pending.pop(ceremony,None)
        if got is None or got[0]!=kind:
            raise Denied('SYNTHETIC_CEREMONY_CONSUMED')
        return {'synthetic':True},got[1]

    def _finish_assertion(self, state, data, response):
        if response != {'syntheticTestOnlyUv':True}:
            raise Denied('SYNTHETIC_UV_REQUIRED')
        return self.owner


class Phase6C1DenyTests(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory(prefix='fortis-local-deny-')
        self.addCleanup(tmp.cleanup)
        root=Path(tmp.name)
        self.adapter=SyntheticAdapter(root/'records.sqlite')
        self.adapter.seed('record','before')
        self.auth=Authenticator({'client-secret':ACTOR})
        self.owner=SyntheticWebAuthn()
        self.core=LocalDenyCore(root/'core.sqlite',
            adapters={'synthetic':self.adapter},policies={
                COORD:'ASK',
                (ACTOR,'synthetic','set_free','record'):'ALLOW',
                (ACTOR,'synthetic','set_deny','record'):'DENY'},
            authenticator=self.auth,owner_verifier=self.owner,
            policy_version='trusted-release-v1')
        self.ceremony=OwnerLocalDenyApply(self.core,self.owner,
            source_digest=SOURCE,credential_generation_digest=CREDS)
        self.session=self.owner._session
        self.csrf=self.owner._csrf

    def candidate(self,**overrides):
        c=dict(actor=ACTOR,provider='synthetic',operation='set_ask',
               target='record',expectedConfiguredPolicy='ASK',
               expectedPolicyVersion=self.core.policy_version,
               expectedRevision=0,reasonCode='OWNER_DENY_EXACT')
        c.update(overrides)
        return c

    def begin(self, candidate=None):
        return self.ceremony.begin_deny(self.session,self.csrf,candidate or self.candidate())

    def finish(self, begin, **kwargs):
        return self.ceremony.finish_deny(self.session,self.csrf,
            begin['ceremonyId'],kwargs.pop('response',{'syntheticTestOnlyUv':True}),
            kwargs.pop('change',begin['change']))

    def request(self):
        return dict(requestId=str(uuid.uuid4()),service='synthetic',
                    operation='set_ask',target='record',params={'value':'after'},
                    expectedVersion=0,reason='test')

    def test_exact_owner_deny_atomically_changes_revision_and_audit(self):
        pending=self.core.submit(ACTOR,self.request())
        self.assertEqual('PENDING',pending['state'])
        begin=self.begin()
        self.assertEqual('OWNER_LOCAL_DENY_APPLY_CEREMONY',begin['kind'])
        self.assertEqual('DENY',begin['change']['newPolicy'])
        result=self.finish(begin)
        self.assertTrue(result['localDenyCommitted'])
        self.assertFalse(result['runtimeIntegrated'])
        self.assertFalse(result['canGrantAllow'])
        self.assertEqual(1,result['appliedRevision'])
        self.assertEqual('trusted-release-v1|owner-local-deny:1',self.core.policy_version)
        self.assertEqual('DENY',self.core._policy(ACTOR,self.request()))
        with self.core._db() as db:
            rows=db.execute('SELECT * FROM owner_local_policy_events').fetchall()
            self.assertEqual(1,len(rows))
            self.assertEqual(begin['change']['requestId'],rows[0]['request_id'])
            self.assertEqual('owner-test',rows[0]['owner'])
            self.assertEqual(0,rows[0]['expected_revision'])
            self.assertEqual(1,rows[0]['applied_revision'])
        self.assertEqual('PENDING',self.core._read(pending['requestId'])['state'])
        with self.assertRaises(Denied):
            self.core.submit(ACTOR,self.request())

    def test_owner_only_readback_after_lost_ack_and_no_double_apply(self):
        begin=self.begin()
        self.finish(begin)
        self.assertEqual(dict(requestId=begin['change']['requestId'],
            found=True,appliedRevision=1,currentRevision=1,runtimeIntegrated=False),
            self.ceremony.readback(self.session,self.csrf,begin['change']['requestId']))
        with self.assertRaises(Denied):
            self.finish(begin)
        with self.assertRaises(Stale):
            self.begin(self.candidate())
        with self.core._db() as db:
            self.assertEqual(1,db.execute('SELECT COUNT(*) FROM owner_local_policy_events').fetchone()[0])

    def test_second_concurrent_ceremony_cas_fails_after_first_commit(self):
        first=self.begin()
        second=self.begin()
        self.finish(first)
        with self.assertRaises(Stale):
            self.finish(second)
        with self.core._db() as db:
            self.assertEqual(1,db.execute('SELECT COUNT(*) FROM owner_local_policy_events').fetchone()[0])

    def test_wrong_uv_and_wrong_descriptor_burn_one_time_challenge(self):
        a=self.begin()
        with self.assertRaises(Denied):
            self.finish(a,response={'syntheticTestOnlyUv':False})
        with self.assertRaises(Denied):
            self.finish(a)
        self.assertEqual('ASK',self.core._policy(ACTOR,self.request()))
        b=self.begin()
        with self.assertRaises(Denied):
            self.finish(b,change={**b['change'],'newPolicy':'ALLOW'})
        with self.assertRaises(Denied):
            self.finish(b)
        self.assertEqual(0,self.core._local_revision(self._one_db()))

    def _one_db(self):
        # Test assertion helper: returns a connection to be closed by cleanup.
        db=sqlite3.connect(self.core.path)
        db.row_factory=sqlite3.Row
        self.addCleanup(db.close)
        return db

    def test_wrong_session_and_csrf_cannot_begin_or_finish(self):
        with self.assertRaises(Denied):
            self.ceremony.begin_deny(self.session,None,self.candidate())
        with self.assertRaises(Denied):
            self.ceremony.begin_deny('bad-session',self.csrf,self.candidate())
        a=self.begin()
        with self.assertRaises(Denied):
            self.ceremony.finish_deny(self.session,'wrong',a['ceremonyId'],
                                      {'syntheticTestOnlyUv':True},a['change'])
        self.assertEqual('ASK',self.core._policy(ACTOR,self.request()))

    def test_invalid_expired_or_stale_change_denied_without_commit(self):
        for changed in (dict(actor='unknown'),dict(target='wrong'),
                        dict(operation='set_deny',expectedConfiguredPolicy='DENY'),
                        dict(expectedRevision=1),dict(expectedPolicyVersion='v1'),
                        dict(reasonCode='invalid'),dict(newPolicy='ALLOW'),
                        dict(expectedConfiguredPolicy='ALLOW')):
            with self.subTest(change=changed),self.assertRaises((Denied,Stale)):
                self.begin(self.candidate(**changed))
        a=self.begin()
        with self.core._db() as db:
            db.execute('UPDATE owner_local_policy_meta SET revision=revision+1')
        with self.assertRaises(Stale):
            self.finish(a)
        self.assertEqual(0,self._count_events())

    def test_expiry_and_source_digest_tampering_denied(self):
        a=self.begin()
        with self.assertRaises(Denied):
            self.finish(a,change={**a['change'],'sourceDigest':'f'*64})
        b=self.begin()
        with self.assertRaises(Denied):
            self.finish(b,change={**b['change'],'expiresAt':b['change']['expiresAt']-1})
        self.assertEqual(0,self._count_events())

    def test_expired_strong_challenge_is_consumed_without_change(self):
        started=self.begin()
        self.owner.clock=lambda:1150
        with self.assertRaises(Denied):
            self.finish(started)
        with self.assertRaises(Denied):
            self.finish(started)
        self.assertEqual(0,self._count_events())

    def test_exact_configured_allow_can_only_be_narrowed_to_deny(self):
        allowed=self.candidate(operation='set_free',
            expectedConfiguredPolicy='ALLOW')
        started=self.begin(allowed)
        self.assertEqual('ALLOW',started['change']['expectedConfiguredPolicy'])
        result=self.finish(started)
        self.assertTrue(result['localDenyCommitted'])
        self.assertEqual('DENY',self.core._policy(ACTOR,dict(
            service='synthetic',operation='set_free',target='record')))
        self.assertEqual('before',self.adapter.get('record')['value'])

    def test_callable_or_actor_wide_rule_not_mutable_via_exact_editor(self):
        self.core.policies[COORD]=lambda actor,payload:'ASK'
        with self.assertRaises(Denied):
            self.begin()
        del self.core.policies[COORD]
        self.core.policies[(ACTOR,'synthetic','set_ask')]='ASK'
        with self.assertRaises(Denied):
            self.begin()

    def test_revoked_actor_is_not_mutable(self):
        self.auth.revoke('client-secret')
        with self.assertRaises(Denied):
            self.begin()

    def test_deny_only_no_machine_apply_or_grant_escalation(self):
        with self.assertRaises(Denied):
            self.core.client('client-secret','owner_local_policy_apply',{})
        for method in ('set_allow','remove_deny','grant','set_ask'):
            self.assertFalse(hasattr(self.ceremony,method))
        self.assertFalse(hasattr(self.core,'owner_local_policy_apply'))
        self.assertEqual('DENY',self.core._policy(ACTOR,dict(service='synthetic',
            operation='set_deny',target='record')))

    def test_untrusted_owner_core_boundary_rejected(self):
        other=SyntheticWebAuthn()
        with self.assertRaises(Denied):
            OwnerLocalDenyApply(self.core,other,
                source_digest=SOURCE,credential_generation_digest=CREDS)
        with self.assertRaises(Denied):
            OwnerLocalDenyApply(self.core,self.owner,
                source_digest='bad',credential_generation_digest=CREDS)

    def test_prepared_gate_blocks_both_begin_and_finish(self):
        a=self.begin()
        with self.core._db() as db:
            db.execute("UPDATE owner_local_policy_meta SET gate='PREPARED'")
        with self.assertRaises(Denied):
            self.finish(a)
        with self.assertRaises(Denied):
            self.begin()
        self.assertEqual(0,self._count_events())

    def test_old_pending_and_approved_requests_cannot_dispatch_after_deny(self):
        pending=self.core.submit(ACTOR,self.request())
        with self.core._db() as db:
            db.execute("UPDATE requests SET state='APPROVED',decision='approve' WHERE id=?",
                       (pending['requestId'],))
        a=self.begin()
        self.finish(a)
        state=self.core.execute(pending['requestId'])
        self.assertEqual('STALE',state['state'])
        self.assertFalse(any(x['state']=='DISPATCHED'
            for x in self.core.events(pending['requestId'])))
        self.assertEqual('before',self.adapter.get('record')['value'])

    def _count_events(self):
        with self.core._db() as db:
            return db.execute('SELECT COUNT(*) FROM owner_local_policy_events').fetchone()[0]


if __name__=='__main__':
    unittest.main()

"""Phase 6C source-only local Core policy subclass acceptance (NO OWNER APPLY).

Direct SQL below is an OFFLINE TEST FIXTURE, not a production owner mutation.
"""
import hashlib
from pathlib import Path
import sqlite3
import tempfile
import unittest
import uuid

from fortis_approvals.core import Core, Authenticator, Conflict, Denied, canonical
from fortis_approvals.synthetic import SyntheticAdapter
from fortis_approvals.tests.test_core import SyntheticOwnerVerifier
from fortis_approvals.extensions.owner_policy_local_core_phase6c import LocalDenyCore

ACTOR='agent-1'
TARGET='record'


class LocalPolicyAdmissionTests(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root=Path(tmp.name)
        self.path=root/'core.sqlite'
        self.adapter=SyntheticAdapter(root/'adapter.sqlite')
        self.adapter.seed(TARGET,'before')
        self.auth=Authenticator({'client-secret': ACTOR})
        self.owner=SyntheticOwnerVerifier()
        self.config={('synthetic','set_ask'):'ASK',
                     ('synthetic','set_free'):'ALLOW',
                     ('synthetic','set_deny'):'DENY'}
        self.core=self.make_core()

    def make_core(self, enabled=True):
        cls=LocalDenyCore if enabled else Core
        return cls(self.path,adapters={'synthetic':self.adapter},
                   policies=self.config,authenticator=self.auth,
                   owner_verifier=self.owner,policy_version='core-local-v1')

    def request(self, operation='set_ask'):
        return dict(requestId=str(uuid.uuid4()),service='synthetic',
                    operation=operation,target=TARGET,
                    params={'value':'after'},expectedVersion=0,reason='test')

    def submit(self, operation='set_ask'):
        return self.core.client('client-secret','submit',self.request(operation))

    def approve(self, view, core=None):
        proof=self.owner.proof(view['requestId'],view['fingerprint'],'approve')
        return (core or self.core).owner_decide(view['requestId'],'approve',proof)

    def simulate_owner_denial(self, operation='set_ask'):
        # Trusted test SQL only; real system has NO editor/apply route.
        with self.core._db() as db:
            db.execute('BEGIN IMMEDIATE')
            db.execute('INSERT OR IGNORE INTO owner_local_denials VALUES(?,?,?,?,?)',
                       (ACTOR,'synthetic',operation,TARGET,'DENY'))
            db.execute('UPDATE owner_local_policy_meta SET revision=revision+1 WHERE id=1')

    def test_core_source_stays_unmodified_and_default_off(self):
        self.assertIsInstance(self.core,LocalDenyCore)
        legacy=self.make_core(False)
        self.assertEqual('core-local-v1',legacy.policy_version)
        self.assertEqual('core-local-v1|owner-local-deny:0',self.core.policy_version)
        self.assertIsNot(type(legacy),type(self.core))

    def test_legacy_new_database_has_no_local_policy_tables(self):
        self.path=self.path.parent/'legacy.sqlite'
        legacy=self.make_core(False)
        with legacy._db() as db:
            names={row['name'] for row in db.execute(
                "SELECT name FROM sqlite_master WHERE type='table'")}
        self.assertNotIn('owner_local_policy_meta',names)
        self.assertNotIn('owner_local_denials',names)

    def test_owner_fingerprint_automatically_binds_local_revision(self):
        view=self.submit()
        bound={'actor':ACTOR,'request':view['request'],
               'policyVersion':'core-local-v1|owner-local-deny:0',
               'preview':view['preview']}
        expected=hashlib.sha256(canonical(bound).encode()).hexdigest()
        self.assertEqual(expected,view['fingerprint'])
        self.assertEqual('EXECUTED',self.approve(view)['state'])

    def test_exact_denial_blocks_existing_allow(self):
        self.simulate_owner_denial('set_free')
        with self.assertRaisesRegex(Denied,'OPERATION_DENIED'):
            self.submit('set_free')
        self.assertEqual('before',self.adapter.get(TARGET)['value'])
        self.assertEqual('DENY',self.core._policy(
            ACTOR,dict(service='synthetic',operation='set_deny',target=TARGET)))

    def test_original_exact_actor_operation_and_target_scope(self):
        self.simulate_owner_denial('set_ask')
        with self.assertRaises(Denied):
            self.submit('set_ask')
        self.assertEqual('ASK',self.core._policy(
            ACTOR,dict(service='synthetic',operation='set_ask',target='other')))
        self.assertEqual('ASK',self.core._policy(
            'unrelated',dict(service='synthetic',operation='set_ask',target=TARGET)))
        self.assertEqual('DENY',self.core._policy(
            ACTOR,dict(service='synthetic',operation='set_ask',target=TARGET)))

    def test_pending_old_revision_cannot_be_owner_approved(self):
        view=self.submit()
        self.simulate_owner_denial('set_ask')
        with self.assertRaisesRegex(Denied,'OWNER_POLICY_CHANGED'):
            self.approve(view)
        self.assertEqual('PENDING',self.core._read(view['requestId'])['state'])
        self.assertEqual('before',self.adapter.get(TARGET)['value'])

    def test_stale_approved_request_cannot_dispatch(self):
        view=self.submit()
        with self.core._db() as db:
            db.execute("UPDATE requests SET state='APPROVED',decision='approve' WHERE id=?",
                       (view['requestId'],))
        self.simulate_owner_denial('set_ask')
        self.assertEqual('STALE',self.core.execute(view['requestId'])['state'])
        self.assertFalse(any(x['state']=='DISPATCHED'
                             for x in self.core.events(view['requestId'])))
        self.assertEqual('before',self.adapter.get(TARGET)['value'])

    def test_revision_bump_unrelated_method_stales_pending(self):
        view=self.submit()
        self.simulate_owner_denial('set_free')
        with self.assertRaisesRegex(Denied,'OWNER_POLICY_CHANGED'):
            self.approve(view)

    def test_version_race_during_owner_proof_is_checked_again(self):
        view=self.submit()
        original=self.owner
        core=self.core
        class BumpingVerifier:
            def verify(_,request_id,fingerprint,decision,proof):
                actor=original.verify(request_id,fingerprint,decision,proof)
                with core._db() as db:
                    db.execute('BEGIN IMMEDIATE')
                    db.execute('UPDATE owner_local_policy_meta SET revision=revision+1')
                return actor
        self.core.owner_verifier=BumpingVerifier()
        with self.assertRaisesRegex(Denied,'OWNER_POLICY_CHANGED'):
            self.approve(view)
        self.assertEqual('PENDING',self.core._read(view['requestId'])['state'])
        self.assertEqual('before',self.adapter.get(TARGET)['value'])

    def test_allow_remains_configured_only_with_no_local_denial(self):
        view=self.submit('set_free')
        self.assertEqual('EXECUTED',view['state'])
        self.assertEqual('after',self.adapter.get(TARGET)['value'])

    def test_prepared_holds_all_new_admissions_and_decisions(self):
        view=self.submit()
        with self.core._db() as db:
            db.execute("UPDATE owner_local_policy_meta SET gate='PREPARED' WHERE id=1")
        with self.assertRaisesRegex(Denied,'OWNER_LOCAL_POLICY_NOT_READY'):
            self.submit()
        with self.assertRaisesRegex(Denied,'OWNER_LOCAL_POLICY_NOT_READY'):
            self.approve(view)
        with self.core._db() as db:
            db.execute("UPDATE requests SET state='APPROVED',decision='approve' WHERE id=?",
                       (view['requestId'],))
        with self.assertRaisesRegex(Denied,'OWNER_LOCAL_POLICY_NOT_READY'):
            self.core.execute(view['requestId'])
        self.assertEqual('before',self.adapter.get(TARGET)['value'])

    def test_restart_preserves_exact_denials(self):
        view=self.submit()
        self.simulate_owner_denial('set_ask')
        new=self.make_core()
        self.assertEqual('core-local-v1|owner-local-deny:1',new.policy_version)
        with self.assertRaises(Denied):
            new.submit(ACTOR,self.request('set_ask'))
        with self.assertRaisesRegex(Denied,'OWNER_POLICY_CHANGED'):
            self.approve(view,core=new)

    def test_missing_metadata_or_partial_schema_fails_closed_on_restart(self):
        with self.core._db() as db:
            db.execute('DELETE FROM owner_local_policy_meta')
        with self.assertRaisesRegex(Denied,'OWNER_LOCAL_POLICY_NOT_READY'):
            self.make_core()
        with self.core._db() as db:
            db.execute('DROP TABLE owner_local_denials')
        with self.assertRaisesRegex(Denied,'OWNER_LOCAL_POLICY_SCHEMA_INCOMPLETE'):
            self.make_core()

    def test_schema_cannot_add_allow_or_invoke_machine_apply(self):
        with self.core._db() as db:
            with self.assertRaises(sqlite3.IntegrityError):
                db.execute('INSERT INTO owner_local_denials VALUES(?,?,?,?,?)',
                           (ACTOR,'synthetic','set_deny',TARGET,'ALLOW'))
        with self.assertRaises(Denied):
            self.core.client('client-secret','owner_policy_apply',{})
        for name in ('owner_policy_apply','policy_apply','change_policy'):
            self.assertFalse(hasattr(self.core,name))

    def test_base_core_bypass_is_unresolved_deployment_gate(self):
        # Honest source-level evidence: a legacy Core without the opt-in
        # subclass cannot enforce this same-DB deny overlay. No production
        # rollout is safe until ALL workers are pinned to the subclass.
        self.simulate_owner_denial('set_free')
        legacy=self.make_core(False)
        self.assertEqual('DENY',self.core._policy(
            ACTOR,dict(service='synthetic',operation='set_free',target=TARGET)))
        self.assertEqual('ALLOW',legacy._policy(
            ACTOR,dict(service='synthetic',operation='set_free',target=TARGET)))

    def test_pre_opt_in_request_is_stale_and_cannot_reuse_uuid(self):
        self.path=self.path.parent/'legacy-before-opt-in.sqlite'
        self.core=self.make_core(False)
        req=self.request()
        prior=self.core.client('client-secret','submit',req)
        guarded=self.make_core(True)
        with self.assertRaises(Conflict):
            guarded.client('client-secret','submit',req)
        with self.assertRaisesRegex(Denied,'OWNER_POLICY_CHANGED'):
            self.approve(prior,core=guarded)


if __name__=='__main__':
    unittest.main()

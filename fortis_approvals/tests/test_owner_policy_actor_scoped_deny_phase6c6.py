"""Phase 6C.6: WebAuthn exact-target DENY derived from actor-scoped ASK/ALLOW.

Source-only, no host activation. Fake proof covers state machine only;
separate FIDO2 crypto suite is required in exact-head Source CI.
"""
from pathlib import Path
import tempfile
import unittest
import uuid

from fortis_approvals.core import Authenticator, Denied, Stale
from fortis_approvals.synthetic import SyntheticAdapter
from fortis_approvals.extensions.owner_policy_local_core_phase6c import LocalDenyCore
from fortis_approvals.extensions.owner_policy_local_deny_apply_phase6c1 import OwnerLocalDenyApply
from fortis_approvals.extensions.owner_policy_local_bundle_phase6c3 import owner_local_deny_inventory
from fortis_approvals.tests.test_owner_policy_local_deny_apply_phase6c1 import (
    ACTOR, CREDS, SOURCE, SyntheticWebAuthn)


class ActorInheritedExactDenyTests(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory(prefix='fortis-actor-target-')
        self.addCleanup(tmp.cleanup)
        root=Path(tmp.name)
        self.adapter=SyntheticAdapter(root/'data.sqlite')
        self.adapter.seed('record','before')
        self.adapter.seed('other','untouched')
        self.owner=SyntheticWebAuthn()
        self.auth=Authenticator({'machine':'agent-1'})
        self.policies={('agent-1','synthetic','set_ask'):'ASK',
                       ('agent-1','synthetic','set_free'):'ALLOW',
                       ('synthetic','set_global'):'ASK'}
        self.core=LocalDenyCore(root/'core.sqlite',
            adapters={'synthetic':self.adapter},policies=self.policies,
            authenticator=self.auth,owner_verifier=self.owner,
            policy_version='source-v1')
        self.apply=OwnerLocalDenyApply(self.core,self.owner,
            source_digest=SOURCE,credential_generation_digest=CREDS)
        self.session=self.owner._session
        self.csrf=self.owner._csrf

    def candidate(self,**overrides):
        candidate=dict(actor=ACTOR,provider='synthetic',operation='set_ask',
            target='record',expectedConfiguredPolicy='ASK',
            expectedConfiguredScope='actor',
            expectedPolicyVersion=self.core.policy_version,
            expectedRevision=0,reasonCode='OWNER_DENY_ONE_TARGET')
        candidate.update(overrides)
        return candidate

    def begin(self,candidate=None):
        return self.apply.begin_deny(self.session,self.csrf,candidate or self.candidate())

    def finish(self,begun,change=None,response=None):
        return self.apply.finish_deny(self.session,self.csrf,
            begun['ceremonyId'],
            {'syntheticTestOnlyUv':True} if response is None else response,
            begun['change'] if change is None else change)

    def req(self,target):
        return dict(requestId=str(uuid.uuid4()),service='synthetic',
            operation='set_ask',target=target,params={'value':'new'},
            expectedVersion=0,reason='test')

    def count(self):
        with self.core._db() as db:
            return db.execute('SELECT COUNT(*) FROM owner_local_policy_events').fetchone()[0]

    def test_one_exact_target_denied_while_actor_wide_ask_is_unchanged(self):
        prior=self.core.submit(ACTOR,self.req('record'))
        begun=self.begin()
        self.assertEqual('actor',begun['change']['expectedConfiguredScope'])
        self.assertEqual('DENY',begun['change']['newPolicy'])
        receipt=self.finish(begun)
        self.assertEqual(1,receipt['appliedRevision'])
        self.assertFalse(receipt['canGrantAllow'])
        self.assertEqual('ASK',self.policies[(ACTOR,'synthetic','set_ask')])
        self.assertEqual('DENY',self.core._policy(ACTOR,self.req('record')))
        self.assertEqual('ASK',self.core._policy(ACTOR,self.req('other')))
        self.assertEqual('PENDING',self.core.submit(ACTOR,self.req('other'))['state'])
        with self.assertRaises(Denied):
            self.core.submit(ACTOR,self.req('record'))
        with self.assertRaisesRegex(Denied,'OWNER_POLICY_CHANGED'):
            self.core.owner_decide(prior['requestId'],'approve',{})
        self.assertEqual('before',self.adapter.get('record')['value'])
        self.assertEqual(1,self.count())

    def test_inventory_shows_derived_exact_denial_not_false_actor_wide_deny(self):
        self.finish(self.begin())
        info=owner_local_deny_inventory(self.core)
        source=[row for row in info['operations'] if
            row['scope']=='actor' and row['operation']=='set_ask']
        exact=[row for row in info['operations'] if
            row['scope']=='exact' and row['operation']=='set_ask']
        self.assertEqual(1,len(source))
        self.assertEqual(1,len(exact))
        self.assertEqual('ASK',source[0]['configuredPolicy'])
        self.assertFalse(source[0]['localDenialApplied'])
        self.assertEqual('record',exact[0]['target'])
        self.assertEqual('DENY',exact[0]['effectivePolicy'])
        self.assertEqual('actor',exact[0]['configuredSourceScope'])
        self.assertTrue(exact[0]['localDenialApplied'])
        self.assertEqual(1,info['localDeniedExactRules'])
        self.assertFalse(info['allWorkersVerified'])

    def test_already_configured_allow_may_be_narrowed_per_target_only(self):
        change=self.candidate(operation='set_free',expectedConfiguredPolicy='ALLOW')
        self.finish(self.begin(change))
        self.assertEqual('ALLOW',self.core._policy(ACTOR,dict(
            service='synthetic',operation='set_free',target='other')))
        self.assertEqual('DENY',self.core._policy(ACTOR,dict(
            service='synthetic',operation='set_free',target='record')))
        self.assertEqual('ALLOW',self.policies[(ACTOR,'synthetic','set_free')])

    def test_exact_override_blocks_actor_parent_from_shadowing(self):
        self.core.policies[(ACTOR,'synthetic','set_ask','record')]='DENY'
        with self.assertRaisesRegex(Denied,'OWNER_LOCAL_APPLY_ACTOR_SCOPE_SHADOWED'):
            self.begin()
        self.assertEqual(0,self.count())

    def test_actor_parent_must_be_literal_and_current(self):
        for change in (None,'DENY',lambda a,p:'ASK'):
            self.core.policies[(ACTOR,'synthetic','set_ask')]=change
            with self.subTest(change=change),self.assertRaises(Denied):
                self.begin()
        self.core.policies[(ACTOR,'synthetic','set_ask')]='ASK'
        begun=self.begin()
        self.core.policies[(ACTOR,'synthetic','set_ask')]='ALLOW'
        with self.assertRaisesRegex(Denied,'OWNER_LOCAL_APPLY_ACTOR_SCOPE_NOT_LITERAL'):
            self.finish(begun)
        self.assertEqual(0,self.count())

    def test_corrupt_inherited_rule_inventory_fails_closed(self):
        begun=self.begin()
        self.finish(begun)
        self.core.policies[(ACTOR,'synthetic','set_ask')]=lambda a,p:'ASK'
        with self.assertRaisesRegex(Denied,'OWNER_LOCAL_INVENTORY_DENIAL_UNRESOLVED'):
            owner_local_deny_inventory(self.core)

    def test_only_global_grant_is_not_sufficient(self):
        with self.assertRaisesRegex(Denied,'OWNER_LOCAL_APPLY_ACTOR_SCOPE_NOT_LITERAL'):
            self.begin(self.candidate(operation='set_global'))
        self.assertEqual(0,self.count())

    def test_wrong_scope_tag_or_implicit_inheritance_denied(self):
        for value in ('global','exact','ACTOR',None,True,0):
            with self.subTest(value=value),self.assertRaises(Denied):
                self.begin(self.candidate(expectedConfiguredScope=value))
        without_scope=self.candidate()
        del without_scope['expectedConfiguredScope']
        with self.assertRaisesRegex(Denied,'OWNER_LOCAL_APPLY_EXACT_CONFIGURED_GRANT_REQUIRED'):
            self.begin(without_scope)

    def test_tampered_scope_proof_consumed_without_write(self):
        begun=self.begin()
        forged={**begun['change'],'expectedConfiguredScope':'global'}
        with self.assertRaises(Denied):
            self.finish(begun,change=forged)
        with self.assertRaises(Denied):
            self.finish(begun)
        self.assertEqual(0,self.count())

    def test_racing_revision_or_second_apply_never_double_writes(self):
        first=self.begin()
        second=self.begin()
        self.finish(first)
        with self.assertRaises(Stale):
            self.finish(second)
        self.assertEqual(1,self.count())
        with self.assertRaises(Denied):
            self.finish(first)
        with self.assertRaises(Stale):
            self.begin()

    def test_drift_to_exact_override_after_begin_is_denied(self):
        begun=self.begin()
        self.core.policies[(ACTOR,'synthetic','set_ask','record')]='ASK'
        with self.assertRaisesRegex(Denied,'OWNER_LOCAL_APPLY_ACTOR_SCOPE_SHADOWED'):
            self.finish(begun)
        self.assertEqual(0,self.count())

    def test_bad_uv_and_unknown_actor_never_write(self):
        begun=self.begin()
        with self.assertRaises(Denied):
            self.finish(begun,response={'syntheticTestOnlyUv':False})
        with self.assertRaises(Denied):
            self.begin(self.candidate(actor='unknown'))
        self.assertEqual(0,self.count())


if __name__ == '__main__':
    unittest.main()

"""No-network proof that persistent owner ALLOW cannot forge ASK approval.

The exact Core/actor/policy/source preview are checked immediately before
the GitHub label write. Publisher actor still requires its per-request ASK.
"""
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from fortis_approvals.core import Denied, Stale, canonical
from fortis_approvals.workflow.adapters import NativeGitHubAdapter
from fortis_approvals.integrations.github.publisher_profile import PublisherProfile, ACTOR as PUBLISHER

REPO_ACTOR='repo-sonar-read-proposal-actor'
IDENT='00000000-0000-4000-8000-000000000001'
REQUEST=dict(requestId=IDENT,service='github',operation='create_release_label',
             target='fortis-approvals',params={'name':'build:gateway'})
POLICY_ID=(REPO_ACTOR,'github','create_release_label')
PROFILE=PublisherProfile(enabled=True,revision='a'*64,
    validator_revision='b'*40,registry_delegation=True)


class GuardTests(unittest.TestCase):
    def setUp(self):
        self.preview={'releaseLabelPolicy':'test-profile-hash'}
        self.row=dict(state='DISPATCHED',decision=None,owner=None,actor=REPO_ACTOR,
                      request=REQUEST,preview=self.preview,expiresAt=200,
                      policyVersion='v|owner-policy-v2:1')
        self.policy='ALLOW'
        self.choices=True
        def admitted(coord):
            if coord!=POLICY_ID or not self.choices:
                raise Denied('OWNER_POLICY_NOT_ADMITTED')
            return 'ASK',frozenset({'DENY','ASK','ALLOW'})
        self.core=SimpleNamespace(_read=lambda ident:self.row,
            clock=lambda:100,policy_version='v|owner-policy-v2:1',
            auth=SimpleNamespace(active=lambda actor:True),
            _policy=lambda actor,request:self.policy,
            authority=SimpleNamespace(choices={POLICY_ID:{'DENY','ASK','ALLOW'}},
                                      admitted=admitted))
        self.adapter=object.__new__(NativeGitHubAdapter)
        self.adapter.actor=REPO_ACTOR
        self.adapter.observation_core=self.core
        self.adapter.publisher=PROFILE
        self.adapter.publisher_broker=object()
        self.adapter.config=object()
        self.profile_patch=patch.object(PublisherProfile,'validate_composition',return_value=None)
        self.profile_patch.start()
        self.addCleanup(self.profile_patch.stop)
        self.fingerprint_patch=patch.object(PublisherProfile,'fingerprint',return_value='test-profile-hash')
        self.fingerprint_patch.start()
        self.addCleanup(self.fingerprint_patch.stop)

    def guard(self,request=None,snapshot=None,approved_preview='default'):
        bound = self.preview if approved_preview=='default' else approved_preview
        self.adapter._before_release_label_write(request or REQUEST,
            self.preview if snapshot is None else snapshot,bound)

    def test_registry_owner_allow_requires_persisted_policy_and_exact_dispatch(self):
        self.guard()
        for changed in (
            dict(state='PENDING'),dict(state='APPROVED'),
            dict(decision='approve'),dict(actor='other-actor'),
            dict(policyVersion='stale'),dict(request={**REQUEST, 'target':'other'}),
            dict(preview={'releaseLabelPolicy':'old-hash'})
        ):
            with self.subTest(changed=changed):
                before=self.row.copy()
                self.row.update(changed)
                with self.assertRaises(Stale):self.guard()
                self.row=before
        self.policy='ASK'
        with self.assertRaises(Stale):self.guard()
        self.policy='ALLOW'
        self.choices=False
        with self.assertRaises(Stale):self.guard()
        self.choices=True
        self.row['owner']='imposter'
        self.guard() # irrelevant owner field cannot forge per-request ASK

    def test_publisher_actor_still_requires_real_ask(self):
        self.row.update(actor=PUBLISHER,decision='approve',owner='owner-test')
        self.policy='ASK'
        self.guard()
        self.row.update(decision=None,owner=None)
        with self.assertRaises(Stale):self.guard()
        self.policy='ALLOW'
        with self.assertRaises(Stale):self.guard()

    def test_never_accept_changed_request_or_preview_even_with_allow(self):
        with self.assertRaises(Stale):
            self.guard(request={**REQUEST,'params':{'name':'build:evil'}})
        with self.assertRaises(Stale):
            self.guard(snapshot={'releaseLabelPolicy':'different'})

    def test_no_direct_allow_without_publisher_admission(self):
        # When profile is disabled there is no P3 approval precondition:
        # actual Core policy/dispatch still controls the effect.
        self.adapter.publisher=PublisherProfile()
        with self.assertRaises(Stale):
            # A bound preview cannot evade its publisher guard by disabling it.
            self.guard(approved_preview=None)
        self.row['preview']={}
        self.guard(snapshot={},approved_preview=None)
        self.row['preview']=self.preview
        self.adapter.publisher=PROFILE
        self.policy='DENY'
        with self.assertRaises(Stale):self.guard()


if __name__=='__main__':
    unittest.main()

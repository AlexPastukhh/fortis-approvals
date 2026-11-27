"""Existing real Policy Engine/editor with synthetic enrollment and guards."""
from pathlib import Path
import tempfile
import unittest
import uuid

from fortis_approvals.core import Authenticator, Denied
from fortis_approvals.extensions.composite_authority import (
    ContextGrant, ContextEnrollment, ContextAdmission, ProviderGuard,
    reviewed_additive_authority,
)
from fortis_approvals.extensions.composite_contract import definition, expand_group
from fortis_approvals.extensions.owner_policy_engine_v2 import PolicyAdmission, UnifiedPolicyCore
from fortis_approvals.extensions.owner_policy_editor_v2 import OwnerPolicyEditor
from fortis_approvals.integrations.registry_contracts.semantic_contract import digest
from fortis_approvals.core import canonical
from fortis_approvals.synthetic import SyntheticAdapter
from fortis_approvals.tests import test_owner_policy_engine_v2 as fixture
from fortis_approvals.tests.test_registry_semantic_contract import begin

ACTOR = fixture.ACTOR
PARENT = (ACTOR, 'registry', 'begin_release_group', 'scope')
CHILD = (ACTOR, 'registry', 'begin_release', 'subject-a')
CHOICES = {'DENY', 'ASK', 'ALLOW'}
SOURCE = 'a'*64


def enrollment(grants):
    value = {'schemaVersion': 1, 'sourceDigest': SOURCE,
             'grants': sorted([g.record() for g in grants], key=canonical)}
    return ContextEnrollment(grants, source_digest=SOURCE, expected_digest=digest(value))


class ContextAuthorityTests(unittest.TestCase):
    candidate = fixture.UnifiedPolicyTests.candidate
    begin = fixture.UnifiedPolicyTests.begin
    finish = fixture.UnifiedPolicyTests.finish
    change = fixture.UnifiedPolicyTests.change

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.auth = Authenticator({'machine': ACTOR})
        self.owner = fixture.HTTPFixtureWebAuthn()
        self.owner.origin = 'http://localhost:18990'
        self.adapter = SyntheticAdapter(self.root/'synthetic.sqlite')
        self.adapter.seed('record', 'before')
        self.grant = ContextGrant(ACTOR, 'begin_release_group', 'scope', 'subject-a',
                                  'Owner/repo', 'a', 'test',
                                  definition('registry', 'begin_release_group').definition_digest)
        self.enrollment = enrollment((self.grant,))
        self.scope = {'origin': 'synthetic', 'compositeContext': self.enrollment.sha}
        self.policies = {PARENT: 'ALLOW', CHILD: 'ASK'}
        self.choices = {PARENT: CHOICES, CHILD: CHOICES}
        self.core = self.make_core('context.sqlite', self.policies)
        self.core.install_policy_authority(self.choices, scope_binding=self.scope)
        self.editor = OwnerPolicyEditor(self.core, self.owner, source_digest=SOURCE,
                                       credential_generation=lambda: 'b'*64)
        self.guard = ProviderGuard(True, True, 'ALLOW', 'c'*64)
        self.admission = ContextAdmission(self.core, self.enrollment,
                                         guard=lambda *_: self.guard)
        self.step = expand_group('registry', 'begin_release_group', str(uuid.uuid4()),
                                 {'items': [begin(), begin('b')]})['steps'][0]

    def make_core(self, name, policies):
        return UnifiedPolicyCore(self.root/name, adapters={'registry': self.adapter,
                                  'synthetic': self.adapter}, policies=policies,
                                 authenticator=self.auth, owner_verifier=self.owner,
                                 policy_version='synthetic')

    def test_owner_policy_edit_and_context_ask_without_standalone_change(self):
        a = self.admission.admit(ACTOR, 'scope', self.step)
        self.assertEqual(a.standalone, 'ASK')
        self.assertTrue(a.contextual)
        self.change(CHILD, 'ASK', 'DENY')
        with self.assertRaises(Denied):
            self.admission.admit(ACTOR, 'scope', self.step)
        self.change(CHILD, 'DENY', 'ASK')
        b = self.admission.admit(ACTOR, 'scope', self.step)
        self.assertNotEqual(a.generation_digest, b.generation_digest)
        self.change(PARENT, 'ALLOW', 'DENY')
        with self.assertRaises(Denied):
            self.admission.admit(ACTOR, 'scope', self.step)

    def test_exact_context_and_provider_veto(self):
        for guard in (ProviderGuard(False, True, 'ALLOW', 'c'*64),
                      ProviderGuard(True, False, 'ALLOW', 'c'*64),
                      ProviderGuard(True, True, 'ASK', 'c'*64),
                      ProviderGuard(True, True, 'DENY', 'c'*64)):
            self.guard = guard
            with self.assertRaises(Denied):
                self.admission.admit(ACTOR, 'scope', self.step)
        self.guard = ProviderGuard(True, True, 'ALLOW', 'c'*64)
        for actor, target in (('other', 'scope'), (ACTOR, 'other')):
            with self.assertRaises(Denied):
                self.admission.admit(actor, target, self.step)
        other = expand_group('registry', 'begin_release_group', str(uuid.uuid4()),
                             {'items': [begin('b'), begin('c')]})['steps'][0]
        with self.assertRaises(Denied):
            self.admission.admit(ACTOR, 'scope', other)
        self.auth.revoke('machine')
        with self.assertRaises(Denied):
            self.admission.admit(ACTOR, 'scope', self.step)

    def test_definition_and_payload_binding(self):
        for patch in ({'definitionDigest': 'f'*64}, {'version': 2},
                      {'payloadDigest': 'f'*64}, {'operation': 'merge_pull_request'}):
            with self.assertRaises(Denied):
                self.admission.admit(ACTOR, 'scope', {**self.step, **patch})
        with self.assertRaises(Denied):
            ContextEnrollment((self.grant,), source_digest=SOURCE, expected_digest='f'*64)

    def test_missing_authority_binding_denied(self):
        core = self.make_core('unbound.sqlite', self.policies)
        core.install_policy_authority(self.choices, scope_binding={'origin': 'synthetic'})
        with self.assertRaises(Denied):
            ContextAdmission(core, self.enrollment, guard=lambda *_: self.guard).admit(
                ACTOR, 'scope', self.step)

    def test_no_fallback_to_actor_rule_for_child_scope(self):
        actor_rule = CHILD[:3]
        core = self.make_core('fallback.sqlite', {PARENT: 'ALLOW', actor_rule: 'ASK'})
        core.install_policy_authority({PARENT: CHOICES, actor_rule: CHOICES},
                                      scope_binding=self.scope)
        with self.assertRaises(Denied):
            ContextAdmission(core, self.enrollment, guard=lambda *_: self.guard).admit(
                ACTOR, 'scope', self.step)

    def test_scope_edit_cannot_create_context_admission(self):
        scope = {'origin': 'synthetic'}
        core = self.make_core('drift.sqlite', self.policies)
        core.install_policy_authority(self.choices, scope_binding=scope)
        scope['compositeContext'] = self.enrollment.sha
        with self.assertRaises(Denied):
            ContextAdmission(core, self.enrollment, guard=lambda *_: self.guard).admit(
                ACTOR, 'scope', self.step)

    def test_additive_proposal_preserves_old_choices_and_defaults_deny(self):
        old_coord = (ACTOR, 'synthetic', 'set_free', 'record')
        old = self.make_core('old.sqlite', {old_coord: 'ALLOW'})
        old.install_policy_authority({old_coord: {'DENY', 'ALLOW'}},
                                     scope_binding={'origin': 'synthetic'})
        policies = {old_coord: 'ALLOW', PARENT: 'DENY', CHILD: 'DENY'}
        core = self.make_core('candidate.sqlite', policies)
        choices = {old_coord: {'DENY', 'ALLOW'}, PARENT: CHOICES, CHILD: CHOICES}
        pin = PolicyAdmission(core, choices, scope_binding=self.scope).sha
        args = dict(predecessor=old.authority, enrollment=self.enrollment, choices=choices,
                    scope_binding=self.scope, expected_predecessor_digest=old.authority.sha,
                    expected_successor_digest=pin)
        candidate = reviewed_additive_authority(core, **args)
        self.assertEqual(candidate.sha, pin)
        self.assertIsNone(core.authority)
        self.assertEqual(candidate.baseline[PARENT], 'DENY')
        self.assertEqual(candidate.baseline[CHILD], 'DENY')
        for changes in (
            {'expected_predecessor_digest': 'f'*64},
            {'expected_successor_digest': 'f'*64},
            {'scope_binding': {**self.scope, 'origin': 'drifted'}},
            {'choices': {**choices, old_coord: CHOICES}},
        ):
            with self.assertRaises(Denied):
                reviewed_additive_authority(core, **{**args, **changes})
        broadened = self.make_core('broader.sqlite', {**policies, PARENT: 'ALLOW'})
        with self.assertRaises(Denied):
            reviewed_additive_authority(broadened, **args)


if __name__ == '__main__':
    unittest.main()

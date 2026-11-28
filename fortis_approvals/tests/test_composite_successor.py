"""Successor composition against real UnifiedPolicyCore and test-only bindings."""
from pathlib import Path
import sqlite3
import tempfile
import unittest
import uuid

from fortis_approvals.core import Authenticator, Denied
from fortis_approvals.extensions.composite_authority import (
    ContextAdmission, ContextGrant, ProviderGuard,
)
from fortis_approvals.extensions.composite_contract import definition
from fortis_approvals.extensions.composite_executor import GroupAdapter
from fortis_approvals.extensions.composite_preservation import (
    inspect_companion, install_checked, legacy_schema_witness,
)
from fortis_approvals.extensions.composite_successor import (
    CompositeUnifiedCore, ReviewedHistory, ReviewedHistoryEvidence)
from fortis_approvals.extensions.owner_policy_editor_v2 import OwnerPolicyEditor, UnifiedPolicyPortal
from fortis_approvals.extensions.owner_policy_engine_v2 import PolicyAdmission, UnifiedPolicyCore
from fortis_approvals.extensions.transition_authority import authority_witness, compare_authority_epoch
from fortis_approvals.integrations.registry_contracts.semantic_contract import digest
from fortis_approvals.synthetic import SyntheticAdapter
from fortis_approvals.tests import test_owner_policy_engine_v2 as fixture
from fortis_approvals.tests.test_composite_authority import enrollment
from fortis_approvals.tests.test_composite_executor import Binding
from fortis_approvals.extensions.maintenance_gate import MaintenanceGate
from fortis_approvals.tests import test_maintenance_gate as maintenance_fixture
from fortis_approvals.tests.test_registry_semantic_contract import begin

ACTOR = fixture.ACTOR
OLD = fixture.FREE
PARENT = (ACTOR, 'registry', 'begin_release_group', 'scope')
CHILDREN = tuple((ACTOR, 'registry', 'begin_release', name) for name in ('a', 'b'))
ALL = {'DENY', 'ASK', 'ALLOW'}


def snapshot(core, fn):
    with core._db() as db:
        db.execute('PRAGMA query_only=ON')
        db.execute('BEGIN')
        return fn(db)


class IntegratedBinding(Binding):
    def admit(self, actor, target, step):
        return self.admission.admit(actor, target, step)


class SuccessorTests(unittest.TestCase):
    candidate = fixture.UnifiedPolicyTests.candidate
    begin = fixture.UnifiedPolicyTests.begin
    finish = fixture.UnifiedPolicyTests.finish
    change = fixture.UnifiedPolicyTests.change

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.path = self.root/'core.sqlite'
        self.auth = Authenticator({'machine': ACTOR})
        self.owner = fixture.HTTPFixtureWebAuthn()
        self.owner.origin = 'http://localhost:18990'
        self.ordinary = SyntheticAdapter(self.root/'ordinary.sqlite')
        self.ordinary.seed('record', 'before')
        self.binding = IntegratedBinding()
        self.old_policies = {OLD: 'ALLOW'}
        self.old_choices = {OLD: {'DENY', 'ALLOW'}}
        self.old_scope = {'origin': 'synthetic-incumbent'}
        self.core = UnifiedPolicyCore(self.path, adapters={'synthetic': self.ordinary},
            policies=self.old_policies, authenticator=self.auth, owner_verifier=self.owner,
            policy_version='old')
        self.core.install_policy_authority(self.old_choices, scope_binding=self.old_scope)
        self.editor = self.make_editor(self.core)
        self.change(OLD, 'ALLOW', 'DENY')
        # Real existing epoch upgrade before the composite epoch.
        self.old_choices = {OLD: ALL}
        intermediate = UnifiedPolicyCore(self.path, adapters={'synthetic': self.ordinary},
            policies=self.old_policies, authenticator=self.auth, owner_verifier=self.owner,
            policy_version='old')
        intermediate.install_policy_authority(self.old_choices, scope_binding=self.old_scope,
                                             reviewed_upgrade_from={OLD: {'DENY', 'ALLOW'}})
        self.core = intermediate
        self.editor = self.make_editor(self.core)
        self.change(OLD, 'DENY', 'ASK')
        self.change(OLD, 'ASK', 'DENY')
        self.old = self.core
        self.before = snapshot(self.old, lambda db: authority_witness(self.old, db))
        self.history = snapshot(self.old, lambda db: ReviewedHistory(
            self.old, db, expected_witness_digest=digest(self.before)))
        self.enrollment = enrollment(tuple(ContextGrant(
            ACTOR, PARENT[2], PARENT[3], child[3], 'Owner/repo', child[3], 'test',
            definition('registry', PARENT[2]).definition_digest) for child in CHILDREN))
        self.scope = {**self.old_scope, 'compositeContext': self.enrollment.sha}
        self.policies = {**self.old_policies, **{key: 'DENY' for key in (PARENT, *CHILDREN)}}
        self.choices = {**self.old_choices, **{key: ALL for key in (PARENT, *CHILDREN)}}
        legacy = snapshot(self.old, legacy_schema_witness)
        with self.old._db() as db:
            db.execute('BEGIN IMMEDIATE')
            install_checked(db, expected=legacy)

    def make_editor(self, core):
        return OwnerPolicyEditor(core, self.owner, source_digest=fixture.SOURCE,
                                 credential_generation=lambda: fixture.CREDS)

    def candidate_core(self):
        adapter = GroupAdapter(binding=self.binding, ordinary=self.ordinary)
        core = CompositeUnifiedCore(self.path, adapters={'registry': adapter,
                    'synthetic': self.ordinary}, policies=self.policies,
                    authenticator=self.auth, owner_verifier=self.owner,
                    policy_version='successor')
        adapter.core = self.binding.core = core
        instance=str(uuid.uuid4())
        ctrl=maintenance_fixture.Controller(instance,'b'*64)
        hold_view={'instanceId':instance,'scopeDigest':'b'*64,'snapshotRevision':0,
                   'eventDigest':'a'*64,'holds':[]}
        core.bind_maintenance(MaintenanceGate(instance_id=instance,scope_digest='b'*64,
            generation=maintenance_fixture.OLD,read_interlock=ctrl.read,
            read_holds=lambda:hold_view))

        self.binding.admission = ContextAdmission(core, self.enrollment,
            guard=lambda *_: ProviderGuard(True, True, 'ALLOW', 'a'*64))
        return core

    def args(self, core, *, transition):
        return dict(history=self.history, enrollment=self.enrollment, choices=self.choices,
                    scope_binding=self.scope, expected_predecessor_digest=self.old.authority.sha,
                    expected_successor_digest=PolicyAdmission(core, self.choices,
                                                               scope_binding=self.scope).sha,
                    expected_companion_digest=digest(snapshot(core, inspect_companion)),
                    transition=transition)

    def install(self):
        self.core = self.candidate_core()
        self.core.install_reviewed(**self.args(self.core, transition=True))
        self.editor = self.make_editor(self.core)
        return self.core

    def request(self):
        return {'requestId': str(uuid.uuid4()), 'service': 'registry',
                'operation': PARENT[2], 'target': PARENT[3],
                'params': {'items': [begin(), begin('b')]},
                'expectedVersion': 0, 'reason': 'isolated successor'}

    def test_exact_epoch_migration_and_existing_editor(self):
        core = self.install()
        after = snapshot(core, lambda db: authority_witness(core, db))
        self.assertEqual(compare_authority_epoch(self.before, after,
                        expected_successor_digest=core.authority.sha), 'AUTHORITY_HISTORY_MATCH_ONLY')
        self.assertEqual(after['epochCount'], 2)
        self.assertEqual(core._policy(ACTOR, dict(service='synthetic', operation='set_free',
                                                  target='record')), 'DENY')
        with self.assertRaises(Denied):
            core.client('machine', 'submit', self.request())
        for child in CHILDREN:
            self.change(child, 'DENY', 'ASK')
        self.change(PARENT, 'DENY', 'ALLOW')
        self.assertEqual(core.client('machine', 'submit', self.request())['state'], 'EXECUTED')
        self.assertEqual(len(self.binding.effects), 2)
        self.change(CHILDREN[0], 'ASK', 'DENY')
        with self.assertRaises(Denied):
            core.client('machine', 'submit', self.request())
        self.assertEqual(len(self.binding.effects), 2)
        portal = UnifiedPolicyPortal(core, self.owner, editor=self.editor)
        self.assertIs(portal.editor, self.editor)
        row = next(r for r in self.editor.inventory()['operations']
                   if r['operation'] == PARENT[2])
        self.assertEqual(row['currentPolicy'], 'ALLOW')
        self.assertEqual(row['effectivePolicy'], 'UNKNOWN')
        self.assertEqual(set(row['editablePolicies']), ALL)

    def restore_history(self, core):
        record = self.history.seal()
        evidence = ReviewedHistoryEvidence(record, expected_digest=digest(record))
        current = PolicyAdmission(core, self.old_choices, scope_binding=self.old_scope,
                                  historical_baseline=self.old_policies)
        return snapshot(core, lambda db: evidence.restore(
            core, db, current=current, previous_scope=None, predecessor=None))

    def test_restart_replays_old_and_new_events_without_new_epoch(self):
        core = self.candidate_core()
        sealed = self.args(core, transition=True)
        core.install_reviewed(**sealed)
        self.core = core
        self.editor = self.make_editor(core)
        for child in CHILDREN:
            self.change(child, 'DENY', 'ASK')
        self.change(PARENT, 'DENY', 'ALLOW')
        result = core.client('machine', 'submit', self.request())
        before = snapshot(core, lambda db: authority_witness(core, db))
        reopened = self.candidate_core()
        restored = self.restore_history(reopened)
        self.assertEqual(restored.seal(), self.history.seal())
        # Docker restart retains the exact original profile, including its
        # first-transition permission and the original empty companion pin.
        reopened.install_reviewed(**{**sealed, 'history':restored, 'release_active':True})
        self.assertTrue(reopened.successor_ready)
        self.assertEqual(snapshot(reopened, lambda db: authority_witness(reopened, db)), before)
        self.assertEqual(reopened.execute(result['requestId'])['result'], result['result'])
        self.assertEqual(len(self.binding.effects), 2)

    def test_successor_inspector_pins_exact_companion_and_schema(self):
        from fortis_approvals.extensions.composite_preservation import sealed_companion

        core=self.install()
        witness=snapshot(core,inspect_companion)
        args={'expected_schema_digest':witness['schemaDigest'],
              'expected_companion_digest':digest(witness)}
        self.assertEqual(sealed_companion(core.path,**args),witness)
        for pin in args:
            with self.subTest(pin=pin),self.assertRaisesRegex(Denied,'PRESERVATION_PIN_CHANGED'):
                sealed_companion(core.path,**{**args,pin:'f'*64})

    def test_unready_and_generic_install_refused(self):
        core = self.candidate_core()
        with self.assertRaises(Denied):
            core.submit(ACTOR, self.request())
        with self.assertRaises(Denied):
            core.install_policy_authority(self.choices)
        with self.assertRaises(Denied):
            self.make_editor(core)

    def test_wrong_companion_pin_or_transition_mode_refused(self):
        core = self.candidate_core()
        args = self.args(core, transition=True)
        for changes in ({'expected_companion_digest': 'f'*64}, {'transition': False},
                        {'expected_predecessor_digest': 'f'*64},
                        {'expected_successor_digest': 'f'*64}):
            with self.subTest(changes=changes), self.assertRaises(Denied):
                core.install_reviewed(**{**args, **changes})
            self.assertFalse(core.successor_ready)

    def test_old_clone_history_drift_refused(self):
        core = self.candidate_core()
        args = self.args(core, transition=True)
        # Isolated fixture tampering, not a supported migration.
        with core._db() as db:
            db.execute("UPDATE owner_local_policy_v2_events SET owner='changed' WHERE revision=1")
        with self.assertRaises(Denied):
            core.install_reviewed(**args)
        self.assertFalse(core.successor_ready)

    def test_restart_rejects_mutation_of_old_event_even_if_replay_valid(self):
        core = self.install()
        self.change(CHILDREN[0], 'DENY', 'ASK')
        with core._db() as db:
            db.execute("UPDATE owner_local_policy_v2_events SET owner='changed' WHERE revision=1")
        reopened = self.candidate_core()
        with self.assertRaisesRegex(Denied, 'HISTORICAL_PREFIX_CHANGED'):
            self.restore_history(reopened)
        self.assertFalse(reopened.successor_ready)

    def test_same_profile_restart_after_installed_epoch(self):
        core = self.candidate_core()
        sealed = self.args(core, transition=True)
        core.install_reviewed(**sealed)
        before = snapshot(core, lambda db: authority_witness(core, db))
        reopened = self.candidate_core()
        reopened.install_reviewed(**sealed, release_active=True)
        self.assertTrue(reopened.successor_ready)
        self.assertEqual(snapshot(reopened, lambda db: authority_witness(reopened, db)), before)

    def test_activated_predecessor_refused_without_migration(self):
        core = self.candidate_core()
        sealed = self.args(core, transition=True)
        with self.assertRaisesRegex(Denied, 'MODE_MISMATCH'):
            core.install_reviewed(**sealed, release_active=True)
        self.assertFalse(core.successor_ready)

    def test_inactive_reopen_requires_original_companion_pin(self):
        core = self.candidate_core()
        sealed = self.args(core, transition=True)
        core.install_reviewed(**sealed)
        reopened = self.candidate_core()
        with self.assertRaisesRegex(Denied, 'COMPANION_PIN_CHANGED'):
            reopened.install_reviewed(**{**sealed, 'expected_companion_digest':'f'*64})
        self.assertFalse(reopened.successor_ready)
        reopened = self.candidate_core()
        reopened.install_reviewed(**sealed)
        self.assertTrue(reopened.successor_ready)

    def test_active_reopen_rejects_corrupt_companion_after_growth(self):
        core = self.candidate_core()
        sealed = self.args(core, transition=True)
        core.install_reviewed(**sealed)
        self.core = core
        self.editor = self.make_editor(core)
        for child in CHILDREN:
            self.change(child, 'DENY', 'ASK')
        self.change(PARENT, 'DENY', 'ALLOW')
        result = core.client('machine', 'submit', self.request())
        self.assertEqual(result['state'], 'EXECUTED')
        # A nonempty journal no longer matches the original snapshot, but
        # its internal receipts and parent coverage remain mandatory.
        with core._db() as db:
            db.execute("DELETE FROM composite_step_events WHERE parent_id=?",
                       (result['requestId'],))
        reopened = self.candidate_core()
        with self.assertRaises(Denied):
            reopened.install_reviewed(**sealed, release_active=True)
        self.assertFalse(reopened.successor_ready)
        self.assertEqual(len(self.binding.effects), 2)

    def test_unreviewed_historical_digest_refused(self):
        core = self.install()
        with core._db() as db:
            db.execute("UPDATE owner_local_policy_v2_authority_epochs SET old_authority=? WHERE id=1",
                       ('f'*64,))
        with self.assertRaises(Denied):
            core.policy_version
        reopened = self.candidate_core()
        with self.assertRaises(Denied):
            reopened.install_reviewed(**self.args(reopened, transition=False))
        self.assertFalse(reopened.successor_ready)


if __name__ == '__main__':
    unittest.main()

"""Actual opt-in executor with isolated synthetic child bindings; no live grants."""
from pathlib import Path
import tempfile
import threading
from concurrent.futures import ThreadPoolExecutor
import unittest
import uuid

from fortis_approvals.core import Authenticator, Core, Denied, Stale
from fortis_approvals.extensions.composite_executor import (
    Admission, CompositeCoreMixin, GroupAdapter,
)
from fortis_approvals.extensions import composite_journal as journal
from fortis_approvals.tests.test_core import SyntheticOwnerVerifier
from fortis_approvals.tests.test_registry_semantic_contract import begin, report


class Crash(BaseException):
    pass


class Binding:
    def __init__(self):
        self.standalone = 'ASK'
        self.contextual = True
        self.floor = 'ALLOW'
        self.generation = 'a'*64
        self.effects = []
        self.receipts = {}
        self.mode = 'ok'
        self.after_first = lambda: None
        self.core = None

    def admit(self, actor, target, step):
        if actor != 'agent-1' or target != 'test-scope' or step['params']['subject']['repository'] != 'Owner/repo':
            raise Denied('SYNTHETIC_SCOPE')
        return Admission(self.standalone, self.contextual, self.floor, self.generation)

    def dispatch(self, ctx):
        # Check marker committed and transaction released before effect.
        with self.core._db() as db:
            db.execute('BEGIN IMMEDIATE')
            self.assert_marker(db, ctx)
        self.effects.append(ctx.step_id)
        receipt = {'operationId': ctx.step_id, 'subject': ctx.params['subject']}
        self.receipts[ctx.step_id] = receipt
        if ctx.ordinal == 0:
            self.after_first()
        if self.mode == 'crash' and ctx.ordinal == 1:
            raise Crash()
        if self.mode == 'stale' and ctx.ordinal == 1:
            raise Stale('late stale after possible effect')
        if self.mode == 'forged' and ctx.ordinal == 1:
            return {**receipt, 'subject': {'wrong': True}}
        return receipt

    def assert_marker(self, db, ctx):
        if journal.inspect(db, ctx.parent_id)['steps'][ctx.ordinal]['state'] != 'DISPATCHED':
            raise RuntimeError('missing committed marker')

    def verify(self, ctx, receipt):
        return (receipt == self.receipts.get(ctx.step_id)
                and receipt['subject'] == ctx.params['subject'])

    def lookup(self, ctx):
        return self.receipts.get(ctx.step_id)


class TestCore(CompositeCoreMixin, Core):
    pass


class CompositeExecutorTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.path = Path(tmp.name)/'core.sqlite'
        self.binding = Binding()
        self.auth = Authenticator({'machine': 'agent-1', 'other': 'agent-2'})
        self.owner = SyntheticOwnerVerifier()
        self.now = 100
        self.policy = {('agent-1', 'registry', 'begin_release_group', 'test-scope'): 'ASK'}
        self.core = self.make_core()
        with self.core._db() as db:
            db.execute('BEGIN IMMEDIATE')
            journal.install_schema(db)

    def make_core(self):
        self.adapter = GroupAdapter(binding=self.binding)
        core = TestCore(self.path, adapters={'registry': self.adapter},
                        authenticator=self.auth, policies=self.policy,
                        owner_verifier=self.owner, clock=lambda: self.now)
        self.adapter.core = self.binding.core = core
        return core

    def payload(self):
        return {'requestId': str(uuid.uuid4()), 'service': 'registry',
                'operation': 'begin_release_group', 'target': 'test-scope',
                'params': {'items': [begin(), begin('b')]},
                'expectedVersion': 0, 'reason': 'isolated executor'}

    def submit(self):
        return self.core.client('machine', 'submit', self.payload())

    def approve(self, view):
        return self.core.owner_decide(view['requestId'], 'approve',
            self.owner.proof(view['requestId'], view['fingerprint'], 'approve'))

    def states(self, view):
        with self.core._db() as db:
            db.execute('BEGIN')
            return [s['state'] for s in journal.inspect(db, view['requestId'])['steps']]

    def test_exact_ask_and_one_parent(self):
        view = self.submit()
        self.assertEqual(view['state'], 'PENDING')
        self.assertEqual(self.binding.effects, [])
        result = self.approve(view)
        self.assertEqual(result['state'], 'EXECUTED')
        self.assertEqual(self.states(view), ['CONFIRMED', 'CONFIRMED'])
        self.assertEqual(len(result['result']['receipts']), 2)
        with self.core._db() as db:
            self.assertEqual(db.execute('SELECT COUNT(*) FROM requests').fetchone()[0], 1)
        self.core.execute(view['requestId'])
        self.assertEqual(len(self.binding.effects), 2)

    def test_explicit_allow_with_contextual_ordinary_ask(self):
        self.core.policies[next(iter(self.policy))] = 'ALLOW'
        self.assertEqual(self.submit()['state'], 'EXECUTED')
        self.assertEqual(self.binding.standalone, 'ASK')
        self.assertEqual(len(self.binding.effects), 2)

    def test_parent_deny_and_missing_child_authority(self):
        for attr, value in (('standalone', 'DENY'), ('contextual', False), ('floor', 'ASK'),
                            ('floor', 'DENY')):
            old = getattr(self.binding, attr)
            setattr(self.binding, attr, value)
            with self.subTest(attr=attr, value=value), self.assertRaises(Denied):
                self.submit()
            setattr(self.binding, attr, old)
        self.core.policies[next(iter(self.policy))] = 'DENY'
        with self.assertRaises(Denied):
            self.submit()
        self.assertFalse(self.binding.effects)

    def test_scope_and_direct_apply_denied(self):
        req = self.payload()
        req['params']['items'][1]['subject']['repository'] = 'Z/other'
        with self.assertRaises(Denied):
            self.core.client('machine', 'submit', req)
        with self.assertRaises(Denied):
            self.core.client('other', 'submit', self.payload())
        with self.assertRaises(Denied):
            self.adapter.apply(self.payload())
        self.assertFalse(self.binding.effects)

    def test_authority_drift_before_approval(self):
        view = self.submit()
        self.binding.generation = 'b'*64
        self.assertEqual(self.approve(view)['state'], 'STALE')
        self.assertFalse(self.binding.effects)

    def test_revocation_or_policy_or_expiry_between_children(self):
        for label in ('revoked', 'policy', 'expiry', 'generation'):
            with self.subTest(label=label):
                self.auth = Authenticator({'machine': 'agent-1'})
                self.now = 100
                self.binding.generation = 'a'*64
                self.core.policies[next(iter(self.policy))] = 'ASK'
                self.core.auth = self.auth
                view = self.submit()
                def change():
                    if label == 'revoked':
                        self.auth.revoke('machine')
                    elif label == 'policy':
                        self.core.policies[next(iter(self.policy))] = 'DENY'
                    elif label == 'expiry':
                        self.now = 5000
                    else:
                        self.binding.generation = 'b'*64
                self.binding.after_first = change
                count = len(self.binding.effects)
                self.assertEqual(self.approve(view)['state'], 'UNCERTAIN')
                self.assertEqual(self.states(view), ['CONFIRMED', 'BLOCKED'])
                self.assertEqual(len(self.binding.effects), count+1)

    def test_late_stale_never_loses_partial_evidence(self):
        self.binding.mode = 'stale'
        view = self.submit()
        self.assertEqual(self.approve(view)['state'], 'UNCERTAIN')
        self.assertEqual(self.states(view), ['CONFIRMED', 'UNKNOWN'])
        result = self.core.reconcile(view['requestId'])
        self.assertEqual(result['state'], 'EXECUTED')
        self.assertEqual(len(self.binding.effects), 2)

    def test_forged_receipt_not_confirmed(self):
        self.binding.mode = 'forged'
        view = self.submit()
        self.assertEqual(self.approve(view)['state'], 'UNCERTAIN')
        self.assertEqual(self.states(view), ['CONFIRMED', 'UNKNOWN'])

    def test_crash_recovery_lookup_only(self):
        self.binding.mode = 'crash'
        view = self.submit()
        with self.assertRaises(Crash):
            self.approve(view)
        self.assertEqual(self.states(view), ['CONFIRMED', 'DISPATCHED'])
        self.core = self.make_core()
        self.assertEqual(self.core.execute(view['requestId'])['state'], 'DISPATCHED')
        self.assertEqual(self.core.reconcile(view['requestId'])['state'], 'EXECUTED')
        self.assertEqual(len(self.binding.effects), 2)

    def test_ordinary_operation_delegates_without_composite_journal(self):
        from fortis_approvals.synthetic import SyntheticAdapter
        ordinary = SyntheticAdapter(self.path.parent/'ordinary.sqlite')
        ordinary.seed('record', 'before')
        self.adapter.ordinary = ordinary
        self.core.policies[('agent-1', 'registry', 'set_free', 'record')] = 'ALLOW'
        req = {'requestId': str(uuid.uuid4()), 'service': 'registry',
               'operation': 'set_free', 'target': 'record',
               'params': {'value': 'after'}, 'expectedVersion': 0,
               'reason': 'ordinary compatibility'}
        view = self.core.client('machine', 'submit', req)
        self.assertEqual(view['state'], 'EXECUTED')
        self.assertEqual(ordinary.get('record')['value'], 'after')
        with self.core._db() as db:
            self.assertEqual(db.execute('SELECT COUNT(*) FROM composite_instances').fetchone()[0], 0)

    def test_recovery_rejects_mismatched_original_receipt(self):
        self.binding.mode = 'crash'
        view = self.submit()
        with self.assertRaises(Crash):
            self.approve(view)
        self.binding.receipts[self.binding.effects[-1]] = {
            'operationId': self.binding.effects[-1], 'subject': {'wrong': True},
        }
        self.core = self.make_core()
        with self.assertRaises(Denied):
            self.core.reconcile(view['requestId'])
        self.assertEqual(self.core._read(view['requestId'])['state'], 'UNCERTAIN')
        self.assertEqual(self.states(view), ['CONFIRMED', 'UNKNOWN'])
        self.assertEqual(len(self.binding.effects), 2)

    def test_report_group_uses_same_executor(self):
        req = self.payload()
        req['operation'] = 'report_release_results'
        req['params'] = {'items': [report(), report('b')]}
        self.core.policies[('agent-1', 'registry', 'report_release_results', 'test-scope')] = 'ALLOW'
        view = self.core.client('machine', 'submit', req)
        self.assertEqual(view['state'], 'EXECUTED')
        self.assertEqual(self.states(view), ['CONFIRMED', 'CONFIRMED'])

    def test_recovery_cannot_race_active_executor(self):
        view = self.submit()
        started, release = threading.Event(), threading.Event()

        def pause():
            started.set()
            if not release.wait(5):
                raise RuntimeError('fixture timeout')

        self.binding.after_first = pause
        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(self.approve, view)
            try:
                self.assertTrue(started.wait(5))
                with self.assertRaisesRegex(Denied, 'EXECUTION_ACTIVE'):
                    self.core.reconcile(view['requestId'])
                self.assertEqual(self.core.execute(view['requestId'])['state'], 'DISPATCHED')
            finally:
                release.set()
            self.assertEqual(future.result(timeout=5)['state'], 'EXECUTED')
        self.assertEqual(len(self.binding.effects), 2)

    def test_crash_after_first_effect_does_not_continue_remaining(self):
        def crash():
            raise Crash()
        self.binding.after_first = crash
        view = self.submit()
        with self.assertRaises(Crash):
            self.approve(view)
        self.core = self.make_core()
        self.assertEqual(self.core.reconcile(view['requestId'])['state'], 'UNCERTAIN')
        self.assertEqual(self.states(view), ['CONFIRMED', 'PLANNED'])
        self.assertEqual(self.core.execute(view['requestId'])['state'], 'UNCERTAIN')
        self.assertEqual(len(self.binding.effects), 1)

    def test_policy_revision_drift_stops_remaining(self):
        view = self.submit()
        self.binding.after_first = lambda: setattr(self.core, 'policy_version', 'changed')
        self.assertEqual(self.approve(view)['state'], 'UNCERTAIN')
        self.assertEqual(self.states(view), ['CONFIRMED', 'BLOCKED'])
        self.assertEqual(len(self.binding.effects), 1)

    def test_revoked_scope_refuses_original_lookup(self):
        self.binding.mode = 'crash'
        view = self.submit()
        with self.assertRaises(Crash):
            self.approve(view)
        self.auth.revoke('machine')
        self.core = self.make_core()
        with self.assertRaises(Denied):
            self.core.reconcile(view['requestId'])
        self.assertEqual(self.core._read(view['requestId'])['state'], 'UNCERTAIN')
        self.assertEqual(self.states(view), ['CONFIRMED', 'UNKNOWN'])
        self.assertEqual(len(self.binding.effects), 2)

    def test_missing_original_receipt_stays_uncertain(self):
        self.binding.mode = 'crash'
        view = self.submit()
        with self.assertRaises(Crash):
            self.approve(view)
        del self.binding.receipts[self.binding.effects[-1]]
        self.core = self.make_core()
        self.assertEqual(self.core.reconcile(view['requestId'])['state'], 'UNCERTAIN')
        self.assertEqual(self.states(view), ['CONFIRMED', 'UNKNOWN'])
        self.assertEqual(len(self.binding.effects), 2)


if __name__ == '__main__':
    unittest.main()

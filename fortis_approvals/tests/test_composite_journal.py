"""Isolated journal tests with real Core parent lifecycle and synthetic adapter.

The adapter below is test plumbing only, not a provider executor or grant.
"""
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import tempfile
import threading
import unittest
import uuid

from fortis_approvals.core import Authenticator, Core, Denied
from fortis_approvals.extensions import composite_journal as journal
from fortis_approvals.extensions.composite_contract import expand_group
from fortis_approvals.tests.test_core import SyntheticOwnerVerifier
from fortis_approvals.tests.test_registry_semantic_contract import begin


class SimulatedCrash(BaseException):
    pass


class FixtureCore(Core):
    def _event(self, db, request_id, state, detail=None):
        super()._event(db, request_id, state, detail)
        # Bind in the same Core transaction as the first request event.
        # This hook is test-only; production integration is W2.2.
        if state in ('PENDING', 'APPROVED'):
            journal.bind_parent(db, request_id)


class FixtureAdapter:
    def __init__(self):
        self.mode = 'crash'
        self.effects = []
        self.core = None

    def prepare(self, payload):
        return {'composite': expand_group(payload['service'], payload['operation'],
                                          payload['requestId'], payload['params']),
                'authorityDigest': 'a'*64}

    def apply(self, payload):
        if self.mode == 'crash':
            raise SimulatedCrash()
        plan = self.prepare(payload)['composite']
        for step in plan['steps']:
            self.write(plan['parentId'], step, 'DISPATCHED')
            self.effects.append(step['stepId'])
            if self.mode == 'partial' and step['ordinal'] == 1:
                self.write(plan['parentId'], step, 'UNKNOWN')
                raise RuntimeError('test lost acknowledgment')
            self.write(plan['parentId'], step, 'CONFIRMED', self.receipt_detail(step))
        return {'stepIds': list(self.effects)}

    @staticmethod
    def receipt_detail(step):
        return {'operationId': step['stepId'], 'receiptDigest': 'b'*64}

    def write(self, parent_id, step, state, detail=None):
        with self.core._db() as db:
            db.execute('BEGIN IMMEDIATE')
            return journal.append_step(db, parent_id, ordinal=step['ordinal'],
                                       step_id=step['stepId'], state=state,
                                       detail={} if detail is None else detail)

    def confirm(self, ident, result):
        with self.core._db() as db:
            db.execute('BEGIN')
            return journal.inspect(db, ident)['allConfirmed']

    def receipt(self, ident):
        return None


class CompositeJournalTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.path = Path(tmp.name) / 'core.sqlite'
        self.adapter = FixtureAdapter()
        self.owner = SyntheticOwnerVerifier()
        self.auth = Authenticator({'machine': 'agent-1'})
        self.policy = {('registry', 'begin_release_group'): 'ASK'}
        self.core = self.make_core()
        with self.core._db() as db:
            db.execute('BEGIN IMMEDIATE')
            journal.install_schema(db)

    def make_core(self):
        core = FixtureCore(self.path, adapters={'registry': self.adapter},
                           policies=self.policy, authenticator=self.auth,
                           owner_verifier=self.owner)
        self.adapter.core = core
        return core

    def payload(self):
        return {'requestId': str(uuid.uuid4()), 'service': 'registry',
                'operation': 'begin_release_group', 'target': 'test-scope',
                'params': {'items': [begin(), begin('b')]},
                'expectedVersion': 0, 'reason': 'isolated test'}

    def submit(self):
        return self.core.client('machine', 'submit', self.payload())

    def approve(self, view, decision='approve'):
        proof = self.owner.proof(view['requestId'], view['fingerprint'], decision)
        return self.core.owner_decide(view['requestId'], decision, proof)

    def snapshot(self, ident):
        with self.core._db() as db:
            db.execute('BEGIN')
            return journal.inspect(db, ident)

    def crash_parent(self):
        view = self.submit()
        with self.assertRaises(SimulatedCrash):
            self.approve(view)
        return view['requestId'], view['preview']['composite']['steps']

    def test_explicit_schema_no_startup_or_old_history_changes(self):
        with self.core._db() as db:
            db.execute('BEGIN IMMEDIATE')
            with self.assertRaises(Denied):
                journal.install_schema(db)
            journal.check_schema(db)
        self.core = self.make_core()
        with self.core._db() as db:
            journal.check_schema(db)
            self.assertEqual(db.execute('SELECT COUNT(*) FROM requests').fetchone()[0], 0)
        # Old plain Core still does not create companion tables on startup.
        other = Core(self.path.parent/'legacy.sqlite', adapters={}, policies={}, authenticator=self.auth)
        with other._db() as db:
            self.assertEqual(journal._schema_rows(db), [])
            with self.assertRaises(Denied):
                journal.check_schema(db)

    def test_schema_addition_preserves_existing_core_rows_and_schema(self):
        from fortis_approvals.synthetic import SyntheticAdapter
        adapter = SyntheticAdapter(self.path.parent/'old-effects.sqlite')
        adapter.seed('record', 'before')
        old = Core(self.path.parent/'old-core.sqlite', adapters={'synthetic': adapter},
                   policies={('synthetic', 'set_free'): 'ALLOW'},
                   authenticator=self.auth)
        req = {'requestId': str(uuid.uuid4()), 'service': 'synthetic',
               'operation': 'set_free', 'target': 'record',
               'params': {'value': 'after'}, 'expectedVersion': 0,
               'reason': 'preserve old receipt'}
        self.assertEqual(old.submit('agent-1', req)['state'], 'EXECUTED')

        def original(db):
            return [
                [tuple(r) for r in db.execute('SELECT rowid,* FROM requests ORDER BY rowid')],
                [tuple(r) for r in db.execute('SELECT rowid,* FROM events ORDER BY rowid')],
                [tuple(r) for r in db.execute(
                    "SELECT type,name,tbl_name,sql FROM sqlite_master "
                    "WHERE tbl_name IN ('requests','events') ORDER BY type,name")],
                [tuple(r) for r in db.execute(
                    "SELECT * FROM sqlite_sequence WHERE name='events'")],
            ]
        with old._db() as db:
            db.execute('BEGIN IMMEDIATE')
            before = original(db)
            journal.install_schema(db)
            self.assertEqual(original(db), before)
        with old._db() as db:
            journal.check_schema(db)
            self.assertEqual(original(db), before)

    def test_blocked_step_prevents_later_effects(self):
        ident, (first, second) = self.crash_parent()
        self.adapter.write(ident, first, 'BLOCKED')
        for step in (first, second):
            with self.assertRaises(Denied):
                self.adapter.write(ident, step, 'DISPATCHED')
        self.assertEqual([s['state'] for s in self.snapshot(ident)['steps']],
                         ['BLOCKED', 'PLANNED'])

    def test_schema_change_fails_closed(self):
        with self.core._db() as db:
            db.execute('CREATE INDEX composite_extra ON composite_step_events(step_id)')
            with self.assertRaisesRegex(Denied, 'SCHEMA_MISMATCH'):
                journal.check_schema(db)

    def test_stale_after_partial_is_not_consistent(self):
        ident, (first, _) = self.crash_parent()
        self.adapter.write(ident, first, 'DISPATCHED')
        self.adapter.write(ident, first, 'CONFIRMED', self.adapter.receipt_detail(first))
        with self.core._db() as db:
            db.execute("UPDATE requests SET state='STALE' WHERE id=?", (ident,))
        with self.assertRaisesRegex(Denied, 'PARENT_STATE_CONFLICT'):
            self.snapshot(ident)

    def test_pending_and_rejected_have_no_dispatched_child(self):
        view = self.submit()
        ident = view['requestId']
        step = view['preview']['composite']['steps'][0]
        self.assertEqual(self.snapshot(ident)['steps'][0]['state'], 'PLANNED')
        with self.assertRaises(Denied):
            self.adapter.write(ident, step, 'DISPATCHED')
        self.assertEqual(self.approve(view, 'reject')['state'], 'REJECTED')
        self.assertFalse(self.adapter.effects)
        with self.assertRaises(Denied):
            self.adapter.write(ident, step, 'DISPATCHED')

    def test_ask_success_one_parent_and_exact_receipts(self):
        self.adapter.mode = 'success'
        view = self.submit()
        result = self.approve(view)
        self.assertEqual(result['state'], 'EXECUTED')
        self.assertTrue(self.snapshot(view['requestId'])['allConfirmed'])
        self.assertEqual(len(self.adapter.effects), 2)
        with self.core._db() as db:
            self.assertEqual(db.execute('SELECT COUNT(*) FROM requests').fetchone()[0], 1)
            self.assertEqual(db.execute('SELECT COUNT(*) FROM composite_step_events').fetchone()[0], 4)
        self.core.execute(view['requestId'])
        self.assertEqual(len(self.adapter.effects), 2)

    def test_allow_and_deny_use_existing_core(self):
        self.adapter.mode = 'success'
        self.core.policies[('registry', 'begin_release_group')] = 'ALLOW'
        self.assertEqual(self.submit()['state'], 'EXECUTED')
        self.core.policies[('registry', 'begin_release_group')] = 'DENY'
        with self.assertRaises(Denied):
            self.submit()
        with self.core._db() as db:
            self.assertEqual(db.execute('SELECT COUNT(*) FROM composite_instances').fetchone()[0], 1)

    def test_partial_unknown_readback_cannot_resume(self):
        self.adapter.mode = 'partial'
        view = self.submit()
        self.assertEqual(self.approve(view)['state'], 'UNCERTAIN')
        ident = view['requestId']
        steps = view['preview']['composite']['steps']
        self.assertEqual([s['state'] for s in self.snapshot(ident)['steps']],
                         ['CONFIRMED', 'UNKNOWN'])
        self.core = self.make_core()
        with self.assertRaises(Denied):
            self.adapter.write(ident, steps[1], 'DISPATCHED')
        self.adapter.write(ident, steps[1], 'CONFIRMED', self.adapter.receipt_detail(steps[1]))
        self.assertTrue(self.snapshot(ident)['interrupted'])
        self.assertTrue(self.snapshot(ident)['allConfirmed'])
        self.assertEqual(self.core.execute(ident)['state'], 'UNCERTAIN')
        self.assertEqual(len(self.adapter.effects), 2)

    def test_dispatch_order_duplicate_and_receipt_binding(self):
        ident, steps = self.crash_parent()
        first, second = steps
        with self.assertRaises(Denied):
            self.adapter.write(ident, second, 'DISPATCHED')
        self.adapter.write(ident, first, 'DISPATCHED')
        with self.assertRaises(Denied):
            self.adapter.write(ident, first, 'DISPATCHED')
        with self.assertRaises(Denied):
            self.adapter.write(ident, first, 'CONFIRMED', self.adapter.receipt_detail(second))
        self.adapter.write(ident, first, 'CONFIRMED', self.adapter.receipt_detail(first))
        with self.assertRaises(Denied):
            self.adapter.write(ident, first, 'CONFIRMED', self.adapter.receipt_detail(first))
        self.adapter.write(ident, second, 'DISPATCHED')
        self.assertEqual(self.snapshot(ident)['steps'][1]['state'], 'DISPATCHED')

    def test_unknown_first_fences_remaining_even_after_confirmation(self):
        ident, (first, second) = self.crash_parent()
        self.adapter.write(ident, first, 'DISPATCHED')
        self.adapter.write(ident, first, 'UNKNOWN')
        self.adapter.write(ident, first, 'CONFIRMED', self.adapter.receipt_detail(first))
        with self.assertRaises(Denied):
            self.adapter.write(ident, second, 'DISPATCHED')
        self.assertEqual(self.snapshot(ident)['steps'][1]['state'], 'PLANNED')

    def test_failed_transaction_leaves_no_dispatch_marker(self):
        ident, (first, _) = self.crash_parent()
        with self.assertRaises(RuntimeError):
            with self.core._db() as db:
                db.execute('BEGIN IMMEDIATE')
                journal.append_step(db, ident, ordinal=0, step_id=first['stepId'],
                                    state='DISPATCHED', detail={})
                raise RuntimeError('rollback transaction before any effect')
        self.assertEqual(self.snapshot(ident)['steps'][0]['state'], 'PLANNED')

    def test_committed_dispatch_survives_restart_no_repeat(self):
        ident, (first, _) = self.crash_parent()
        self.adapter.write(ident, first, 'DISPATCHED')
        self.core = self.make_core()
        self.assertEqual(self.core.execute(ident)['state'], 'DISPATCHED')
        with self.assertRaises(Denied):
            self.adapter.write(ident, first, 'DISPATCHED')
        self.assertFalse(self.adapter.effects)

    def test_concurrent_dispatch_one_marker(self):
        ident, (first, _) = self.crash_parent()
        barrier = threading.Barrier(2)
        def run():
            barrier.wait(timeout=5)
            try:
                self.adapter.write(ident, first, 'DISPATCHED')
                return 'recorded'
            except Denied:
                return 'denied'
        with ThreadPoolExecutor(max_workers=2) as pool:
            outcomes = list(pool.map(lambda _: run(), range(2)))
        self.assertCountEqual(outcomes, ['recorded', 'denied'])

    def test_corruption_and_inconsistent_terminal_state_fail_closed(self):
        ident, (first, _) = self.crash_parent()
        self.adapter.write(ident, first, 'DISPATCHED')
        # Deliberate isolated fixture corruption, never a migration path.
        with self.core._db() as db:
            db.execute("UPDATE composite_step_events SET detail='{}',event_digest=?",
                       ('c'*64,))
        with self.assertRaises(Denied):
            self.snapshot(ident)

    def test_incomplete_parent_success_rejected(self):
        ident, _ = self.crash_parent()
        with self.core._db() as db:
            db.execute("UPDATE requests SET state='EXECUTED' WHERE id=?", (ident,))
        with self.assertRaisesRegex(Denied, 'PARENT_RESULT_INCOMPLETE'):
            self.snapshot(ident)


if __name__ == '__main__':
    unittest.main()

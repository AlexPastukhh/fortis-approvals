"""Isolated v4 additive migration and local release journal mechanics."""
import copy
import sqlite3
import unittest
from concurrent.futures import ThreadPoolExecutor

from fortis_approvals.core import Conflict, Denied, Stale
from fortis_approvals.registry.release_event_journal import ReleaseEventJournal
from fortis_approvals.registry.transition_preservation import legacy_prefix_witness
from fortis_approvals.tests import test_registry_transition_contract as fixture
from fortis_approvals.registry.boundary import PLANNER
from unittest.mock import patch
from fortis_approvals.tests.test_registry_state_journal import uid
from fortis_approvals.tests.test_registry_semantic_contract import begin, report


class ReleaseJournalTests(unittest.TestCase):
    setUp = fixture.LegacyPrefixTests.setUp
    append = fixture.LegacyPrefixTests.append
    clone = fixture.LegacyPrefixTests.clone

    def migrate(self):
        self.witness = legacy_prefix_witness(self.state)
        self.copy = self.clone()
        self.store = ReleaseEventJournal.migrate_clone(
            self.copy, expected_legacy=self.witness, transition_digest='e'*64)
        return self.store

    def reopen(self):
        return ReleaseEventJournal(self.copy.path, instance_id=self.instance,
            scope=self.scope, expected_legacy=self.witness, transition_digest='e'*64)

    def event(self, target='a', revision=0, kind='OWNER_RESULT_RECORDED'):
        params = begin(target) if kind == 'RELEASE_ATTEMPT_STARTED' else report(target)
        params['subject']['repository'] = self.scope['repository']
        params['expected']['targetRevision'] = revision
        return {'operationId': uid(), 'kind': kind, 'actor': 'agent-1',
                'assertionSource': 'OWNER_TRANSCRIBED', 'parentRequestId': None,
                'params': params}

    def test_nonempty_migration_preserves_exact_receipt_and_source_cursor(self):
        old = self.append()['receipt']
        store = self.migrate()
        with self.assertRaises(Denied):
            self.copy.checkpoint()
        self.assertEqual(store.operation(actor=PLANNER,
                         operation_id=old['operationId'])['receipt'], old)
        self.assertEqual(store.release_checkpoint()['legacy'], self.witness)
        self.assertEqual(legacy_prefix_witness(self.state), self.witness)
        with self.assertRaises(Denied):
            store.append_range()

    def test_genesis_and_separate_target_cas_and_idempotency(self):
        store = self.migrate()
        first = self.event()
        r = store.append_event(first, recorded_at=100)
        self.assertEqual(r['targetRevision'], 1)
        self.assertFalse(r['technicalInstallationVerified'])
        second = store.append_event(self.event('b'), recorded_at=101)
        self.assertEqual(second['targetRevision'], 1)
        self.assertEqual(second['snapshotRevision'], 2)
        with self.assertRaises(Stale):
            store.append_event(self.event(), recorded_at=102)
        third = store.append_event(self.event(revision=1), recorded_at=103)
        self.assertEqual(third['targetRevision'], 2)
        reopened = self.reopen()
        self.assertEqual(reopened.append_event(first, recorded_at=999), r)
        self.assertEqual(reopened.release_operation(first['operationId']), r)
        changed = copy.deepcopy(first)
        changed['actor'] = 'another'
        with self.assertRaises(Conflict):
            reopened.append_event(changed, recorded_at=104)
        self.assertEqual(reopened.release_checkpoint()['legacy'], self.witness)
        self.assertTrue(reopened.release_checkpoint()['sourceTransitionPending'])

    def test_scope_and_verified_claim_denied(self):
        store = self.migrate()
        e = self.event()
        e['params']['subject']['repository'] = 'Other/repo'
        with self.assertRaises(Denied):
            store.append_event(e, recorded_at=1)
        e = self.event()
        e['kind'] = 'TECHNICAL_OBSERVATION_ACCEPTED'
        with self.assertRaises(Denied):
            store.append_event(e, recorded_at=1)
        self.assertEqual(store.release_checkpoint()['snapshotRevision'], 0)

    def test_concurrent_target_cas_one_winner(self):
        store = self.migrate()
        events = [self.event(), self.event()]
        def attempt(event):
            try:
                return store.append_event(event, recorded_at=1)['targetRevision']
            except Stale:
                return 'stale'
        with ThreadPoolExecutor(max_workers=2) as pool:
            self.assertCountEqual(list(pool.map(attempt, events)), [1, 'stale'])

    def test_attempt_event_does_not_claim_installation(self):
        store = self.migrate()
        r = store.append_event(self.event(kind='RELEASE_ATTEMPT_STARTED'), recorded_at=1)
        self.assertEqual(r['eventKind'], 'RELEASE_ATTEMPT_STARTED')
        self.assertFalse(r['technicalInstallationVerified'])

    def test_tamper_detected_and_original_untouched(self):
        store = self.migrate()
        store.append_event(self.event(), recorded_at=1)
        with sqlite3.connect(store.path) as db:
            db.execute("UPDATE release_events SET receipt='{}'")
        with self.assertRaises(Denied):
            self.reopen().release_checkpoint()
        self.assertEqual(legacy_prefix_witness(self.state), self.witness)

    def test_lost_readback_after_commit_recovers_original(self):
        store = self.migrate()
        event = self.event()
        with patch.object(store, 'release_operation', side_effect=Denied('test readback lost')):
            self.assertEqual(store.append_event(event, recorded_at=1),
                             {'result': 'UNKNOWN_OUTCOME', 'operationId': event['operationId']})
        receipt = self.reopen().release_operation(event['operationId'])
        self.assertEqual(receipt['targetRevision'], 1)
        self.assertEqual(receipt['recordedAt'], 1)
        self.assertEqual(store.release_checkpoint()['snapshotRevision'], 1)

    def test_legacy_operation_uuid_cannot_be_reused(self):
        old = self.append()['receipt']
        store = self.migrate()
        event = self.event()
        event['operationId'] = old['operationId']
        with self.assertRaises(Denied):
            store.append_event(event, recorded_at=1)

    def test_capacity_stops_new_events_not_original_receipts(self):
        store = self.migrate()
        event = self.event()
        with patch('fortis_approvals.registry.release_event_journal._MAX_EVENTS', 1):
            receipt = store.append_event(event, recorded_at=1)
            with self.assertRaises(Denied):
                store.append_event(self.event('b'), recorded_at=2)
            self.assertEqual(store.append_event(event, recorded_at=3), receipt)
            self.assertEqual(store.release_checkpoint()['remainingEvents'], 0)

    def test_unknown_schema_or_invalid_json_rejected(self):
        store = self.migrate()
        store.append_event(self.event(), recorded_at=1)
        with sqlite3.connect(store.path) as db:
            db.execute("UPDATE release_events SET request='not json'")
        with self.assertRaises(Denied):
            store.release_checkpoint()

    def test_wrong_migration_witness_and_wrong_restart_pin(self):
        self.witness = legacy_prefix_witness(self.state)
        self.copy = self.clone()
        with self.assertRaises(Denied):
            ReleaseEventJournal.migrate_clone(self.copy,
                expected_legacy={**self.witness, 'prefixDigest': 'f'*64},
                transition_digest='e'*64)
        self.assertEqual(legacy_prefix_witness(self.copy), self.witness)
        ReleaseEventJournal.migrate_clone(self.copy, expected_legacy=self.witness,
                                          transition_digest='e'*64)
        wrong = ReleaseEventJournal(self.copy.path, instance_id=self.instance, scope=self.scope,
                     expected_legacy=self.witness, transition_digest='f'*64)
        with self.assertRaises(Denied):
            wrong.release_checkpoint()


if __name__ == '__main__':
    unittest.main()

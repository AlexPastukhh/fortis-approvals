"""Exercise the existing actual authority upgrade on synthetic Core copies."""
import copy
import sqlite3
import unittest
import uuid

from fortis_approvals.core import Denied
from fortis_approvals.extensions.owner_policy_engine_v2 import UnifiedPolicyCore
from fortis_approvals.extensions.transition_authority import (
    authority_witness, compare_authority_epoch,
)
from fortis_approvals.tests import test_owner_policy_engine_v2 as fixture


class TransitionAuthorityTests(unittest.TestCase):
    setUp = fixture.UnifiedPolicyTests.setUp
    kwargs = fixture.UnifiedPolicyTests.kwargs
    make_core = fixture.UnifiedPolicyTests.make_core
    candidate = fixture.UnifiedPolicyTests.candidate
    begin = fixture.UnifiedPolicyTests.begin
    finish = fixture.UnifiedPolicyTests.finish
    change = fixture.UnifiedPolicyTests.change

    def snapshot(self, core):
        db = sqlite3.connect(core.path.absolute().as_uri()+'?mode=ro', uri=True)
        try:
            db.row_factory = sqlite3.Row
            db.execute('PRAGMA query_only=ON')
            db.execute('BEGIN')
            return authority_witness(core, db)
        finally:
            db.close()

    def upgrade(self):
        # This is an existing supported reviewed choice transition, NOT
        # admission of a new Registry coordinate or a real owner approval.
        request = self.core.submit(fixture.ACTOR, {
            'requestId': str(uuid.uuid4()), 'service': 'synthetic',
            'operation': 'set_free', 'target': 'record',
            'params': {'value': 'preserve receipt'}, 'expectedVersion': 0,
            'reason': 'isolated transition history test',
        })
        self.assertEqual(request['state'], 'EXECUTED')
        self.change(fixture.EXACT, 'ASK', 'DENY')
        before = self.snapshot(self.core)
        choices = {**self.choices, fixture.FREE: {'DENY', 'ALLOW', 'ASK'}}
        after_core = UnifiedPolicyCore(self.core.path, **self.kwargs())
        after_core.install_policy_authority(choices, reviewed_upgrade_from=self.choices)
        after = self.snapshot(after_core)
        return before, after, after_core

    def test_existing_epoch_upgrade_preserves_exact_history(self):
        before, after, migrated = self.upgrade()
        self.assertEqual(compare_authority_epoch(
            before, after, expected_successor_digest=migrated.authority.sha),
            'AUTHORITY_HISTORY_MATCH_ONLY')
        self.assertEqual(migrated._policy(fixture.ACTOR, {
            'service': 'synthetic', 'operation': 'set_ask', 'target': 'record',
        }), 'DENY')
        self.assertEqual(before['policy']['revision'], 1)

    def test_unreviewed_or_mutated_witness_rejected(self):
        before, after, migrated = self.upgrade()
        for key in ('coreHistoryDigest', 'unchangedPolicyDigest', 'previousEpochDigest'):
            changed = copy.deepcopy(after)
            changed[key] = 'a'*64
            with self.subTest(key=key), self.assertRaises(Denied):
                compare_authority_epoch(before, changed,
                                        expected_successor_digest=migrated.authority.sha)
        with self.assertRaises(Denied):
            compare_authority_epoch(before, after, expected_successor_digest='f'*64)

    def test_write_connection_not_accepted(self):
        with self.core._db() as db:
            db.execute('BEGIN')
            with self.assertRaises(Denied):
                authority_witness(self.core, db)


if __name__ == '__main__':
    unittest.main()

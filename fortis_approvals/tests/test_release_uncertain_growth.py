"""Pure append-only UNCERTAIN drift admission; still byte-preserved on clone."""
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest

from test_orphaned_worker_claim_release import OrphanedClaimStateTests, H, IDENT, ACTOR, REQUEST

NEW='77777777-7777-4777-8777-777777777777'
NEW2='88888888-8888-4888-8888-888888888888'


class UncertainGrowthWitnessTests(unittest.TestCase):
    def setUp(self):
        self.fixture=OrphanedClaimStateTests('test_explicit_claimed_id_preserves_all_bytes_and_unknown_state')
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.source=self.fixture.source
        self.target=self.fixture.target
        self.core=self.source/'private'/'approvals.sqlite'
        with sqlite3.connect(self.core) as db:
            db.execute('DROP TABLE events')
            db.execute('DROP TABLE requests')
            db.executescript("""
                CREATE TABLE requests(
                    id TEXT PRIMARY KEY, fingerprint TEXT NOT NULL,
                    actor TEXT NOT NULL, payload TEXT NOT NULL,
                    snapshot TEXT NOT NULL, state TEXT NOT NULL,
                    policy_version TEXT NOT NULL, created_at INTEGER NOT NULL,
                    expires_at INTEGER NOT NULL, decision TEXT, owner TEXT,
                    result TEXT, failure TEXT);
                CREATE TABLE events(seq INTEGER PRIMARY KEY AUTOINCREMENT,
                    request_id TEXT NOT NULL, at INTEGER NOT NULL,
                    state TEXT NOT NULL, detail TEXT NOT NULL);
            """)
            db.execute("""INSERT INTO requests VALUES
              (?,?,?,?,?,?,?,?,?,?,?,?,?)""",(
                IDENT,'0'*64,ACTOR,json.dumps(REQUEST),'{}','UNCERTAIN',
                'v1',42,3600,'approve','owner',None,'effect-unknown'))
            for state in ('APPROVED','DISPATCHED','UNCERTAIN'):
                db.execute('INSERT INTO events(request_id,at,state,detail) VALUES(?,?,?,?)',
                           (IDENT,43,state,'{}'))
        self.params=dict(github=True,native=True,uid=os.geteuid(),gid=os.getegid(),
                         preserve_claimed_ids=[IDENT],preserve_approved_ids=[],
                         require_exact_claimed=True,require_exact_approved=True)

    def snapshot(self):
        return H.uncertain_growth_snapshot(self.source,**self.params)

    def review(self,snapshot):
        return H.review_uncertain_growth(
            self.source,original=snapshot['receipt'],
            witness=snapshot['witness'],**self.params)

    def append_uncertain(self,id=NEW):
        with sqlite3.connect(self.core) as db:
            db.execute('INSERT INTO requests VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)',
                       (id,'b'*64,ACTOR,json.dumps(REQUEST),'{}','UNCERTAIN',
                        'v1',44,3600,'approve','owner',None,'effect-unknown'))
            for state in ('APPROVED','DISPATCHED','UNCERTAIN'):
                db.execute('INSERT INTO events(request_id,at,state,detail) VALUES(?,?,?,?)',
                           (id,44,state,'{}'))

    def test_stable_snapshot_and_growth_preserve_every_byte(self):
        baseline=self.snapshot()
        self.assertEqual(baseline['uncertainIds'],[IDENT])
        self.assertEqual(self.review(baseline)['addedCount'],0)
        self.append_uncertain()
        grown=self.review(baseline)
        self.assertEqual(grown['addedCount'],1)
        self.assertEqual(grown['uncertainIds'],sorted((IDENT,NEW)))
        with self.assertRaisesRegex(RuntimeError,'UNREVIEWED_UNCERTAIN'):
            H.inspect_state(self.source,uid=os.geteuid(),gid=os.getegid(),github=True,native=True,
                            preserve_uncertain_ids=[IDENT],preserve_claimed_ids=[IDENT])
        before=self.core.read_bytes()
        copied=H.clone_state(self.source,self.target,uid=os.geteuid(),gid=os.getegid(),github=True,native=True,
            preserve_uncertain_ids=grown['uncertainIds'],
            preserve_claimed_ids=[IDENT],require_exact_approved=True)
        self.assertEqual(copied,grown['receipt'])
        self.assertEqual(self.core.read_bytes(),before)
        self.assertEqual((self.target/'private'/'approvals.sqlite').read_bytes(),before)

    def test_unmodified_existing_core_rows_are_required(self):
        baseline=self.snapshot()
        self.append_uncertain()
        with sqlite3.connect(self.core) as db:
            db.execute("UPDATE requests SET failure='tampered' WHERE id=?",(IDENT,))
        with self.assertRaisesRegex(RuntimeError,'CORE_PREFIX_CHANGED'):
            self.review(baseline)

    def test_unmodified_existing_audit_is_required(self):
        baseline=self.snapshot()
        self.append_uncertain()
        with sqlite3.connect(self.core) as db:
            db.execute("UPDATE events SET detail='tampered' WHERE request_id=?",(IDENT,))
        with self.assertRaisesRegex(RuntimeError,'CORE_PREFIX_CHANGED'):
            self.review(baseline)

    def test_new_row_must_be_uncertain_with_matching_audit(self):
        baseline=self.snapshot()
        self.append_uncertain()
        with sqlite3.connect(self.core) as db:
            db.execute("UPDATE requests SET state='EXECUTED' WHERE id=?",(NEW,))
        with self.assertRaisesRegex(RuntimeError,'NEW_REQUEST_NOT_UNCERTAIN|OTHER_STATE_CHANGED'):
            self.review(baseline)

    def test_new_audit_may_only_belong_to_new_unknown(self):
        baseline=self.snapshot()
        self.append_uncertain()
        with sqlite3.connect(self.core) as db:
            db.execute('INSERT INTO events(request_id,at,state,detail) VALUES(?,?,?,?)',
                       (IDENT,46,'DISPATCHED','{}'))
        with self.assertRaisesRegex(RuntimeError,'NEW_AUDIT_INVALID'):
            self.review(baseline)

    def test_changed_provider_receipts_denied(self):
        baseline=self.snapshot()
        self.append_uncertain()
        with sqlite3.connect(self.source/'private'/'github-receipts.sqlite') as db:
            db.execute('INSERT INTO receipts VALUES(?,?)',('new','unexpected'))
        with self.assertRaisesRegex(RuntimeError,'OTHER_STATE_CHANGED'):
            self.review(baseline)

    def test_new_approved_and_pending_denied(self):
        baseline=self.snapshot()
        self.append_uncertain()
        with sqlite3.connect(self.core) as db:
            db.execute('INSERT INTO requests VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)',
                       (NEW2,'b'*64,ACTOR,json.dumps(REQUEST),'{}','APPROVED',
                        'v1',47,3600,'approve','owner',None,None))
        with self.assertRaisesRegex(RuntimeError,'NEW_REQUEST_NOT_UNCERTAIN|PRESERVATION_SCOPE_EMPTY'):
            self.review(baseline)

    def test_schema_witness_and_approval_are_bound(self):
        baseline=self.snapshot()
        self.append_uncertain()
        baseline['witness']['prefixSha256']='0'*64
        with self.assertRaisesRegex(RuntimeError,'CORE_PREFIX_CHANGED'):
            self.review(baseline)

    def test_new_trigger_or_index_is_not_part_of_allowed_growth(self):
        baseline=self.snapshot()
        self.append_uncertain()
        with sqlite3.connect(self.core) as db:
            db.execute('CREATE INDEX malicious_extra ON requests(state)')
        with self.assertRaisesRegex(RuntimeError,'CORE_SCHEMA_CHANGED'):
            self.review(baseline)

    def test_new_uncertain_without_matching_audit_is_not_admitted(self):
        baseline=self.snapshot()
        with sqlite3.connect(self.core) as db:
            db.execute('INSERT INTO requests VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)',
                       (NEW,'b'*64,ACTOR,json.dumps(REQUEST),'{}','UNCERTAIN',
                        'v1',47,3600,'approve','owner',None,'effect-unknown'))
        with self.assertRaisesRegex(RuntimeError,'NEW_AUDIT_INVALID'):
            self.review(baseline)

    def test_new_worker_claim_is_not_auto_preserved(self):
        baseline=self.snapshot()
        self.append_uncertain()
        with sqlite3.connect(self.source/'private/native-git/workflow.sqlite') as db:
            db.execute('INSERT INTO jobs VALUES(?,?,?,?,?,?,?)',
                       (NEW,ACTOR,json.dumps({'requestId':NEW,**REQUEST}),'CLAIMED',
                        '11111111-1111-4111-8111-111111111111',None,None))
        with self.assertRaisesRegex(RuntimeError,'UNREVIEWED_CLAIMED_JOBS'):
            self.review(baseline)

    def test_local_policy_state_is_preserved_during_uncertain_growth(self):
        from fortis_approvals.extensions.owner_policy_local_core_phase6c import LocalDenyCore
        from fortis_approvals.core import Authenticator
        LocalDenyCore(self.core,adapters={},policies={},authenticator=Authenticator({'fixture':'fixture'}))
        baseline=self.snapshot()
        self.assertEqual(0,baseline['receipt']['summary']['localPolicy']['revision'])
        self.append_uncertain()
        result=self.review(baseline)
        self.assertEqual(baseline['receipt']['summary']['localPolicy'],
                         result['receipt']['summary']['localPolicy'])

    def test_changed_local_policy_is_not_uncertain_growth(self):
        from fortis_approvals.extensions.owner_policy_local_core_phase6c import LocalDenyCore
        from fortis_approvals.core import Authenticator
        LocalDenyCore(self.core,adapters={},policies={},authenticator=Authenticator({'fixture':'fixture'}))
        baseline=self.snapshot()
        self.append_uncertain()
        with sqlite3.connect(self.core) as db:
            db.execute("UPDATE owner_local_policy_meta SET revision=1")
            db.execute("INSERT INTO owner_local_denials VALUES(?,?,?,?,?)",
                       (ACTOR,'sonarcloud','accept_issue','ISSUE-1','DENY'))
            change=dict(actor=ACTOR,provider='sonarcloud',operation='accept_issue',target='ISSUE-1',
                        requestId=NEW2,expectedRevision=0,newPolicy='DENY',purpose='OWNER_LOCAL_EXACT_DENY_APPLY_V1')
            db.execute("INSERT INTO owner_local_policy_events VALUES(?,?,?,?,?,?)",
                       (NEW2,45,'owner',json.dumps(change),0,1))
        with self.assertRaisesRegex(RuntimeError,'SUMMARY_CHANGED'):
            self.review(baseline)

    def test_growth_cannot_remove_previous_unknown(self):
        baseline=self.snapshot()
        with sqlite3.connect(self.core) as db:
            db.execute("UPDATE requests SET state='EXECUTED' WHERE id=?",(IDENT,))
        with self.assertRaisesRegex(RuntimeError,'REMOVED_OR_OVERFLOW'):
            self.review(baseline)


if __name__ == '__main__':
    unittest.main()

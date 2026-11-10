"""Exact one-off pre-dispatch APPROVED carryover, without status changes or replay."""
import json
from pathlib import Path
import sqlite3
import unittest

from test_orphaned_worker_claim_release import OrphanedClaimStateTests, H, IDENT

APPROVED = 'ba299f4f-f49c-4ef7-80cf-e1f31a232024'
APPROVED_OTHER = '49bcd340-8d21-4a7c-906a-ea5ea56ba748'
TARGET = 'fortis-approvals'
TASK = 'mirror-read-provider-20261110'
PAYLOAD = {'service': 'workspace', 'operation': 'edit',
           'target': TARGET, 'params': {'task': TASK}, 'reason': 'Bootstrap fixture'}


class SingleApprovedCarryoverTests(unittest.TestCase):
    def setUp(self):
        # Co-exists with a preserved UNCERTAIN and CLOSED_UNCONFIRMED-compatible
        # claimed job fixture, without changing either protected worker record.
        self.fixture = OrphanedClaimStateTests('test_explicit_claimed_id_preserves_all_bytes_and_unknown_state')
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.source = self.fixture.source
        self.target = self.fixture.target
        self.root = self.source / 'private'
        self.kw = {**self.fixture.kw, **self.fixture.good}
        self.review = {'preserve_approved_ids': [APPROVED]}
        with sqlite3.connect(self.root/'approvals.sqlite') as db:
            db.execute('ALTER TABLE requests ADD COLUMN result TEXT')
            db.execute('ALTER TABLE requests ADD COLUMN failure TEXT')
            db.execute('DROP TABLE events')
            db.execute('CREATE TABLE events(seq INTEGER PRIMARY KEY AUTOINCREMENT,'
                       'request_id TEXT,state TEXT,detail TEXT)')
            db.execute('INSERT INTO requests(id,actor,state,payload) VALUES(?,?,?,?)',
                       (APPROVED, 'repo-sonar-read-proposal-actor', 'APPROVED', json.dumps(PAYLOAD)))
            db.execute('INSERT INTO events(request_id,state,detail) VALUES(?,?,?)',
                       (APPROVED, 'APPROVED', json.dumps({'policy':'ALLOW'})))
        with sqlite3.connect(self.root/'sonar-receipts.sqlite') as db:
            db.execute('ALTER TABLE receipts ADD COLUMN request_id TEXT')

    def sql(self, name, query, args=()):
        with sqlite3.connect(self.root/name) as db:
            return db.execute(query, args).fetchall()

    def read(self, **params):
        return H.inspect_state(self.source, **self.kw, **params)

    def test_exact_approved_is_byte_preserved_and_still_approved(self):
        with self.assertRaisesRegex(RuntimeError, 'PRESERVATION_SCOPE_EMPTY'):
            self.read()
        state=self.read(**self.review, require_exact_approved=True)
        self.assertEqual(state['summary']['approvedRequestIds'], [APPROVED])
        before={name:(self.root/name).read_bytes() for name in state['sha256']}
        cloned=H.clone_state(self.source,self.target,**self.kw,
                             **self.review, require_exact_approved=True)
        self.assertEqual(cloned,state)
        for name,data in before.items():
            self.assertEqual(data,(self.target/'private'/name).read_bytes(),name)
        self.assertEqual(self.sql('approvals.sqlite',
            'SELECT state,result,failure FROM requests WHERE id=?',(APPROVED,)),
            [('APPROVED',None,None)])

    def test_scope_single_exact_and_no_wildcard(self):
        wrong=['11111111-1111-4111-8111-111111111111']
        with self.assertRaisesRegex(RuntimeError,'EXPECTED_REQUEST_MISMATCH'):
            self.read(preserve_approved_ids=wrong)
        with self.assertRaisesRegex(RuntimeError,'APPROVED_SET_CHANGED'):
            self.read(preserve_approved_ids=[APPROVED,*wrong],
                      require_exact_approved=True)
        with self.assertRaisesRegex(RuntimeError,'UNCERTAIN_SCOPE_INVALID'):
            self.read(preserve_approved_ids=[APPROVED,APPROVED])
        with self.assertRaisesRegex(RuntimeError,'APPROVED_SET_CHANGED'):
            self.sql('approvals.sqlite',"UPDATE requests SET state='STALE' WHERE id=?",(APPROVED,))
            self.read(**self.review,require_exact_approved=True)
        self.assertEqual(self.read(**self.review)['summary']['approvedRequestIds'],[])

    def test_another_approved_request_cannot_be_silently_preserved(self):
        extra='11111111-1111-4111-8111-111111111111'
        self.sql('approvals.sqlite',
            'INSERT INTO requests(id,actor,state,payload) VALUES(?,?,?,?)',
            (extra,'different-actor','APPROVED',json.dumps(PAYLOAD)))
        with self.assertRaisesRegex(RuntimeError,'ADDITIONAL_REQUESTS_PRESENT'):
            self.read(**self.review)
        with self.assertRaisesRegex(RuntimeError,'PRESERVATION_SCOPE_EMPTY'):
            self.read()
        # Never fix a second APPROVED by silently expanding the bootstrap
        # allowlist; that can only be a separate owner-reviewed design.
        with self.assertRaisesRegex(RuntimeError,'WAS_DISPATCHED_OR_REWRITTEN'):
            self.read(preserve_approved_ids=[APPROVED,extra],
                      require_exact_approved=True)

    def test_two_different_approved_targets_are_preserved_byte_identically(self):
        second = dict(PAYLOAD, target='feed_and_search_and_bank_and_brain',
                      params={'task':'external-ai-run-registration-20261110'})
        self.sql('approvals.sqlite',
            'INSERT INTO requests(id,actor,state,payload) VALUES(?,?,?,?)',
            (APPROVED_OTHER,'other-ai','APPROVED',json.dumps(second)))
        self.sql('approvals.sqlite',
            'INSERT INTO events(request_id,state,detail) VALUES(?,?,?)',
            (APPROVED_OTHER,'APPROVED','{}'))
        ids=[APPROVED,APPROVED_OTHER]
        with self.assertRaisesRegex(RuntimeError,'ADDITIONAL_REQUESTS_PRESENT'):
            self.read(**self.review)
        state=self.read(preserve_approved_ids=ids,require_exact_approved=True)
        self.assertEqual(state['summary']['approvedRequestIds'],sorted(ids))
        before={n:(self.root/n).read_bytes() for n in state['sha256']}
        clone=H.clone_state(self.source,self.target,**self.kw,
                            preserve_approved_ids=ids,
                            require_exact_approved=True)
        self.assertEqual(clone,state)
        self.assertEqual(before,{n:(self.target/'private'/n).read_bytes()
                                 for n in state['sha256']})
        self.assertEqual(self.sql('approvals.sqlite',
            'SELECT id,state FROM requests WHERE state=? ORDER BY id',
            ('APPROVED',)),[(x,'APPROVED') for x in sorted(ids)])

    def test_scope_rejects_21_approved_ids(self):
        extras=['00000000-0000-4000-8000-%012x'%i for i in range(20)]
        with self.assertRaisesRegex(RuntimeError,'UNCERTAIN_SCOPE_INVALID'):
            self.read(preserve_approved_ids=[APPROVED,*extras])

    def test_dispatch_history_and_active_states_fail_closed(self):
        self.sql('approvals.sqlite',
            'INSERT INTO events(request_id,state,detail) VALUES(?,?,?)',
            (APPROVED,'DISPATCHED','{}'))
        with self.assertRaisesRegex(RuntimeError,'WAS_DISPATCHED'):
            self.read(**self.review)
        self.sql('approvals.sqlite',
            'DELETE FROM events WHERE request_id=? AND state=?',(APPROVED,'DISPATCHED'))
        for state in ('PENDING','DISPATCHED'):
            with self.subTest(state=state):
                self.sql('approvals.sqlite','UPDATE requests SET state=? WHERE id=?',(state,APPROVED))
                with self.assertRaisesRegex(RuntimeError,'UNFINISHED_REQUESTS'):
                    self.read(**self.review)
        self.sql('approvals.sqlite',
            "UPDATE requests SET state='APPROVED' WHERE id=?",(APPROVED,))
        self.assertEqual(self.read(**self.review)['summary']['approvedRequestIds'],[APPROVED])

    def test_reject_worker_job_receipts_and_record_result(self):
        for dbfile,query,args,code in [
            ('native-git/workflow.sqlite',
             "INSERT INTO jobs(id,actor,payload,state,claim,result,error) VALUES(?,?,?,?,?,?,?)",
             (APPROVED,'actor','{}','FAILED',None,None,None),'WORKER_JOB_PRESENT'),
            ('github-receipts.sqlite',"INSERT INTO receipts(request_id,result) VALUES(?,?)",
             (APPROVED,'{}'),'GITHUB_RECEIPT_PRESENT'),
            ('sonar-receipts.sqlite',"INSERT INTO receipts(request_id,value) VALUES(?,?)",
             (APPROVED,'x'),'SONAR_RECEIPT_PRESENT')]:
            with self.subTest(dbfile=dbfile):
                self.sql(dbfile,query,args)
                with self.assertRaisesRegex(RuntimeError,code):
                    self.read(**self.review)
                self.sql(dbfile,'DELETE FROM '+('jobs' if dbfile.startswith('native-') else 'receipts')+
                         ' WHERE '+('id' if dbfile.startswith('native-') else 'request_id')+'=?',(APPROVED,))
        self.sql('approvals.sqlite',"UPDATE requests SET result='{}' WHERE id=?",(APPROVED,))
        with self.assertRaisesRegex(RuntimeError,'RECORD_INVALID'):
            self.read(**self.review)

    def test_approved_payload_must_still_be_well_formed(self):
        for payload in [{'operation':'edit','target':'repo'},
                        {**PAYLOAD,'target':''},
                        {**PAYLOAD,'service':''},
                        {**PAYLOAD,'params':'malformed'}]:
            with self.subTest(payload=payload):
                self.sql('approvals.sqlite','UPDATE requests SET payload=? WHERE id=?',
                         (json.dumps(payload),APPROVED))
                with self.assertRaisesRegex(RuntimeError,'PAYLOAD_INVALID'):
                    self.read(**self.review)
        self.sql('approvals.sqlite','UPDATE requests SET payload=? WHERE id=?',
                 (json.dumps(PAYLOAD),APPROVED))
        self.assertEqual(self.read(**self.review)['summary']['approvedRequestIds'],[APPROVED])


class WindowsReleaseScopeStaticTests(unittest.TestCase):
    def test_controller_requires_explicit_scoped_owner_build_and_backup(self):
        root=Path(__file__).resolve().parents[2]
        script=(root/'fortis_approvals/deploy/Manage-Integrations.ps1').read_text()
        backup=(root/'fortis_approvals/deploy/Primary-Gateway.ps1').read_text()
        for marker in (
            "[string]$PreserveApprovedRequest=''",
            'RELEASE_APPROVED_REQUIRES_EXACT_OWNER_BUILD_AND_QUIESCENCE',
            'preserveApprovedRequest=$script:PreserveApprovedRequest',
            'preserveApprovedIds=$Approved;requireExactApproved=([bool]$ExactApproved)',
            'requireExactApproved=([bool]$script:PreserveApprovedExact',
            'RELEASE_APPROVED_BACKUP_PROMOTE_REQUIRES_QUIESCENCE',
            'RELEASE_APPROVED_FLAG_FORWARD_SELFTEST_FAILED',
            'RELEASE_APPROVED_SCOPE_FORWARD_SELFTEST_FAILED',
            'RELEASE_APPROVED_MULTI_SCOPE_SELFTEST_FAILED',
            'RELEASE_APPROVED_SCOPE_NOT_FORWARDED',
            'SOURCE_STATE_PREFLIGHT_READ_ONLY',
            'Assert-ApprovedScopeForwarded $Payload'):
            self.assertIn(marker,script)
        self.assertIn('preserveApprovedIds=@(Approved-Ids)',backup)
        self.assertNotIn('UPDATE requests SET state',(
            root/'fortis_approvals/deploy/github_pilot_helpers.py').read_text())


if __name__=='__main__':
    unittest.main()

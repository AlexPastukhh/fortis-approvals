"""Source-only inactive policy draft ledger: CAS, audit, rollback and denial."""
from concurrent.futures import ThreadPoolExecutor
import hashlib
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
import uuid

from fortis_approvals.core import Denied, Stale
from fortis_approvals.extensions.owner_policy_draft_ledger import PolicyDraftLedger


BASELINE = {
    ('repo-ai', 'github', 'create_pull_request', 'fortis-approvals'): 'ASK',
    ('repo-ai', 'github', 'get_branch', 'fortis-approvals'): 'ALLOW',
    ('repo-ai', 'powershell', 'execute', 'windows-local'): 'ASK',
    ('other-ai', 'github', 'get_branch', 'fortis-approvals'): 'DENY',
}
COORD = ('repo-ai', 'github', 'create_pull_request', 'fortis-approvals')
SOURCE = hashlib.sha256(b'sealed-provider-source').hexdigest()
CREDS = hashlib.sha256(b'credential-generation-id-not-secret').hexdigest()


class PolicyLedgerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name)/'drafts.sqlite'
        self.baseline = dict(BASELINE)
        self.options = dict(baseline=self.baseline, source_digest=SOURCE,
                            credential_generation_digest=CREDS,
                            policy_version='release-test-v1', clock=lambda:1720000000)
        self.ledger = PolicyDraftLedger(self.path, **self.options)

    def reopen(self):
        return PolicyDraftLedger(self.path, **self.options)

    def pins(self, *, revision=0, old='ASK', req=None, **updates):
        row = dict(request_id=req or str(uuid.uuid4()), expected_revision=revision,
            expected_policy=old, expected_source_digest=SOURCE,
            expected_credential_generation_digest=CREDS,
            expected_policy_version='release-test-v1', reason_code='OWNER_POLICY_DRAFT_REVIEW')
        row.update(updates)
        return row

    def current(self, coord=COORD):
        return next(row['draftPolicy'] for row in self.ledger.snapshot()['drafts']
                    if tuple(row[field] for field in ('actor','provider','operation','target')) == coord)

    def test_inactive_store_permissions_initialization_persistence(self):
        self.assertEqual(0,self.ledger.snapshot()['revision'])
        self.assertEqual('0'*64,self.ledger.snapshot()['auditHash'])
        self.assertFalse(self.ledger.snapshot()['canApply'])
        self.assertEqual('NOT_CONNECTED',self.ledger.snapshot()['runtimeIntegration'])
        self.assertEqual(0,self.path.stat().st_mode & 0o077)
        self.assertEqual(0,Path(self.tmp.name).stat().st_mode & 0o077)
        event=self.ledger.stage_draft(COORD,desired_policy='DENY',**self.pins())
        self.assertTrue(event['recorded'])
        self.assertFalse(event['alreadyRecorded'])
        self.assertFalse(event['canApply'])
        self.assertEqual('DENY',self.current())
        reopened=self.reopen()
        self.assertEqual(self.ledger.snapshot(),reopened.snapshot())
        self.assertEqual('ASK',self.baseline[COORD])
        self.assertEqual(1,reopened.snapshot()['revision'])

    def test_rollback_is_new_audited_revision_and_restart_stable(self):
        first=self.ledger.stage_draft(COORD,desired_policy='DENY',**self.pins())
        self.assertEqual(1,first['revision'])
        second=self.ledger.rollback_draft(COORD,**self.pins(revision=1,old='DENY'))
        self.assertEqual(2,second['revision'])
        self.assertNotEqual(first['auditHash'],second['auditHash'])
        self.assertEqual('ASK',self.current())
        reopened = self.reopen()
        self.assertEqual('ASK',next(row['draftPolicy'] for row in reopened.snapshot()['drafts']
                        if (row['actor'],row['provider'],row['operation'],row['target']) == COORD))
        with sqlite3.connect(self.path) as db:
            events=db.execute('SELECT revision,payload FROM draft_events ORDER BY revision').fetchall()
        self.assertEqual(2,len(events))
        self.assertIn('DRAFT_SET',events[0][1])
        self.assertIn('DRAFT_ROLLBACK',events[1][1])
        with self.assertRaisesRegex(Denied,'DRAFT_NOOP'):
            self.ledger.rollback_draft(COORD,**self.pins(revision=2,old='ASK'))

    def test_verified_audit_page_has_exact_immutable_change_history(self):
        first=self.ledger.stage_draft(COORD,desired_policy='DENY',**self.pins())
        self.ledger.rollback_draft(COORD,**self.pins(revision=1,old='DENY'))
        a=self.reopen().audit_history(after_revision=0,limit=1)
        b=self.reopen().audit_history(after_revision=1,limit=1)
        self.assertEqual([1],[x['revision'] for x in a['items']])
        self.assertEqual([2],[x['revision'] for x in b['items']])
        self.assertEqual('DRAFT_SET',a['items'][0]['action'])
        self.assertEqual('DRAFT_ROLLBACK',b['items'][0]['action'])
        self.assertEqual(a['items'][0]['eventHash'],b['items'][0]['previousHash'])
        self.assertEqual(first['auditHash'],a['items'][0]['eventHash'])
        self.assertEqual(self.ledger.snapshot()['auditHash'],b['auditHeadHash'])
        self.assertFalse(a['canApply'])
        for kwargs in [{'after_revision':-1},{'after_revision':True},
                       {'limit':0},{'limit':101},{'limit':1.5}]:
            with self.subTest(kwargs=kwargs),self.assertRaisesRegex(Denied,'DRAFT_AUDIT_PAGE_INVALID'):
                self.ledger.audit_history(**kwargs)

    def test_revision_stale_and_old_value_stale_fail_closed(self):
        self.ledger.stage_draft(COORD,desired_policy='DENY',**self.pins())
        for updates,expected in [({'revision':0,'old':'ASK'},'DRAFT_REVISION_STALE'),
                                 ({'revision':1,'old':'ASK'},'DRAFT_OLD_POLICY_STALE')]:
            with self.subTest(updates=updates):
                with self.assertRaisesRegex(Stale,expected):
                    self.ledger.stage_draft(COORD,desired_policy='ALLOW',**self.pins(**updates))
        self.assertEqual(1,self.ledger.snapshot()['revision'])
        self.assertEqual('DENY',self.current())

    def test_idempotent_same_request_only_and_no_duplicate_effect(self):
        token=str(uuid.uuid4())
        pins=self.pins(req=token)
        result=self.ledger.stage_draft(COORD,desired_policy='DENY',**pins)
        repeated=self.ledger.stage_draft(COORD,desired_policy='DENY',**pins)
        self.assertEqual(1,result['revision'])
        self.assertEqual(1,repeated['revision'])
        self.assertTrue(repeated['alreadyRecorded'])
        with self.assertRaisesRegex(Denied,'DRAFT_REQUEST_REPLAY_MISMATCH'):
            self.ledger.stage_draft(COORD,desired_policy='ALLOW',**pins)
        self.assertEqual(1,self.ledger.snapshot()['revision'])

    def test_full_pin_drift_denied_and_no_rebind_after_restart(self):
        for change in [{'expected_source_digest':'0'*64},
                       {'expected_credential_generation_digest':'1'*64},
                       {'expected_policy_version':'release-test-old'}]:
            with self.subTest(change=change), self.assertRaisesRegex(Stale,'DRAFT_EXPECTED_BINDING_STALE'):
                self.ledger.stage_draft(COORD,desired_policy='DENY',**self.pins(**change))
        for change in [{'source_digest':'0'*64},{'credential_generation_digest':'1'*64},
                       {'policy_version':'restarted-v2'},
                       {'baseline':{**BASELINE,COORD:'DENY'}}]:
            with self.subTest(change=change), self.assertRaisesRegex(Denied,'DRAFT_BINDING_CHANGED'):
                PolicyDraftLedger(self.path,**{**self.options,**change})
        self.assertEqual(0,self.ledger.snapshot()['revision'])

    def test_rejects_unknown_actor_target_method_grant_and_predicate(self):
        for coord in [('unknown-ai',*COORD[1:]),
                      (COORD[0],COORD[1],COORD[2],'other-target'),
                      (COORD[0],COORD[1],'delete_repository',COORD[3])]:
            with self.subTest(coord=coord),self.assertRaisesRegex(Denied,'DRAFT_UNKNOWN_EXACT_GRANT'):
                self.ledger.stage_draft(coord,desired_policy='DENY',**self.pins())
        for bad in [('',*COORD[1:]),('x/escape',*COORD[1:]),
                    ('a',),['repo-ai',*COORD[1:]],('a', 'b', 'c', None)]:
            with self.subTest(bad=bad),self.assertRaisesRegex(Denied,'DRAFT_COORDINATES_INVALID'):
                self.ledger.stage_draft(bad,desired_policy='DENY',**self.pins())
        with self.assertRaisesRegex(Denied,'DRAFT_BASELINE_INVALID'):
            PolicyDraftLedger(Path(self.tmp.name)/'invalid.sqlite',
                **{**self.options,'baseline':{COORD:lambda *args:'ALLOW'}})

    def test_reason_noop_rollback_bad_uuid_and_unknown_policy_denied(self):
        with self.assertRaisesRegex(Denied,'DRAFT_NOOP'):
            self.ledger.stage_draft(COORD,desired_policy='ASK',**self.pins())
        for settings,policy,expected in [
            ({'reason_code':'arbitrary comment that could contain secrets'},'DENY','DRAFT_REASON_CODE_INVALID'),
            ({'request_id':'wrong-id'},'DENY','DRAFT_REQUEST_ID_INVALID'),
            ({},'SUPERUSER','DRAFT_POLICY_INVALID')]:
            with self.subTest(expected=expected),self.assertRaisesRegex(Denied,expected):
                self.ledger.stage_draft(COORD,desired_policy=policy,**self.pins(**settings))
        with self.assertRaisesRegex(Denied,'DRAFT_NOOP'):
            self.ledger.rollback_draft(COORD,**self.pins())

    def test_real_cas_across_two_independent_connections(self):
        second=self.reopen()
        args=self.pins()
        def submit(which):
            try:
                result=which.stage_draft(COORD,desired_policy='DENY',
                    **{**args,'request_id':str(uuid.uuid4())})
                return 'success',result['revision']
            except Stale as exc:
                return 'stale',str(exc)
        with ThreadPoolExecutor(max_workers=2) as pool:
            a=pool.submit(submit,self.ledger);b=pool.submit(submit,second)
            results=[a.result(),b.result()]
        self.assertEqual(1,sum(item[0]=='success' for item in results))
        self.assertEqual(1,sum(item[0]=='stale' for item in results))
        self.assertEqual(1,self.reopen().snapshot()['revision'])

    def test_corrupted_event_hash_or_projection_fails_closed(self):
        self.ledger.stage_draft(COORD,desired_policy='DENY',**self.pins())
        with sqlite3.connect(self.path) as db:
            db.execute("UPDATE draft_events SET event_hash=? WHERE revision=1",('f'*64,))
        for factory in [self.ledger.snapshot,self.reopen]:
            with self.subTest(factory=factory),self.assertRaisesRegex(Denied,'DRAFT_AUDIT_INTEGRITY'):
                factory()

    def test_current_row_tampering_without_event_denied(self):
        self.ledger.stage_draft(COORD,desired_policy='DENY',**self.pins())
        with sqlite3.connect(self.path) as db:
            db.execute('''UPDATE draft_current SET policy='ALLOW'
                WHERE actor=? AND provider=? AND operation=? AND target=?''',COORD)
        with self.assertRaisesRegex(Denied,'DRAFT_PROJECTION_INTEGRITY'):
            self.ledger.snapshot()

    def test_symlink_and_overbroad_directory_file_rejected(self):
        symlink = Path(self.tmp.name)/'alias.sqlite'
        symlink.symlink_to(self.path)
        with self.assertRaisesRegex(Denied,'DRAFT_STORE_SYMLINK'):
            PolicyDraftLedger(symlink,**self.options)
        with tempfile.TemporaryDirectory() as second:
            os.chmod(second,0o755)
            with self.assertRaisesRegex(Denied,'DRAFT_PARENT_PERMISSIONS'):
                PolicyDraftLedger(Path(second)/'drafts.sqlite',**self.options)
        os.chmod(self.path,0o644)
        with self.assertRaisesRegex(Denied,'DRAFT_STORE_PERMISSIONS'):
            self.reopen()

    def test_never_mints_runtime_authority_even_for_allow(self):
        row=('repo-ai','powershell','execute','windows-local')
        staged=self.ledger.stage_draft(row,desired_policy='ALLOW',**self.pins())
        self.assertFalse(staged['canApply'])
        snap=self.reopen().snapshot()
        self.assertEqual('NOT_CONNECTED',snap['runtimeIntegration'])
        self.assertEqual('ASK',BASELINE[row])
        self.assertFalse(snap['canApply'])
        # No import, mutation or dependency from Core/Owner Portal to this module.
        from fortis_approvals import core, owner_portal, incidents
        for module in [core,owner_portal,incidents]:
            self.assertNotIn('owner_policy_draft_ledger',Path(module.__file__).read_text())


if __name__=='__main__':unittest.main()

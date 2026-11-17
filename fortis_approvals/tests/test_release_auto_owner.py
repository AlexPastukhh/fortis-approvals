"""PR4b auto-release: offline, read-only preflight and safety source gates."""
from contextlib import redirect_stdout
from io import StringIO
import json
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[2]
SOURCE=(ROOT/'fortis_approvals/deploy/Manage-Integrations.ps1').read_text()
SHA='c7eb0cab1d8261bb6ba0bbd4c004185ef55bbb72'


def read_code():
    start=SOURCE.index("        $ReadCode=@'\n")+len("        $ReadCode=@'\n")
    end=SOURCE.index("\n'@\n",start)
    return SOURCE[start:end].replace('__EXACT_HEAD_SHA__',SHA).replace(
        'from fortis_approvals.workflow.client import default_client',
        'default_client=lambda: __fake_client__')


class FakeClient:
    def __init__(self):
        self.sha=SHA
        self.branch_pages={1:[{'name':'main','sha':self.sha}]}
        self.branch_calls=[]
        self.rows=[
            {'requestId':'11111111-1111-4111-8111-111111111111','state':'UNCERTAIN'},
            {'requestId':'22222222-2222-4222-8222-222222222222','state':'UNCERTAIN'},
        ]
        self.claims=[{'requestId':'33333333-3333-4333-8333-333333333333','jobState':'CLAIMED'}]
        self.incomplete=False
        self.github=self;self.gateway=self

    def list_branches(self,repo,*,page,per_page):
        assert repo=='fortis-approvals' and per_page==100
        self.branch_calls.append(page)
        return {'items':self.branch_pages.get(page,[])}

    def post(self,path,payload):
        assert path=='/v1/workspace/capabilities' and payload=={}
        return {'globalRequestInventory':{'crossActorDetails':True}}

    def list_requests(self,*,offset,limit,unresolved_only):
        assert offset==0 and limit==100 and unresolved_only is True
        return dict(items=self.rows,total=len(self.rows)+(1 if self.incomplete else 0),
                    offset=0,nextOffset=None,truncated=False,unresolvedOnly=True)

    def activity(self,*,offset,limit):
        assert offset==0 and limit==100
        return dict(items=self.claims,total=len(self.claims),offset=0,
                    nextOffset=None,truncated=False)


def run_read(fake):
    buf=StringIO()
    with redirect_stdout(buf):
        exec(compile(read_code(),'<offline-auto-read>','exec'),{'__fake_client__':fake})
    return json.loads(buf.getvalue())


class AutoOwnerSourceTests(unittest.TestCase):
    def test_auto_check_reuses_protected_config_and_exact_scopes(self):
        for marker in (
            '[switch]$Auto','RELEASE_AUTO_MANUAL_ARGUMENTS_DENIED',
            '$Build=[switch]$true',
            'Get-SourceRecord  # ACL checked, validates prior scopes',
            '$script:AutoConfigText=[string]$Source.runtime.extensionsConfig',
            '$SourceRecord=Read-Private $Source.path',
            '$script:AutoProbeText=$SourceRecord.probes',
            'RELEASE_AUTO_CONFIG_NOT_RETAINED',
            'if($Auto){$ConfigText=$script:AutoConfigText}',
            'if($Auto){$ProbeText=$script:AutoProbeText}',
            '$ConfigHash=Sha256-Utf8 $script:AutoConfigText',
            '$script:PreserveUncertainExact=($script:PreserveUncertainRequests -ne \'\')',
            '$script:PreserveClaimedExact=($script:PreserveClaimedJobs -ne \'\')',
            'Save-Checked-Image $Source $Report $CheckReceipt',
        ):
            with self.subTest(marker=marker):self.assertIn(marker,SOURCE)

    def test_owner_go_required_and_existing_guards_not_bypassed(self):
        for marker in (
            'Type QUIESCENT','RELEASE_AUTO_QUIESCENCE_NOT_ATTESTED',
            'Type APPLY','RELEASE_AUTO_OWNER_GO_REQUIRED',
            'RELEASE_AUTO_OWNER_REVIEW_REQUIRED',
            'RELEASE_AUTO_CHECK_BINDING_INVALID','Read-Private $script:AutoCheckPointer',
            'Write-Private $script:AutoCheckPointer',
            'Verify-Checked-Image $SourceForOwnerShell $Report',
            'Assert-Checked-Source-Receipt $script:R.sourceReceipt',
            'RELEASE_PREVIOUS_IMAGE_MISSING',
            'Assert-Previous-Image-Retained $Source',
            'RELEASE_PRIOR_ATTEMPT_REQUIRES_RESUME_OR_RETURN',
            "if($Action -eq 'Backup'){Backup-Primary;return}",
            "if($Action -eq 'Promote'){Promote-Primary;return}",
        ):
            with self.subTest(marker=marker):self.assertIn(marker,SOURCE)
        for disallowed in ('reconcile(','.publish(','.submit(','.execute('):
            self.assertNotIn(disallowed,read_code())

    def test_branch_inventory_paginates_beyond_100(self):
        fake=FakeClient()
        fake.branch_pages={
            1:([{'name':f'branch-{i:03d}','sha':'a'*40} for i in range(99)] +
               [{'name':'main','sha':SHA}]),
            2:[{'name':f'task-branch-{i:03d}','sha':'b'*40} for i in range(31)],
        }
        data=run_read(fake)
        self.assertEqual(fake.branch_calls,[1,2])
        self.assertEqual(data['sourceSha'],SHA)

    def test_branch_inventory_page_limit_fails_closed(self):
        fake=FakeClient()
        fake.branch_pages={
            page:[{'name':f'branch-{page}-{i}','sha':'a'*40} for i in range(100)]
            for page in range(1,21)
        }
        with self.assertRaisesRegex(RuntimeError,'RELEASE_BRANCH_PAGE_LIMIT'):
            run_read(fake)

    def test_branch_inventory_rejects_duplicate_names(self):
        fake=FakeClient()
        fake.branch_pages={
            1:([{'name':f'branch-{i:03d}','sha':'a'*40} for i in range(99)] +
               [{'name':'main','sha':SHA}]),
            2:[{'name':'main','sha':SHA}],
        }
        with self.assertRaisesRegex(RuntimeError,'RELEASE_BRANCH_DUPLICATE'):
            run_read(fake)

    def test_inventory_growth_detected_without_manual_uuid(self):
        fake=FakeClient()
        self.assertEqual(len(run_read(fake)['uncertain']),2)
        self.assertEqual(len(run_read(fake)['claimed']),1)
        fake.rows.append({'requestId':'44444444-4444-4444-8444-444444444444',
                          'state':'UNCERTAIN'})
        self.assertEqual(len(run_read(fake)['uncertain']),3)

    def test_incomplete_read_unexpected_job_and_remote_mismatch_stop(self):
        fake=FakeClient();fake.incomplete=True
        with self.assertRaisesRegex(AssertionError,'RELEASE_INVENTORY_INCOMPLETE'):
            run_read(fake)
        fake=FakeClient()
        fake.branch_pages={1:[{'name':'main','sha':'a'*40}]}
        with self.assertRaisesRegex(RuntimeError,'RELEASE_REMOTE_MAIN_MISMATCH'):
            run_read(fake)
        fake=FakeClient();fake.claims=[{'requestId':'x','jobState':'QUEUED'}]
        with self.assertRaisesRegex(AssertionError,'RELEASE_ACTIVITY_UNEXPECTED_JOB'):
            run_read(fake)

    def test_approved_pending_and_dispatched_are_exposed_not_hidden(self):
        fake=FakeClient()
        for state in ('APPROVED','PENDING','DISPATCHED'):
            fake.rows.append({'requestId':state,'state':state})
        data=run_read(fake)
        self.assertEqual(data['approved'],['APPROVED'])
        self.assertEqual(data['pending'],['PENDING'])
        self.assertEqual(data['dispatched'],['DISPATCHED'])
        for token in ('@($Snapshot.pending).Count','@($Snapshot.dispatched).Count',
                      '@($Snapshot.approved).Count'):
            self.assertIn(token,SOURCE)


if __name__=='__main__':
    unittest.main()

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

    def test_auto_check_apply_enable_same_sealed_growth_helper_by_default(self):
        auto=SOURCE.split('if($Auto){',1)[1].split('if($Pull -and -not $Build)',1)[0]
        self.assertIn('$AllowUncertainGrowth=[switch]$true',auto)
        self.assertIn("if($Action -cin @('Check','Apply'))",auto)
        self.assertIn('RELEASE_AUTO_CHECK_GROWTH_WITNESS_REQUIRED',auto)
        self.assertIn('$SavedCheck.binding.allowUncertainGrowth',auto)
        self.assertIn('$null -eq $SavedCheck.growthWitness',auto)
        self.assertIn('$OriginalIds=@(Parse-PreservedUncertainRequests',auto)
        self.assertIn('$SavedCheck.binding.preserveUncertainRequests',auto)
        self.assertIn('$ObservedIds=@($Snapshot.uncertain)',auto)
        self.assertIn('RELEASE_AUTO_UNCERTAIN_SCOPE_REDUCED',auto)
        self.assertIn('$script:PreserveUncertainRequests=$OriginalIds -join',auto)
        self.assertIn('Snapshot-Uncertain-Growth $Source.runtime.stateVolume',SOURCE)
        self.assertIn('original=$Checked.sourceReceipt;witness=$Checked.growthWitness',SOURCE)
        self.assertIn('preserveUncertainIds=@(Effective-Uncertain-Ids)',SOURCE)
        # Explicit manual flags are STILL denied in -Auto. Only internal
        # owner-confirmed -Auto Check/Apply enables the shared witness.
        self.assertIn('$PreserveApprovedRequest -or $AllowUncertainGrowth -or',auto)
        self.assertIn("if($EnablePublisherMount -and ($Auto",SOURCE)
        self.assertIn('RELEASE_AUTO_OWNER_REVIEW_REQUIRED',SOURCE)
        self.assertIn('RELEASE_AUTO_QUIESCENCE_NOT_ATTESTED',SOURCE)
        self.assertIn('RELEASE_AUTO_OWNER_GO_REQUIRED',SOURCE)

    def test_successor_checked_profile_is_bound_and_verified_before_source_stop(self):
        store=SOURCE.split('function Save-Checked-Image',1)[1].split(
            'function Assert-Checked-Image-Binding',1)[0]
        verify=SOURCE.split('function Verify-Checked-Image',1)[1].split(
            'function Assert-CheckedImagePreflightSelfTest',1)[0]
        self.assertIn("binding=(Checked-Image-Binding $Source $Report $Maintenance)",store)
        self.assertIn("$Record['maintenanceSeal']=$Seal",store)
        self.assertLess(verify.index('Read-SuccessorMaintenanceContext $Source'),
                        verify.index('Assert-Checked-Image-Binding $Record.binding $Expected'))
        self.assertLess(verify.index('Same-Json $Record.maintenanceSeal $Maintenance.checkSeal'),
                        verify.index('Read-SuccessorFreezeSeal $Maintenance'))
        prepare=SOURCE.index('Verify-Checked-Image $SourceForOwnerShell $Report -PrepareSuccessorStop')
        save=SOURCE.index('Save-SuccessorApplyStopIntent $StopIntent',prepare)
        stop=SOURCE.index("throw 'RELEASE_SUCCESSOR_STAGED_HANDOVER_UNAVAILABLE'",save)
        self.assertLess(prepare,save)
        self.assertLess(save,stop)
        self.assertLess(stop,SOURCE.index("Step 'STOP_SOURCE';Assert-Release-Production"))

    def test_ordinary_entrypoint_uses_protected_check_and_exact_stopped_source(self):
        dispatch=SOURCE[ SOURCE.index("if($Report.status -cne 'READY')"): ]
        self.assertLess(dispatch.index('Assert-PairedReleaseProbes $SourceForOwnerShell'),
                        dispatch.index('Prepare-SuccessorMaintenanceContext $SourceForOwnerShell $OrdinaryCandidate -Report $Report'))
        self.assertIn("if(-not $OrdinaryPairRequested){",dispatch)
        self.assertIn("if($Bootstrap289 -and $Action -ceq 'Apply')",dispatch)
        preflight=dispatch.split("Step 'REPO_CLIENT_PREFLIGHT'",1)[1].split("Step 'PREVIOUS_IMAGE_RETENTION_PREFLIGHT'",1)[0]
        self.assertIn('binding.ordinaryNativeRead',preflight)
        self.assertIn("if($Rows.gateway.State.Status -ceq 'running'){Assert-NativeRepoRead}",preflight)
        self.assertIn("Read-OrdinarySuccessorSource $Source -PublicationRecovery",preflight)
        self.assertNotIn("Docker-Text @('start'",preflight)
        self.assertLess(dispatch.index('Save-OrdinaryPreparedAttempt $Source $Report $StopIntent'),
                        dispatch.index('Invoke-BootstrapPreparedTransition'))
        resume=SOURCE.split('\nfunction Resume-Target {',1)[1].split('\nfunction ',1)[0]
        self.assertIn('Assert-NativeRepoRead',resume)
        self.assertIn("'probe-frozen'",resume)

    def test_successor_publication_keeps_pending_intent_until_exact_readback(self):
        publish=SOURCE.split('\nfunction Publish-SuccessorInterlock {',1)[1].split(
            '\nfunction Read-SuccessorMaintenanceContext {',1)[0]
        check=SOURCE.split('function Read-SuccessorMaintenanceContext',1)[1].split('function Ensure-Vault',1)[0]
        self.assertIn("if(-not (Same-Json $Anchor.next $Next))",publish)
        self.assertLess(publish.index("state='Pending'"),publish.index("mode='readback'"))
        self.assertLess(publish.index("mode='readback'"),publish.index("$Payload.mode='publish'"))
        self.assertLess(publish.index("$Actual.position -cne 'NEXT'"),publish.index("state='Committed'"))
        self.assertEqual(publish.count('-FlushToDisk'),2)
        self.assertIn("$Publication.state -cne 'Committed'",check)
        self.assertIn("Same-Json $Publication.record $Transitions.checked",check)

    def test_successor_check_starts_pause_before_snapshot_and_never_reports_ready_at_draining(self):
        flow=SOURCE.split("if($Action -eq 'Check'){\n    $CheckReceipt",1)[1].split(
            'if(Test-Path -LiteralPath $AttemptPointer)',1)[0]
        assert_start=flow.index('Start-SuccessorMaintenanceCheck $Source $CurrentMaintenance')
        waiting=flow.index("status='MAINTENANCE_DRAINING'",assert_start)
        capture=flow.index('Read-SuccessorFreezeSeal $SuccessorMaintenance',waiting)
        save=flow.index('Save-Checked-Image $Source $Report $CheckReceipt',capture)
        self.assertLess(flow.index('return',waiting),capture)
        finish=flow.index('Complete-SuccessorMaintenanceCheck $Source $CurrentMaintenance $Stored',save)
        self.assertLess(finish,flow.index("-NotePropertyName checkedImageRecord",finish))
        self.assertIn("$Record['maintenanceTransitions']=$Transitions",SOURCE)
        complete=SOURCE.split('function Complete-SuccessorMaintenanceCheck',1)[1].split(
            'function Assert-SuccessorCheckSealSelfTest',1)[0]
        freeze=complete.index('Publish-SuccessorInterlock $Source $Transitions.frozen')
        checked=complete.index('Publish-SuccessorInterlock $Source $Transitions.checked')
        readback=complete.index('Read-SuccessorFreezeSeal $Verify')
        self.assertLess(freeze,checked)
        self.assertLess(checked,readback)
        self.assertIn('Same-Json $Final.sourceReceipt $Stored.sourceReceipt',complete)
        self.assertIn('Successor-CheckRecordPath $Maintenance.attemptId',SOURCE)
        self.assertIn("if(-not (Same-Json (Read-Private $Path) $Record))",SOURCE)
        self.assertIn('Assert-SuccessorCheckStartSelfTest',SOURCE)

    def test_successor_apply_reuses_check_context_and_persists_exact_stop_intent(self):
        context=SOURCE.split('function Read-SuccessorMaintenanceContext',1)[1].split(
            'function New-SuccessorApplyVerifyPayload',1)[0]
        self.assertIn("Payload.action -cne 'successor_freeze_inspect'",context)
        self.assertIn('$Stored=Read-Private $ExpectedPath',context)
        self.assertIn('Same-Json $Publication.record $Transitions.checked',context)
        self.assertIn('New-SuccessorApplyVerifyPayload $Payload $Stored.maintenanceSeal',context)
        store=SOURCE.split('function Save-SuccessorApplyStopIntent',1)[1].split(
            '# Offline fixture',1)[0]
        self.assertIn("Join-Path $Directory 'apply-stop.json'",store)
        self.assertIn('Write-Private $Path $Intent -FlushToDisk',store)
        self.assertIn('Same-Json (Read-Private $Path) $Intent',store)

    def test_auto_check_refuses_old_unwitnessed_pointer(self):
        auto=SOURCE.split('if($Auto){',1)[1].split('if($Pull -and -not $Build)',1)[0]
        check=auto.index('$SavedCheck=Read-Private $CheckedImageRecord')
        refusal=auto.index('RELEASE_AUTO_CHECK_GROWTH_WITNESS_REQUIRED',check)
        read=auto.index('$Snapshot=Repo-JSON $ReadCode',refusal)
        self.assertLess(check,refusal)
        self.assertLess(refusal,read)
        self.assertIn("-not $SavedCheck.binding.allowUncertainGrowth",auto)
        self.assertIn('$SavedCheck.binding.allowUncertainGrowth -isnot [bool]',auto)
        self.assertIn('$null -eq $SavedCheck.sourceReceipt',auto)

    def test_auto_apply_original_scope_not_replaced_by_recent_repo_read(self):
        auto=SOURCE.split('if($Auto){',1)[1].split('if($Pull -and -not $Build)',1)[0]
        idx=auto.index("if($Action -eq 'Apply'){",auto.index('$Snapshot=Repo-JSON $ReadCode'))
        compare=auto.index("if($Missing.Count -or $ObservedIds.Count -lt $OriginalIds.Count)",idx)
        sealed=auto.index("$script:PreserveUncertainRequests=$OriginalIds -join ','",compare)
        check_path=auto.index("} else {" + chr(10) + "            # Check is bound to its final offline snapshot",sealed)
        self.assertLess(compare,sealed)
        self.assertLess(sealed,check_path)
        self.assertNotIn('$script:PreserveUncertainRequests=$ObservedIds',auto)
        self.assertIn("RELEASE_AUTO_OWNER_REVIEW_REQUIRED",auto)
        self.assertIn('$script:PreserveClaimedJobs=@($Snapshot.claimed)',auto)

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

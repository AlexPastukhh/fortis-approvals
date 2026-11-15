"""Confirmed effects survive unavailable postflight reads without more WRITE."""
import copy
from collections import Counter
from pathlib import Path
import tempfile
import unittest
from fortis_approvals.workflow.intents import _call_failure

from fortis_approvals.core import Denied
from test_command_intents import Client, SHA


class ResultRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.client=Client(Path(self.tmp.name)/'journal')
        self.calls=Counter()
        def wrap(obj,name):
            original=getattr(obj,name)
            def counted(*args,**kwargs):
                self.calls[name]+=1
                return original(*args,**kwargs)
            setattr(obj,name,counted)
        for obj,name in [(self.client,'result'),(self.client,'details'),
                         (self.client.gateway,'post'),(self.client.github,'list_branches'),
                         (self.client.github,'list_pull_requests'),(self.client.github,'get_pull_request')]:
            wrap(obj,name)

    def pr(self):
        return self.client.intent.github_action('create_pull_request','sandbox',
            dict(head='task/agent',base='main',title='review',body='body',draft=False),reason='review')

    def test_normal_success_uses_bound_receipt_without_inventory_rescan(self):
        result=self.pr()
        self.assertEqual(result['status'],'DONE')
        self.assertEqual(result['effect']['state'],'EXECUTED')
        self.assertEqual(result['verification']['state'],'CONFIRMED')
        self.assertEqual(result['nextAction']['kind'],'NONE')
        self.assertEqual(len(self.client.github.posts),1)
        self.assertLessEqual(sum(self.calls.values()),4)
        self.assertEqual(self.calls['details'],0)
        self.assertEqual(self.calls['get_pull_request'],0)

    def test_unavailable_details_cannot_turn_success_into_stop(self):
        def unavailable(*args,**kwargs):raise Denied('FORTIS_HTTP_503')
        self.client.details=unavailable
        self.assertEqual(self.pr()['status'],'DONE')
        self.assertEqual(len(self.client.github.posts),1)

    def test_unavailable_result_keeps_execution_and_retry_is_read_only(self):
        original=self.client.result
        def unavailable(*args,**kwargs):raise Denied('FORTIS_HTTP_503')
        self.client.result=unavailable
        first=self.pr()
        self.assertEqual(first['status'],'WAITING')
        self.assertEqual(first['effect']['state'],'EXECUTED')
        self.assertEqual(first['verification']['code'],'FORTIS_HTTP_503')
        self.assertEqual(first['nextAction']['kind'],'RETRY_READ')
        self.assertEqual(len(self.client.github.posts),1)
        before=self.calls.copy()
        self.client.result=original
        recovered=self.client.intent.retry(first['intentId'])
        self.assertEqual(recovered['status'],'DONE')
        self.assertEqual(recovered['requestId'],first['requestId'])
        self.assertEqual(len(self.client.github.posts),1)
        for method in ['list_branches','list_pull_requests','details','post']:
            self.assertEqual(self.calls[method],before[method])

    def test_missing_receipt_waits_and_foreign_receipt_never_becomes_success(self):
        original=self.client.result
        mode=['missing']
        def result(ident,**kwargs):
            row=original(ident,**kwargs)
            if mode[0]=='missing':row['result']=None
            if mode[0]=='foreign':row['result']['requestId']='22222222-2222-4222-8222-222222222222'
            return row
        self.client.result=result
        first=self.pr()
        self.assertEqual(first['status'],'WAITING')
        mode[0]='foreign'
        invalid=self.client.intent.retry(first['intentId'])
        self.assertEqual(invalid['status'],'STOP')
        self.assertEqual(invalid['code'],'INTENT_RECEIPT_BINDING_INVALID')
        self.assertEqual(invalid['nextAction']['kind'],'FIX_PRECONDITION')
        mode[0]='valid'
        self.assertEqual(self.client.intent.retry(first['intentId'])['status'],'DONE')
        self.assertEqual(len(self.client.github.posts),1)

    def test_same_uuid_with_different_core_payload_is_not_adopted(self):
        def conflict(operation,repo,params,*,request_id,reason):
            other={**params,'body':'a different immutable request'}
            self.client.rows[request_id]={'state':'EXECUTED','request':dict(
                requestId=request_id,target=repo,operation=operation,params=other)}
            raise Denied('FORTIS_HTTP_409')
        self.client.github._action_once=conflict
        self.assertEqual(self.pr()['code'],'INTENT_DETAILS_BINDING_INVALID')

    def test_invalid_head_receipt_is_not_a_success(self):
        original=self.client.result
        def result(ident,**kwargs):
            row=original(ident,**kwargs)
            if row.get('result'):row['result']['pullRequest']['head']['sha']='c'*40
            return row
        self.client.result=result
        self.assertEqual(self.pr()['code'],'INTENT_RECEIPT_BINDING_INVALID')

    def test_owner_pending_is_actionable_without_new_ask(self):
        self.client.github.outcomes=['pending']
        first=self.pr()
        self.assertEqual(first['nextAction']['kind'],'WAIT_OWNER')
        again=self.client.intent.retry(first['intentId'])
        self.assertEqual(again['nextAction']['kind'],'WAIT_OWNER')
        self.assertEqual(len(self.client.github.posts),1)

    def test_late_receipt_is_attributed_to_its_own_uuid_not_latest_failed_attempt(self):
        self.client.github.outcomes=['missing','before','before']
        first=self.pr()
        self.assertEqual(first['status'],'RETRY_EXHAUSTED')
        ident=first['attemptIds'][0]
        row=self.client.rows[ident]
        row['state']='EXECUTED'
        row['result']=dict(requestId=ident,operation='create_pull_request',repository='sandbox',
            pullRequest=dict(number=1,head={'ref':'task/agent','sha':SHA},
                base={'ref':'main','sha':'a'*40},draft=False,url='https://github.com/owner/sandbox/pull/1'))
        result=self.client.intent.retry(first['intentId'])
        self.assertEqual(result['status'],'DONE',result)
        self.assertEqual(result['requestId'],ident)
        self.assertEqual(result['effect']['requestId'],ident)
        self.assertEqual(result['lastAttemptId'],first['attemptIds'][-1])
        self.assertEqual(len(self.client.github.posts),3)

    def test_pre_core_artifact_failure_keeps_attempt_phase_without_raw_error(self):
        ident='11111111-1111-4111-8111-111111111111'
        code='FORTIS_ARTIFACT_GIT_COMMAND_FAILED_FETCH_MAIN'
        evidence=_call_failure(Denied(code),ident,93505)
        self.assertEqual(evidence,dict(requestId=ident,origin='REPO_CALL',code=code,
            elapsedMs=93505,stage='ARTIFACT',phase='FETCH_MAIN'))
        raw=_call_failure(RuntimeError('Bearer SECRET https://private.invalid'),ident,1)
        self.assertEqual(raw['code'],'INTENT_CALL_FAILED')
        self.assertNotIn('SECRET',str(raw))

    def test_exhausted_round_reports_its_actual_failed_attempt(self):
        self.client.github.outcomes=['before']*3
        result=self.pr()
        self.assertEqual(result['status'],'RETRY_EXHAUSTED')
        evidence=result['failureEvidence']
        self.assertEqual(evidence['requestId'],result['lastAttemptId'])
        self.assertEqual(evidence['code'],'FORTIS_HTTP_500')
        self.assertIs(type(evidence['elapsedMs']),int)
        journal=self.client.intent.journal.load(result['intentId'])
        self.assertTrue(all(a['failureEvidence']['requestId']==a['requestId'] for a in journal['attempts']))


if __name__=='__main__':unittest.main()

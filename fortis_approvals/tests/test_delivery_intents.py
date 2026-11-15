"""One delivery handle delegates budgets and owner waits to child intents."""
import copy
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest

from fortis_approvals.core import Denied
from fortis_approvals.workflow.client import GitDelivery
from fortis_approvals.workflow.intents import IntentClient
from test_command_intents import Client, SHA, OLD


class DeliveryIntentTests(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory();self.addCleanup(tmp.cleanup)
        self.root=Path(tmp.name);self.client=Client(self.root/'intents')
        c=self.client;c.intents=c.intent;c.automatic_recovery=True;c.git_delivery=GitDelivery(c)
        state=self.root/'state';state.mkdir(mode=0o700)
        c.worker=SimpleNamespace(_open=lambda repo:(self.root,state,None,None),
            _snapshot=lambda *a:{'clean':True,'headSha':SHA})
        c.github.head=None
        self.pushes=[];self.push_outcomes=[];self.error=None
        self.original_details=c.details
        def details(ident):
            result=self.original_details(ident)
            if self.error and ident in self.pushes:
                result['diagnostic']={'coreError':{'stage':'GITHUB_ADAPTER','code':self.error}}
            return result
        c.details=details
        def push(repo,task,old,new,*,request_id,reason,package_id=None):
            self.pushes.append(request_id)
            outcome=self.push_outcomes.pop(0) if self.push_outcomes else 'success'
            if outcome=='before':raise Denied('FORTIS_HTTP_500')
            if outcome=='forbidden':raise Denied('FORTIS_HTTP_403')
            params=dict(task=task,expectedHeadSha=old,newSha=new)
            state='PENDING' if outcome=='pending' else 'DENIED' if outcome=='denied' else 'UNCERTAIN'
            c.rows[request_id]={'state':state,'request':dict(requestId=request_id,
                operation='push_commits',target=repo,params=params)}
            if outcome=='uncertain-error':raise Denied('FORTIS_HTTP_500')
            if outcome in ('pending','uncertain','denied'):
                return {'requestId':request_id,'state':state}
            c.github.head=new
            c.rows[request_id]['state']='EXECUTED'
            c.rows[request_id]['result']=dict(requestId=request_id,operation='push_commits',
                repository=repo,branch='task/'+task,sha=new)
            return {'requestId':request_id,'state':'EXECUTED'}
        c._publish_once=push
    def submit(self,**kwargs):
        return self.client.git_delivery.submit('sandbox','agent',SHA,
            title='review',body='body',reason='publish task',**kwargs)
    def test_normal_delivery_owns_ids_and_uses_one_push_one_pr(self):
        result=self.submit()
        self.assertEqual(result['status'],'DONE',result)
        self.assertEqual(len(self.pushes),1)
        self.assertEqual(len(self.client.github.posts),1)
        self.assertEqual(result['pushRequestId'],self.pushes[-1])
        self.assertEqual(result['prRequestId'],self.client.github.posts[-1])
        self.assertEqual(result['pullRequestNumber'],1)
        self.assertEqual(result['nextAction']['intentId'],result['intentId'])
        self.assertNotIn(result['intentId'],result['attemptIds'])
        for child in result['children'].values():
            self.assertNotIn(child['intentId'],child['attemptIds'])
    def test_pr_exhaustion_continues_only_pr_after_restart(self):
        self.client.github.outcomes=['before']*3
        first=self.submit()
        self.assertEqual(first['status'],'RETRY_EXHAUSTED',first)
        self.assertEqual(first['stage'],'pr')
        self.assertEqual(len(self.pushes),1)
        self.assertEqual(len(self.client.github.posts),3)
        again=self.submit()
        self.assertEqual(again['attemptIds'],first['attemptIds'])
        c=self.client
        c.intents=c.intent=IntentClient(c,root=self.root/'intents',retry_policy=c.intent.policy)
        result=c.intents.retry(first['intentId'])
        self.assertEqual(result['status'],'DONE',result)
        self.assertEqual(len(self.pushes),1)
        self.assertEqual(len(c.github.posts),4)
        self.assertEqual(result['prRequestId'],c.github.posts[-1])
        self.assertNotEqual(result['prRequestId'],first['prRequestId'])
        self.assertEqual(result['intentId'],first['intentId'])
        self.assertEqual(len(set(result['attemptIds'])),5)
    def test_owner_pending_stays_on_original_push_and_does_not_create_pr(self):
        self.push_outcomes=['pending']
        first=self.submit()
        self.assertEqual((first['status'],first['stage']),('WAITING','push'),first)
        self.assertEqual(first['nextAction']['kind'],'WAIT_OWNER')
        again=self.client.intents.retry(first['intentId'])
        self.assertEqual(again['status'],'WAITING',again)
        self.assertEqual(len(self.pushes),1)
        self.assertEqual(self.client.github.posts,[])
    def test_legacy_explicit_ids_remain_first_attempt_ids(self):
        push='11111111-1111-4111-8111-111111111111'
        pr='22222222-2222-4222-8222-222222222222'
        result=self.submit(push_request_id=push,pr_request_id=pr)
        self.assertEqual(result['status'],'DONE',result)
        self.assertEqual(result['attemptIds'],[push,pr])
    def test_manual_retry_after_repair_does_not_require_a_new_uuid(self):
        self.push_outcomes=['forbidden']
        first=self.submit()
        self.assertEqual(first['status'],'STOP',first)
        result=self.client.intents.retry(first['intentId'])
        self.assertEqual(result['status'],'DONE',result)
        self.assertEqual(len(set(self.pushes)),2)
    def test_core_denied_cannot_be_overridden_by_manual_retry(self):
        self.push_outcomes=['denied']
        first=self.submit()
        self.assertEqual(first['status'],'STOP',first)
        result=self.client.intents.retry(first['intentId'])
        self.assertEqual(result['status'],'STOP',result)
        self.assertEqual(len(self.pushes),1)
    def test_reported_auth_failure_stops_automatic_retry_but_allows_repair(self):
        self.error='GIT_AUTH_FAILURE_REPORTED';self.push_outcomes=['uncertain']
        first=self.submit()
        self.assertEqual((first['status'],first['code']),('STOP',self.error),first)
        self.assertEqual(len(self.pushes),1)
        self.error=None
        result=self.client.intents.retry(first['intentId'])
        self.assertEqual(result['status'],'DONE',result)
        self.assertEqual(len(self.pushes),2)
    def test_competing_head_after_push_cannot_rebind_pr_to_other_commit(self):
        original=self.client.result
        def result(ident,**kwargs):
            value=original(ident,**kwargs)
            if ident in self.pushes and value['state']=='EXECUTED':
                self.client.github.head='c'*40
            return value
        self.client.result=result
        response=self.submit()
        self.assertEqual(response['code'],'INTENT_PR_HEAD_CHANGED',response)
        self.assertEqual(self.client.github.posts,[])

    def test_reported_git_rate_limit_retains_backoff_across_manual_retry(self):
        now=[100]
        self.client.intent.policy.clock=lambda:now[0]
        self.client.intent.policy.max_wait=1
        self.error='GIT_RATE_LIMIT_REPORTED';self.push_outcomes=['uncertain']
        first=self.submit()
        self.assertEqual(first['status'],'WAITING',first)
        self.assertEqual(first['nextAction']['kind'],'WAIT_BACKOFF')
        self.assertEqual(first['retryAfterSeconds'],60)
        now[0]=150
        waiting=self.client.intents.retry(first['intentId'])
        self.assertEqual(waiting['status'],'WAITING',waiting)
        self.assertEqual(waiting['retryAfterSeconds'],10)
        self.assertEqual(len(self.pushes),1)
        self.error=None;now[0]=161
        self.assertEqual(self.client.intents.retry(first['intentId'])['status'],'DONE')
        self.assertEqual(len(set(self.pushes)),2)

    def test_core_reason_is_not_hidden_by_preceding_http_500_evidence(self):
        self.error='GIT_AUTH_FAILURE_REPORTED';self.push_outcomes=['uncertain-error']
        result=self.submit()
        self.assertEqual((result['status'],result['code']),('STOP',self.error),result)
        self.assertEqual(len(self.pushes),1)
        child=self.client.intent.journal.load(result['children']['push']['intentId'])
        self.assertEqual(child['attempts'][0]['callFailureEvidence']['code'],'FORTIS_HTTP_500')
        self.assertEqual(child['attempts'][0]['coreFailureEvidence']['code'],self.error)


if __name__=='__main__':unittest.main()

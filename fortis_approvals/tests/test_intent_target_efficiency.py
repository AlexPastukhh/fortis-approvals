"""Read budgets count coordination, including retries and capability reads."""
import copy
from collections import Counter
from pathlib import Path
import tempfile
import unittest

from fortis_approvals.core import Denied
from fortis_approvals.workflow.client import WorkflowClient
from test_command_intents import Client, SHA, OLD

FEATURE={'version':1,'branch':'repository-access-checked-v1',
         'pullRequests':'same-repository-head-base-v1'}


class TargetEfficiencyTests(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory();self.addCleanup(tmp.cleanup)
        self.client=Client(Path(tmp.name)/'journal');self.calls=Counter()
        def cap(*args):
            self.calls['capabilities']+=1
            return {'globalRequestInventory':{'crossActorDetails':True},
                    'githubTargetReads':copy.deepcopy(FEATURE)}
        self.client.gateway.post=cap
        gh=self.client.github
        def branch(repo,name):
            self.calls['get_branch']+=1
            return {'found':True,'branch':{'name':name,'sha':gh.head if name=='task/agent' else OLD}}
        def pulls(repo,head,base,*,page,per_page):
            self.calls['find_pull_requests']+=1
            rows=[r for r in gh.prs if r['head']['ref']==head and r['base']['ref']==base]
            rows=copy.deepcopy(rows[(page-1)*per_page:page*per_page])
            return {'items':rows,'hasNextPage':len(rows)==per_page}
        gh.get_branch=branch;gh.find_pull_requests=pulls
        for obj,name in [(self.client,'result'),(self.client,'details'),(gh,'get_pull_request')]:
            original=getattr(obj,name)
            def wrapper(*args,_fn=original,_name=name,**kwargs):
                self.calls[_name]+=1;return _fn(*args,**kwargs)
            setattr(obj,name,wrapper)
        def forbidden(*a,**kw):raise AssertionError('No full inventory in addressed path')
        gh.list_branches=forbidden;gh.list_pull_requests=forbidden
        self.client.intent.policy.sleep=lambda _:None
    def pr(self):
        return self.client.intent.github_action('create_pull_request','sandbox',
            dict(head='task/agent',base='main',title='review',body='body',draft=False),reason='review')
    def test_normal_success_four_reads_with_one_capability_read(self):
        result=self.pr()
        self.assertEqual(result['status'],'DONE',result)
        self.assertLessEqual(sum(self.calls.values())-self.calls['capabilities'],4)
        self.assertEqual(self.calls['capabilities'],1)
        self.assertEqual(len(self.client.github.posts),1)
    def test_one_pre_effect_500_at_most_ten_reads_and_fresh_attempt(self):
        self.client.github.outcomes=['before','success']
        result=self.pr()
        self.assertEqual(result['status'],'DONE',result)
        self.assertLessEqual(sum(self.calls.values())-self.calls['capabilities'],10)
        self.assertEqual(self.calls['capabilities'],1)
        self.assertEqual(len(set(result['attemptIds'])),2)
    def test_lost_ack_uses_original_receipt_and_never_sleeps_after_confirmation(self):
        self.client.github.outcomes=['lost']
        slept=[];self.client.intent.policy.sleep=slept.append
        result=self.pr()
        self.assertEqual(result['status'],'DONE',result)
        self.assertEqual(len(self.client.github.posts),1)
        self.assertEqual(slept,[])
    def test_pagination_ambiguity_and_incomplete_page_prevent_write(self):
        template=dict(number=1,state='open',merged=False,draft=False,
            head={'ref':'task/agent','sha':SHA},base={'ref':'main','sha':OLD},
            url='https://github.com/owner/sandbox/pull/1')
        self.client.github.prs=[{**template,'number':i+1} for i in range(51)]
        result=self.pr()
        self.assertEqual(result['code'],'INTENT_PR_AMBIGUOUS')
        self.assertEqual(self.calls['find_pull_requests'],2)
        self.assertEqual(self.client.github.posts,[])
        self.client.github.find_pull_requests=lambda *a,**kw:{'items':[],'hasNextPage':True}
        result=self.pr()
        self.assertEqual(result['code'],'INTENT_READ_INCOMPLETE')
        self.assertEqual(self.client.github.posts,[])
    def test_target_read_denial_does_not_trigger_legacy_permission_fallback(self):
        def denied(*a,**kw):raise Denied('FORTIS_HTTP_403')
        self.client.github.get_branch=denied
        result=self.pr()
        self.assertEqual(result['code'],'FORTIS_HTTP_403')
        self.assertEqual(self.client.github.posts,[])
    def test_new_client_passes_initial_capabilities_without_another_read(self):
        gateway=self.client.gateway
        caps={'globalRequestInventory':{'crossActorDetails':True},'githubTargetReads':FEATURE}
        flow=WorkflowClient(gateway=gateway,worker=None,capabilities=caps)
        self.assertEqual(flow.intents._capabilities(),caps)
        self.assertEqual(self.calls['capabilities'],0)
        flow.capabilities(refresh=True)
        self.assertEqual(self.calls['capabilities'],1)


if __name__=='__main__':unittest.main()

"""Offline typed GitHub Issue readback, pagination and preserved visual provenance.

No live GitHub mutations; no token or owner credential is ever used.
"""
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from fortis_approvals.core import Denied
from fortis_approvals.integrations.github.contract import (
    validate_github_read,validate_github_read_projection,
)
from fortis_approvals.integrations.github.gateway.adapter import GitHubAdapter
from fortis_approvals.integrations.github.gateway.transport import GitHubHTTPTransport
from fortis_approvals.integrations.github.repo_client.client import GitHubClient
from fortis_approvals.workflow.ingress import NativeIngress

ROOT='/repos/PilotOwner/visual-workspace'
ISSUE_URL='https://github.com/PilotOwner/visual-workspace/issues/42'
PNG_URL='https://github.com/user-attachments/assets/abc123'
BODY='<!-- fortis-visual-review:visual-run-1 -->\n\nQA: PASS\n\n![Front]('+PNG_URL+')'

def issue(num=42, body=BODY):
    return dict(number=num,title='Northlight Beacon',state='open',body=body,
                html_url='https://github.com/PilotOwner/visual-workspace/issues/'+str(num),
                created_at='2026-11-11T01:00:00Z',updated_at='2026-11-11T01:00:00Z')

class FakeGitHub:
    def __init__(self):self.calls=[]
    def request(self,method,path,*,params=None,body=None,expected_statuses=(200,),allow_not_found=False):
        assert GitHubHTTPTransport._route_allowed(method,path),(method,path)
        self.calls.append((method,path,params))
        assert method=='GET'
        if path==ROOT+'/issues':
            if params['page']==1:
                pr={**issue(12), 'pull_request':{'url':'https://api.github.com/repos/PilotOwner/visual-workspace/pulls/12'}}
                return [pr,issue()]
            return []
        if path==ROOT+'/issues/42':return issue()
        if path==ROOT+'/issues/44' and allow_not_found:return {'_httpStatus':404}
        if path==ROOT+'/issues/42/comments':
            return [dict(id=65,body='Revised PNG: ![v2]('+PNG_URL+')',created_at='2026-11-11T01:01:00Z',
                html_url=ISSUE_URL+'#issuecomment-65')]
        raise AssertionError((method,path,params))

class Tests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup)
        self.transport=FakeGitHub()
        self.adapter=GitHubAdapter(self.transport,owner='PilotOwner',repositories=['visual-workspace'],
                                   receipt_store=Path(temp.name)/'receipts.sqlite')
        adapter=self.adapter
        class Gateway:
            def post(self,path,body):
                assert path=='/v1/reads'
                data=adapter.read(body)
                return dict(requestId=body['requestId'],service='github',operation=body['operation'],data=data)
        self.client=GitHubClient(gateway=Gateway())

    def test_list_issues_skips_prs_and_reliably_reports_page_metadata(self):
        data=self.client.list_issues('visual-workspace',state='all',page=1,per_page=2)
        self.assertEqual(len(data['items']),1)
        self.assertEqual(data['items'][0]['runIdMarker'],'visual-run-1')
        self.assertEqual(data['items'][0]['embeddedMediaCount'],1)
        self.assertTrue(data['hasNextPage'])  # Despite one visible Issue: GitHub returned 2 items, including a PR.
        self.assertEqual(self.client.list_issues('visual-workspace',page=2)['items'],[])
        self.assertEqual(self.transport.calls[0][1],ROOT+'/issues')

    def test_get_issue_body_and_reference_only_media_links(self):
        data=self.client.get_issue('visual-workspace',42)
        self.assertTrue(data['found'])
        self.assertEqual(data['issue']['url'],ISSUE_URL)
        self.assertEqual(data['issue']['embeddedMediaUrls'],[PNG_URL])
        self.assertEqual(data['issue']['body'],BODY)
        self.assertEqual(self.client.get_issue('visual-workspace',44),{'operation':'get_issue','found':False,'issue':None})
        self.assertFalse(any(action!='GET' for action,*_ in self.transport.calls))

    def test_typed_comment_reads_for_future_same_issue_versions(self):
        data=self.client.list_issue_comments('visual-workspace',42)
        self.assertEqual(len(data['items']),1)
        self.assertEqual(data['items'][0]['embeddedMediaUrls'],[PNG_URL])
        self.assertEqual(data['items'][0]['url'],ISSUE_URL+'#issuecomment-65')

    def test_find_run_is_read_only_not_retry_authorization(self):
        found=self.client.find_visual_review_run('visual-workspace','visual-run-1')
        self.assertTrue(found['found'])
        self.assertEqual(found['issue']['number'],42)
        missing=self.client.find_visual_review_run('visual-workspace','unknown-run')
        self.assertEqual(missing,dict(found=False,complete=True,issue=None))
        with self.assertRaises(Denied):self.client.find_visual_review_run('visual-workspace','../escape')

    def test_closed_contract_rejects_unbounded_or_unknown_fetches(self):
        for op,args in [('list_issues',{'page':1,'perPage':101,'state':'all'}),
                        ('get_issue',{'number':True}),
                        ('get_issue',{'number':0}),
                        ('list_issue_comments',{'number':42,'page':1,'perPage':100,'url':'evil'})]:
            with self.assertRaises(Denied):validate_github_read(op,'visual-workspace',args)
        self.assertFalse(GitHubHTTPTransport._route_allowed('DELETE',ROOT+'/issues/42'))
        self.assertFalse(GitHubHTTPTransport._route_allowed('GET',ROOT+'/issues/42/comments/1'))
        correct=self.adapter.read(dict(service='github',operation='get_issue',target='visual-workspace',params={'number':42}))
        with self.assertRaises(Denied):validate_github_read_projection('get_issue',{**correct,'token':'SECRET'})
        with self.assertRaises(Denied):validate_github_read_projection('get_issue',{
            **correct,'issue':{**correct['issue'],'embeddedMediaUrls':['https://evil.example/image.png']}})
        with self.assertRaises(Denied):self.adapter._project_issue('visual-workspace',issue(body='x'*24001),with_body=True)

    def test_runtime_visual_policy_only_exact_private_repo(self):
        from fortis_approvals.core import Core, Authenticator
        from fortis_approvals.integrations.github.pilot import GitHubPilotConfig
        from fortis_approvals.workflow.runtime import install
        with tempfile.TemporaryDirectory() as d:
            core=Core(Path(d)/'core.sqlite',adapters={},policies={},
                      authenticator=Authenticator({'secret':'agent'}))
            portal=SimpleNamespace(strong_operations=frozenset())
            broker=SimpleNamespace(read_adapters={},actor_read_operations={},actor_operations={})
            class Transport:
                def request(self,*args,**kwargs):raise AssertionError('no HTTP at install')
            configured=install(core=core,portal=portal,broker=broker,
                               config=GitHubPilotConfig('PilotOwner','visual-workspace'),
                               root=Path(d),actor='agent',transport=Transport(),backend=object())
            def policy(operation,repo):
                return core._policy('agent',{'service':'github','operation':operation,'target':repo})
            self.assertEqual(policy('publish_visual_review','visual-workspace'),'ALLOW')
            self.assertEqual(policy('publish_visual_review','other'),'DENY')
            self.assertEqual(policy('merge_pull_request','visual-workspace'),'ASK')
            for operation in ('list_issues','get_issue','list_issue_comments'):
                self.assertIn(('github',operation),broker.actor_read_operations['agent'])
            native=NativeIngress(SimpleNamespace(broker=SimpleNamespace(core=core)),
                                 github=configured['adapter'],workspace=None,store=None,actor='agent')
            caps=native._dispatch('/v1/workspace/capabilities',{},'secret','agent')
            self.assertEqual(caps['visualReview']['publishPolicy'],'ALLOW')
            self.assertIn('publish_visual_review',caps['allowGitHub'])
            self.assertNotIn('publish_visual_review',caps['askGitHub'])
            self.assertEqual(caps['githubIssueReads'],['list_issues','get_issue','list_issue_comments'])

    def test_details_uses_core_nested_request_for_media_progress(self):
        ref='00000000-0000-4000-8000-000000000009'
        calls=[]
        core=SimpleNamespace(auth=SimpleNamespace(authenticate=lambda cred:'agent'),
            machine_request_details=lambda cred,ident,**kwargs:{
                'request':{'requestId':ident,'state':'UNCERTAIN',
                           'request':{'service':'github','operation':'publish_visual_review','target':'visual-workspace'}},
                'state':'UNCERTAIN'},)
        gh=SimpleNamespace(visual_evidence=lambda ident:calls.append(ident) or dict(issueNumber=42,uploadedFiles=1))
        native=NativeIngress(SimpleNamespace(broker=SimpleNamespace(core=core)),github=gh,workspace=None,store=None,actor='agent')
        with patch('fortis_approvals.workflow.ingress.diagnose',return_value={'schemaVersion':1}):
            row=native._dispatch('/v1/workspace/details',{'requestId':ref,'eventOffset':0,'eventLimit':30},'secret','agent')
        self.assertEqual(row['visualReview'],dict(issueNumber=42,uploadedFiles=1))
        self.assertEqual(calls,[ref])

if __name__=='__main__':unittest.main()

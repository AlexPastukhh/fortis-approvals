"""Visual review: closed contract, staging and fake GitHub multi-step effect."""
import hashlib
import json
from io import BytesIO
from pathlib import Path
import struct
import tempfile
import unittest
import uuid
from unittest.mock import patch

from fortis_approvals.core import Denied
from fortis_approvals.integrations.github.contract import validate_github_action
from fortis_approvals.integrations.github.gateway.transport import GitHubHTTPTransport
from fortis_approvals.integrations.github.repo_client.client import GitHubClient
from fortis_approvals.workflow.adapters import NativeGitHubAdapter
from fortis_approvals.workflow.store import Store
import test_dynamic_github_repos as dynamic

# PNG IHDR with signature sufficient for the strict staging type check.
PNG=b'\x89PNG\r\n\x1a\n'+struct.pack('>I',13)+b'IHDR'+struct.pack('>IIBBBBB',1,1,8,2,0,0,0)+b'\x00'*4
REPO='visual-workspace'
RUN='run-20261110-001'


def params():
    return dict(runId=RUN,title='Scanner Drone',description='Result',qaSummary='PASS',
                durationSeconds=180,media=[dict(index=0,name='Preview',sha256=hashlib.sha256(PNG).hexdigest(),size=len(PNG))])


class FakeVisualGitHub:
    def __init__(self):
        self.issue=None;self.posts=0;self.uploads=0
    def request(self,method,path,*,params=None,body=None,expected_statuses=(200,),allow_not_found=False):
        assert GitHubHTTPTransport._route_allowed(method,path),(method,path)
        prefix='/repos/PilotOwner/visual-workspace'
        assert path.startswith(prefix)
        if method=='GET' and path==prefix:
            return dict(id=33,full_name='PilotOwner/visual-workspace',private=True,has_issues=True,
                        archived=False,disabled=False,default_branch='main')
        if method=='POST' and path==prefix+'/issues':
            self.posts+=1;self.issue=dict(number=42,html_url='https://github.com/PilotOwner/visual-workspace/issues/42',
                body=body['body'],state='open');return dict(self.issue)
        if method=='PATCH' and path==prefix+'/issues/42':
            self.issue['body']=body['body'];return dict(self.issue)
        if method=='GET' and path==prefix+'/issues/42':return dict(self.issue)
        raise AssertionError((method,path))
    def upload_visual_png(self,repository_id,name,data):
        assert repository_id==33 and name.endswith('.png') and data==PNG
        self.uploads+=1
        return 'https://github.com/user-attachments/assets/abc123'


class Tests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup)
        self.root=Path(temp.name);self.workfiles=self.root/'Workfiles';self.workfiles.mkdir()
        self.store=Store(self.root/'native-git')
        self.id=str(uuid.uuid4());self.p=params();self.transport=FakeVisualGitHub()
        self.adapter=NativeGitHubAdapter(self.transport,config=dynamic.cfg(),
            root=self.root,actor='agent',backend=None,store=self.store)
    def stage(self):
        return self.store.stage_visual_png('agent',self.id,REPO,RUN,0,'Preview',
                                            self.p['media'][0]['sha256'],PNG)
    def intent(self):
        return dict(requestId=self.id,service='github',operation='publish_visual_review',
                    target=REPO,params=self.p,reason='Preview')
    def test_contract_scoped_and_closed(self):
        validate_github_action('publish_visual_review',REPO,self.p)
        with self.assertRaises(Denied):validate_github_action('publish_visual_review','other',self.p)
        for key,value in [('unknown',True),('durationSeconds',True),('media',[])]:
            wrong={**self.p,key:value}
            with self.assertRaises(Denied):validate_github_action('publish_visual_review',REPO,wrong)
        self.assertFalse(GitHubHTTPTransport._route_allowed('DELETE','/repos/PilotOwner/visual-workspace/issues/42'))
        self.assertFalse(GitHubHTTPTransport._route_allowed('POST','/repos/PilotOwner/visual-workspace/issues/42'))
        self.assertTrue(GitHubHTTPTransport._route_allowed('PATCH','/repos/PilotOwner/visual-workspace/issues/42'))
    def test_stage_actor_digest_and_conflict(self):
        self.stage()
        self.assertEqual(self.store.visual_png('agent',self.id,REPO,RUN,self.p['media'][0]),PNG)
        with self.assertRaises(Denied):self.store.visual_png('wrong',self.id,REPO,RUN,self.p['media'][0])
        with self.assertRaises(Denied):self.store.stage_visual_png('agent',self.id,REPO,RUN,0,'Preview','0'*64,PNG)
        with self.assertRaises(Denied):self.store.stage_visual_png('agent',self.id,REPO,RUN,0,'Preview',
                                                                    hashlib.sha256(b'exe').hexdigest(),b'exe')
    def test_missing_stage_blocks_create(self):
        with self.assertRaises(Denied):self.adapter.prepare(self.intent())
        self.assertEqual(self.transport.posts,0)
    def test_publish_and_receipt_prevent_duplicates(self):
        self.stage()
        preview=self.adapter.prepare(self.intent());self.assertEqual(preview['repositoryId'],33)
        done=self.adapter.apply(self.intent())
        self.assertEqual(done['issueNumber'],42);self.assertEqual(done['uploadedFiles'],1)
        self.assertEqual(self.transport.posts,1);self.assertEqual(self.transport.uploads,1)
        self.assertEqual(self.adapter.apply(self.intent()),done)
        self.assertEqual(self.transport.posts,1)
        self.assertTrue(self.adapter.confirm(self.id,done))
        self.assertEqual(self.adapter.visual_evidence(self.id)['issueNumber'],42)
        other=self.intent();other['requestId']=str(uuid.uuid4())
        self.store.stage_visual_png('agent',other['requestId'],REPO,RUN,0,'Preview',
                                    self.p['media'][0]['sha256'],PNG)
        with self.assertRaises(Denied):self.adapter.apply(other)
        self.assertEqual(self.transport.posts,1)
    def test_lost_create_reply_does_not_repeat_issue(self):
        self.stage()
        original=self.transport.request
        def lost(method,path,**kwargs):
            row=original(method,path,**kwargs)
            if method=='POST' and path.endswith('/issues'):
                raise RuntimeError('reply lost after GitHub created issue')
            return row
        self.transport.request=lost
        with self.assertRaises(RuntimeError):self.adapter.apply(self.intent())
        self.assertEqual(self.transport.posts,1)
        with self.assertRaises(Denied):self.adapter.apply(self.intent())
        self.assertEqual(self.transport.posts,1)
        self.assertIsNone(self.adapter.visual_evidence(self.id)['issueNumber'])

    def test_client_stages_bytes_then_submits_one_action(self):
        folder=self.workfiles/RUN;folder.mkdir();file=folder/'preview.png';file.write_bytes(PNG)
        calls=[]
        class Gateway:
            def post(self,path,body,*,accept_202=False):
                calls.append((path,body))
                if path.endswith('/stage'):
                    return {k:body[k] for k in ('index','name','sha256')}|{'size':len(PNG)}
                return dict(requestId=body['requestId'],state='PENDING')
        client=GitHubClient(gateway=Gateway())
        from fortis_approvals.integrations.github.repo_client import client as client_module
        with patch.object(client_module,'WORKFILES_ROOT',self.workfiles):
            result=client.publish_visual_review(repository=REPO,run_id=RUN,title='Result',
                description='',media=[dict(path=str(file),name='Preview')],qa_summary='PASS',
                duration_seconds=1,request_id=self.id,reason='Visual preview')
        self.assertEqual(result['state'],'PENDING')
        self.assertEqual([x[0] for x in calls],['/v1/github/visual-review/stage','/v1/actions'])
        self.assertEqual(calls[1][1]['params']['media'][0]['sha256'],hashlib.sha256(PNG).hexdigest())
        self.assertEqual(calls[1][1]['requestId'],self.id)

    def test_fixed_upload_host_and_reject_bad_media(self):
        class Response:
            status=201
            def __enter__(self):return self
            def __exit__(self,*args):return None
            def read(self,n):return json.dumps(dict(url='https://github.com/user-attachments/assets/abc123')).encode()
        class Opener:
            def __init__(self):self.calls=[]
            def open(self,req,timeout):
                self.calls.append(req)
                return Response()
        opener=Opener()
        transport=GitHubHTTPTransport('x'*32,opener=opener)
        self.assertEqual(transport.upload_visual_png(33,'fortis-0-1234567890123456.png',PNG),
                         'https://github.com/user-attachments/assets/abc123')
        self.assertEqual(len(opener.calls),1)
        self.assertTrue(opener.calls[0].full_url.startswith('https://uploads.github.com/user-attachments/assets?'))
        self.assertEqual(opener.calls[0].get_header('Authorization'),'token '+'x'*32)
        self.assertEqual(opener.calls[0].data,PNG)
        for filename,data in [('bad.jpg',PNG),('image.png',b'malware'),('other/foo.png',PNG)]:
            with self.assertRaises(Denied):transport.upload_visual_png(33,filename,data)
        self.assertEqual(len(opener.calls),1)

    def test_client_rejects_symlink_and_wrong_run_before_upload(self):
        class Gateway:
            def post(self,*args,**kwargs):raise AssertionError('must not call gateway')
        client=GitHubClient(gateway=Gateway())
        safe=self.workfiles/RUN;safe.mkdir();asset=safe/'image.png';asset.write_bytes(PNG)
        link=safe/'link.png';link.symlink_to(asset)
        opts=dict(repository=REPO,run_id=RUN,title='Result',description='',
                  qa_summary='PASS',duration_seconds=1,request_id=self.id,reason='Preview')
        from fortis_approvals.integrations.github.repo_client import client as client_module
        with patch.object(client_module,'WORKFILES_ROOT',self.workfiles):
            with self.assertRaises(Denied):client.publish_visual_review(media=[dict(path=str(link),name='Image')],**opts)
            with self.assertRaises(Denied):client.publish_visual_review(media=[dict(path=str(asset),name='Image')],**{**opts,'run_id':'wrong-run'})

if __name__=='__main__':unittest.main()

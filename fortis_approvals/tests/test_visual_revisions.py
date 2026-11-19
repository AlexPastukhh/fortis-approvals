"""Offline append-only GitHub Issue revision safety and strict typed contract."""
import hashlib
from pathlib import Path
from types import SimpleNamespace
import time
import tempfile
import unittest
import uuid
from unittest.mock import patch

from fortis_approvals.core import Denied, Core, Authenticator
from fortis_approvals.integrations.github.contract import validate_github_action
from fortis_approvals.integrations.github.gateway.transport import GitHubHTTPTransport
from fortis_approvals.integrations.github.repo_client.client import GitHubClient
from fortis_approvals.workflow.adapters import NativeGitHubAdapter
from fortis_approvals.workflow.store import Store
from test_visual_review import FakeVisualGitHub, PNG, RUN, REPO, params
import test_dynamic_github_repos as dynamic


class FakeWithComments(FakeVisualGitHub):
    def __init__(self):
        super().__init__()
        self.comments={}
        self.comment_posts=0

    def request(self,method,path,*,params=None,body=None,expected_statuses=(200,),allow_not_found=False):
        prefix='/repos/PilotOwner/visual-workspace'
        comments=prefix+'/issues/42/comments'
        if method=='POST' and path==comments:
            assert GitHubHTTPTransport._route_allowed(method,path)
            self.comment_posts+=1
            ident=777+self.comment_posts
            item=dict(id=ident,body=body['body'],
                html_url='https://github.com/PilotOwner/visual-workspace/issues/42#issuecomment-'+str(ident))
            self.comments[ident]=item
            return dict(item)
        if method=='GET' and path.startswith(prefix+'/issues/comments/'):
            assert GitHubHTTPTransport._route_allowed(method,path)
            return dict(self.comments[int(path.rsplit('/',1)[-1])])
        return super().request(method,path,params=params,body=body,
            expected_statuses=expected_statuses,allow_not_found=allow_not_found)


class FakeCore:
    def __init__(self):
        self.rows={}
        self.policy='ASK'
        self.policy_version=1
        self.auth=SimpleNamespace(active=lambda actor: actor=='agent')
        self.clock=time.time

    def _policy(self,actor,request):
        return self.policy if actor=='agent' and request['operation']=='append_visual_revision' else 'DENY'

    def _read(self,ident):
        if ident not in self.rows: raise Denied('GITHUB_REVISION_OWNER_APPROVAL_MISSING')
        return self.rows[ident]


class RevisionTests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup)
        self.root=Path(temp.name);self.store=Store(self.root/'native-git')
        self.media=self.root/'Workfiles';self.media.mkdir()
        self.transport=FakeWithComments()
        self.core=FakeCore()
        self.adapter=NativeGitHubAdapter(self.transport,config=dynamic.cfg(),
            root=self.root,actor='agent',backend=None,store=self.store,
            observation_core=self.core)
        self.first_id=str(uuid.uuid4());self.rev_id=str(uuid.uuid4())
        self.p=params()
        self.store.stage_visual_png('agent',self.first_id,REPO,RUN,0,'Preview',
            self.p['media'][0]['sha256'],PNG)
        first=dict(requestId=self.first_id,service='github',operation='publish_visual_review',
            target=REPO,params=self.p,reason='original')
        self.adapter.apply(first)
        self.base_body=self.transport.issue['body']
        self.rev=self.revision_params('second-run',2)
        self.stage(self.rev_id,self.rev)

    def revision_params(self,run,revision):
        return dict(issueNumber=42,baseRunId=RUN,assetId='scanner-drone',
                    revision=revision,runId=run,sourceSha='a'*40,
                    description='Adjusted antenna',qaSummary='PASS Godot capture',
                    durationSeconds=77,media=self.p['media'])

    def stage(self,ident,p):
        self.store.stage_visual_png('agent',ident,REPO,p['runId'],0,'Preview',
            p['media'][0]['sha256'],PNG)

    def intent(self,ident=None,p=None):
        return dict(requestId=ident or self.rev_id,service='github',
                    operation='append_visual_revision',target=REPO,
                    params=p or self.rev,reason='owner review v2')

    def approved(self,intent):
        preview=self.adapter.prepare(intent)
        self.core.rows[intent['requestId']]=dict(
            request=intent,preview=preview,state='DISPATCHED',decision='approve',
            owner='owner',actor='agent',policyVersion=1,
            expiresAt=int(time.time())+3600)
        result=self.adapter.apply(intent)
        self.core.rows[intent['requestId']]['state']='EXECUTED'
        return result

    def test_no_owner_approval_or_wrong_policy_blocks_before_effect(self):
        with self.assertRaises(Denied):self.adapter.apply(self.intent())
        self.core.policy='ALLOW'
        with self.assertRaises(Denied):self.adapter.apply(self.intent())
        self.core.policy='ASK'
        intent=self.intent()
        self.core.rows[self.rev_id]=dict(
            request=intent,preview=self.adapter.prepare(intent),
            state='DISPATCHED',decision='reject',owner='owner',actor='agent',
            policyVersion=1,expiresAt=int(time.time())+3600)
        with self.assertRaisesRegex(Denied,'GITHUB_REVISION_CORE_ADMISSION_REQUIRED'):
            self.adapter.apply(intent)
        self.assertEqual(self.transport.comment_posts,0)
        self.assertIsNone(self.adapter.visual_evidence(self.rev_id))

    def core_allow(self):
        """Real Core admission: no owner verifier, exact owner-repo ALLOW."""
        core=Core(self.root/'core.sqlite',adapters={'github':self.adapter},
                  policies={('agent','github','append_visual_revision'):'DENY',
                            ('agent','github','append_visual_revision',REPO):'ALLOW'},
                  authenticator=Authenticator({'machine-grant':'agent'}))
        self.adapter.observation_core=core
        return core

    def test_core_allow_appends_without_owner_and_keeps_one_shot_receipt(self):
        core=self.core_allow()
        result=core.client('machine-grant','submit',dict(self.intent(),expectedVersion=0))
        self.assertEqual(result['state'],'EXECUTED')
        self.assertIsNone(result['owner'])
        self.assertIsNone(result['decision'])
        self.assertEqual(result['result']['revision'],2)
        self.assertEqual(self.transport.comment_posts,1)
        self.assertEqual(self.transport.issue['body'],self.base_body)
        self.assertEqual(core.client('machine-grant','submit',dict(self.intent(),expectedVersion=0))['state'],
                         'EXECUTED')
        self.assertEqual(self.transport.comment_posts,1)
        # Generic targets and foreign Issues cannot inherit the scoped ALLOW.
        foreign=self.intent(str(uuid.uuid4()))
        foreign['target']='other-repository'
        with self.assertRaises(Denied):
            core.client('machine-grant','submit',dict(foreign,expectedVersion=0))
        self.assertEqual(self.transport.comment_posts,1)

    def test_public_repository_can_append_to_original_issue(self):
        original=self.transport.request
        def public(method,path,**kwargs):
            response=original(method,path,**kwargs)
            if method=='GET' and path=='/repos/PilotOwner/visual-workspace':
                return {**response,'private':False}
            return response
        self.transport.request=public
        core=self.core_allow()
        result=core.client('machine-grant','submit',dict(self.intent(),expectedVersion=0))
        self.assertEqual(result['state'],'EXECUTED')
        self.assertEqual(result['result']['issueNumber'],42)
        self.assertEqual(result['result']['revision'],2)
        self.assertEqual(self.transport.comment_posts,1)
        self.assertEqual(self.transport.issue['body'],self.base_body)

    def test_core_allow_stops_duplicate_after_lost_comment_ack(self):
        core=self.core_allow()
        actual=self.transport.request
        def lost(method,path,**kwargs):
            result=actual(method,path,**kwargs)
            if method=='POST' and path.endswith('/comments'):
                raise TimeoutError('simulated lost create-comment ACK')
            return result
        self.transport.request=lost
        first=core.client('machine-grant','submit',dict(self.intent(),expectedVersion=0))
        self.assertEqual(first['state'],'UNCERTAIN')
        self.assertEqual(self.transport.comment_posts,1)
        self.transport.request=actual
        self.assertEqual(core.client('machine-grant','submit',dict(self.intent(),expectedVersion=0))['state'],
                         'UNCERTAIN')
        self.assertEqual(self.transport.comment_posts,1)
        duplicate=self.intent(str(uuid.uuid4()))
        duplicate['params']={**self.rev,'runId':'another-run'}
        self.stage(duplicate['requestId'],duplicate['params'])
        with self.assertRaises(Denied):
            core.client('machine-grant','submit',dict(duplicate,expectedVersion=0))
        self.assertEqual(self.transport.comment_posts,1)

    def test_contract_no_broadening_and_exact_routes(self):
        validate_github_action('append_visual_revision',REPO,self.rev)
        for update in ({'issueNumber':True},{'revision':1},{'revision':2.0},
                       {'sourceSha':'z'*40},{'baseRunId':'second-run'},
                       {'assetId':'scanner drone'},{'media':[]},{'hidden':True}):
            with self.subTest(update=update),self.assertRaises(Denied):
                validate_github_action('append_visual_revision',REPO,{**self.rev,**update})
        with self.assertRaises(Denied):
            validate_github_action('append_visual_revision','not-visual-workspace',self.rev)
        base='/repos/PilotOwner/visual-workspace'
        self.assertTrue(GitHubHTTPTransport._route_allowed('POST',base+'/issues/42/comments'))
        self.assertTrue(GitHubHTTPTransport._route_allowed('GET',base+'/issues/comments/778'))
        self.assertFalse(GitHubHTTPTransport._route_allowed('DELETE',base+'/issues/42/comments'))
        self.assertFalse(GitHubHTTPTransport._route_allowed('POST',base+'/issues/42/comments/778'))
        self.assertFalse(GitHubHTTPTransport._route_allowed('PATCH',base+'/issues/comments/778'))
        self.assertFalse(GitHubHTTPTransport._route_allowed('POST',base+'/issues/0/comments'))

    def test_append_creates_one_comment_and_keeps_original_issue(self):
        before=self.adapter._revision_prepare(self.intent())
        self.assertEqual(before['originalIssueUrl'],
            'https://github.com/PilotOwner/visual-workspace/issues/42')
        result=self.approved(self.intent())
        self.assertEqual(result['issueNumber'],42)
        self.assertEqual(result['revision'],2)
        self.assertEqual(result['uploadedFiles'],1)
        self.assertEqual(result['commentId'],778)
        self.assertEqual(self.transport.comment_posts,1)
        self.assertEqual(self.transport.issue['body'],self.base_body)
        self.assertEqual(self.adapter.apply(self.intent()),result)
        self.assertEqual(self.transport.comment_posts,1)
        self.assertTrue(self.adapter.confirm(self.rev_id,result))
        evidence=self.adapter.visual_evidence(self.rev_id)
        self.assertEqual(evidence['revision'],2)
        self.assertEqual(evidence['commentId'],778)
        self.assertIn('<!-- fortis-visual-revision:scanner-drone:2:second-run -->',
                      self.transport.comments[778]['body'])

    def test_next_version_can_append_but_replay_old_version_denied(self):
        self.approved(self.intent())
        third=str(uuid.uuid4());p=self.revision_params('third-run',3)
        self.stage(third,p)
        self.assertEqual(self.approved(self.intent(third,p))['revision'],3)
        self.assertEqual(self.transport.comment_posts,2)
        duplicate=str(uuid.uuid4());q=self.revision_params('duplicate-run',3)
        self.stage(duplicate,q)
        with self.assertRaises(Denied):
            self.approved(self.intent(duplicate,q))
        self.assertEqual(self.transport.comment_posts,2)

    def test_wrong_issue_marker_and_cross_asset_prevent_effects(self):
        self.rev['issueNumber']=41
        with self.assertRaises(Denied):self.approved(self.intent())
        self.rev['issueNumber']=42
        self.transport.issue['body']='<!-- fortis-visual-review:forged -->\n'
        with self.assertRaises(Denied):self.approved(self.intent())
        self.transport.issue['body']=self.base_body
        self.transport.issue['pull_request']={'url':'other'}
        with self.assertRaises(Denied):self.approved(self.intent())
        del self.transport.issue['pull_request']
        self.approved(self.intent())
        third=str(uuid.uuid4());different=self.revision_params('third-run',3)
        different['assetId']='another-asset'
        self.stage(third,different)
        with self.assertRaises(Denied):self.approved(self.intent(third,different))
        self.assertEqual(self.transport.comment_posts,1)

    def test_partial_comment_effect_is_reserved_no_blind_replay(self):
        real=self.transport.request
        def lost(method,path,**kwargs):
            result=real(method,path,**kwargs)
            if method=='POST' and path.endswith('/comments'):
                raise TimeoutError('response lost after GitHub already created the comment')
            return result
        self.transport.request=lost
        with self.assertRaises(TimeoutError):self.approved(self.intent())
        self.assertEqual(self.transport.comment_posts,1)
        self.assertEqual(self.adapter.visual_evidence(self.rev_id)['uploadedFiles'],1)
        self.assertIsNone(self.adapter.visual_evidence(self.rev_id)['commentId'])
        self.transport.request=real
        with self.assertRaises(Denied):self.approved(self.intent())
        fresh=str(uuid.uuid4());self.stage(fresh,self.rev)
        with self.assertRaises(Denied):self.approved(self.intent(fresh,self.rev))
        self.assertEqual(self.transport.comment_posts,1)

    def test_incomplete_previous_revision_blocks_next_version(self):
        real=self.transport.request
        def lost(method,path,**kwargs):
            result=real(method,path,**kwargs)
            if method=='POST' and path.endswith('/comments'):
                raise TimeoutError('late response lost')
            return result
        self.transport.request=lost
        with self.assertRaises(TimeoutError):self.approved(self.intent())
        self.transport.request=real
        third=str(uuid.uuid4());p=self.revision_params('third-run',3)
        self.stage(third,p)
        with self.assertRaisesRegex(Denied,'GITHUB_REVISION_PREVIOUS_UNCONFIRMED'):
            self.approved(self.intent(third,p))
        self.assertEqual(self.transport.comment_posts,1)

    def test_missing_final_readback_receipt_blocks_v3(self):
        original=self.transport.request
        def lost(method,path,**kwargs):
            if method=='GET' and '/issues/comments/' in path:
                raise TimeoutError('readback lost after comment created')
            return original(method,path,**kwargs)
        self.transport.request=lost
        with self.assertRaises(TimeoutError):self.approved(self.intent())
        self.assertEqual(self.transport.comment_posts,1)
        self.assertIsNone(self.adapter.receipt(self.rev_id))
        self.assertEqual(self.adapter.visual_evidence(self.rev_id)['commentId'],778)
        self.transport.request=original
        ident=str(uuid.uuid4());p=self.revision_params('third-after-lost-readback',3)
        self.stage(ident,p)
        with self.assertRaisesRegex(Denied,'GITHUB_REVISION_PREVIOUS_UNCONFIRMED'):
            self.approved(self.intent(ident,p))
        self.assertEqual(self.transport.comment_posts,1)

    def test_previous_core_uncertain_blocks_v3_even_with_receipt(self):
        self.approved(self.intent())
        self.core.rows[self.rev_id]['state']='UNCERTAIN'
        ident=str(uuid.uuid4());p=self.revision_params('third-after-uncertain',3)
        self.stage(ident,p)
        with self.assertRaisesRegex(Denied,'GITHUB_REVISION_PREVIOUS_UNCONFIRMED'):
            self.approved(self.intent(ident,p))
        self.assertEqual(self.transport.comment_posts,1)

    def test_deleted_prior_comment_blocks_next_version(self):
        self.approved(self.intent())
        self.transport.comments.pop(778)
        third=str(uuid.uuid4());p=self.revision_params('third-run',3)
        self.stage(third,p)
        with self.assertRaises((Denied,KeyError)):
            self.approved(self.intent(third,p))
        self.assertEqual(self.transport.comment_posts,1)

    def test_changed_previous_comment_url_blocks_v3(self):
        self.approved(self.intent())
        self.transport.comments[778]['html_url']='https://github.com/PilotOwner/visual-workspace/issues/99#issuecomment-778'
        ident=str(uuid.uuid4());p=self.revision_params('third-after-moved-comment',3)
        self.stage(ident,p)
        with self.assertRaisesRegex(Denied,'GITHUB_REVISION_PREVIOUS_COMMENT_CHANGED'):
            self.approved(self.intent(ident,p))
        self.assertEqual(self.transport.comment_posts,1)

    def test_client_previews_locally_and_stages_once(self):
        folder=self.media/'second-run';folder.mkdir()
        file=folder/'preview.png';file.write_bytes(PNG)
        calls=[]
        class Gateway:
            def post(self,path,body,*,accept_202=False):
                calls.append((path,body))
                if path.endswith('/stage'):
                    return {k:body[k] for k in ('index','name','sha256')}|{'size':len(PNG)}
                return dict(requestId=body['requestId'],state='PENDING')
        client=GitHubClient(gateway=Gateway())
        from fortis_approvals.integrations.github.repo_client import client as module
        kwargs=dict(repository=REPO,issue_number=42,base_run_id=RUN,
            asset_id='scanner-drone',revision=2,run_id='second-run',source_sha='a'*40,
            description='Adjusted antenna',media=[dict(path=str(file),name='Preview')],
            qa_summary='PASS Godot capture',duration_seconds=77)
        with patch.object(module,'WORKFILES_ROOT',self.media):
            pre=client.prepare_visual_revision(**kwargs)
            self.assertEqual(calls,[])
            with self.assertRaises(Denied):
                client.append_visual_revision(**kwargs,request_id=self.rev_id,
                    reason='append',expected_payload_sha256='0'*64)
            self.assertEqual(calls,[])
            result=client.append_visual_revision(**kwargs,request_id=self.rev_id,
                reason='append',expected_payload_sha256=pre['payloadSha256'])
        self.assertEqual(result['state'],'PENDING')
        self.assertEqual([x[0] for x in calls],['/v1/github/visual-review/stage','/v1/actions'])
        self.assertEqual(calls[1][1]['operation'],'append_visual_revision')
        self.assertEqual(calls[1][1]['params']['issueNumber'],42)


if __name__=='__main__':unittest.main()

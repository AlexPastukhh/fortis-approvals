"""Real Git bundles/worktrees and real TLS/Core/WebAuthn; upstream Git is a local fixture."""
import base64
from contextlib import contextmanager
import json
import os
from pathlib import Path
import subprocess
import tempfile
from threading import Thread, RLock
import time
import unittest
from unittest.mock import patch
from urllib.parse import unquote
import uuid

from fortis_approvals.core import Denied
from fortis_approvals.integrations.github.pilot import GitHubPilotConfig
from fortis_approvals.workflow.common import Git
from fortis_approvals.workflow.git_backend import GitHubGitBackend
from fortis_approvals.workflow.worker import Worker
from fortis_approvals.workflow.client import WorkflowClient, WorkflowTransport
import test_github_pilot as m1


def git(root,*args):
    env={**os.environ,'GIT_CONFIG_NOSYSTEM':'1','GIT_CONFIG_GLOBAL':'/dev/null','GIT_TERMINAL_PROMPT':'0'}
    r=subprocess.run(['git','-c','credential.helper=','-c','core.hooksPath=/dev/null',*args],
        cwd=root,env=env,capture_output=True)
    if r.returncode:raise AssertionError(r.stderr.decode(errors='replace'))
    return r.stdout.decode().strip()


class LocalBackend(GitHubGitBackend):
    """Test-only file upstream; never selectable from an HTTP request or environment."""
    def __init__(self,root,remote):
        self.root=Path(root);self.root.mkdir(mode=0o700)
        self.remote=Path(remote);self.owner='PilotOwner';self.repositories={'sandbox'}
        self.git=Git(self.root/'runner',protocols='file');self.pushes=0;self.race=False;self.lock=RLock()
    def url(self,repo):
        if repo!='sandbox':raise Denied('GIT_REPOSITORY_DENIED')
        return str(self.remote)
    @contextmanager
    def credentials(self,repo):yield None
    def _fetch(self,repo,bare,ref,dest,config):
        self.git.run(['fetch','--no-tags','--no-write-fetch-head',self.url(repo),'refs/heads/'+ref+':'+dest],cwd=bare)
    def push(self,*args):
        self.pushes+=1
        return super().push(*args)


class GitFixture:
    def __init__(self,root):
        self.root=Path(root);self.remote=self.root/'remote.git';self.primary=self.root/'Repos'/'sandbox'
        self.worktrees=self.root/'Worktrees'/'sandbox';self.worktrees.mkdir(parents=True)
        seed=self.root/'seed';seed.mkdir()
        git(seed,'init','-b','main')
        git(seed,'config','user.name','Offline Owner');git(seed,'config','user.email','offline@example.invalid')
        (seed/'README.md').write_text('base\n')
        (seed/'delete.txt').write_text('delete me\n')
        git(seed,'add','README.md','delete.txt');git(seed,'commit','-m','base')
        git(self.root,'clone','--bare',str(seed),str(self.remote))
        git(self.remote,'config','user.name','Offline Owner');git(self.remote,'config','user.email','offline@example.invalid')
        self.primary.parent.mkdir()
        git(self.root,'clone',str(self.remote),str(self.primary))
        git(self.primary,'remote','set-url','origin','https://github.com/PilotOwner/sandbox.git')
        git(self.primary,'config','user.name','Offline Owner');git(self.primary,'config','user.email','offline@example.invalid')
        self.base=git(self.primary,'rev-parse','HEAD')
        self.backend=LocalBackend(self.root/'gateway-git',self.remote)
        self.helper_marker=self.root/'HELPER_MUST_NOT_RUN'
        helper=self.root/'helper';helper.write_text('#!/bin/sh\ntouch '+str(self.helper_marker)+'\nexit 1\n');helper.chmod(0o700)
        git(self.primary,'config','credential.helper',str(helper))


class FakeAPI:
    def __init__(self,fixture):
        self.fixture=fixture;self.backend=fixture.backend;self.pulls={};self.ci_status='success';self.posts=0
    def request(self,method,path,*,params=None,body=None,expected_statuses=(200,),allow_not_found=False):
        # Exercise the real closed HTTP catalogue even with the offline upstream.
        from fortis_approvals.integrations.github.gateway.transport import GitHubHTTPTransport
        if not GitHubHTTPTransport._route_allowed(method,path):raise Denied('GITHUB_HTTP_ROUTE_DENIED')
        base='/repos/PilotOwner/sandbox'
        refs=self.backend.refs('sandbox')
        if method=='GET' and path==base:return dict(name='sandbox',full_name='PilotOwner/sandbox',private=True,
            default_branch='main',archived=False,disabled=False,html_url='https://github.com/PilotOwner/sandbox',pushed_at=None)
        if method=='GET' and path==base+'/branches':
            rows=[dict(name=k,commit={'sha':v},protected=k=='main') for k,v in refs.items()]
            n=(params['page']-1)*params['per_page'];return rows[n:n+params['per_page']]
        if method=='GET' and path.startswith(base+'/git/ref/heads/'):
            name=unquote(path.split('/git/ref/heads/')[1])
            if name not in refs and allow_not_found:return {'_httpStatus':404}
            return {'object':{'sha':refs[name]}}
        if method=='GET' and path.startswith(base+'/compare/'):
            first,last=path.split('/compare/')[1].split('...')
            for commit in (first,last):
                found=subprocess.run(['git','cat-file','-e',commit+'^{commit}'],cwd=self.fixture.remote,capture_output=True)
                if found.returncode:
                    assert allow_not_found
                    return {'_httpStatus':404}
            common=git(self.fixture.remote,'merge-base',first,last)
            behind,ahead=map(int,git(self.fixture.remote,'rev-list','--left-right','--count',first+'...'+last).split())
            status='identical' if first==last else 'ahead' if not behind else 'behind' if not ahead else 'diverged'
            return dict(status=status,behind_by=behind,ahead_by=ahead,
                        base_commit={'sha':first},merge_base_commit={'sha':common})
        if method=='GET' and path.startswith(base+'/commits/') and path.endswith('/pulls'):
            head=path.split('/commits/')[1].split('/')[0]
            return [dict(number=pr['number']) for pr in self.pulls.values() if pr['head']['sha']==head]
        if method=='POST' and path==base+'/pulls':
            number=len(self.pulls)+1;self.posts+=1
            self.pulls[number]=dict(number=number,node_id='PR_fixture_'+str(number),title=body['title'],state='open',
                draft=body['draft'],merged=False,body=body['body'],head=dict(ref=body['head'],sha=refs[body['head']],repo={'full_name':'PilotOwner/sandbox'}),
                base=dict(ref=body['base'],sha=refs[body['base']],repo={'full_name':'PilotOwner/sandbox'}),html_url='https://github.com/PilotOwner/sandbox/pull/'+str(number))
            return self.pulls[number]
        if method=='PATCH' and path.startswith(base+'/pulls/'):
            number=int(path.rsplit('/',1)[1]);assert set(body)=={'body'}
            self.pulls[number]['body']=body['body'];self.posts+=1
            return self.pulls[number]
        if method=='GET' and path==base+'/pulls':return list(self.pulls.values())
        if method=='GET' and path.startswith(base+'/pulls/'):return self.pulls[int(path.rsplit('/',1)[1])]
        if method=='GET' and path==base+'/actions/runs':
            return dict(total_count=1,workflow_runs=[dict(id=888,workflow_id=101,head_sha=params['head_sha'],
                head_branch=next(x['head']['ref'] for x in self.pulls.values() if x['head']['sha']==params['head_sha']),
                event='pull_request',status='completed' if self.ci_status!='pending' else 'in_progress',
                conclusion=self.ci_status if self.ci_status!='pending' else None,run_number=1,run_attempt=1)])
        if method=='PUT' and path.endswith('/merge'):
            pr=self.pulls[int(path.split('/')[-2])]
            assert body['sha']==pr['head']['sha'] and body['merge_method']=='merge' and not pr['draft']
            old=refs['main'];tree=git(self.fixture.remote,'rev-parse',pr['head']['sha']+'^{tree}')
            merged=git(self.fixture.remote,'commit-tree',tree,'-p',old,'-p',pr['head']['sha'],'-m','Offline merge')
            git(self.fixture.remote,'update-ref','refs/heads/main',merged,old)
            pr['state']='closed';pr['merged']=True;self.posts+=1
            return dict(merged=True,sha=merged)
        raise AssertionError((method,path))
    def mark_ready(self,node):
        row=next(x for x in self.pulls.values() if x['node_id']==node)
        row['draft']=False;self.posts+=1


class NativeTLS(unittest.TestCase):
    owner_call=m1.PilotTLSWebAuthnTests.owner_call
    login=m1.PilotTLSWebAuthnTests.login
    decide=m1.PilotTLSWebAuthnTests.decide
    stop=m1.PilotTLSWebAuthnTests.stop

    def setUp(self):
        tmp=tempfile.TemporaryDirectory(prefix='native-git-fixture-');self.addCleanup(tmp.cleanup)
        self.fixture=GitFixture(tmp.name);self.api=FakeAPI(self.fixture)
        legacy='fortis-e2e/11111111-1111-4111-8111-111111111111-approve'
        config=GitHubPilotConfig('PilotOwner','sandbox',file_pr_branch=legacy,ci_reads=True,native_worktree=True,required_workflows=(101,))
        with patch('test_github_pilot.CONFIG',config),patch('test_github_pilot.FakeGitHub',return_value=self.api),\
             patch('fortis_approvals.workflow.runtime.GitHubGitBackend',return_value=self.fixture.backend):
            m1.PilotTLSWebAuthnTests.setUp(self)
        self.gateway=WorkflowTransport(endpoint='https://host.docker.internal:19204',allow_test_endpoint=True,
            grant_path=self.grant,certificate_path=self.cert)
        self.worker=Worker(owner='PilotOwner',repositories={'sandbox':self.fixture.primary},
            worktrees={'sandbox':self.fixture.worktrees},gateway=self.gateway)
        self.flow=WorkflowClient(gateway=self.gateway,worker=self.worker)

    def test_visual_issues_capabilities_are_policy_scoped(self):
        capabilities=self.gateway.post('/v1/workspace/capabilities',{})
        self.assertEqual(capabilities['visualReview']['repository'],'visual-workspace')
        self.assertEqual(capabilities['visualReview']['publishPolicy'],'ALLOW')
        self.assertEqual(capabilities['visualReview']['attachmentReadback'],'markdown-links-only')
        self.assertEqual(capabilities['githubIssueReads'],
                         ['list_issues','get_issue','list_issue_comments'])
        self.assertIn('publish_visual_review',capabilities['allowGitHub'])
        self.assertNotIn('publish_visual_review',capabilities['askGitHub'])
        self.assertIn('merge_pull_request',capabilities['askGitHub'])
        # The dynamic repo pilot fixture uses sandbox; no auto-publish to other repos.
        self.assertNotIn('publish_visual_review',capabilities['workspaceOperations'])

    def command(self,op,p,ident=None):
        out=self.flow.command(op,'sandbox',p,request_id=ident or str(uuid.uuid4()),reason='Offline authorized worktree task')
        self.assertEqual(out['state'],'EXECUTED',out)
        return out['result']['data']

    def create(self,task='real-cycle'):
        return self.command('create_task',dict(task=task,baseSha=self.fixture.base,adoptHeadSha=None))

    def edit_commit(self,task='real-cycle',sensitive=False):
        state=self.command('inspect',dict(task=task))
        changes=[dict(path='binary.dat',content=base64.b64encode(bytes(range(256))).decode(),delete=False,executable=False),
                 dict(path='delete.txt',content='',delete=True,executable=False),
                 dict(path='run.sh',content=base64.b64encode(b'#!/bin/sh\necho fixture\n').decode(),delete=False,executable=True)]
        if sensitive:changes=[dict(path='.github/workflows/new.yml',content=base64.b64encode(b'name: fixture\n').decode(),delete=False,executable=False)]
        state=self.command('edit',dict(task=task,expectedHeadSha=state['headSha'],expectedTreeSha256=state['treeSha256'],changes=changes))
        state=self.command('stage',dict(task=task,expectedHeadSha=state['headSha'],expectedTreeSha256=state['treeSha256'],paths=[x['path'] for x in changes]))
        return self.command('commit',dict(task=task,expectedHeadSha=state['headSha'],expectedIndexSha256=state['indexSha256'],message='Offline real Git commit'))

    def test_closed_incident_is_terminal_for_resume_no_claim_or_retry(self):
        ident=str(uuid.uuid4())
        finished=self.flow.command('inspect','sandbox',dict(task=None),
            request_id=ident,reason='Offline closed request resume regression')
        self.assertEqual(finished['state'],'EXECUTED')
        with self.core._db() as db:
            db.execute("UPDATE requests SET state='CLOSED_UNCONFIRMED' WHERE id=?",(ident,))
        original_post=self.gateway.post
        def no_claim(path,body,**kw):
            if path=='/v1/workspace/claim':
                raise AssertionError('A closed incident must never be claimed')
            return original_post(path,body,**kw)
        with patch.object(self.gateway,'post',side_effect=no_claim):
            row=self.flow.resume(ident)
        self.assertEqual(row['state'],'CLOSED_UNCONFIRMED')

    def test_ai_full_details_reuses_authenticated_tls_and_does_not_replay(self):
        ident=str(uuid.uuid4())
        response=self.flow.command('inspect','sandbox',dict(task=None),
            request_id=ident,reason='Offline machine read-only incident details regression')
        self.assertEqual(response['state'],'EXECUTED')
        before=self.core.events(ident)
        details=self.flow.details(ident,event_offset=0,event_limit=100)
        self.assertEqual(details['request']['requestId'],ident)
        self.assertEqual(details['request']['actor'],self.core._read(ident)['actor'])
        self.assertEqual(details['request']['preview'],self.core._read(ident)['preview'])
        self.assertEqual(details['request']['request']['operation'],'inspect')
        self.assertEqual(details['request']['state'],'EXECUTED')
        self.assertEqual(details['eventTotal'],len(before))
        self.assertEqual(details['worker']['state'],'DONE')
        self.assertIsNotNone(details['receipt'])
        self.assertEqual(details['receipt']['source'],'native-worker-job')
        self.assertNotIn('claim',details['worker'])
        self.assertEqual(self.flow.details(ident,event_offset=1,event_limit=1)['eventOffset'],1)
        self.assertEqual(self.core.events(ident),before)

    def test_pr_description_update_requires_owner_ask_and_registered_task(self):
        self.create()
        head=self.edit_commit()['headSha']
        self.flow.publish('sandbox','real-cycle',None,head,
                          request_id=str(uuid.uuid4()),reason='Publish PR metadata test')
        self.assertEqual(self.flow.github.create_pull_request(
            'sandbox','task/real-cycle','main','Review description',body='Old text',
            request_id=str(uuid.uuid4()),reason='Create bounded PR')['state'],'EXECUTED')
        cap=self.gateway.post('/v1/workspace/capabilities',{})
        self.assertIn('update_pull_request',cap['askGitHub'])
        self.assertNotIn('update_pull_request',cap['allowGitHub'])
        ident=str(uuid.uuid4())
        before=self.api.posts
        response=self.flow.github.update_pull_request(
            'sandbox',1,head,'Corrected release impact description',
            request_id=ident,reason='Fix PR metadata using typed Gateway ASK')
        self.assertEqual(response['state'],'PENDING')
        self.assertEqual(self.api.posts,before)
        self.assertEqual(self.api.pulls[1]['body'],'Old text')
        self.login()
        accepted=self.decide(ident,'approve')[1]
        self.assertEqual(accepted['state'],'EXECUTED')
        self.assertEqual(self.api.pulls[1]['body'],'Corrected release impact description')
        self.assertEqual(self.api.posts,before+1)
        self.assertEqual(self.flow.github.status(ident)['state'],'EXECUTED')
        self.assertEqual(self.flow.github.update_pull_request(
            'sandbox',1,head,'Corrected release impact description',
            request_id=ident,reason='Fix PR metadata using typed Gateway ASK')['state'],'EXECUTED')
        self.assertEqual(self.api.posts,before+1)
        rejected=self.flow.github.update_pull_request(
            'sandbox',1,head,'Disallowed without owner',
            request_id=str(uuid.uuid4()),reason='Owner must review exact changed body')
        self.assertEqual(rejected['state'],'PENDING')
        self.assertEqual(self.api.posts,before+1)
        with self.assertRaises(Denied):
            self.flow.github.update_pull_request(
                'foreign',1,head,'Another repo',
                request_id=str(uuid.uuid4()),reason='Wrong repository denied')
        self.assertEqual(self.api.posts,before+1)

    def test_full_actual_worktree_commit_push_pr_ci_merge_update_main(self):
        self.command('fetch',dict(ref='main',expectedSha=self.fixture.base))
        self.create();state=self.edit_commit()
        head=state['headSha'];ident=str(uuid.uuid4())
        p=self.flow.publish('sandbox','real-cycle',None,head,request_id=ident,reason='Publish actual commits automatically')
        self.assertEqual(p['state'],'EXECUTED')
        self.assertEqual(git(self.fixture.remote,'rev-parse','refs/heads/task/real-cycle'),head)
        self.assertEqual(git(self.fixture.remote,'show',head+':run.sh'),'#!/bin/sh\necho fixture')
        self.assertEqual(git(self.fixture.remote,'ls-tree',head,'run.sh').split()[0],'100755')
        self.assertEqual(git(self.fixture.remote,'ls-tree',head,'delete.txt'),'')
        raw=subprocess.check_output(['git','-C',str(self.fixture.remote),'show',head+':binary.dat'])
        self.assertEqual(raw,bytes(range(256)))
        self.assertEqual(self.flow.publish('sandbox','real-cycle',None,head,request_id=ident,
            reason='Publish actual commits automatically')['state'],'EXECUTED')
        self.assertEqual(self.fixture.backend.pushes,1)
        checked=self.command('check',dict(task='real-cycle',expectedHeadSha=head,profile='syntax'))
        self.assertTrue(checked['passed'])
        self.login()
        pr_id=str(uuid.uuid4())
        self.assertEqual(self.flow.github.create_pull_request('sandbox','task/real-cycle','main','Offline PR',draft=True,
            request_id=pr_id,reason='Create bounded native draft PR')['state'],'EXECUTED')
        self.assertIsNone(self.core._read(pr_id)['decision'])
        ready=str(uuid.uuid4())
        self.assertEqual(self.flow.github.mark_pr_ready('sandbox',1,head,request_id=ready,reason='Mark reviewed draft ready')['state'],'PENDING')
        self.assertEqual(self.decide(ready,'approve')[1]['state'],'EXECUTED')
        merge=str(uuid.uuid4())
        self.assertEqual(self.flow.github.merge_pull_request('sandbox',1,head,merge_method='merge',request_id=merge,
            reason='Merge exact successful CI head')['state'],'PENDING')
        self.assertEqual(self.decide(merge,'approve')[1]['state'],'EXECUTED')
        updated=self.command('update_main',dict(expectedHeadSha=self.fixture.base,mergeRequestId=merge))
        self.assertEqual(updated['headSha'],git(self.fixture.remote,'rev-parse','refs/heads/main'))
        self.assertEqual(git(self.fixture.primary,'branch','--show-current'),'main')
        self.assertFalse(self.fixture.helper_marker.exists())
        self.assertEqual(git(self.fixture.worktrees/'real-cycle','rev-parse','HEAD'),head)
        # Legacy mergeRequestId requests remain supported; merged cleanup is ALLOW.
        cleanup=str(uuid.uuid4())
        result=self.flow.command('cleanup_task','sandbox',
            dict(task='real-cycle',expectedHeadSha=head,mergeRequestId=merge),request_id=cleanup,
            reason='Remove only this merged clean worktree')
        self.assertEqual(result['state'],'EXECUTED',result)
        self.assertIsNone(self.core._read(cleanup)['decision'])
        self.assertFalse((self.fixture.worktrees/'real-cycle').exists())
        with self.assertRaises(Denied):
            self.machine.get_app().github.task('sandbox','real-cycle')

    def _cleanup(self,head,*,ident=None,task='real-cycle',wait_owner=False):
        return self.flow.cleanup_task('sandbox',task,head,request_id=ident or str(uuid.uuid4()),
                                      reason='Fixture exact task cleanup',wait_owner=wait_owner)

    def _publish_cleanup_fixture(self,*,squash=False):
        self.create();head=self.edit_commit()['headSha']
        self.flow.publish('sandbox','real-cycle',None,head,request_id=str(uuid.uuid4()),reason='Fixture publish')
        self.flow.github.create_pull_request('sandbox','task/real-cycle','main','Cleanup fixture',draft=False,
            request_id=str(uuid.uuid4()),reason='Owner reviews cleanup fixture')
        if squash:
            tree=git(self.fixture.remote,'rev-parse',head+'^{tree}')
            merged=git(self.fixture.remote,'commit-tree',tree,'-p',self.fixture.base,'-m','Squash fixture')
            git(self.fixture.remote,'update-ref','refs/heads/main',merged,self.fixture.base)
            self.api.pulls[1].update(state='closed',merged=True,draft=False,
                merged_at='2026-11-07T19:00:00Z',merge_commit_sha=merged)
        else:merged=self._owner_ui_merged_pr(head)
        return head,merged

    def test_cleanup_merged_ui_pr_is_allow_with_lagging_local_main_and_replay(self):
        head,merged=self._publish_cleanup_fixture()
        # Main advanced again since merge; neither an old receipt nor exact local
        # main equality should keep a completed task forever.
        tree=git(self.fixture.remote,'rev-parse',merged+'^{tree}')
        current=git(self.fixture.remote,'commit-tree',tree,'-p',merged,'-m','Later main')
        git(self.fixture.remote,'update-ref','refs/heads/main',current,merged)
        ident=str(uuid.uuid4());result=self._cleanup(head,ident=ident)
        self.assertEqual(result['state'],'EXECUTED',result)
        row=self.core._read(ident)
        self.assertIsNone(row['decision']);self.assertIsNone(row['owner'])
        self.assertEqual(row['preview']['cleanup']['kind'],'ancestor')
        self.assertEqual(row['preview']['mergeSha'],current)  # Old workers fail closed on stale main.
        self.assertEqual(git(self.fixture.primary,'rev-parse','HEAD'),self.fixture.base)
        self.assertEqual(git(self.fixture.primary,'branch','--show-current'),'main')
        self.assertEqual(git(self.fixture.primary,'branch','--list','task/real-cycle'),'')
        self.assertEqual(self.fixture.backend.refs('sandbox')['task/real-cycle'],head)
        self.assertFalse((self.fixture.worktrees/'real-cycle').exists())
        self.assertEqual(self._cleanup(head,ident=ident)['state'],'EXECUTED')
        self.assertFalse(self.fixture.helper_marker.exists())
        self.assertEqual(self.gateway.post('/v1/workspace/capabilities',{})['cleanupTask'],
                         {'merged':'ALLOW','unmerged':'ASK','proof':'github-main-v1'})

    def test_cleanup_squash_pr_is_allow_only_with_exact_merged_pr_and_accepted_merge(self):
        head,_=self._publish_cleanup_fixture(squash=True)
        ident=str(uuid.uuid4());result=self._cleanup(head,ident=ident)
        self.assertEqual(result['state'],'EXECUTED',result)
        self.assertEqual(self.core._read(ident)['preview']['cleanup']['kind'],'pull_request')
        self.assertIsNone(self.core._read(ident)['decision'])

    def test_cleanup_unpublished_unmerged_requires_strong_owner_approval(self):
        self.create();head=self.edit_commit()['headSha']
        ident=str(uuid.uuid4());completed=[]
        thread=Thread(target=lambda:completed.append(self._cleanup(head,ident=ident,wait_owner=True)),daemon=True)
        thread.start();deadline=time.monotonic()+5
        while time.monotonic()<deadline:
            try:
                if self.core._read(ident)['state']=='PENDING':break
            except Denied:pass
            time.sleep(.02)
        self.assertEqual(self.core._read(ident)['state'],'PENDING')
        self.assertTrue((self.fixture.worktrees/'real-cycle').exists())
        self.login();self.assertEqual(self.decide(ident,'approve',uv=False)[0],403)
        self.assertEqual(self.decide(ident,'approve')[1]['state'],'EXECUTED')
        thread.join(timeout=10);self.assertFalse(thread.is_alive())
        self.assertEqual(completed[0]['state'],'EXECUTED')
        self.assertFalse((self.fixture.worktrees/'real-cycle').exists())
        self.assertEqual(git(self.fixture.primary,'branch','--list','task/real-cycle'),'')
        self.assertEqual(git(self.fixture.primary,'rev-parse','HEAD'),self.fixture.base)

    def test_cleanup_reject_and_policy_race_preserve_unmerged_task(self):
        self.create();head=self.edit_commit()['headSha'];ident=str(uuid.uuid4())
        self.assertEqual(self._cleanup(head,ident=ident)['state'],'PENDING')
        self.login();self.assertEqual(self.decide(ident,'reject')[1]['state'],'REJECTED')
        self.assertEqual(self._cleanup(head,ident=ident)['state'],'REJECTED')
        # An ASK cannot quietly turn into a different ALLOW intent after review.
        ident=str(uuid.uuid4());self.assertEqual(self._cleanup(head,ident=ident)['state'],'PENDING')
        self.flow.publish('sandbox','real-cycle',None,head,request_id=str(uuid.uuid4()),reason='Publish race fixture')
        git(self.fixture.remote,'update-ref','refs/heads/main',head,self.fixture.base)
        code,_,_=self.owner_call('/v1/owner/decision/begin',{'requestId':ident,'decision':'approve'})
        self.assertEqual(code,403)
        self.assertEqual(self.decide(ident,'reject')[1]['state'],'REJECTED')
        self.assertTrue((self.fixture.worktrees/'real-cycle').exists())

    def test_cleanup_never_removes_dirty_staged_untracked_or_ignored_files(self):
        self.create();target=self.fixture.worktrees/'real-cycle'
        # HEAD is already in main: these would be ALLOW without the local guards.
        actions=(('tracked',lambda:(target/'README.md').write_text('keep tracked')),
                 ('staged',lambda:((target/'README.md').write_text('keep index'),git(target,'add','README.md'))),
                 ('untracked',lambda:(target/'private.txt').write_text('keep untracked')),
                 ('ignored',lambda:((self.fixture.primary/'.git/info/exclude').write_text('private.txt\n'),
                                    (target/'private.txt').write_text('keep ignored'))))
        for name,change in actions:
            with self.subTest(name=name):
                change();result=self._cleanup(self.fixture.base)
                self.assertEqual(result['state'],'STALE',result)
                self.assertTrue(target.exists())
                self.assertEqual(git(target,'rev-parse','HEAD'),self.fixture.base)
                # Reset is only for this disposable test fixture.
                git(target,'reset','--hard',self.fixture.base)
                (target/'private.txt').unlink(missing_ok=True)
        self.assertEqual(git(self.fixture.primary,'rev-parse','HEAD'),self.fixture.base)

    def test_cleanup_wrong_head_locked_worktree_and_bootstrap_are_retained(self):
        self.create();target=self.fixture.worktrees/'real-cycle'
        self.assertEqual(self._cleanup('f'*40)['state'],'PENDING')
        # A changed head is never deleted, including after explicit approval.
        job=dict(operation='cleanup_task',target='sandbox',params={'task':'real-cycle','expectedHeadSha':'f'*40})
        root,_,run,text=self.worker._open('sandbox')
        from fortis_approvals.core import Stale
        with self.assertRaises(Stale):self.worker._prepare(job,root,run,text)
        git(self.fixture.primary,'worktree','lock',str(target))
        self.assertEqual(self._cleanup(self.fixture.base)['state'],'STALE')
        self.assertTrue(target.exists())
        from dataclasses import replace
        github=self.machine.get_app().github;bootstrap='protected-source'
        self.create(bootstrap)
        with patch.object(github,'config',replace(github.config,bootstrap_task=bootstrap)):
            with self.assertRaises(Denied):self._cleanup(self.fixture.base,task=bootstrap)
        with self.assertRaises(Denied):self._cleanup(self.fixture.base,task='missing')

    def test_cleanup_unconfirmed_or_mismatched_squash_proof_stays_ask(self):
        head,merged=self._publish_cleanup_fixture(squash=True);pr=self.api.pulls[1]
        variants=[{'merged':False},{'merge_commit_sha':head},
                  {'head':{**pr['head'],'sha':self.fixture.base}},
                  {'head':{**pr['head'],'ref':'task/other'}},
                  {'base':{**pr['base'],'repo':{'full_name':'OtherOwner/sandbox'}}}]
        for fields in variants:
            with self.subTest(fields=fields),patch.dict(pr,fields):
                ident=str(uuid.uuid4());self.assertEqual(self._cleanup(head,ident=ident)['state'],'PENDING')
                self.assertEqual(self.core._read(ident)['preview']['cleanup']['kind'],'unmerged')
        self.assertTrue((self.fixture.worktrees/'real-cycle').exists())

    def test_cleanup_rechecks_remote_main_before_any_local_removal(self):
        self.create();original=self.worker._prepare
        def race(job,root,run,text):
            if job['operation']=='cleanup_task':
                tree=git(self.fixture.remote,'rev-parse',self.fixture.base+'^{tree}')
                newer=git(self.fixture.remote,'commit-tree',tree,'-p',self.fixture.base,'-m','Race remote main')
                git(self.fixture.remote,'update-ref','refs/heads/main',newer,self.fixture.base)
            return original(job,root,run,text)
        with patch.object(self.worker,'_prepare',side_effect=race):
            self.assertEqual(self._cleanup(self.fixture.base)['state'],'STALE')
        self.assertTrue((self.fixture.worktrees/'real-cycle').exists())

    def test_cleanup_rechecks_ignored_files_after_fetch_and_before_removal(self):
        self.create();target=self.fixture.worktrees/'real-cycle';original=self.worker._execute
        (self.fixture.primary/'.git/info/exclude').write_text('late-private.txt\n')
        def race(job,root,run,text):
            if job['operation']=='cleanup_task':(target/'late-private.txt').write_text('preserve late ignored file')
            return original(job,root,run,text)
        ident=str(uuid.uuid4())
        with patch.object(self.worker,'_execute',side_effect=race):
            result=self._cleanup(self.fixture.base,ident=ident)
        self.assertEqual(result['state'],'UNCERTAIN',result)
        self.assertEqual((target/'late-private.txt').read_text(),'preserve late ignored file')
        self.assertEqual(self.flow.result(ident,reconcile=True)['state'],'UNCERTAIN')
        self.assertEqual(git(target,'rev-parse','HEAD'),self.fixture.base)

    def test_new_worker_preserves_old_gateway_cleanup_job_contract(self):
        self.create();head=self.edit_commit()['headSha']
        # Disposable local fixture emulates an admitted old server job.
        git(self.fixture.primary,'merge','--ff-only',head)
        ident=str(uuid.uuid4());params=dict(task='real-cycle',expectedHeadSha=head,mergeRequestId=str(uuid.uuid4()))
        preview=dict(operation='cleanup_task',repository='sandbox',params=params,mergeSha=head)
        payload=dict(requestId=ident,operation='cleanup_task',target='sandbox',params=params,approvedPreview=preview)
        result,error=self.worker.execute({'payload':payload})
        self.assertIsNone(error);self.assertTrue(result['data']['removed'])
        self.assertEqual(self.worker.execute({'payload':payload}),(result,None))

    def test_cleanup_scope_unknown_fields_and_invalid_compare_never_allow(self):
        self.create();workspace=self.machine.get_app().workspace
        payload=dict(service='workspace',operation='cleanup_task',target='sandbox',
                     params=dict(task='real-cycle',expectedHeadSha=self.fixture.base))
        self.assertEqual(workspace.cleanup_policy('other-actor',payload),'DENY')
        for extra in ({'merged':True},{'force':True}):
            with self.assertRaises(Denied):
                self.flow.command('cleanup_task','sandbox',{**payload['params'],**extra},
                    request_id=str(uuid.uuid4()),reason='Reject caller authorization')
        original=self.api.request
        def invalid(method,path,**kwargs):
            if '/compare/' in path:return dict(status='ahead',behind_by=0,base_commit={'sha':'f'*40},
                                              merge_base_commit={'sha':self.fixture.base})
            return original(method,path,**kwargs)
        with patch.object(self.api,'request',side_effect=invalid),self.assertRaises(Denied):
            self._cleanup(self.fixture.base)
        self.assertTrue((self.fixture.worktrees/'real-cycle').exists())

    def test_create_task_refuses_dirty_primary_without_losing_user_changes(self):
        # A task based on committed main would silently omit these files.
        primary=self.fixture.primary
        (primary/'README.md').write_text('preserve tracked local change\n')
        (primary/'OWNER-NOTE.txt').write_text('preserve untracked local change\n')
        before=git(primary,'status','--porcelain=v1','--untracked-files=all')
        result=self.flow.command('create_task','sandbox',
            dict(task='dirty-primary-isolated',baseSha=self.fixture.base,adoptHeadSha=None),
            request_id=str(uuid.uuid4()),reason='Reject task creation on dirty canonical main')
        self.assertEqual(result['state'],'STALE',result)
        self.assertEqual(git(primary,'status','--porcelain=v1','--untracked-files=all'),before)
        self.assertEqual((primary/'README.md').read_text(),'preserve tracked local change\n')
        self.assertEqual((primary/'OWNER-NOTE.txt').read_text(),'preserve untracked local change\n')
        self.assertEqual(git(primary,'rev-parse','HEAD'),self.fixture.base)
        self.assertFalse((self.fixture.worktrees/'dirty-primary-isolated').exists())
        self.assertFalse(git(primary,'branch','--list','task/dirty-primary-isolated'))

    def test_create_task_refuses_staged_primary_without_unstaging(self):
        primary=self.fixture.primary
        (primary/'README.md').write_text('staged owner change\n')
        git(primary,'add','README.md')
        before=git(primary,'diff','--cached')
        result=self.flow.command('create_task','sandbox',
            dict(task='staged-primary-denied',baseSha=self.fixture.base,adoptHeadSha=None),
            request_id=str(uuid.uuid4()),reason='Protect staged main changes')
        self.assertEqual(result['state'],'STALE',result)
        self.assertEqual(git(primary,'diff','--cached'),before)
        self.assertFalse((self.fixture.worktrees/'staged-primary-denied').exists())

    def _owner_ui_merged_pr(self,head,*,login='PilotOwner'):
        ref='refs/heads/main'
        original=git(self.fixture.remote,'rev-parse',ref)
        tree=git(self.fixture.remote,'rev-parse',head+'^{tree}')
        merged=git(self.fixture.remote,'commit-tree',tree,'-p',original,'-p',head,'-m','Owner GitHub UI merge fixture')
        git(self.fixture.remote,'update-ref',ref,merged,original)
        pr=self.api.pulls[1]
        pr.update(state='closed',merged=True,merged_at='2026-11-07T15:00:00Z',
                  merged_by={'login':login},merge_commit_sha=merged)
        return merged

    def test_owner_github_ui_merge_can_fast_forward_clean_main_via_typed_api(self):
        self.create();state=self.edit_commit();head=state['headSha']
        self.flow.publish('sandbox','real-cycle',None,head,request_id=str(uuid.uuid4()),reason='Publish for owner GitHub merge')
        self.flow.github.create_pull_request('sandbox','task/real-cycle','main','Owner reviewed',draft=False,
            request_id=str(uuid.uuid4()),reason='Owner merge workflow')
        merged=self._owner_ui_merged_pr(head)
        ident=str(uuid.uuid4())
        params=dict(expected_head_sha=self.fixture.base,number=1,
                    expected_pr_head_sha=head,expected_merge_sha=merged,
                    request_id=ident,reason='Read-only owner GitHub PR proof and local safe fast-forward')
        response=self.flow.update_main_from_pr('sandbox',**params)
        self.assertEqual(response['state'],'EXECUTED',response)
        self.assertEqual(response['result']['data']['headSha'],merged)
        self.assertEqual(git(self.fixture.primary,'rev-parse','HEAD'),merged)
        self.assertEqual(git(self.fixture.primary,'status','--porcelain'),'')
        self.assertFalse(self.fixture.helper_marker.exists())
        self.assertEqual(self.flow.update_main_from_pr('sandbox',**params)['state'],'EXECUTED')

    def test_owner_external_merge_proof_must_be_exact_and_owner_merged(self):
        self.create();state=self.edit_commit();head=state['headSha']
        self.flow.publish('sandbox','real-cycle',None,head,request_id=str(uuid.uuid4()),reason='Publish external merge fixture')
        self.flow.github.create_pull_request('sandbox','task/real-cycle','main','Owner merge preview',draft=False,
            request_id=str(uuid.uuid4()),reason='Ready for external merge')
        params=dict(expectedHeadSha=self.fixture.base,number=1,
                    expectedPrHeadSha=head,expectedMergeSha='a'*40)
        # An open PR is not a merge: a typed command may not update main.
        with self.assertRaises(Denied):
            self.flow.command('update_main_from_pr','sandbox',params,request_id=str(uuid.uuid4()),reason='Must reject open PR')
        merged=self._owner_ui_merged_pr(head,login='untrusted-actor')
        params['expectedMergeSha']=merged
        with self.assertRaises(Denied):
            self.flow.command('update_main_from_pr','sandbox',params,request_id=str(uuid.uuid4()),reason='Must reject non-owner merge')
        self.api.pulls[1]['merged_by']={'login':'PilotOwner'}
        with self.assertRaises(Denied):
            self.flow.command('update_main_from_pr','sandbox',{**params,'expectedPrHeadSha':'f'*40},request_id=str(uuid.uuid4()),reason='Must reject wrong PR SHA')
        with self.assertRaises(Denied):
            self.flow.command('update_main_from_pr','sandbox',{**params,'expectedMergeSha':'f'*40},request_id=str(uuid.uuid4()),reason='Must reject wrong merge SHA')
        with self.assertRaises(Denied):
            self.flow.command('update_main_from_pr','sandbox',{**params,'number':0},request_id=str(uuid.uuid4()),reason='Must reject unknown PR')
        self.assertEqual(git(self.fixture.primary,'rev-parse','HEAD'),self.fixture.base)
        (self.fixture.primary/'README.md').write_text('dirty: preserve this!\n')
        result=self.flow.command('update_main_from_pr','sandbox',params,request_id=str(uuid.uuid4()),reason='Must not change dirty primary')
        self.assertEqual(result['state'],'STALE',result)
        self.assertEqual(git(self.fixture.primary,'rev-parse','HEAD'),self.fixture.base)
        self.assertEqual((self.fixture.primary/'README.md').read_text(),'dirty: preserve this!\n')

    def test_regular_pr_allow_is_exact_actor_repo_without_owner_and_replays_once(self):
        self.create();state=self.edit_commit()
        self.flow.publish('sandbox','real-cycle',None,state['headSha'],request_id=str(uuid.uuid4()),reason='Publish regular PR fixture')
        capabilities=self.gateway.post('/v1/workspace/capabilities',{})
        self.assertIn('create_pull_request',capabilities['allowGitHub'])
        self.assertNotIn('create_pull_request',capabilities['askGitHub'])
        ident=str(uuid.uuid4())
        def create(title='Automatic bounded PR'):
            return self.flow.github.create_pull_request('sandbox','task/real-cycle','main',title,draft=False,
                request_id=ident,reason='Create PR without owner session')
        self.assertIsNone(self.cookie)
        self.assertEqual(create()['state'],'EXECUTED');row=self.core._read(ident)
        self.assertIsNone(row['decision']);self.assertIsNone(row['owner'])
        self.assertEqual(row['result']['pullRequest']['head']['sha'],state['headSha'])
        self.assertEqual(create()['state'],'EXECUTED');self.assertEqual(self.api.posts,1)
        with self.assertRaises(Denied):create('Different intent')
        self.assertEqual(self.api.posts,1)
        actor=row['actor'];query=dict(service='github',operation='create_pull_request',target='sandbox')
        self.assertEqual(self.core._policy('unrelated-actor',query),'DENY')
        self.assertEqual(self.core._policy(actor,{**query,'target':'foreign'}),'ASK')
        for service,operation in (('github','mark_pr_ready'),('github','merge_pull_request'),
                                  ('github','update_pull_request'),('github','update_workflow_file'),
                                  ('workspace','cleanup_task')):
            self.assertEqual(self.core._policy(actor,dict(service=service,operation=operation,target='sandbox')),'ASK')

    def test_pr_allow_rejects_foreign_repo_base_and_unregistered_branch(self):
        self.create()
        for repo,head,base in (('foreign','task/real-cycle','main'),('sandbox','task/missing','main'),
                              ('sandbox','task/real-cycle','task/other'),('sandbox','main','main')):
            with self.subTest(repo=repo,head=head,base=base),self.assertRaises(Denied):
                self.flow.github.create_pull_request(repo,head,base,'Denied PR',request_id=str(uuid.uuid4()),reason='Scope denial')
        self.assertEqual(self.api.posts,0)

    def test_pr_allow_lost_response_never_retries_post(self):
        self.create();state=self.edit_commit()
        self.flow.publish('sandbox','real-cycle',None,state['headSha'],request_id=str(uuid.uuid4()),reason='Publish lost response fixture')
        original=self.api.request
        def lose(method,path,**kwargs):
            result=original(method,path,**kwargs)
            if method=='POST' and path.endswith('/pulls'):raise TimeoutError('Offline lost PR response')
            return result
        ident=str(uuid.uuid4())
        with patch.object(self.api,'request',side_effect=lose):
            for _ in range(2):
                row=self.flow.github.create_pull_request('sandbox','task/real-cycle','main','Uncertain PR',
                    request_id=ident,reason='Same intent after lost response')
                self.assertEqual(row['state'],'UNCERTAIN')
        self.assertEqual(self.api.posts,1)
        self.assertEqual(self.flow.result(ident,reconcile=True)['state'],'UNCERTAIN')
        self.assertEqual(self.api.posts,1)

    def test_sensitive_workflow_in_native_push_requires_owner_and_replay(self):
        self.create();state=self.edit_commit(sensitive=True);ident=str(uuid.uuid4())
        out=self.flow.publish('sandbox','real-cycle',None,state['headSha'],request_id=ident,reason='Workflow changes need owner')
        self.assertEqual(out['state'],'PENDING');self.assertEqual(self.fixture.backend.pushes,0)
        self.login()
        self.assertEqual(self.decide(ident,'approve',uv=False)[0],403)
        self.assertEqual(self.decide(ident,'approve')[1]['state'],'EXECUTED')
        self.assertEqual(self.flow.publish('sandbox','real-cycle',None,state['headSha'],request_id=ident,
            reason='Workflow changes need owner')['state'],'EXECUTED')
        self.assertEqual(self.fixture.backend.pushes,1)

    def test_rejected_native_workflow_push_does_not_publish(self):
        self.create();state=self.edit_commit(sensitive=True);ident=str(uuid.uuid4())
        self.flow.publish('sandbox','real-cycle',None,state['headSha'],request_id=ident,reason='Reject workflow fixture')
        self.login();self.assertEqual(self.decide(ident,'reject')[1]['state'],'REJECTED')
        self.assertNotIn('task/real-cycle',self.fixture.backend.refs('sandbox'))

    def test_unregistered_worktree_and_outdated_workspace_digest_are_blocked(self):
        path=self.fixture.worktrees/'fake';path.mkdir()
        with self.assertRaises(Denied):self.worker.bundle('sandbox','fake',self.fixture.base)
        state=self.create()
        (self.fixture.worktrees/'real-cycle'/'README.md').write_text('unexpected external edit')
        out=self.flow.command('stage','sandbox',dict(task='real-cycle',expectedHeadSha=state['headSha'],
            expectedTreeSha256=state['treeSha256'],paths=['README.md']),request_id=str(uuid.uuid4()),reason='Must fail stale')
        self.assertEqual(out['state'],'STALE')
        self.assertEqual(git(self.fixture.worktrees/'real-cycle','diff','--cached'),'')

    def test_repeated_local_commit_request_does_not_create_another_commit(self):
        self.create();state=self.command('inspect',dict(task='real-cycle'))
        state=self.command('edit',dict(task='real-cycle',expectedHeadSha=state['headSha'],expectedTreeSha256=state['treeSha256'],
            changes=[dict(path='README.md',content=base64.b64encode(b'new text\n').decode(),delete=False,executable=False)]))
        state=self.command('stage',dict(task='real-cycle',expectedHeadSha=state['headSha'],expectedTreeSha256=state['treeSha256'],paths=['README.md']))
        ident=str(uuid.uuid4());params=dict(task='real-cycle',expectedHeadSha=state['headSha'],expectedIndexSha256=state['indexSha256'],message='Once only')
        first=self.command('commit',params,ident)
        second=self.command('commit',params,ident)
        self.assertEqual(first['headSha'],second['headSha'])
        self.assertIsNone(self.gateway.post('/v1/workspace/claim',dict(requestId=ident))['job'])
        self.assertEqual(git(self.fixture.worktrees/'real-cycle','rev-list','--count',self.fixture.base+'..HEAD'),'1')

    def test_push_cannot_force_update_or_publish_main(self):
        self.create();state=self.edit_commit();data=self.worker.bundle('sandbox','real-cycle',state['headSha'])
        # API branch is derived from the registered task, never supplied as a refspec.
        with self.assertRaises(Denied):
            self.gateway.post('/v1/git/artifact',dict(repository='sandbox',task='main',expectedHeadSha=None,
                newSha=state['headSha'],bundle=base64.b64encode(data).decode()))
        git(self.fixture.remote,'update-ref','refs/heads/task/real-cycle',self.fixture.base)
        with self.assertRaises(Denied):
            self.flow.publish('sandbox','real-cycle',None,state['headSha'],request_id=str(uuid.uuid4()),reason='Stale absent ref')
        self.assertEqual(git(self.fixture.remote,'rev-parse','refs/heads/task/real-cycle'),self.fixture.base)

    def test_failed_ci_blocks_merge_before_owner_proposal(self):
        self.create();state=self.edit_commit()
        self.flow.publish('sandbox','real-cycle',None,state['headSha'],request_id=str(uuid.uuid4()),reason='Normal native push')
        self.login();ident=str(uuid.uuid4())
        self.assertEqual(self.flow.github.create_pull_request('sandbox','task/real-cycle','main','Test PR',draft=False,
            request_id=ident,reason='Create non-draft')['state'],'EXECUTED')
        self.api.ci_status='failure'
        with self.assertRaises(Denied):
            self.flow.github.merge_pull_request('sandbox',1,state['headSha'],merge_method='merge',
                request_id=str(uuid.uuid4()),reason='Must not offer failed CI merge')
        self.assertEqual(git(self.fixture.remote,'rev-parse','refs/heads/main'),self.fixture.base)


    def test_reverted_workflow_change_in_intermediate_commit_still_requires_ask(self):
        self.create();state=self.edit_commit(sensitive=True)
        state=self.command('edit',dict(task='real-cycle',expectedHeadSha=state['headSha'],expectedTreeSha256=state['treeSha256'],
            changes=[dict(path='.github/workflows/new.yml',content='',delete=True,executable=False)]))
        state=self.command('stage',dict(task='real-cycle',expectedHeadSha=state['headSha'],expectedTreeSha256=state['treeSha256'],paths=['.github/workflows/new.yml']))
        state=self.command('commit',dict(task='real-cycle',expectedHeadSha=state['headSha'],expectedIndexSha256=state['indexSha256'],message='Revert workflow at tip'))
        out=self.flow.publish('sandbox','real-cycle',None,state['headSha'],request_id=str(uuid.uuid4()),reason='History still includes workflow change')
        self.assertEqual(out['state'],'PENDING');self.assertEqual(self.fixture.backend.pushes,0)

    def test_non_fast_forward_is_denied_even_with_matching_remote_lease(self):
        self.create();first=self.edit_commit()
        self.flow.publish('sandbox','real-cycle',None,first['headSha'],request_id=str(uuid.uuid4()),reason='Initial native publish')
        # Destructive command is only in this disposable negative fixture, never a public operation.
        target=self.fixture.worktrees/'real-cycle';git(target,'reset','--hard',self.fixture.base)
        (target/'README.md').write_text('divergent fixture')
        git(target,'add','README.md');git(target,'commit','-m','Divergent fixture')
        different=git(target,'rev-parse','HEAD')
        with self.assertRaises(Denied):
            self.flow.publish('sandbox','real-cycle',first['headSha'],different,request_id=str(uuid.uuid4()),reason='Must not rewrite task history')
        self.assertEqual(self.fixture.backend.refs('sandbox')['task/real-cycle'],first['headSha'])

    def test_atomic_remote_lease_race_is_uncertain_and_never_retried(self):
        self.create();first=self.edit_commit()
        self.flow.publish('sandbox','real-cycle',None,first['headSha'],request_id=str(uuid.uuid4()),reason='Initial publish')
        target=self.fixture.worktrees/'real-cycle';(target/'README.md').write_text('second native commit')
        git(target,'add','README.md');git(target,'commit','-m','Second commit')
        new=git(target,'rev-parse','HEAD');original=self.fixture.backend.git.run;raced=[]
        def race(args,**kwargs):
            if args[0]=='push' and not raced:
                tree=git(self.fixture.remote,'rev-parse',first['headSha']+'^{tree}')
                other=git(self.fixture.remote,'commit-tree',tree,'-p',first['headSha'],'-m','Concurrent publisher')
                git(self.fixture.remote,'update-ref','refs/heads/task/real-cycle',other,first['headSha'])
                raced.append(other)
            return original(args,**kwargs)
        ident=str(uuid.uuid4())
        with patch.object(self.fixture.backend.git,'run',side_effect=race):
            out=self.flow.publish('sandbox','real-cycle',first['headSha'],new,request_id=ident,reason='Atomic compare and swap')
        self.assertEqual(out['state'],'UNCERTAIN')
        before=self.fixture.backend.pushes
        self.assertEqual(self.flow.publish('sandbox','real-cycle',first['headSha'],new,request_id=ident,
            reason='Atomic compare and swap')['state'],'UNCERTAIN')
        self.assertEqual(self.fixture.backend.pushes,before)
        self.assertEqual(self.fixture.backend.refs('sandbox')['task/real-cycle'],raced[0])


    def test_sync_uses_gateway_fetch_and_rejects_custom_merge_driver(self):
        state=self.create()
        tree=git(self.fixture.remote,'rev-parse',self.fixture.base+'^{tree}')
        newer=git(self.fixture.remote,'commit-tree',tree,'-p',self.fixture.base,'-m','New upstream main')
        git(self.fixture.remote,'update-ref','refs/heads/main',newer,self.fixture.base)
        state=self.command('sync_task',dict(task='real-cycle',expectedHeadSha=state['headSha'],baseSha=newer))
        self.assertEqual(state['headSha'],newer)
        self.assertEqual(git(self.fixture.primary,'rev-parse','HEAD'),self.fixture.base)
        git(self.fixture.primary,'config','merge.synthetic.driver','touch '+str(self.fixture.helper_marker))
        out=self.flow.command('sync_task','sandbox',dict(task='real-cycle',expectedHeadSha=newer,baseSha=newer),
            request_id=str(uuid.uuid4()),reason='Custom driver must not execute')
        self.assertEqual(out['state'],'STALE')
        self.assertFalse(self.fixture.helper_marker.exists())


class NativeConfigTests(unittest.TestCase):
    def test_native_requires_explicit_opt_in_and_exact_required_ci(self):
        from fortis_approvals.integrations.github.pilot import config_from_environment
        partial={'FORTIS_GITHUB_NATIVE_WORKTREE':'1'}
        with self.assertRaises(ValueError):config_from_environment(partial)
        base=dict(owner='PilotOwner',repository='sandbox',
            file_pr_branch='fortis-e2e/11111111-1111-4111-8111-111111111111-approve',ci_reads=True)
        for required in ((),(0,),(True,),(101,101)):
            with self.assertRaises(ValueError):GitHubPilotConfig(**base,native_worktree=True,required_workflows=required)
        with self.assertRaises(ValueError):GitHubPilotConfig(**base,bootstrap_task='anything')
        self.assertEqual(GitHubPilotConfig(**base,native_worktree=True,required_workflows=(101,),
            bootstrap_task='source-bootstrap').bootstrap_task,'source-bootstrap')

    def test_uncertain_local_effect_only_reconciles_without_reexecution(self):
        from unittest.mock import Mock
        class Gateway:
            def post(self,path,body,**kwargs):
                if path.endswith('/claim'):return {'job':None}
                return dict(requestId=body.get('requestId'),state='UNCERTAIN',result=None,failure='unknown')
        worker=Mock();flow=WorkflowClient(gateway=Gateway(),worker=worker);ident=str(uuid.uuid4())
        self.assertEqual(flow.resume(ident)['state'],'UNCERTAIN')
        self.assertEqual(flow.command('commit','sandbox',{},request_id=ident,reason='Read existing uncertain result')['state'],'UNCERTAIN')
        worker.execute.assert_not_called()

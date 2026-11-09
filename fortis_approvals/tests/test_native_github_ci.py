"""Native GitHub CI diagnostics/controls without SonarCloud or provider access."""
from dataclasses import replace
import json
from io import BytesIO
from pathlib import Path
import tempfile
import unittest
import uuid
import zipfile
from types import SimpleNamespace

from fortis_approvals.core import Authenticator, Core, Denied
from fortis_approvals.integrations.github.analysis_contract import READ_NAMES, ACTION_NAMES
from fortis_approvals.integrations.github.pilot import config_from_environment, GitHubPilotConfig
from fortis_approvals.integrations.github.repo_client.client import GitHubClient
from fortis_approvals.workflow.adapters import NativeGitHubAdapter
from fortis_approvals.repo_action_contract import RepoIntentBroker
from fortis_approvals.workflow.runtime import install
from test_dynamic_github_repos import FakeTokenAccess, cfg

SHA = 'a'*40
ALT = 'b'*40
REPO = 'rd-graphs'


class FakeActions(FakeTokenAccess):
    def __init__(self):
        super().__init__()
        self.permitted.add(REPO)
        self.run=dict(id=9,run_attempt=2,workflow_id=17,path='.github/workflows/rdg-ci.yml',
            event='pull_request',status='completed',conclusion='failure',head_sha=SHA,
            head_branch='task/rdg',repository={'full_name':'PilotOwner/'+REPO},
            head_repository={'full_name':'PilotOwner/'+REPO},
            created_at='now',updated_at='now',pull_requests=[dict(
                number=3,head=dict(sha=SHA),base=dict(sha=ALT))])
        self.job=dict(id=5,run_id=9,run_attempt=2,head_sha=SHA,name='tests',status='completed',
            conclusion='failure',steps=[dict(number=1,name='Run tests',status='completed',conclusion='failure')])
        self.artifact=dict(id=4,name='fortis-sonar-analysis-9-2',size_in_bytes=100,
            expired=False,created_at='now',digest=None,
            workflow_run=dict(id=9,head_sha=SHA))
        self.manifest=dict(schemaVersion=1,repository='PilotOwner/'+REPO,workflowId=17,
            workflowPath='.github/workflows/rdg-ci.yml',runId=9,attempt=2,
            projectKey='SOME_UNVERIFIED_SONAR_PROJECT',context={'pullRequest':'3'},
            prHeadSha=SHA,checkoutSha=SHA,scannerRevision=SHA,ceTaskId='T1')
        self.controls=[]
    def request(self,method,path,*,params=None,body=None,expected_statuses=(200,),allow_not_found=False):
        if path==f'/repos/PilotOwner/{REPO}':
            return super().request(method,path,params=params,body=body,
                expected_statuses=expected_statuses,allow_not_found=allow_not_found)
        if f'/repos/PilotOwner/{REPO}/' not in path:
            return super().request(method,path,params=params,body=body,
                expected_statuses=expected_statuses,allow_not_found=allow_not_found)
        self.requests.append((method,path,params))
        if method=='POST':
            self.controls.append((path,body))
            return {'_httpStatus':201}
        if path.endswith('/actions/runs/9/attempts/2'):return dict(self.run)
        if path.endswith('/actions/runs/9'):return dict(self.run)
        if path.endswith('/actions/runs/9/attempts/2/jobs'):
            return {'total_count':1,'jobs':[dict(self.job)]}
        if path.endswith('/actions/jobs/5'):return dict(self.job)
        if path.endswith('/check-runs/6'):
            return dict(id=6,name='CI',head_sha=SHA,status='completed',conclusion='failure',
                app={'id':1,'slug':'github-actions'},
                output={'title':'Tests','summary':'Failure','text':None,'annotations_count':1})
        if path.endswith('/check-runs/6/annotations'):
            return [dict(path='src/x.py',start_line=3,end_line=3,annotation_level='failure',
                message='tests failed',title=None)]
        if path.endswith('/actions/runs/9/artifacts'):
            return dict(total_count=1,artifacts=[dict(self.artifact)])
        if path.endswith('/actions/artifacts/4'):return dict(self.artifact)
        if path.endswith('/actions/workflows/17'):
            return dict(id=17,state='active',path='.github/workflows/rdg-ci.yml')
        if path.endswith('/git/ref/heads/main'):return dict(object=dict(sha=SHA))
        if path.endswith('/contents/.github/workflows/rdg-ci.yml'):
            return dict(path='.github/workflows/rdg-ci.yml',type='file',sha=ALT)
        raise AssertionError((method,path,params))
    def download(self,path,*,maximum):
        if path.endswith('/logs'):return b'CI failure\nAssertionError: expected 1\n'
        out=BytesIO()
        with zipfile.ZipFile(out,'w') as z:
            z.writestr('analysis-manifest.json',json.dumps(self.manifest))
        return out.getvalue()
    def redact(self,value):return value


class NativeGitHubCITests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root=Path(temp.name)
        self.transport=FakeActions()
        self.adapter=NativeGitHubAdapter(self.transport,config=cfg(),root=self.root,
            actor='agent',backend=None,store=None)
    def query(self,operation,params,repo=REPO):
        return dict(service='github',operation=operation,target=repo,params=params)
    def test_all_ci_reads_work_without_sonar_project_binding(self):
        parameters={
            'get_workflow_run':dict(runId=9,attempt=2),
            'list_workflow_jobs':dict(runId=9,attempt=2,page=1,perPage=100),
            'get_job_log':dict(runId=9,attempt=2,jobId=5,offsetLines=0,maxLines=100),
            'get_check_run':dict(checkRunId=6,expectedHeadSha=SHA),
            'list_check_annotations':dict(checkRunId=6,expectedHeadSha=SHA,page=1,perPage=100),
            'list_run_artifacts':dict(runId=9,attempt=2,page=1,perPage=100),
            'get_analysis_manifest':dict(runId=9,attempt=2,artifactId=4)}
        self.assertEqual(set(parameters),READ_NAMES)
        results={operation:self.adapter.read(self.query(operation,params))
                 for operation,params in parameters.items()}
        self.assertEqual(results['get_workflow_run']['data']['run']['headSha'],SHA)
        self.assertEqual(results['list_workflow_jobs']['data']['items'][0]['steps'][0]['conclusion'],'failure')
        self.assertIn('AssertionError',results['get_job_log']['data']['text'])
        self.assertEqual(results['get_check_run']['data']['check']['conclusion'],'failure')
        self.assertEqual(results['list_check_annotations']['data']['items'][0]['path'],'src/x.py')
        self.assertEqual(results['list_run_artifacts']['data']['items'][0]['id'],4)
        self.assertEqual(results['get_analysis_manifest']['data']['trust'],'CI_RECORDED_NOT_SONAR_VERIFIED')
        self.assertEqual(results['get_analysis_manifest']['data']['manifest']['projectKey'],
                         'SOME_UNVERIFIED_SONAR_PROJECT')

    def test_all_reads_token_scoped_and_exact_run_job_sha(self):
        with self.assertRaises(Denied):
            self.adapter.read(self.query('get_workflow_run',dict(runId=9,attempt=2),'foreign'))
        self.transport.run['repository']['full_name']='attacker/rd-graphs'
        with self.assertRaisesRegex(Denied,'GITHUB_RUN_REPOSITORY_MISMATCH'):
            self.adapter.read(self.query('get_workflow_run',dict(runId=9,attempt=2)))
        self.transport.run['repository']['full_name']='PilotOwner/rd-graphs'
        self.transport.job['head_sha']=ALT
        with self.assertRaisesRegex(Denied,'GITHUB_JOB_ATTEMPT_MISMATCH'):
            self.adapter.read(self.query('get_job_log',dict(
                runId=9,attempt=2,jobId=5,offsetLines=0,maxLines=10)))

    def test_ci_controls_denied_by_default(self):
        with self.assertRaisesRegex(Denied,'GITHUB_CI_CONTROL_DISABLED'):
            self.adapter.prepare(self.query('rerun_failed_jobs',dict(
                runId=9,attempt=2,expectedHeadSha=SHA)))
        self.assertEqual(self.transport.controls,[])
        with self.assertRaises(ValueError):
            replace(cfg(),ci_control_repositories=('rd-graphs','rd-graphs'))
        with self.assertRaises(ValueError):
            replace(cfg(),ci_control_repositories=('bad/repo',))
        with self.assertRaises(ValueError):
            replace(cfg(dynamic=False),ci_control_repositories=('rd-graphs',))

    def test_explicit_ci_control_repo_ask_only(self):
        config=replace(cfg(),ci_control_repositories=(REPO,))
        root=self.root/'new';root.mkdir(mode=0o700)
        ci=NativeGitHubAdapter(self.transport,config=config,root=root,
            actor='agent',backend=None,store=None)
        preview=ci.prepare(self.query('rerun_failed_jobs',dict(
            runId=9,attempt=2,expectedHeadSha=SHA)))
        self.assertEqual(preview['run']['headSha'],SHA)
        for repo in ('tunnel','fortis-approvals'):
            with self.assertRaisesRegex(Denied,'GITHUB_CI_CONTROL_DISABLED'):
                ci.prepare(self.query('rerun_failed_jobs',dict(
                    runId=9,attempt=2,expectedHeadSha=SHA),repo))
        c=SimpleNamespace(adapters={},policies={})
        broker=SimpleNamespace(read_adapters={},actor_read_operations={},actor_operations={})
        portal=SimpleNamespace(strong_operations=frozenset())
        (self.root/'installed').mkdir(mode=0o700)
        build=install(core=c,portal=portal,broker=broker,config=config,
                      root=self.root/'installed',actor='agent',transport=self.transport)
        self.assertEqual(set(x[1] for x in broker.actor_read_operations['agent']
                             if x[1] in READ_NAMES),READ_NAMES)
        self.assertEqual(set(x[1] for x in broker.actor_operations['agent']
                             if x[1] in ACTION_NAMES),ACTION_NAMES)
        for op in ACTION_NAMES:
            self.assertEqual(c.policies[('agent','github',op,REPO)],'ASK')
            self.assertNotIn(('agent','github',op,'tunnel'),c.policies)
        self.assertIn(('github','get_job_log'),broker.actor_read_operations['agent'])
        self.assertEqual(self.transport.controls,[])

    def test_trusted_core_read_and_ci_control_ask_boundary(self):
        # The actual machine read route and Core decision are exercised without
        # an owner authenticator; ASK may be submitted but cannot be approved.
        core=Core(self.root/'core.sqlite',adapters={},policies={},
                  authenticator=Authenticator({'machine-grant':'agent'}))
        portal=SimpleNamespace(core=core,strong_operations=frozenset())
        broker=RepoIntentBroker(core,actor_operations={
            'agent':{('sonarcloud','accept_issue')}})
        config=replace(cfg(),ci_control_repositories=(REPO,))
        native=install(core=core,portal=portal,broker=broker,config=config,
                       root=self.root,actor='agent',transport=self.transport)
        query=dict(requestId=str(uuid.uuid4()),service='github',operation='get_job_log',
            target=REPO,params=dict(runId=9,attempt=2,jobId=5,offsetLines=0,maxLines=20),
            reason='Find exact CI failure')
        got=broker.read('machine-grant',query)
        self.assertIn('AssertionError',got['data']['data']['text'])
        wrong=dict(query,target='not-permitted',requestId=str(uuid.uuid4()))
        with self.assertRaises(Denied):
            broker.read('machine-grant',wrong)
        intent=dict(requestId=str(uuid.uuid4()),service='github',operation='rerun_failed_jobs',
            target=REPO,params=dict(runId=9,attempt=2,expectedHeadSha=SHA),reason='Owner-controlled CI rerun')
        pending=broker.submit('machine-grant',intent)
        self.assertEqual(pending['state'],'PENDING')
        self.assertFalse(self.transport.controls)
        with self.assertRaises(Denied):
            broker.submit('machine-grant',dict(intent,target='tunnel',requestId=str(uuid.uuid4())))

    def test_environment_ci_controls_trusted_default_disabled(self):
        self.assertFalse(cfg().ci_control_repositories)
        valid={'FORTIS_GITHUB_PILOT':'1','FORTIS_GITHUB_OWNER':'PilotOwner',
            'FORTIS_GITHUB_REPOSITORY':'fortis-approvals',
            'FORTIS_GITHUB_FILE_PR_BRANCH':'fortis-e2e/11111111-1111-4111-8111-111111111111-approve',
            'FORTIS_GITHUB_CI_READS':'1','FORTIS_GITHUB_NATIVE_WORKTREE':'1',
            'FORTIS_GITHUB_REQUIRED_WORKFLOWS':'101',
            'FORTIS_GITHUB_NATIVE_MULTI_REPO':'1'}
        self.assertEqual(config_from_environment(valid).ci_control_repositories,())
        self.assertEqual(config_from_environment(dict(valid,
            FORTIS_GITHUB_CI_CONTROL_REPOSITORIES='rd-graphs,tunnel')).ci_control_repositories,
            ('rd-graphs','tunnel'))
        for raw in ('rd-graphs,rd-graphs','bad/name','rd-graphs,../x',''):
            if not raw:continue
            with self.assertRaises(ValueError):
                config_from_environment(dict(valid,FORTIS_GITHUB_CI_CONTROL_REPOSITORIES=raw))
        with self.assertRaises(ValueError):
            config_from_environment({'FORTIS_GITHUB_CI_CONTROL_REPOSITORIES':'rd-graphs'})

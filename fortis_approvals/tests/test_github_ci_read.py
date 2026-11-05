"""Actual TLS Gateway CI reads with fake provider and precise head/run identity."""
from copy import deepcopy
from dataclasses import replace
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from fortis_approvals.core import Denied
from fortis_approvals.integrations.github.pilot import GitHubPilotConfig, GitHubPilotAdapter, config_from_environment
from fortis_approvals.integrations.github.repo_client.ci_read_scenario import read_ci
import test_github_pilot as m1
import test_github_file_pr as m2

CONFIG=replace(m2.CONFIG,ci_reads=True)
STATE=dict(format='fortis-github-ci-read-v1',runId='33333333-3333-4333-8333-333333333333',owner='PilotOwner',repository='sandbox',
    branch=m2.BRANCH,headSha=m1.SHA,pullRequestNumber=8,workflowRunId=777,phase='READ')


class FakeCI(m2.FileGitHub):
    def __init__(self):
        super().__init__()
        self.pulls=[dict(number=8,title='Test draft',state='open',draft=True,merged=False,
            head=dict(ref=m2.BRANCH,sha=m1.SHA),base=dict(ref='main',sha=m1.SHA),html_url='https://github.com/PilotOwner/sandbox/pull/8')]
        self.runs=[dict(id=777,name='Source CI',event='pull_request',status='completed',conclusion='success',
            head_branch=m2.BRANCH,head_sha=m1.SHA,run_number=1,run_attempt=1,
            created_at='2026-11-06T00:00:00Z',updated_at='2026-11-06T00:01:00Z',
            html_url='https://github.com/PilotOwner/sandbox/actions/runs/777')]
        self.ci_calls=[]
    def request(self,method,path,**kwargs):
        if method=='GET' and path=='/repos/PilotOwner/sandbox/pulls/8': return self.pulls[0]
        if method=='GET' and path=='/repos/PilotOwner/sandbox/actions/runs':
            self.ci_calls.append(kwargs['params'])
            p=kwargs['params'];start=(p['page']-1)*p['per_page']
            return dict(total_count=len(self.runs),workflow_runs=self.runs[start:start+p['per_page']])
        return super().request(method,path,**kwargs)


class ConfigTests(unittest.TestCase):
    def test_opt_in_is_explicit_and_disabled_without_reading_provider(self):
        for env in ({'FORTIS_GITHUB_CI_READS':'1'}, {'FORTIS_GITHUB_PILOT':'1','FORTIS_GITHUB_OWNER':'PilotOwner',
                    'FORTIS_GITHUB_REPOSITORY':'sandbox','FORTIS_GITHUB_CI_READS':'true'}):
            with self.assertRaises(ValueError):config_from_environment(env)
        with self.assertRaises(ValueError):GitHubPilotConfig('PilotOwner','sandbox',ci_reads=True)
        with self.assertRaises(ValueError):replace(CONFIG,ci_reads='1')
        env=dict(FORTIS_GITHUB_PILOT='1',FORTIS_GITHUB_OWNER='PilotOwner',FORTIS_GITHUB_REPOSITORY='sandbox',
                 FORTIS_GITHUB_FILE_PR_BRANCH=m2.BRANCH,FORTIS_GITHUB_CI_READS='1')
        self.assertEqual(config_from_environment(env),CONFIG)
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)/'private';root.mkdir(mode=0o700);remote=FakeCI()
            adapter=GitHubPilotAdapter(remote,config=m2.CONFIG,receipt_store=root/'receipts.sqlite')
            with self.assertRaises(Denied):adapter.read(dict(service='github',operation='list_workflow_runs',target='sandbox',params=dict(page=1,perPage=100)))
            self.assertEqual(remote.ci_calls,[])


class CIReadTLS(m1.PilotTLSWebAuthnTests):
    def setUp(self):
        with patch('test_github_pilot.FakeGitHub',FakeCI),patch('test_github_pilot.CONFIG',CONFIG):super().setUp()

    def test_exact_ci_report_and_no_mutations(self):
        report=read_ci(STATE,self.client)
        self.assertTrue(report['ciPassed']);self.assertEqual(report['workflowRun']['id'],777)
        self.assertEqual((self.remote.mutations,self.remote.files_writes,self.remote.pr_writes),(0,0,0))
        broker=self.machine.get_app().broker
        for operation,params in [('dispatch_workflow',dict(workflowId=1,ref=m2.BRANCH,inputs={})),
                ('rerun_workflow',dict(runId=777)),('cancel_workflow',dict(runId=777))]:
            with self.assertRaises(Denied):self.client.action(operation,'sandbox',params,request_id=str(__import__('uuid').uuid4()),reason='Must remain denied')
        self.assertEqual(len(self.remote.ci_calls),1)

    def test_ci_failure_or_pending_is_reported_without_false_success(self):
        for status,conclusion in [('completed','failure'),('in_progress',None)]:
            self.remote.runs[0].update(status=status,conclusion=conclusion)
            report=read_ci(STATE,self.client)
            self.assertFalse(report['ciPassed']);self.assertEqual(report['workflowRun']['status'],status)

    def test_different_commit_event_or_run_identity_is_rejected(self):
        for key,value in [('head_sha','e'*40),('head_branch','other'),('event','push'),('name','Other CI')]:
            original=deepcopy(self.remote.runs[0]);self.remote.runs[0][key]=value
            with self.assertRaisesRegex(Denied,'RUN_IDENTITY'):read_ci(STATE,self.client)
            self.remote.runs[0]=original
        changed={**STATE,'headSha':'f'*40}
        with self.assertRaisesRegex(Denied,'PR_HEAD'):read_ci(changed,self.client)

    def test_pagination_and_missing_run_do_not_fall_back_to_latest_green(self):
        expected=deepcopy(self.remote.runs[0])
        self.remote.runs=[{**expected,'id':1000+i,'html_url':'https://github.com/PilotOwner/sandbox/actions/runs/'+str(1000+i)} for i in range(100)]+[expected]
        self.assertTrue(read_ci(STATE,self.client)['ciPassed'])
        self.assertEqual([p['page'] for p in self.remote.ci_calls],[1,2])
        self.remote.runs=[]
        with self.assertRaisesRegex(Denied,'EXPECTED_RUN_NOT_FOUND'):read_ci(STATE,self.client)

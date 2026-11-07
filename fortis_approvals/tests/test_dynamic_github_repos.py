"""Token-scoped native repository discovery without a duplicate repo list.

Runs without Docker, GitHub network or owner secrets. Production rollout still
requires original native TLS/Core/WebAuthn suites and owner live acceptance.
"""
from pathlib import Path
import os
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from fortis_approvals.core import Denied
from fortis_approvals.integrations.github.pilot import GitHubPilotConfig, config_from_environment
from fortis_approvals.integrations.github.gateway.transport import GitHubHTTPTransport
from fortis_approvals.workflow.adapters import NativeGitHubAdapter
from fortis_approvals.workflow.git_backend import GitHubGitBackend
from fortis_approvals.workflow.worker import Worker


class FakeTokenAccess:
    def __init__(self):
        self.permitted={'fortis-approvals','fortis-container','tunnel'}
        self.rules=[]
        self.checks=[]
        self.statuses=[]
        self.requests=[]
        self.mismatch=False
        self.archived=False
    def request(self,method,path,*,params=None,body=None,expected_statuses=(200,),allow_not_found=False):
        self.requests.append((method,path,params))
        repo=path.split('/')[3]
        if repo not in self.permitted:raise Denied('GITHUB_TOKEN_REPOSITORY_DENIED')
        if method=='GET' and path==f'/repos/PilotOwner/{repo}':
            return {'full_name':'PilotOwner/'+('wrong' if self.mismatch else repo),
                    'archived':self.archived,'disabled':False,'default_branch':'main'}
        if method=='GET' and path.endswith('/rules/branches/main'):
            return self.rules
        if method=='GET' and path.endswith('/check-runs'):
            return {'check_runs':self.checks}
        if method=='GET' and path.endswith('/status'):
            return {'statuses':self.statuses}
        raise AssertionError((method,path,params))


def cfg(dynamic=True):
    return GitHubPilotConfig('PilotOwner','fortis-approvals',
        file_pr_branch='fortis-e2e/11111111-1111-4111-8111-111111111111-approve',
        ci_reads=True,native_worktree=True,required_workflows=(101,),
        dynamic_repositories=dynamic)


class DynamicNativeTests(unittest.TestCase):
    def setUp(self):
        folder=tempfile.TemporaryDirectory();self.addCleanup(folder.cleanup)
        self.root=Path(folder.name);self.transport=FakeTokenAccess()
        self.adapter=NativeGitHubAdapter(self.transport,config=cfg(),root=self.root,
            actor='agent',backend=None,store=None)

    def test_explicit_opt_in_and_legacy_single_repo(self):
        with self.assertRaisesRegex(ValueError,'GITHUB_DYNAMIC_REPOS_REQUIRES_NATIVE'):
            GitHubPilotConfig('PilotOwner','fortis-approvals',dynamic_repositories=True)
        with self.assertRaisesRegex(ValueError,'GITHUB_DYNAMIC_REPOS_OPT_IN_INVALID'):
            config_from_environment({'FORTIS_GITHUB_PILOT':'1','FORTIS_GITHUB_NATIVE_MULTI_REPO':'yes'})
        single=NativeGitHubAdapter(self.transport,config=cfg(False),root=self.root,
            actor='agent',backend=None,store=None)
        self.assertEqual(single._access('fortis-approvals'),'fortis-approvals')
        with self.assertRaisesRegex(Denied,'GITHUB_REPOSITORY_NOT_ALLOWLISTED'):
            single._access('fortis-container')
        self.assertEqual(self.transport.requests,[])

    def test_environment_opt_in_exact_and_disabled_cannot_bypass(self):
        good={'FORTIS_GITHUB_PILOT':'1','FORTIS_GITHUB_OWNER':'PilotOwner',
              'FORTIS_GITHUB_REPOSITORY':'fortis-approvals',
              'FORTIS_GITHUB_FILE_PR_BRANCH':'fortis-e2e/11111111-1111-4111-8111-111111111111-approve',
              'FORTIS_GITHUB_CI_READS':'1','FORTIS_GITHUB_NATIVE_WORKTREE':'1',
              'FORTIS_GITHUB_REQUIRED_WORKFLOWS':'101',
              'FORTIS_GITHUB_NATIVE_MULTI_REPO':'1'}
        self.assertTrue(config_from_environment(good).dynamic_repositories)
        self.assertFalse(config_from_environment({**good,'FORTIS_GITHUB_NATIVE_MULTI_REPO':'0'}).dynamic_repositories)
        with self.assertRaisesRegex(ValueError,'GITHUB_PILOT_PARTIAL_CONFIGURATION'):
            config_from_environment({'FORTIS_GITHUB_PILOT':'0','FORTIS_GITHUB_NATIVE_MULTI_REPO':'1'})
        with self.assertRaisesRegex(ValueError,'GITHUB_DYNAMIC_REPOS_REQUIRES_NATIVE'):
            config_from_environment({**good,'FORTIS_GITHUB_NATIVE_WORKTREE':'0',
                                    'FORTIS_GITHUB_REQUIRED_WORKFLOWS':''})

    def test_token_is_repository_access_authority(self):
        self.assertEqual(self.adapter._access('fortis-container'),'fortis-container')
        self.assertEqual(self.adapter._access('tunnel'),'tunnel')
        self.assertIn(('GET','/repos/PilotOwner/tunnel',None),self.transport.requests)
        with self.assertRaisesRegex(Denied,'GITHUB_TOKEN_REPOSITORY_DENIED'):
            self.adapter._access('not-permitted')
        self.assertEqual(self.adapter.repositories,None)

    def test_explicit_404_does_not_turn_into_retry_or_write(self):
        original=self.transport.request
        def not_found(method,path,**kw):
            if path.endswith('/not-permitted'):return {'_httpStatus':404}
            return original(method,path,**kw)
        self.transport.request=not_found
        with self.assertRaisesRegex(Denied,'GITHUB_REPOSITORY_ACCESS_UNCONFIRMED'):
            self.adapter._access('not-permitted')

    def test_repo_validation_no_slashes_symlinks_or_wrong_owner(self):
        for name in ('../tunnel','tunnel/../fortis-approvals','/tmp','.', '..','a b','x\\y',''):
            with self.subTest(name=name), self.assertRaises(Denied):self.adapter._access(name)
        self.transport.mismatch=True
        with self.assertRaisesRegex(Denied,'GITHUB_REPOSITORY_ACCESS_UNCONFIRMED'):
            self.adapter._access('tunnel')
        self.transport.mismatch=False;self.transport.archived=True
        with self.assertRaisesRegex(Denied,'GITHUB_REPOSITORY_ACCESS_UNCONFIRMED'):
            self.adapter._access('tunnel')

    def test_backend_dynamic_repo_name_and_fixed_owner(self):
        g=GitHubGitBackend(self.root/'bundles',owner='PilotOwner',repositories=None)
        self.assertEqual(g.url('tunnel'),'https://github.com/PilotOwner/tunnel.git')
        with self.assertRaises(Denied):g.url('../../evil')
        with self.assertRaises(Denied):g.url('bad/repo')
        g2=GitHubGitBackend(self.root/'bundles2',owner='PilotOwner',repositories=('fortis-approvals',))
        with self.assertRaises(Denied):g2.url('tunnel')

    def test_rules_required_ci_for_exact_head(self):
        head='1'*40
        self.transport.rules=[{'type':'required_status_checks','parameters':{
            'required_status_checks':[{'context':'Test / python','integration_id':32}]}}]
        self.transport.checks=[{'id':5,'name':'Test / python','head_sha':head,
                                'app':{'id':32},'status':'completed','conclusion':'success'},
                               {'id':7,'name':'Test / python','head_sha':'2'*40,
                                'app':{'id':32},'status':'completed','conclusion':'success'}]
        got=self.adapter._dynamic_ci_gate('tunnel',head)
        self.assertEqual(got,[{'context':'Test / python','runId':5,'headSha':head,'source':'check_run'}])

    def test_missing_rules_or_pending_is_not_merge_pass(self):
        head='1'*40
        with self.assertRaisesRegex(Denied,'GIT_REQUIRED_CHECKS_UNCONFIGURED'):
            self.adapter._dynamic_ci_gate('tunnel',head)
        self.transport.rules=[{'type':'required_status_checks','parameters':{
            'required_status_checks':[{'context':'Test / python','integration_id':32}]}}]
        self.transport.checks=[{'id':5,'name':'Test / python','head_sha':head,
                                'app':{'id':32},'status':'in_progress','conclusion':None}]
        with self.assertRaisesRegex(Denied,'GIT_REQUIRED_CI_NOT_SUCCESSFUL'):
            self.adapter._dynamic_ci_gate('tunnel',head)
        self.transport.checks[0]['status']='completed'
        self.transport.checks[0]['conclusion']='success'
        self.transport.checks[0]['app']['id']=33
        with self.assertRaisesRegex(Denied,'GIT_REQUIRED_CI_MISSING'):
            self.adapter._dynamic_ci_gate('tunnel',head)

    def test_unhandled_required_rule_fails_closed(self):
        self.transport.rules=[{'type':'required_status_checks','parameters':{
            'required_status_checks':[{'context':'build','integration_id':None}]}},
            {'type':'workflows','parameters':{'workflows':[]}}]
        with self.assertRaisesRegex(Denied,'GIT_REQUIRED_RULE_UNSUPPORTED'):
            self.adapter._dynamic_ci_gate('tunnel','1'*40)

    def test_legacy_commit_status_fallback_only_without_app_pin(self):
        head='1'*40
        self.transport.rules=[{'type':'required_status_checks','parameters':{
            'required_status_checks':[{'context':'legacy/test','integration_id':None}]}}]
        self.transport.statuses=[{'id':9,'context':'legacy/test','state':'success'}]
        self.assertEqual(self.adapter._dynamic_ci_gate('tunnel',head),
            [{'context':'legacy/test','statusId':9,'headSha':head,'source':'commit_status'}])
        self.transport.statuses[0]['state']='failure'
        with self.assertRaisesRegex(Denied,'GIT_REQUIRED_CI_NOT_SUCCESSFUL'):
            self.adapter._dynamic_ci_gate('tunnel',head)

    def test_rules_response_invalid_fails_closed(self):
        self.transport.rules={'not':'a-list'}
        with self.assertRaisesRegex(Denied,'GIT_BRANCH_RULES_INVALID'):
            self.adapter._dynamic_ci_gate('tunnel','1'*40)

    def test_native_runtime_policies_are_scoped_to_actor_even_when_repo_is_dynamic(self):
        from types import SimpleNamespace
        from fortis_approvals.workflow.runtime import install
        c=SimpleNamespace(adapters={},policies={})
        broker=SimpleNamespace(read_adapters={},actor_read_operations={},actor_operations={})
        portal=SimpleNamespace(strong_operations=frozenset())
        built=install(core=c,portal=portal,broker=broker,config=cfg(),
                      root=self.root,actor='agent',transport=self.transport)
        self.assertIsNone(built['adapter'].repositories)
        self.assertEqual(c.policies[('agent','github','create_pull_request')],'ALLOW')
        self.assertEqual(c.policies[('agent','github','merge_pull_request')],'ASK')
        self.assertNotIn(('outsider','github','create_pull_request'),c.policies)
        self.assertNotIn(('agent','github','delete_repository'),c.policies)

    def test_native_transport_does_not_allow_generic_api_urls(self):
        self.assertTrue(GitHubHTTPTransport._route_allowed('GET','/repos/PilotOwner/tunnel/rules/branches/main'))
        self.assertFalse(GitHubHTTPTransport._route_allowed('PUT','/repos/PilotOwner/tunnel/rules/branches/main'))
        self.assertFalse(GitHubHTTPTransport._route_allowed('GET','/repos/PilotOwner/tunnel/rules/branches/evil'))

    def test_dynamic_worker_no_arbitrary_filesystem_paths(self):
        repos=self.root/'Repos';repos.mkdir()
        trees=self.root/'Worktrees';trees.mkdir()
        source=repos/'tunnel';source.mkdir()
        (trees/'tunnel').mkdir()
        def git(*args):
            subprocess.run(['git','-C',str(source),*args],check=True,capture_output=True)
        git('init','-b','main')
        git('remote','add','origin','https://github.com/PilotOwner/tunnel.git')
        worker=Worker(owner='PilotOwner',repositories={},worktrees={},gateway=None,
            dynamic_repositories=True,repository_root=repos,worktree_root=trees)
        self.assertEqual(worker._open('tunnel')[0],source)
        with self.assertRaises(Denied):worker._open('../tunnel')
        (trees/'evil').symlink_to(trees/'tunnel')
        (repos/'evil').symlink_to(source)
        with self.assertRaises(Denied):worker._open('evil')
        git('remote','set-url','origin','https://github.com/OtherOwner/tunnel.git')
        with self.assertRaisesRegex(Denied,'WORKER_ORIGIN_MISMATCH'):
            worker._open('tunnel')


if __name__=='__main__':unittest.main()

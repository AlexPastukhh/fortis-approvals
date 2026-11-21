"""Pre-merge paths and current policy/workflow observations via pinned GETs."""
import hashlib
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from fortis_approvals.core import Denied, Stale
from fortis_approvals.integrations.github.gateway.analysis_adapter import AnalysisGitHubAdapter
from fortis_approvals.integrations.github.gateway.path_ci_observation import observe_path_ci
from fortis_approvals.integrations.github.gateway.transport import GitHubHTTPTransport
from fortis_approvals.integrations.github.release_label_ci import WORKFLOWS
from fortis_approvals.integrations.github.tests.publisher_fixture import API, HEAD, BASE, OWNER, REPOSITORY


class Provider(API):
    def __init__(self):
        super().__init__()
        self.changed_count = 2
        self.files = [
            {'filename': 'src/new.py', 'previous_filename': 'src/old.py', 'status': 'renamed'},
            {'filename': '.github/workflows/source-ci.yml', 'status': 'modified'},
        ]
        self.rules = [{'type': 'required_status_checks', 'parameters': {
            'required_status_checks': [{'context': name, 'integration_id': 12}
                                       for workflow in WORKFLOWS for name in workflow.jobs]}}]
        self.compare_base = BASE

    def pr(self):
        return dict(super().pr(), changed_files=self.changed_count)

    def request(self, method, path, **kw):
        assert method == 'GET' and GitHubHTTPTransport._route_allowed(method, path)
        suffix = path.split('/'+REPOSITORY, 1)[1]
        if suffix.startswith('/compare/') or suffix == '/rules/branches/main':
            params = kw.get('params')
            self.calls.append((method, suffix, params, None))
            if self.on_request:
                self.on_request(method, suffix, params, None)
            if suffix.startswith('/compare/'):
                assert suffix == '/compare/'+BASE+'...'+HEAD and params == {'page':1,'per_page':1}
                return {'status':'ahead','ahead_by':1,'base_commit':{'sha':self.compare_base},
                        'merge_base_commit':{'sha':BASE},'files':self.files}
            return self.rules[(params['page']-1)*100:params['page']*100]
        return super().request(method, path, **kw)


class PathCITests(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory();self.addCleanup(tmp.cleanup)
        self.api=Provider()
        self.adapter=AnalysisGitHubAdapter(self.api, owner=OWNER, repositories=[REPOSITORY],
            receipt_store=Path(tmp.name)/'receipts.sqlite',
            bindings={REPOSITORY:{'workflows':{str(w.ident):w.path for w in WORKFLOWS},
                                  'projectKey':'fixture','allowCiControl':False}})
        self.kw={'number':7,'expected_head_sha':HEAD,'expected_base_sha':BASE,
                 'expected_body_sha256':hashlib.sha256(self.api.body.encode()).hexdigest()}

    def observe(self, **kwargs):
        return observe_path_ci(self.adapter, **(self.kw|kwargs))

    def test_paths_and_ci_bound_without_authority(self):
        r=self.observe();o=r['observation']
        self.assertEqual(r['result'],'PRE_MERGE_PATH_CI_OBSERVED')
        self.assertEqual(o['paths']['impactPaths'],['.github/workflows/source-ci.yml','src/new.py','src/old.py'])
        self.assertEqual(o['paths']['count'],2)
        self.assertEqual([row['attempt'] for row in o['pinnedWorkflowCI']],[1,1])
        self.assertEqual(len(o['currentRules']['requiredContexts']),3)
        for key in ('historicalPolicyVerified','requiredPolicySatisfied','reviewAttested',
                    'evidenceVerified','admissionAllowed','deploymentAllowed'):
            self.assertIs(r[key],False)
        self.assertNotIn(self.api.body,repr(r))
        self.assertTrue(all(c[0]=='GET' for c in self.api.calls))
        self.assertEqual(r,self.observe())

    def test_missing_files_and_truncation_bound(self):
        self.api.files.pop()
        with self.assertRaisesRegex(Denied,'P5_PATH_CI_FILES_INCOMPLETE'):self.observe()
        self.api.changed_count=300
        with self.assertRaisesRegex(Denied,'P5_PATH_CI_FILE_COUNT_INVALID'):self.observe()

    def test_rename_and_path_checks(self):
        for field,value in [('previous_filename','../bad'),('previous_filename','src/new.py'),
                            ('filename','C:/bad'),('status','copied')]:
            with self.subTest(field=field,value=value),patch.dict(self.api.files[0],{field:value}),self.assertRaises(Denied):
                self.observe()

    def test_removed_normalized(self):
        self.api.files[0]={'filename':'src/old.py','status':'removed'}
        r=self.observe()
        self.assertEqual(r['observation']['paths']['records'][1]['status'],'deleted')

    def test_compare_wrong_base(self):
        self.api.compare_base='f'*40
        with self.assertRaisesRegex(Denied,'P5_PATH_CI_COMPARE_INVALID'):self.observe()

    def test_bad_head_body_or_closed(self):
        with self.assertRaises(Denied):self.observe(expected_body_sha256='f'*64)
        with self.assertRaises(Denied):self.observe(expected_head_sha='f'*40)
        self.api.state='closed'
        with self.assertRaisesRegex(Denied,'P5_PATH_CI_PR_NOT_OPEN'):self.observe()

    def test_rules_missing_and_unsupported(self):
        self.api.rules=[]
        with self.assertRaises(Denied):self.observe()
        self.api.rules=[{'type':'required_workflows'}]
        with self.assertRaisesRegex(Denied,'P5_PATH_CI_UNSUPPORTED_RULE'):self.observe()

    def test_ambiguous_integration(self):
        checks=self.api.rules[0]['parameters']['required_status_checks']
        checks.append(dict(checks[0],integration_id=99))
        with self.assertRaisesRegex(Denied,'P5_PATH_CI_RULES_AMBIGUOUS'):self.observe()

    def test_jobs_and_run_binding_fail_closed(self):
        self.api.job_changes['offline-tests']={'run_attempt':2}
        with self.assertRaises(Denied):self.observe()
        self.api.job_changes={};self.api.total_override=3
        with self.assertRaises(Denied):self.observe()

    def test_failed_or_modified_workflow(self):
        self.api.conclusion[WORKFLOWS[0].ident]='failure'
        with self.assertRaises(Denied):self.observe()
        self.api.conclusion={};self.api.sources[WORKFLOWS[0].path]+=b'\n# changed'
        with self.assertRaises(Denied):self.observe()

    def test_rules_drift(self):
        def race(method,suffix,params,body):
            if suffix=='/rules/branches/main' and sum(c[1]==suffix for c in self.api.calls)>1:
                self.api.rules[0]['parameters']['required_status_checks'][0]['integration_id']=99
        self.api.on_request=race
        with self.assertRaisesRegex(Stale,'P5_PATH_CI_OBSERVATION_CHANGED'):self.observe()

    def test_attempt_drift(self):
        def race(method,suffix,params,body):
            if suffix=='/actions/runs' and sum(c[1]==suffix for c in self.api.calls)>1:
                self.api.attempts[WORKFLOWS[0].ident]=2
        self.api.on_request=race
        with self.assertRaises(Denied):self.observe()

    def test_deadline(self):
        times=iter([0,61])
        with self.assertRaisesRegex(Denied,'P5_PATH_CI_BUDGET'):self.observe(clock=lambda:next(times))
        self.assertFalse(self.api.calls)

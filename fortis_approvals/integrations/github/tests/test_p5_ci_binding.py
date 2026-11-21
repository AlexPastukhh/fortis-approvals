"""P5 v2 capture and Core review; pinned workflow and provider check witnesses."""
import copy
import unittest
from unittest.mock import patch

from fortis_approvals.core import Conflict, Denied
from fortis_approvals.integrations.github.gateway.p5_ci_binding import P5_WORKFLOWS, APP_ID
from fortis_approvals.integrations.github.tests import test_integrated_capture as fixture
from fortis_approvals.integrations.github.tests import publisher_fixture


class PolicyBindingTests(unittest.TestCase):
    def setUp(self):
        # Actual private capture and Core, expanded provider fixture only.
        self.enterContext(patch.object(publisher_fixture, 'WORKFLOWS', P5_WORKFLOWS))
        fixture.IntegratedCaptureTests.setUp(self)
        self.adapter.bindings[fixture.REPO]['workflows'] = {str(w.ident):w.path for w in P5_WORKFLOWS}
        self.api.rules[0]['parameters']['required_status_checks'] = [
            {'context':n,'integration_id':APP_ID} for w in P5_WORKFLOWS for n in w.jobs]
        self.checks = []
        self.statuses = []
        self.check_count = None
        self.run_changes = {}
        for idx,w in enumerate(P5_WORKFLOWS):
            run=101+idx
            for i,name in enumerate(w.jobs):
                ident=1000+run*10+i
                self.checks.append(dict(id=ident,name=name,head_sha=fixture.HEAD,
                    app={'id':APP_ID,'slug':'github-actions'},status='completed',conclusion='success',
                    details_url='https://github.com/'+fixture.OWNER+'/'+fixture.REPO+
                        '/actions/runs/'+str(run)+'/job/'+str(ident),
                    started_at='2026-11-16T01:00:00Z',completed_at='2026-11-16T01:01:00Z'))
        original_runs=self.api.runs
        def runs():
            rows=original_runs()
            return [{**row,**self.run_changes.get(row['workflow_id'],{})} for row in rows]
        self.api.runs=runs
        original=self.api.request
        def request(method,path,**kw):
            suffix=path.split('/'+fixture.REPO,1)[1]
            if suffix=='/commits/'+fixture.HEAD+'/check-runs':
                self.api.calls.append((method,suffix,kw.get('params'),None))
                return {'total_count':len(self.checks) if self.check_count is None else self.check_count,
                        'check_runs':copy.deepcopy(self.checks)}
            if suffix=='/commits/'+fixture.HEAD+'/status':
                self.api.calls.append((method,suffix,kw.get('params'),None))
                return {'sha':fixture.HEAD,'total_count':len(self.statuses),'statuses':copy.deepcopy(self.statuses)}
            return original(method,path,**kw)
        self.api.request=request

    def capture(self):
        return self.store.capture_bundle(self.adapter,policy_bound=True,**self.kw)

    prepare=fixture.IntegratedCaptureTests.prepare
    decide=fixture.IntegratedCaptureTests.decide
    merge=fixture.IntegratedCaptureTests.merge
    read_merge=fixture.IntegratedCaptureTests.read_merge

    def test_v2_capture_review_merge_and_replay(self):
        receipt=self.capture()
        material=self.store.retained_material(receipt['operationId'],expected_checkpoint=self.store.checkpoint())
        self.assertEqual(material['bundle']['schemaVersion'],2)
        binding=material['bundle']['pathCi']['ciPolicyBinding']
        self.assertEqual(len(binding['checks']),4)
        self.assertTrue(binding['candidateChecksMatched'])
        self.assertFalse(binding['historicalPolicyVerified'])
        self.assertEqual({c['appId'] for c in binding['checks']},{APP_ID})
        with self.assertRaises(Conflict):
            self.store.capture_bundle(self.adapter,**self.kw)
        row=self.prepare(receipt)
        self.assertEqual(row['state'],'PENDING')
        self.assertEqual(self.decide(row)['state'],'EXECUTED')
        self.merge()
        self.assertEqual(self.capture(),receipt)
        observed=self.read_merge()
        self.assertFalse(observed['evidenceVerified'])
        self.assertEqual(observed['observation']['retainedCiPolicySha256'],binding['policySha256'])

    def test_missing_third_gate(self):
        self.checks.pop()
        with self.assertRaises(Denied):self.capture()

    def test_wrong_app_or_job_id(self):
        row=self.checks[0]
        for changes in ({'app':{'id':99,'slug':'github-actions'}},{'id':99},{'conclusion':'failure'},
                        {'details_url':'https://github.com/other/repo/actions/runs/101/job/2010'}):
            with self.subTest(changes=changes),patch.dict(row,changes),self.assertRaises(Denied):
                self.capture()

    def test_duplicate_context_or_incomplete_inventory(self):
        self.checks.append(dict(self.checks[0],id=999))
        with self.assertRaises(Denied):self.capture()
        self.checks.pop();self.check_count=99
        with self.assertRaises(Denied):self.capture()

    def test_legacy_status_is_not_check(self):
        self.statuses=[{'context':'offline-tests','state':'success'}]
        with self.assertRaisesRegex(Denied,'P5_CI_LEGACY_STATUS_AMBIGUOUS'):self.capture()

    def test_missing_pr_or_wrong_base_in_attempt(self):
        w=P5_WORKFLOWS[-1]
        for pulls in ([],[{'number':7,'head':{'sha':fixture.HEAD},'base':{'sha':'e'*40}}]):
            self.run_changes[w.ident]={'pull_requests':pulls}
            with self.subTest(pulls=pulls),self.assertRaises(Denied):self.capture()

    def test_unknown_rule_or_app(self):
        checks=self.api.rules[0]['parameters']['required_status_checks']
        checks.append({'context':'unknown','integration_id':APP_ID})
        with self.assertRaisesRegex(Denied,'P5_CI_RULE_CONTEXT_UNSUPPORTED'):self.capture()
        checks.pop();checks[0]['integration_id']=99
        with self.assertRaisesRegex(Denied,'P5_CI_RULE_CONTEXT_UNSUPPORTED'):self.capture()

    def test_check_changed_after_pending(self):
        row=self.prepare(self.capture())
        self.checks[0]['completed_at']='2026-11-16T01:02:00Z'
        self.assertEqual(self.decide(row)['state'],'STALE')


    def test_future_completed_check_cannot_be_merge_evidence(self):
        self.checks[0]['completed_at']='2098-01-01T00:00:00Z'
        self.assertEqual(self.decide(self.prepare(self.capture()))['state'],'EXECUTED')
        self.merge()
        with self.assertRaisesRegex(Denied,'P5_MERGE_CI_REVIEW_ORDER_UNPROVEN'):
            self.read_merge()

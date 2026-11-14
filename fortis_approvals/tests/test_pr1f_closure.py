"""PR1F: native PR-create checkpoints and bounded Git artifact errors, offline."""
from io import BytesIO
import json
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch
from urllib.error import HTTPError
import uuid

from fortis_approvals.core import Authenticator, Core, Denied
from fortis_approvals.clients.gateway_transport import GatewayTransport
from fortis_approvals.workflow.client import WorkflowTransport
from fortis_approvals.workflow.ingress import NativeIngress
from fortis_approvals.workflow.adapters import NativeGitHubAdapter
from fortis_approvals.workflow.artifact_diagnostics import (
    ARTIFACT_FAILURE_HEADER, bounded_artifact_error)
from fortis_approvals.integrations.github.gateway.adapter import GitHubAdapter
from fortis_approvals.tests.test_pr1d_create_pr_phases_precore import FakeTransport

GRANT='q'*48

class OfflineNative(NativeGitHubAdapter):
    def prepare(self, request):
        # Use the common typed adapter's read-only PR precondition checks.
        # Native worktree authorization is tested by existing native tests.
        return GitHubAdapter.prepare(self,request)

class HTTPFail:
    def __init__(self,status,headers,body=b'{"error":"WORKFLOW_DENIED"}'):
        self.status=status;self.headers=headers;self.body=body
    def open(self,req,timeout):
        raise HTTPError(req.full_url,self.status,'offline',self.headers,BytesIO(self.body))

class OfflineIngressBase:
    def __init__(self,core):
        self.broker=SimpleNamespace(core=core)
    def _environment(self,env):
        return True
    def _credential(self,env):
        return GRANT,'actor'

class PR1FTests(unittest.TestCase):
    def native_case(self,mode,inject=None):
        with tempfile.TemporaryDirectory() as td:
            transport=FakeTransport(mode)
            config=SimpleNamespace(owner='owner',repository='repo',
                                   dynamic_repositories=False)
            adapter=OfflineNative(transport,config=config,root=Path(td),
                actor='actor',backend=None,store=None)
            core=Core(Path(td)/'core.sqlite',adapters={'github':adapter},
                policies={('actor','github','create_pull_request'):'ALLOW'},
                authenticator=Authenticator({GRANT:'actor'}))
            adapter.observation_core=core
            if inject is not None:
                original=adapter.pr_create_checkpoint
                def handle(request_id, event):
                    if inject=='before':
                        raise Denied('OFFLINE_JOURNAL_UNAVAILABLE')
                    if inject=='after' and event=='PR_CREATE_POST_ACKNOWLEDGED':
                        raise Denied('OFFLINE_JOURNAL_UNAVAILABLE')
                    return original(request_id,event)
                adapter.pr_create_checkpoint=handle
            row=core.submit('actor',{'requestId':str(uuid.uuid4()),
                'service':'github','operation':'create_pull_request','target':'repo',
                'params':{'title':'offline','body':'','head':'task/unit',
                          'base':'main','draft':False},
                'expectedVersion':0,'reason':'offline PR1F acceptance'})
            events=[{'state':e['state'],'detail':json.loads(e['detail'])}
                for e in core.events(row['requestId'])]
            return row,events,transport.posts,adapter.receipt(row['requestId'])

    def test_post_error_has_durable_start_without_ack(self):
        row,events,posts,receipt=self.native_case('post')
        self.assertEqual((row['state'],posts,receipt),('UNCERTAIN',1,None))
        states=[x['state'] for x in events]
        self.assertIn('PR_CREATE_POST_STARTED',states)
        self.assertNotIn('PR_CREATE_POST_ACKNOWLEDGED',states)
        self.assertLess(states.index('PR_CREATE_POST_STARTED'),states.index('ERROR_OBSERVED'))
        journal=next(x['detail'] for x in events if x['state']=='PR_CREATE_POST_STARTED')
        self.assertEqual(journal,{'origin':'GITHUB_ADAPTER',
            'effectAssessment':'OUTCOME_UNCONFIRMED','providerAcknowledged':False})

    def test_readback_error_has_ack_but_still_uncertain(self):
        row,events,posts,receipt=self.native_case('readback')
        self.assertEqual((row['state'],posts,receipt),('UNCERTAIN',1,None))
        states=[x['state'] for x in events]
        self.assertLess(states.index('PR_CREATE_POST_STARTED'),
                        states.index('PR_CREATE_POST_ACKNOWLEDGED'))
        self.assertEqual(next(x['detail'] for x in events
            if x['state']=='PR_CREATE_POST_ACKNOWLEDGED')['effectAssessment'],
            'OUTCOME_UNCONFIRMED')

    def test_success_durable_receipt_and_checkpoints(self):
        row,events,posts,receipt=self.native_case('success')
        self.assertEqual((row['state'],posts),('EXECUTED',1))
        self.assertEqual(row['result'],receipt)
        states=[x['state'] for x in events]
        self.assertLess(states.index('PR_CREATE_POST_STARTED'),
                        states.index('PR_CREATE_POST_ACKNOWLEDGED'))
        self.assertLess(states.index('PR_CREATE_POST_ACKNOWLEDGED'),
                        states.index('EXECUTED'))

    def test_failed_before_post_journal_never_calls_provider(self):
        row,events,posts,receipt=self.native_case('success',inject='before')
        self.assertEqual((row['state'],posts,receipt),('UNCERTAIN',0,None))
        self.assertNotIn('PR_CREATE_POST_STARTED',[x['state'] for x in events])

    def test_failed_after_post_journal_never_double_posts(self):
        row,events,posts,receipt=self.native_case('success',inject='after')
        self.assertEqual((row['state'],posts,receipt),('UNCERTAIN',1,None))
        self.assertIn('PR_CREATE_POST_STARTED',[x['state'] for x in events])
        self.assertNotIn('PR_CREATE_POST_ACKNOWLEDGED',[x['state'] for x in events])

    def test_artifact_failure_is_bounded_never_claims_remote_noneffect(self):
        core=SimpleNamespace(auth=Authenticator({GRANT:'actor'}))
        native=NativeIngress(OfflineIngressBase(core),github=None,workspace=None,
                             store=None,actor='actor')
        payload=json.dumps({'invalid':True}).encode()
        env={'HTTP_HOST':'host.example','QUERY_STRING':'',
             'PATH_INFO':'/v1/git/artifact','REQUEST_METHOD':'POST',
             'wsgi.url_scheme':'https','HTTP_AUTHORIZATION':'Bearer '+GRANT,
             'CONTENT_TYPE':'application/json','CONTENT_LENGTH':str(len(payload)),
             'wsgi.input':BytesIO(payload)}
        out=[]
        body=b''.join(native(env,lambda status,headers:out.append(
            (int(status[:3]),dict(headers)))))
        self.assertEqual(out[0][0],403)
        self.assertEqual(json.loads(body),{'error':'WORKFLOW_DENIED'})
        self.assertEqual(out[0][1][ARTIFACT_FAILURE_HEADER],'WORKFLOW_PARAMS_INVALID')
        self.assertEqual(out[0][1]['X-Fortis-Diagnostic-Contract'],'2')
        self.assertNotIn('NOT_EXECUTED',json.dumps(out))
        self.assertEqual(bounded_artifact_error(Denied('SENSITIVE-INPUT')),
                         'GIT_ARTIFACT_REJECTION_UNCLASSIFIED')

    def test_new_client_distinguishes_artifact_error_only_on_native_path(self):
        with tempfile.TemporaryDirectory() as td:
            grant=Path(td)/'grant';cert=Path(td)/'cert'
            grant.write_text(GRANT);grant.chmod(0o600);cert.write_text('offline')
            for version,path,expected in (
                ('2','/v1/git/artifact','FORTIS_ARTIFACT_WORKFLOW_SHA_INVALID'),
                ('3','/v1/git/artifact','FORTIS_HTTP_403'),
                ('2','/v1/workspace/submit','FORTIS_HTTP_403'),
                ('2','/v1/reads','FORTIS_HTTP_403'),
            ):
                with self.subTest(version=version,path=path):
                    opener=HTTPFail(403,{'X-Fortis-Diagnostic-Contract':version,
                         ARTIFACT_FAILURE_HEADER:'WORKFLOW_SHA_INVALID'})
                    c=WorkflowTransport(endpoint='http://localhost:19828',
                        grant_path=str(grant),certificate_path=str(cert),
                        opener=opener)
                    with self.assertRaises(Denied) as caught:
                        c.post(path,dict(test='offline'))
                    self.assertEqual(str(caught.exception),expected)

    def test_legacy_client_keeps_http_403_fallback(self):
        with tempfile.TemporaryDirectory() as td:
            grant=Path(td)/'grant';cert=Path(td)/'cert'
            grant.write_text(GRANT);grant.chmod(0o600);cert.write_text('offline')
            old_client=GatewayTransport(endpoint='http://localhost:19828',
                grant_path=str(grant),certificate_path=str(cert),
                opener=HTTPFail(403,{'X-Fortis-Diagnostic-Contract':'2',
                    ARTIFACT_FAILURE_HEADER:'WORKFLOW_SHA_INVALID'}))
            with self.assertRaisesRegex(Denied,'FORTIS_GATEWAY_ROUTE_DENIED'):
                old_client.post('/v1/git/artifact',{})

    def test_new_python_modules_are_in_gateway_image_and_release_catalog(self):
        root=Path(__file__).resolve().parents[2]
        docker=(root/'fortis_approvals/deploy/Dockerfile-Gateway-Modularized-Candidate').read_text()
        catalog=(root/'release/targets.yaml').read_text()
        for name in ('fortis_approvals/diagnostic_contract.py',
                     'fortis_approvals/workflow/artifact_diagnostics.py'):
            with self.subTest(name=name):
                self.assertIn(name,docker)
                self.assertIn(name,catalog)
        self.assertIn('  - release/**',catalog)
        self.assertIn('  - fortis_approvals/workflow/client.py',catalog)
        # Repo-only client is not baked into the Primary Gateway image.
        self.assertNotIn('fortis_approvals/workflow/client.py',docker)
        ci=(root/'scripts/test-source.sh').read_text()
        for name in ('test_pr1_git_push_audit_phase.py',
                     'test_pr1b_github_read_errors.py',
                     'test_pr1c_github_http_signals.py',
                     'test_pr1d_create_pr_phases_precore.py',
                     'test_pr1e_diagnostic_contract.py',
                     'test_pr1f_closure.py',
                     'test_pr1g_artifact_validation_phase.py',
                     'test_pr1h_final_contract.py'):
            self.assertIn(name,ci)
        self.assertIn('python -B -m compileall',(
            root/'.github/workflows/source-ci.yml').read_text())

    def test_capability_does_not_claim_recovery(self):
        from fortis_approvals.diagnostic_contract import advertised_diagnostic_capability as cap
        data=cap()
        self.assertFalse(data['automaticRetry'])
        self.assertEqual(data['outcomeResolver'],'NOT_IMPLEMENTED')
        self.assertEqual(data['effectAssessment'],'NOT_AN_OUTCOME_VERDICT')
        self.assertEqual(data['githubWriteAudit']['phaseCodes'],
                         ['push_commits','create_pull_request'])

if __name__=='__main__':
    unittest.main()

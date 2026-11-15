"""PR1E: explicit diagnostic v2 capability + old/new error-wire compatibility."""
from io import BytesIO
from pathlib import Path
import json
import tempfile
import unittest
from types import SimpleNamespace
from urllib.error import HTTPError

from fortis_approvals.clients.gateway_transport import GatewayTransport
from fortis_approvals.core import Authenticator, Denied
from fortis_approvals.diagnostic_contract import (
    DIAGNOSTIC_VERSION, DIAGNOSTIC_VERSION_HEADER,
    advertised_diagnostic_capability, inspect_diagnostic_capability)
from fortis_approvals.integrations.github.gateway.transport import GitHubTransportError
from fortis_approvals.repo_ingress import RepoIngress
from fortis_approvals.workflow.ingress import NativeIngress
from fortis_approvals.workflow.client import WorkflowClient

GRANT='z'*48

class FakeBroker:
    def __init__(self):
        self.core=SimpleNamespace(auth=Authenticator({GRANT:'actor'}),
            _policy=lambda actor,request:'DENY')
        self.exc=GitHubTransportError('GITHUB_HTTP_403')
        self.submit_calls=0
    def read(self,grant,action):
        raise self.exc
    def submit(self,grant,action):
        self.submit_calls+=1
        return {'state':'PENDING','requestId':action['requestId']}

class FakeFail:
    def __init__(self,body,headers,status):
        self.body=body;self.headers=headers;self.status=status
    def open(self,req,timeout):
        raise HTTPError(req.full_url,self.status,'offline',self.headers,BytesIO(self.body))

class FakeCapabilities:
    def __init__(self,result):self.result=result;self.calls=[]
    def post(self,path,body):
        self.calls.append((path,body))
        if isinstance(self.result,Exception):raise self.result
        return self.result

class ContractTests(unittest.TestCase):
    def setUp(self):
        self.broker=FakeBroker()
        self.app=RepoIngress(self.broker,host='gw.example')

    def ingress_call(self,path,payload):
        raw=json.dumps(payload).encode()
        env=dict(HTTP_HOST='gw.example',QUERY_STRING='',PATH_INFO=path,
            REQUEST_METHOD='POST',CONTENT_TYPE='application/json',
            CONTENT_LENGTH=str(len(raw)),HTTP_AUTHORIZATION='Bearer '+GRANT,
            **{'wsgi.input':BytesIO(raw),'wsgi.url_scheme':'https'})
        meta=[]
        body=b''.join(self.app(env,lambda s,h:meta.append((int(s[:3]),dict(h)))))
        return meta[0][0],meta[0][1],body

    def client_error(self,status,body,headers,path):
        with tempfile.TemporaryDirectory() as d:
            grant=Path(d)/'grant';cert=Path(d)/'cert'
            grant.write_text(GRANT);grant.chmod(0o600);cert.write_text('offline')
            cli=GatewayTransport(read_attempts=1,endpoint='http://localhost:19899',
                grant_path=str(grant),certificate_path=str(cert),
                opener=FakeFail(body,headers,status))
            with self.assertRaises(Denied) as caught:
                cli.post(path,dict(hello='world'))
            return str(caught.exception)

    def test_v2_server_preserves_old_read_json_and_adds_version_header(self):
        req=dict(requestId='a'*36,service='github',operation='list_issues',
            target='repo',params={},reason='offline')
        status,headers,payload=self.ingress_call('/v1/reads',req)
        self.assertEqual(status,500)
        self.assertEqual(headers[DIAGNOSTIC_VERSION_HEADER],'2')
        # Exactly PR1B legacy envelope, no additional JSON keys.
        self.assertEqual(json.loads(payload),{
            'error':'REPO_GITHUB_READ_FAILED','providerCode':'GITHUB_HTTP_403'})
        self.assertEqual(self.client_error(status,payload,headers,'/v1/reads'),
            'FORTIS_READ_GITHUB_HTTP_403')

    def test_v2_precore_marker_is_explicit_but_attempt_local(self):
        invalid=dict(requestId='b'*36,service='github',operation='create_pull_request',
            target='repo',params={},reason='offline')
        status,headers,payload=self.ingress_call('/v1/actions',invalid)
        self.assertEqual(status,403)
        self.assertEqual(json.loads(payload),{'error':'REPO_DENIED'})
        self.assertEqual(headers[DIAGNOSTIC_VERSION_HEADER],'2')
        self.assertEqual(headers['X-Fortis-Admission'],'PRE_CORE_VALIDATION_REJECTED')
        self.assertEqual(self.broker.submit_calls,0)
        self.assertEqual(self.client_error(status,payload,headers,'/v1/actions'),
            'FORTIS_PRE_CORE_VALIDATION_REJECTED')

    def test_new_client_accepts_bounded_legacy_v1_and_v2(self):
        old={'error':'REPO_GITHUB_READ_FAILED','providerCode':'GITHUB_HTTP_403'}
        raw=json.dumps(old).encode()
        for headers in ({},{DIAGNOSTIC_VERSION_HEADER:'2'}):
            with self.subTest(headers=headers):
                self.assertEqual(self.client_error(500,raw,headers,'/v1/reads'),
                    'FORTIS_READ_GITHUB_HTTP_403')
        # Valid legacy pre-Core attempt-local marker remains recognized.
        headers={'X-Fortis-Admission':'PRE_CORE_VALIDATION_REJECTED'}
        self.assertEqual(self.client_error(403,b'{}',headers,'/v1/actions'),
            'FORTIS_PRE_CORE_VALIDATION_REJECTED')

    def test_unknown_versions_are_not_interpreted(self):
        raw=json.dumps({'error':'REPO_GITHUB_READ_FAILED',
                        'providerCode':'GITHUB_HTTP_403'}).encode()
        for v in ('0','3','2.0',' 2',True,'UNKNOWN-SECRET'):
            with self.subTest(version=v):
                h={DIAGNOSTIC_VERSION_HEADER:v}
                self.assertEqual(self.client_error(500,raw,h,'/v1/reads'),
                    'FORTIS_HTTP_500')
                h['X-Fortis-Admission']='PRE_CORE_VALIDATION_REJECTED'
                self.assertEqual(self.client_error(403,b'{}',h,'/v1/actions'),
                    'FORTIS_HTTP_403')

    def test_old_gateway_error_does_not_claim_new_capabilities(self):
        self.assertEqual(self.client_error(500,
            b'{"error":"REPO_OUTCOME_UNCONFIRMED"}',{},'/v1/reads'),
            'FORTIS_HTTP_500')
        self.assertEqual(inspect_diagnostic_capability(None)['status'],
            'NOT_ADVERTISED')
        self.assertEqual(inspect_diagnostic_capability(
            {'schemaVersion':True})['status'],'UNRECOGNIZED')

    def test_capabilities_advertised_on_existing_native_read_only_route(self):
        config=SimpleNamespace(owner='owner',repository='repo',
                                dynamic_repositories=False,ci_control_repositories=())
        native=NativeIngress(SimpleNamespace(broker=self.broker),
            github=SimpleNamespace(config=config),workspace=None,store=None,actor='actor')
        caps=native._dispatch('/v1/workspace/capabilities',{},GRANT,'actor')
        self.assertEqual(caps['diagnosticContract'],advertised_diagnostic_capability())
        self.assertEqual(caps['diagnosticContract']['schemaVersion'],DIAGNOSTIC_VERSION)
        self.assertFalse(caps['diagnosticContract']['automaticRetry'])
        self.assertEqual(caps['diagnosticContract']['outcomeResolver'],'NOT_IMPLEMENTED')
        self.assertEqual(caps['incidentInventory']['diagnostic'],'evidence-stage-v1')

    def test_workflow_client_version_gate_and_no_recovery(self):
        for record,want in (
            ({},'NOT_ADVERTISED'),
            ({'diagnosticContract':advertised_diagnostic_capability()},'SUPPORTED'),
            ({'diagnosticContract':{'schemaVersion':3}},'UNRECOGNIZED'),
            ({'diagnosticContract':{'schemaVersion':True}},'UNRECOGNIZED'),
            ({'diagnosticContract':{'schemaVersion':2,'automaticRetry':True}},'UNRECOGNIZED')):
            with self.subTest(want=want,record=record):
                fake=FakeCapabilities(record)
                cli=WorkflowClient(gateway=fake,worker=None)
                out=cli.diagnostic_capabilities()
                self.assertEqual(out['status'],want)
                self.assertFalse(out['automaticRetry'])
                self.assertEqual(fake.calls,[('/v1/workspace/capabilities',{})])

    def test_capability_transport_errors_not_mislabeled_legacy(self):
        cli=WorkflowClient(gateway=FakeCapabilities(Denied('FORTIS_HTTP_404')),worker=None)
        with self.assertRaisesRegex(Denied,'FORTIS_HTTP_404'):
            cli.diagnostic_capabilities()
        cli=WorkflowClient(gateway=FakeCapabilities([]),worker=None)
        with self.assertRaisesRegex(Denied,'WORKFLOW_CAPABILITIES_RESPONSE_INVALID'):
            cli.diagnostic_capabilities()

    def test_no_headers_or_capabilities_expand_route_permissions(self):
        with tempfile.TemporaryDirectory() as d:
            grant=Path(d)/'grant';cert=Path(d)/'cert'
            grant.write_text(GRANT);grant.chmod(0o600);cert.write_text('offline')
            cli=GatewayTransport(read_attempts=1,endpoint='http://localhost:19899',
                grant_path=str(grant),certificate_path=str(cert),
                opener=FakeFail(b'{}',{},500))
            with self.assertRaisesRegex(Denied,'FORTIS_GATEWAY_ROUTE_DENIED'):
                cli.post('/v1/owner/pending',{})
            with self.assertRaisesRegex(Denied,'FORTIS_GATEWAY_ROUTE_DENIED'):
                cli.post('/v1/workspace/capabilities',{}) # WorkflowTransport only
if __name__=='__main__':unittest.main()

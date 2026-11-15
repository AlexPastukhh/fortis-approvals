"""PR1H: bounded GitHub evidence, exact new-branch mismatch, incident v2."""
from contextlib import contextmanager
from io import BytesIO
from pathlib import Path
from types import SimpleNamespace
from urllib.error import HTTPError
import json
import tempfile
import unittest
import uuid

from fortis_approvals.core import Authenticator, Denied, Stale
from fortis_approvals.incidents import IncidentCore
from fortis_approvals.synthetic import SyntheticAdapter
from fortis_approvals.integrations.github.gateway.transport import (
    GitHubHTTPTransport, GitHubTransportError)
from fortis_approvals.integrations.github.read_failure_codes import (
    bounded_rate_limit_reset,safe_read_route_class,
    PROVIDER_ROUTE_CLASS_HEADER,PROVIDER_METHOD_CLASS_HEADER,
    PROVIDER_RATE_RESET_HEADER)
from fortis_approvals.clients.gateway_transport import GatewayTransport
from fortis_approvals.workflow.client import WorkflowTransport
from fortis_approvals.repo_ingress import RepoIngress
from fortis_approvals.workflow.git_backend import GitHubGitBackend
from fortis_approvals.workflow.artifact_diagnostics import (
    bounded_artifact_error,bounded_artifact_phase)
from fortis_approvals.workflow.incident_read import diagnose,diagnose_v2
from fortis_approvals.workflow.ingress import NativeIngress

TOKEN='a'*64
GRANT='b'*48
RESET=1800000000
MAIN='f'*40
NEW='e'*40

class Upstream403:
    def __init__(self,headers,status=403):
        self.headers=headers;self.status=status
    def open(self,req,timeout):
        raise HTTPError(req.full_url,self.status,'offline',self.headers,
                        BytesIO(b'SECRET_GITHUB_RESPONSE_DO_NOT_FORWARD'))

class GatewayFail:
    def __init__(self,headers,body,status=500):
        self.headers=headers;self.body=body;self.status=status
    def open(self,req,timeout):
        raise HTTPError(req.full_url,self.status,'offline',self.headers,BytesIO(self.body))

class Broker:
    def __init__(self,exc):
        self.core=SimpleNamespace(auth=Authenticator({GRANT:'actor'}))
        self.exc=exc
    def read(self,*args):
        raise self.exc

class FinalContractTests(unittest.TestCase):
    def github_error(self,headers,method='GET',path='/repos/owner/repo/pulls/4',status=403):
        t=GitHubHTTPTransport(TOKEN,opener=Upstream403(headers,status))
        with self.assertRaises(GitHubTransportError) as caught:
            t.request(method,path,body={} if method=='POST' else None)
        return caught.exception

    def bridge(self,exc):
        broker=Broker(exc)
        app=RepoIngress(broker,host='gw.test',max_requests=300)
        payload=json.dumps(dict(service='github',operation='list_pull_requests',
             requestId=str(uuid.uuid4()),target='repo',params={},reason='offline')).encode()
        env={'HTTP_HOST':'gw.test','QUERY_STRING':'','PATH_INFO':'/v1/reads',
             'REQUEST_METHOD':'POST','CONTENT_TYPE':'application/json',
             'CONTENT_LENGTH':str(len(payload)),
             'HTTP_AUTHORIZATION':'Bearer '+GRANT,
             'wsgi.url_scheme':'https','wsgi.input':BytesIO(payload)}
        started=[]
        body=b''.join(app(env,lambda status,headers:started.append(
            (int(status[:3]),dict(headers)))))
        self.assertEqual(started[0][0],500)
        return started[0][1],body

    def downstream(self,headers,body):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)
            grant=p/'grant';cert=p/'cert'
            grant.write_text(GRANT);grant.chmod(0o600);cert.write_text('offline')
            client=GatewayTransport(read_attempts=1,endpoint='http://localhost:19713',
                grant_path=str(grant),certificate_path=str(cert),
                opener=GatewayFail(headers,body))
            with self.assertRaises(Denied) as caught:
                client.post('/v1/reads',dict(dummy='offline'))
            return caught.exception

    def test_full_provider_403_evidence_preserves_exact_old_json(self):
        exc=self.github_error({
            'X-RateLimit-Remaining':'0',
            'X-RateLimit-Reset':str(RESET),
            'Retry-After':'120',
        })
        self.assertEqual(str(exc),'GITHUB_HTTP_403')
        self.assertEqual(exc.signal,'PRIMARY_RATE_LIMIT_REPORTED')
        self.assertEqual((exc.route_class,exc.method_class,exc.rate_limit_reset),
                         ('PULL_REQUESTS','READ',RESET))
        headers,body=self.bridge(exc)
        self.assertEqual(json.loads(body),{
            'error':'REPO_GITHUB_READ_FAILED','providerCode':'GITHUB_HTTP_403',
            'signal':'PRIMARY_RATE_LIMIT_REPORTED'})
        self.assertEqual(headers[PROVIDER_ROUTE_CLASS_HEADER],'PULL_REQUESTS')
        self.assertEqual(headers[PROVIDER_METHOD_CLASS_HEADER],'READ')
        self.assertEqual(headers[PROVIDER_RATE_RESET_HEADER],str(RESET))
        self.assertNotIn('SECRET_GITHUB_RESPONSE',body.decode())
        denied=self.downstream(headers,body)
        self.assertEqual(str(denied),
            'FORTIS_READ_GITHUB_HTTP_403_PRIMARY_RATE_LIMIT_REPORTED')
        self.assertEqual(denied.provider_metadata,{
            'routeClass':'PULL_REQUESTS','methodClass':'READ','rateLimitReset':RESET})
        self.assertNotIn('rateLimitReset',str(denied))
        self.assertNotIn('SAFE_TO_RETRY',str(denied))

    def test_reset_is_evidence_only_without_zero_remaining(self):
        exc=self.github_error({'X-RateLimit-Remaining':'4','X-RateLimit-Reset':str(RESET)})
        self.assertIsNone(exc.signal)  # a reset header alone is not throttling proof
        headers,body=self.bridge(exc)
        self.assertNotIn('signal',json.loads(body))
        self.assertEqual(self.downstream(headers,body).provider_metadata['rateLimitReset'],RESET)

    def test_reset_rejects_invalid_dates_and_untrusted_values(self):
        for value in ('1','0','-1','NaN','1800000000.0','04102444800',
                      '9999999999','1800000000\r\nBearer fake','1800000000'*80):
            with self.subTest(value=value):
                self.assertIsNone(bounded_rate_limit_reset(403,
                    {'X-RateLimit-Reset':value}))
        self.assertIsNone(bounded_rate_limit_reset(200,
            {'X-RateLimit-Reset':str(RESET)}))
        self.assertIsNone(bounded_rate_limit_reset(True,
            {'X-RateLimit-Reset':str(RESET)}))
        self.assertIsNone(bounded_rate_limit_reset(403,object()))

    def test_closed_route_classes_without_leaking_path(self):
        cases={
            '/user/repos':'ACCOUNT_REPOSITORIES',
            '/repos/alice/r':'REPOSITORY_METADATA',
            '/repos/alice/r/branches':'BRANCHES',
            '/repos/alice/r/pulls/12':'PULL_REQUESTS',
            '/repos/alice/r/commits/abc/status':'CHECKS',
            '/repos/alice/r/actions/runs/1':'ACTIONS',
            '/repos/alice/r/issues/12':'ISSUES',
            '/repos/alice/r/rules/branches/main':'RULES',
        }
        for path,expected in cases.items():
            with self.subTest(path=path):
                self.assertEqual(safe_read_route_class('GET',path),expected)
        self.assertIsNone(safe_read_route_class('POST','/repos/a/b/pulls'))

    def test_invalid_forged_header_is_not_trusted_by_client(self):
        exc=self.github_error({'X-RateLimit-Reset':str(RESET)})
        headers,body=self.bridge(exc)
        for field,forgery in (
            (PROVIDER_ROUTE_CLASS_HEADER,'../SECRET'),
            (PROVIDER_METHOD_CLASS_HEADER,'WRITE'),
            (PROVIDER_RATE_RESET_HEADER,'SECRETS'),
        ):
            with self.subTest(field=field):
                bad=dict(headers);bad[field]=forgery
                self.assertIsNone(self.downstream(bad,body).provider_metadata)
        wrong_version=dict(headers)
        wrong_version['X-Fortis-Diagnostic-Contract']='99'
        error=self.downstream(wrong_version,body)
        self.assertEqual(str(error),'FORTIS_HTTP_500')

    def test_write_http_error_does_not_claim_read_metadata(self):
        exc=self.github_error({'X-RateLimit-Reset':str(RESET)},
            method='POST',path='/repos/owner/repo/pulls')
        self.assertEqual(exc.route_class,'PULL_REQUESTS')
        self.assertEqual(exc.method_class,'WRITE')
        self.assertIsNone(exc.signal)
        # Even if a WRITE error carries bounded evidence internally, it must
        # never be mistaken for a READ result or an authorization to replay.
        self.assertEqual(exc.rate_limit_reset,RESET)

    def test_new_branch_remote_exists_has_exact_stale_code_and_phase(self):
        with tempfile.TemporaryDirectory() as tmp:
            backend=GitHubGitBackend(Path(tmp)/'git',owner='offline',
                repositories={'repo'})
            @contextmanager
            def credentials(_):
                yield None
            backend.credentials=credentials
            backend._fetch=lambda *a:None
            backend.git.text=lambda args,**kwargs:MAIN
            backend.refs=lambda _:{'task/example':NEW}
            target=dict(task='example',branch='task/example',baseSha=MAIN)
            with self.assertRaises(Stale) as caught:
                backend.validate('repo',target,None,NEW,b'not-a-real-bundle')
            self.assertEqual(str(caught.exception),'GIT_EXPECTED_REMOTE_HEAD_MISMATCH')
            self.assertEqual(bounded_artifact_error(caught.exception),
                             'GIT_EXPECTED_REMOTE_HEAD_MISMATCH')
            self.assertEqual(bounded_artifact_phase(caught.exception),'READ_REMOTE_REFS')
            # Existing branch with a stale old SHA retains its older code.
            with self.assertRaises(Stale) as caught:
                backend.validate('repo',target,'d'*40,NEW,b'not-a-real-bundle')
            self.assertEqual(str(caught.exception),'GIT_REMOTE_HEAD_CHANGED')

    def test_diagnostic_v2_is_bounded_and_does_not_assume_effect(self):
        ident=str(uuid.uuid4())
        row=dict(requestId=ident,state='UNCERTAIN',request={'service':'github'})
        events=[
            dict(at=10,state='DISPATCHED',detail={}),
            dict(at=20,state='ERROR_OBSERVED',
                 detail={'stage':'GITHUB_ADAPTER','code':'GIT_OUTCOME_TIMEOUT','phase':'push'}),
            dict(at=22,state='UNCERTAIN',detail={}),
        ]
        details={'request':row,'events':events,'eventTotal':3,'eventOffset':0,
                 'worker':None,'receipt':None}
        legacy=diagnose(details)
        before=json.dumps(details,sort_keys=True)
        v2=diagnose_v2(details)
        self.assertEqual(v2,{
            'schemaVersion':2,'requestId':ident,'origin':'GITHUB_ADAPTER',
            'phase':'push','code':'GIT_OUTCOME_TIMEOUT',
            'effectAssessment':'UNCONFIRMED','evidenceScope':'FULL_AUDIT_PAGE'})
        self.assertEqual(json.dumps(details,sort_keys=True),before)
        self.assertEqual(legacy['schemaVersion'],1)
        details['events']=[events[-1]]
        details['eventOffset']=2
        limited=diagnose_v2(details)
        self.assertEqual((limited['origin'],limited['code'],limited['evidenceScope']),
                         ('CORE_STATE','UNDETERMINED','PARTIAL_AUDIT_PAGE'))
        details['request']['state']='CLOSED_UNCONFIRMED'
        self.assertEqual(diagnose_v2(details)['effectAssessment'],'UNCONFIRMED')
        details['request']['state']='EXECUTED'
        self.assertIsNone(diagnose_v2(details))

    def test_advertised_capability_returns_isolated_structures(self):
        from fortis_approvals.diagnostic_contract import (
            advertised_diagnostic_capability,inspect_diagnostic_capability)
        advertised=advertised_diagnostic_capability()
        advertised['githubWriteAudit']['phaseCodes'].append('UNSAFE_EXTRA_OPERATION')
        self.assertEqual(inspect_diagnostic_capability(advertised)['status'],'UNRECOGNIZED')
        fresh=advertised_diagnostic_capability()
        self.assertEqual(fresh['githubWriteAudit']['phaseCodes'],
                         ['push_commits','create_pull_request'])
        self.assertEqual(inspect_diagnostic_capability(fresh)['status'],'SUPPORTED')

    def test_real_cross_actor_details_v2_has_no_core_write(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            adapter=SyntheticAdapter(root/'synthetic.sqlite')
            adapter.seed('R3','before')
            core=IncidentCore(root/'core.sqlite',adapters={'synthetic':adapter},
                policies={('synthetic','set_ask'):'ASK'},
                authenticator=Authenticator({'secret-a':'agent-a','secret-b':'agent-b'}))
            row=core.submit('agent-b',dict(requestId=str(uuid.uuid4()),
                service='synthetic',operation='set_ask',target='R3',
                params={'value':'do-not-copy'},expectedVersion=0,reason='private'))
            ident=row['requestId']
            with core._db() as db:
                db.execute("UPDATE requests SET state='UNCERTAIN',failure=? WHERE id=?",
                    ('REMOTE_OUTCOME_UNCONFIRMED',ident))
                core._event(db,ident,'DISPATCHED')
                core._event(db,ident,'UNCERTAIN')
            native=NativeIngress(SimpleNamespace(broker=SimpleNamespace(core=core)),
                github=None,workspace=None,store=None,actor='agent-a')
            count=len(core.events(ident))
            result=native._dispatch('/v1/workspace/details',
                {'requestId':ident,'eventOffset':0,'eventLimit':100},
                'secret-a','agent-a')
            self.assertEqual(result['diagnosticV2']['requestId'],ident)
            self.assertEqual(result['diagnosticV2']['effectAssessment'],'UNCONFIRMED')
            self.assertEqual(result['diagnostic']['schemaVersion'],1)
            self.assertNotIn('do-not-copy',json.dumps(result['diagnosticV2']))
            self.assertNotIn('private',json.dumps(result['diagnosticV2']))
            self.assertEqual(len(core.events(ident)),count)
            self.assertEqual(core._read(ident)['state'],'UNCERTAIN')

if __name__=='__main__':
    unittest.main()

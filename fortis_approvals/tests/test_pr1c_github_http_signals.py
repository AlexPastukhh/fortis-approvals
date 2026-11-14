"""PR1c: bounded, non-authoritative GitHub header signals; offline only."""
from io import BytesIO
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from urllib.error import HTTPError

from fortis_approvals.clients.gateway_transport import GatewayTransport
from fortis_approvals.core import Authenticator, Denied
from fortis_approvals.integrations.github.gateway.transport import (
    GitHubHTTPTransport, GitHubTransportError)
from fortis_approvals.integrations.github.read_failure_codes import (
    classify_read_http_signal, valid_read_failure_signal)
from fortis_approvals.repo_ingress import RepoIngress

TOKEN='a'*64
GRANT='b'*48

class GitHubErrorOpener:
    def __init__(self,status,headers):
        self.status=status;self.headers=headers
    def open(self, req, timeout):
        raise HTTPError(req.full_url,self.status,'offline',self.headers,BytesIO(b'SECRET-PROVIDER-BODY'))

class Bridge:
    def __init__(self):
        self.core=SimpleNamespace(auth=Authenticator({GRANT:'actor'}))
        self.exc=None
    def read(self,grant,body):
        raise self.exc
    def submit(self,grant,body):
        raise self.exc

class GatewayErrorOpener:
    def __init__(self,status,body):self.status=status;self.body=body
    def open(self,req,timeout):
        raise HTTPError(req.full_url,self.status,'offline',{},
                        BytesIO(self.body))

class HeaderSignalTests(unittest.TestCase):
    def git_error(self,status,headers):
        transport=GitHubHTTPTransport(TOKEN,opener=GitHubErrorOpener(status,headers))
        with self.assertRaises(GitHubTransportError) as caught:
            transport.request('GET','/repos/owner/repository')
        return caught.exception

    def bridge(self,exc):
        broker=Bridge();broker.exc=exc
        app=RepoIngress(broker,host='gateway.example')
        payload=json.dumps(dict(service='github',operation='list_issues',requestId='a'*36,
            target='repo',reason='offline',params={})).encode()
        env=dict(HTTP_HOST='gateway.example',QUERY_STRING='',PATH_INFO='/v1/reads',
                 REQUEST_METHOD='POST',CONTENT_TYPE='application/json',
                 CONTENT_LENGTH=str(len(payload)),HTTP_AUTHORIZATION='Bearer '+GRANT,
                 **{'wsgi.input':BytesIO(payload),'wsgi.url_scheme':'https'})
        responses=[]
        response=b''.join(app(env,lambda s,h:responses.append(int(s[:3]))))
        return responses[0],response

    def client_error(self,payload,path='/v1/reads'):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);g=root/'grant';c=root/'server.crt'
            g.write_text(GRANT);g.chmod(0o600);c.write_text('offline-cert')
            transport=GatewayTransport(endpoint='http://localhost:19001',
                grant_path=str(g),certificate_path=str(c),
                opener=GatewayErrorOpener(500,payload))
            with self.assertRaises(Denied) as caught:
                transport.post(path,dict(dummy='value'))
            return str(caught.exception)

    def test_403_without_headers_is_unclassified(self):
        exc=self.git_error(403,{})
        self.assertEqual(exc.args,('GITHUB_HTTP_403',))
        self.assertIsNone(exc.signal)
        status,payload=self.bridge(exc)
        self.assertEqual(status,500)
        self.assertEqual(json.loads(payload),
            {'error':'REPO_GITHUB_READ_FAILED','providerCode':'GITHUB_HTTP_403'})
        self.assertEqual(self.client_error(payload),'FORTIS_READ_GITHUB_HTTP_403')

    def test_primary_rate_limit_is_status_and_zero_remaining(self):
        for status in (403,429):
            with self.subTest(status=status):
                exc=self.git_error(status,{'X-RateLimit-Remaining':'0'})
                self.assertEqual(exc.signal,'PRIMARY_RATE_LIMIT_REPORTED')
                code,payload=self.bridge(exc)
                self.assertEqual(code,500)
                self.assertEqual(self.client_error(payload),
                    f'FORTIS_READ_GITHUB_HTTP_{status}_PRIMARY_RATE_LIMIT_REPORTED')

    def test_backoff_header_is_hint_not_secondary_limit_proof(self):
        exc=self.git_error(403,{'Retry-After':'60'})
        self.assertEqual(exc.signal,'BACKOFF_HEADER_PRESENT')
        _,payload=self.bridge(exc)
        self.assertEqual(json.loads(payload)['signal'],'BACKOFF_HEADER_PRESENT')
        self.assertEqual(self.client_error(payload),
            'FORTIS_READ_GITHUB_HTTP_403_BACKOFF_HEADER_PRESENT')
        self.assertNotIn('60',payload.decode())

    def test_primary_evidence_precedes_backoff_hint(self):
        exc=self.git_error(429,{'X-RateLimit-Remaining':'0','Retry-After':'75'})
        self.assertEqual(exc.signal,'PRIMARY_RATE_LIMIT_REPORTED')

    def test_permissions_required_not_permissions_missing(self):
        accepted='pull_requests=read,contents=read; issues=read,contents=read'
        exc=self.git_error(403,{'X-Accepted-GitHub-Permissions':accepted})
        self.assertEqual(exc.signal,'PERMISSION_REQUIREMENTS_ADVERTISED')
        _,payload=self.bridge(exc)
        self.assertEqual(json.loads(payload)['signal'],'PERMISSION_REQUIREMENTS_ADVERTISED')
        self.assertNotIn('pull_requests',payload.decode())
        self.assertEqual(self.client_error(payload),
            'FORTIS_READ_GITHUB_HTTP_403_PERMISSION_REQUIREMENTS_ADVERTISED')
        self.assertIsNone(classify_read_http_signal(200,
            {'X-Accepted-GitHub-Permissions':accepted}))
        self.assertIsNone(classify_read_http_signal(429,
            {'X-Accepted-GitHub-Permissions':accepted}))

    def test_lower_case_and_bad_headers_are_handled(self):
        self.assertEqual(classify_read_http_signal(403,{'x-ratelimit-remaining':'0'}),
                         'PRIMARY_RATE_LIMIT_REPORTED')
        for v in ('-1','NaN','abc','3.5','0'*600,'9999999'):
            with self.subTest(value=v):
                self.assertIsNone(classify_read_http_signal(403,{'Retry-After':v}))
        self.assertIsNone(classify_read_http_signal(403,
            {'X-Accepted-GitHub-Permissions':'issues=read\r\nAuthorization: Bearer SECRET'}))
        self.assertIsNone(classify_read_http_signal(500,{'X-RateLimit-Remaining':'0'}))
        self.assertIsNone(classify_read_http_signal(403,{'X-RateLimit-Remaining':'000'}))

    def test_unknown_codes_and_fake_signals_never_cross_boundary(self):
        for code,signal in (
            ('GITHUB_HTTP_500','PRIMARY_RATE_LIMIT_REPORTED'),
            ('GITHUB_HTTP_403','SECRET-HEADER'),
            ('GITHUB_HTTP_403','PERMISSION_DENIED'),
            ('GITHUB_HTTP_429','PERMISSION_REQUIREMENTS_ADVERTISED')
        ):
            with self.subTest(code=code,signal=signal):
                exc=GitHubTransportError(code,signal=signal)
                _,response=self.bridge(exc)
                self.assertNotIn('signal',json.loads(response))
                self.assertEqual(self.client_error(response),'FORTIS_READ_'+code)
                forged=json.dumps(dict(error='REPO_GITHUB_READ_FAILED',
                   providerCode=code,signal=signal)).encode()
                self.assertEqual(self.client_error(forged),'FORTIS_HTTP_500')

    def test_write_and_other_route_not_carried(self):
        exc=GitHubTransportError('GITHUB_HTTP_403',signal='PRIMARY_RATE_LIMIT_REPORTED')
        _,payload=self.bridge(exc)
        self.assertEqual(self.client_error(payload,path='/v1/actions'),'FORTIS_HTTP_500')
        self.assertNotIn('SECRET-PROVIDER-BODY',payload.decode())

    def test_header_evidence_does_not_change_write_retry_policy(self):
        exc=self.git_error(403,{'X-RateLimit-Remaining':'1'})
        self.assertIsNone(exc.signal)
        self.assertFalse(valid_read_failure_signal('GITHUB_HTTP_403','AUTOMATIC_RETRY'))

if __name__=='__main__':unittest.main()

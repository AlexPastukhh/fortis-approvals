"""PR1b: bounded GitHub READ errors, no GitHub/owner/production effects."""
from io import BytesIO
import json
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from urllib.error import HTTPError

from fortis_approvals.clients.gateway_transport import GatewayTransport
from fortis_approvals.core import Authenticator, Denied
from fortis_approvals.integrations.github.gateway.transport import GitHubTransportError
from fortis_approvals.integrations.github.read_failure_codes import (
    READ_FAILURE_CODES, bounded_read_failure_code)
from fortis_approvals.repo_ingress import RepoIngress

GRANT='f'*48

class FakeBroker:
    def __init__(self):
        self.core=SimpleNamespace(auth=Authenticator({GRANT:'actor'}))
        self.failure=GitHubTransportError('GITHUB_HTTP_403')
    def read(self, credential, body):
        raise self.failure
    def submit(self, credential, body):
        raise self.failure

class FailureOpener:
    def __init__(self, body, status=500):
        self.body=body;self.status=status
    def open(self, req, timeout):
        raise HTTPError(req.full_url,self.status,'Synthetic',{},BytesIO(self.body))

class ReadErrorBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.broker=FakeBroker()
        self.app=RepoIngress(self.broker,host='gateway.example',max_requests=900)
    def call(self, service='github', path='/v1/reads', token=GRANT):
        body=json.dumps(dict(requestId='a'*36,service=service,operation='list_issues',
                             target='repo',params={},reason='offline')).encode()
        env=dict(HTTP_HOST='gateway.example',QUERY_STRING='',PATH_INFO=path,
                 REQUEST_METHOD='POST',**{'wsgi.url_scheme':'https'},
                 HTTP_AUTHORIZATION='Bearer '+token,
                 CONTENT_TYPE='application/json',CONTENT_LENGTH=str(len(body)),
                 **{'wsgi.input':BytesIO(body)})
        meta=[]
        payload=b''.join(self.app(env,lambda s,h:meta.append((int(s[:3]),dict(h)))))
        return meta[0][0],json.loads(payload),meta[0][1],payload

    def _client_error(self,payload,status=500,path='/v1/reads'):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); grant=root/'grant';cert=root/'server.crt'
            grant.write_text(GRANT);grant.chmod(0o600);cert.write_text('test-only')
            client=GatewayTransport(read_attempts=1,endpoint='http://localhost:19123',
                grant_path=str(grant),certificate_path=str(cert),
                opener=FailureOpener(payload,status=status))
            with self.assertRaises(Denied) as cm:
                client.post(path,dict(requestId='x'))
            return str(cm.exception)

    def test_upstream_403_is_distinct_from_local_fortis_403(self):
        status,body,headers,raw=self.call()
        self.assertEqual(status,500)  # old client compatibility
        self.assertEqual(body,{'error':'REPO_GITHUB_READ_FAILED',
                               'providerCode':'GITHUB_HTTP_403'})
        self.assertEqual(headers['Cache-Control'],'no-store')
        self.assertEqual(self._client_error(raw),'FORTIS_READ_GITHUB_HTTP_403')
        self.assertEqual(self._client_error(raw,status=403),'FORTIS_HTTP_403')

    def test_fixed_upstream_codes_401_403_429_5xx_and_unknown(self):
        for code in ('GITHUB_HTTP_401','GITHUB_HTTP_403','GITHUB_HTTP_429',
                     'GITHUB_HTTP_500','GITHUB_HTTP_503',
                     'GITHUB_UPSTREAM_UNAVAILABLE_OR_INVALID'):
            with self.subTest(code=code):
                self.broker.failure=GitHubTransportError(code)
                status,body,_,raw=self.call()
                self.assertEqual(status,500)
                self.assertEqual(body['providerCode'],code)
                self.assertEqual(self._client_error(raw),'FORTIS_READ_'+code)
        self.broker.failure=GitHubTransportError('GitHub token SECRET-RAW-HEADER')
        status,body,_,raw=self.call()
        self.assertEqual(body['providerCode'],'GITHUB_TRANSPORT_ERROR')
        self.assertNotIn('SECRET-RAW-HEADER',raw.decode())

    def test_non_github_and_write_errors_do_not_leak_upstream(self):
        self.assertEqual(self.call(service='sonar')[1],
                         {'error':'REPO_OUTCOME_UNCONFIRMED'})
        self.assertEqual(self.call(path='/v1/actions')[1],
                         {'error':'REPO_OUTCOME_UNCONFIRMED'})
        self.assertEqual(self.call(token='wrong-token')[0],401)

    def test_untrusted_body_falls_back_to_generic_fortis_error(self):
        for payload in (
            {'error':'REPO_GITHUB_READ_FAILED','providerCode':'SECRET'},
            {'error':'REPO_GITHUB_READ_FAILED','providerCode':'GITHUB_HTTP_403','extra':'token'},
            {'error':'REPO_OTHER','providerCode':'GITHUB_HTTP_403'},
        ):
            with self.subTest(payload=payload):
                self.assertEqual(self._client_error(json.dumps(payload).encode()),
                                 'FORTIS_HTTP_500')
        self.assertEqual(self._client_error(b'{'*3000),'FORTIS_HTTP_500')
        self.assertEqual(self._client_error(b'{"error":"REPO_GITHUB_READ_FAILED","providerCode":"GITHUB_HTTP_403","providerCode":"GITHUB_HTTP_403"}'),
                         'FORTIS_HTTP_500')

    def test_error_not_accepted_on_other_routes(self):
        _,_,_,raw=self.call()
        self.assertEqual(self._client_error(raw,path='/v1/actions'),'FORTIS_HTTP_500')

    def test_bounded_code_whitelist_is_explicit(self):
        self.assertIn('GITHUB_HTTP_403',READ_FAILURE_CODES)
        self.assertNotIn('GITHUB_HTTP_999',READ_FAILURE_CODES)
        self.assertEqual(bounded_read_failure_code(GitHubTransportError('untrusted-token')),
                         'GITHUB_TRANSPORT_ERROR')

if __name__=='__main__':unittest.main()

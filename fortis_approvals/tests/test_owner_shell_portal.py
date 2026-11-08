"""Owner Portal manual Windows PowerShell routes; no Windows process is run."""
from io import BytesIO
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock
import uuid

from fortis_approvals.core import Denied
from fortis_approvals.owner_portal import OwnerPortal
from fortis_approvals.owner_shell_portal import OwnerShellPortal
from fortis_approvals.owner_shell import OwnerShellClient, ShellTransportUnavailable


class FakeOwner:
    origin = 'http://localhost:19203'
    def session(self, cookie, csrf=None):
        if cookie != 'owner-session' or csrf not in (None,'owner-csrf'):
            raise Denied('OWNER_SESSION_REQUIRED')
        return {'owner':'test-owner','csrf':'owner-csrf'}


class FakeCore:
    def __init__(self, owner):
        self.owner_verifier = owner


class FakeExecutor:
    def __init__(self):
        self.calls=[]
        self.fail=False
    def execute(self, script, request_id):
        self.calls.append((script,request_id))
        if self.fail:
            raise ShellTransportUnavailable('OWNER_SHELL_OUTCOME_UNCONFIRMED')
        return {'requestId':request_id,'state':'EXECUTED','exitCode':0,
                'stdout':'OK','stderr':'','commandSha256':'a'*64}
    def status(self, request_id):
        return {'requestId':request_id,'state':'EXECUTED'}


class OwnerShellPortalRouteTests(unittest.TestCase):
    def setUp(self):
        self.auth=FakeOwner()
        self.runner=FakeExecutor()
        self.portal=OwnerShellPortal(FakeCore(self.auth),self.auth,owner_shell=self.runner)
        self.rid=str(uuid.uuid4())

    def call(self,method,path,body=None,*,cookie='',csrf='',origin=None,host=None):
        raw=json.dumps(body).encode('utf-8') if body is not None else b''
        env={'HTTP_HOST':host or 'localhost:19203','REQUEST_METHOD':method,
             'PATH_INFO':path,'QUERY_STRING':'','wsgi.input':BytesIO(raw),
             'CONTENT_LENGTH':str(len(raw)),'CONTENT_TYPE':'application/json'}
        if cookie:env['HTTP_COOKIE']='fortis_owner='+cookie
        if csrf:env['HTTP_X_FORTIS_CSRF']=csrf
        if origin is not None:env['HTTP_ORIGIN']=origin
        outgoing=[]
        data=b''.join(self.portal(env,lambda status,headers:outgoing.append((status,headers))))
        return int(outgoing[0][0][:3]), json.loads(data)

    def test_baseline_owner_portal_does_not_gain_shell_routes(self):
        baseline = OwnerPortal(FakeCore(self.auth), self.auth)
        old = self.portal
        self.portal = baseline
        try:
            code, result = self.call('GET', '/v1/owner/powershell/capabilities', cookie='owner-session')
            self.assertEqual(404, code)
            self.assertEqual('ROUTE_NOT_FOUND', result['error'])
            code, result = self.call('POST', '/v1/owner/powershell/execute',
                {'command':'Get-Date','requestId':self.rid}, cookie='owner-session',
                csrf='owner-csrf',origin=self.auth.origin)
            self.assertEqual(404, code)
            self.assertEqual('ROUTE_NOT_FOUND', result['error'])
            self.assertEqual([],self.runner.calls)
        finally:
            self.portal = old

    def test_login_required_for_capabilities_and_receipts(self):
        caps='/v1/owner/powershell/capabilities'
        self.assertEqual(403,self.call('GET',caps)[0])
        code,data=self.call('GET',caps,cookie='owner-session')
        self.assertEqual((200,True),(code,data['configured']))
        self.assertFalse(data['analysisAvailable'])
        self.assertFalse(data['otherAIAvailable'])
        receipt='/v1/owner/powershell/results/'+self.rid
        self.assertEqual(403,self.call('GET',receipt)[0])
        self.assertEqual(200,self.call('GET',receipt,cookie='owner-session')[0])

    def test_execute_requires_owner_session_exact_origin_and_csrf(self):
        path='/v1/owner/powershell/execute';body={'command':'Get-Date','requestId':self.rid}
        for label,args in [
            ('not logged in', {'origin':self.auth.origin,'csrf':'owner-csrf'}),
            ('missing origin', {'cookie':'owner-session','csrf':'owner-csrf'}),
            ('wrong origin', {'cookie':'owner-session','csrf':'owner-csrf','origin':'http://example.test'}),
            ('missing csrf', {'cookie':'owner-session','origin':self.auth.origin}),
            ('wrong csrf', {'cookie':'owner-session','csrf':'wrong','origin':self.auth.origin}),
            ('wrong host', {'cookie':'owner-session','csrf':'owner-csrf','origin':self.auth.origin,'host':'other.test'}),
        ]:
            with self.subTest(label=label):
                code,_=self.call('POST',path,body,**args)
                self.assertEqual(403,code)
        self.assertEqual([],self.runner.calls)
        code,result=self.call('POST',path,body,cookie='owner-session',csrf='owner-csrf',origin=self.auth.origin)
        self.assertEqual(200,code)
        self.assertEqual('EXECUTED',result['state'])
        self.assertEqual([('Get-Date',self.rid)],self.runner.calls)

    def test_invalid_body_and_readonly_portal_fail_closed(self):
        path='/v1/owner/powershell/execute';good={'command':'Get-Date','requestId':self.rid}
        for bad in ({'command':'Get-Date'},{**good,'extra':'x'},
                    {**good,'command':'x'*8193},{**good,'command':'\x00'},
                    {**good,'requestId':'not-uuid'}):
            with self.subTest(bad=str(bad)[:50]):
                code,_=self.call('POST',path,bad,cookie='owner-session',csrf='owner-csrf',origin=self.auth.origin)
                self.assertEqual(403,code)
        self.assertEqual([],self.runner.calls)
        self.portal.read_only_banner=True
        self.assertEqual(403,self.call('POST',path,good,cookie='owner-session',csrf='owner-csrf',origin=self.auth.origin)[0])
        self.portal=OwnerShellPortal(self.portal.core,self.auth,owner_shell=None)
        code,caps=self.call('GET','/v1/owner/powershell/capabilities',cookie='owner-session')
        self.assertEqual(200,code)
        self.assertFalse(caps['configured'])
        self.assertEqual(403,self.call('POST',path,good,cookie='owner-session',csrf='owner-csrf',origin=self.auth.origin)[0])

    def test_downstream_timeout_never_claims_success(self):
        self.runner.fail=True
        code,answer=self.call('POST','/v1/owner/powershell/execute',
                              {'command':'Get-Date','requestId':self.rid},
                              cookie='owner-session',csrf='owner-csrf',origin=self.auth.origin)
        self.assertEqual(503,code)
        self.assertEqual('OWNER_SHELL_OUTCOME_UNCONFIRMED',answer['error'])
        self.assertEqual(1,len(self.runner.calls))


class OwnerShellClientConfigTests(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory();self.addCleanup(tmp.cleanup)
        self.base=Path(tmp.name)
        self.inputs=[]
        for name in ('ca.pem','client.crt','client.key','secret'):
            p=self.base/name;p.write_text('s'*40)
            p.chmod(0o600)
            self.inputs.append(str(p))

    def config(self):
        return {'port':10443,'serverCA':self.inputs[0], 'clientCert':self.inputs[1],
                'clientKey':self.inputs[2],'secretFile':self.inputs[3]}

    def test_config_exact_schema_and_fixed_host(self):
        self.assertIsNone(OwnerShellClient.from_environment({}))
        for bad in ({**self.config(),'url':'https://evil.test'},
                    {**self.config(),'port':443},
                    {**self.config(),'port':'10443'},
                    {'port':10443}):
            with self.subTest(bad=bad):
                with self.assertRaises(Denied):
                    OwnerShellClient.from_environment({'FORTIS_OWNER_SHELL_CONFIG':json.dumps(bad)})
        class FakeContext:
            minimum_version=None
            def load_cert_chain(self,**kwargs):return None
        class FakeOpener:
            def open(self,*args,**kwargs):raise AssertionError('no transport requests here')
        with mock.patch('fortis_approvals.owner_shell.ssl.create_default_context',return_value=FakeContext()), \
             mock.patch('fortis_approvals.owner_shell.request.build_opener',return_value=FakeOpener()):
            client=OwnerShellClient.from_environment({'FORTIS_OWNER_SHELL_CONFIG':json.dumps(self.config())})
        self.assertEqual('https://host.docker.internal:10443',client.origin)
        self.assertEqual('s'*40,client.secret)


if __name__=='__main__':unittest.main()

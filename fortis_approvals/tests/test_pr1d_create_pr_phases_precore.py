"""PR1D: attempt-local admission and post-dispatch PR creation stage, offline."""
from io import BytesIO
import json
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch
from urllib.error import HTTPError
import uuid

from fortis_approvals.clients.gateway_transport import GatewayTransport
from fortis_approvals.core import Authenticator, Core, Denied
from fortis_approvals.integrations.github.gateway.adapter import GitHubAdapter
from fortis_approvals.integrations.github.gateway.transport import GitHubTransportError
from fortis_approvals.integrations.github.gateway.pr_create_diagnostic import (
    GitHubPRCreateFailure, PR_CREATE_PHASES)
from fortis_approvals.repo_ingress import RepoIngress
from fortis_approvals.workflow.error_diagnostics import category, observe_adapter
from fortis_approvals.workflow.incident_read import diagnose

GRANT='m'*48
HEAD='b'*40
BASE='a'*40

class FakeTransport:
    def __init__(self,mode):
        self.mode=mode
        self.posts=0
        self.ref_gets=0
    def request(self, method,path,**kwargs):
        if method=='GET' and '/git/ref/heads/' in path:
            self.ref_gets+=1
            if self.mode=='revalidate' and self.ref_gets==5:
                raise GitHubTransportError('GITHUB_UPSTREAM_UNAVAILABLE_OR_INVALID')
            return {'object':{'sha':BASE if path.endswith('/main') else HEAD}}
        if method=='POST' and path.endswith('/pulls'):
            self.posts+=1
            if self.mode=='post':
                raise GitHubTransportError('GITHUB_HTTP_403')
            if self.mode=='unknown':
                raise RuntimeError('SECRET-PR-ERROR')
            return {'number':0 if self.mode=='post_response' else 7}
        if method=='GET' and path.endswith('/pulls/7'):
            if self.mode=='readback':
                raise GitHubTransportError('GITHUB_UPSTREAM_UNAVAILABLE_OR_INVALID')
            return {'number':7,'title':'offline','state':'open','draft':False,
                'head':{'ref':'task/unit','sha':HEAD},'base':{'ref':'main','sha':BASE},
                'merged':False,'html_url':'https://github.com/owner/repo/pull/7'}
        raise AssertionError('UNEXPECTED FAKE ROUTE '+method+' '+path)

class AuditedAdapter(GitHubAdapter):
    @observe_adapter('GITHUB_ADAPTER')
    def apply(self,request):
        return super().apply(request)

class LocalBroker:
    def __init__(self):
        self.core=SimpleNamespace(auth=Authenticator({GRANT:'actor'}))
        self.calls=0
    def submit(self,token,intent):
        self.calls+=1
        return {'requestId':intent['requestId'],'state':'PENDING'}

class HTTPFail:
    def __init__(self,headers,status=403):
        self.headers=headers;self.status=status
    def open(self,request,timeout):
        raise HTTPError(request.full_url,self.status,'offline',self.headers,BytesIO(b'{}'))

class PR1DTests(unittest.TestCase):
    def _case(self,mode):
        with tempfile.TemporaryDirectory() as tmp:
            gh=FakeTransport(mode)
            adapter=AuditedAdapter(gh,owner='owner',repositories={'repo'},
                                   receipt_store=Path(tmp)/'receipts.sqlite')
            core=Core(Path(tmp)/'core.sqlite',adapters={'github':adapter},
                policies={('actor','github','create_pull_request'):'ALLOW'},
                authenticator=Authenticator({'offline':'actor'}))
            adapter.core=core
            if mode=='receipt':
                ctx=patch.object(adapter,'_save_receipt',side_effect=OSError('SECRET-DB-TEXT'))
            else:
                from contextlib import nullcontext
                ctx=nullcontext()
            with ctx:
                row=core.submit('actor',{'requestId':str(uuid.uuid4()),
                    'service':'github','operation':'create_pull_request','target':'repo',
                    'params':{'title':'offline','body':'','head':'task/unit',
                              'base':'main','draft':False},
                    'expectedVersion':0,'reason':'isolated PR create check'})
            events=[{'state':e['state'],'at':e['at'],'detail':json.loads(e['detail'])}
                    for e in core.events(row['requestId'])]
            diagnosis=diagnose(dict(request=row,worker=None,receipt=None,events=events))
            return row,events,diagnosis,gh.posts

    def test_create_phases_persist_without_claiming_remote_result(self):
        expected={
            'revalidate':('GITHUB_UPSTREAM_UNAVAILABLE_OR_INVALID',0),
            'post':('GITHUB_HTTP_403',1),
            'post_response':('GITHUB_PR_READBACK_UNCONFIRMED',1),
            'readback':('GITHUB_UPSTREAM_UNAVAILABLE_OR_INVALID',1),
            'receipt':('GITHUB_PR_CREATE_STEP_UNCONFIRMED',1),
            'unknown':('GITHUB_PR_CREATE_STEP_UNCONFIRMED',1),
        }
        for mode,(code,posts) in expected.items():
            with self.subTest(mode=mode):
                row,events,diagnosis,count=self._case(mode)
                phase='post' if mode=='unknown' else mode
                self.assertEqual((row['state'],row['failure']),
                    ('UNCERTAIN','REMOTE_OUTCOME_UNCONFIRMED'))
                self.assertEqual(count,posts)
                self.assertEqual(events[-2]['state'],'ERROR_OBSERVED')
                self.assertEqual(events[-2]['detail'],
                    {'stage':'GITHUB_ADAPTER','code':code,'phase':phase})
                self.assertEqual(diagnosis['coreError'],events[-2]['detail'])
                self.assertEqual(diagnosis['originalEffect'],'UNCONFIRMED')

    def test_tampered_phase_or_code_fail_closed(self):
        err=GitHubPRCreateFailure('post','GITHUB_HTTP_403')
        err.phase='UNTRUSTED-SECRET'
        self.assertEqual(category(err),'GITHUB_PR_CREATE_STEP_UNCONFIRMED')
        for bogus in ({'stage':'GITHUB_ADAPTER','phase':'post','code':'SECRET'},
                      {'stage':'GITHUB_ADAPTER','phase':'bad','code':'GITHUB_HTTP_403'},
                      {'stage':'WORKER_EXECUTE','phase':'post','code':'GITHUB_HTTP_403'}):
            self.assertIsNone(diagnose({
                'request':{'state':'UNCERTAIN','request':{'service':'github'}},
                'worker':None,'receipt':None,'events':[
                    {'state':'ERROR_OBSERVED','detail':bogus}]
            })['coreError'])

    def test_pr_phase_is_strict_and_preserves_stale(self):
        from fortis_approvals.core import Stale
        from fortis_approvals.integrations.github.gateway.pr_create_diagnostic import pr_create_phase
        with self.assertRaises(ValueError):
            GitHubPRCreateFailure('untrusted-phase','GITHUB_HTTP_403')
        with self.assertRaises(Stale):
            with pr_create_phase('revalidate'):
                raise Stale('GITHUB_PR_BRANCH_CHANGED')

    def test_pre_core_validation_only_marked_before_broker_call(self):
        broker=LocalBroker()
        app=RepoIngress(broker,host='host.example')
        request={'requestId':str(uuid.uuid4()),'service':'github',
            'operation':'create_pull_request','target':'repo',
            'params':{},'reason':'offline'}
        def call(data):
            payload=json.dumps(data).encode()
            env={'HTTP_HOST':'host.example','QUERY_STRING':'',
                 'PATH_INFO':'/v1/actions','REQUEST_METHOD':'POST',
                 'wsgi.url_scheme':'https','HTTP_AUTHORIZATION':'Bearer '+GRANT,
                 'CONTENT_TYPE':'application/json','CONTENT_LENGTH':str(len(payload)),
                 'wsgi.input':BytesIO(payload)}
            rows=[]
            data=b''.join(app(env,lambda status,headers:rows.append(
                (int(status[:3]),dict(headers)))))
            return rows[0][0],rows[0][1],json.loads(data)
        code,headers,data=call(request)
        self.assertEqual(code,403)
        self.assertEqual(data,{'error':'REPO_DENIED'})
        self.assertEqual(headers.get('X-Fortis-Admission'),'PRE_CORE_VALIDATION_REJECTED')
        self.assertEqual(broker.calls,0)
        request['params']={'title':'offline','body':'','head':'task/unit',
                           'base':'main','draft':False}
        code,headers,data=call(request)
        self.assertEqual(code,202)
        self.assertNotIn('X-Fortis-Admission',headers)
        self.assertEqual(broker.calls,1)

    def test_client_accepts_fixed_pre_core_marker_only_for_actions(self):
        with tempfile.TemporaryDirectory() as d:
            grant=Path(d)/'grant';cert=Path(d)/'cert'
            grant.write_text(GRANT);grant.chmod(0o600);cert.write_text('offline')
            for path,header,expected in (
                ('/v1/actions',{'X-Fortis-Admission':'PRE_CORE_VALIDATION_REJECTED'},
                 'FORTIS_PRE_CORE_VALIDATION_REJECTED'),
                ('/v1/actions',{'X-Fortis-Admission':'BAD-SECRET'},'FORTIS_HTTP_403'),
                ('/v1/reads',{'X-Fortis-Admission':'PRE_CORE_VALIDATION_REJECTED'},'FORTIS_HTTP_403'),
            ):
                with self.subTest(path=path,header=header):
                    cli=GatewayTransport(endpoint='http://localhost:19025',
                       grant_path=str(grant),certificate_path=str(cert),
                       opener=HTTPFail(header))
                    with self.assertRaises(Denied) as caught:
                        cli.post(path,dict(dummy='offline'))
                    self.assertEqual(str(caught.exception),expected)

if __name__=='__main__':unittest.main()

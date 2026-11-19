"""Tests for additive, owner-session-only provider inventory."""
from io import BytesIO
import json
from types import SimpleNamespace
import unittest

from fortis_approvals.core import Denied
from fortis_approvals.incidents import IncidentOwnerPortal
from fortis_approvals.owner_inventory import owner_policy_inventory


class Owner:
    origin='http://localhost:19203'
    def session(self, cookie, csrf=None):
        if cookie!='valid-owner':raise Denied('OWNER_SESSION_REQUIRED')
        return {'owner':'test-owner','csrf':'some-csrf'}


class Core:
    def __init__(self, owner):
        self.owner_verifier=owner
        self.policy_version='v1'
        self.adapters={'github':object(),'sonarcloud':object(),'sample-ext':object()}
        self.policies={('alice','github','create_pull_request'):'ASK',
            ('bob','github','create_pull_request','repo-A'):'DENY',
            ('github','get_branch'):'ALLOW',
            ('alice','sonarcloud','accept_issue'):lambda actor,req:'ASK',
            ('alice','sample-ext','read_data','repo-A'):'ALLOW',
            ('alice','sample-ext','write_data','repo-A'):'ASK'}
    def _policy(self, actor, payload):
        key=(actor,payload['service'],payload['operation'],payload['target'])
        rule=self.policies.get(key,self.policies.get(key[:3],self.policies.get(key[1:3],'DENY')))
        return rule(actor,payload) if callable(rule) else rule


class Vault:
    def __init__(self):self.calls=[]
    def readiness(self, alias):
        self.calls.append(alias)
        return {'ready': alias=='good-token',
                'status': 'READY' if alias=='good-token' else 'MISSING'}


def runtime():
    op=lambda name,kind,cred:SimpleNamespace(name=name,kind=kind,version='2',ready=True,
        credential=cred,signing_credential=None)
    provider=SimpleNamespace(source_digest='abc',operations=(
        op('read_data','read','read_auth'),op('write_data','write','write_auth'),
        op('not_enabled','read',None)))
    return SimpleNamespace(providers={'sample-ext':provider},
        credentials={'sample-ext':{'read_auth':'good-token','write_auth':'bad-token'}},
        rules={('alice','sample-ext','read_data','repo-A'):'ALLOW',
               ('alice','sample-ext','write_data','repo-A'):'ASK'},vault=Vault())


class InventoryTests(unittest.TestCase):
    def setUp(self):
        self.owner=Owner();self.core=Core(self.owner);self.runtime=runtime()
        self.portal=IncidentOwnerPortal(self.core,self.owner)
        self.portal._extension_runtime=self.runtime

    def call(self,cookie='',host='localhost:19203',query='',headers=None,method='GET'):
        env={'HTTP_HOST':host,'REQUEST_METHOD':method,'PATH_INFO':'/v1/owner/provider-inventory',
             'QUERY_STRING':query,'wsgi.input':BytesIO(b''),'CONTENT_LENGTH':'0',
             'CONTENT_TYPE':'application/json'}
        if cookie:env['HTTP_COOKIE']='fortis_owner='+cookie
        if headers:env.update(headers)
        out=[];body=b''.join(self.portal(env,lambda status,h:out.append((status,h))))
        return int(out[0][0][:3]),json.loads(body),dict(out[0][1])

    def test_owner_only_and_host_fail_closed(self):
        code,data,_=self.call();self.assertEqual((403,'OWNER_SESSION_REQUIRED'),(code,data['error']))
        for opts in ({'host':'other.test'},{'query':'x=1'},
                     {'headers':{'HTTP_AUTHORIZATION':'Bearer x'}},
                     {'headers':{'HTTP_X_FORWARDED_HOST':'evil.test'}}):
            with self.subTest(opts=opts):
                code,data,_=self.call('valid-owner',**opts)
                self.assertEqual((403,'HOST_DENIED'),(code,data['error']))
        self.assertEqual(403,self.call('valid-owner',method='POST')[0])

    def test_inventory_is_read_only_secret_free_and_unverified_upstream(self):
        code,data,headers=self.call('valid-owner')
        self.assertEqual(200,code)
        self.assertEqual('no-store',headers['Cache-Control'])
        self.assertEqual(('v1','LOADED_GATEWAY_RUNTIME_ONLY'),(data['policyVersion'],data['coverage']))
        self.assertEqual('extension',next(p['type'] for p in data['providers'] if p['provider']=='sample-ext'))
        policy=next(r for r in data['operations'] if r['provider']=='github' and r['scope']=='actor')
        self.assertEqual(('ASK','UNKNOWN'),(policy['configuredPolicy'],policy['effectivePolicy']))
        exact=next(r for r in data['operations'] if r['provider']=='github' and r['scope']=='exact')
        self.assertEqual('DENY',exact['effectivePolicy'])
        read=next(r for r in data['operations'] if r['operation']=='read_data')
        write=next(r for r in data['operations'] if r['operation']=='write_data')
        self.assertEqual(('ALLOW','READY','UNVERIFIED'),
            (read['effectivePolicy'],read['credentialStatus'],read['upstreamStatus']))
        self.assertEqual('NOT_READY',write['credentialStatus'])
        absent=next(r for r in data['operations'] if r['operation']=='not_enabled')
        self.assertEqual(('DENY',False),(absent['effectivePolicy'],absent['configured']))
        output=json.dumps(data)
        self.assertNotIn('good-token',output);self.assertNotIn('bad-token',output)
        self.assertEqual({'good-token','bad-token'},set(self.runtime.vault.calls))

    def test_no_extensions_and_no_native_predicate_execution(self):
        called=[]
        self.core.policies[('alice','sonarcloud','accept_issue')]=lambda a,p:called.append(1)
        data=owner_policy_inventory(self.core)
        self.assertEqual([],called)
        row=next(r for r in data['operations'] if r['operation']=='accept_issue')
        self.assertEqual(('CONDITIONAL','UNKNOWN'),(row['configuredPolicy'],row['effectivePolicy']))
        self.assertTrue(all(p['type']=='native' for p in data['providers']))


if __name__=='__main__':unittest.main()

"""Exact-scope owner policy preview. Source read-only, no grants mutated."""
from io import BytesIO
import json
import sqlite3
import tempfile
from pathlib import Path
from types import SimpleNamespace
import unittest

from fortis_approvals.core import Denied
from fortis_approvals.incidents import IncidentOwnerPortal
from fortis_approvals.extensions.owner_policy_preview import preview_policy_change
from fortis_approvals.owner_portal import OwnerPortal


class Owner:
    origin = 'http://localhost:19203'
    def session(self, token, csrf=None):
        if token != 'owner-session' or (csrf is not None and csrf != 'owner-csrf'):
            raise Denied('OWNER_SESSION_REQUIRED')
        return {'owner': 'test-owner', 'csrf': 'owner-csrf'}


class Vault:
    def __init__(self):self.calls=[]
    def readiness(self, alias):
        self.calls.append(alias)
        return {'status':'READY', 'ready':True, 'configured':True}


class Core:
    def __init__(self, owner, path):
        self.owner_verifier = owner
        self.policy_version = 'release-v6'
        self.adapters = {'github': object(), 'sample-ext': object(), 'powershell': object()}
        self.policies = {
            ('alice','github','create_pull_request','repo-A'): 'ASK',
            ('bob','github','create_pull_request','repo-A'): 'DENY',
            ('github','get_branch'): 'ALLOW',
            ('alice','sample-ext','read_data','repo-A'): 'ALLOW',
            ('alice','sample-ext','write_data','repo-A'): 'ASK',
            ('alice','powershell','execute','windows-local'): 'ASK',
        }
        self.path = path
        with self._db() as db:
            db.execute('CREATE TABLE requests(actor TEXT, payload TEXT, state TEXT)')
            for actor,service,method,target,state in [
                ('alice','github','create_pull_request','repo-A','PENDING'),
                ('alice','github','create_pull_request','repo-A','APPROVED'),
                ('alice','github','create_pull_request','repo-A','DISPATCHED'),
                ('alice','github','create_pull_request','repo-A','UNCERTAIN'),
                ('alice','github','create_pull_request','repo-A','EXECUTED'),
                ('bob','github','create_pull_request','repo-A','PENDING'),
                ('alice','github','create_pull_request','repo-B','PENDING'),
            ]:
                db.execute('INSERT INTO requests VALUES(?,?,?)',
                    (actor,json.dumps({'service':service,'operation':method,'target':target}),state))
    def _db(self):return sqlite3.connect(self.path)
    def _policy(self,actor,payload):
        raise AssertionError('Pure read model must never invoke policy callbacks')


def runtime():
    op=lambda name,kind,cred:SimpleNamespace(name=name,kind=kind,version='1',ready=True,
        credential=cred,signing_credential=None)
    provider=SimpleNamespace(source_digest='packaged-sha',operations=(
        op('read_data','read','api-read'),op('write_data','write','api-write'),
        op('not_configured','read',None)))
    return SimpleNamespace(providers={'sample-ext':provider},
        credentials={'sample-ext':{'api-read':'vault-read','api-write':'vault-write'}},
        rules={('alice','sample-ext','read_data','repo-A'):'ALLOW',
               ('alice','sample-ext','write_data','repo-A'):'ASK'},
        vault=Vault(),digest='extension-config-digest')


class PreviewTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.owner=Owner();self.core=Core(self.owner,str(Path(self.temp.name)/'requests.sqlite'))
        self.rt=runtime()
        self.portal=IncidentOwnerPortal(self.core,self.owner)
        self.portal._extension_runtime=self.rt
        self.payload={'provider':'github','operation':'create_pull_request',
                      'actor':'alice','target':'repo-A','desiredPolicy':'DENY',
                      'expectedPolicyVersion':'release-v6','expectedConfiguredPolicy':'ASK'}

    def call(self,payload=None, *, token='owner-session', csrf='owner-csrf',origin='http://localhost:19203',
             method='POST',host='localhost:19203',query='',extra=None,portal=None):
        data=json.dumps(self.payload if payload is None else payload).encode()
        env={'REQUEST_METHOD':method,'PATH_INFO':'/v1/owner/policy/preview',
             'HTTP_HOST':host,'QUERY_STRING':query,'wsgi.input':BytesIO(data),
             'CONTENT_TYPE':'application/json','CONTENT_LENGTH':str(len(data))}
        if token:env['HTTP_COOKIE']='fortis_owner='+token
        if csrf:env['HTTP_X_FORTIS_CSRF']=csrf
        if origin:env['HTTP_ORIGIN']=origin
        env.update(extra or {})
        res=[]
        body=b''.join((portal or self.portal)(env,lambda status,headers:res.append((status,headers))))
        return int(res[0][0][:3]),json.loads(body),dict(res[0][1])

    def test_owner_session_origin_csrf_strict_host_and_machine_isolation(self):
        baseline=OwnerPortal(self.core,self.owner)
        self.assertEqual(404,self.call(portal=baseline)[0])
        for case in ({'token':''},{'token':'not-owner'},{'csrf':''},{'csrf':'invalid'},
                     {'origin':''},{'origin':'http://evil.test'},
                     {'host':'evil.test'},{'query':'x=1'},
                     {'extra':{'HTTP_AUTHORIZATION':'Bearer fake'}},
                     {'extra':{'HTTP_X_FORWARDED_HOST':'evil.test'}}):
            with self.subTest(case=case):
                code,body,_=self.call(**case)
                self.assertEqual(403,code)
        self.assertEqual(404,self.call(method='GET')[0])

    def test_valid_native_exact_preview_and_unresolved_counts_are_readonly(self):
        policies_before=dict(self.core.policies)
        with self.core._db() as db:
            before=db.execute('SELECT COUNT(*) FROM requests').fetchone()[0]
        code,data,headers=self.call()
        self.assertEqual(200,code)
        self.assertEqual('no-store',headers['Cache-Control'])
        self.assertEqual('OWNER_READ_ONLY_POLICY_PREVIEW',data['kind'])
        self.assertEqual({'configuredPolicy':'ASK','effectivePolicy':'ASK'},data['current'])
        self.assertEqual({'configuredPolicy':'DENY','effectivePolicy':'DENY'},data['proposed'])
        self.assertTrue(data['changed'])
        self.assertFalse(data['canApply'])
        self.assertFalse(data['applyEnabled'])
        self.assertEqual({'PENDING':1,'APPROVED':1,'DISPATCHED':1,'UNCERTAIN':1},data['unresolvedRequests'])
        self.assertEqual('HIGH',data['risk']) # native effect kind unknown: conservative
        self.assertEqual(64,len(data['previewFingerprint']))
        self.assertEqual(data['previewFingerprint'],self.call()[1]['previewFingerprint'])
        self.assertEqual(policies_before,self.core.policies)
        with self.core._db() as db:
            after=db.execute('SELECT COUNT(*) FROM requests').fetchone()[0]
        self.assertEqual(before,after)
        self.assertNotIn('vault-read',json.dumps(data))
        self.assertNotIn('vault-write',json.dumps(data))

    def test_extension_read_and_write_preview_with_explicit_unknown_upstream(self):
        for op,old,new,risk in [('read_data','ALLOW','DENY','LOW'),
                                ('write_data','ASK','ALLOW','HIGH')]:
            candidate={**self.payload,'provider':'sample-ext','operation':op,
                       'expectedConfiguredPolicy':old,'desiredPolicy':new}
            with self.subTest(op=op):
                code,data,_=self.call(candidate)
                self.assertEqual(200,code)
                self.assertEqual(risk,data['risk'])
                self.assertEqual('extension-config-digest',data['identity']['configurationDigest'])
                self.assertEqual('packaged-sha',data['identity']['sourceDigest'])
                self.assertEqual('UNVERIFIED',data['upstreamStatus'])
                self.assertFalse(data['canApply'])

    def test_stale_version_rule_unknown_grant_and_wrong_schema_fail_closed(self):
        cases=[
            ({**self.payload,'expectedPolicyVersion':'outdated'},'OWNER_POLICY_PREVIEW_STALE_VERSION'),
            ({**self.payload,'expectedConfiguredPolicy':'ALLOW'},'OWNER_POLICY_PREVIEW_STALE_RULE'),
            ({**self.payload,'actor':'mallory'},'OWNER_POLICY_PREVIEW_EXACT_GRANT_REQUIRED'),
            ({**self.payload,'target':'repo-B'},'OWNER_POLICY_PREVIEW_EXACT_GRANT_REQUIRED'),
            ({**self.payload,'operation':'delete_everything'},'OWNER_POLICY_PREVIEW_EXACT_GRANT_REQUIRED'),
            ({**self.payload,'desiredPolicy':'OWNER'},'OWNER_POLICY_PREVIEW_POLICY'),
            ({**self.payload,'desiredPolicy':None},'OWNER_POLICY_PREVIEW_POLICY'),
            ({**self.payload,'unexpected':'yes'},'OWNER_POLICY_PREVIEW_SCHEMA'),
            ({**self.payload,'actor':None},'OWNER_POLICY_PREVIEW_COORDINATES'),
            ({**self.payload,'provider':'sample-ext','operation':'not_configured'},'OWNER_POLICY_PREVIEW_EXACT_GRANT_REQUIRED'),
        ]
        for payload,expected in cases:
            with self.subTest(expected=expected):
                code,data,_=self.call(payload)
                self.assertEqual((403,expected),(code,data.get('error')))

    def test_conditional_policy_no_evaluation_and_fail_closed(self):
        calls=[]
        self.core.policies[('alice','github','create_pull_request','repo-A')]=lambda *a: calls.append(a)
        code,data,_=self.call()
        self.assertEqual((403,'OWNER_POLICY_PREVIEW_STALE_RULE'),(code,data['error']))
        self.assertEqual([],calls)

    def test_preview_works_in_readonly_banner_and_without_effects(self):
        self.portal.read_only_banner=True
        code,data,_=self.call()
        self.assertEqual(200,code)
        self.assertFalse(data['canApply'])

    def test_bad_db_fails_closed_without_overriding_policy(self):
        self.core._db=lambda:sqlite3.connect(':memory:')
        code,data,_=self.call()
        self.assertEqual((403,'OWNER_POLICY_PREVIEW_PENDING_STATE_UNAVAILABLE'),
                         (code,data['error']))
        self.assertEqual('ASK',self.core.policies[('alice','github','create_pull_request','repo-A')])

    def test_same_policy_noop_and_powershell_requires_strong_authorization(self):
        code,data,_=self.call({**self.payload,'desiredPolicy':'ASK'})
        self.assertEqual(200,code)
        self.assertFalse(data['changed'])
        code,data,_=self.call({**self.payload,'provider':'powershell','operation':'execute',
                    'actor':'alice','target':'windows-local','expectedConfiguredPolicy':'ASK',
                    'desiredPolicy':'ALLOW'})
        self.assertEqual(200,code)
        self.assertEqual('CRITICAL',data['risk'])
        self.assertIn('FRESH_STRONG_OWNER_WEBAUTHN',data['requires'])
        self.assertFalse(data['canApply'])


if __name__=='__main__':unittest.main()

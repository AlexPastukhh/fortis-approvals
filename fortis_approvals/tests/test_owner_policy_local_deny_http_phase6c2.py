"""Phase 6C.2 opt-in owner WSGI routes, synthetic-only state test lane.

The synthetic WebAuthn fixture exercises HTTP guards/state transitions,
NOT cryptographic authentication; real VirtualKey tests cover FIDO2 in CI.
"""
from io import BytesIO
import json
from pathlib import Path
import tempfile
import unittest
import uuid

from fortis_approvals.core import Authenticator, Denied
from fortis_approvals.incidents import IncidentOwnerPortal
from fortis_approvals.synthetic import SyntheticAdapter
from fortis_approvals.extensions.owner_policy_local_core_phase6c import LocalDenyCore
from fortis_approvals.extensions.owner_policy_local_deny_apply_phase6c1 import OwnerLocalDenyApply
from fortis_approvals.extensions.owner_policy_local_deny_http_phase6c2 import OwnerLocalDenyPortal
from fortis_approvals.tests.test_owner_policy_local_deny_apply_phase6c1 import (
    SyntheticWebAuthn, ACTOR, COORD, SOURCE, CREDS)


_PREFIX='/v1/owner/policy/local-deny'
_SESSION='synthetic-session-value-012345678901234567890'


class HTTPFixtureWebAuthn(SyntheticWebAuthn):
    """Match real OwnerWebAuthn session readback without CSRF for GET."""
    def session(self, token, csrf=None):
        if token != self._session or (csrf is not None and csrf != self._csrf):
            raise Denied('SYNTHETIC_SESSION_INVALID')
        return {'owner': self.owner}


class OwnerDenyWSGITests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory(prefix='fortis-local-deny-http-')
        self.addCleanup(temp.cleanup)
        root=Path(temp.name)
        self.adapter=SyntheticAdapter(root/'data.sqlite')
        self.adapter.seed('record','before')
        self.owner=HTTPFixtureWebAuthn()
        self.owner.origin='http://localhost:18990'
        self.core=LocalDenyCore(root/'core.sqlite',adapters={'synthetic':self.adapter},
            policies={COORD:'ASK'},authenticator=Authenticator({'machine':'agent-1'}),
            owner_verifier=self.owner,policy_version='candidate-source-v1')
        self.apply=OwnerLocalDenyApply(self.core,self.owner,source_digest=SOURCE,
                                       credential_generation_digest=CREDS)
        self.portal=OwnerLocalDenyPortal(self.core,self.owner,local_deny_apply=self.apply)
        self.candidate=dict(actor=ACTOR,provider='synthetic',operation='set_ask',
            target='record',expectedConfiguredPolicy='ASK',
            expectedPolicyVersion=self.core.policy_version,expectedRevision=0,
            reasonCode='OWNER_DENY_EXACT')

    def call(self,path,body=None,*,method=None,host='localhost:18990',
             origin='http://localhost:18990',cookie=_SESSION,
             csrf='synthetic-csrf',query='',extra=None):
        if isinstance(body,bytes):
            raw=body
        elif body is None:
            raw=b''
        else:
            raw=json.dumps(body).encode()
        env={'REQUEST_METHOD':method or ('POST' if body is not None else 'GET'),
             'PATH_INFO':path,'HTTP_HOST':host,'QUERY_STRING':query,
             'wsgi.input':BytesIO(raw),'CONTENT_LENGTH':str(len(raw)),
             'CONTENT_TYPE':'application/json'}
        if origin is not None:env['HTTP_ORIGIN']=origin
        if cookie is not None:env['HTTP_COOKIE']='fortis_owner='+cookie
        if csrf is not None:env['HTTP_X_FORTIS_CSRF']=csrf
        if extra:env.update(extra)
        record=[]
        answer=b''.join(self.portal(env,lambda status,headers:record.append(
            (status,dict(headers)))))
        return int(record[0][0][:3]),json.loads(answer),record[0][1]

    def begin(self):
        return self.call(_PREFIX+'/begin',{'candidate':self.candidate})

    def finish(self,started,response=None,change=None):
        return self.call(_PREFIX+'/finish',{'ceremonyId':started['ceremonyId'],
            'response':{'syntheticTestOnlyUv':True} if response is None else response,
            'change':started['change'] if change is None else change})

    def audit_count(self):
        with self.core._db() as db:
            return db.execute('SELECT count(*) FROM owner_local_policy_events').fetchone()[0]

    def test_default_incident_portal_has_no_deny_routes(self):
        default=IncidentOwnerPortal(self.core,self.owner)
        old=self.portal
        self.portal=default
        try:
            code,body,_=self.call(_PREFIX+'/begin',{'candidate':self.candidate})
            self.assertEqual(404,code)
            code,body,_=self.call(_PREFIX+'/capabilities')
            self.assertEqual(404,code)
        finally:
            self.portal=old
        self.assertEqual(0,self.audit_count())

    def test_caps_requires_owner_and_discloses_no_grants(self):
        code,value,headers=self.call(_PREFIX+'/capabilities')
        self.assertEqual(200,code)
        self.assertTrue(value['configured'])
        self.assertTrue(value['requiresFreshStrongWebAuthn'])
        self.assertFalse(value['canGrantAllow'])
        self.assertNotIn('credential',json.dumps(value).lower())
        self.assertEqual('no-store',headers['Cache-Control'])
        for cookie in (None,'wrong'):
            code,_,_=self.call(_PREFIX+'/capabilities',cookie=cookie)
            self.assertEqual(403,code)
        self.assertEqual(0,self.audit_count())

    def test_bound_session_apply_is_exact_deny_only_and_readback_post(self):
        code,started,headers=self.begin()
        self.assertEqual(200,code)
        self.assertEqual('OWNER_LOCAL_DENY_APPLY_CEREMONY',started['kind'])
        self.assertEqual('DENY',started['newPolicy'])
        code,result,headers=self.finish(started)
        self.assertEqual(200,code)
        self.assertTrue(result['localDenyCommitted'])
        self.assertFalse(result['runtimeIntegrated'])
        self.assertEqual(1,self.audit_count())
        code,readback,_=self.call(_PREFIX+'/readback',{'requestId':result['requestId']})
        self.assertEqual(200,code)
        self.assertTrue(readback['found'])
        self.assertEqual(1,readback['appliedRevision'])
        code,_,_=self.finish(started)
        self.assertEqual(403,code)
        self.assertEqual(1,self.audit_count())
        self.assertEqual('DENY',self.core._policy(ACTOR,dict(
            service='synthetic',operation='set_ask',target='record')))
        self.assertEqual('before',self.adapter.get('record')['value'])

    def test_unconfigured_and_read_only_never_mutate(self):
        for portal in (OwnerLocalDenyPortal(self.core,self.owner),
                       OwnerLocalDenyPortal(self.core,self.owner,
                                           local_deny_apply=self.apply,
                                           read_only_banner=True)):
            with self.subTest(portal=portal):
                old=self.portal
                self.portal=portal
                try:
                    code,cap,_=self.call(_PREFIX+'/capabilities')
                    self.assertEqual(200,code)
                    self.assertFalse(cap['configured'])
                    self.assertEqual(403,self.begin()[0])
                    self.assertEqual(403,self.call(_PREFIX+'/readback',
                        {'requestId':str(uuid.uuid4())})[0])
                finally:
                    self.portal=old
        self.assertEqual(0,self.audit_count())

    def test_http_host_origin_proxy_cookie_csrf_controls(self):
        unsafe=(
            dict(host='evil.test'),dict(origin='https://evil.test'),
            dict(origin=None),dict(cookie=None),dict(cookie='machine'),
            dict(csrf=None),dict(csrf='wrong'),dict(query='x=1'),
            dict(extra={'HTTP_X_FORWARDED_HOST':'evil.test'}),
            dict(extra={'HTTP_FORWARDED':'host=evil.test'}),
            dict(extra={'HTTP_AUTHORIZATION':'Bearer token'}),
            dict(extra={'HTTP_PROXY_AUTHORIZATION':'Bearer token'}),
        )
        for args in unsafe:
            with self.subTest(args=args):
                code,_,_=self.call(_PREFIX+'/begin',{'candidate':self.candidate},**args)
                self.assertEqual(403,code)
        self.assertEqual(0,self.audit_count())

    def test_closed_body_schema_duplicate_json_and_invalid_method_fail(self):
        for b in ({'candidate':self.candidate,'extra':'ALLOW'},
                  {'actor':ACTOR}, {}, b'{"candidate":{},"candidate":{}}'):
            with self.subTest(body=b):
                self.assertNotEqual(200,self.call(_PREFIX+'/begin',b)[0])
        self.assertEqual(404,self.call(_PREFIX+'/begin',method='GET')[0])
        self.assertEqual(404,self.call(_PREFIX+'/readback',method='GET')[0])
        self.assertEqual(0,self.audit_count())

    def test_wrong_uv_descriptor_and_cross_session_do_not_apply(self):
        code,started,_=self.begin()
        self.assertEqual(200,code)
        self.assertEqual(403,self.finish(started,response={
            'syntheticTestOnlyUv':False})[0])
        self.assertEqual(403,self.finish(started)[0])
        _,started,_=self.begin()
        self.assertEqual(403,self.finish(started,change={
            **started['change'],'newPolicy':'ALLOW'})[0])
        self.assertEqual(403,self.finish(started)[0])
        self.assertEqual(0,self.audit_count())

    def test_stale_revision_is_409_and_never_partial_commit(self):
        _,started,_=self.begin()
        with self.core._db() as db:
            db.execute('UPDATE owner_local_policy_meta SET revision=revision+1')
        code,info,_=self.finish(started)
        self.assertEqual(409,code)
        self.assertEqual('OWNER_LOCAL_APPLY_STALE_REVISION',info['error'])
        self.assertEqual(0,self.audit_count())
        self.assertEqual('ASK',self.core._policy(ACTOR,dict(
            service='synthetic',operation='set_ask',target='record')))

    def test_broken_constructor_binding_fails_before_route_exists(self):
        with self.assertRaises(Denied):
            OwnerLocalDenyPortal(self.core,self.owner,local_deny_apply=object())
        other=LocalDenyCore(self.core.path.parent/'other.sqlite',
            adapters={'synthetic':self.adapter},policies={COORD:'ASK'},
            authenticator=Authenticator({'other':'agent-1'}),
            owner_verifier=self.owner)
        with self.assertRaises(Denied):
            OwnerLocalDenyPortal(other,self.owner,local_deny_apply=self.apply)

    def test_request_id_readback_is_owner_session_only(self):
        self.assertEqual(403,self.call(_PREFIX+'/readback',
            {'requestId':str(uuid.uuid4())},cookie=None)[0])
        self.assertEqual(403,self.call(_PREFIX+'/readback',
            {'requestId':str(uuid.uuid4())},csrf=None)[0])
        code,row,_=self.call(_PREFIX+'/readback',{'requestId':str(uuid.uuid4())})
        self.assertEqual(200,code)
        self.assertFalse(row['found'])
        self.assertEqual(0,self.audit_count())


if __name__=='__main__':
    unittest.main()

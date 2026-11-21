"""Phase 6C.2 opt-in owner-only HTTP + actual virtual FIDO2 acceptance.

Requires the crypto Source CI lane. Uses a synthetic P-256 WebAuthn key,
never a real owner credential, and no live Gateway/runtime policy writes.
"""
from io import BytesIO
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
import uuid

from fortis_approvals.core import Authenticator
from fortis_approvals.owner_auth import OwnerWebAuthn
from fortis_approvals.synthetic import SyntheticAdapter
from fortis_approvals.extensions.owner_policy_local_core_phase6c import LocalDenyCore
from fortis_approvals.extensions.owner_policy_local_deny_apply_phase6c1 import OwnerLocalDenyApply
from fortis_approvals.extensions.owner_policy_local_deny_http_phase6c2 import OwnerLocalDenyPortal
from test_owner_portal import VirtualKey

COORD=('agent-1','synthetic','set_ask','R3')
SOURCE=hashlib.sha256(b'test-installed-source').hexdigest()
CREDS=hashlib.sha256(b'test-credential-generation').hexdigest()
_PREFIX='/v1/owner/policy/local-deny'


class BrowserDenyVirtualFIDO2(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory(prefix='fortis-local-deny-http-crypto-')
        self.addCleanup(tmp.cleanup)
        root=Path(tmp.name)
        self.owner=OwnerWebAuthn(root/'owner-keys.sqlite',
                                 origin='http://localhost:18990')
        self.key=VirtualKey()
        self.adapter=SyntheticAdapter(root/'adapter.sqlite')
        self.adapter.seed('R3','before')
        self.core=LocalDenyCore(root/'core.sqlite',adapters={'synthetic':self.adapter},
            policies={COORD:'ASK'},
            authenticator=Authenticator({'machine-token':'agent-1'}),
            owner_verifier=self.owner, policy_version='test-v1')
        self.bound=OwnerLocalDenyApply(self.core,self.owner,
            source_digest=SOURCE,credential_generation_digest=CREDS)
        self.portal=OwnerLocalDenyPortal(self.core,self.owner,
            local_deny_apply=self.bound)
        invite=self.owner.issue_invitation()
        enroll=self.owner.begin_enrollment(invite)
        self.owner.finish_enrollment(enroll['ceremonyId'],self.key.enroll(enroll))
        login=self.owner.begin_login()
        self.session,self.csrf=self.owner.finish_login(login['ceremonyId'],
                                                         self.key.assert_(login))
        self.candidate=dict(actor=COORD[0],provider=COORD[1],
            operation=COORD[2],target=COORD[3],expectedConfiguredPolicy='ASK',
            expectedPolicyVersion=self.core.policy_version,
            expectedRevision=0,reasonCode='OWNER_DENY_EXACT')

    def call(self,path,body,*,cookie=None,csrf=None,origin='http://localhost:18990',
             host='localhost:18990'):
        raw=json.dumps(body).encode()
        env={'HTTP_HOST':host,'HTTP_ORIGIN':origin,
             'REQUEST_METHOD':'POST','PATH_INFO':path,'QUERY_STRING':'',
             'CONTENT_TYPE':'application/json','CONTENT_LENGTH':str(len(raw)),
             'wsgi.input':BytesIO(raw),
             'HTTP_COOKIE':'fortis_owner='+(self.session if cookie is None else cookie)}
        if csrf is not False:
            env['HTTP_X_FORTIS_CSRF']=self.csrf if csrf is None else csrf
        record=[]
        data=b''.join(self.portal(env,lambda status,headers:record.append(
            (status,dict(headers)))))
        return int(record[0][0][:3]),json.loads(data)

    def begin(self):
        return self.call(_PREFIX+'/begin',{'candidate':self.candidate})

    def finish(self,started,response,change=None):
        return self.call(_PREFIX+'/finish',dict(ceremonyId=started['ceremonyId'],
            response=response,change=started['change'] if change is None else change))

    def test_real_signed_uv_exact_deny_and_one_use_readback(self):
        code,started=self.begin()
        self.assertEqual(200,code,started)
        code,result=self.finish(started,self.key.assert_(started))
        self.assertEqual(200,code,result)
        self.assertTrue(result['localDenyCommitted'])
        self.assertFalse(result['canGrantAllow'])
        self.assertFalse(result['runtimeIntegrated'])
        self.assertEqual('DENY',self.core._policy('agent-1',dict(
            service='synthetic',operation='set_ask',target='R3')))
        code,found=self.call(_PREFIX+'/readback',
            {'requestId':result['requestId']})
        self.assertEqual(200,code,found)
        self.assertTrue(found['found'])
        self.assertEqual(1,found['appliedRevision'])
        self.assertEqual(403,self.finish(started,self.key.assert_(started))[0])
        self.assertEqual('before',self.adapter.get('R3')['value'])

    def test_real_uv_origin_crossorigin_session_and_purpose_rejected(self):
        for attack in ('uv','origin','crossorigin','session','review_proof'):
            with self.subTest(attack=attack):
                code,started=self.begin()
                self.assertEqual(200,code,started)
                if attack=='uv':
                    response=self.key.assert_(started,uv=False)
                    code,_=self.finish(started,response)
                elif attack=='origin':
                    response=self.key.assert_(started,origin='https://evil.example')
                    code,_=self.finish(started,response)
                elif attack=='crossorigin':
                    response=self.key.assert_(started,cross_origin=True)
                    code,_=self.finish(started,response)
                elif attack=='session':
                    response=self.key.assert_(started)
                    code,_=self.call(_PREFIX+'/finish',{
                        'ceremonyId':started['ceremonyId'],
                        'response':response,'change':started['change']},
                        cookie='invalid-owner-cookie')
                else:
                    response=self.key.assert_(started)
                    code,_=self.finish(started,response,{**started['change'],
                        'purpose':'REVIEW_INACTIVE_POLICY_DRAFT_V1'})
                self.assertEqual(403,code)
                if attack!='session':
                    self.assertEqual(403,self.finish(started,
                        self.key.assert_(started))[0])
        self.assertEqual('ASK',self.core._policy('agent-1',dict(
            service='synthetic',operation='set_ask',target='R3')))

    def test_http_auth_blocks_before_real_webauthn_begin(self):
        before=len(self.owner.pending)
        for attack in (dict(origin='https://evil.example'),dict(host='evil.test'),
                       dict(cookie='machine-token'),dict(csrf=False)):
            with self.subTest(attack=attack):
                code,_=self.call(_PREFIX+'/begin',{'candidate':self.candidate},
                                 **attack)
                self.assertEqual(403,code)
        self.assertEqual(before,len(self.owner.pending))
        self.assertEqual('ASK',self.core._policy('agent-1',dict(
            service='synthetic',operation='set_ask',target='R3')))

    def test_real_signed_uv_actor_source_exact_target_via_owner_http(self):
        self.core.policies.pop(COORD)
        self.core.policies[COORD[:3]]='ASK'
        candidate={**self.candidate,'expectedConfiguredScope':'actor'}
        code,started=self.call(_PREFIX+'/begin',{'candidate':candidate})
        self.assertEqual(200,code,started)
        self.assertEqual('actor',started['change']['expectedConfiguredScope'])
        code,result=self.finish(started,self.key.assert_(started))
        self.assertEqual(200,code,result)
        self.assertTrue(result['localDenyCommitted'])
        self.assertEqual('DENY',self.core._policy('agent-1',dict(
            service='synthetic',operation='set_ask',target='R3')))
        self.assertEqual('ASK',self.core._policy('agent-1',dict(
            service='synthetic',operation='set_ask',target='R4')))
        self.assertEqual('ASK',self.core.policies[COORD[:3]])
        self.assertEqual(403,self.finish(started,self.key.assert_(started))[0])

    def test_runtime_sonar_only_real_uv_binds_credential_generation(self):
        self.core.adapters['sonarcloud']=self.adapter
        self.core.policies[('agent-1','sonarcloud','accept_issue')]='ASK'
        bound=OwnerLocalDenyApply(self.core,self.owner,source_digest=SOURCE,
            credential_generation_digest=CREDS,runtime_sonar_only=True)
        self.portal=OwnerLocalDenyPortal(self.core,self.owner,local_deny_apply=bound)
        candidate={**self.candidate,'provider':'sonarcloud','operation':'accept_issue',
                   'expectedConfiguredScope':'actor'}
        self.assertEqual(403,self.begin()[0])
        code,started=self.call(_PREFIX+'/begin',{'candidate':candidate})
        self.assertEqual(200,code,started)
        code,result=self.finish(started,self.key.assert_(started))
        self.assertEqual(200,code,result)
        self.assertEqual('DENY',self.core._policy('agent-1',
            dict(service='sonarcloud',operation='accept_issue',target='R3')))
        self.assertEqual('ASK',self.core._policy('agent-1',
            dict(service='sonarcloud',operation='accept_issue',target='R4')))

    def test_stale_revision_returns_409_even_with_real_valid_fido2(self):
        code,started=self.begin()
        self.assertEqual(200,code)
        with self.core._db() as db:
            db.execute('UPDATE owner_local_policy_meta SET revision=revision+1')
        code,value=self.finish(started,self.key.assert_(started))
        self.assertEqual(409,code,value)
        self.assertEqual('ASK',self.core._policy('agent-1',dict(
            service='synthetic',operation='set_ask',target='R3')))


if __name__=='__main__':
    unittest.main()

"""Strong real virtual WebAuthn assertion over owner-only HTTP, CI FIDO2 lane.

Uses test-only P-256 VirtualKey. No owner credential or live policy changes.
"""
from io import BytesIO
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from fortis_approvals.core import Core, Authenticator
from fortis_approvals.incidents import IncidentOwnerPortal
from fortis_approvals.owner_auth import OwnerWebAuthn
from fortis_approvals.synthetic import SyntheticAdapter
from fortis_approvals.extensions.owner_policy_draft_ledger import PolicyDraftLedger
from test_owner_portal import VirtualKey

COORD=('agent-1','synthetic','set_ask','R3')


class BrowserReviewVirtualWebAuthn(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='fortis-policy-review-crypto-')
        self.addCleanup(self.temp.cleanup)
        root=Path(self.temp.name)
        self.owner=OwnerWebAuthn(root/'owner-keys.sqlite',origin='http://localhost:18990')
        self.key=VirtualKey()
        self.adapter=SyntheticAdapter(root/'adapter.sqlite')
        self.adapter.seed('R3','before')
        self.core=Core(root/'approvals.sqlite',adapters={'synthetic':self.adapter},
            policies={COORD:'ASK'},authenticator=Authenticator({'agent-secret':'agent-1'}),
            owner_verifier=self.owner)
        self.ledger=PolicyDraftLedger(root/'drafts.sqlite',baseline={COORD:'ASK'},
            source_digest=hashlib.sha256(b'reviewed-code').hexdigest(),
            credential_generation_digest=hashlib.sha256(b'owner-credential-generation').hexdigest(),
            policy_version=self.core.policy_version)
        self.portal=IncidentOwnerPortal(self.core,self.owner,policy_review_ledger=self.ledger)
        invitation=self.owner.issue_invitation()
        enroll=self.owner.begin_enrollment(invitation)
        self.owner.finish_enrollment(enroll['ceremonyId'],self.key.enroll(enroll))
        login=self.owner.begin_login()
        self.session,self.csrf=self.owner.finish_login(login['ceremonyId'],self.key.assert_(login))
        self.candidate={'provider':'synthetic','operation':'set_ask',
            'actor':'agent-1','target':'R3','desiredPolicy':'DENY',
            'expectedConfiguredPolicy':'ASK','expectedPolicyVersion':self.core.policy_version}

    def call(self,path,body=None,*,session=None,csrf=None,origin='http://localhost:18990'):
        raw=json.dumps(body or {}).encode()
        env={'REQUEST_METHOD':'POST' if body is not None else 'GET','PATH_INFO':path,
             'HTTP_HOST':'localhost:18990','QUERY_STRING':'','wsgi.input':BytesIO(raw),
             'CONTENT_TYPE':'application/json','CONTENT_LENGTH':str(len(raw))}
        if session is not False:env['HTTP_COOKIE']='fortis_owner='+(self.session if session is None else session)
        if csrf is not False:env['HTTP_X_FORTIS_CSRF']=self.csrf if csrf is None else csrf
        if origin:env['HTTP_ORIGIN']=origin
        record=[]
        data=b''.join(self.portal(env,lambda status,headers:record.append((status,dict(headers)))))
        return int(record[0][0][:3]),json.loads(data)

    def begin(self):return self.call('/v1/owner/policy/review/begin',{'candidate':self.candidate})

    def finish(self,begin,response):
        return self.call('/v1/owner/policy/review/finish',{
            'ceremonyId':begin['ceremonyId'],'change':begin['change'],'response':response})

    def test_strong_browser_review_signed_credential_one_use_no_apply(self):
        code,begin=self.begin()
        self.assertEqual(200,code,begin)
        self.assertEqual('OWNER_POLICY_DRAFT_REVIEW_ONLY',begin['kind'])
        code,result=self.finish(begin,self.key.assert_(begin))
        self.assertEqual(200,code,result)
        self.assertTrue(result['verified'])
        self.assertFalse(result['canApply'])
        self.assertFalse(result['policyActivated'])
        self.assertIsNone(result['authorizationToken'])
        self.assertEqual(403,self.finish(begin,self.key.assert_(begin))[0])
        self.assertEqual('ASK',self.core.policies[COORD])
        self.assertEqual(0,self.ledger.snapshot()['revision'])
        self.assertEqual(self.adapter.get('R3')['version'],0)

    def test_real_uv_origin_wrong_change_and_login_session_only_denied(self):
        for issue in ('uv','origin','wrong-policy','session-only'):
            with self.subTest(issue=issue):
                code,begin=self.begin()
                self.assertEqual(200,code,begin)
                if issue=='uv':
                    response=self.key.assert_(begin,uv=False)
                elif issue=='origin':
                    response=self.key.assert_(begin,origin='https://evil.test')
                else:
                    response=self.key.assert_(begin)
                if issue=='wrong-policy':
                    payload={'ceremonyId':begin['ceremonyId'],'change':{**begin['change'],'newPolicy':'ALLOW'},
                             'response':response}
                    code,_=self.call('/v1/owner/policy/review/finish',payload)
                elif issue=='session-only':
                    code,_=self.finish(begin,{'mode':'session','session':self.session,'permit':'not-fido2'})
                else:
                    code,_=self.finish(begin,response)
                self.assertEqual(403,code)
                self.assertEqual(403,self.finish(begin,self.key.assert_(begin))[0])
        self.assertEqual('ASK',self.core.policies[COORD])
        self.assertEqual(self.adapter.get('R3')['version'],0)

    def test_state_drift_before_finish_is_409_and_no_runtime_grant(self):
        code,begin=self.begin()
        self.assertEqual(200,code,begin)
        self.core.policies[COORD]='DENY'
        code,result=self.finish(begin,self.key.assert_(begin))
        self.assertIn(code,(403,409),result)
        self.assertNotEqual(result.get('verified'),True)
        self.assertEqual(0,self.ledger.snapshot()['revision'])
        self.assertEqual(self.adapter.get('R3')['version'],0)


if __name__=='__main__':unittest.main()

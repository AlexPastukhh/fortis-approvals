"""Policy review owner HTTP boundary: simulated authenticator, never real FIDO2.

Actual elliptic-curve WebAuthn proof tests live in
 test_owner_policy_review_http_crypto.py and run in curated source CI.
"""
from io import BytesIO
import hashlib
import json
from pathlib import Path
import tempfile
import threading
from types import MethodType
import unittest
import uuid

from fortis_approvals.core import Denied
from fortis_approvals.incidents import IncidentOwnerPortal
from fortis_approvals.owner_portal import OwnerPortal
from fortis_approvals.owner_auth import OwnerWebAuthn, _hash
from fortis_approvals.extensions.owner_policy_draft_ledger import PolicyDraftLedger
from test_owner_policy_preview import Core

SESSION='owner-session-'+('a'*65)
CSRF='csrf-owner-session'
COORD=('alice','github','create_pull_request','repo-A')
SRC=hashlib.sha256(b'reviewed-install-source').hexdigest()
CRED=hashlib.sha256(b'operator-credential-epoch').hexdigest()


class ReviewRoutes(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.now=2000000000
        owner=object.__new__(OwnerWebAuthn)
        owner.owner='test-owner';owner.origin='http://localhost:19203';owner.rp_id='localhost'
        owner.clock=lambda:self.now;owner.lock=threading.RLock()
        owner.pending={};owner.session_decisions={};owner.session_ttl=3600
        owner.sessions={_hash(SESSION):{'owner':owner.owner,'expires':self.now+1000,'csrf':CSRF}}
        self.owner=owner
        def fake_begin(obj,kind,**data):
            self.assertEqual('policy_change_review',kind)
            ceremony=obj._remember(kind,{'test':'one-use'},**data)
            return {'ceremonyId':ceremony,'options':{'publicKey':{'challenge':'fake'}}}
        def fake_finish(obj,state,data,response):
            if response!={'fakeUserVerified':True}:
                raise Denied('TEST_CRYPTO_FAKE_REJECTED')
            return obj.owner
        owner._begin_assertion=MethodType(fake_begin,owner)
        owner._finish_assertion=MethodType(fake_finish,owner)
        self.core=Core(owner,str(Path(self.tmp.name)/'requests.sqlite'))
        self.ledger=PolicyDraftLedger(Path(self.tmp.name)/'drafts.sqlite',
            baseline={COORD:'ASK'},source_digest=SRC,credential_generation_digest=CRED,
            policy_version=self.core.policy_version,clock=lambda:self.now)
        self.portal=IncidentOwnerPortal(self.core,owner,policy_review_ledger=self.ledger)
        self.candidate={'provider':'github','operation':'create_pull_request',
           'actor':'alice','target':'repo-A','desiredPolicy':'DENY',
           'expectedConfiguredPolicy':'ASK','expectedPolicyVersion':self.core.policy_version}

    def call(self,path,body=None,*,portal=None,cookie=SESSION,csrf=CSRF,origin='http://localhost:19203',
             host='localhost:19203',method=None,query='',extra=None):
        raw=json.dumps(body or {}).encode()
        env={'REQUEST_METHOD':method or ('POST' if body is not None else 'GET'),
             'PATH_INFO':path,'HTTP_HOST':host,'QUERY_STRING':query,'wsgi.input':BytesIO(raw),
             'CONTENT_TYPE':'application/json','CONTENT_LENGTH':str(len(raw))}
        if cookie:env['HTTP_COOKIE']='fortis_owner='+cookie
        if csrf:env['HTTP_X_FORTIS_CSRF']=csrf
        if origin:env['HTTP_ORIGIN']=origin
        env.update(extra or {})
        out=[]
        payload=b''.join((portal or self.portal)(env,lambda status,headers:out.append((status,dict(headers)))))
        return int(out[0][0][:3]),json.loads(payload),out[0][1]

    def begin(self,candidate=None):
        return self.call('/v1/owner/policy/review/begin',{'candidate':candidate or self.candidate})

    def finish(self,started,change=None,proof=None,**kwargs):
        return self.call('/v1/owner/policy/review/finish',
            {'ceremonyId':started['ceremonyId'],'response':{'fakeUserVerified':True} if proof is None else proof,
             'change':change or started['change']},**kwargs)

    def test_optin_is_disabled_and_legacy_owner_portal_has_no_route(self):
        no_ledger=IncidentOwnerPortal(self.core,self.owner)
        code,data,_=self.call('/v1/owner/policy/review/capabilities',portal=no_ledger)
        self.assertEqual(200,code)
        self.assertFalse(data['configured'])
        self.assertFalse(data['canApply'])
        self.assertEqual(403,self.call('/v1/owner/policy/review/begin',
            {'candidate':self.candidate},portal=no_ledger)[0])
        legacy=OwnerPortal(self.core,self.owner)
        self.assertEqual(404,self.call('/v1/owner/policy/review/capabilities',portal=legacy)[0])
        self.assertEqual(404,self.call('/v1/owner/policy/review/begin',
            {'candidate':self.candidate},portal=legacy)[0])

    def test_capabilities_owner_only_and_readonly_banner_disabled(self):
        code,data,headers=self.call('/v1/owner/policy/review/capabilities')
        self.assertEqual(200,code)
        self.assertTrue(data['configured'])
        self.assertTrue(data['requiresStrongWebAuthn'])
        self.assertFalse(data['canApply'])
        self.assertEqual('no-store',headers['Cache-Control'])
        for opts in ({'cookie':''},{'cookie':'wrong'}, {'host':'evil.test'},
                     {'extra':{'HTTP_AUTHORIZATION':'Bearer agent'}},
                     {'query':'x=1'}):
            with self.subTest(opts=opts):
                self.assertEqual(403,self.call('/v1/owner/policy/review/capabilities',**opts)[0])
        self.portal.read_only_banner=True
        self.assertFalse(self.call('/v1/owner/policy/review/capabilities')[1]['configured'])
        self.assertEqual(403,self.begin()[0])

    def test_begin_and_finish_exact_inert_change(self):
        before=self.core.policies.copy()
        code,begin,_=self.begin()
        self.assertEqual(200,code,begin)
        self.assertFalse(begin['canApply'])
        self.assertFalse(begin['policyActivated'])
        self.assertEqual('OWNER_POLICY_DRAFT_REVIEW_ONLY',begin['kind'])
        self.assertEqual('DENY',begin['change']['newPolicy'])
        self.assertEqual('ASK',begin['change']['oldPolicy'])
        self.assertEqual(COORD,tuple(begin['change'][k] for k in ('actor','provider','operation','target')))
        code,result,_=self.finish(begin)
        self.assertEqual(200,code,result)
        self.assertTrue(result['verified'])
        self.assertFalse(result['canApply'])
        self.assertFalse(result['policyActivated'])
        self.assertIsNone(result['authorizationToken'])
        self.assertEqual(begin['previewFingerprint'],result['previewFingerprint'])
        self.assertEqual(403,self.finish(begin)[0])
        self.assertEqual(before,self.core.policies)
        self.assertEqual(0,self.ledger.snapshot()['revision'])
        self.assertEqual('ASK',self.ledger.snapshot()['drafts'][0]['draftPolicy'])

    def test_body_schema_host_origin_csrf_and_agent_headers_deny(self):
        for opts in ({'cookie':''},{'csrf':''},{'csrf':'wrong'},
                     {'origin':''},{'origin':'https://evil.test'}, {'host':'evil.test'},
                     {'query':'anything=1'},{'extra':{'HTTP_X_FORWARDED_HOST':'evil.test'}},
                     {'extra':{'HTTP_PROXY_AUTHORIZATION':'bearer fake'}},
                     {'extra':{'HTTP_FORWARDED':'for=evil.test'}}):
            with self.subTest(opts=opts):
                self.assertEqual(403,self.call('/v1/owner/policy/review/begin',
                    {'candidate':self.candidate},**opts)[0])
        for body in ({'candidate':self.candidate,'apply':True},
                     {'candidate':self.candidate,'sessionPermit':'fake'}, {},
                     {'candidate':{**self.candidate,'unknown':'value'}}):
            with self.subTest(body=body):
                self.assertEqual(403,self.call('/v1/owner/policy/review/begin',body)[0])
        self.assertEqual(404,self.call('/v1/owner/policy/review/finish',method='GET')[0])
        self.assertEqual(404,self.call('/v1/owner/policy/apply',{})[0])

    def test_wrong_scope_noop_stale_preview_and_missing_rule(self):
        variants=[{'actor':'mallory'},{'target':'repo-B'},
                  {'operation':'delete_everything'},
                  {'expectedConfiguredPolicy':'ALLOW'},
                  {'expectedPolicyVersion':'old-release'},
                  {'desiredPolicy':'ASK'}]
        for variant in variants:
            with self.subTest(variant=variant):
                code,response,_=self.begin({**self.candidate,**variant})
                self.assertIn(code,(403,409),response)
        self.assertEqual(0,self.ledger.snapshot()['revision'])

    def test_replay_tampering_and_stale_draft_consume_ceremony(self):
        started=self.begin()[1]
        bad={**started['change'],'newPolicy':'ALLOW'}
        self.assertEqual(403,self.finish(started,change=bad)[0])
        self.assertEqual(403,self.finish(started)[0])
        started=self.begin()[1]
        self.ledger.stage_draft(COORD,desired_policy='DENY',request_id=str(uuid.uuid4()),
            expected_revision=0,expected_policy='ASK',expected_source_digest=SRC,
            expected_credential_generation_digest=CRED,
            expected_policy_version=self.core.policy_version,
            reason_code='OWNER_REVIEW_TEST')
        code,data,_=self.finish(started)
        self.assertEqual((409,'POLICY_CHANGE_STALE_REVISION'),(code,data['error']))
        self.assertEqual(403,self.finish(started)[0])
        self.assertEqual('ASK',self.core.policies[COORD])

    def test_strong_proof_not_session_permit(self):
        started=self.begin()[1]
        code,result,_=self.finish(started,proof={'mode':'session','permit':'fake'})
        self.assertEqual((403,'TEST_CRYPTO_FAKE_REJECTED'),(code,result['error']))
        self.assertEqual(403,self.finish(started)[0])
        self.assertEqual('ASK',self.core.policies[COORD])

    def test_missing_or_wrong_trusted_ledger_configuration_fail_closed(self):
        with self.assertRaisesRegex(Denied,'OWNER_POLICY_REVIEW_TRUSTED_LEDGER_REQUIRED'):
            IncidentOwnerPortal(self.core,self.owner,policy_review_ledger=object())
        with self.assertRaisesRegex(Denied,'OWNER_POLICY_REVIEW_TRUSTED_LEDGER_REQUIRED'):
            IncidentOwnerPortal(self.core,self.owner,policy_review_ledger=str(self.ledger.path))
        self.core.policy_version='a-new-release'
        code,data,_=self.call('/v1/owner/policy/review/capabilities')
        self.assertEqual((409,'OWNER_POLICY_REVIEW_POLICY_VERSION_CHANGED'),
                         (code,data['error']))
        self.assertEqual(403,self.begin()[0])
        self.assertEqual(0,self.ledger.snapshot()['revision'])

    def test_browser_markup_cannot_offer_policy_apply(self):
        root=Path(__file__).resolve().parents[1]
        html=(root/'static/index.html').read_text()
        js=(root/'static/app.js').read_text()
        self.assertIn('id="policy-review-button" type="button" disabled',html)
        self.assertIn('id="policy-review-availability"',html)
        self.assertIn("'/v1/owner/policy/review/begin'",js)
        self.assertIn("'/v1/owner/policy/review/finish'",js)
        self.assertNotIn("'/v1/owner/policy/apply'",js)
        self.assertNotIn('id="policy-apply-button"',html)
        self.assertIn('policyReviewCapabilities?.configured===true',js)

    def test_denies_ledger_mismatch_and_running_policy_changes(self):
        self.ledger.stage_draft(COORD,desired_policy='DENY',request_id=str(uuid.uuid4()),
            expected_revision=0,expected_policy='ASK',expected_source_digest=SRC,
            expected_credential_generation_digest=CRED,
            expected_policy_version=self.core.policy_version,
            reason_code='OWNER_REVIEW_TEST')
        self.assertEqual(409,self.begin()[0])
        self.assertEqual('ASK',self.core.policies[COORD])
        self.core.policies[COORD]='DENY'
        self.assertIn(self.begin()[0],(403,409))


if __name__=='__main__':unittest.main()

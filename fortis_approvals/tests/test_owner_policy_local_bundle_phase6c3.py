"""Phase 6C.3 in-process Core/client/owner identity and truthful inventory.

This source-only harness DOES NOT attest external workers or installed runtime.
SyntheticWebAuthn in these tests is not cryptographic authentication.
"""
from io import BytesIO
import json
from pathlib import Path
import tempfile
import unittest
import uuid

from fortis_approvals.core import Core,Authenticator,Denied
from fortis_approvals.incidents import IncidentCore
from fortis_approvals.gateway import ClientGateway
from fortis_approvals.owner_auth import OwnerWebAuthn
from fortis_approvals.synthetic import SyntheticAdapter
from fortis_approvals.extensions.owner_policy_local_core_phase6c import LocalDenyCore
from fortis_approvals.extensions.owner_policy_local_bundle_phase6c3 import (
    bind_source_only_local_policy_bundle,owner_local_deny_inventory)
from fortis_approvals.tests.test_owner_policy_local_deny_apply_phase6c1 import SOURCE,CREDS
from fortis_approvals.tests.test_owner_policy_local_deny_http_phase6c2 import HTTPFixtureWebAuthn

COORD=('agent-1','synthetic','set_ask','record')
_OWNER='http://localhost:18990'
_PREFIX='/v1/owner/policy/local-deny'


class InProcessBundleTests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory(prefix='fortis-owner-bundle-')
        self.addCleanup(temp.cleanup)
        root=Path(temp.name)
        self.path=root/'core.sqlite'
        self.owner=HTTPFixtureWebAuthn()
        self.owner.origin=_OWNER
        self.auth=Authenticator({'machine-secret':'agent-1'})
        self.adapter=SyntheticAdapter(root/'data.sqlite')
        self.adapter.seed('record','before')
        self.config={COORD:'ASK'}
        self.core=LocalDenyCore(self.path,adapters={'synthetic':self.adapter},
            policies=self.config,authenticator=self.auth,
            owner_verifier=self.owner,policy_version='bundle-v1')
        self.bundle=bind_source_only_local_policy_bundle(
            core=self.core,owner_auth=self.owner,client_host='machine.test',
            source_digest=SOURCE,credential_generation_digest=CREDS)
        self.candidate=dict(actor='agent-1',provider='synthetic',
            operation='set_ask',target='record',
            expectedConfiguredPolicy='ASK',
            expectedPolicyVersion=self.core.policy_version,
            expectedRevision=0,reasonCode='OWNER_DENY_EXACT')

    def machine_call(self,body):
        raw=json.dumps(body).encode()
        env={'REQUEST_METHOD':'POST','PATH_INFO':'/v1/actions',
             'HTTP_HOST':'machine.test','QUERY_STRING':'',
             'CONTENT_TYPE':'application/json','CONTENT_LENGTH':str(len(raw)),
             'wsgi.input':BytesIO(raw),
             'HTTP_AUTHORIZATION':'Bearer machine-secret'}
        result=[]
        response=b''.join(self.bundle.client_gateway(
            env,lambda status,headers:result.append((status,dict(headers)))))
        return int(result[0][0][:3]),json.loads(response)

    def owner_call(self,path,body=None,*,host='localhost:18990',
                   cookie='synthetic-session-value-012345678901234567890'):
        raw=json.dumps(body or {}).encode()
        env={'REQUEST_METHOD':'POST' if body is not None else 'GET',
             'PATH_INFO':path,'HTTP_HOST':host,'QUERY_STRING':'',
             'HTTP_COOKIE':'fortis_owner='+cookie,
             'CONTENT_TYPE':'application/json','CONTENT_LENGTH':str(len(raw)),
             'wsgi.input':BytesIO(raw)}
        if body is not None:
            env['HTTP_ORIGIN']=_OWNER
            env['HTTP_X_FORTIS_CSRF']='synthetic-csrf'
        result=[]
        response=b''.join(self.bundle.owner_portal(
            env,lambda status,headers:result.append((status,dict(headers)))))
        return int(result[0][0][:3]),json.loads(response)

    def request(self):
        return {'requestId':str(uuid.uuid4()),'service':'synthetic',
                'operation':'set_ask','target':'record',
                'params':{'value':'after'},'expectedVersion':0,
                'reason':'source test'}

    def apply_deny(self):
        code,started=self.owner_call(_PREFIX+'/begin',{'candidate':self.candidate})
        self.assertEqual(200,code,started)
        code,result=self.owner_call(_PREFIX+'/finish',{
            'ceremonyId':started['ceremonyId'],'change':started['change'],
            'response':{'syntheticTestOnlyUv':True}})
        self.assertEqual(200,code,result)
        return result

    def test_wiring_identity_is_bound_but_external_attestation_is_not_claimed(self):
        self.assertIs(self.bundle.client_gateway.core,self.core)
        self.assertIs(self.bundle.owner_portal.core,self.core)
        self.assertIs(self.bundle.local_deny_apply.core,self.core)
        self.assertIsInstance(self.core,IncidentCore)
        status=self.bundle.status()
        self.assertTrue(status['allInProcessEntrypointsBound'])
        for field in ('externalWorkersVerified','hostSourceAttested',
                      'hostCredentialGenerationAttested','rollbackProtected',
                      'runtimeIntegrated','canDeploy'):
            self.assertIs(status[field],False)
        self.assertEqual(0,status['revision'])

    def test_owner_incident_route_and_default_machine_submit_still_work(self):
        code,unresolved=self.owner_call('/v1/owner/unresolved')
        self.assertEqual(200,code,unresolved)
        self.assertEqual(0,unresolved['total'])
        code,response=self.machine_call(self.request())
        self.assertEqual(202,code,response)
        self.assertEqual('PENDING',response['state'])
        self.assertEqual('before',self.adapter.get('record')['value'])

    def test_owner_readback_reflects_local_deny_not_configured_ask(self):
        code,before=self.owner_call('/v1/owner/provider-inventory')
        self.assertEqual(200,code,before)
        entry=[x for x in before['operations'] if x['scope']=='exact'][0]
        self.assertEqual(('ASK','ASK',False),
            (entry['configuredPolicy'],entry['effectivePolicy'],
             entry['localDenialApplied']))
        self.apply_deny()
        code,after=self.owner_call('/v1/owner/provider-inventory')
        self.assertEqual(200,code,after)
        entry=[x for x in after['operations'] if x['scope']=='exact'][0]
        self.assertEqual('ASK',entry['configuredPolicy'])
        self.assertEqual('DENY',entry['effectivePolicy'])
        self.assertTrue(entry['localDenialApplied'])
        self.assertEqual(1,after['localDeniedExactRules'])
        self.assertEqual(1,after['localPolicyRevision'])
        self.assertFalse(after['allWorkersVerified'])
        self.assertFalse(after['externalRollbackProof'])
        self.assertEqual(403,self.machine_call(self.request())[0])

    def test_restricting_deny_stales_prior_pending_before_any_side_effect(self):
        code,pending=self.machine_call(self.request())
        self.assertEqual(202,code)
        self.apply_deny()
        with self.assertRaisesRegex(Denied,'OWNER_POLICY_CHANGED'):
            self.core.owner_decide(pending['requestId'],'approve',{})
        self.assertEqual('before',self.adapter.get('record')['value'])

    def test_restart_with_guarded_core_retains_deny(self):
        self.apply_deny()
        restarted=LocalDenyCore(self.path,adapters={'synthetic':self.adapter},
            policies=self.config,authenticator=self.auth,
            owner_verifier=self.owner,policy_version='bundle-v1')
        self.assertEqual('DENY',restarted._policy('agent-1',dict(
            service='synthetic',operation='set_ask',target='record')))
        self.assertEqual('bundle-v1|owner-local-deny:1',restarted.policy_version)

    def test_plain_legacy_core_bypass_is_explicit_unresolved_release_blocker(self):
        self.apply_deny()
        legacy=Core(self.path,adapters={'synthetic':self.adapter},
            policies=self.config,authenticator=self.auth,
            owner_verifier=self.owner,policy_version='bundle-v1')
        self.assertEqual('ASK',legacy._policy('agent-1',dict(
            service='synthetic',operation='set_ask',target='record')))
        with self.assertRaisesRegex(Denied,'OWNER_LOCAL_BUNDLE_TRUSTED_CORE_REQUIRED'):
            bind_source_only_local_policy_bundle(core=legacy,
                owner_auth=self.owner,client_host='machine.test',
                source_digest=SOURCE,credential_generation_digest=CREDS)

    def test_inventory_missing_exact_rule_fails_closed(self):
        self.apply_deny()
        self.core.policies.clear()
        with self.assertRaisesRegex(Denied,'OWNER_LOCAL_INVENTORY_DENIAL_UNRESOLVED'):
            owner_local_deny_inventory(self.core)

    def test_inventory_requires_owner_cookie_and_exact_host(self):
        for kwargs in (dict(cookie='bad'),dict(host='proxy.test')):
            with self.subTest(kwargs=kwargs):
                self.assertEqual(403,self.owner_call(
                    '/v1/owner/provider-inventory',**kwargs)[0])

    def test_unready_policy_gate_fails_closed_on_inventory(self):
        with self.core._db() as db:
            db.execute("UPDATE owner_local_policy_meta SET gate='PREPARED'")
        code,body=self.owner_call('/v1/owner/provider-inventory')
        self.assertEqual(403,code)
        self.assertEqual('OWNER_LOCAL_POLICY_NOT_READY',body['error'])
        with self.assertRaisesRegex(Denied,'OWNER_LOCAL_POLICY_NOT_READY'):
            self.bundle.status()

    def test_identity_mutation_detected(self):
        self.bundle.client_gateway.core=Core(self.path,
            adapters={'synthetic':self.adapter},policies=self.config,
            authenticator=self.auth,owner_verifier=self.owner)
        with self.assertRaisesRegex(Denied,'OWNER_LOCAL_BUNDLE_IDENTITY_DRIFT'):
            self.bundle.status()

    def test_no_external_portal_mounted_in_machine_gateway(self):
        code,result=self.machine_call(self.request())
        self.assertEqual(202,code,result)
        self.assertIsInstance(self.bundle.client_gateway,ClientGateway)
        self.assertNotIn('owner_portal',vars(self.bundle.client_gateway))
        self.assertFalse(hasattr(self.bundle,'start'))
        self.assertFalse(hasattr(self.bundle,'deploy'))
        self.assertFalse(hasattr(self.bundle,'release'))


if __name__=='__main__':
    unittest.main()

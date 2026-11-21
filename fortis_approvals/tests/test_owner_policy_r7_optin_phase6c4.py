"""Phase 6C.4: isolated R7 source builder opt-in, NEVER deployed.

The local fake owner exists only because the minimal Repo image lacks fido2.
Real R7/WebAuthn tests run in the crypto-capable GitHub Source CI.
"""
from io import BytesIO
import inspect
import json
from pathlib import Path
import tempfile
import unittest
import uuid
from unittest.mock import patch

from fortis_approvals.core import Denied
from fortis_approvals.incidents import IncidentCore, IncidentOwnerPortal
from fortis_approvals.r7_unified_candidate import (
    ACTOR,G4_OPERATION,build_r7_unified_candidate)
from fortis_approvals import r7_unified_server
from fortis_approvals.extensions.owner_policy_local_core_phase6c import LocalDenyCore
from fortis_approvals.extensions.owner_policy_local_bundle_phase6c3 import (
    OwnerLocalDenyInventoryPortal)
from fortis_approvals.extensions.owner_policy_r7_optin_phase6c4 import (
    R7LocalDenySourceOptIn)
from fortis_approvals.tests.test_owner_policy_local_deny_http_phase6c2 import (
    HTTPFixtureWebAuthn)


GRANT='R7-SOURCE-TEST-GRANT-00000000000000000001'
SOURCE='a'*64
CREDS='b'*64
ISSUE='ISSUE-1'


class NeverNetworkSonar:
    def __init__(self):
        self.calls=0
    def call(self,method,path,params):
        self.calls+=1
        raise AssertionError('REAL_SONAR_NETWORK_FORBIDDEN_IN_OFFLINE_TEST')


class OptInR7BuilderTests(unittest.TestCase):
    def setUp(self):
        td=tempfile.TemporaryDirectory(prefix='fortis-r7-local-')
        self.addCleanup(td.cleanup)
        self.root=Path(td.name)
        self.sonar=NeverNetworkSonar()
        self.owner=HTTPFixtureWebAuthn()
        self.owner.origin='http://localhost:19103'
        self.kwargs=dict(
            owner_origin='http://localhost:19103',
            ingress_host='host.docker.internal:19104',
            ingress_grant=GRANT,sonar_transport=self.sonar,
            organizations=('acme',))
        self._seq=0

    def build(self,selector=None):
        self._seq+=1
        state=self.root/('state-'+str(self._seq))
        state.mkdir(mode=0o700)
        args=dict(self.kwargs,state=state)
        if selector is not None:
            args['local_deny_source_opt_in']=selector
        with patch('fortis_approvals.r7_unified_candidate.IncidentOwnerWebAuthn',
                   return_value=self.owner):
            return build_r7_unified_candidate(**args)

    def candidate(self):
        return R7LocalDenySourceOptIn(SOURCE,CREDS)

    def test_server_selector_is_explicit_owner_config_only(self):
        from fortis_approvals.extensions.runtime import ExtensionConfig
        from unittest.mock import patch
        config=ExtensionConfig({'schemaVersion':1,'providers':{}})
        self.assertIsNone(r7_unified_server._owner_release_local_deny(config,None,GRANT,'sonar-fixture'))
        config=ExtensionConfig({'schemaVersion':1,'providers':{},
                                'ownerLocalDeny':'SONAR_ACCEPT_ISSUE_V1'})
        with self.assertRaises(RuntimeError):
            r7_unified_server._owner_release_local_deny(config,None,GRANT,'sonar-fixture')
        selected=r7_unified_server._owner_release_local_deny(
            config,str(uuid.uuid4()),GRANT,'sonar-fixture')
        self.assertTrue(selected.runtime_sonar_only)
        self.assertFalse(selected.runtime_verified)
        self.assertNotEqual(selected.credential_generation_digest,
            r7_unified_server._owner_release_local_deny(config,str(uuid.uuid4()),GRANT,'rotated').credential_generation_digest)
        with self.assertRaises(Denied):
            ExtensionConfig({'schemaVersion':1,'providers':{},'ownerLocalDeny':True})

    def test_runtime_scope_denies_non_sonar_mutations_and_keeps_configured_version(self):
        core,owner,portal,ingress=self.build(R7LocalDenySourceOptIn(SOURCE,CREDS,True))
        with core._db() as db:
            candidate=dict(actor=ACTOR,provider='sonarcloud',operation='get_issue',
                 target='ISSUE-1',expectedConfiguredPolicy='ALLOW',
                 expectedPolicyVersion=core.policy_version,expectedRevision=0,reasonCode='OWNER_DENY_EXACT')
            with self.assertRaisesRegex(Denied,'RUNTIME_SCOPE_DENIED'):
                portal._local_deny_apply._check(db,candidate)
        from fortis_approvals.extensions.runtime import ExtensionConfig,ExtensionRuntime
        runtime=ExtensionRuntime(ExtensionConfig({'schemaVersion':1,'providers':{}}),
                 providers=(),actors=(ACTOR,),default_actor=ACTOR)
        runtime.install(core,portal)
        self.assertEqual(core.policy_version.count('|owner-local-deny:'),1)
        self.assertTrue(core.policy_version.endswith('|owner-local-deny:0'))

    def test_real_server_composes_staged_owner_and_guarded_machine(self):
        from types import SimpleNamespace
        from fortis_approvals.extensions.runtime import ExtensionConfig
        from fortis_approvals.extensions.staging import StagedOwner, StagedMachine, ReleaseGate
        import sqlite3
        self.owner.path=self.root/'fixture-owner.sqlite'
        with sqlite3.connect(self.owner.path) as db:
            db.execute('CREATE TABLE credentials(id TEXT PRIMARY KEY,data BLOB,active INTEGER,counter INTEGER)')
            db.execute("INSERT INTO credentials VALUES('fixture-key',x'1234',1,0)")
        state=self.root/'server-state';state.mkdir(mode=0o700)
        paths={}
        for name,content in [('grant',GRANT),('sonar','synthetic-sonar-credential'),
                             ('cert','synthetic-cert'),('key','synthetic-key')]:
            p=self.root/name;p.write_text(content);p.chmod(0o600);paths[name]=p
        config=ExtensionConfig({'schemaVersion':1,'providers':{},
                                'ownerLocalDeny':'SONAR_ACCEPT_ISSUE_V1'})
        def fake_server(host,port,app,**kwargs):
            return SimpleNamespace(app=app)
        with patch('fortis_approvals.r7_unified_candidate.IncidentOwnerWebAuthn',return_value=self.owner), patch.object(r7_unified_server,'SonarHTTPTransport',return_value=self.sonar), patch.object(r7_unified_server,'make_server',side_effect=fake_server), patch.object(r7_unified_server.ssl,'SSLContext'):
            owner_server,machine_server=r7_unified_server.create_servers(
                state=state,grant_path=paths['grant'],sonar_token_path=paths['sonar'],
                cert_path=paths['cert'],key_path=paths['key'],region='eu',
                organizations=('acme',),project_key='acme',extensions=config,
                release_nonce=str(uuid.uuid4()))
        owner_app,machine_app=owner_server.app,machine_server.app
        self.assertIsInstance(owner_app,StagedOwner)
        self.assertIsInstance(machine_app,StagedMachine)
        core=owner_app.delegate.core
        self.assertIs(core,machine_app.broker.core)
        self.assertIs(type(core),LocalDenyCore)
        candidate=dict(actor=ACTOR,provider='sonarcloud',operation='accept_issue',
            target=ISSUE,expectedConfiguredScope='actor',expectedConfiguredPolicy='ASK',
            expectedPolicyVersion=core.policy_version,expectedRevision=0,
            reasonCode='OWNER_DENY_EXACT')
        def post(path,body):
            raw=json.dumps(body).encode();response=[]
            env={'REQUEST_METHOD':'POST','PATH_INFO':'/v1/owner/policy/local-deny/'+path,
                'HTTP_HOST':'localhost:19103','HTTP_ORIGIN':'http://localhost:19103',
                'HTTP_COOKIE':'fortis_owner='+self.owner._session,
                'HTTP_X_FORTIS_CSRF':self.owner._csrf,'QUERY_STRING':'',
                'CONTENT_TYPE':'application/json','CONTENT_LENGTH':str(len(raw)),
                'wsgi.input':BytesIO(raw)}
            result=b''.join(owner_app(env,lambda status,headers:response.append(status)))
            return int(response[0][:3]),json.loads(result)
        with patch.object(ReleaseGate,'ready',return_value=False):
            self.assertEqual(403,post('begin',{'candidate':candidate})[0])
        with patch.object(ReleaseGate,'ready',return_value=True):
            status,started=post('begin',{'candidate':candidate})
            self.assertEqual(200,status,started)
            with self.owner._db() as db:
                db.execute('UPDATE credentials SET counter=1')
            status,result=post('finish',{'ceremonyId':started['ceremonyId'],
                'change':started['change'],'response':{'syntheticTestOnlyUv':True}})
            self.assertEqual(200,status,result)
            self.assertEqual(1,result['appliedRevision'])
        self.assertEqual('DENY',core._policy(ACTOR,dict(
            service='sonarcloud',operation='accept_issue',target=ISSUE)))
        self.assertEqual('ASK',core._policy(ACTOR,dict(
            service='sonarcloud',operation='accept_issue',target='OTHER')))
        self.assertEqual(0,self.sonar.calls)

    def test_selector_is_not_external_attestation(self):
        self.assertNotIn('local_deny_source_opt_in',
                         inspect.signature(r7_unified_server.create_servers).parameters)
        self.assertNotIn('local_deny_source_opt_in',
                         inspect.signature(r7_unified_server.runtime_endpoints).parameters)
        self.assertFalse(self.candidate().runtime_verified)

    def test_legacy_default_is_unchanged_and_not_local_policy_aware(self):
        core,owner,portal,ingress=self.build()
        self.assertIs(type(core),IncidentCore)
        self.assertIs(type(portal),IncidentOwnerPortal)
        self.assertIs(ingress.broker.core,core)
        self.assertFalse(hasattr(portal,'_local_deny_apply'))
        self.assertEqual('r7-p1-sonar-accept-issue-write-v1',core.policy_version)
        with core._db() as db:
            self.assertFalse(db.execute("SELECT 1 FROM sqlite_master "
                "WHERE type='table' AND name='owner_local_policy_meta'").fetchone())
        self.assertEqual(0,self.sonar.calls)

    def test_explicit_opt_in_binds_all_r7_components_to_same_guarded_core(self):
        core,owner,portal,ingress=self.build(self.candidate())
        self.assertIs(type(core),LocalDenyCore)
        self.assertIs(type(portal),OwnerLocalDenyInventoryPortal)
        self.assertIs(portal.core,core)
        self.assertIs(portal.auth,owner)
        self.assertIs(portal._local_deny_apply.core,core)
        self.assertIs(portal._local_deny_apply.auth,owner)
        self.assertIs(ingress.broker.core,core)
        self.assertEqual('r7-p1-sonar-accept-issue-write-v1|owner-local-deny:0',
                         core.policy_version)
        self.assertEqual(core.auth.authenticate(GRANT),ACTOR)

        self.assertEqual(0,self.sonar.calls)

    def test_exact_local_deny_via_r7_core_prevents_sonar_before_network(self):
        core,owner,portal,ingress=self.build(self.candidate())
        coord=(ACTOR,'sonarcloud','accept_issue',ISSUE)
        # Test fixture exact grant, not present in the default R7 policies.
        core.policies[coord]='ASK'
        with core._db() as db:
            db.execute('BEGIN IMMEDIATE')
            db.execute("INSERT INTO owner_local_denials VALUES(?,?,?,?,'DENY')",
                       coord)
            db.execute('UPDATE owner_local_policy_meta SET revision=revision+1')
        self.assertEqual('DENY',core._policy(ACTOR,dict(
            service='sonarcloud',operation='accept_issue',target=ISSUE)))
        with self.assertRaises(Denied):
            core.submit(ACTOR,dict(requestId=str(uuid.uuid4()),
                 service='sonarcloud',operation='accept_issue',
                 target=ISSUE,params={'projectKey':'acme'},expectedVersion=0,
                 reason='offline deny'))
        self.assertEqual(0,self.sonar.calls)
        self.assertEqual('r7-p1-sonar-accept-issue-write-v1|owner-local-deny:1',
                         core.policy_version)

    def test_exact_local_deny_owner_inventory_is_truthful(self):
        core,owner,portal,ingress=self.build(self.candidate())
        coord=(ACTOR,'sonarcloud','accept_issue',ISSUE)
        core.policies[coord]='ASK'
        with core._db() as db:
            db.execute('BEGIN IMMEDIATE')
            db.execute("INSERT INTO owner_local_denials VALUES(?,?,?,?,'DENY')",
                       coord)
            db.execute('UPDATE owner_local_policy_meta SET revision=revision+1')
        response=[]
        env={'REQUEST_METHOD':'GET','PATH_INFO':'/v1/owner/provider-inventory',
             'QUERY_STRING':'','HTTP_HOST':'localhost:19103',
             'HTTP_COOKIE':'fortis_owner='+owner._session,
             'CONTENT_LENGTH':'0','wsgi.input':BytesIO(b'')}
        raw=b''.join(portal(env,lambda code,headers:response.append(code)))
        self.assertEqual('200 OK',response[0])
        result=json.loads(raw)
        rows=[r for r in result['operations'] if r['scope']=='exact']
        self.assertEqual(1,len(rows))
        self.assertEqual('DENY',rows[0]['effectivePolicy'])
        self.assertTrue(rows[0]['localDenialApplied'])
        self.assertEqual(1,result['localDeniedExactRules'])
        self.assertFalse(result['allWorkersVerified'])
        self.assertEqual(0,self.sonar.calls)

    def test_actor_scoped_r7_sonar_ask_can_be_denied_for_one_issue_only(self):
        core,owner,portal,ingress=self.build(self.candidate())
        self.assertEqual('ASK',core.policies[(ACTOR,'sonarcloud','accept_issue')])
        candidate=dict(actor=ACTOR,provider='sonarcloud',operation='accept_issue',
                       target='ISSUE-1',expectedConfiguredPolicy='ASK',
                       expectedConfiguredScope='actor',
                       expectedPolicyVersion=core.policy_version,
                       expectedRevision=0,reasonCode='OWNER_DENY_ONE_ISSUE')
        apply=portal._local_deny_apply
        begun=apply.begin_deny(owner._session,owner._csrf,candidate)
        receipt=apply.finish_deny(owner._session,owner._csrf,
            begun['ceremonyId'],{'syntheticTestOnlyUv':True},begun['change'])
        self.assertTrue(receipt['localDenyCommitted'])
        self.assertEqual('DENY',core._policy(ACTOR,dict(
            service='sonarcloud',operation='accept_issue',target='ISSUE-1')))
        self.assertEqual('ASK',core._policy(ACTOR,dict(
            service='sonarcloud',operation='accept_issue',target='ISSUE-2')))
        self.assertEqual('ASK',core.policies[(ACTOR,'sonarcloud','accept_issue')])
        from fortis_approvals.extensions.owner_policy_local_bundle_phase6c3 import owner_local_deny_inventory
        rows=owner_local_deny_inventory(core)['operations']
        narrowed=[r for r in rows if r['scope']=='exact' and
                  r['provider']=='sonarcloud' and r['operation']=='accept_issue']
        self.assertEqual(1,len(narrowed))
        self.assertEqual('ISSUE-1',narrowed[0]['target'])
        self.assertEqual('actor',narrowed[0]['configuredSourceScope'])
        self.assertEqual('DENY',narrowed[0]['effectivePolicy'])
        self.assertEqual(0,self.sonar.calls)

    def test_bad_opt_in_fails_before_creating_new_state(self):
        with self.assertRaises(Denied):
            R7LocalDenySourceOptIn('bad',CREDS)
        with self.assertRaises(Denied):
            R7LocalDenySourceOptIn(SOURCE,None)
        state=self.root/'untouched-state'
        state.mkdir(mode=0o700)
        with patch('fortis_approvals.r7_unified_candidate.IncidentOwnerWebAuthn',
                   return_value=self.owner):
            with self.assertRaisesRegex(Denied,'R7_LOCAL_DENY_SOURCE_OPT_IN_REJECTED'):
                build_r7_unified_candidate(**dict(self.kwargs,state=state),
                                           local_deny_source_opt_in=True)
        self.assertEqual([],list(state.iterdir()))


if __name__=='__main__':
    unittest.main()

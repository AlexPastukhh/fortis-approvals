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

    def test_upgrade_flag_requires_exact_owner_v2_configuration(self):
        from fortis_approvals.extensions.runtime import ExtensionConfig
        from fortis_approvals.extensions.owner_policy_r7_v2 import R7UnifiedPolicySourceOptIn
        from fortis_approvals.r7_unified_server import _owner_release_unified_policy
        from fortis_approvals.core import Denied
        for raw in (
            {'schemaVersion':1,'providers':{},'ownerPolicyAuthorityUpgrade':'OWNER_LABELS_V1'},
            {'schemaVersion':1,'providers':{},'ownerPolicyEditor':'UNIFIED_V2',
             'ownerPolicyAuthorityUpgrade':'INVALID'},
            {'schemaVersion':1,'providers':{},'ownerPolicyEditor':'UNIFIED_V2',
             'ownerPolicyAuthorityUpgrade':'OWNER_LABELS_V1','ownerLocalDeny':'SONAR_ACCEPT_ISSUE_V1'},
        ):
            with self.subTest(raw=raw),self.assertRaises(Denied):
                ExtensionConfig(raw)
        cfg=ExtensionConfig({'schemaVersion':1,'providers':{},
            'ownerPolicyEditor':'UNIFIED_V2','ownerPolicyAuthorityUpgrade':'OWNER_LABELS_V1'})
        with self.assertRaises(RuntimeError):
            _owner_release_unified_policy(cfg,None,lambda:CREDS)
        opt=_owner_release_unified_policy(cfg,str(uuid.uuid4()),lambda:CREDS)
        self.assertTrue(opt.allow_label_policy_upgrade)
        self.assertIs(type(opt),R7UnifiedPolicySourceOptIn)

    def test_all_method_r7_read_ask_installed_and_provider_not_called_before_uv(self):
        from fortis_approvals.extensions.owner_policy_r7_v2 import R7UnifiedPolicySourceOptIn
        from fortis_approvals.deploy.image_offline_smoke import FakeSonar
        state=self.root/'r7-read-ask';state.mkdir(mode=0o700)
        sonar=FakeSonar()
        with patch('fortis_approvals.r7_unified_candidate.IncidentOwnerWebAuthn',
                   return_value=self.owner):
            core,owner,portal,ingress=build_r7_unified_candidate(**dict(
                self.kwargs,state=state,sonar_transport=sonar,
                organizations=('offline_org',),project_keys=('offline_project',),
                unified_policy_source_opt_in=R7UnifiedPolicySourceOptIn(
                    SOURCE,lambda:CREDS,allow_all_method_policy_upgrade=True)))
        broker=ingress.broker
        self.assertIs(broker.read_approval,core._owner_read_approval)
        coord=(ACTOR,'sonarcloud','get_quality_gate')
        self.assertEqual(core.authority.choices[coord],{'DENY','ASK','ALLOW'})
        rows=portal.editor.inventory()['operations']
        row=next(r for r in rows if r['actor']==ACTOR and
                 (r['provider'],r['operation'])==coord[1:] and r['scope']=='actor')
        self.assertEqual(row['editablePolicies'],['ALLOW','ASK','DENY'])
        candidate=dict(actor=ACTOR,provider='sonarcloud',operation='get_quality_gate',
                       scope='actor',target=None,expectedPolicy='ALLOW',
                       desiredPolicy='ASK',expectedRevision=0,
                       expectedPolicyVersion=core.policy_version,reasonCode='OWNER_POLICY_CHANGE')
        begun=portal.editor.begin(owner._session,owner._csrf,candidate)
        portal.editor.finish(owner._session,owner._csrf,begun['ceremonyId'],
                             {'syntheticTestOnlyUv':True},begun['change'])
        query=dict(requestId=str(uuid.uuid4()),service='sonarcloud',
                   operation='get_quality_gate',target='offline_project',
                   params={},reason='Offline R7 one-use read')
        def wire_read():
            raw=json.dumps(query).encode()
            env={'REQUEST_METHOD':'POST','PATH_INFO':'/v1/reads',
                 'QUERY_STRING':'','SCRIPT_NAME':'',
                 'HTTP_HOST':'host.docker.internal:19104',
                 'HTTP_AUTHORIZATION':'Bearer '+GRANT,
                 'wsgi.url_scheme':'https','CONTENT_TYPE':'application/json',
                 'CONTENT_LENGTH':str(len(raw)),'wsgi.input':BytesIO(raw)}
            statuses=[]
            data=b''.join(ingress(env,lambda status,headers:statuses.append(status)))
            return int(statuses[0][:3]),json.loads(data)
        status,pending=wire_read()
        self.assertEqual((status,pending['state']),(202,'PENDING'))
        self.assertEqual(set(pending),{'requestId','service','operation','state'})
        self.assertEqual(len(sonar.calls),0)
        with patch.object(owner,'verify',return_value='offline-owner',create=True):
            self.assertEqual(core.owner_decide(query['requestId'],'approve',
                                               {'offlineFakeProof':True})['state'],'EXECUTED')
        status,result=wire_read()
        self.assertEqual((status,result['data']['status']),(200,'OK'))
        provider_calls=len(sonar.calls)
        self.assertGreater(provider_calls,0)
        status,denied=wire_read()
        self.assertEqual((status,denied['error']),(403,'REPO_DENIED'))
        self.assertEqual(len(sonar.calls),provider_calls)

    def test_all_method_initial_deny_extension_can_be_allowed_without_widening_grants(self):
        from fortis_approvals.extensions.owner_policy_r7_v2 import R7UnifiedPolicySourceOptIn
        from fortis_approvals.extensions.runtime import ExtensionConfig
        from fortis_approvals.extensions.model import Provider,Operation
        from fortis_approvals.integrations.review_schema import object_schema
        from fortis_approvals.deploy.image_offline_smoke import FakeSonar
        state=self.root/'deny-extension';state.mkdir(mode=0o700)
        called=[]
        empty=object_schema({})
        provider=Provider('fixture',(
            Operation('read_item','Read only registered record','read',empty,empty,
                      lambda ctx: called.append(ctx.target) or {}),))
        config=ExtensionConfig({'schemaVersion':1,'providers':{'fixture':{
            'credentials':{},'operations':{'read_item':{
                'policy':'DENY','targets':['record']}}}}})
        with patch('fortis_approvals.r7_unified_candidate.IncidentOwnerWebAuthn',
                   return_value=self.owner):
            core,owner,portal,_=build_r7_unified_candidate(**dict(
                self.kwargs,state=state,sonar_transport=FakeSonar(),
                extensions=config,extension_providers=(provider,),
                unified_policy_source_opt_in=R7UnifiedPolicySourceOptIn(
                    SOURCE,lambda:CREDS,allow_all_method_policy_upgrade=True)))
        rt=portal._extension_runtime
        coord=(ACTOR,'fixture','read_item','record')
        self.assertEqual(core.authority.choices[coord],{'DENY','ASK','ALLOW'})
        rows=portal.editor.inventory(rt)['operations']
        matching=[row for row in rows if row['scope']=='exact' and
                  (row['actor'],row['provider'],row['operation'],row['target'])==coord]
        self.assertEqual(len(matching),1)
        self.assertEqual((matching[0]['currentPolicy'],matching[0]['editablePolicies']),
                         ('DENY',['ALLOW','ASK','DENY']))
        def call(target):
            return rt.call(GRANT,dict(requestId=str(uuid.uuid4()),service='fixture',
                       operation='read_item',target=target,params={},reason='Offline registered read'))
        with self.assertRaises(Denied):
            call('record')
        self.assertEqual(called,[])
        candidate=dict(actor=ACTOR,provider='fixture',operation='read_item',
                       scope='exact',target='record',expectedPolicy='DENY',
                       desiredPolicy='ALLOW',expectedRevision=0,
                       expectedPolicyVersion=core.policy_version,
                       reasonCode='OWNER_POLICY_CHANGE')
        begin=portal.editor.begin(owner._session,owner._csrf,candidate)
        portal.editor.finish(owner._session,owner._csrf,begin['ceremonyId'],
                             {'syntheticTestOnlyUv':True},begin['change'])
        with self.assertRaises(Denied):
            call('unregistered')
        self.assertEqual(called,[])
        self.assertEqual(call('record')['state'],'EXECUTED')
        self.assertEqual(called,['record'])

    def test_owner_label_allow_admission_and_persistence_opt_in(self):
        from fortis_approvals.extensions.owner_policy_r7_v2 import R7UnifiedPolicySourceOptIn
        from fortis_approvals.extensions.owner_policy_engine_v2 import UnifiedPolicyCore
        from fortis_approvals.workflow.common import WORKSPACE_OPS
        from fortis_approvals.integrations.github.pilot import GitHubPilotConfig
        from fortis_approvals.integrations.github.gateway.transport import GitHubHTTPTransport
        state=self.root/'label-policy';state.mkdir(mode=0o700)
        config=GitHubPilotConfig('OfflineOwner','offline_repo',
            file_pr_branch='fortis-e2e/'+str(uuid.uuid4())+'-approve',
            ci_reads=True,native_worktree=True,required_workflows=(1,),dynamic_repositories=True)
        transport=GitHubHTTPTransport('OFFLINE_TEST_TOKEN_NOT_REAL_00001')
        def build(upgrade):
            with patch('fortis_approvals.r7_unified_candidate.IncidentOwnerWebAuthn',return_value=self.owner):
                return build_r7_unified_candidate(**dict(self.kwargs,state=state,
                    owner_origin='http://localhost:19203',ingress_host='host.docker.internal:19204',
                    github_pilot=config,github_transport=transport,
                    unified_policy_source_opt_in=R7UnifiedPolicySourceOptIn(
                        SOURCE,lambda:CREDS,allow_label_policy_upgrade=upgrade)))
        original,*_=build(False)
        key=(ACTOR,'github','add_pr_release_labels')
        self.assertEqual(original.authority.choices[key],{'DENY','ASK'})
        from fortis_approvals.extensions.owner_policy_editor_v2 import OwnerPolicyEditor
        from fortis_approvals.extensions.owner_policy_r7_v2 import derive_admission
        with self.assertRaises(Denied):
            # Without reviewed release upgrade the stored digest is immutable.
            from fortis_approvals.extensions.owner_policy_engine_v2 import PolicyAdmission
            unexpected=UnifiedPolicyCore(state/'approvals.sqlite',adapters=original.adapters,
                policies=original.policies,authenticator=original.auth,
                owner_verifier=self.owner,policy_version='r7-p1-sonar-accept-issue-write-v1')
            unexpected.install_policy_authority(
                {**dict(original.authority.choices),
                 key:frozenset({'DENY','ASK','ALLOW'})},
                scope_binding={'unreviewed':'scope drift'})
        updated,*_=build(True)
        self.assertEqual(updated.authority.choices[key],{'DENY','ASK','ALLOW'})
        editor=OwnerPolicyEditor(updated,self.owner,source_digest=SOURCE,
                                 credential_generation=lambda:CREDS)
        candidate=dict(actor=ACTOR,provider='github',operation='add_pr_release_labels',
            scope='actor',target=None,expectedPolicy='ASK',desiredPolicy='ALLOW',
            expectedRevision=0,expectedPolicyVersion=updated.policy_version,
            reasonCode='OWNER_POLICY_CHANGE')
        b=editor.begin(self.owner._session,self.owner._csrf,candidate)
        editor.finish(self.owner._session,self.owner._csrf,b['ceremonyId'],
                      {'syntheticTestOnlyUv':True},b['change'])
        self.assertEqual(updated._policy(ACTOR,dict(service='github',
            operation='add_pr_release_labels',target='offline_repo')),'ALLOW')
        restarted,*_=build(True)
        self.assertEqual(restarted._policy(ACTOR,dict(service='github',
            operation='add_pr_release_labels',target='offline_repo')),'ALLOW')
        with self.assertRaises(Denied):build(False)

    def test_all_method_authority_upgrade_preserves_history_and_can_edit_pr(self):
        from fortis_approvals.extensions.owner_policy_r7_v2 import R7UnifiedPolicySourceOptIn
        from fortis_approvals.extensions.owner_policy_editor_v2 import OwnerPolicyEditor
        from fortis_approvals.integrations.github.pilot import GitHubPilotConfig
        from fortis_approvals.integrations.github.gateway.transport import GitHubHTTPTransport
        from fortis_approvals.deploy.github_pilot_helpers import _local_policy_receipt
        import sqlite3
        state=self.root/'all-method-policy'
        state.mkdir(mode=0o700)
        github=GitHubPilotConfig('OfflineOwner','offline_repo',
            file_pr_branch='fortis-e2e/'+str(uuid.uuid4())+'-approve',
            ci_reads=True,native_worktree=True,required_workflows=(1,),
            dynamic_repositories=True)
        transport=GitHubHTTPTransport('OFFLINE_TEST_TOKEN_NOT_REAL_00001')
        def build(labels=False,all_methods=False):
            with patch('fortis_approvals.r7_unified_candidate.IncidentOwnerWebAuthn',
                       return_value=self.owner):
                return build_r7_unified_candidate(**dict(self.kwargs,state=state,
                    owner_origin='http://localhost:19203',
                    ingress_host='host.docker.internal:19204',
                    github_pilot=github,github_transport=transport,
                    unified_policy_source_opt_in=R7UnifiedPolicySourceOptIn(
                        SOURCE,lambda:CREDS,
                        allow_label_policy_upgrade=labels,
                        allow_all_method_policy_upgrade=all_methods)))
        current,*_=build(labels=True)
        def change(core,op,old,new):
            editor=OwnerPolicyEditor(core,self.owner,source_digest=SOURCE,
                                     credential_generation=lambda:CREDS)
            candidate=dict(actor=ACTOR,provider='github',operation=op,
                scope='actor',target=None,expectedPolicy=old,
                desiredPolicy=new,
                expectedRevision=int(core.policy_version.rsplit(':',1)[1]),
                expectedPolicyVersion=core.policy_version,
                reasonCode='OWNER_POLICY_CHANGE')
            begin=editor.begin(self.owner._session,self.owner._csrf,candidate)
            editor.finish(self.owner._session,self.owner._csrf,begin['ceremonyId'],
                          {'syntheticTestOnlyUv':True},begin['change'])
        change(current,'add_pr_release_labels','ASK','ALLOW')
        change(current,'add_pr_release_labels','ALLOW','ASK')
        with sqlite3.connect(current.path) as db:
            original=db.execute('SELECT * FROM owner_local_policy_v2_events ORDER BY revision').fetchall()
            assert len(original)==2
        with self.assertRaises(Denied):
            build()
        widened,*_=build(all_methods=True)
        # Verify the real R7 composition installs the one-shot READ gate,
        # not merely that an isolated broker test can install it.
        self.assertIsNotNone(getattr(widened,'_owner_read_approval',None))
        for provider,op in (('github','update_pull_request'),
                            ('github','merge_pull_request'),
                            ('sonarcloud','accept_issue'),
                            ('sonarcloud','get_quality_gate')):
            key=(ACTOR,provider,op)
            with self.subTest(key=key):
                self.assertEqual(widened.authority.choices[key],
                                 {'DENY','ASK','ALLOW'})
        change(widened,'update_pull_request','ASK','ALLOW')
        self.assertEqual(widened._policy(ACTOR,dict(service='github',
            operation='update_pull_request',target='offline_repo')),'ALLOW')
        with sqlite3.connect(widened.path) as db:
            self.assertEqual(_local_policy_receipt(db)['revision'],3)
            self.assertEqual(db.execute('SELECT * FROM owner_local_policy_v2_events '
                         'ORDER BY revision LIMIT 2').fetchall(),original)
        restarted,*_=build(all_methods=True)
        self.assertEqual(restarted._policy(ACTOR,dict(service='github',
            operation='update_pull_request',target='offline_repo')),'ALLOW')
        with self.assertRaises(Denied):
            build(labels=True)

    def test_unified_r7_composition_enforces_real_broker_and_extension(self):
        from fortis_approvals.extensions.owner_policy_r7_v2 import R7UnifiedPolicySourceOptIn
        from fortis_approvals.extensions.owner_policy_engine_v2 import UnifiedPolicyCore
        from fortis_approvals.extensions.owner_policy_editor_v2 import UnifiedPolicyPortal
        from fortis_approvals.extensions.runtime import ExtensionConfig
        from fortis_approvals.extensions.model import Operation, Provider
        from fortis_approvals.integrations.review_schema import object_schema
        from fortis_approvals.deploy.github_pilot_helpers import _local_policy_receipt
        from fortis_approvals.deploy.image_offline_smoke import FakeSonar
        import sqlite3
        state=self.root/'v2-state';state.mkdir(mode=0o700)
        remote=FakeSonar()
        calls=[]
        empty=object_schema({})
        provider=Provider('fixture',(
            Operation('read_item','Read test record','read',empty,empty,
                      lambda ctx: calls.append(ctx.target) or {}),
        ))
        settings=ExtensionConfig({'schemaVersion':1,'providers':{'fixture':{
            'credentials':{},'operations':{'read_item':{'policy':'ALLOW','targets':['record']}}}}})
        with patch('fortis_approvals.r7_unified_candidate.IncidentOwnerWebAuthn',return_value=self.owner):
            core,owner,portal,ingress=build_r7_unified_candidate(**dict(
                self.kwargs,state=state,sonar_transport=remote,organizations=('offline_org',),
                project_keys=('offline_project',),extensions=settings,extension_providers=(provider,),
                unified_policy_source_opt_in=R7UnifiedPolicySourceOptIn(SOURCE,lambda:CREDS)))
        self.assertIs(type(core),UnifiedPolicyCore)
        self.assertIs(type(portal),UnifiedPolicyPortal)
        self.assertIs(ingress.base.broker.core,core)
        self.assertIs(portal._extension_runtime.core,core)
        self.assertEqual(core.authority.choices[(ACTOR,'sonarcloud','get_quality_gate')],{'ALLOW','DENY'})
        self.assertEqual(core.authority.choices[(ACTOR,'sonarcloud','accept_issue')],{'ASK','DENY'})
        self.assertEqual(core.authority.choices[(ACTOR,'fixture','read_item','record')],{'DENY','ASK','ALLOW'})
        self.assertIn(('fixture','read_item'),portal.strong_operations)
        def change(service,op,scope,target,old,new):
            with core._db() as db: rev,_,_=core._snapshot(db)
            candidate=dict(actor=ACTOR,provider=service,operation=op,scope=scope,target=target,
                expectedPolicy=old,desiredPolicy=new,expectedRevision=rev,
                expectedPolicyVersion=core.policy_version,reasonCode='OWNER_POLICY_CHANGE')
            b=portal.editor.begin(owner._session,owner._csrf,candidate)
            return portal.editor.finish(owner._session,owner._csrf,b['ceremonyId'],
                {'syntheticTestOnlyUv':True},b['change'])
        call=dict(requestId=str(uuid.uuid4()),service='sonarcloud',operation='get_quality_gate',
                  target='offline_project',params={},reason='Offline V2')
        self.assertEqual(ingress.base.broker.read(GRANT,call)['data']['status'],'OK')
        change('sonarcloud','get_quality_gate','actor',None,'ALLOW','DENY')
        count=len(remote.calls)
        with self.assertRaises(Denied): ingress.base.broker.read(GRANT,call)
        self.assertEqual(len(remote.calls),count)
        change('sonarcloud','get_quality_gate','actor',None,'DENY','ALLOW')
        self.assertEqual(ingress.base.broker.read(GRANT,call)['data']['status'],'OK')
        change('sonarcloud','accept_issue','exact',ISSUE,'ASK','DENY')
        with self.assertRaises(Denied):
            ingress.base.broker.submit(GRANT,dict(requestId=str(uuid.uuid4()),service='sonarcloud',
                operation='accept_issue',target=ISSUE,params={'projectKey':'offline_project'},
                reason='Do not contact the provider'))
        rt=portal._extension_runtime
        change('fixture','read_item','exact','record','ALLOW','ASK')
        payload=dict(requestId=str(uuid.uuid4()),service='fixture',operation='read_item',
                     target='record',params={},reason='Offline test')
        self.assertEqual(rt.call(GRANT,payload)['state'],'PENDING')
        self.assertEqual(calls,[])
        change('fixture','read_item','exact','record','ASK','ALLOW')
        payload['requestId']=str(uuid.uuid4())
        self.assertEqual(rt.call(GRANT,payload)['state'],'EXECUTED')
        self.assertEqual(calls,['record'])
        with sqlite3.connect(core.path) as db:
            receipt=_local_policy_receipt(db)
            self.assertEqual(receipt['revision'],5)
            self.assertEqual(receipt['schemaVersion'],2)

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

    def test_v2_server_explicit_release_gate_and_credential_binding(self):
        from types import SimpleNamespace
        import sqlite3
        from fortis_approvals.extensions.runtime import ExtensionConfig
        from fortis_approvals.extensions.staging import ReleaseGate, StagedOwner
        from fortis_approvals.extensions.owner_policy_engine_v2 import UnifiedPolicyCore
        self.owner.path=self.root/'owner-fixture-v2.sqlite'
        with sqlite3.connect(self.owner.path) as db:
            db.execute('CREATE TABLE credentials(id TEXT PRIMARY KEY,data BLOB,active INTEGER,counter INTEGER)')
            db.execute("INSERT INTO credentials VALUES('fixture-key',x'1234',1,0)")
        state=self.root/'server-v2';state.mkdir(mode=0o700)
        paths={}
        for name,content in [('grant',GRANT),('sonar','synthetic-sonar-credential'),
                             ('cert','synthetic-cert'),('key','synthetic-key')]:
            p=self.root/name;p.write_text(content);p.chmod(0o600);paths[name]=p
        config=ExtensionConfig({'schemaVersion':1,'providers':{},'ownerPolicyEditor':'UNIFIED_V2'})
        with self.assertRaises(RuntimeError):
            r7_unified_server._owner_release_unified_policy(config,None,lambda:CREDS)
        with self.assertRaises(Denied):
            ExtensionConfig({**config.value,'ownerLocalDeny':'SONAR_ACCEPT_ISSUE_V1'})
        with patch('fortis_approvals.r7_unified_candidate.IncidentOwnerWebAuthn',return_value=self.owner), patch.object(r7_unified_server,'SonarHTTPTransport',return_value=self.sonar), patch.object(r7_unified_server,'make_server',side_effect=lambda h,p,a,**kw:SimpleNamespace(app=a)), patch.object(r7_unified_server.ssl,'SSLContext'):
            owner_server,machine_server=r7_unified_server.create_servers(
                state=state,grant_path=paths['grant'],sonar_token_path=paths['sonar'],
                cert_path=paths['cert'],key_path=paths['key'],region='eu',
                organizations=('acme',),project_key='acme',extensions=config,
                release_nonce=str(uuid.uuid4()))
        app=owner_server.app
        self.assertIsInstance(app,StagedOwner)
        core=app.delegate.core
        self.assertIs(type(core),UnifiedPolicyCore)
        self.assertIs(machine_server.app.broker.core,core)
        editor=app.delegate.editor
        def post(path,body):
            raw=json.dumps(body).encode();status=[]
            env={'REQUEST_METHOD':'POST','PATH_INFO':'/v1/owner/policy/editor/'+path,
                'HTTP_HOST':'localhost:19103','HTTP_ORIGIN':'http://localhost:19103',
                'HTTP_COOKIE':'fortis_owner='+self.owner._session,
                'HTTP_X_FORTIS_CSRF':self.owner._csrf,'QUERY_STRING':'',
                'CONTENT_TYPE':'application/json','CONTENT_LENGTH':str(len(raw)),
                'wsgi.input':BytesIO(raw)}
            result=b''.join(app(env,lambda line,headers:status.append(line)))
            return int(status[0][:3]),json.loads(result)
        candidate=dict(actor=ACTOR,provider='sonarcloud',operation='accept_issue',
            scope='actor',target=None,expectedPolicy='ASK',desiredPolicy='DENY',
            expectedPolicyVersion=core.policy_version,expectedRevision=0,
            reasonCode='OWNER_POLICY_CHANGE')
        with patch.object(ReleaseGate,'ready',return_value=False):
            self.assertEqual(post('begin',{'candidate':candidate})[0],403)
        with patch.object(ReleaseGate,'ready',return_value=True):
            self.assertEqual(post('begin',{'candidate':candidate})[0],200)
            before=editor.generation()
            with self.owner._db() as db:
                db.execute('UPDATE credentials SET counter=1')
            self.assertEqual(editor.generation(),before)
            code,b=post('begin',{'candidate':candidate})
            self.assertEqual(code,200)
            paths['sonar'].write_text('rotated-synthetic-credential')
            code,_=post('finish',{'ceremonyId':b['ceremonyId'],'change':b['change'],
                'response':{'syntheticTestOnlyUv':True}})
            self.assertEqual(code,403)
            paths['sonar'].write_text('synthetic-sonar-credential')
            code,b=post('begin',{'candidate':candidate})
            self.assertEqual(code,200)
            code,result=post('finish',{'ceremonyId':b['ceremonyId'],'change':b['change'],
                'response':{'syntheticTestOnlyUv':True}})
            self.assertEqual(code,200,result)
            self.assertEqual(result['appliedRevision'],1)
        self.assertEqual(core._policy(ACTOR,{'service':'sonarcloud','operation':'accept_issue','target':ISSUE}),'DENY')
        self.assertEqual(self.sonar.calls,0)

    def test_r7_v1_to_v2_legacy_receipt_and_restart_scope_binding(self):
        import sqlite3
        from fortis_approvals.extensions.owner_policy_r7_v2 import R7UnifiedPolicySourceOptIn
        from fortis_approvals.deploy.github_pilot_helpers import _local_policy_receipt
        state=self.root/'migration';state.mkdir(mode=0o700)
        selector=R7UnifiedPolicySourceOptIn(SOURCE,lambda:CREDS)
        with patch('fortis_approvals.r7_unified_candidate.IncidentOwnerWebAuthn',return_value=self.owner):
            args=dict(self.kwargs,state=state)
            old,owner,portal,_=build_r7_unified_candidate(**args,
                local_deny_source_opt_in=R7LocalDenySourceOptIn(SOURCE,CREDS))
            apply=portal._local_deny_apply
            candidate=dict(actor=ACTOR,provider='sonarcloud',operation='accept_issue',
                target=ISSUE,expectedConfiguredScope='actor',expectedConfiguredPolicy='ASK',
                expectedPolicyVersion=old.policy_version,expectedRevision=0,reasonCode='OWNER_DENY_EXACT')
            b=apply.begin_deny(owner._session,owner._csrf,candidate)
            apply.finish_deny(owner._session,owner._csrf,b['ceremonyId'],
                {'syntheticTestOnlyUv':True},b['change'])
            with sqlite3.connect(old.path) as db: legacy=_local_policy_receipt(db)
            core,owner,portal,_=build_r7_unified_candidate(**args,
                unified_policy_source_opt_in=selector)
            with sqlite3.connect(core.path) as db: receipt=_local_policy_receipt(db)
            self.assertEqual(receipt['legacy'],legacy)
            payload={'service':'sonarcloud','operation':'accept_issue','target':ISSUE}
            self.assertEqual(core._policy(ACTOR,payload),'DENY')
            candidate=dict(actor=ACTOR,provider='sonarcloud',operation='accept_issue',
                scope='exact',target=ISSUE,expectedPolicy='DENY',desiredPolicy='ASK',
                expectedRevision=0,expectedPolicyVersion=core.policy_version,reasonCode='OWNER_POLICY_CHANGE')
            b=portal.editor.begin(owner._session,owner._csrf,candidate)
            portal.editor.finish(owner._session,owner._csrf,b['ceremonyId'],
                {'syntheticTestOnlyUv':True},b['change'])
            restarted,*_=build_r7_unified_candidate(**args,unified_policy_source_opt_in=selector)
            self.assertEqual(restarted._policy(ACTOR,payload),'ASK')
            with sqlite3.connect(restarted.path) as db:
                self.assertEqual(_local_policy_receipt(db)['legacy'],legacy)
            with self.assertRaises(Denied):
                build_r7_unified_candidate(**{**args,'organizations':('changed',)},
                    unified_policy_source_opt_in=selector)

    def test_packaged_unified_smoke_with_offline_owner(self):
        from fortis_approvals.deploy.image_offline_smoke import smoke_owner_policy_v2
        with patch('fortis_approvals.r7_unified_candidate.IncidentOwnerWebAuthn',return_value=self.owner):
            smoke_owner_policy_v2()

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

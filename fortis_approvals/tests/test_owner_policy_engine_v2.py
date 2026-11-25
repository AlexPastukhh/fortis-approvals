"""Source-only tests: no live provider, owner or production policy changes."""
from pathlib import Path
import tempfile
import json
from io import BytesIO
import unittest
import uuid

from fortis_approvals.core import Authenticator, Denied, Stale
from fortis_approvals.synthetic import SyntheticAdapter
from fortis_approvals.extensions.owner_policy_engine_v2 import UnifiedPolicyCore
from fortis_approvals.extensions.owner_policy_editor_v2 import OwnerPolicyEditor, UnifiedPolicyPortal
from fortis_approvals.extensions.owner_policy_local_core_phase6c import LocalDenyCore
from fortis_approvals.extensions.owner_policy_local_deny_apply_phase6c1 import OwnerLocalDenyApply
from fortis_approvals.tests.test_owner_policy_local_deny_http_phase6c2 import HTTPFixtureWebAuthn

ACTOR="agent-1"
PARENT=(ACTOR,"synthetic","set_ask")
EXACT=(*PARENT,"record")
OTHER=(*PARENT,"other")
FREE=(ACTOR,"synthetic","set_free","record")
FIXED=(*PARENT,"fixed")
SOURCE="a"*64
CREDS="b"*64


class UnifiedPolicyTests(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root=Path(tmp.name)
        self.adapter=SyntheticAdapter(self.root/"data.sqlite")
        self.adapter.seed("record","before")
        self.auth=Authenticator({"machine":ACTOR})
        self.owner=HTTPFixtureWebAuthn()
        self.owner.origin="http://localhost:18990"
        self.policy={PARENT:"ASK",FREE:"ALLOW",FIXED:"DENY"}
        self.choices={PARENT:{"DENY","ASK","ALLOW"},FREE:{"DENY","ALLOW"}}
        self.creds=CREDS
        self.make_core()

    def kwargs(self):
        return dict(adapters={"synthetic":self.adapter},policies=self.policy,
                    authenticator=self.auth,owner_verifier=self.owner,policy_version="test")

    def make_core(self):
        self.core=UnifiedPolicyCore(self.root/"core.sqlite",**self.kwargs())
        self.core.install_policy_authority(self.choices)
        self.editor=OwnerPolicyEditor(self.core,self.owner,source_digest=SOURCE,
                                      credential_generation=lambda:self.creds)
        self.portal=UnifiedPolicyPortal(self.core,self.owner,editor=self.editor)

    def candidate(self,key,old,new):
        with self.core._db() as db:
            rev,_,_=self.core._snapshot(db)
        return dict(actor=key[0],provider=key[1],operation=key[2],
                    scope="exact" if len(key)==4 else "actor",target=key[3] if len(key)==4 else None,
                    expectedPolicy=old,desiredPolicy=new,expectedRevision=rev,
                    expectedPolicyVersion=self.core.policy_version,reasonCode="OWNER_POLICY_CHANGE")

    def begin(self,candidate):
        return self.editor.begin(self.owner._session,self.owner._csrf,candidate)

    def finish(self,b,response=None,change=None):
        return self.editor.finish(self.owner._session,self.owner._csrf,b["ceremonyId"],
            {"syntheticTestOnlyUv":True} if response is None else response,
            b["change"] if change is None else change)

    def change(self,key,old,new):
        return self.finish(self.begin(self.candidate(key,old,new)))

    def decision(self,key):
        return self.core._policy(key[0],dict(service=key[1],operation=key[2],target=key[3]))

    def test_all_six_transitions_and_restart(self):
        old="ASK"
        for new in ("DENY","ALLOW","ASK","ALLOW","DENY","ASK"):
            result=self.change(EXACT,old,new)
            self.assertTrue(result["found"])
            self.assertEqual(self.decision(EXACT),new)
            self.assertEqual(self.decision(OTHER),"ASK")
            self.assertEqual(self.decision(FIXED),"DENY")
            old=new
        self.make_core()
        self.assertEqual(self.decision(EXACT),"ASK")
        self.assertTrue(self.core.policy_version.endswith(":6"))

    def test_actor_rule_and_exact_precedence(self):
        self.change(EXACT,"ASK","DENY")
        preview=self.core.preview_change(self.candidate(PARENT,"ASK","ALLOW"))
        self.assertEqual(preview["exactExceptions"],2)
        self.change(PARENT,"ASK","ALLOW")
        self.assertEqual(self.decision(EXACT),"DENY")
        self.assertEqual(self.decision(OTHER),"ALLOW")
        self.assertEqual(self.decision(FIXED),"DENY")
        self.change(PARENT,"ALLOW","DENY")
        self.assertEqual(self.decision(OTHER),"DENY")

    def test_server_admits_only_explicit_transitions(self):
        for key,old,new in ((FREE,"ALLOW","ASK"),(FIXED,"DENY","ALLOW"),
              ((ACTOR,"synthetic","unknown","record"),"DENY","ALLOW")):
            with self.assertRaises(Denied):
                self.begin(self.candidate(key,old,new))
        self.assertEqual(self.decision(FREE),"ALLOW")

    def test_uv_descriptor_revision_generation_and_replay(self):
        b=self.begin(self.candidate(EXACT,"ASK","ALLOW"))
        with self.assertRaises(Denied):
            self.finish(b,change={**b["change"],"desiredPolicy":"DENY"})
        with self.assertRaises(Denied):
            self.finish(b)
        b=self.begin(self.candidate(EXACT,"ASK","ALLOW"))
        with self.assertRaises(Denied):
            self.finish(b,response={})
        self.assertEqual(self.decision(EXACT),"ASK")
        b=self.begin(self.candidate(EXACT,"ASK","ALLOW"))
        self.creds="c"*64
        with self.assertRaises(Denied):
            self.finish(b)
        self.creds=CREDS
        b=self.begin(self.candidate(EXACT,"ASK","ALLOW"))
        self.change(FREE,"ALLOW","DENY")
        with self.assertRaises(Stale):
            self.finish(b)
        self.assertEqual(self.decision(EXACT),"ASK")

    def test_dispatched_blocks_target_mutation_and_old_pending_stales(self):
        payload=dict(requestId=str(uuid.uuid4()),service="synthetic",operation="set_ask",
                     target="record",params={"value":"after"},expectedVersion=0,reason="offline")
        row=self.core.submit(ACTOR,payload)
        self.assertEqual(row["state"],"PENDING")
        with self.core._db() as db:
            db.execute("UPDATE requests SET state='DISPATCHED' WHERE id=?",(row["requestId"],))
        with self.assertRaises(Denied):
            self.begin(self.candidate(EXACT,"ASK","DENY"))
        with self.core._db() as db:
            db.execute("UPDATE requests SET state='APPROVED',decision='approve' WHERE id=?",(row["requestId"],))
        self.change(EXACT,"ASK","DENY")
        self.assertEqual(self.core.execute(row["requestId"])["state"],"STALE")
        self.assertEqual(self.adapter.get("record")["value"],"before")

    def http(self,path,body=None,*,owner=True,csrf=True,origin="http://localhost:18990",host="localhost:18990"):
        raw=json.dumps(body).encode() if body is not None else b""
        env={"REQUEST_METHOD":"POST" if body is not None else "GET",
             "PATH_INFO":path,"HTTP_HOST":host,"QUERY_STRING":"",
             "wsgi.input":BytesIO(raw),"CONTENT_LENGTH":str(len(raw)),
             "CONTENT_TYPE":"application/json","HTTP_ORIGIN":origin}
        if owner:
            env["HTTP_COOKIE"]="fortis_owner="+self.owner._session
        if csrf:
            env["HTTP_X_FORTIS_CSRF"]=self.owner._csrf
        status=[]
        answer=b"".join(self.portal(env,lambda line,headers:status.append(line)))
        return int(status[0][:3]),json.loads(answer)

    def test_owner_http_inventory_preview_and_write_separation(self):
        prefix="/v1/owner/policy/editor"
        candidate=self.candidate(EXACT,"ASK","ALLOW")
        for args in ({"owner":False},{"csrf":False},{"origin":"https://evil.example"},
                     {"host":"evil.example"}):
            status,_=self.http(prefix+"/begin",{"candidate":candidate},**args)
            self.assertEqual(status,403)
        code,inventory=self.http("/v1/owner/provider-inventory")
        self.assertEqual(code,200)
        self.assertEqual(inventory["policyEditorVersion"],2)
        code,preview=self.http(prefix+"/preview",{"candidate":candidate})
        self.assertEqual(code,200)
        self.assertEqual(preview["risk"],"EXPANDS")
        self.assertEqual(self.decision(EXACT),"ASK")
        code,b=self.http(prefix+"/begin",{"candidate":candidate})
        self.assertEqual(code,200)
        self.assertEqual(self.decision(EXACT),"ASK")
        body=dict(ceremonyId=b["ceremonyId"],response={"syntheticTestOnlyUv":True},change=b["change"])
        code,_=self.http(prefix+"/finish",body,csrf=False)
        self.assertEqual(code,403)
        code,result=self.http(prefix+"/finish",body)
        self.assertEqual(code,200)
        self.assertTrue(result["found"])
        self.assertEqual(self.decision(EXACT),"ALLOW")
        code,result=self.http(prefix+"/readback",{"requestId":b["change"]["requestId"]})
        self.assertEqual(code,200)
        self.assertEqual(result["change"],b["change"])
        self.assertEqual(self.http(prefix+"/finish",body)[0],403)

    def test_actual_submit_enforces_each_new_policy(self):
        def payload(version,value):
            return dict(requestId=str(uuid.uuid4()),service="synthetic",operation="set_ask",
                        target="record",params={"value":value},expectedVersion=version,reason="offline test")
        self.change(EXACT,"ASK","ALLOW")
        outcome=self.core.submit(ACTOR,payload(0,"allowed"))
        self.assertEqual(outcome["state"],"EXECUTED")
        self.change(EXACT,"ALLOW","DENY")
        with self.assertRaises(Denied):
            self.core.submit(ACTOR,payload(1,"denied"))
        self.change(EXACT,"DENY","ASK")
        self.assertEqual(self.core.submit(ACTOR,payload(1,"pending"))["state"],"PENDING")
        self.assertEqual(self.adapter.get("record"),{"value":"allowed","version":1})

    def test_invalid_projection_and_restart_authority_drift_fail_closed(self):
        self.change(EXACT,"ASK","DENY")
        with self.core._db() as db:
            db.execute("UPDATE owner_local_policy_v2_rules SET policy='ALLOW'")
        with self.assertRaises(Denied):
            self.decision(EXACT)
        with self.assertRaises(Denied):
            self.make_core()

    def test_reviewed_authority_upgrade_from_exact_old_digest_only(self):
        # V2 authority changes must not silently reinterpret prior grants.
        old={PARENT:{"DENY","ASK"},FREE:{"DENY","ALLOW"}}
        self.core=UnifiedPolicyCore(self.root/"upgrade.sqlite",**self.kwargs())
        self.core.install_policy_authority(old,scope_binding={"origin":"reviewed"})
        with self.core._db() as db:
            before=db.execute("SELECT authority FROM owner_local_policy_v2_meta").fetchone()[0]
        target={PARENT:{"DENY","ASK","ALLOW"},FREE:{"DENY","ALLOW"}}
        plain=UnifiedPolicyCore(self.root/"upgrade.sqlite",**self.kwargs())
        with self.assertRaises(Denied):
            plain.install_policy_authority(target,scope_binding={"origin":"reviewed"})
        with plain._db() as db:
            self.assertEqual(db.execute("SELECT authority FROM owner_local_policy_v2_meta").fetchone()[0],before)
        plain.install_policy_authority(target,scope_binding={"origin":"reviewed"},reviewed_upgrade_from=old)
        with plain._db() as db:
            after=db.execute("SELECT authority FROM owner_local_policy_v2_meta").fetchone()[0]
        self.assertNotEqual(before,after)
        restarted=UnifiedPolicyCore(self.root/"upgrade.sqlite",**self.kwargs())
        restarted.install_policy_authority(target,scope_binding={"origin":"reviewed"},reviewed_upgrade_from=old)
        with restarted._db() as db:
            self.assertEqual(db.execute("SELECT authority FROM owner_local_policy_v2_meta").fetchone()[0],after)
        self.assertEqual(restarted._policy(ACTOR,dict(service='synthetic',operation='set_ask',target='record')),"ASK")
        downgrade=UnifiedPolicyCore(self.root/"upgrade.sqlite",**self.kwargs())
        with self.assertRaises(Denied):
            downgrade.install_policy_authority(old,scope_binding={"origin":"reviewed"})
        with self.assertRaises(Denied):
            UnifiedPolicyCore(self.root/"upgrade.sqlite",**self.kwargs()).install_policy_authority(
                target,scope_binding={"origin":"drifted"},reviewed_upgrade_from=old)

    def test_reviewed_upgrade_preserves_previous_v2_policy_events(self):
        old={PARENT:{"DENY","ASK"},FREE:{"DENY","ALLOW"}}
        core=UnifiedPolicyCore(self.root/"edited.sqlite",**self.kwargs())
        core.install_policy_authority(old)
        editor=OwnerPolicyEditor(core,self.owner,source_digest=SOURCE,
                                 credential_generation=lambda:CREDS)
        candidate=dict(actor=ACTOR,provider='synthetic',operation='set_ask',
            scope='exact',target='record',expectedPolicy='ASK',desiredPolicy='DENY',
            expectedRevision=0,expectedPolicyVersion=core.policy_version,
            reasonCode='OWNER_POLICY_CHANGE')
        b=editor.begin(self.owner._session,self.owner._csrf,candidate)
        editor.finish(self.owner._session,self.owner._csrf,b['ceremonyId'],
                      {'syntheticTestOnlyUv':True},b['change'])
        upgraded_choices={PARENT:{"DENY","ASK","ALLOW"},FREE:{"DENY","ALLOW"}}
        migrated=UnifiedPolicyCore(self.root/"edited.sqlite",**self.kwargs())
        with self.assertRaises(Denied):
            migrated.install_policy_authority(upgraded_choices)
        migrated.install_policy_authority(upgraded_choices,reviewed_upgrade_from=old)
        with migrated._db() as db:
            self.assertEqual(db.execute("SELECT revision FROM owner_local_policy_v2_meta").fetchone()[0],1)
            self.assertEqual(db.execute("SELECT COUNT(*) FROM owner_local_policy_v2_authority_epochs").fetchone()[0],1)
            self.assertEqual(db.execute("SELECT COUNT(*) FROM owner_local_policy_v2_events").fetchone()[0],1)
        self.assertEqual(migrated._policy(ACTOR,dict(service='synthetic',operation='set_ask',
                                target='record')),'DENY')
        reopened=UnifiedPolicyCore(self.root/"edited.sqlite",**self.kwargs())
        reopened.install_policy_authority(upgraded_choices,reviewed_upgrade_from=old)
        self.assertEqual(reopened._policy(ACTOR,dict(service='synthetic',operation='set_ask',
                                target='record')),'DENY')
        with reopened._db() as db:
            # Tampered epoch boundaries or old digest cannot be accepted.
            db.execute("UPDATE owner_local_policy_v2_authority_epochs SET old_authority=?",
                       ('0'*64,))
        with self.assertRaises(Denied):
            reopened.policy_version

    def test_registry_reviewed_managed_source_matches_packaged_provider(self):
        from fortis_approvals.extensions.model import discover
        from fortis_approvals.extensions.owner_policy_r7_v2 import (
            _REGISTRY_MANAGED_SOURCE_BEFORE, _REGISTRY_MANAGED_SOURCE_AFTER)
        provider, = discover(('registry',))
        self.assertEqual(provider.source_digest, _REGISTRY_MANAGED_SOURCE_AFTER)
        self.assertNotEqual(provider.source_digest, _REGISTRY_MANAGED_SOURCE_BEFORE)

    def test_registry_first_activation_preserves_exact_old_authority_and_epochs(self):
        from copy import deepcopy
        from fortis_approvals.extensions.owner_policy_r7_v2 import (
            RegistryAuthorityPredecessor, _MIRROR_V1_CAPACITY_SOURCE_BEFORE,
            _MIRROR_V1_CAPACITY_SOURCE_AFTER, _REGISTRY_MANAGED_SOURCE_BEFORE,
            _REGISTRY_MANAGED_SOURCE_AFTER)
        from fortis_approvals.integrations.github.gateway.review_attestation import ACTOR as REVIEW, SERVICE, BUNDLE_OPERATION
        from fortis_approvals.integrations.registry.read_contract import PLANNER_ACTOR
        path=self.root/'registry-cutover.sqlite'
        old_scope={'extensions':{'definitions':{'mirror':{'source':_MIRROR_V1_CAPACITY_SOURCE_BEFORE,
            'operations':[]}},'credentials':{'mirror':{}}},'readGrants':{},'writeGrants':{}}
        old=UnifiedPolicyCore(path,**self.kwargs())
        old.install_policy_authority(self.choices,scope_binding=old_scope)
        editor=OwnerPolicyEditor(old,self.owner,source_digest=SOURCE,credential_generation=lambda:CREDS)
        candidate=dict(actor=ACTOR,provider='synthetic',operation='set_ask',
            scope='exact',target='record',expectedPolicy='ASK',desiredPolicy='DENY',
            expectedRevision=0,expectedPolicyVersion=old.policy_version,reasonCode='OWNER_POLICY_CHANGE')
        begin=editor.begin(self.owner._session,self.owner._csrf,candidate)
        editor.finish(self.owner._session,self.owner._csrf,begin['ceremonyId'],
            {'syntheticTestOnlyUv':True},begin['change'])
        mirror_scope=deepcopy(old_scope)
        mirror_scope['extensions']['definitions']['mirror']['source']=_MIRROR_V1_CAPACITY_SOURCE_AFTER
        intermediate=UnifiedPolicyCore(path,**self.kwargs())
        intermediate.install_policy_authority(self.choices,scope_binding=mirror_scope,
            reviewed_previous_scope=old_scope,reviewed_upgrade_from=self.choices)
        with intermediate._db() as db:
            events=[tuple(r) for r in db.execute('SELECT * FROM owner_local_policy_v2_events')]
            rules=[tuple(r) for r in db.execute('SELECT * FROM owner_local_policy_v2_rules')]
        new_scope=deepcopy(mirror_scope);new_scope['registryFunctional']='a'*64
        read_ops=('candidate_head','candidate_list_desired','candidate_original_operation')
        new_scope['extensions']['definitions']['registry']={'source':_REGISTRY_MANAGED_SOURCE_BEFORE,
            'operations':[[op,'1','read',True,None,None] for op in read_ops]}
        new_scope['extensions']['credentials']['registry']={}
        added={(ACTOR,'registry',op,'fortis-approvals'):'DENY' for op in read_ops}
        def ask(*args):return 'ASK'
        policies={**self.policy,**added,
            (REVIEW,SERVICE,BUNDLE_OPERATION,'fortis-approvals'):ask,
            (PLANNER_ACTOR,'registry','ingest_merged','fortis-approvals'):ask}
        kwargs={**self.kwargs(),'policies':policies,
            'adapters':{'synthetic':self.adapter,'registry':self.adapter,SERVICE:self.adapter},
            'authenticator':Authenticator({'machine':ACTOR,'review':REVIEW,'planner':PLANNER_ACTOR})}
        choices={**self.choices,**{k:{'DENY','ASK','ALLOW'} for k in added}}
        new=UnifiedPolicyCore(path,**kwargs)
        with self.assertRaises(Denied):
            new.install_policy_authority(choices,scope_binding=new_scope)
        pred=RegistryAuthorityPredecessor(new,new_scope,choices)
        new.install_policy_authority(choices,scope_binding=new_scope,
            reviewed_registry_predecessor=pred,reviewed_upgrade_from=pred.choices)
        with new._db() as db:
            self.assertEqual([tuple(r) for r in db.execute('SELECT * FROM owner_local_policy_v2_events')],events)
            self.assertEqual([tuple(r) for r in db.execute('SELECT * FROM owner_local_policy_v2_rules')],rules)
            self.assertEqual(db.execute('SELECT COUNT(*) FROM owner_local_policy_v2_authority_epochs').fetchone()[0],2)
        self.assertEqual(new._policy(ACTOR,dict(service='synthetic',operation='set_ask',target='record')),'DENY')
        self.assertEqual(new._policy(REVIEW,dict(service=SERVICE,operation=BUNDLE_OPERATION,target='fortis-approvals')),'ASK')
        restarted=UnifiedPolicyCore(path,**kwargs)
        pred=RegistryAuthorityPredecessor(restarted,new_scope,choices)
        restarted.install_policy_authority(choices,scope_binding=new_scope,
            reviewed_registry_predecessor=pred,reviewed_upgrade_from=pred.choices)
        self.assertEqual(restarted.policy_version,new.policy_version)
        drifted=deepcopy(new_scope);drifted['region']='different'
        broken=UnifiedPolicyCore(path,**kwargs)
        pred=RegistryAuthorityPredecessor(broken,drifted,choices)
        with self.assertRaises(Denied):
            broken.install_policy_authority(choices,scope_binding=drifted,
                reviewed_registry_predecessor=pred,reviewed_upgrade_from=pred.choices)

        # The next owner-sealed functional release changes only the verified
        # config binding. It must preserve decisions from every prior epoch.
        previous_editor=OwnerPolicyEditor(new,self.owner,source_digest=SOURCE,
                                         credential_generation=lambda:CREDS)
        transition={**candidate, 'expectedPolicy':'DENY', 'desiredPolicy':'ASK',
                    'expectedRevision':1, 'expectedPolicyVersion':new.policy_version}
        begin=previous_editor.begin(self.owner._session,self.owner._csrf,transition)
        previous_editor.finish(self.owner._session,self.owner._csrf,begin['ceremonyId'],
                               {'syntheticTestOnlyUv':True},begin['change'])
        with new._db() as db:
            events=[tuple(r) for r in db.execute('SELECT * FROM owner_local_policy_v2_events')]
            rules=[tuple(r) for r in db.execute('SELECT * FROM owner_local_policy_v2_rules')]
        next_scope={**new_scope, 'registryFunctional':'c'*64}
        successor=UnifiedPolicyCore(path,**kwargs)
        unreviewed=RegistryAuthorityPredecessor(successor,next_scope,choices)
        with self.assertRaisesRegex(Denied,'AUTHORITY_UPGRADE_REVIEW_REQUIRED'):
            successor.install_policy_authority(choices,scope_binding=next_scope,
                reviewed_registry_predecessor=unreviewed,reviewed_upgrade_from=unreviewed.choices)

        wrong_scope={**next_scope,'region':'unreviewed'}
        wrong=RegistryAuthorityPredecessor(successor,wrong_scope,choices,
                                          previous_functional_digests=(new_scope['registryFunctional'],))
        with self.assertRaisesRegex(Denied,'AUTHORITY_UPGRADE_REVIEW_REQUIRED'):
            successor.install_policy_authority(choices,scope_binding=wrong_scope,
                reviewed_registry_predecessor=wrong,reviewed_upgrade_from=wrong.choices)

        for _ in range(2):
            successor=UnifiedPolicyCore(path,**kwargs)
            verified=RegistryAuthorityPredecessor(successor,next_scope,choices,
                                                 previous_functional_digests=(new_scope['registryFunctional'],))
            successor.install_policy_authority(choices,scope_binding=next_scope,
                reviewed_registry_predecessor=verified,reviewed_upgrade_from=verified.choices)
            with successor._db() as db:
                self.assertEqual([tuple(r) for r in db.execute('SELECT * FROM owner_local_policy_v2_events')],events)
                self.assertEqual([tuple(r) for r in db.execute('SELECT * FROM owner_local_policy_v2_rules')],rules)
                self.assertEqual(db.execute('SELECT COUNT(*) FROM owner_local_policy_v2_authority_epochs').fetchone()[0],3)
            self.assertEqual(successor._policy(ACTOR,dict(service='synthetic',operation='set_ask',target='record')),'ASK')

        # This is the rehearsal failure: the immediate current variant
        # matches, but an earlier functional epoch also admitted Registry.
        third_scope={**next_scope,'registryFunctional':'d'*64}
        third=UnifiedPolicyCore(path,**kwargs)
        immediate=(next_scope['registryFunctional'],)
        incomplete=RegistryAuthorityPredecessor(third,third_scope,choices,
                                               previous_functional_digests=immediate)
        with self.assertRaisesRegex(Denied,'AUTHORITY_UPGRADE_REVIEW_REQUIRED'):
            third.install_policy_authority(choices,scope_binding=third_scope,
                reviewed_registry_predecessor=incomplete,reviewed_upgrade_from=incomplete.choices)
        with third._db() as db:
            self.assertEqual(db.execute('SELECT COUNT(*) FROM owner_local_policy_v2_authority_epochs').fetchone()[0],3)

        history=(*immediate,new_scope['registryFunctional'])
        for _ in range(2):
            third=UnifiedPolicyCore(path,**kwargs)
            verified=RegistryAuthorityPredecessor(third,third_scope,choices,
                                                 previous_functional_digests=history)
            third.install_policy_authority(choices,scope_binding=third_scope,
                reviewed_registry_predecessor=verified,reviewed_upgrade_from=verified.choices)
            with third._db() as db:
                self.assertEqual([tuple(r) for r in db.execute('SELECT * FROM owner_local_policy_v2_events')],events)
                self.assertEqual([tuple(r) for r in db.execute('SELECT * FROM owner_local_policy_v2_rules')],rules)
                self.assertEqual(db.execute('SELECT COUNT(*) FROM owner_local_policy_v2_authority_epochs').fetchone()[0],4)
            self.assertEqual(third._policy(ACTOR,dict(service='synthetic',operation='set_ask',target='record')),'ASK')

        # A fourth functional scope must launch against all three historical
        # Registry epochs. Exercise the real predecessor constructor and
        # policy installation together, then repeat startup against the DB.
        fourth_scope = {**third_scope, 'registryFunctional': 'e'*64}
        all_history = (third_scope['registryFunctional'], *history)
        fourth = UnifiedPolicyCore(path, **kwargs)
        incomplete = RegistryAuthorityPredecessor(fourth, fourth_scope, choices,
                                                   previous_functional_digests=all_history[:-1])
        with self.assertRaisesRegex(Denied, 'AUTHORITY_UPGRADE_REVIEW_REQUIRED'):
            fourth.install_policy_authority(choices, scope_binding=fourth_scope,
                reviewed_registry_predecessor=incomplete, reviewed_upgrade_from=incomplete.choices)
        with self.assertRaisesRegex(Denied, 'REGISTRY_PREDECESSOR_INVALID'):
            RegistryAuthorityPredecessor(fourth, fourth_scope, choices,
                                         previous_functional_digests=(*all_history, 'f'*64, '0'*64, '9'*64))
        for _ in range(2):
            fourth = UnifiedPolicyCore(path, **kwargs)
            verified = RegistryAuthorityPredecessor(fourth, fourth_scope, choices,
                                                     previous_functional_digests=all_history)
            fourth.install_policy_authority(choices, scope_binding=fourth_scope,
                reviewed_registry_predecessor=verified, reviewed_upgrade_from=verified.choices)
            with fourth._db() as db:
                self.assertEqual([tuple(r) for r in db.execute('SELECT * FROM owner_local_policy_v2_events')], events)
                self.assertEqual([tuple(r) for r in db.execute('SELECT * FROM owner_local_policy_v2_rules')], rules)
                self.assertEqual(db.execute('SELECT COUNT(*) FROM owner_local_policy_v2_authority_epochs').fetchone()[0], 5)
            self.assertEqual(fourth._policy(ACTOR,dict(service='synthetic',operation='set_ask',target='record')),'ASK')

        fifth_scope = {**fourth_scope, 'registryFunctional': 'f'*64}
        fifth_history = (fourth_scope['registryFunctional'], *all_history)
        for _ in range(2):
            fifth = UnifiedPolicyCore(path, **kwargs)
            verified = RegistryAuthorityPredecessor(fifth, fifth_scope, choices,
                                                    previous_functional_digests=fifth_history)
            fifth.install_policy_authority(choices, scope_binding=fifth_scope,
                reviewed_registry_predecessor=verified, reviewed_upgrade_from=verified.choices)
            with fifth._db() as db:
                self.assertEqual([tuple(r) for r in db.execute('SELECT * FROM owner_local_policy_v2_events')], events)
                self.assertEqual([tuple(r) for r in db.execute('SELECT * FROM owner_local_policy_v2_rules')], rules)
                self.assertEqual(db.execute('SELECT COUNT(*) FROM owner_local_policy_v2_authority_epochs').fetchone()[0], 6)

        sixth_scope = deepcopy(fifth_scope)
        sixth_scope['registryFunctional'] = '0'*64
        sixth_scope['extensions']['definitions']['registry']['source'] = _REGISTRY_MANAGED_SOURCE_AFTER
        unknown_scope = deepcopy(sixth_scope)
        unknown_scope['extensions']['definitions']['registry']['source'] = '9'*64
        unknown = UnifiedPolicyCore(path, **kwargs)
        unknown_predecessor = RegistryAuthorityPredecessor(
            unknown, unknown_scope, choices,
            previous_functional_digests=(fifth_scope['registryFunctional'], *fifth_history))
        with self.assertRaisesRegex(Denied, 'AUTHORITY_UPGRADE_REVIEW_REQUIRED'):
            unknown.install_policy_authority(choices, scope_binding=unknown_scope,
                reviewed_registry_predecessor=unknown_predecessor,
                reviewed_upgrade_from=unknown_predecessor.choices)
        sixth_history = (fifth_scope['registryFunctional'], *fifth_history)
        for _ in range(2):
            sixth = UnifiedPolicyCore(path, **kwargs)
            verified = RegistryAuthorityPredecessor(sixth, sixth_scope, choices,
                                                    previous_functional_digests=sixth_history)
            historical = verified.variants()
            self.assertEqual(
                {scope['extensions']['definitions']['registry']['source']
                 for scope, baseline in historical if 'registryFunctional' in scope},
                {_REGISTRY_MANAGED_SOURCE_BEFORE})
            sixth.install_policy_authority(choices, scope_binding=sixth_scope,
                reviewed_registry_predecessor=verified, reviewed_upgrade_from=verified.choices)
            with sixth._db() as db:
                self.assertEqual([tuple(r) for r in db.execute('SELECT * FROM owner_local_policy_v2_events')], events)
                self.assertEqual([tuple(r) for r in db.execute('SELECT * FROM owner_local_policy_v2_rules')], rules)
                self.assertEqual(db.execute('SELECT COUNT(*) FROM owner_local_policy_v2_authority_epochs').fetchone()[0], 7)

    def test_functional_predecessor_rejects_drift_outside_release(self):
        from copy import deepcopy
        from unittest.mock import patch
        from fortis_approvals.integrations.github.gateway import functional_review_runtime as runtime
        from fortis_approvals.integrations.github.gateway import forward_lineage as lineage
        prior={'validatorRevision':'f'*40,'bootstrapReceipt':{'scopeDigest':'a'*64},
               'cutoverRecovery':{
                   'gap': {'disposition':'OWNER_REVIEWED_PRE_CAPTURE_GAP',
                           'merges':[lineage._CUTOVER_253,lineage._CUTOVER_254]},
                   'release':{'releaseNonce':'e43f890f-fe66-4139-b397-4bb20be82e80',
                       'validatorRevision':'f'*40,
                       'registryImageId':'sha256:6d41a635d71392a2397df7f470a1b0b0a8a779943a0c21e0185faf9885589060',
                       'gatewayImageId':'sha256:22de6d321559c70d3e7c788dc1e77a77cde7dea078cdd7c67cbe59aa93930963',
                       'gatewaySourceDigest':'ece8ada947e53301fa3cc6d9bd6b645bbc02c6b122de851e7780a07bd3b66b61'},
               }}
        successor=deepcopy(prior)
        successor['cutoverRecovery']['gap']['disposition']=lineage._POST_255_GAP
        successor['cutoverRecovery']['gap']['merges'] += [lineage._CUTOVER_255, {'number':256}]
        successor['cutoverRecovery']['release']={'releaseNonce':str(uuid.uuid4())}
        pin=runtime._hash(prior)
        self.assertEqual(runtime._reviewed_functional_predecessor_digests(prior),())
        with patch.object(runtime,'_CUTOVER_254_CONFIG_SHA256',pin):
            self.assertEqual(runtime._reviewed_functional_predecessor_digests(successor),(pin,))
            successor['bootstrapReceipt']['scopeDigest']='b'*64
            with self.assertRaisesRegex(Denied,'CUTOVER_POLICY_PREDECESSOR_NOT_REVIEWED'):
                runtime._reviewed_functional_predecessor_digests(successor)

    def test_post_260_predecessor_uses_exact_259_policy_scope(self):
        from copy import deepcopy
        from unittest.mock import patch
        from fortis_approvals.integrations.github.gateway import functional_review_runtime as runtime
        from fortis_approvals.integrations.github.gateway import forward_lineage as lineage
        prefix=[getattr(lineage, f'_CUTOVER_{number}') for number in range(253,260)]
        prior={'validatorRevision':'f'*40,'bootstrapReceipt':{'scopeDigest':'a'*64},
               'cutoverRecovery':{
                   'gap': {'disposition':lineage._POST_255_GAP, 'merges':prefix},
                   'release':{'releaseNonce':'92836269-9f83-47c4-aa0c-c352249f5fa8',
                       'validatorRevision':'f'*40,
                       'registryImageId':'sha256:32794e660626d4d173861d019261d202aabf5fdcbf092ecd489715d711b73ada',
                       'gatewayImageId':'sha256:ecf412817a0595e66aea867c0f6744a7313b0b33a81f14bfcf590e735f9cf72e',
                       'gatewaySourceDigest':'fe607625bd79e2ad45fbb7065e2fef2da45d077af6ce8c085325aac988e4ab57'},
               }}
        successor=deepcopy(prior)
        successor['cutoverRecovery']['gap']['merges'] += [lineage._CUTOVER_260, {'number':261}]
        successor['cutoverRecovery']['release']={'releaseNonce':str(uuid.uuid4())}
        # Build the separately retained #254 configuration independently.
        older=deepcopy(prior)
        older['cutoverRecovery']={
            'gap':{'disposition':'OWNER_REVIEWED_PRE_CAPTURE_GAP','merges':prefix[:2]},
            'release':{'releaseNonce':'e43f890f-fe66-4139-b397-4bb20be82e80',
                'validatorRevision':'f'*40,
                'registryImageId':'sha256:6d41a635d71392a2397df7f470a1b0b0a8a779943a0c21e0185faf9885589060',
                'gatewayImageId':'sha256:22de6d321559c70d3e7c788dc1e77a77cde7dea078cdd7c67cbe59aa93930963',
                'gatewaySourceDigest':'ece8ada947e53301fa3cc6d9bd6b645bbc02c6b122de851e7780a07bd3b66b61'},
        }
        pin=runtime._hash(prior)
        older_pin=runtime._hash(older)
        with patch.multiple(runtime,_CUTOVER_259_CONFIG_SHA256=pin,_CUTOVER_254_CONFIG_SHA256=older_pin):
            self.assertEqual(runtime._reviewed_functional_predecessor_digests(successor),(pin,older_pin))
            successor['cutoverRecovery']['gap']['merges'][-1:]=[lineage._CUTOVER_261,{'number':262}]
            self.assertEqual(runtime._reviewed_functional_predecessor_digests(successor),(pin,older_pin))
            previous262=deepcopy(successor)
            previous262['cutoverRecovery']['gap']['merges'][-1]=lineage._CUTOVER_262
            previous262['cutoverRecovery']['release']={
                'releaseNonce':'370079a2-d23e-4c55-a97f-cd8cdf305600',
                'validatorRevision':'f'*40,
                'registryImageId':'sha256:a535c91943341e8ae04705c458012e3e4c03226efd513efda86cfea644a7992b',
                'gatewayImageId':'sha256:07450e0f5c362290d3fecce5f5d7cdb7abc5295dbb828f22f6e4321168068966',
                'gatewaySourceDigest':'c71eebc342f3e4cd45f1cdd502d0c0854088af66c0a0a5fa988fc76ff6182bb4',
            }
            next263=deepcopy(previous262)
            next263['cutoverRecovery']['gap']['merges'] += [lineage._CUTOVER_263, {'number':264}]
            next263['cutoverRecovery']['release']={'releaseNonce':str(uuid.uuid4())}
            pin262=runtime._hash(previous262)
            with patch.object(runtime, '_CUTOVER_262_CONFIG_SHA256', pin262):
                self.assertEqual(runtime._reviewed_functional_predecessor_digests(next263),
                                 (pin262,pin,older_pin))
                next264=deepcopy(next263)
                next264['cutoverRecovery']['gap']['merges'][-1:]=[lineage._CUTOVER_264, {'number':265}]
                self.assertEqual(runtime._reviewed_functional_predecessor_digests(next264),
                                 (pin262,pin,older_pin))
                previous265=deepcopy(next264)
                previous265['cutoverRecovery']['gap']['merges'][-1]=lineage._CUTOVER_265
                previous265['cutoverRecovery']['release']={
                    'releaseNonce':'8afe6cf9-acc6-4c24-897a-dcde0143e2ff',
                    'validatorRevision':'f'*40,
                    'registryImageId':'sha256:2c48c667215c85086a7fb1358b7be3d816e56ee6f4bcb0a4e3cc85ee5dc10081',
                    'gatewayImageId':'sha256:6334d9d1c75b3dff7d42c9dfef3cf730227e2ad9bf3399caa817dd00b5ad2af6',
                    'gatewaySourceDigest':'e5d23744bcdb5028d8872aaaae6dc267873a7ddf6406a5e2e40032a80a1c268e',
                }
                next266=deepcopy(previous265)
                next266['cutoverRecovery']['gap']['merges'] += [lineage._CUTOVER_266, {'number':267}]
                next266['cutoverRecovery']['release']={'releaseNonce':str(uuid.uuid4())}
                pin265=runtime._hash(previous265)
                with patch.object(runtime, '_CUTOVER_265_CONFIG_SHA256', pin265):
                    self.assertEqual(runtime._reviewed_functional_predecessor_digests(next266),
                                     (pin265,pin262,pin,older_pin))
                    current265=deepcopy(previous265)
                    current265['cutoverRecovery']['release']['releaseNonce']='2471add6-079b-42ae-9e1d-a22adf821a0d'
                    retry_pin=runtime._hash(current265)
                    self.assertNotEqual(retry_pin,pin265)
                    next267=deepcopy(next266)
                    next267['cutoverRecovery']['gap']['merges'][-1:]=[lineage._CUTOVER_267, {'number':268}]
                    self.assertEqual(runtime._reviewed_functional_predecessor_digests(next267),
                                     (retry_pin,pin262,pin,older_pin))
                    previous268 = deepcopy(next267)
                    previous268['cutoverRecovery']['gap']['merges'][-1] = lineage._CUTOVER_268
                    prior_release = {
                        'releaseNonce': runtime._CUTOVER_268_PREPARED_NONCE,
                        'validatorRevision': 'f'*40,
                        'registryImageId': 'sha256:'+'a'*64,
                        'gatewayImageId': 'sha256:'+'b'*64,
                        'gatewaySourceDigest': 'c'*64,
                    }
                    previous268['cutoverRecovery']['release'] = prior_release
                    pin268 = runtime._hash(previous268)
                    next269 = deepcopy(previous268)
                    next269['cutoverRecovery']['gap']['merges'] += [lineage._CUTOVER_269, {'number': 270}]
                    next269['cutoverRecovery']['release']['releaseNonce'] = str(uuid.uuid4())
                    next269['cutoverRecovery']['predecessorRelease'] = dict(prior_release)
                    with patch.object(runtime, '_CUTOVER_268_CONFIG_SHA256', pin268):
                        self.assertEqual(runtime._reviewed_functional_predecessor_digests(next269),
                                         (pin268, retry_pin, pin262, pin, older_pin))
                        actual268 = deepcopy(previous268)
                        actual268['cutoverRecovery']['release']['releaseNonce'] = runtime._CUTOVER_268_RECHECKED_NONCE
                        next269['cutoverRecovery']['predecessorRelease'] = dict(actual268['cutoverRecovery']['release'])
                        self.assertEqual(runtime._reviewed_functional_predecessor_digests(next269),
                                         (runtime._hash(actual268), retry_pin, pin262, pin, older_pin))
                        next270 = deepcopy(next269)
                        next270['cutoverRecovery']['gap']['merges'][-1:] = [lineage._CUTOVER_270, {'number': 271}]
                        self.assertEqual(runtime._reviewed_functional_predecessor_digests(next270),
                                         (runtime._hash(actual268), retry_pin, pin262, pin, older_pin))
                        next271 = deepcopy(next270)
                        next271['cutoverRecovery']['gap']['merges'][-1:] = [
                            lineage._CUTOVER_271, {'number': 273}]
                        self.assertEqual(runtime._reviewed_functional_predecessor_digests(next271),
                                         (runtime._hash(actual268), retry_pin, pin262, pin, older_pin))
                        # The prepared #270/#271 configurations were never
                        # active; do not reconstruct additional authority epochs.
                        next271['cutoverRecovery']['predecessorRelease']['gatewaySourceDigest'] = '0'*64
                        with self.assertRaisesRegex(Denied, 'CUTOVER_POLICY_PREDECESSOR_NOT_REVIEWED'):
                            runtime._reviewed_functional_predecessor_digests(next271)
                        next269['cutoverRecovery']['predecessorRelease']['gatewaySourceDigest'] = '0'*64
                        with self.assertRaisesRegex(Denied, 'CUTOVER_POLICY_PREDECESSOR_NOT_REVIEWED'):
                            runtime._reviewed_functional_predecessor_digests(next269)
                    next267['cutoverRecovery']['gap']['merges'][12]['headSha']='0'*40
                    with self.assertRaisesRegex(Denied,'CUTOVER_POLICY_PREDECESSOR_NOT_REVIEWED'):
                        runtime._reviewed_functional_predecessor_digests(next267)
                    next266=deepcopy(next266)
                    next266['cutoverRecovery']['gap']['merges'][12]['headSha']='0'*40
                    with self.assertRaisesRegex(Denied,'CUTOVER_POLICY_PREDECESSOR_NOT_REVIEWED'):
                        runtime._reviewed_functional_predecessor_digests(next266)
                next263['cutoverRecovery']['gap']['merges'][9]['headSha']='0'*40
                with self.assertRaisesRegex(Denied,'CUTOVER_POLICY_PREDECESSOR_NOT_REVIEWED'):
                    runtime._reviewed_functional_predecessor_digests(next263)
            successor['bootstrapReceipt']['scopeDigest']='b'*64
            with self.assertRaisesRegex(Denied,'CUTOVER_POLICY_PREDECESSOR_NOT_REVIEWED'):
                runtime._reviewed_functional_predecessor_digests(successor)

    def test_two_reviewed_migrations_preserve_all_uv_events_and_receipts(self):
        from fortis_approvals.deploy.github_pilot_helpers import _local_policy_receipt
        import sqlite3
        start={PARENT:{"DENY","ASK"},FREE:{"DENY","ALLOW"}}
        widened={PARENT:{"DENY","ASK","ALLOW"},FREE:{"DENY","ALLOW"}}
        full={PARENT:{"DENY","ASK","ALLOW"},FREE:{"DENY","ASK","ALLOW"}}
        path=self.root/"twice.sqlite"
        core=UnifiedPolicyCore(path,**self.kwargs())
        core.install_policy_authority(start)
        editor=OwnerPolicyEditor(core,self.owner,source_digest=SOURCE,
                                 credential_generation=lambda:CREDS)
        def apply_to(instance,which,old,new):
            ed=OwnerPolicyEditor(instance,self.owner,source_digest=SOURCE,
                                  credential_generation=lambda:CREDS)
            candidate=dict(actor=which[0],provider=which[1],
                operation=which[2],scope='actor' if len(which)==3 else 'exact',
                target=which[3] if len(which)==4 else None,
                expectedPolicy=old,desiredPolicy=new,
                expectedRevision=int(instance.policy_version.rsplit(':',1)[1]),
                expectedPolicyVersion=instance.policy_version,reasonCode='OWNER_POLICY_CHANGE')
            begin=ed.begin(self.owner._session,self.owner._csrf,candidate)
            ed.finish(self.owner._session,self.owner._csrf,begin['ceremonyId'],
                      {'syntheticTestOnlyUv':True},begin['change'])
        apply_to(core,PARENT,'ASK','DENY')
        with sqlite3.connect(path) as db:
            initial_event=db.execute("SELECT * FROM owner_local_policy_v2_events").fetchall()
        next_core=UnifiedPolicyCore(path,**self.kwargs())
        next_core.install_policy_authority(widened,reviewed_upgrade_from=start)
        with sqlite3.connect(path) as db:
            self.assertEqual(db.execute("SELECT * FROM owner_local_policy_v2_events").fetchall(),initial_event)
            self.assertEqual(_local_policy_receipt(db)["revision"],1)
        apply_to(next_core,PARENT,'DENY','ASK')
        last=UnifiedPolicyCore(path,**self.kwargs())
        last.install_policy_authority(full,reviewed_upgrade_from=widened)
        self.assertEqual(last._policy(ACTOR,dict(service='synthetic',
                          operation='set_ask',target='record')),'ASK')
        with sqlite3.connect(path) as db:
            rows=db.execute("SELECT * FROM owner_local_policy_v2_events ORDER BY revision").fetchall()
            self.assertEqual(rows[0],initial_event[0])
            self.assertEqual(len(rows),2)
            self.assertEqual(db.execute("SELECT COUNT(*) FROM owner_local_policy_v2_authority_epochs").fetchone()[0],2)
            self.assertEqual(_local_policy_receipt(db)["revision"],2)
        restarted=UnifiedPolicyCore(path,**self.kwargs())
        restarted.install_policy_authority(full,reviewed_upgrade_from=widened)
        with sqlite3.connect(path) as db:
            db.execute("UPDATE owner_local_policy_v2_authority_epochs SET through_revision=0 WHERE id=2")
        with self.assertRaises(Denied):
            restarted.policy_version

    def test_outer_allow_does_not_bypass_signed_executor_or_publisher_ask(self):
        from fortis_approvals.powershell_machine import MachinePowerShellAdapter
        from fortis_approvals.workflow.adapters import NativeGitHubAdapter
        from fortis_approvals.integrations.github.publisher_profile import (
            PublisherProfile,ACTOR as PUBLISHER)
        from fortis_approvals.extensions.runtime import ExtensionAdapter
        from types import SimpleNamespace
        machine=object.__new__(MachinePowerShellAdapter)
        machine.actor=ACTOR
        machine.target='windows-owner'
        self.assertEqual(machine.inner_policy(ACTOR,dict(service='powershell',
            operation='execute',target='windows-owner')),'ASK')
        self.assertEqual(machine.inner_policy('other-actor',dict(
            service='powershell',operation='execute',
            target='windows-owner')),'DENY')
        github=object.__new__(NativeGitHubAdapter)
        github.publisher=PublisherProfile(enabled=True,revision='a'*64,
            validator_revision='b'*40,registry_delegation=True)
        payload=dict(service='github',operation='add_pr_release_labels',
                     target='fortis-approvals')
        self.assertEqual(github.inner_policy(PUBLISHER,payload),'ASK')
        self.assertEqual(github.inner_policy(ACTOR,payload),'ALLOW')
        self.assertEqual(github.inner_policy(PUBLISHER,{**payload,
            'target':'not-fortis-approvals'}),'DENY')
        signed=object.__new__(ExtensionAdapter)
        signed.provider=SimpleNamespace(name='mirror')
        operation=SimpleNamespace(signing_credential='signing-key')
        signed.runtime=SimpleNamespace(
            rules={(ACTOR,'mirror','publish','host'): 'ASK'},
            operations={('mirror','publish'):operation})
        self.assertEqual(signed.inner_policy(ACTOR,dict(service='mirror',
            operation='publish',target='host')),'ASK')
        self.assertEqual(signed.inner_policy(ACTOR,dict(service='mirror',
            operation='publish',target='another-host')),'DENY')

    def test_conditional_inner_veto_is_not_bypassed_by_owner_allow(self):
        coord=(ACTOR,'synthetic','set_ask')
        def conditional(_actor,payload):
            return 'DENY' if payload['target']=='blocked' else 'ASK'
        policy={coord:conditional}
        full={coord:{'DENY','ASK','ALLOW'}}
        path=self.root/'conditional.sqlite'
        core=UnifiedPolicyCore(path,adapters={'synthetic':self.adapter},
             policies=policy,authenticator=self.auth,owner_verifier=self.owner,
             policy_version='inner-test')
        core.install_policy_authority(full)
        self.assertEqual(core._policy(ACTOR,dict(service='synthetic',
            operation='set_ask',target='allowed')),'ASK')
        self.assertEqual(core._policy(ACTOR,dict(service='synthetic',
            operation='set_ask',target='blocked')),'DENY')
        editor=OwnerPolicyEditor(core,self.owner,source_digest=SOURCE,
                                 credential_generation=lambda:CREDS)
        candidate=dict(actor=ACTOR,provider='synthetic',operation='set_ask',
                       scope='actor',target=None,expectedPolicy='ALLOW',
                       desiredPolicy='DENY',expectedRevision=0,
                       expectedPolicyVersion=core.policy_version,
                       reasonCode='OWNER_POLICY_CHANGE')
        begin=editor.begin(self.owner._session,self.owner._csrf,candidate)
        editor.finish(self.owner._session,self.owner._csrf,begin['ceremonyId'],
                      {'syntheticTestOnlyUv':True},begin['change'])
        for target in ('allowed','blocked'):
            self.assertEqual(core._policy(ACTOR,dict(service='synthetic',
                operation='set_ask',target=target)),'DENY')

    def test_authority_upgrade_rejects_pending_approved_or_dispatched_work(self):
        old={PARENT:{'DENY','ASK'}}
        new={PARENT:{'DENY','ASK','ALLOW'}}
        for state in ('PENDING','APPROVED','DISPATCHED'):
            path=self.root/(state+'.sqlite')
            core=UnifiedPolicyCore(path,**self.kwargs())
            core.install_policy_authority(old)
            with core._db() as db:
                db.execute("""INSERT INTO requests
                    (id,fingerprint,actor,payload,snapshot,state,policy_version,
                     created_at,expires_at) VALUES(?,?,?,?,?,?,?,?,?)""",
                    (str(uuid.uuid4()),'0'*64,ACTOR,'{}','{}',state,'test',1,99999))
            with self.subTest(state=state),self.assertRaisesRegex(
                    Denied,'UPGRADE_IN_FLIGHT'):
                UnifiedPolicyCore(path,**self.kwargs()).install_policy_authority(
                    new,reviewed_upgrade_from=old)

    def test_release_receipt_v2_and_tamper(self):
        import sqlite3
        from fortis_approvals.deploy.github_pilot_helpers import _local_policy_receipt
        self.change(EXACT,"ASK","DENY")
        self.change(EXACT,"DENY","ALLOW")
        with sqlite3.connect(self.core.path) as db:
            receipt=_local_policy_receipt(db)
            self.assertEqual(receipt["schemaVersion"],2)
            self.assertEqual(receipt["revision"],2)
            self.assertIsNone(receipt["legacy"])
            db.execute("UPDATE owner_local_policy_v2_rules SET policy='ASK'")
            with self.assertRaisesRegex(RuntimeError,"AUDIT_MISMATCH"):
                _local_policy_receipt(db)

    def test_legacy_history_preserved_and_old_core_fenced(self):
        path=self.root/"legacy.sqlite"
        old=LocalDenyCore(path,**self.kwargs())
        apply=OwnerLocalDenyApply(old,self.owner,source_digest=SOURCE,
                                  credential_generation_digest=CREDS)
        candidate=dict(actor=ACTOR,provider="synthetic",operation="set_ask",target="record",
                       expectedConfiguredScope="actor",expectedConfiguredPolicy="ASK",
                       expectedRevision=0,expectedPolicyVersion=old.policy_version,
                       reasonCode="OWNER_DENY_EXACT")
        b=apply.begin_deny(self.owner._session,self.owner._csrf,candidate)
        apply.finish_deny(self.owner._session,self.owner._csrf,b["ceremonyId"],
                          {"syntheticTestOnlyUv":True},b["change"])
        def legacy_rows():
            with old._db() as db:
                return [tuple(row) for row in db.execute("SELECT * FROM owner_local_policy_events")]
        before=legacy_rows()
        self.core=UnifiedPolicyCore(path,**self.kwargs())
        self.core.install_policy_authority(self.choices)
        self.editor=OwnerPolicyEditor(self.core,self.owner,source_digest=SOURCE,
                                      credential_generation=lambda:CREDS)
        self.assertEqual(self.decision(EXACT),"DENY")
        self.change(EXACT,"DENY","ASK")
        self.assertEqual(self.decision(EXACT),"ASK")
        self.assertEqual(legacy_rows(),before)
        with self.assertRaises(Denied):
            LocalDenyCore(path,**self.kwargs())


if __name__=="__main__":
    unittest.main()

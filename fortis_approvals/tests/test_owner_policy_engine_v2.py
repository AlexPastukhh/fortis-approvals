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

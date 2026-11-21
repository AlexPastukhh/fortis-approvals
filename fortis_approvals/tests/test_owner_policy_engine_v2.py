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

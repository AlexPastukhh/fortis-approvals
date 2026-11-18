"""Offline ASK-only Core and proof tests. No Windows, credential or network."""
import hashlib
import hmac
import tempfile
from pathlib import Path
from types import SimpleNamespace
import unittest
import uuid

from fortis_approvals.core import Authenticator, Conflict, Core, Denied, Stale
from fortis_approvals.powershell_machine import (
    ACCEPTED_EXECUTOR_GIT_SHA, EXECUTOR_IDENTITY,
    MachinePowerShellAdapter, _canonical, _CONTRACT_DIGEST, issue_proof,
)
from fortis_approvals.workflow.ingress import NativeIngress

KEY = b"offline-only-gateway-and-Windows-shared-proof-key-32bytes"
ACTOR = "fortis-repo"
TARGET = "windows-owner"


class FakeOwnerVerifier:
    """TEST-ONLY verification, not a WebAuthn implementation."""
    key = b"unit-only-owner-approval-verification"

    def proof(self, row, decision):
        text = (row["requestId"] + ":" + row["fingerprint"] + ":" + decision).encode()
        return {"mac":hmac.new(self.key,text,hashlib.sha256).hexdigest()}

    def verify(self, request_id, fingerprint, decision, proof):
        text = (request_id + ":" + fingerprint + ":" + decision).encode()
        expected = hmac.new(self.key,text,hashlib.sha256).hexdigest()
        if type(proof) is not dict or not hmac.compare_digest(
                str(proof.get("mac", "")),expected):
            raise Denied("OWNER_VERIFICATION_REQUIRED")
        return "synthetic-owner"


class FakeMachineTransport:
    def __init__(self):
        self.key = KEY
        self.calls = []
        self.receipts = {}
        self.lose_ack = False
        self.override_result = None

    def execute(self, request_id, command, proof):
        claims = proof["claims"]
        expected = hmac.new(KEY, b"fortis:machine-powershell:v1\n" + _canonical(claims),
                            hashlib.sha256).hexdigest()
        if (not hmac.compare_digest(expected, proof["mac"]) or
                claims["requestId"] != request_id or claims["actor"] != ACTOR or
                claims["target"] != TARGET or
                claims["commandSha256"] != hashlib.sha256(command.encode()).hexdigest()):
            raise AssertionError("invalid signed proof passed fake Windows")
        self.calls.append((request_id,command,proof))
        result = {"requestId":request_id,"state":"EXECUTED",
                  "commandSha256":claims["commandSha256"],
                  "exitCode":0,"stdout":"fixture","stderr":""}
        self.receipts[request_id] = result
        if self.lose_ack:
            raise RuntimeError("fixture lost ACK after the single effect")
        return result if self.override_result is None else self.override_result

    def status(self, request_id):
        return self.receipts.get(request_id, {"requestId":request_id,"state":"NOT_FOUND"})


class TestMachineGateway(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory(prefix="fortis-machine-ask-test-")
        self.addCleanup(tmp.cleanup)
        self.transport=FakeMachineTransport()
        self.owner=FakeOwnerVerifier()
        self.auth=Authenticator({"repo-grant":ACTOR, "foreign-grant":"foreign-ai"})
        self.core=Core(Path(tmp.name)/"core.sqlite",
                       adapters={},policies={},authenticator=self.auth,
                       owner_verifier=self.owner, clock=lambda:1000, expiry_seconds=3600)
        self.adapter=MachinePowerShellAdapter(
            transport=self.transport,target=TARGET,actor=ACTOR,
            executor_git_sha=ACCEPTED_EXECUTOR_GIT_SHA,executor_identity=EXECUTOR_IDENTITY)
        self.adapter.bind_core(self.core)

    def payload(self, command="Get-Date", ident=None):
        return {
            "requestId": ident or str(uuid.uuid4()),"service":"powershell",
            "operation":"execute", "target":TARGET,
            "params":{"command":command},"expectedVersion":0,
            "reason":"ASK per machine PowerShell execution",
        }

    def submit(self, payload):
        return self.core.client("repo-grant","submit",payload)

    def decide(self, row, action="approve"):
        return self.core.owner_decide(row["requestId"],action,
                                      self.owner.proof(row,action))

    def test_submit_pending_without_running_windows(self):
        row=self.submit(self.payload())
        self.assertEqual(row["state"],"PENDING")
        self.assertEqual(self.transport.calls,[])
        self.assertEqual(row["preview"]["disposition"],"ASK_ONLY")
        self.assertEqual(row["preview"]["contractDigest"],_CONTRACT_DIGEST)
        self.assertEqual(row["preview"]["command"],"Get-Date")
        self.assertEqual(row["preview"]["commandSha256"],
                         hashlib.sha256(b"Get-Date").hexdigest())

    def test_approve_web_authn_equivalent_calls_once_with_bound_proof(self):
        row=self.submit(self.payload())
        result=self.decide(row)
        self.assertEqual(result["state"],"EXECUTED")
        self.assertEqual(len(self.transport.calls),1)
        self.assertEqual(result["result"]["state"],"EXECUTED")
        self.assertEqual(self.submit(row["request"])["state"],"EXECUTED")
        self.assertEqual(len(self.transport.calls),1)
        self.assertEqual(self.core.client("repo-grant","status",row["requestId"])["state"],
                         "EXECUTED")
        with self.assertRaises(Denied):
            self.core.client("foreign-grant","status",row["requestId"])

    def test_reject_and_unapproved_direct_apply_do_not_execute(self):
        row=self.submit(self.payload())
        with self.assertRaises(Stale):
            self.adapter.apply(row["request"])
        self.assertEqual(self.decide(row,"reject")["state"],"REJECTED")
        self.assertEqual(self.transport.calls,[])
        with self.assertRaises(Stale):
            self.adapter.apply(row["request"])

    def test_always_ask_even_if_trusted_policy_misconfigured_allow(self):
        self.core.policies[(ACTOR,"powershell","execute",TARGET)]="ALLOW"
        with self.assertRaises(Denied):
            self.submit(self.payload())
        self.assertEqual(self.transport.calls,[])

    def test_other_actor_target_extra_params_and_oversize_are_denied(self):
        payload=self.payload()
        with self.assertRaises(Denied):
            self.core.client("foreign-grant","submit",payload)
        for changed in [
            {**payload,"target":"other"},
            {**payload,"params":{"command":"Get-Date","approved":True}},
            {**payload,"params":{"command":"x"*8193}},
            {**payload,"params":{"command":"Remove-Item x\u0000"}},
        ]:
            with self.subTest(changed=changed["target"]):
                with self.assertRaises(Denied):
                    self.submit(changed)
        self.assertEqual(self.transport.calls,[])

    def test_arbitrary_command_does_not_bypass_ask(self):
        row=self.submit(self.payload("Remove-Item $HOME\\some-file"))
        self.assertEqual(row["state"],"PENDING")
        self.assertEqual(self.transport.calls,[])

    def test_stale_executor_profile_before_owner_decision(self):
        row=self.submit(self.payload())
        self.adapter.executor_git_sha="0"*40
        self.assertEqual(self.decide(row)["state"],"STALE")
        self.assertEqual(self.transport.calls,[])

    def test_adapter_denies_unreviewed_executor_source_or_claimed_identity(self):
        for source in ("0"*40, "a"*64, "BAD", "", None):
            with self.subTest(source=source), self.assertRaises(ValueError):
                MachinePowerShellAdapter(
                    transport=self.transport, target=TARGET, actor=ACTOR,
                    executor_git_sha=source, executor_identity=EXECUTOR_IDENTITY)
        for identity in ("other-user", "", None, "admin-windows"):
            with self.subTest(identity=identity), self.assertRaises(ValueError):
                MachinePowerShellAdapter(
                    transport=self.transport, target=TARGET, actor=ACTOR,
                    executor_git_sha=ACCEPTED_EXECUTOR_GIT_SHA, executor_identity=identity)
        with self.assertRaises(ValueError):
            MachinePowerShellAdapter(
                transport=self.transport, target="another-target", actor=ACTOR,
                executor_git_sha=ACCEPTED_EXECUTOR_GIT_SHA, executor_identity=EXECUTOR_IDENTITY)

    def test_unknown_after_lost_ack_reconcile_original_uuid_no_repeat(self):
        self.transport.lose_ack=True
        row=self.submit(self.payload())
        uncertain=self.decide(row)
        self.assertEqual(uncertain["state"],"UNCERTAIN")
        self.assertEqual(len(self.transport.calls),1)
        recovered=self.core.reconcile(row["requestId"])
        self.assertEqual(recovered["state"],"EXECUTED")
        self.assertEqual(len(self.transport.calls),1)

    def test_wrong_postflight_receipt_stays_unknown_not_success(self):
        row=self.submit(self.payload())
        self.transport.override_result={"requestId":row["requestId"],"state":"EXECUTED",
                                         "commandSha256":"0"*64,"exitCode":0,
                                         "stdout":"","stderr":""}
        self.assertEqual(self.decide(row)["state"],"UNCERTAIN")
        self.assertEqual(len(self.transport.calls),1)

    def test_same_uuid_different_command_conflicts(self):
        row=self.submit(self.payload())
        with self.assertRaises(Conflict):
            self.submit({**row["request"],"params":{"command":"Get-Location"}})
        self.assertEqual(len(self.transport.calls),0)

    def test_native_ingress_typed_route_is_ask_and_scoped(self):
        ingress=object.__new__(NativeIngress)
        ingress.broker=SimpleNamespace(core=self.core)
        ingress.actor=ACTOR
        p=self.payload()
        params={"requestId":p["requestId"],"target":TARGET,
                "command":p["params"]["command"]}
        caps=ingress._dispatch("/v1/powershell/capabilities",{},"repo-grant",ACTOR)
        self.assertEqual((caps["configured"],caps["policy"]), (True,"ASK"))
        result=ingress._dispatch("/v1/powershell/submit",params,"repo-grant",ACTOR)
        self.assertEqual(result["state"],"PENDING")
        self.assertEqual(self.transport.calls,[])
        read=ingress._dispatch("/v1/powershell/result",
                               {"requestId":p["requestId"]},"repo-grant",ACTOR)
        self.assertEqual(read["state"],"PENDING")
        with self.assertRaises(Denied):
            ingress._dispatch("/v1/powershell/result",
                              {"requestId":p["requestId"]},"foreign-grant","foreign-ai")
        with self.assertRaises(Denied):
            ingress._dispatch("/v1/powershell/submit",
                              {**params,"approved":True},"repo-grant",ACTOR)

    def test_r7_machine_opt_in_refuses_non_native_composition(self):
        from fortis_approvals.r7_unified_candidate import build_r7_unified_candidate
        with self.assertRaises(Denied):
            build_r7_unified_candidate(
                state=self.core.path.parent, owner_origin="http://localhost:19357",
                ingress_host="host.docker.internal:19358",
                ingress_grant="g"*40, sonar_transport=object(),
                organizations=("synthetic-org",), machine_shell=self.adapter,
                github_pilot=None)

    def test_machine_ingress_disabled_without_adapter(self):
        del self.core.adapters["powershell"]
        ingress=object.__new__(NativeIngress)
        ingress.broker=SimpleNamespace(core=self.core)
        ingress.actor=ACTOR
        caps=ingress._dispatch("/v1/powershell/capabilities",{},"repo-grant",ACTOR)
        self.assertEqual((caps["configured"],caps["policy"]), (False,"DENY"))
        with self.assertRaises(Denied):
            ingress._dispatch("/v1/powershell/submit",
                              {"requestId":str(uuid.uuid4()),"target":TARGET,"command":"Get-Date"},
                              "repo-grant",ACTOR)


if __name__ == "__main__":
    unittest.main()

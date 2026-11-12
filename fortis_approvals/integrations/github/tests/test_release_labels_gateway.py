"""UC-GW-011: closed GitHub Release Label REST boundary; no real credentials."""
import copy
import hashlib
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from fortis_approvals.core import Denied, Stale
from fortis_approvals.integrations.github.contract import (
    validate_github_action, validate_github_read, validate_github_read_projection)
from fortis_approvals.integrations.github.gateway.adapter import GitHubAdapter
from fortis_approvals.workflow.adapters import NativeGitHubAdapter
from fortis_approvals.integrations.github.gateway.transport import (
    GitHubHTTPTransport, GitHubTransportError)
from fortis_approvals.integrations.github.release_label_contract import names_hash

HEAD = "a"*40
BASE = "b"*40
BODY = "<!-- fortis-release-impact:start --> reviewed exact-head evidence"


def item(name):
    return {"name":name, "color":"aa9911", "description":None}


class FakeReleaseGitHub:
    def __init__(self):
        self.calls=[]
        self.head=HEAD
        self.base=BASE
        self.body=BODY
        self.state="open"
        self.draft=False
        self.head_repo="Alex/tunnel"
        self.head_ref="task/release-pilot"
        self.base_repo="Alex/tunnel"
        self.base_ref="main"
        self.merged=False
        self.issue_labels=["bug", "build:legacy", "release:review-required"]
        self.definitions=["bug", "build:legacy", "release:review-required",
                          "build:api", "release:image-rebuild", "release:no-deployment"]
        self.flip_sha_after_write=False
        self.lose_response=False

    def request(self,method,path,*,params=None,body=None,expected_statuses=(200,),
                allow_not_found=False):
        assert GitHubHTTPTransport._route_allowed(method,path), (method,path)
        self.calls.append((method,path,copy.deepcopy(body)))
        base="/repos/Alex/tunnel"
        assert path.startswith(base)
        suffix=path[len(base):]
        if method=="GET" and suffix=="/pulls/7":
            return {"number":7,"state":self.state,"draft":self.draft,
                    "merged":self.merged,"merged_at":None,"body":self.body,
                    "head":{"ref":self.head_ref,"sha":self.head,
                            "repo":{"full_name":self.head_repo}},
                    "base":{"ref":self.base_ref,"sha":self.base,
                            "repo":{"full_name":self.base_repo}}}
        if method=="GET" and suffix in ("/labels","/issues/7/labels"):
            source=self.definitions if suffix=="/labels" else self.issue_labels
            page=params["page"]
            count=params["per_page"]
            return [item(x) for x in source[(page-1)*count:page*count]]
        if method=="POST" and suffix=="/labels":
            assert body["name"] not in self.definitions
            self.definitions.append(body["name"])
            return {**body,"id":42}
        if method=="POST" and suffix=="/issues/7/labels":
            for name in body["labels"]:
                if name not in self.issue_labels:self.issue_labels.append(name)
            if self.flip_sha_after_write:self.head="c"*40
            if self.lose_response:raise GitHubTransportError("GITHUB_HTTP_LOST")
            return [item(x) for x in self.issue_labels]
        if method=="DELETE" and suffix.startswith("/issues/7/labels/"):
            from urllib.parse import unquote
            name=unquote(suffix.split("/")[-1])
            self.issue_labels.remove(name)
            if self.flip_sha_after_write:self.head="c"*40
            if self.lose_response:raise GitHubTransportError("GITHUB_HTTP_LOST")
            return [item(x) for x in self.issue_labels]
        raise AssertionError((method,suffix,body))


class NativeLabelHarness(NativeGitHubAdapter):
    def __init__(self,transport,store):
        GitHubAdapter.__init__(self,transport,owner="Alex",
                               repositories=("tunnel",),receipt_store=store)
        self.config=SimpleNamespace(dynamic_repositories=True,owner="Alex",
                                     repository="tunnel")
        self.task_calls=[]

    def _access(self,repo):
        if repo!="tunnel":raise Denied("GITHUB_REPOSITORY_NOT_ALLOWED")
        return repo

    def task_branch(self,repo,branch):
        if branch!="task/release-pilot":
            raise Denied("GIT_TASK_NOT_REGISTERED")
        self.task_calls.append(branch)


class ReleaseLabelGatewayTests(unittest.TestCase):
    def setUp(self):
        self.temporary=tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.upstream=FakeReleaseGitHub()
        store=Path(self.temporary.name)/"receipts.sqlite"
        self.adapter=GitHubAdapter(self.upstream,owner="Alex",
                                   repositories=("tunnel",),receipt_store=store)

    def params(self,**updates):
        fields=dict(number=7,expectedHeadSha=HEAD,expectedBaseSha=BASE,
                    expectedBodySha256=hashlib.sha256(BODY.encode()).hexdigest(),
                    expectedLabelsSha256=names_hash(self.upstream.issue_labels))
        fields.update(updates)
        return fields

    def action(self,operation,params,request_id=None):
        request=dict(service="github",operation=operation,target="tunnel",
                     params=params,requestId=request_id or ("a"*8+"-aaaa-4aaa-8aaa-aaaaaaaaaaaa"))
        validate_github_action(operation,"tunnel",params)
        return self.adapter.apply(request)

    def test_native_preflight_requires_registered_task_and_typed_policies(self):
        native=NativeLabelHarness(
            self.upstream,Path(self.temporary.name)/"native-receipts.sqlite")
        params={**self.params(),"labels":["build:api"]}
        req={"service":"github","operation":"add_pr_release_labels",
             "target":"tunnel","params":params,
             "requestId":"cccccccc-cccc-4ccc-8ccc-cccccccccccc"}
        preview=native.prepare(req)
        self.assertEqual(preview["headSha"],HEAD)
        self.assertEqual(native.task_calls,["task/release-pilot"])
        self.upstream.head_ref="task/unregistered"
        with self.assertRaisesRegex(Denied,"TASK_NOT_REGISTERED"):
            native.prepare(req)

    def test_read_repo_and_pr_labels_typed_and_redacted(self):
        for operation,params in [
            ("list_repository_labels",{"page":1,"perPage":50}),
            ("list_pr_labels",{"number":7,"page":1,"perPage":50})]:
            validate_github_read(operation,"tunnel",params)
            result=self.adapter.read(dict(service="github",operation=operation,
                                          target="tunnel",params=params))
            self.assertEqual(result["operation"],operation)
            self.assertTrue(all(set(row)=={"name","color","description"}
                                for row in result["items"]))
            validate_github_read_projection(operation,result)
            self.assertEqual("number" in result,operation=="list_pr_labels")

    def test_full_pr_label_context_includes_proofs_without_pr_body_or_token(self):
        data=self.adapter.read(dict(service="github",
            operation="get_pr_release_label_context",target="tunnel",
            params={"number":7}))
        validate_github_read_projection("get_pr_release_label_context",data)
        self.assertEqual(data["headSha"],HEAD)
        self.assertEqual(data["baseSha"],BASE)
        self.assertEqual(data["labelsSha256"],names_hash(self.upstream.issue_labels))
        self.assertEqual(data["bodySha256"],hashlib.sha256(BODY.encode()).hexdigest())
        self.assertNotIn("body",data)

    def test_bounded_impact_evidence_exposes_body_only_for_exact_open_pr(self):
        operation = "get_pr_release_impact_evidence"
        params = {"number":7, "expectedHeadSha": HEAD}
        validate_github_read(operation, "tunnel", params)
        before = len(self.upstream.calls)
        data = self.adapter.read(dict(service="github", operation=operation,
                                      target="tunnel", params=params))
        validate_github_read_projection(operation, data)
        self.assertEqual(data["body"], BODY)
        self.assertEqual(data["bodySha256"], hashlib.sha256(BODY.encode()).hexdigest())
        self.assertEqual((data["headSha"], data["baseSha"]), (HEAD, BASE))
        self.assertEqual((data["headRepository"], data["baseRepository"]),
                         ("Alex/tunnel", "Alex/tunnel"))
        self.assertEqual((data["headBranch"], data["baseBranch"]),
                         ("task/release-pilot", "main"))
        self.assertEqual([method for method, _, _ in self.upstream.calls[before:]],
                         ["GET"])

    def test_impact_evidence_rejects_stale_invalid_or_overbroad_request(self):
        operation = "get_pr_release_impact_evidence"
        for params in (
            {}, {"number":7}, {"number":7,"expectedHeadSha":BASE},
            {"number":True,"expectedHeadSha":HEAD},
            {"number":7,"expectedHeadSha":HEAD,"extra":True}):
            with self.subTest(params=params):
                if params == {"number":7,"expectedHeadSha":BASE}:
                    with self.assertRaises(Stale):
                        self.adapter.read(dict(service="github",operation=operation,
                                               target="tunnel",params=params))
                else:
                    with self.assertRaises(Denied):
                        validate_github_read(operation,"tunnel",params)

    def test_impact_evidence_rejects_untrusted_pr_provenance_or_body(self):
        operation = "get_pr_release_impact_evidence"
        params = {"number":7,"expectedHeadSha":HEAD}
        for attr, value in (
            ("draft", True), ("state", "closed"), ("merged", True),
            ("head_repo", "other/fork"), ("base_repo", "other/fork"),
            ("head_ref", "main"), ("base_ref", "develop"),
            ("body", None), ("body", ""), ("body", "z"*20001),
            ("body", "ю"*11000)):
            with self.subTest(attr=attr):
                original = getattr(self.upstream, attr)
                setattr(self.upstream, attr, value)
                try:
                    with self.assertRaises(Denied):
                        self.adapter.read(dict(service="github", operation=operation,
                                               target="tunnel", params=params))
                finally:
                    setattr(self.upstream, attr, original)

    def test_impact_evidence_projection_rejects_forged_body_or_metadata(self):
        operation = "get_pr_release_impact_evidence"
        good = self.adapter.read(dict(service="github", operation=operation,
                                      target="tunnel",
                                      params={"number":7,"expectedHeadSha":HEAD}))
        for changes in ({"body": "forged"},
                        {"bodySha256": "0"*64},
                        {"headRepository": "Other/tunnel"},
                        {"headBranch": "main"},
                        {"unexpected": True}):
            with self.subTest(changes=changes):
                altered = {**good, **changes}
                with self.assertRaises(Denied):
                    validate_github_read_projection(operation, altered)

    def test_add_is_incremental_and_preserves_nonmanaged_human_and_review_flag(self):
        params={**self.params(),"labels":["build:api","release:image-rebuild"]}
        result=self.action("add_pr_release_labels",params)
        self.assertTrue(result["changed"])
        self.assertEqual(result["headSha"],HEAD)
        self.assertTrue({"bug","build:legacy","release:review-required",
                         "build:api","release:image-rebuild"}<=set(result["labels"]))
        self.assertFalse(any(method=="PUT" for method,_,_ in self.upstream.calls))
        self.assertEqual(self.adapter.receipt(result["requestId"]),result)

    def test_add_existing_is_verified_noop(self):
        self.upstream.issue_labels.append("build:api")
        params={**self.params(),"labels":["build:api"]}
        result=self.action("add_pr_release_labels",params)
        self.assertFalse(result["changed"])
        self.assertFalse(any(method=="POST" for method,_,_ in self.upstream.calls))

    def test_remove_exact_managed_not_human(self):
        params={**self.params(),"name":"build:legacy"}
        result=self.action("remove_pr_release_label",params)
        self.assertTrue(result["changed"])
        self.assertEqual(set(result["labels"]),{"bug","release:review-required"})
        self.assertTrue(any(method=="DELETE" for method,_,_ in self.upstream.calls))

    def test_sticky_review_and_human_labels_immutable(self):
        for name in ["release:review-required","bug","release:unknown","admin:approved"]:
            with self.subTest(name=name),self.assertRaises(Denied):
                validate_github_action("remove_pr_release_label","tunnel",
                                       {**self.params(),"name":name})

    def test_unknown_or_malformed_generated_labels_denied(self):
        for value in ["release:deployed","build:Abc","build:"+"a"*45,
                      "release:approved","private:label",None]:
            with self.subTest(value=value),self.assertRaises(Denied):
                validate_github_action("add_pr_release_labels","tunnel",
                                       {**self.params(),"labels":[value]})

    def test_empty_and_oversized_add_batch_denied(self):
        for labels in [[],["build:api"]*2,["build:"+chr(97+i) for i in range(6)]]:
            with self.subTest(labels=labels),self.assertRaises(Denied):
                validate_github_action("add_pr_release_labels","tunnel",
                                       {**self.params(),"labels":labels})

    def test_create_label_server_controls_definition(self):
        result=self.action("create_release_label",{"name":"release:config-deploy"})
        self.assertTrue(result["created"])
        outgoing=[call for call in self.upstream.calls if call[0]=="POST"][-1][2]
        self.assertEqual(outgoing["name"],"release:config-deploy")
        self.assertEqual(outgoing["color"],"fbca04")
        self.assertIn("not installed",outgoing["description"])
        # Same request ID returns the durable receipt, not a duplicate write.
        same=self.action("create_release_label",{"name":"release:config-deploy"})
        self.assertEqual(same,result)
        with self.assertRaises(Denied):
            self.action("create_release_label",{"name":"release:config-deploy"},
                        request_id="bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb")

    def test_missing_repository_definition_fails_before_write(self):
        self.upstream.definitions.remove("build:api")
        with self.assertRaisesRegex(Denied,"MISSING_DEFINITION"):
            self.action("add_pr_release_labels",{**self.params(),"labels":["build:api"]})
        self.assertFalse(any(x[0]=="POST" for x in self.upstream.calls))

    def test_wrong_head_base_body_and_label_digest_denied_before_write(self):
        options=[
            {"expectedHeadSha":"c"*40}, {"expectedBaseSha":"c"*40},
            {"expectedBodySha256":"c"*64}, {"expectedLabelsSha256":"c"*64}]
        for update in options:
            with self.subTest(update=update),self.assertRaises(Stale):
                self.action("add_pr_release_labels",
                            {**self.params(),**update,"labels":["build:api"]})
        self.assertFalse(any(x[0]=="POST" for x in self.upstream.calls))

    def test_current_head_and_body_race_denied(self):
        params={**self.params(),"labels":["build:api"]}
        self.upstream.head="c"*40
        with self.assertRaises(Stale):self.action("add_pr_release_labels",params)
        self.upstream.head=HEAD;self.upstream.body="edited"
        with self.assertRaises(Stale):self.action("add_pr_release_labels",params)

    def test_draft_closed_or_fork_denied(self):
        for attr,value in [("draft",True),("state","closed"),("head_repo","Other/tunnel")]:
            with self.subTest(attr=attr):
                old=getattr(self.upstream,attr)
                setattr(self.upstream,attr,value)
                with self.assertRaises(Denied):
                    self.action("add_pr_release_labels",
                                {**self.params(),"labels":["build:api"]})
                setattr(self.upstream,attr,old)

    def test_stale_baseline_preserves_other_actors_labels(self):
        params={**self.params(),"labels":["build:api"]}
        self.upstream.issue_labels.append("human-changed")
        with self.assertRaises(Stale):self.action("add_pr_release_labels",params)
        self.assertIn("human-changed",self.upstream.issue_labels)

    def test_after_write_sha_race_is_unconfirmed_not_success(self):
        self.upstream.flip_sha_after_write=True
        with self.assertRaises(GitHubTransportError):
            self.action("add_pr_release_labels",
                        {**self.params(),"labels":["build:api"]})
        self.assertIn("build:api",self.upstream.issue_labels)
        self.assertIsNone(self.adapter.receipt("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"))

    def test_lost_http_ack_must_not_claim_not_executed(self):
        self.upstream.lose_response=True
        with self.assertRaises(GitHubTransportError):
            self.action("remove_pr_release_label",
                        {**self.params(),"name":"build:legacy"})
        self.assertNotIn("build:legacy",self.upstream.issue_labels)
        self.assertIsNone(self.adapter.receipt("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"))

    def test_transport_allowlist_no_generic_issue_or_full_replacement(self):
        allowed=[("GET","/repos/Alex/tunnel/labels"),
                 ("GET","/repos/Alex/tunnel/issues/7/labels"),
                 ("POST","/repos/Alex/tunnel/issues/7/labels"),
                 ("DELETE","/repos/Alex/tunnel/issues/7/labels/build%3Aapi")]
        denied=[("PUT","/repos/Alex/tunnel/issues/7/labels"),
                ("DELETE","/repos/Alex/tunnel/issues/7/labels/bug"),
                ("POST","/repos/Alex/tunnel/issues/7"),
                ("DELETE","/repos/Alex/tunnel/labels/build%3Aapi")]
        for method,url in allowed:self.assertTrue(GitHubHTTPTransport._route_allowed(method,url),(method,url))
        for method,url in denied:self.assertFalse(GitHubHTTPTransport._route_allowed(method,url),(method,url))

    def test_read_and_action_typing_reject_extra_fields(self):
        with self.assertRaises(Denied):
            validate_github_read("list_pr_labels","tunnel",
                                 {"number":7,"page":1,"perPage":50,"rawUrl":"/admin"})
        with self.assertRaises(Denied):
            validate_github_action("create_release_label","tunnel",
                                   {"name":"build:api","color":"ff0000"})
        with self.assertRaises(Denied):
            validate_github_action("add_pr_release_labels","tunnel",
                                   {**self.params(),"labels":["build:api"],"policy":"ALLOW"})


if __name__=="__main__":
    unittest.main()

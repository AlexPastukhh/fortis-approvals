"""Offline tests for the isolated GitHub integration and default-deny wiring."""
import json
import os
from pathlib import Path
import tempfile
import unittest

from fortis_approvals.core import Authenticator, Core, Denied
from fortis_approvals.integrations.github.contract import (
    GITHUB_ACTION_OPERATIONS, GITHUB_READ_OPERATIONS,
    validate_github_action, validate_github_read, validate_github_read_projection,
)
from fortis_approvals.integrations.github.gateway.adapter import GitHubAdapter
from fortis_approvals.integrations.github.gateway.transport import (
    GitHubHTTPTransport, GitHubTransportError,
)
from fortis_approvals.integrations.github.registration import register_github_integration
from fortis_approvals.integrations.github.repo_client.client import GitHubClient
from fortis_approvals.repo_action_contract import RepoIntentBroker, validate_intent, validate_read_query


SHA_A = "a" * 40
SHA_B = "b" * 40
SHA_C = "c" * 40


class FakeTransport:
    def __init__(self):
        self.calls = []
        self.head = SHA_A
        self.pr_body = "Original description"
        self.pr_state = "open"
    def request(self, method, path, *, params=None, body=None,
                expected_statuses=(200,), allow_not_found=False):
        self.calls.append((method, path, params, body))
        if path.endswith("/git/ref/heads/feature%2Ftest"):
            return {"object": {"sha": self.head}}
        if path.endswith("/git/commits/" + SHA_A):
            return {"tree": {"sha": SHA_B}}
        if path.endswith("/git/blobs"):
            return {"sha": SHA_B}
        if path.endswith("/git/trees"):
            return {"sha": SHA_B}
        if path.endswith("/git/commits") and method == "POST":
            return {"sha": SHA_C}
        if path.endswith("/git/refs/heads/feature%2Ftest") and method == "PATCH":
            self.head = body["sha"]
            return {"ref": "refs/heads/feature/test"}
        if path.endswith("/git/ref/heads/new-branch") and allow_not_found:
            return {"_httpStatus": 404}
        if path.endswith("/git/commits/" + SHA_A):
            return {"sha": SHA_A, "tree": {"sha": SHA_B}}
        if path.endswith("/repos/Alex/tunnel") and method == "GET":
            return {"name": "tunnel", "full_name": "Alex/tunnel",
                    "private": True, "default_branch": "main",
                    "archived": False, "disabled": False,
                    "html_url": "https://github.com/Alex/tunnel",
                    "pushed_at": "2026-11-05T00:00:00Z",
                    "token": "MUST_NOT_ESCAPE"}
        if path.endswith("/git/ref/heads/main"):
            return {"object": {"sha": SHA_A}}
        if path.endswith("/git/ref/heads/source"):
            return {"object": {"sha": SHA_A}}
        if path.endswith("/pulls") and method == "GET":
            return []
        if path.endswith("/pulls/1"):
            if method == "PATCH":
                assert set(body) == {"body"}
                self.pr_body = body["body"]
            return {"number": 1, "title": "T", "state": self.pr_state,
                    "draft": False, "merged": False, "body": self.pr_body,
                    "head": {"ref": "feature", "sha": SHA_A},
                    "base": {"ref": "main", "sha": SHA_B},
                    "html_url": "https://github.com/Alex/tunnel/pull/1"}
        if path.endswith("/actions/workflows/ci.yml"):
            return {"state": "active"}
        if path.endswith("/actions/runs/1"):
            return {"status": "completed", "run_attempt": 1, "head_sha": SHA_A}
        if path.endswith("/contents/.github/workflows/ci.yml"):
            return {"sha": SHA_B}
        if path.endswith("/git/ref/heads/feature%2Ftest") and allow_not_found:
            return {"_httpStatus": 404}
        raise AssertionError((method, path, params, body, expected_statuses, allow_not_found))


class ContractTests(unittest.TestCase):
    def test_typed_read_and_action_contracts(self):
        validate_github_read("get_repository", "tunnel", {})
        validate_github_read("list_pull_requests", "tunnel",
                             {"page": 1, "perPage": 30, "state": "open"})
        validate_github_action("create_branch", "tunnel",
                               {"branch": "feature/new", "sourceSha": SHA_A})
        with self.assertRaises(Denied):
            validate_github_read("get_repository", "tunnel", {"url": "https://evil"})
        with self.assertRaises(Denied):
            validate_github_action("delete_repository", "tunnel", {})
        with self.assertRaises(Denied):
            validate_github_read([], "tunnel", {})
        with self.assertRaises(Denied):
            validate_github_action([], "tunnel", {})
        with self.assertRaisesRegex(Denied, "GITHUB_FILE_CONTENT_INVALID"):
            validate_github_action("push_files", "tunnel", {
                "branch": "feature/work", "expectedHeadSha": SHA_A,
                "message": "update", "files": [{"path": "a.txt", "content": "\ud800"}],
            })
        with self.assertRaisesRegex(Denied, "GITHUB_FILE_PATH_DENIED"):
            validate_github_action("push_files", "tunnel", {
                "branch": "feature/work", "expectedHeadSha": SHA_A,
                "message": "x", "files": [{"path": "../escape", "content": "x"}],
            })

    def test_update_pr_description_schema_only(self):
        valid = {"number": 1, "expectedHeadSha": SHA_A, "body": "Safe description"}
        validate_github_action("update_pull_request", "tunnel", valid)
        for bad in (
                {**valid, "base": "other"}, {**valid, "title": "Change"},
                {**valid, "merge": True}, {**valid, "number": True},
                {**valid, "number": 0}, {**valid, "expectedHeadSha": SHA_B.upper()},
                {**valid, "body": None}, {**valid, "body": "x" * 20_001},
                {**valid, "body": chr(0xD800)}):
            with self.subTest(bad=str(bad)[:45]), self.assertRaises(Denied):
                validate_github_action("update_pull_request", "tunnel", bad)

    def test_github_action_envelope_respects_ingress_body_cap(self):
        body = {"requestId": "00000000-0000-4000-8000-000000000001",
                "service": "github", "operation": "push_files", "target": "tunnel",
                "params": {"branch": "feature/test", "expectedHeadSha": SHA_A,
                           "message": "update", "files": [
                               {"path": "a.txt", "content": "\U0001F642" * 16000},
                               {"path": "b.txt", "content": "\U0001F642" * 16000},
                               {"path": "c.txt", "content": "\U0001F642" * 16000}]},
                "reason": "review"}
        with self.assertRaisesRegex(Denied, "GITHUB_REQUEST_TOO_LARGE_FOR_INGRESS"):
            validate_intent(body)

    def test_read_contract_is_not_action_contract(self):
        body = {"requestId": "00000000-0000-4000-8000-000000000002",
                "service": "github", "operation": "get_repository",
                "target": "tunnel", "params": {}, "reason": "read"}
        validate_read_query(body)
        with self.assertRaises(Denied):
            validate_intent(body)

    def test_public_projection_rejects_type_confusion_and_extra_fields(self):
        valid = {"operation": "get_repository", "repository": {
            "name": "tunnel", "full_name": "Alex/tunnel", "private": True,
            "default_branch": "main", "archived": False, "disabled": False,
            "html_url": "https://github.com/Alex/tunnel",
            "pushed_at": "2026-11-05T00:00:00Z"}}
        validate_github_read_projection("get_repository", valid)
        malformed = {**valid, "repository": {**valid["repository"], "private": "false"}}
        with self.assertRaises(Denied):
            validate_github_read_projection("get_repository", malformed)
        with self.assertRaises(Denied):
            validate_github_read_projection("get_repository",
                                            {**valid, "token": "must-not-escape"})
        checks = {"operation": "list_check_runs", "totalCount": 1, "items": [{
            "id": 7, "name": "ci", "status": "completed", "conclusion": "success",
            "headSha": SHA_A, "startedAt": None, "completedAt": "2026-11-05T00:00:00Z",
            "url": "https://ci.example.test/build/7"}]}
        validate_github_read_projection("list_check_runs", checks)
        checks["items"][0]["url"] = "http://ci.example.test/build/7"
        with self.assertRaises(Denied):
            validate_github_read_projection("list_check_runs", checks)


class AdapterTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="github-adapter-")
        self.addCleanup(self.tmp.cleanup)
        self.transport = FakeTransport()
        self.adapter = GitHubAdapter(
            self.transport, owner="Alex", repositories=("tunnel", "fortis-approvals"),
            receipt_store=str(Path(self.tmp.name) / "receipts.sqlite"),
        )
    def test_repository_read_is_projected_and_allowlisted(self):
        request = {"service": "github", "operation": "get_repository",
                   "target": "tunnel", "params": {}}
        result = self.adapter.read(request)
        self.assertEqual(result["repository"]["name"], "tunnel")
        self.assertNotIn("token", json.dumps(result))
        with self.assertRaisesRegex(Denied, "GITHUB_REPOSITORY_NOT_ALLOWLISTED"):
            self.adapter.read({**request, "target": "not-selected"})

    def test_push_is_compare_and_swap_and_receipted(self):
        request = {
            "requestId": "00000000-0000-4000-8000-000000000003",
            "service": "github", "operation": "push_files", "target": "tunnel",
            "expectedVersion": 0, "reason": "push",
            "params": {"branch": "feature/test", "expectedHeadSha": SHA_A,
                       "message": "small change",
                       "files": [{"path": "notes.txt", "content": "hello"}]},
        }
        preview = self.adapter.prepare(request)
        self.assertEqual(preview["headSha"], SHA_A)
        result = self.adapter.apply(request)
        self.assertEqual(result["sha"], SHA_C)
        self.assertTrue(self.adapter.confirm(request["requestId"], result))
        self.assertEqual(self.adapter.receipt(request["requestId"]), result)
        methods = [(m, p) for m, p, _q, _b in self.transport.calls]
        self.assertIn(("PATCH", "/repos/Alex/tunnel/git/refs/heads/feature%2Ftest"), methods)
        patch = next(x for x in self.transport.calls if x[0] == "PATCH")
        self.assertIs(patch[3]["force"], False)

    def test_update_pr_body_is_bound_to_exact_head_and_receipted(self):
        request = {
            "requestId": "00000000-0000-4000-8000-000000000081",
            "service": "github", "operation": "update_pull_request", "target": "tunnel",
            "params": {"number": 1, "expectedHeadSha": SHA_A,
                       "body": "Updated exact description"},
        }
        preview = self.adapter.prepare(request)
        self.assertEqual(preview["number"], 1)
        self.assertNotIn("Original description", str(preview))
        result = self.adapter.apply(request)
        self.assertEqual(result["bodySha256"], preview["nextBodySha256"])
        self.assertEqual(self.transport.pr_body, "Updated exact description")
        self.assertEqual(self.adapter.apply(request), result)
        self.assertEqual(sum(1 for method, path, _, _ in self.transport.calls
                             if method == "PATCH" and path.endswith("/pulls/1")), 1)
        self.assertTrue(self.adapter.confirm(request["requestId"], result))

        stale = {**request, "requestId": "00000000-0000-4000-8000-000000000082"}
        self.transport.pr_body = "External owner edit"
        # External edit is observed in the preview; applying the exact request
        # requires a fresh owner decision, never silently retrying a past UUID.
        self.assertNotEqual(self.adapter.prepare(stale)["currentBodySha256"],
                            preview["currentBodySha256"])
        self.transport.pr_state = "closed"
        with self.assertRaisesRegex(Denied, "GITHUB_PR_NOT_EDITABLE"):
            self.adapter.prepare(stale)
        self.transport.pr_state = "open"
        stale["params"] = {**stale["params"], "expectedHeadSha": SHA_C}
        with self.assertRaisesRegex(Exception, "GITHUB_PR_HEAD_CHANGED"):
            self.adapter.prepare(stale)

    def test_protected_branch_is_never_push_target(self):
        request = {"service": "github", "operation": "push_files",
                   "target": "tunnel", "expectedVersion": 0,
                   "params": {"branch": "main", "expectedHeadSha": SHA_A,
                              "message": "x", "files": [{"path": "x", "content": "x"}]}}
        with self.assertRaisesRegex(Denied, "GITHUB_PROTECTED_BRANCH_DENIED"):
            self.adapter.prepare(request)

    def test_direct_adapter_calls_revalidate_untrusted_shapes(self):
        with self.assertRaises(Denied):
            self.adapter.read({"service": "github", "operation": "get_repository",
                               "target": ["tunnel"], "params": {}})
        with self.assertRaises(Denied):
            self.adapter.prepare({"service": "github", "operation": "push_files",
                                  "target": "tunnel", "params": None})

    def test_pull_projection_requires_typed_fields_and_https_github_url(self):
        row = {"number": 1, "title": "T", "state": "open", "draft": False,
               "merged": False, "head": {"ref": "feature", "sha": SHA_A},
               "base": {"ref": "main", "sha": SHA_B},
               "html_url": "https://github.com/Alex/tunnel/pull/1"}
        projected = self.adapter._project_pull(row)
        self.assertEqual(projected["number"], 1)
        row["html_url"] = "https://github.com.attacker.invalid/Alex/tunnel/pull/1"
        with self.assertRaises(Denied):
            self.adapter._project_pull(row)


class RegistrationTests(unittest.TestCase):
    def test_register_does_not_grant_any_github_operation_or_policy(self):
        tmp = tempfile.TemporaryDirectory(prefix="github-registration-")
        self.addCleanup(tmp.cleanup)
        core = Core(Path(tmp.name) / "core.sqlite", adapters={}, policies={},
                    authenticator=Authenticator({"machine-grant-000000000000000000000000": "agent"}))
        broker = RepoIntentBroker(
            core, actor_operations={"agent": {("synthetic", "set_free")}},
            actor_read_operations={"agent": {("sonarcloud", "list_projects")}},
        )
        adapter = GitHubAdapter(FakeTransport(), owner="Alex",
                                repositories=("tunnel",),
                                receipt_store=str(Path(tmp.name) / "github.sqlite"))
        status = register_github_integration(core=core, broker=broker, adapter=adapter)
        self.assertFalse(status["policy_configured"])
        self.assertFalse(status["actor_grants_configured"])
        self.assertNotIn(("agent", "github", "get_repository"), core.policies)
        self.assertNotIn(("github", "get_repository"), broker.actor_read_operations["agent"])
        self.assertNotIn(("github", "push_files"), broker.actor_operations["agent"])
        with self.assertRaises(Denied):
            broker.authorize_read("machine-grant-000000000000000000000000", {
                "requestId": "00000000-0000-4000-8000-000000000004",
                "service": "github", "operation": "get_repository",
                "target": "tunnel", "params": {}, "reason": "read"})
        with self.assertRaises(Denied):
            broker.submit("machine-grant-000000000000000000000000", {
                "requestId": "00000000-0000-4000-8000-000000000005",
                "service": "github", "operation": "create_branch",
                "target": "tunnel",
                "params": {"branch": "feature/new", "sourceSha": SHA_A},
                "reason": "create"})
class TokenFileTests(unittest.TestCase):
    def test_token_file_requires_regular_private_file(self):
        tmp = tempfile.TemporaryDirectory(prefix="github-token-")
        self.addCleanup(tmp.cleanup)
        path = Path(tmp.name) / "token"
        token = "github_pat_" + "x" * 60
        path.write_bytes((token + "\r\n").encode("ascii"))
        path.chmod(0o600)
        transport = GitHubHTTPTransport.from_file(
            str(path), expected_uid=os.geteuid())
        self.assertIsInstance(transport, GitHubHTTPTransport)
        path.chmod(0o644)
        with self.assertRaises(Denied):
            GitHubHTTPTransport.from_file(str(path), expected_uid=os.geteuid())
        path.chmod(0o600)
        link = Path(tmp.name) / "token-link"
        link.symlink_to(path)
        with self.assertRaises(Denied):
            GitHubHTTPTransport.from_file(str(link), expected_uid=os.geteuid())
class _Response:
    status = 200
    def __init__(self, body):
        self.body = body
    def __enter__(self):
        return self
    def __exit__(self, *args):
        return False
    def read(self, limit):
        return self.body[:limit]


class _Opener:
    def __init__(self, body=b'{"name":"tunnel"}'):
        self.body = body
        self.request = None
    def open(self, outgoing, timeout):
        self.request = outgoing
        return _Response(self.body)


class TransportTests(unittest.TestCase):
    def test_origin_route_and_secret_header_are_pinned(self):
        opener = _Opener()
        token = "github_pat_" + "x" * 60
        transport = GitHubHTTPTransport(token, opener=opener)
        result = transport.request("GET", "/repos/Alex/tunnel")
        self.assertEqual(result, {"name": "tunnel"})
        self.assertEqual(opener.request.full_url, "https://api.github.com/repos/Alex/tunnel")
        self.assertEqual(opener.request.get_header("Authorization"), "Bearer " + token)
        self.assertEqual(opener.request.get_header("X-github-api-version"), "2022-11-28")
        with self.assertRaisesRegex(Denied, "GITHUB_HTTP_ROUTE_DENIED"):
            transport.request("GET", "https://attacker.invalid/steal")
        with self.assertRaisesRegex(Denied, "GITHUB_HTTP_ROUTE_DENIED"):
            transport.request("GET", ["/repos/Alex/tunnel"])
        with self.assertRaisesRegex(Denied, "GITHUB_JSON_BODY_INVALID"):
            transport.request("POST", "/repos/Alex/tunnel/git/blobs",
                              body={"content": float("nan")})
    def test_cleanup_evidence_uses_exact_sha_get_routes_on_pinned_origin(self):
        opener=_Opener(b'{"status":"identical"}')
        transport=GitHubHTTPTransport('github_pat_'+'x'*60,opener=opener)
        head='a'*40;main='b'*40
        for suffix in ('compare/'+head+'...'+main,'commits/'+head+'/pulls'):
            path='/repos/Alex/sandbox/'+suffix
            self.assertEqual(transport.request('GET',path,params={'per_page':1}),{'status':'identical'})
            self.assertEqual(opener.request.full_url,'https://api.github.com'+path+'?per_page=1')
            self.assertEqual(opener.request.get_method(),'GET')

    def test_cleanup_evidence_does_not_open_generic_compare_or_mutation_routes(self):
        transport=GitHubHTTPTransport('github_pat_'+'x'*60,opener=_Opener())
        head='a'*40;main='b'*40;base='/repos/Alex/sandbox/'
        denied=('compare/main...task/name','compare/'+head+'...main',
                'compare/'+head+'..'+main,'compare/'+head+'...'+main+'/extra',
                'commits/main/pulls','commits/'+head+'/pulls/extra')
        for suffix in denied:
            with self.subTest(suffix=suffix),self.assertRaisesRegex(Denied,'GITHUB_HTTP_ROUTE_DENIED'):
                transport.request('GET',base+suffix)
        for method in ('POST','PATCH','PUT','DELETE'):
            for suffix in ('compare/'+head+'...'+main,'commits/'+head+'/pulls'):
                with self.subTest(method=method,suffix=suffix),self.assertRaisesRegex(Denied,'GITHUB_HTTP_ROUTE_DENIED'):
                    transport.request(method,base+suffix)

    def test_nonfinite_json_response_is_rejected(self):
        token = "github_pat_" + "z" * 60
        transport = GitHubHTTPTransport(token, opener=_Opener(b'{"value":NaN}'))
        with self.assertRaisesRegex(
                GitHubTransportError, "GITHUB_UPSTREAM_UNAVAILABLE_OR_INVALID"):
            transport.request("GET", "/repos/Alex/tunnel")

    def test_mark_ready_has_one_fixed_graphql_mutation_and_no_generic_proxy(self):
        node='PR_fixture_node'
        opener=_Opener(json.dumps({'data':{'markPullRequestReadyForReview':{'pullRequest':{'id':node,'isDraft':False}}}}).encode())
        transport=GitHubHTTPTransport('github_pat_'+'x'*60,opener=opener)
        transport.mark_ready(node)
        self.assertEqual(opener.request.full_url,'https://api.github.com/graphql')
        body=json.loads(opener.request.data)
        self.assertEqual(body['variables'],{'id':node})
        self.assertIn('markPullRequestReadyForReview(input:{pullRequestId:$id})',body['query'])
        with self.assertRaises(Denied):transport.request('POST','/graphql',body={'query':'anything'})
        with self.assertRaises(Denied):transport.mark_ready('node"; arbitrary query')
        bad=_Opener(b'{"data":{"markPullRequestReadyForReview":{"pullRequest":{"id":"wrong","isDraft":false}}}}')
        with self.assertRaises(GitHubTransportError):
            GitHubHTTPTransport('github_pat_'+'x'*60,opener=bad).mark_ready(node)

    def test_redirect_is_not_followed_and_error_is_redacted(self):
        from urllib.error import HTTPError
        class RedirectOpener:
            def open(self, outgoing, timeout):
                raise HTTPError(outgoing.full_url, 302, "redirect",
                                {"Location": "https://attacker.invalid"}, None)
        token = "github_pat_" + "y" * 60
        transport = GitHubHTTPTransport(token, opener=RedirectOpener())
        with self.assertRaisesRegex(GitHubTransportError, "GITHUB_REDIRECT_DENIED") as caught:
            transport.request("GET", "/repos/Alex/tunnel")
        self.assertNotIn(token, str(caught.exception))
class FakeGateway:
    def __init__(self):
        self.calls = []
    def post(self, path, body, accept_202=False):
        self.calls.append((path, body, accept_202))
        if path == "/v1/reads":
            data = {"operation": "get_repository", "repository": {
                "name": "tunnel", "full_name": "Alex/tunnel", "private": True,
                "default_branch": "main", "archived": False, "disabled": False,
                "html_url": "https://github.com/Alex/tunnel",
                "pushed_at": "2026-11-05T00:00:00Z"}}
            return {"requestId": body["requestId"], "service": "github",
                    "operation": body["operation"], "data": data}
        return {"requestId": body["requestId"], "state": "PENDING"}
    def get_status(self, request_id):
        return {"requestId": request_id, "state": "EXECUTED"}


class RepoClientTests(unittest.TestCase):
    def test_typed_read_action_and_status_use_only_gateway_contract(self):
        gateway = FakeGateway()
        client = GitHubClient(gateway=gateway)
        repository = client.get_repository("tunnel")
        self.assertEqual(repository["repository"]["name"], "tunnel")
        request_id = "00000000-0000-4000-8000-000000000010"
        result = client.create_branch("tunnel", "feature/new", SHA_A,
                                      request_id=request_id, reason="prepare feature branch")
        self.assertEqual(result, {"requestId": request_id, "state": "PENDING"})
        self.assertEqual(client.status(request_id)["state"], "EXECUTED")
        self.assertEqual(gateway.calls[0][0], "/v1/reads")
        self.assertEqual(gateway.calls[1][0], "/v1/actions")
        self.assertTrue(gateway.calls[1][2])
        self.assertNotIn("token", vars(client))

    def test_mutations_require_caller_supplied_stable_request_id(self):
        gateway = FakeGateway()
        client = GitHubClient(gateway=gateway)
        with self.assertRaisesRegex(Denied, "GITHUB_STABLE_REQUEST_ID_REQUIRED"):
            client.create_branch("tunnel", "feature/new", SHA_A,
                                 request_id=None, reason="create")
        self.assertEqual(gateway.calls, [])

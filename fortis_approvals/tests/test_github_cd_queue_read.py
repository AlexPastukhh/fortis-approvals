"""P4 source-only typed GitHub Deployments READ: strict scope, no WRITE."""
from copy import deepcopy
from pathlib import Path
import re
import tempfile
import unittest

from fortis_approvals.core import Denied
from fortis_approvals.integrations.github.contract import (
    DEPLOYMENT_READ_OPERATIONS, LEGACY_READ_OPERATIONS, GITHUB_ACTION_OPERATIONS,
    validate_github_read, validate_github_read_projection,
)
from fortis_approvals.integrations.github.repo_client.client import GitHubClient
from fortis_approvals.integrations.github.gateway.adapter import GitHubAdapter
from fortis_approvals.integrations.github.gateway.transport import GitHubHTTPTransport

OWNER = "PilotOwner"
REPO = "sandbox"
SHA = "a" * 40
ENV = "fortis-cd/api/production"
BASE = "/repos/PilotOwner/sandbox"


def deployment(number=12):
    return dict(
        id=number,
        url="https://api.github.com" + BASE + "/deployments/" + str(number),
        repository_url="https://api.github.com" + BASE,
        sha=SHA, ref=SHA, task="fortis-cd-projection", environment=ENV,
        created_at="2026-11-19T00:00:00Z", updated_at="2026-11-19T00:01:00Z",
        payload=dict(
            schemaVersion=1, kind="fortis-cd-projection",
            repository="PilotOwner/sandbox", target="api", environment="production",
            desiredSourceSha=SHA, catalogSha="b" * 40,
            buildUnit="feedbrain-app-image", artifactDigest=None,
            actions=["image-rebuild"], linkedPRs=[1, 2],
            projectionId="d" * 64,
            operationId="00000000-0000-4000-8000-000000000001",
        ),
    )


def status(number=34, deployment_id=12, state="queued"):
    return dict(
        id=number, state=state,
        url="https://api.github.com" + BASE + "/deployments/" +
            str(deployment_id) + "/statuses/" + str(number),
        deployment_url="https://api.github.com" + BASE + "/deployments/" +
            str(deployment_id),
        repository_url="https://api.github.com" + BASE,
        environment=ENV, created_at="2026-11-19T00:01:00Z",
        updated_at="2026-11-19T00:02:00Z",
        description="Planned; not an actual install", log_url="",
    )


class FakeReadTransport:
    def __init__(self):
        self.calls = []
        self.items = [deployment()]
        self.statuses = [status()]

    def request(self, method, path, *, params=None, body=None,
                expected_statuses=(200,), allow_not_found=False):
        self.calls.append((method, path, params, body))
        if method != "GET" or body is not None:
            raise AssertionError("READ must not write")
        if path == BASE + "/deployments":
            if params is None or params.get("task") != "fortis-cd-projection":
                raise AssertionError("Unbounded deployments query")
            rows = [x for x in self.items
                    if (not params.get("sha") or x["sha"] == params["sha"]) and
                    (not params.get("environment") or x["environment"] == params["environment"])]
            start = (params["page"] - 1) * params["per_page"]
            return deepcopy(rows[start:start + params["per_page"]])
        if path.startswith(BASE + "/deployments/"):
            suffix = path[len(BASE + "/deployments/"):]
            match = re.fullmatch(r"([1-9][0-9]*)(?:/statuses(?:/([1-9][0-9]*))?)?", suffix)
            if match is None:
                raise AssertionError(("unexpected path", path))
            ident=int(match.group(1))
            if match.group(2) is not None:
                return deepcopy(next(x for x in self.statuses
                                     if x["id"] == int(match.group(2))))
            if suffix.endswith("/statuses"):
                rows=[x for x in self.statuses if x["deployment_url"].endswith("/deployments/"+str(ident))]
                start = (params["page"] - 1) * params["per_page"]
                return deepcopy(rows[start:start + params["per_page"]])
            return deepcopy(next(x for x in self.items if x["id"] == ident))
        raise AssertionError(("unexpected path", path))


class DeploymentReadTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.transport = FakeReadTransport()
        self.adapter = GitHubAdapter(self.transport, owner=OWNER,
            repositories=(REPO,), receipt_store=Path(tmp.name) / "receipt.sqlite")

    def read(self, operation, params, repo=REPO):
        return self.adapter.read(dict(service="github", operation=operation,
                                      target=repo, params=params))

    def client(self):
        adapter=self.adapter
        class Broker:
            def post(self, path, request):
                if path != "/v1/reads":
                    raise AssertionError("Client must use typed READ route")
                data=adapter.read(request)
                return dict(requestId=request["requestId"], service="github",
                            operation=request["operation"], data=data)
        return GitHubClient(gateway=Broker())

    def test_closed_read_surface_no_inherited_grants_or_deployment_write(self):
        self.assertTrue(DEPLOYMENT_READ_OPERATIONS)
        self.assertFalse(DEPLOYMENT_READ_OPERATIONS & LEGACY_READ_OPERATIONS)
        self.assertNotIn(("github", "create_cd_projection"), GITHUB_ACTION_OPERATIONS)
        self.assertNotIn(("github", "append_cd_status"), GITHUB_ACTION_OPERATIONS)
        for path in (BASE + "/deployments",
                     BASE + "/deployments/12/statuses"):
            self.assertTrue(GitHubHTTPTransport._route_allowed("GET", path))
            self.assertFalse(GitHubHTTPTransport._route_allowed("POST", path))
        self.assertFalse(GitHubHTTPTransport._route_allowed(
            "GET", BASE + "/deployments/12/statuses/34/something"))

    def test_list_get_and_status_projection(self):
        query=dict(page=1, perPage=30, sha=SHA, environment=ENV)
        page=self.read("list_deployments", query)
        self.assertEqual([x["id"] for x in page["items"]], [12])
        self.assertFalse(page["hasNextPage"])
        self.assertEqual(page["evidenceClass"], "GITHUB_PROJECTION_ONLY")
        self.assertEqual(self.transport.calls[0][2]["task"], "fortis-cd-projection")
        item=self.read("get_deployment", dict(deploymentId=12))
        self.assertEqual(item["deployment"]["payload"]["linkedPRs"], [1, 2])
        statuses=self.read("list_deployment_statuses",
                           dict(deploymentId=12,page=1,perPage=30))
        self.assertEqual([x["state"] for x in statuses["items"]], ["queued"])
        single=self.read("get_deployment_status",
                         dict(deploymentId=12,statusId=34))
        self.assertEqual(single["status"]["deploymentId"], 12)
        self.assertTrue(all(call[0]=="GET" and call[3] is None
                            for call in self.transport.calls))

    def test_client_closed_broker_read_and_response(self):
        c=self.client()
        self.assertEqual(c.list_deployments(REPO)["items"][0]["id"],12)
        self.assertEqual(c.get_deployment(REPO,12)["deployment"]["sha"],SHA)
        self.assertEqual(c.list_deployment_statuses(REPO,12)["items"][0]["state"],"queued")
        self.assertEqual(c.get_deployment_status(REPO,12,34)["status"]["id"],34)
        with self.assertRaises(Denied):
            c.list_deployments(REPO, environment="../../secrets")
        with self.assertRaises(Denied):
            c.get_deployment_status(REPO,12,False)

    def test_inventory_only_github_projection_never_actual_install(self):
        c=self.client()
        for github_status in ("queued", "in_progress", "success", "failure"):
            self.transport.statuses=[status(state=github_status)]
            result=c.list_cd_projection_inventory(REPO,"api","production")
            self.assertEqual(result["evidenceClass"],"GITHUB_PROJECTION_ONLY")
            self.assertTrue(result["paginationComplete"])
            self.assertFalse(result["atomicSnapshot"])
            self.assertEqual(result["actualState"],"UNKNOWN")
            self.assertIsNone(result["actualInstalledVersion"])
            self.assertEqual(result["items"][0]["observedGitHubStatuses"],[github_status])
            self.assertEqual(result["items"][0]["fortisState"],"UNKNOWN")
            self.assertEqual(result["items"][0]["linkedPRsClaimed"],[1,2])
            self.assertEqual(result["items"][0]["buildUnitClaimed"],"feedbrain-app-image")
            self.assertIsNone(result["items"][0]["actualInstalledVersion"])
        self.assertTrue(all(call[0]=="GET" and call[3] is None
                            for call in self.transport.calls))

    def test_inventory_empty_does_not_prove_installed_absence(self):
        self.transport.items=[]
        result=self.client().list_cd_projection_inventory(REPO,"api","production")
        self.assertEqual(result["items"],[])
        self.assertTrue(result["paginationComplete"])
        self.assertEqual(result["actualState"],"UNKNOWN")

    def test_inventory_paginates_cross_pages_and_rechecks(self):
        self.transport.items=[deployment(12),deployment(13)]
        self.transport.items[1]["payload"]["projectionId"]="e"*64
        self.transport.statuses=[status(34,12),status(35,13,state="success")]
        result=self.client().list_cd_projection_inventory(REPO,"api","production",per_page=1)
        self.assertEqual([x["deploymentId"] for x in result["items"]],[12,13])
        self.assertEqual([x["observedGitHubStatuses"] for x in result["items"]],[["queued"],["success"]])
        self.assertTrue(result["paginationComplete"])
        self.assertEqual(result["actualState"],"UNKNOWN")

    def test_inventory_rejects_budgets_scope_and_duplicate_identity(self):
        c=self.client()
        for kwargs in (
            dict(target="../api",environment="production"),
            dict(target="api",environment="bad/environment"),
            dict(target="api",environment="production",per_page=11),
            dict(target="api",environment="production",max_pages=0),
            dict(target="api",environment="production",max_status_pages=4),
        ):
            with self.assertRaisesRegex(Denied,"GITHUB_CD_INVENTORY_SCOPE_DENIED"):
                c.list_cd_projection_inventory(REPO,**kwargs)
        self.transport.items=[deployment(12),deployment(13)]
        with self.assertRaisesRegex(Denied,"GITHUB_CD_INVENTORY_LIMIT_UNKNOWN"):
            c.list_cd_projection_inventory(REPO,"api","production",per_page=1,max_pages=1)
        self.transport.items=[deployment(12),deployment(12)]
        with self.assertRaises(Denied):
            c.list_cd_projection_inventory(REPO,"api","production",per_page=1)
        self.transport.items=[deployment(12),deployment(13)]
        with self.assertRaisesRegex(Denied,"GITHUB_CD_INVENTORY_REPEATED_PROJECTION_UNKNOWN"):
            c.list_cd_projection_inventory(REPO,"api","production",per_page=1)

    def test_inventory_status_page_exhaustion_is_unknown_not_partial_success(self):
        self.transport.statuses=[status(34),status(35),status(36),status(37)]
        with self.assertRaisesRegex(Denied,"GITHUB_CD_INVENTORY_LIMIT_UNKNOWN"):
            self.client().list_cd_projection_inventory(REPO,"api","production",
                                                    per_page=1,max_status_pages=2)

    def test_inventory_race_and_changed_detail_fail_closed(self):
        c=self.client()
        request=self.transport.request
        counter=[0]
        def race(method,path,**kwargs):
            if method=="GET" and path==BASE+"/deployments":
                counter[0]+=1
                if counter[0]==2:
                    self.transport.items.insert(0,deployment(13))
                    self.transport.items[0]["payload"]["projectionId"]="e"*64
            return request(method,path,**kwargs)
        self.transport.request=race
        with self.assertRaisesRegex(Denied,"GITHUB_CD_INVENTORY_RACE_UNKNOWN"):
            c.list_cd_projection_inventory(REPO,"api","production",per_page=10)
        self.transport.request=request
        self.transport.items=[deployment()]
        counter=[0]
        def change_detail(method,path,**kwargs):
            if method=="GET" and path==BASE+"/deployments/12":
                counter[0]+=1
                if counter[0]==1:
                    self.transport.items[0]["payload"]["projectionId"]="e"*64
            return request(method,path,**kwargs)
        self.transport.request=change_detail
        with self.assertRaisesRegex(Denied,"GITHUB_CD_INVENTORY_DEPLOYMENT_CHANGED"):
            c.list_cd_projection_inventory(REPO,"api","production")

    def test_empty_page_not_proof_of_not_deployed(self):
        self.transport.items=[]
        query=dict(page=1,perPage=30,sha=SHA,environment=ENV)
        result=self.read("list_deployments",query)
        self.assertEqual(result["items"],[])
        self.assertEqual(result["evidenceClass"],"GITHUB_PROJECTION_ONLY")

    def test_pagination_and_ids_are_bounded(self):
        self.transport.items=[deployment(12)]*30+[deployment(13)]
        # Duplicate IDs in a page are ambiguous, not a valid completed inventory.
        with self.assertRaisesRegex(Denied,"GITHUB_READ_PROJECTION_DENIED"):
            self.read("list_deployments",
                      dict(page=1,perPage=30,sha=None,environment=None))
        # The adapter must reject a provider with too many rows for the requested page.
        self.transport.items=[deployment(i) for i in range(1,33)]
        with self.assertRaises(Denied):
            self.read("list_deployments",dict(page=1,perPage=31,sha=None,environment=None))
        for params in (
            dict(page=1,perPage=30,sha="main",environment=None),
            dict(page=1,perPage=30,sha=None,environment="../production"),
            dict(page=0,perPage=30,sha=None,environment=None),
            dict(page=1,perPage=30,sha=None,environment=None,task="deploy"),
            dict(page=True,perPage=30,sha=None,environment=None),
        ):
            with self.assertRaises(Denied):
                validate_github_read("list_deployments",REPO,params)

    def test_reject_foreign_or_changed_payload_before_status_read(self):
        for key,value in (
            ("task","deploy"),("environment","fortis-cd/worker/production"),
            ("sha","e"*40),
        ):
            self.transport.items=[deployment()]
            self.transport.items[0][key]=value
            with self.assertRaises(Denied):
                self.read("get_deployment", dict(deploymentId=12))
        for key,value in (
            ("repository","WrongOwner/sandbox"),
            ("desiredSourceSha","e"*40),
            ("schemaVersion",2),
            ("environment","../production"),
            ("linkedPRs",[1, 1]),
        ):
            self.transport.items=[deployment()]
            self.transport.items[0]["payload"][key]=value
            with self.assertRaises(Denied):
                self.read("get_deployment", dict(deploymentId=12))

    def test_status_binding_and_unknown_states_fail_closed(self):
        for key,value in (
            ("environment","production"),
            ("deployment_url","https://example.invalid/other"),
            ("state","deployed"),
            ("log_url","http://attacker.invalid/log"),
        ):
            self.transport.statuses=[status()]
            self.transport.statuses[0][key]=value
            with self.assertRaises(Denied):
                self.read("get_deployment_status",
                          dict(deploymentId=12,statusId=34))
        for params in (
            dict(deploymentId=0,statusId=34),
            dict(deploymentId=12,statusId=False),
            dict(deploymentId=12,statusId=34,body={}),
        ):
            with self.assertRaises(Denied):
                validate_github_read("get_deployment_status",REPO,params)
        with self.assertRaises(Denied):
            validate_github_read("get_deployment","foreign",dict(deploymentId=-4))


if __name__ == "__main__":
    unittest.main()

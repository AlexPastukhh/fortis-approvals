"""P4 source-only typed GitHub Deployments READ: strict scope, no WRITE."""
from copy import deepcopy
from pathlib import Path
import re
import tempfile
import unittest
import uuid
from dataclasses import replace
from types import SimpleNamespace

from fortis_approvals.core import Denied, Core, Authenticator
from fortis_approvals.repo_action_contract import RepoIntentBroker
from fortis_approvals.integrations.github.pilot import GitHubPilotConfig, config_from_environment
from fortis_approvals.workflow.runtime import install
from fortis_approvals.workflow.ingress import NativeIngress
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


class DeploymentReadActivationTests(unittest.TestCase):
    """Source contract only; tests NEVER configure live policy or credentials."""

    def setUp(self):
        tmp=tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root=Path(tmp.name)
        self.transport=FakeReadTransport()
        self.config=GitHubPilotConfig(
            OWNER,REPO,file_pr_branch='fortis-e2e/11111111-1111-4111-8111-111111111111-approve',
            ci_reads=True,native_worktree=True,required_workflows=(101,))

    def native(self, config, *, actor='agent'):
        core=Core(self.root/'core.sqlite',adapters={},policies={},
                  authenticator=Authenticator({
                      'reader-one':'agent','reader-two':'outsider'}))
        broker=RepoIntentBroker(core,actor_operations={})
        portal=SimpleNamespace(strong_operations=frozenset())
        install(core=core,portal=portal,broker=broker,config=config,
                root=self.root,actor=actor,transport=self.transport)
        ingress=NativeIngress(SimpleNamespace(broker=broker),
            github=SimpleNamespace(config=config),workspace=None,store=None,actor=actor)
        return core,broker,ingress

    def query(self,repo=REPO,operation='list_deployments'):
        params={'page':1,'perPage':10,'sha':SHA,'environment':ENV}
        if operation=='get_deployment':params={'deploymentId':12}
        if operation=='list_deployment_statuses':
            params={'deploymentId':12,'page':1,'perPage':10}
        if operation=='get_deployment_status':params={'deploymentId':12,'statusId':34}
        return dict(requestId=str(uuid.uuid4()),service='github',operation=operation,
                    target=repo,params=params,reason='P4 source-only read test')

    def test_default_closed_without_broker_grants_or_transport_use(self):
        core,broker,ingress=self.native(self.config)
        for op in DEPLOYMENT_READ_OPERATIONS:
            self.assertEqual(core.policies[('agent',op[0],op[1])],'DENY')
            self.assertNotIn(op,broker.actor_read_operations['agent'])
        with self.assertRaisesRegex(Denied,'REPO_READ_GRANT_DENIED'):
            broker.read('reader-one',self.query())
        with self.assertRaisesRegex(Denied,'GITHUB_CD_READ_REPOSITORY_NOT_ADMITTED'):
            core.adapters['github'].read(self.query())
        caps=ingress._dispatch('/v1/workspace/capabilities',{},'reader-one','agent')
        self.assertEqual(caps['githubDeploymentReads']['repositories'],[])
        self.assertFalse(caps['githubDeploymentReads']['enabled'])
        self.assertEqual(caps['githubDeploymentReads']['operations'],[])
        self.assertFalse(caps['githubDeploymentReads']['writeEnabled'])
        self.assertFalse(caps['githubDeploymentReads']['installedStateProof'])
        self.assertEqual(self.transport.calls,[])

    def test_explicit_exact_repo_read_only_and_denies_wrong_actor_and_repo(self):
        config=replace(self.config,cd_read_repositories=(REPO,))
        core,broker,ingress=self.native(config)
        for service,op in DEPLOYMENT_READ_OPERATIONS:
            self.assertEqual(core.policies[('agent',service,op)],'DENY')
            self.assertEqual(core.policies[('agent',service,op,REPO)],'ALLOW')
            self.assertNotIn(('agent',service,op,'other-repo'),core.policies)
            self.assertIn((service,op),broker.actor_read_operations['agent'])
            output=broker.read('reader-one',self.query(operation=op))
            self.assertEqual(output['data']['evidenceClass'],'GITHUB_PROJECTION_ONLY')
            self.assertEqual(output['data']['operation'],op)
            with self.assertRaises(Denied):
                broker.read('reader-one',self.query(repo='other-repo',operation=op))
            with self.assertRaisesRegex(Denied,'GITHUB_CD_READ_REPOSITORY_NOT_ADMITTED'):
                core.adapters['github'].read(self.query(repo='other-repo',operation=op))
            with self.assertRaises(Denied):
                broker.read('reader-two',self.query(operation=op))
        caps=ingress._dispatch('/v1/workspace/capabilities',{},'reader-one','agent')
        self.assertTrue(caps['githubDeploymentReads']['enabled'])
        self.assertEqual(caps['githubDeploymentReads']['repositories'],[REPO])
        self.assertEqual(set(caps['githubDeploymentReads']['operations']), {
            op for _,op in DEPLOYMENT_READ_OPERATIONS})
        self.assertFalse(caps['githubDeploymentReads']['writeEnabled'])
        self.assertNotIn(('github','create_cd_projection'),
                         broker.actor_operations['agent'])
        self.assertNotIn(('github','append_cd_status'),
                         broker.actor_operations['agent'])
        self.assertTrue(all(call[0]=='GET' and call[3] is None
                            for call in self.transport.calls))

    def test_dynamic_two_exact_repositories_no_third_repo_grant(self):
        config=replace(self.config,dynamic_repositories=True,
                       cd_read_repositories=(REPO,'fortis-container'))
        core,broker,ingress=self.native(config)
        for repo in (REPO,'fortis-container'):
            for service,operation in DEPLOYMENT_READ_OPERATIONS:
                broker.authorize_read('reader-one',self.query(repo=repo,operation=operation))
                self.assertEqual(core._policy('agent',dict(
                    service=service,operation=operation,target=repo)),'ALLOW')
        for service,operation in DEPLOYMENT_READ_OPERATIONS:
            self.assertEqual(core._policy('agent',dict(
                service=service,operation=operation,target='tunnel')),'DENY')
            with self.assertRaises(Denied):
                broker.authorize_read('reader-one',
                    self.query(repo='tunnel',operation=operation))
        caps=ingress._dispatch('/v1/workspace/capabilities',{},'reader-one','agent')
        self.assertEqual(caps['githubDeploymentReads']['repositories'],
                         ['fortis-container',REPO])
        self.assertTrue(caps['githubDeploymentReads']['enabled'])
        self.assertEqual(self.transport.calls,[])

    def test_caps_fail_closed_on_partial_grant_or_policy(self):
        config=replace(self.config,cd_read_repositories=(REPO,))
        core,broker,ingress=self.native(config)
        opname=next(iter(DEPLOYMENT_READ_OPERATIONS))
        broker.actor_read_operations['agent']-=frozenset({opname})
        caps=ingress._dispatch('/v1/workspace/capabilities',{},'reader-one','agent')
        self.assertFalse(caps['githubDeploymentReads']['enabled'])
        self.assertEqual(caps['githubDeploymentReads']['repositories'],[])
        broker.actor_read_operations['agent']|=frozenset({opname})
        core.policies[('agent',opname[0],opname[1],REPO)]='DENY'
        caps=ingress._dispatch('/v1/workspace/capabilities',{},'reader-one','agent')
        self.assertFalse(caps['githubDeploymentReads']['enabled'])
        self.assertEqual(caps['githubDeploymentReads']['repositories'],[])

    def test_config_default_disabled_and_explicit_env_parser(self):
        self.assertEqual(self.config.cd_read_repositories,())
        base={
            'FORTIS_GITHUB_PILOT':'1','FORTIS_GITHUB_OWNER':OWNER,
            'FORTIS_GITHUB_REPOSITORY':REPO,
            'FORTIS_GITHUB_FILE_PR_BRANCH':self.config.file_pr_branch,
            'FORTIS_GITHUB_CI_READS':'1','FORTIS_GITHUB_NATIVE_WORKTREE':'1',
            'FORTIS_GITHUB_REQUIRED_WORKFLOWS':'101',
            'FORTIS_GITHUB_NATIVE_MULTI_REPO':'1',
        }
        self.assertEqual(config_from_environment(base).cd_read_repositories,())
        enabled=config_from_environment({
            **base,'FORTIS_GITHUB_CD_READ_REPOSITORIES':'sandbox,fortis-container'})
        self.assertEqual(enabled.cd_read_repositories,('sandbox','fortis-container'))
        with self.assertRaisesRegex(ValueError,'GITHUB_PILOT_PARTIAL_CONFIGURATION'):
            config_from_environment({
                'FORTIS_GITHUB_PILOT':'0','FORTIS_GITHUB_CD_READ_REPOSITORIES':REPO})
        for raw in ('sandbox,sandbox','../x','sandbox/production', 'sandbox,',
                    'sandbox,other/scope','sandbox,*','a'*101,',sandbox'):
            with self.assertRaises(ValueError,msg=raw):
                config_from_environment({
                    **base,'FORTIS_GITHUB_CD_READ_REPOSITORIES':raw})
        for bad in (
            dict(cd_read_repositories='sandbox'),
            dict(cd_read_repositories=(REPO,REPO)),
            dict(cd_read_repositories=('sandbox','SANDBOX')),
            dict(cd_read_repositories=('..',)),
            dict(cd_read_repositories=(REPO,)*11),
        ):
            with self.assertRaises(ValueError,msg=str(bad)):
                replace(self.config,**bad)
        with self.assertRaisesRegex(ValueError,'GITHUB_CD_READ_SCOPE_INVALID'):
            replace(self.config,native_worktree=False,ci_reads=False,
                    required_workflows=(),cd_read_repositories=(REPO,))
        with self.assertRaisesRegex(ValueError,'GITHUB_CD_READ_SCOPE_INVALID'):
            replace(self.config,cd_read_repositories=('fortis-container',))




if __name__ == "__main__":
    unittest.main()

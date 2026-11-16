"""Real local Git objects plus the existing offline scoped Gateway fixture."""
import base64
import copy
import hashlib
from pathlib import Path

from fortis_approvals.integrations.github.publisher_profile import PublisherProfile, REPOSITORY
from fortis_approvals.integrations.github.release_label_ci import WORKFLOWS
from fortis_approvals.integrations.github.release_label_publisher import RunnerConfig, PublisherRunner
from fortis_approvals.workflow.client import WorkflowClient
from fortis_approvals.workflow.common import Git, secure_dir
from publisher_fixture import API, Fixture, OWNER, REGISTRY_ACTOR, ROOT

CATALOG = """schemaVersion: 1
repository: fortis-approvals
buildUnits:
  - id: shared-image
    artifactType: docker-image
    recipe: runtime/Dockerfile
    inputs: [runtime/**]
targets:
  - id: api
    buildUnit: shared-image
    deployment:
      kind: owner-controlled
      procedure: docs/DEPLOYMENT.md
      environments: [production]
    verification: [source-ci]
  - id: worker
    buildUnit: shared-image
    deployment:
      kind: owner-controlled
      procedure: docs/DEPLOYMENT.md
      environments: [production]
    verification: [source-ci]
noDeploymentPaths: [docs/**, release/**, .github/**, .gitattributes, tools/**]
"""

BODY = """Fixture metadata.
<!-- fortis-release-impact:start -->
FENCEyaml
releaseImpact:
  schemaVersion: 1
  classification: no-deployment
  reason: Only reviewed documentation data changes in this source fixture.
  targets: []
  dependencies:
    pullRequests: []
    targets: []
  verification: [source-ci]
FENCE
<!-- fortis-release-impact:end -->
""".replace('FENCE',chr(96)*3)


class Graph:
    def __init__(self, root):
        self.root=secure_dir(root);self.git=Git(self.root/'git-state')
        self.repository=secure_dir(self.root/'origin')
        self.git.run(['init','--quiet','--template=','--initial-branch=main',self.repository])
        for args in [('user.name','Fixture'),('user.email','fixture@example.invalid')]:
            self.git.run(['config',*args],cwd=self.repository)
        self.write('release/targets.yaml',CATALOG)
        self.write('runtime/Dockerfile','FROM scratch\n')
        self.write('runtime/app.py','BASE = 1\n')
        self.write('docs/DEPLOYMENT.md','Owner fixture procedure.\n')
        for workflow in WORKFLOWS:
            self.write(workflow.path,(ROOT/workflow.path).read_bytes())
        self.base=self.commit('Trusted fixture base')
        self.write('docs/accepted.txt','Later accepted main data.\n')
        self.main=self.commit('Main advances independently')
        self.git.run(['checkout','--quiet','-b','task/release-pilot',self.base],cwd=self.repository)
        self.write('docs/pr.txt','PR data\n')
        self.write('.gitattributes','docs/*.txt text eol=crlf filter=evil\n')
        self.write('tools/release/ci_entry.py',"raise RuntimeError('UNTRUSTED PR CODE EXECUTED')\n")
        self.head=self.commit('PR data only')

    def write(self, path, data):
        p=self.repository/path;p.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
        p.write_bytes(data.encode() if isinstance(data,str) else data)

    def commit(self, message):
        self.git.run(['add','--all'],cwd=self.repository)
        self.git.run(['commit','--quiet','-m',message],cwd=self.repository)
        return self.git.text(['rev-parse','HEAD'],cwd=self.repository)

    def bundle(self, sha):
        self.git.run(['update-ref','refs/heads/transfer',sha],cwd=self.repository)
        path=self.root/(sha+'.bundle')
        if not path.exists():
            self.git.run(['bundle','create',path,'refs/heads/transfer'],cwd=self.repository)
        return path.read_bytes()


class GraphAPI(API):
    def __init__(self, graph):
        super().__init__();self.graph=graph
        self.head=self.ci_head=graph.head;self.base=graph.base;self.body=BODY

    def request(self, method, path, **kw):
        if method=='GET' and path=='/repos/'+OWNER+'/'+REPOSITORY+'/branches/main':
            self.calls.append((method,'/branches/main',kw.get('params'),kw.get('body')))
            return dict(name='main',commit=dict(sha=self.graph.main),protected=True)
        return super().request(method,path,**kw)


class GraphBackend:
    def __init__(self, graph):
        self.graph=graph;self.fetches=[];self.transform=None
    def fetch_bundle(self, repo, ref, expected):
        self.fetches.append((repo,ref,expected));data=self.graph.bundle(expected)
        result=dict(repository=repo,ref=ref,sha=expected,bundleSha256=hashlib.sha256(data).hexdigest(),
                    bundle=base64.b64encode(data).decode())
        return self.transform(result) if self.transform else result


class PlanFixture:
    """Scheduling input only. This is not a second Release Impact classifier."""
    def __init__(self):
        self.calls=0;self.after_plan=None
        self.value=dict(status='PREVIEW_ONLY',suggestedLabels=['release:no-deployment'],
            add=['release:no-deployment'],remove=['build:legacy'],missingDefinitions=[],
            preservedHumanLabels=['bug'],preservedReviewFlag=True,
            classification='no-deployment',affectedTargets=[])
    def factory(self, root, revision, *, git, folder):
        parent=self
        class Bound:
            def plan(self, **kw):
                parent.calls+=1
                value=copy.deepcopy(parent.value)
                pr=kw['current_pr']
                value.update(repository=kw['repository'],pullRequest=pr['number'],headSha=pr['head']['sha'])
                if parent.after_plan:parent.after_plan()
                return value
        return Bound()


class RunnerFixture:
    def __init__(self, root, *, revision='d'*40, validator_root=None, validator_factory=None):
        self.root=secure_dir(root);self.graph=Graph(self.root/'source')
        self.api=GraphAPI(self.graph)
        profile=PublisherProfile(enabled=True,revision='c'*64,validator_revision=revision,
                                 registry_delegation=True)
        self.gateway=Fixture(self.root/'gateway',api=self.api,profile=profile)
        # Keep the real 30/minute policy; explicit owner invocations use a virtual clock.
        self.owner_clock=[0.0]
        self.gateway.app.base.limiter.clock=lambda:self.owner_clock[0]
        self.backend=GraphBackend(self.graph);self.gateway.backend=self.gateway.adapter.backend=self.backend
        self.plan=PlanFixture()
        code=secure_dir(self.root/'trusted-code') if validator_root is None else validator_root
        self.config=RunnerConfig(validator_root=code,validator_revision=revision,
            profile_sha256=profile.fingerprint(REGISTRY_ACTOR),cache_root=self.root/'cache',
            intent_root=self.root/'intents',endpoint=self.gateway.publisher.endpoint,
            grant_path=self.root/'grant',certificate_path=self.root/'certificate',owner=OWNER,enabled=True)
        self.client=WorkflowClient.for_release_label_publisher(gateway=self.gateway.publisher,
                                                              intent_root=self.config.intent_root)
        self.runner=PublisherRunner(self.config,self.client,
            validator_factory=validator_factory or self.plan.factory)

    def next_invocation(self):
        self.owner_clock[0]+=61

    def update_head(self, message):
        self.graph.head=self.graph.commit(message)
        self.api.head=self.api.ci_head=self.graph.head

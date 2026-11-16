"""Offline P3 machine boundary fixture. No live TLS, credentials or provider calls."""
import base64
import copy
import hashlib
import io
import json
from pathlib import Path
from types import SimpleNamespace
import uuid

from fortis_approvals.core import Authenticator, Denied
from fortis_approvals.incidents import IncidentCore
from fortis_approvals.repo_action_contract import RepoIntentBroker
from fortis_approvals.repo_ingress import RepoIngress
from fortis_approvals.integrations.github.pilot import GitHubPilotConfig
from fortis_approvals.integrations.github.publisher_profile import (
    ACTOR, REPOSITORY, READS, WRITES, PublisherProfile)
from fortis_approvals.integrations.github.release_label_ci import WORKFLOWS
from fortis_approvals.integrations.github.release_label_contract import names_hash
from fortis_approvals.integrations.github.gateway.transport import GitHubHTTPTransport, GitHubTransportError
from fortis_approvals.workflow.runtime import install, wrap

HEAD, BASE = 'a'*40, 'b'*40
REGISTRY_ACTOR = 'repo-fixture-actor'
CREDS = {'repo-fixture-credential':REGISTRY_ACTOR,
         'publisher-fixture-credential':ACTOR, 'other-ai-credential':'other-ai'}
OWNER = 'Alex'
ROOT = Path(__file__).resolve().parents[4]


def label(name):
    return dict(name=name, color='aa9911', description=None)


class TestOwnerVerifier:
    def verify(self, ident, fingerprint, decision, proof):
        if proof != (ident, fingerprint, decision):
            raise Denied('UNIT_OWNER_PROOF_INVALID')
        return 'unit-owner'


class API:
    def __init__(self):
        self.calls = []
        self.head, self.base, self.branch = HEAD, BASE, 'task/release-pilot'
        self.body, self.state, self.draft, self.merged = 'reviewed fixture PR body', 'open', False, False
        self.head_repo = self.base_repo = OWNER+'/'+REPOSITORY
        self.labels = ['bug', 'build:legacy', 'release:review-required']
        self.definitions = self.labels+['build:api','release:no-deployment','release:image-rebuild']
        self.attempts = {w.ident:1 for w in WORKFLOWS}
        self.status, self.conclusion = {}, {}
        self.sources = {w.path:(ROOT/w.path).read_bytes() for w in WORKFLOWS}
        self.extra_runs, self.extra_jobs = [], []
        self.job_changes = {}
        self.workflow_state, self.workflow_name = {}, {}
        self.total_override = self.jobs_total_override = None
        self.on_request = None
        self.fail_context = self.lose_response = False
        self.ci_head = HEAD

    def pr(self):
        return dict(number=7, title='Scoped publisher fixture', state=self.state, draft=self.draft,
            merged=self.merged, merged_at=None, body=self.body,
            html_url='https://github.com/'+OWNER+'/'+REPOSITORY+'/pull/7',
            head=dict(ref=self.branch, sha=self.head, repo=dict(full_name=self.head_repo)),
            base=dict(ref='main', sha=self.base, repo=dict(full_name=self.base_repo)))

    def runs(self):
        return [dict(id=101+i, name=w.name, workflow_id=w.ident, path=w.path,
            event='pull_request', status=self.status.get(w.ident,'completed'),
            conclusion=self.conclusion.get(w.ident,'success'), head_sha=self.ci_head,
            head_branch=self.branch, run_number=1, run_attempt=self.attempts[w.ident],
            created_at='2026-11-16T01:00:00Z', updated_at='2026-11-16T01:01:00Z',
            html_url='https://github.com/'+OWNER+'/'+REPOSITORY+'/actions/runs/'+str(101+i),
            repository=dict(full_name=OWNER+'/'+REPOSITORY),
            head_repository=dict(full_name=OWNER+'/'+REPOSITORY),
            pull_requests=[dict(number=7, head=dict(sha=self.ci_head), base=dict(sha=self.base))])
            for i,w in enumerate(WORKFLOWS)]+copy.deepcopy(self.extra_runs)

    def request(self, method, path, *, params=None, body=None, expected_statuses=(200,), allow_not_found=False):
        assert GitHubHTTPTransport._route_allowed(method, path), (method,path)
        prefix='/repos/'+OWNER+'/'+REPOSITORY
        assert path.casefold().startswith(prefix.casefold()), path
        suffix=path[len(prefix):]
        self.calls.append((method,suffix,copy.deepcopy(params),copy.deepcopy(body)))
        if self.on_request:
            self.on_request(method,suffix,params,body)
        if method == 'GET' and not suffix:
            return dict(full_name=OWNER+'/'+REPOSITORY, archived=False, disabled=False, default_branch='main')
        if method == 'GET' and suffix == '/pulls':
            assert params['head']==OWNER+':'+self.branch and params['base']=='main'
            return [self.pr()] if self.state=='open' else []
        if method == 'GET' and suffix == '/pulls/7':
            if self.fail_context:
                raise GitHubTransportError('GITHUB_HTTP_503')
            return self.pr()
        if method == 'GET' and suffix in ('/branches/main','/branches/task%2Frelease-pilot'):
            main=suffix.endswith('/main')
            return dict(name='main' if main else self.branch,
                        commit=dict(sha=self.base if main else self.head), protected=main)
        if method == 'GET' and suffix in ('/labels','/issues/7/labels'):
            values=self.definitions if suffix=='/labels' else self.labels
            start=(params['page']-1)*params['per_page']
            return [label(n) for n in values[start:start+params['per_page']]]
        if method == 'GET' and suffix == '/actions/runs':
            assert params['head_sha']==HEAD and params['event']=='pull_request'
            assert params['per_page']==20
            rows=self.runs();start=(params['page']-1)*params['per_page']
            return dict(total_count=len(rows) if self.total_override is None else self.total_override,
                        workflow_runs=copy.deepcopy(rows[start:start+params['per_page']]))
        if method == 'GET' and suffix.startswith('/actions/workflows/'):
            ident=int(suffix.rsplit('/',1)[1]);w=next(w for w in WORKFLOWS if w.ident==ident)
            return dict(id=ident, name=self.workflow_name.get(ident,w.name), path=w.path,
                        state=self.workflow_state.get(ident,'active'))
        if method == 'GET' and suffix.startswith('/contents/'):
            path=suffix[len('/contents/'):];data=self.sources[path];assert params==dict(ref=HEAD)
            return dict(path=path,type='file',encoding='base64',size=len(data),
                content=base64.encodebytes(data).decode(),
                sha=hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest())
        if method == 'GET' and suffix.startswith('/actions/runs/') and '/attempts/' in suffix:
            parts=suffix.split('/');ident,attempt=int(parts[3]),int(parts[5])
            run=next(r for r in self.runs() if r['id']==ident and r['run_attempt']==attempt)
            if not suffix.endswith('/jobs'):
                return copy.deepcopy(run)
            w=next(w for w in WORKFLOWS if w.ident==run['workflow_id'])
            jobs=[dict(id=1000+ident*10+i,name=name,run_id=ident,run_attempt=attempt,
                head_sha=self.ci_head,status='completed',conclusion='success',steps=[])
                for i,name in enumerate(w.jobs)]
            jobs=[{**j,**self.job_changes.get(j['name'],{})} for j in jobs]+copy.deepcopy(self.extra_jobs)
            return dict(total_count=len(jobs) if self.jobs_total_override is None else self.jobs_total_override,
                        jobs=jobs)
        if method == 'POST' and suffix == '/labels':
            self.definitions.append(body['name']);return {**body,'id':500}
        if method == 'POST' and suffix == '/issues/7/labels':
            self.labels=sorted(set(self.labels)|set(body['labels']))
        elif method == 'DELETE' and suffix.startswith('/issues/7/labels/'):
            from urllib.parse import unquote
            self.labels.remove(unquote(suffix.rsplit('/',1)[1]))
        else:
            raise AssertionError((method,suffix,params,body))
        if self.lose_response:
            raise GitHubTransportError('GITHUB_HTTP_LOST')
        return [label(n) for n in self.labels]

    @property
    def writes(self):
        return [x for x in self.calls if x[0] != 'GET']


class Backend:
    def __init__(self):self.fetches=[]
    def fetch_bundle(self, repo, ref, expected):
        self.fetches.append((repo,ref,expected))
        return dict(repository=repo,ref=ref,sha=expected,bundleSha256='d'*64,bundle='Zml4dHVyZQ==')


class Bridge:
    endpoint='https://host.docker.internal:19204'
    def __init__(self, app, credential):
        self.app,self.credential=app,credential;self.calls=[];self.lose_ask_ack=False
    def call(self, path, body=None, *, method='POST'):
        raw=json.dumps(body).encode() if method=='POST' else b''
        env=dict(REQUEST_METHOD=method,PATH_INFO=path,QUERY_STRING='',SCRIPT_NAME='',
            HTTP_HOST='host.docker.internal:19204',HTTP_AUTHORIZATION='Bearer '+self.credential,
            CONTENT_TYPE='application/json' if method=='POST' else '',CONTENT_LENGTH=str(len(raw)),
            REMOTE_ADDR='127.0.0.1',**{'wsgi.url_scheme':'https','wsgi.input':io.BytesIO(raw)})
        states=[];output=b''.join(self.app(env,lambda status,headers:states.append(status)))
        self.calls.append((path,copy.deepcopy(body),int(states[0].split()[0])))
        return int(states[0].split()[0]),json.loads(output)
    def post(self, path, body, accept_202=False):
        code,out=self.call(path,body)
        if code>=400:raise Denied('FORTIS_HTTP_'+str(code))
        if path=='/v1/actions' and self.lose_ask_ack:
            self.lose_ask_ack=False;raise TimeoutError('unit lost ASK acknowledgement')
        return out
    def get(self,path):
        code,out=self.call(path,method='GET')
        if code>=400:raise Denied('FORTIS_HTTP_'+str(code))
        return out


class Fixture:
    def __init__(self, root, *, enabled=True, api=None, profile=None):
        self.root=Path(root);self.root.mkdir(mode=0o700,parents=True,exist_ok=True)
        self.api=api or API();self.backend=Backend()
        self.profile=(profile if profile is not None else PublisherProfile(enabled=True,
            revision='c'*64,validator_revision='d'*40,registry_delegation=True) if enabled else PublisherProfile())
        policies=self.profile.owner_policy_map() if self.profile.enabled else {}
        self.core=IncidentCore(self.root/'core.sqlite',adapters={},policies=policies,
            authenticator=Authenticator(CREDS),owner_verifier=TestOwnerVerifier())
        actions={REGISTRY_ACTOR:frozenset({('github','create_pull_request')})}
        reads={REGISTRY_ACTOR:frozenset({('github','get_pull_request')})}
        if self.profile.enabled:
            actions[ACTOR]=frozenset(('github',op) for op in WRITES)
            reads[ACTOR]=frozenset(('github',op) for op in READS)
        self.broker=RepoIntentBroker(self.core,actor_operations=actions,actor_read_operations=reads)
        self.portal=SimpleNamespace(core=self.core,strong_operations=frozenset())
        config=GitHubPilotConfig(OWNER,REPOSITORY,ci_reads=True,native_worktree=True,
            file_pr_branch='fortis-e2e/11111111-1111-4111-8111-111111111111-approve',
            required_workflows=tuple(w.ident for w in WORKFLOWS),dynamic_repositories=True)
        installed=install(core=self.core,portal=self.portal,broker=self.broker,config=config,
            root=self.root,actor=REGISTRY_ACTOR,transport=self.api,backend=self.backend,
            publisher_profile=self.profile)
        self.adapter,self.store=installed['adapter'],installed['store']
        self.store.register(REGISTRY_ACTOR,REPOSITORY,'release-pilot',dict(repository=REPOSITORY,
            task='release-pilot',branch='task/release-pilot',baseSha=BASE))
        self.app=wrap(RepoIngress(self.broker,host='host.docker.internal:19204'),installed)
        self.publisher=Bridge(self.app,'publisher-fixture-credential')
        self.repo=Bridge(self.app,'repo-fixture-credential')
        self.other=Bridge(self.app,'other-ai-credential')

    def params(self, *, remove=False):
        p=dict(number=7,expectedHeadSha=self.api.head,expectedBaseSha=self.api.base,
            expectedBodySha256=hashlib.sha256(self.api.body.encode()).hexdigest(),
            expectedLabelsSha256=names_hash(self.api.labels))
        p.update(dict(name='build:legacy') if remove else dict(labels=['build:api']))
        return p

    def intent(self, *, operation='add_pr_release_labels', ident=None, target=REPOSITORY, params=None):
        return dict(requestId=ident or str(uuid.uuid4()),service='github',operation=operation,
            target=target,params=self.params(remove=operation=='remove_pr_release_label') if params is None else params,
            reason='Reviewed fixture one-shot release label proposal')

    def approve(self, ident, decision='approve'):
        row=self.core._read(ident)
        return self.core.owner_decide(ident,decision,(ident,row['fingerprint'],decision))

"""Trusted policies/adapters for native publication and delegated local commands."""
import hashlib
import json
from pathlib import Path
import re
import time
from ..core import Denied, Stale, canonical
from ..integrations.github.gateway.adapter import GitHubAdapter
from ..integrations.github.gateway.analysis_adapter import AnalysisGitHubAdapter
from ..integrations.github.analysis_contract import READ_NAMES as CI_READ_NAMES, ACTION_NAMES as CI_ACTION_NAMES
from ..integrations.github.contract import validate_github_action, validate_github_read, validate_github_read_projection
from .error_diagnostics import observe_adapter
from .common import WORKSPACE_OPS, branch, digest, file_path, require, sha, slug


class NativeGitHubAdapter(AnalysisGitHubAdapter):
    _PR_CREATE_CHECKPOINTS=frozenset({
        'PR_CREATE_POST_STARTED','PR_CREATE_POST_ACKNOWLEDGED'
    })

    def pr_create_checkpoint(self, request_id, checkpoint):
        """Mandatory Core journal for native PR-create around the effect edge.

        Never claim nonexecution from an absent ACK; never use an ordinary
        heartbeat or a response code as proof of the original effect.
        """
        if checkpoint not in self._PR_CREATE_CHECKPOINTS or type(request_id) is not str:
            raise Denied('GITHUB_PR_CREATE_CHECKPOINT_INVALID')
        core=self.observation_core
        if core is None:
            # Native publish must have a trusted Core state store. No silent
            # best-effort skip when the journal binding is missing.
            raise Denied('GITHUB_PR_CREATE_CHECKPOINT_CORE_REQUIRED')
        with core._db() as db:
            db.execute('BEGIN IMMEDIATE')
            row=db.execute('SELECT state,payload FROM requests WHERE id=?',
                (request_id,)).fetchone()
            if row is None or row['state']!='DISPATCHED':
                raise Denied('GITHUB_PR_CREATE_CHECKPOINT_STATE_INVALID')
            payload=json.loads(row['payload'])
            if (payload.get('service'),payload.get('operation'))!=(
                    'github','create_pull_request'):
                raise Denied('GITHUB_PR_CREATE_CHECKPOINT_OPERATION_INVALID')
            core._event(db,request_id,checkpoint,{
                'origin':'GITHUB_ADAPTER',
                'effectAssessment':'OUTCOME_UNCONFIRMED',
                'providerAcknowledged':checkpoint=='PR_CREATE_POST_ACKNOWLEDGED',
            })

    def __init__(self,transport,*,config,root,actor,backend,store,observation_core=None):
        self.config=config;self.actor=actor;self.backend=backend;self.workflow=store
        self.observation_core=observation_core
        super().__init__(transport,owner=config.owner,repositories=(config.repository,),
            receipt_store=Path(root)/'github-receipts.sqlite',bindings={})
        if config.dynamic_repositories:
            # No second repository allowlist: upstream token determines access.
            # Legacy single-repository mode remains the default until owner rollout.
            self.repositories=None

    def _visual_prepare(self,request):
        p=request['params'];repo=request['target'];ident=request['requestId']
        from ..integrations.github.contract import validate_github_action
        validate_github_action('publish_visual_review',repo,p)
        require(repo=='visual-workspace','VISUAL_REVIEW_REPOSITORY_DENIED')
        raw=self._api('GET',self._path(repo))
        require(type(raw) is dict and raw.get('full_name')==self.owner+'/'+repo and
                raw.get('private') is True and raw.get('has_issues') is True and
                type(raw.get('id')) is int and 0<raw['id']<2**63,
                'VISUAL_REVIEW_REPO_INVALID')
        for row in p['media']:
            self.workflow.visual_png(self.actor,ident,repo,p['runId'],row)
        return dict(operation='publish_visual_review',repository=repo,runId=p['runId'],
                    repositoryId=raw['id'],media=p['media'],
                    contentSha256=hashlib.sha256(canonical({k:v for k,v in p.items() if k!='media'}).encode()).hexdigest())

    def visual_evidence(self,ident):
        """Read-only durable evidence for actor-scoped existing details endpoint."""
        with self._db() as db:
            table=db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='visual_reviews'").fetchone()
            if table is None:return None
            row=db.execute('SELECT repository,run_id,issue_number,uploads FROM visual_reviews WHERE id=?',(ident,)).fetchone()
        if row is None:return None
        return dict(repository=row[0],runId=row[1],issueNumber=row[2],
                    uploadedFiles=len(json.loads(row[3])))

    def _visual_apply(self,request):
        """Single Core action; partial GitHub effects are never blindly replayed."""
        ident=request['requestId'];p=request['params'];repo=request['target']
        preview=self._visual_prepare(request)
        # Reserve the run before the first GitHub effect. An unresolved run blocks
        # new request IDs, even if the original HTTP response was lost.
        with self._db() as db:
            db.execute('BEGIN IMMEDIATE')
            db.execute('CREATE TABLE IF NOT EXISTS visual_reviews ('
                'id TEXT PRIMARY KEY, repository TEXT, run_id TEXT, issue_number INTEGER, '
                'uploads TEXT NOT NULL, UNIQUE(repository,run_id))')
            row=db.execute('SELECT id FROM visual_reviews WHERE repository=? AND run_id=?',
                           (repo,p['runId'])).fetchone()
            require(row is None,'VISUAL_REVIEW_RUN_ALREADY_RESERVED')
            # Persist the one-shot boundary before *any* GitHub mutation.
            db.execute('INSERT INTO visual_reviews VALUES(?,?,?,NULL,?)',
                       (ident,repo,p['runId'],'{}'))
        # The reservation is durable; unexpected exceptions leave an incident.
        marker='<!-- fortis-visual-review:'+p['runId']+' -->'
        intro=(marker+'\n\n'+p['description']+'\n\n**QA:** '+p['qaSummary']+
               '\n\n**Duration:** '+str(p['durationSeconds'])+' seconds')
        created=self._api('POST',self._path(repo,'issues'),body={
            'title':p['title'],'body':intro},expected=(201,))
        require(type(created) is dict and type(created.get('number')) is int and
                0<created['number']<=1000000 and
                created.get('html_url')=='https://github.com/'+self.owner+'/'+repo+'/issues/'+str(created['number']),
                'VISUAL_REVIEW_CREATE_UNCONFIRMED')
        number=created['number']
        with self._db() as db:
            db.execute('UPDATE visual_reviews SET issue_number=? WHERE id=?',(number,ident))
        attachments=[]
        for item in p['media']:
            data=self.workflow.visual_png(self.actor,ident,repo,p['runId'],item)
            filename='fortis-'+str(item['index'])+'-'+item['sha256'][:16]+'.png'
            url=self.transport.upload_visual_png(preview['repositoryId'],filename,data)
            attachments.append((item,url))
            with self._db() as db:
                db.execute('UPDATE visual_reviews SET uploads=? WHERE id=?',
                           (canonical({str(row['index']):link for row,link in attachments}),ident))
        def alt(value):
            return value.replace('\\','\\\\').replace('[','\\[').replace(']','\\]').replace('\r',' ').replace('\n',' ')
        body=intro+'\n\n## Preview\n\n'+'\n\n'.join(
            '!['+alt(item['name'])+']('+url+')' for item,url in attachments)
        updated=self._api('PATCH',self._path(repo,'issues/'+str(number)),body={'body':body})
        require(type(updated) is dict and updated.get('number')==number,
                'VISUAL_REVIEW_UPDATE_UNCONFIRMED')
        saved=self._api('GET',self._path(repo,'issues/'+str(number)))
        url='https://github.com/'+self.owner+'/'+repo+'/issues/'+str(number)
        require(type(saved) is dict and saved.get('number')==number and
                saved.get('html_url')==url and saved.get('body')==body and
                saved.get('state')=='open' and 'pull_request' not in saved,
                'VISUAL_REVIEW_READBACK_UNCONFIRMED')
        result=dict(requestId=ident,operation='publish_visual_review',repository=repo,
                    runId=p['runId'],issueNumber=number,url=url,uploadedFiles=len(attachments))
        self._save_receipt(ident,result)
        return result

    def _workflow(self, repo, ident, path):
        # Unlike the Sonar review profile, native GitHub CI is not pinned
        # to a Sonar project. The run, workflow path and ID come from GitHub.
        require(type(ident) is int and 0 < ident < 2**63 and
            type(path) is str and
            re.fullmatch(r'\.github/workflows/[A-Za-z0-9_-]+\.ya?ml', path),
            'GITHUB_NATIVE_WORKFLOW_INVALID')

    def _manifest_project_key(self, repo):
        # CI-recorded claim only: not independently Sonar-verified.
        return None

    def _ci_control_allowed(self, repo):
        return repo in self.config.ci_control_repositories

    def _repo(self,target):
        if not self.config.dynamic_repositories:return super()._repo(target)
        if (type(target) is not str or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,99}',target)
                or target in ('.','..')):
            raise Denied('GITHUB_REPOSITORY_INVALID')
        return target

    def _access(self,repo):
        """Token-scoped repo preflight, never a source of write authorization."""
        repo=self._repo(repo)
        if not self.config.dynamic_repositories:return repo
        info=self._api('GET',self._path(repo),allow_not_found=True)
        require(type(info) is dict and info.get('_httpStatus')!=404 and type(info.get('full_name')) is str,
                'GITHUB_REPOSITORY_ACCESS_UNCONFIRMED')
        require(type(info) is dict and type(info.get('full_name')) is str and
                info['full_name'].casefold()==(self.owner+'/'+repo).casefold() and
                info.get('archived') is False and info.get('disabled') is False and
                info.get('default_branch')=='main','GITHUB_REPOSITORY_ACCESS_UNCONFIRMED')
        return repo

    def read(self,request):
        if type(request) is dict and request.get('operation') in CI_READ_NAMES:
            self._access(request.get('target'))
            return AnalysisGitHubAdapter.read(self,request)
        if not self.config.dynamic_repositories:
            return GitHubAdapter.read(self,request)
        if type(request) is not dict or request.get('service')!='github':
            return GitHubAdapter.read(self,request)
        operation=request.get('operation');target=request.get('target');params=request.get('params')
        validate_github_read(operation,target,params)
        if operation=='list_repositories':
            require(target==self.owner,'GITHUB_OWNER_NOT_ALLOWLISTED')
            names=set()
            for page in range(1,11):
                rows=self._api('GET','/user/repos',params={
                    'affiliation':'owner','page':page,'per_page':100})
                require(type(rows) is list and len(rows)<=100,
                        'GITHUB_REPOSITORIES_RESPONSE_INVALID')
                for row in rows:
                    require(type(row) is dict and type(row.get('owner')) is dict and
                            type(row['owner'].get('login')) is str,
                            'GITHUB_REPOSITORY_RESPONSE_INVALID')
                    if row['owner']['login'].casefold()!=self.owner.casefold():
                        continue
                    name=row.get('name');full_name=row.get('full_name')
                    require(type(name) is str and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,99}',name)
                            and name not in ('.','..') and type(full_name) is str and
                            full_name.casefold()==(self.owner+'/'+name).casefold() and
                            type(row.get('archived')) is bool and type(row.get('disabled')) is bool and
                            type(row.get('default_branch')) is str,
                            'GITHUB_REPOSITORY_RESPONSE_INVALID')
                    if (row['archived'] is False and row['disabled'] is False and
                            row['default_branch']=='main'):
                        names.add(name)
                if len(rows)<100:
                    break
            else:
                raise Denied('GITHUB_REPOSITORY_INVENTORY_LIMIT')
            result={'operation':'list_repositories','items':[
                {'name':name,'owner':self.owner} for name in sorted(names,key=str.casefold)]}
            validate_github_read_projection(operation,result)
            return result
        self._access(target)
        return GitHubAdapter.read(self,request)

    def _dynamic_ci_gate(self,repo,head):
        """Exact required check names from active GitHub branch rules, no local repo list.

        Unknown/absent rules and unverified checks MUST NOT authorize merge.
        Classic branch protections without visible rules require explicit
        owner review or a subsequent verified API extension.
        """
        required={}
        for page in range(1,11):
            rules=self._api('GET',self._path(repo,'rules/branches/main'),
                            params={'page':page,'per_page':100})
            require(type(rules) is list,'GIT_BRANCH_RULES_INVALID')
            for rule in rules:
                require(type(rule) is dict and type(rule.get('type')) is str,'GIT_BRANCH_RULES_INVALID')
                if rule['type'] in ('workflows','required_workflows','required_deployments'):
                    raise Denied('GIT_REQUIRED_RULE_UNSUPPORTED')
                if rule['type']!='required_status_checks':continue
                params=rule.get('parameters')
                require(type(params) is dict and type(params.get('required_status_checks')) is list,
                        'GIT_REQUIRED_CHECKS_INVALID')
                for check in params['required_status_checks']:
                    require(type(check) is dict and type(check.get('context')) is str and
                            0<len(check['context'])<=200,'GIT_REQUIRED_CHECKS_INVALID')
                    app=check.get('integration_id')
                    require(app is None or type(app) is int and (app>0 or app==-1),
                            'GIT_REQUIRED_CHECKS_INVALID')
                    if app==-1:app=None  # GitHub 'any source' integration selector.
                    key=(check['context'],app);required[key]=None
            if len(rules)<100:break
        else:raise Denied('GIT_BRANCH_RULES_TOO_MANY')
        require(required,'GIT_REQUIRED_CHECKS_UNCONFIGURED')
        runs=[]
        for page in range(1,11):
            response=self._api('GET',self._path(repo,'commits/'+head+'/check-runs'),
                               params={'page':page,'per_page':100})
            require(type(response) is dict and type(response.get('check_runs')) is list,
                    'GIT_CHECK_RUNS_INVALID')
            runs+=response['check_runs']
            if len(response['check_runs'])<100:break
        else:raise Denied('GIT_CHECK_RUNS_TOO_MANY')
        statuses=self._api('GET',self._path(repo,'commits/'+head+'/status'))
        require(type(statuses) is dict and type(statuses.get('statuses')) is list,
                'GIT_COMMIT_STATUS_INVALID')
        evidence=[]
        for (name,app) in required:
            candidates=[r for r in runs if r.get('name')==name and r.get('head_sha')==head and
                        (app is None or type(r.get('app')) is dict and r['app'].get('id')==app)]
            if candidates:
                latest=max(candidates,key=lambda r:(r.get('id') if type(r.get('id')) is int else 0))
                require(type(latest.get('id')) is int and latest['id']>0,'GIT_CHECK_RUNS_INVALID')
                require(latest.get('status')=='completed' and latest.get('conclusion')=='success',
                        'GIT_REQUIRED_CI_NOT_SUCCESSFUL')
                evidence.append(dict(context=name,runId=latest['id'],headSha=head,source='check_run'))
                continue
            # A check pinned to a GitHub App may not be satisfied by a legacy commit status.
            require(app is None,'GIT_REQUIRED_CI_MISSING')
            matches=[s for s in statuses['statuses'] if s.get('context')==name]
            require(matches,'GIT_REQUIRED_CI_MISSING')
            latest=max(matches,key=lambda s:(s.get('id') if type(s.get('id')) is int else 0))
            require(type(latest.get('id')) is int and latest['id']>0,'GIT_COMMIT_STATUS_INVALID')
            require(latest.get('state')=='success','GIT_REQUIRED_CI_NOT_SUCCESSFUL')
            evidence.append(dict(context=name,statusId=latest['id'],headSha=head,source='commit_status'))
        return evidence

    def task(self,repo,task):
        self._repo(repo);slug(task)
        value=self.workflow.task(self.actor,repo,task)
        require(not value.get('closed'),'WORKFLOW_TASK_CLOSED')
        return value

    def task_branch(self,repo,name):
        branch(name)
        return self.task(repo,name[5:])

    def artifact(self,request):
        p=request['params'];row=self.workflow.artifact(self.actor,p['artifactSha256'])
        require(row['repository']==request['target'] and row['task']==p['task'] and
            row['newSha']==p['newSha'] and row['expectedHeadSha']==p['expectedHeadSha'],'GIT_ARTIFACT_BINDING_MISMATCH')
        self.task(request['target'],p['task'])
        return row

    def push_policy(self,actor,request):
        if actor!=self.actor:return 'DENY'
        try:return 'ASK' if self.artifact(request)['sensitivePaths'] else 'ALLOW'
        except (Denied,KeyError,TypeError):return 'DENY'

    def _ci_gate(self,repo,head,branch_name):
        rows=[]
        for page in range(1,101):
            raw=self._api('GET',self._path(repo,'actions/runs'),params={'head_sha':head,'event':'pull_request','page':page,'per_page':100})
            require(type(raw) is dict and type(raw.get('workflow_runs')) is list,'GIT_CI_RESPONSE_INVALID')
            rows+=raw['workflow_runs']
            if len(raw['workflow_runs'])<100:break
        else:raise Denied('GIT_CI_INVENTORY_LIMIT')
        witness=[]
        for ident in self.config.required_workflows:
            matches=[r for r in rows if r.get('workflow_id')==ident and r.get('head_sha')==head and
                r.get('head_branch')==branch_name and r.get('event')=='pull_request']
            require(matches,'GIT_REQUIRED_CI_MISSING')
            latest=max(matches,key=lambda r:(r.get('run_number',0),r.get('run_attempt',0),r.get('id',0)))
            require(latest.get('status')=='completed' and latest.get('conclusion')=='success','GIT_REQUIRED_CI_NOT_SUCCESSFUL')
            witness.append(dict(workflowId=ident,runId=latest['id'],attempt=latest['run_attempt'],headSha=head))
        return witness

    def prepare(self,request):
        operation=request['operation'];repo=self._access(request['target']);p=request['params']
        if operation=='publish_visual_review':return self._visual_prepare(request)
        if operation in CI_ACTION_NAMES:
            return AnalysisGitHubAdapter.prepare(self,request)
        if operation=='push_commits':
            row=self.artifact(request);task=self.task(repo,p['task'])
            actual=self._ref(repo,task['branch'],allow_not_found=True)
            old=None if actual.get('_httpStatus')==404 else self._sha(actual.get('object',{}).get('sha'))
            if old!=p['expectedHeadSha']:raise Stale('GIT_REMOTE_HEAD_CHANGED')
            return dict(operation=operation,repository=repo,**{k:row[k] for k in (
                'task','branch','baseSha','expectedHeadSha','newSha','bundleSha256','commits','paths',
                'sensitivePaths','sensitivePreview','diffSha256')})
        if operation in ('create_release_label','add_pr_release_labels','remove_pr_release_label'):
            validate_github_action(operation,repo,p)
            if operation!='create_release_label':
                pr=self._api('GET',self._path(repo,'pulls/'+str(p['number'])))
                require(type(pr) is dict and type(pr.get('head')) is dict and
                        type(pr['head'].get('repo')) is dict and
                        pr['head']['repo'].get('full_name')==self.owner+'/'+repo and
                        type(pr.get('base')) is dict and
                        type(pr['base'].get('repo')) is dict and
                        pr['base']['repo'].get('full_name')==self.owner+'/'+repo,
                        'GITHUB_RELEASE_PR_REPOSITORY_DENIED')
                self.task_branch(repo,pr['head'].get('ref'))
            return GitHubAdapter.prepare(self,request)
        require(operation in ('create_pull_request','mark_pr_ready','merge_pull_request','update_pull_request','update_workflow_file'),'GIT_OPERATION_DISABLED')
        if operation=='create_pull_request':
            self.task_branch(repo,p['head']);require(p['base']=='main','GIT_PR_BASE_DENIED')
        elif operation=='update_workflow_file':
            self.task_branch(repo,p['branch'])
        else:
            if operation=='update_pull_request':
                validate_github_action(operation,repo,p)
            raw=self._api('GET',self._path(repo,'pulls/'+str(p['number'])))
            expected=self.config.owner+'/'+repo
            require(raw.get('head',{}).get('repo',{}).get('full_name')==expected and
                    raw.get('base',{}).get('repo',{}).get('full_name')==expected,'GIT_PR_REPOSITORY_MISMATCH')
            pr=self._project_pull(raw);self.task_branch(repo,pr['head']['ref'])
            require(pr['base']['ref']=='main' and pr['state']=='open' and not pr['merged'],'GIT_PR_SCOPE_DENIED')
            if pr['head']['sha']!=p['expectedHeadSha']:raise Stale('GIT_PR_HEAD_CHANGED')
            if operation=='mark_pr_ready':
                require(pr['draft'] is True and type(raw.get('node_id')) is str and
                        re.fullmatch('[A-Za-z0-9_+=/-]{1,240}',raw['node_id']),'GIT_DRAFT_PR_REQUIRED')
                return dict(operation=operation,repository=repo,number=p['number'],head=pr['head'],base=pr['base'],nodeId=raw['node_id'])
            if operation=='update_pull_request':
                return GitHubAdapter.prepare(self,request)
            require(not pr['draft'] and p['mergeMethod']=='merge','GIT_READY_PR_MERGE_REQUIRED')
            ci=(self._dynamic_ci_gate(repo,p['expectedHeadSha'])
                if self.config.dynamic_repositories and repo!=self.config.repository
                else self._ci_gate(repo,p['expectedHeadSha'],pr['head']['ref']))
            return {**GitHubAdapter.prepare(self,request),'requiredCI':ci}
        return GitHubAdapter.prepare(self,request)

    @observe_adapter('GITHUB_ADAPTER')
    def apply(self,request):
        prior=self.receipt(request['requestId'])
        if prior is not None:return prior
        operation=request['operation']
        if operation in CI_ACTION_NAMES:
            self._access(request['target'])
            return AnalysisGitHubAdapter.apply(self,request)
        if operation=='publish_visual_review':return self._visual_apply(request)
        if operation not in ('push_commits','mark_pr_ready'):
            return GitHubAdapter.apply(self,request)
        snapshot=self.prepare(request);repo=request['target'];p=request['params']
        if operation=='push_commits':
            row=self.artifact(request);path=self.workflow.artifacts/(p['artifactSha256']+'.bundle')
            data=path.read_bytes()
            require(hashlib.sha256(data).hexdigest()==p['artifactSha256'],'GIT_ARTIFACT_CHANGED')
            metadata=self.backend.push(repo,self.task(repo,p['task']),p['expectedHeadSha'],p['newSha'],data)
            require(metadata==row,'GIT_ARTIFACT_REVALIDATION_MISMATCH')
            result=dict(requestId=request['requestId'],operation=operation,repository=repo,branch=row['branch'],
                        sha=p['newSha'],bundleSha256=p['artifactSha256'],paths=row['paths'])
        else:
            self.transport.mark_ready(snapshot['nodeId'])
            raw=self._api('GET',self._path(repo,'pulls/'+str(p['number'])));pr=self._project_pull(raw)
            require(not pr['draft'] and pr['head']==snapshot['head'] and pr['base']==snapshot['base'],'GIT_READY_READBACK_UNCONFIRMED')
            result=dict(requestId=request['requestId'],operation=operation,repository=repo,pullRequest=pr)
        self._save_receipt(request['requestId'],result)
        return result


class WorkspaceAdapter:
    """Core DISPATCHED covers the actual worker effect, not merely permit issuance."""
    def __init__(self,*,core,github,store,actor,wait_seconds=90):
        self.core=core;self.github=github;self.store=store;self.actor=actor;self.wait_seconds=wait_seconds

    def _ancestor(self,repo,base,head):
        # Exact immutable SHAs; no branch name or caller-supplied merged flag.
        raw=self.github._api('GET',self.github._path(repo,'compare/'+base+'...'+head),
                             params={'per_page':1},allow_not_found=True)
        require(type(raw) is dict,'WORKSPACE_CLEANUP_COMPARE_INVALID')
        if raw.get('_httpStatus')==404:return False  # Unpublished local head.
        require(raw.get('status') in ('ahead','behind','diverged','identical') and
                type(raw.get('base_commit')) is dict and raw['base_commit'].get('sha')==base and
                type(raw.get('merge_base_commit')) is dict and
                type(raw.get('behind_by')) is int and raw['behind_by']>=0 and
                type(raw.get('ahead_by')) is int and raw['ahead_by']>=0,
                'WORKSPACE_CLEANUP_COMPARE_INVALID')
        forward=(raw['status']=='identical' and base==head and raw['ahead_by']==0 or
                 raw['status']=='ahead' and base!=head and raw['ahead_by']>0)
        return (forward and raw['behind_by']==0 and raw['merge_base_commit'].get('sha')==base)

    def _cleanup_proof(self,repo,p):
        main=self.github._sha(self.github._ref(repo,'main').get('object',{}).get('sha'))
        head=p['expectedHeadSha']
        if self._ancestor(repo,head,main):
            return dict(kind='ancestor',mainSha=main,acceptedSha=head)
        # Squash/rebase do not retain the task HEAD as an ancestor. A closed
        # same-repo PR must retain that exact HEAD and its merge in current main.
        rows=self.github._api('GET',self.github._path(repo,'commits/'+head+'/pulls'),
                              params={'per_page':100,'page':1},allow_not_found=True)
        if type(rows) is dict and rows.get('_httpStatus')==404:rows=[]
        require(type(rows) is list and len(rows)<=100,'WORKSPACE_CLEANUP_PULLS_INVALID')
        full=self.github.config.owner+'/'+repo
        for item in rows:
            require(type(item) is dict and type(item.get('number')) is int and
                    1<=item['number']<=1000000,'WORKSPACE_CLEANUP_PULLS_INVALID')
            raw=self.github._api('GET',self.github._path(repo,'pulls/'+str(item['number'])))
            require(type(raw) is dict,'WORKSPACE_CLEANUP_PULL_INVALID')
            h=raw.get('head');b=raw.get('base');merged=raw.get('merge_commit_sha')
            if not (raw.get('number')==item['number'] and raw.get('state')=='closed' and
                    raw.get('merged') is True and raw.get('draft') is False and
                    type(raw.get('merged_at')) is str and bool(raw['merged_at']) and
                    type(h) is dict and h.get('ref')=='task/'+p['task'] and h.get('sha')==head and
                    type(h.get('repo')) is dict and h['repo'].get('full_name')==full and
                    type(b) is dict and b.get('ref')=='main' and
                    type(b.get('repo')) is dict and b['repo'].get('full_name')==full):continue
            sha(merged)
            if self._ancestor(repo,merged,main):
                return dict(kind='pull_request',mainSha=main,acceptedSha=merged,number=item['number'])
        return dict(kind='unmerged',mainSha=main,acceptedSha=None)

    def cleanup_policy(self,actor,payload):
        if actor!=self.actor:return 'DENY'
        if 'params' not in payload:return 'ASK'  # No blanket ALLOW capability.
        try:
            proof=self.prepare(payload)['cleanup']
            return 'ASK' if proof['kind']=='unmerged' else 'ALLOW'
        except (Denied,Stale,KeyError,TypeError,ValueError):return 'DENY'

    def prepare(self,payload):
        repo=self.github._access(payload['target']);op=payload['operation'];p=payload['params']
        require(op in WORKSPACE_OPS and type(p) is dict,'WORKSPACE_OPERATION_DENIED')
        fields={
          'inspect':{'task'},'fetch':{'ref','expectedSha'},'create_task':{'task','baseSha','adoptHeadSha'},
          'edit':{'task','expectedHeadSha','expectedTreeSha256','changes'},
          'check':{'task','expectedHeadSha','profile'},
          'stage':{'task','expectedHeadSha','expectedTreeSha256','paths'},
          'commit':{'task','expectedHeadSha','expectedIndexSha256','message'},
          'sync_task':{'task','expectedHeadSha','baseSha'},'update_main':{'expectedHeadSha','mergeRequestId'},
          'update_main_from_pr':{'expectedHeadSha','number','expectedPrHeadSha','expectedMergeSha'},
          'cleanup_task':{'task','expectedHeadSha','mergeRequestId'}}
        allowed=(fields[op],{'task','expectedHeadSha'}) if op=='cleanup_task' else (fields[op],)
        require(set(p) in allowed,'WORKSPACE_PARAMS_INVALID')
        snapshot=dict(operation=op,repository=repo,params=p)
        if 'task' in p and p['task'] is not None:
            slug(p['task'])
            if op not in ('inspect','create_task'):snapshot['task']=self.github.task(repo,p['task'])
        elif op not in ('inspect','fetch','update_main','update_main_from_pr'):raise Denied('WORKSPACE_TASK_REQUIRED')
        for key in ('expectedHeadSha','baseSha'):
            if key in p:sha(p[key])
        if op=='fetch':
            require(p['ref']=='main' or re.fullmatch('task/[a-z0-9][a-z0-9-]{0,99}',p['ref']),'WORKSPACE_FETCH_REF_DENIED')
            sha(p['expectedSha'],optional=True)
            ref=self.github._ref(repo,p['ref']);actual=self.github._sha(ref.get('object',{}).get('sha'))
            if p['expectedSha'] is not None and p['expectedSha']!=actual:raise Stale('WORKSPACE_FETCH_HEAD_CHANGED')
            snapshot['remoteSha']=actual
        if op in ('create_task','sync_task'):
            main=self.github._sha(self.github._ref(repo,'main').get('object',{}).get('sha'))
            if main!=p['baseSha']:raise Stale('WORKSPACE_BASE_HEAD_CHANGED')
        if op=='create_task':
            sha(p['adoptHeadSha'],optional=True)
            # Local safety: the worker checks an immutable head and exact task
            # path/branch; it does not copy staged/untracked primary files.
        if op=='check':require(p['profile']=='syntax','WORKSPACE_CHECK_PROFILE_DENIED')
        if op=='edit':
            require(type(p['changes']) is list and 0<len(p['changes'])<=20,'WORKSPACE_EDIT_LIMIT')
            import base64
            total=0
            for change in p['changes']:
                require(type(change) is dict and set(change)=={'path','content','delete','executable'},'WORKSPACE_EDIT_INVALID')
                file_path(change['path'])
                require(type(change['delete']) is bool and type(change['executable']) is bool and type(change['content']) is str,'WORKSPACE_EDIT_INVALID')
                total+=len(base64.b64decode(change['content'],validate=True))
            require(total<=16000 and len({x['path'] for x in p['changes']})==len(p['changes']),'WORKSPACE_EDIT_LIMIT')
        if op=='stage':
            require(type(p['paths']) is list and 0<len(p['paths'])<=64 and len(set(p['paths']))==len(p['paths']),'WORKSPACE_PATHS_INVALID')
            for name in p['paths']:file_path(name)
            require(type(p['expectedTreeSha256']) is str and re.fullmatch('[0-9a-f]{64}',p['expectedTreeSha256']),'WORKSPACE_TREE_DIGEST_INVALID')
        if op=='commit':
            require(type(p['expectedIndexSha256']) is str and re.fullmatch('[0-9a-f]{64}',p['expectedIndexSha256']),'WORKSPACE_INDEX_DIGEST_INVALID')
            require(type(p['message']) is str and 0<len(p['message'].strip())<=500,'WORKSPACE_MESSAGE_INVALID')
        if op=='cleanup_task':
            require(repo!=self.github.config.repository or p['task']!=self.github.config.bootstrap_task,
                    'WORKSPACE_BOOTSTRAP_SOURCE_RETAINED')
            snapshot['cleanup']=self._cleanup_proof(repo,p)
            # Old Repo workers recognize only mergeSha + exact local-main
            # ancestry. They can safely succeed or refuse, never lack the key.
            snapshot['mergeSha']=snapshot['cleanup']['mainSha']
        if op=='update_main_from_pr':
            # Alternative to Gateway-side ASK merge: the owner merged in GitHub UI.
            # Bind to one exact reviewed PR, owner identity, and remote main SHA.
            require(type(p['number']) is int and 1<=p['number']<=1000000,'WORKSPACE_EXTERNAL_PR_NUMBER_INVALID')
            sha(p['expectedPrHeadSha']);sha(p['expectedMergeSha'])
            raw=self.github._api('GET',self.github._path(repo,'pulls/'+str(p['number'])))
            pr=self.github._project_pull(raw)
            expected_full_name=self.github.config.owner+'/'+repo
            require(pr['number']==p['number'] and pr['state']=='closed' and pr['merged'] is True and
                    pr['draft'] is False and pr['base']['ref']=='main' and
                    pr['head']['ref'].startswith('task/') and
                    type(raw.get('head',{}).get('repo')) is dict and
                    raw['head']['repo'].get('full_name')==expected_full_name and
                    type(raw.get('base',{}).get('repo')) is dict and
                    raw['base']['repo'].get('full_name')==expected_full_name,
                    'WORKSPACE_EXTERNAL_PR_NOT_ADMITTED')
            branch(pr['head']['ref'])  # Same-repo registered native task branch only.
            require(pr['head']['sha']==p['expectedPrHeadSha'],'WORKSPACE_EXTERNAL_PR_HEAD_CHANGED')
            require(type(raw.get('merged_at')) is str and bool(raw['merged_at']) and
                    type(raw.get('merged_by')) is dict and
                    raw['merged_by'].get('login')==self.github.config.owner,
                    'WORKSPACE_EXTERNAL_OWNER_MERGE_REQUIRED')
            require(raw.get('merge_commit_sha')==p['expectedMergeSha'],
                    'WORKSPACE_EXTERNAL_MERGE_SHA_CHANGED')
            actual=self.github._sha(self.github._ref(repo,'main').get('object',{}).get('sha'))
            if actual!=p['expectedMergeSha']:raise Stale('WORKSPACE_EXTERNAL_MAIN_CHANGED')
            snapshot['mergeSha']=p['expectedMergeSha']
            snapshot['externalPullNumber']=p['number']
        if op=='update_main' or (op=='cleanup_task' and 'mergeRequestId' in p):
            row=self.core._read(p['mergeRequestId'])
            require(row['actor']==self.actor and row['state']=='EXECUTED' and row['decision']=='approve' and
                row['request']['service']=='github' and row['request']['operation']=='merge_pull_request' and
                row['request']['target']==repo and row['result']['merged'] is True,'WORKSPACE_APPROVED_MERGE_REQUIRED')
            merged=row['result']['sha'];sha(merged)
            if op=='cleanup_task' and row['request']['params']['expectedHeadSha']!=p['expectedHeadSha']:
                raise Stale('WORKSPACE_CLEANUP_HEAD_CHANGED')
            actual=self.github._sha(self.github._ref(repo,'main').get('object',{}).get('sha'))
            if op=='update_main':
                if actual!=merged:raise Stale('WORKSPACE_APPROVED_MAIN_CHANGED')
                snapshot['mergeSha']=merged
        return snapshot

    @observe_adapter('WORKSPACE_ADAPTER')
    def apply(self,payload):
        prior=self.receipt(payload['requestId'])
        if prior is not None:return prior
        snapshot=self.prepare(payload)
        if payload['operation']=='cleanup_task':
            row=self.core._read(payload['requestId'])
            require(row['actor']==self.actor and row['state']=='DISPATCHED' and
                    row['request']==payload,'WORKSPACE_CLEANUP_AUTHORIZATION_REQUIRED')
            if row['preview']!=snapshot:raise Stale('WORKSPACE_CLEANUP_PROOF_CHANGED')
            approved=row['decision']=='approve' and row['owner'] is not None
            require(approved or (row['decision'] is None and snapshot['cleanup']['kind']!='unmerged'),
                    'WORKSPACE_CLEANUP_OWNER_REQUIRED')
            snapshot={**snapshot,'ownerApprovedCleanup':approved}
        self.store.enqueue(self.actor,{**payload,'approvedPreview':snapshot})
        deadline=time.monotonic()+self.wait_seconds
        while time.monotonic()<deadline:
            row=self.store.job(payload['requestId'])
            if row and row['state']=='DONE':return self.receipt(payload['requestId'])
            if row and row['state']=='FAILED':
                if row['error']=='STALE':raise Stale('WORKSPACE_PRECONDITION_FAILED')
                raise RuntimeError('WORKSPACE_LOCAL_OUTCOME_UNCERTAIN')
            time.sleep(.1)
        raise RuntimeError('WORKSPACE_WORKER_NOT_CONFIRMED')

    def receipt(self,ident):
        row=self.store.job(ident)
        if row and row['state']=='DONE':
            payload=json.loads(row['payload'])
            if payload['operation']=='create_task':
                p=payload['params']
                self.store.register(self.actor,payload['target'],p['task'],dict(repository=payload['target'],task=p['task'],branch='task/'+p['task'],baseSha=p['baseSha']))
            elif payload['operation']=='cleanup_task':
                self.store.close_task(self.actor,payload['target'],payload['params']['task'])
            return json.loads(row['result'])
        return None

    def confirm(self,ident,result):
        return type(result) is dict and result.get('requestId')==ident and self.receipt(ident)==result

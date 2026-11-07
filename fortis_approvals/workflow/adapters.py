"""Trusted policies/adapters for native publication and delegated local commands."""
import hashlib
import json
from pathlib import Path
import re
import time
from ..core import Denied, Stale, canonical
from ..integrations.github.gateway.adapter import GitHubAdapter
from ..integrations.github.contract import validate_github_read, validate_github_read_projection
from .common import WORKSPACE_OPS, branch, digest, file_path, require, sha, slug


class NativeGitHubAdapter(GitHubAdapter):
    def __init__(self,transport,*,config,root,actor,backend,store):
        self.config=config;self.actor=actor;self.backend=backend;self.workflow=store
        super().__init__(transport,owner=config.owner,repositories=(config.repository,),receipt_store=Path(root)/'github-receipts.sqlite')
        if config.dynamic_repositories:
            # No second repository allowlist: upstream token determines access.
            # Legacy single-repository mode remains the default until owner rollout.
            self.repositories=None

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
        if not self.config.dynamic_repositories:
            return super().read(request)
        if type(request) is not dict or request.get('service')!='github':
            return super().read(request)
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
        return super().read(request)

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
        if operation=='push_commits':
            row=self.artifact(request);task=self.task(repo,p['task'])
            actual=self._ref(repo,task['branch'],allow_not_found=True)
            old=None if actual.get('_httpStatus')==404 else self._sha(actual.get('object',{}).get('sha'))
            if old!=p['expectedHeadSha']:raise Stale('GIT_REMOTE_HEAD_CHANGED')
            return dict(operation=operation,repository=repo,**{k:row[k] for k in (
                'task','branch','baseSha','expectedHeadSha','newSha','bundleSha256','commits','paths',
                'sensitivePaths','sensitivePreview','diffSha256')})
        require(operation in ('create_pull_request','mark_pr_ready','merge_pull_request','update_workflow_file'),'GIT_OPERATION_DISABLED')
        if operation=='create_pull_request':
            self.task_branch(repo,p['head']);require(p['base']=='main','GIT_PR_BASE_DENIED')
        elif operation=='update_workflow_file':
            self.task_branch(repo,p['branch'])
        else:
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
            require(not pr['draft'] and p['mergeMethod']=='merge','GIT_READY_PR_MERGE_REQUIRED')
            ci=(self._dynamic_ci_gate(repo,p['expectedHeadSha'])
                if self.config.dynamic_repositories and repo!=self.config.repository
                else self._ci_gate(repo,p['expectedHeadSha'],pr['head']['ref']))
            return {**super().prepare(request),'requiredCI':ci}
        return super().prepare(request)

    def apply(self,request):
        prior=self.receipt(request['requestId'])
        if prior is not None:return prior
        operation=request['operation']
        if operation not in ('push_commits','mark_pr_ready'):return super().apply(request)
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
          'cleanup_task':{'task','expectedHeadSha','mergeRequestId'}}
        require(set(p)==fields[op],'WORKSPACE_PARAMS_INVALID')
        snapshot=dict(operation=op,repository=repo,params=p)
        if 'task' in p and p['task'] is not None:
            slug(p['task'])
            if op not in ('inspect','create_task'):snapshot['task']=self.github.task(repo,p['task'])
        elif op not in ('inspect','fetch','update_main'):raise Denied('WORKSPACE_TASK_REQUIRED')
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
        if op=='create_task':sha(p['adoptHeadSha'],optional=True)
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
        if op in ('cleanup_task','update_main'):
            row=self.core._read(p['mergeRequestId'])
            require(row['actor']==self.actor and row['state']=='EXECUTED' and row['decision']=='approve' and
                row['request']['service']=='github' and row['request']['operation']=='merge_pull_request' and
                row['request']['target']==repo and row['result']['merged'] is True,'WORKSPACE_APPROVED_MERGE_REQUIRED')
            merged=row['result']['sha'];sha(merged)
            if op=='cleanup_task' and row['request']['params']['expectedHeadSha']!=p['expectedHeadSha']:
                raise Stale('WORKSPACE_CLEANUP_HEAD_CHANGED')
            actual=self.github._sha(self.github._ref(repo,'main').get('object',{}).get('sha'))
            if actual!=merged:raise Stale('WORKSPACE_APPROVED_MAIN_CHANGED')
            snapshot['mergeSha']=merged
        return snapshot

    def apply(self,payload):
        prior=self.receipt(payload['requestId'])
        if prior is not None:return prior
        snapshot=self.prepare(payload)
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

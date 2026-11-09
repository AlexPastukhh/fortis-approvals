"""Additional closed machine routes. Same TLS, Host, grant and owner separation."""
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import uuid
from threading import BoundedSemaphore
from ..core import ApprovalError, Conflict, Denied, Stale, canonical, loads_strict
from ..repo_ingress import RepoIngress, _PerActorWindow
from .common import MAX_BUNDLE, WORKSPACE_OPS, branch, require, sha, slug
from ..integrations.github.analysis_contract import READ_NAMES as CI_READ_NAMES, ACTION_NAMES as CI_ACTION_NAMES

NATIVE_PATHS=frozenset({'/v1/workspace/submit','/v1/workspace/claim','/v1/workspace/finish',
    '/v1/workspace/result','/v1/workspace/reconcile','/v1/workspace/details','/v1/workspace/capabilities','/v1/git/artifact','/v1/git/fetch'})


class NativeIngress:
    def __init__(self,base,*,github,workspace,store,actor):
        self.base=base;self.broker=base.broker;self.github=github;self.workspace=workspace;self.store=store;self.actor=actor
        self.git_slot=BoundedSemaphore(1)
        import time
        self.limiter=_PerActorWindow(max_requests=600,seconds=60,clock=time.monotonic)
        self.upload_limiter=_PerActorWindow(max_requests=12,seconds=60,clock=time.monotonic)

    def _body(self,env,path):
        require(env.get('CONTENT_TYPE')=='application/json','WORKFLOW_JSON_REQUIRED')
        value=env.get('CONTENT_LENGTH','')
        require(type(value) is str and value.isdecimal() and not value.startswith('0'),'WORKFLOW_LENGTH_INVALID')
        size=int(value);limit=MAX_BUNDLE*4//3+8192 if path=='/v1/git/artifact' else 524288
        require(0<size<=limit,'WORKFLOW_BODY_LIMIT')
        raw=env['wsgi.input'].read(size);require(len(raw)==size,'WORKFLOW_LENGTH_INVALID')
        body=loads_strict(raw);require(type(body) is dict,'WORKFLOW_OBJECT_REQUIRED')
        return body

    def _row(self,credential,ident):
        require(type(ident) is str and str(uuid.UUID(ident))==ident,'WORKFLOW_REQUEST_ID_INVALID')
        return self.broker.core.client(credential,'status',ident)

    def _dispatch(self,path,body,credential,actor):
        core=self.broker.core
        if path=='/v1/workspace/capabilities':
            require(not body,'WORKFLOW_PARAMS_INVALID')
            pr_policy=core._policy(actor,dict(service='github',operation='create_pull_request',target=self.github.config.repository))
            dynamic=getattr(self.github.config,'dynamic_repositories',False)
            require(type(dynamic) is bool,'WORKFLOW_DYNAMIC_FLAG_INVALID')
            return dict(owner=self.github.config.owner,repository=self.github.config.repository,
                dynamicRepositories=dynamic,branchPrefix='task/',workspaceOperations=sorted(WORKSPACE_OPS),
                allowGitHub=['push_commits']+(['create_pull_request'] if pr_policy=='ALLOW' else []),
                askGitHub=(['create_pull_request'] if pr_policy=='ASK' else [])+['mark_pr_ready','merge_pull_request','update_workflow_file'],
                sensitivePush='ASK',gitHubCredentialInRepo=False,
                cleanupTask={'merged':'ALLOW','unmerged':'ASK','proof':'github-main-v1'},
                githubCiReads=sorted(CI_READ_NAMES),
                githubCiControls={'default':'DENY','optIn':'ASK',
                    'repositories':list(getattr(self.github.config,'ci_control_repositories',()))})
        if path=='/v1/git/fetch':
            require(set(body)=={'repository','ref','expectedSha'},'WORKFLOW_PARAMS_INVALID')
            self.github._access(body['repository']);sha(body['expectedSha'],optional=True)
            return self.github.backend.fetch_bundle(body['repository'],body['ref'],body['expectedSha'])
        if path=='/v1/git/artifact':
            require(set(body)=={'repository','task','expectedHeadSha','newSha','bundle'},'WORKFLOW_PARAMS_INVALID')
            repo=self.github._access(body['repository']);task=self.github.task(repo,body['task'])
            sha(body['expectedHeadSha'],optional=True);sha(body['newSha'])
            require(type(body['bundle']) is str and len(body['bundle'])<=MAX_BUNDLE*4//3+4,'GIT_BUNDLE_LIMIT')
            try:data=base64.b64decode(body['bundle'],validate=True)
            except ValueError:raise Denied('GIT_BUNDLE_INVALID') from None
            require(0<len(data)<=MAX_BUNDLE,'GIT_BUNDLE_LIMIT')
            ident=hashlib.sha256(data).hexdigest()
            metadata=self.github.backend.validate(repo,task,body['expectedHeadSha'],body['newSha'],data)
            dest=self.store.artifacts/(ident+'.bundle')
            try:fd=os.open(dest,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
            except FileExistsError:
                require(not dest.is_symlink() and hashlib.sha256(dest.read_bytes()).hexdigest()==ident,'GIT_ARTIFACT_CHANGED')
            else:
                with os.fdopen(fd,'wb') as f:f.write(data);f.flush();os.fsync(f.fileno())
            self.store.save_artifact(actor,ident,metadata)
            return dict(artifactSha256=ident,newSha=metadata['newSha'],branch=metadata['branch'],
                paths=metadata['paths'],policy='ASK' if metadata['sensitivePaths'] else 'ALLOW')
        if path=='/v1/workspace/submit':
            require(set(body)=={'requestId','operation','target','params','reason'},'WORKFLOW_PARAMS_INVALID')
            payload={**body,'service':'workspace','expectedVersion':0}
            row=core.client(credential,'submit',payload)
            return dict(requestId=row['requestId'],state=row['state'])
        if path=='/v1/workspace/claim':
            require(set(body)=={'requestId'},'WORKFLOW_PARAMS_INVALID')
            # Authorization must still be DISPATCHED. An uncertain queued effect is never newly started.
            try:row=self._row(credential,body['requestId'])
            except Denied as exc:
                if str(exc)=='REQUEST_NOT_AVAILABLE':return dict(job=None)
                raise
            if row['request']['service']!='workspace' or row['state']!='DISPATCHED':return dict(job=None)
            return dict(job=self.store.claim(actor,body['requestId']))
        if path=='/v1/workspace/finish':
            require(set(body)=={'requestId','claim','result','error'},'WORKFLOW_PARAMS_INVALID')
            row=self._row(credential,body['requestId'])
            require(row['request']['service']=='workspace' and row['state'] in ('DISPATCHED','UNCERTAIN','EXECUTED','STALE'),'WORKFLOW_JOB_NOT_DISPATCHED')
            require(len(canonical(body['result']).encode())<=524288,'WORKFLOW_RESULT_LIMIT')
            if body['error'] is None:
                r=body['result']
                require(type(r) is dict and r.get('requestId')==body['requestId'] and
                    r.get('operation')==row['request']['operation'] and r.get('repository')==row['request']['target'],'WORKFLOW_RESULT_BINDING_INVALID')
            self.store.finish(actor,body['requestId'],body['claim'],body['result'],body['error'])
            return dict(recorded=True)
        if path=='/v1/workspace/details':
            require(set(body)=={'requestId','eventOffset','eventLimit'},
                    'WORKFLOW_PARAMS_INVALID')
            require(callable(getattr(core,'machine_request_details',None)),
                    'INCIDENT_DETAIL_NOT_SUPPORTED')
            return core.machine_request_details(
                credential,body['requestId'],
                event_offset=body['eventOffset'],event_limit=body['eventLimit'])
        if path in ('/v1/workspace/result','/v1/workspace/reconcile'):
            require(set(body)=={'requestId'},'WORKFLOW_PARAMS_INVALID')
            try:row=self._row(credential,body['requestId'])
            except Denied as exc:
                if str(exc)=='REQUEST_NOT_AVAILABLE':
                    return dict(requestId=body['requestId'],state='NOT_FOUND',result=None,failure=None)
                raise
            require(row['request']['service'] in ('workspace','github'),'WORKFLOW_RESULT_SERVICE_DENIED')
            if path.endswith('/reconcile') and row['state'] in ('DISPATCHED','UNCERTAIN'):
                row=core.reconcile(body['requestId'])
            return dict(requestId=row['requestId'],state=row['state'],result=row['result'],failure=row['failure'])
        raise Denied('WORKFLOW_ROUTE_DENIED')

    def __call__(self,env,start):
        path=env.get('PATH_INFO','')
        if path not in NATIVE_PATHS:return self.base(env,start)
        acquired=False
        try:
            require(self.base._environment(env) and env.get('REQUEST_METHOD')=='POST','WORKFLOW_ROUTE_DENIED')
            credential,actor=self.base._credential(env);require(actor==self.actor,'WORKFLOW_ACTOR_DENIED')
            if not self.limiter.take(actor):return RepoIngress._reply(start,429,dict(error='WORKFLOW_RATE_LIMIT'))
            if path=='/v1/git/artifact' and not self.upload_limiter.take(actor):
                return RepoIngress._reply(start,429,dict(error='WORKFLOW_UPLOAD_RATE_LIMIT'))
            if path.startswith('/v1/git/'):
                acquired=self.git_slot.acquire(blocking=False)
                if not acquired:return RepoIngress._reply(start,429,dict(error='WORKFLOW_GIT_BUSY'))
            result=self._dispatch(path,self._body(env,path),credential,actor)
            return RepoIngress._reply(start,202 if result.get('state')=='PENDING' else 200,result)
        except Conflict:return RepoIngress._reply(start,409,dict(error='WORKFLOW_CONFLICT'))
        except (Denied,Stale):return RepoIngress._reply(start,403,dict(error='WORKFLOW_DENIED'))
        except (ApprovalError,ValueError,KeyError,TypeError,UnicodeError):
            return RepoIngress._reply(start,400,dict(error='WORKFLOW_REQUEST_INVALID'))
        except (OSError,RuntimeError):
            return RepoIngress._reply(start,500,dict(error='WORKFLOW_OUTCOME_UNCONFIRMED'))
        finally:
            if acquired:self.git_slot.release()

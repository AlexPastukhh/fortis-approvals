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
from .common import (MAX_BUNDLE, WORKSPACE_OPS, branch, require, sha, slug,
                     GitCommandFailure, GitCommandTimeout)
from .incident_read import list_uncertain, list_requests, diagnose, diagnose_v2
from ..integrations.github.analysis_contract import READ_NAMES as CI_READ_NAMES, ACTION_NAMES as CI_ACTION_NAMES
from ..diagnostic_contract import advertised_diagnostic_capability
from ..integrations.github.publisher_profile import (ACTOR as PUBLISHER_ACTOR, REPOSITORY as PUBLISHER_REPOSITORY, PublisherProfile)
from ..integrations.github.release_label_evidence import release_label_receipt_matches
from .artifact_diagnostics import (
    bounded_artifact_error, bounded_artifact_phase, ARTIFACT_FAILURE_HEADER)

NATIVE_PATHS=frozenset({'/v1/workspace/submit','/v1/workspace/claim','/v1/workspace/finish',
    '/v1/workspace/result','/v1/workspace/reconcile','/v1/workspace/details','/v1/workspace/list_uncertain','/v1/workspace/list_requests','/v1/workspace/activity','/v1/workspace/heartbeat','/v1/workspace/capabilities','/v1/git/artifact','/v1/git/fetch','/v1/github/visual-review/stage',
    '/v1/powershell/submit','/v1/powershell/result','/v1/powershell/capabilities'})


class NativeIngress:
    def __init__(self,base,*,github,workspace,store,actor,publisher_profile=None):
        self.base=base;self.broker=base.broker;self.github=github;self.workspace=workspace;self.store=store;self.actor=actor
        self.publisher = (getattr(github, "publisher", PublisherProfile())
                          if publisher_profile is None else publisher_profile)
        if type(self.publisher) is not PublisherProfile:
            raise ValueError("GITHUB_PUBLISHER_CONFIG_INVALID")
        self.publisher.validate_composition(self.broker.core, self.broker, actor,
                                            getattr(github, 'config', None))
        # Incident-only ingress has no GitHub adapter. An enabled publisher must
        # still pass full composition; a disabled profile preserves that reader.
        if github is not None:
            self.publisher.bind_guards(self.broker.core, self.broker, github)
        self.git_slot=BoundedSemaphore(1)
        import time
        self.limiter=_PerActorWindow(max_requests=600,seconds=60,clock=time.monotonic)
        self.upload_limiter=_PerActorWindow(max_requests=12,seconds=60,clock=time.monotonic)

    def _body(self,env,path):
        require(env.get('CONTENT_TYPE')=='application/json','WORKFLOW_JSON_REQUIRED')
        value=env.get('CONTENT_LENGTH','')
        require(type(value) is str and value.isdecimal() and not value.startswith('0'),'WORKFLOW_LENGTH_INVALID')
        size=int(value);limit=(MAX_BUNDLE*4//3+8192 if path=='/v1/git/artifact' else
            10*1024*1024*4//3+8192 if path=='/v1/github/visual-review/stage' else 524288)
        require(0<size<=limit,'WORKFLOW_BODY_LIMIT')
        raw=env['wsgi.input'].read(size);require(len(raw)==size,'WORKFLOW_LENGTH_INVALID')
        body=loads_strict(raw);require(type(body) is dict,'WORKFLOW_OBJECT_REQUIRED')
        return body

    def _row(self,credential,ident):
        require(type(ident) is str and str(uuid.UUID(ident))==ident,'WORKFLOW_REQUEST_ID_INVALID')
        row = self.broker.core.client(credential,'status',ident)
        if self.broker.core.auth.authenticate(credential) == PUBLISHER_ACTOR:
            self.publisher.own_row(row)
        return row

    def _publisher_fetch(self, body):
        require(self.publisher.enabled and self.publisher.registry_delegation,
                'GITHUB_PUBLISHER_DISABLED')
        try:
            self.publisher.validate_composition(self.broker.core, self.broker, self.actor, self.github.config)
        except ValueError:
            raise Denied('GITHUB_PUBLISHER_COMPOSITION_CHANGED') from None
        repo, ref, expected = body['repository'], body['ref'], body['expectedSha']
        require(repo == PUBLISHER_REPOSITORY, 'GITHUB_PUBLISHER_SCOPE_DENIED')
        sha(expected)  # mandatory exact SHA; no provider-selected latest ref
        if ref != 'main':
            self.github.task_branch(repo, ref)  # fail before provider access if unregistered/closed
        self.github._access(repo)
        if ref != 'main':
            rows = self.github._api('GET', self.github._path(repo, 'pulls'), params=dict(
                head=self.github.owner+':'+ref, base='main', state='open', page=1, per_page=2))
            require(type(rows) is list and len(rows) == 1 and type(rows[0]) is dict and
                    type(rows[0].get('number')) is int and 0 < rows[0]['number'] <= 1000000,
                    'GITHUB_PUBLISHER_TASK_PR_REQUIRED')
            pr = self.github._api('GET', self.github._path(repo, 'pulls/'+str(rows[0]['number'])))
            full = self.github.owner+'/'+repo
            require(type(pr) is dict and pr.get('number') == rows[0]['number'] and
                    pr.get('state') == 'open' and pr.get('draft') is False and
                    pr.get('merged') is False and pr.get('merged_at') is None and
                    type(pr.get('head')) is dict and type(pr.get('base')) is dict,
                    'GITHUB_PUBLISHER_TASK_PR_REQUIRED')
            require(pr['head'].get('ref') == ref and pr['head'].get('sha') == expected and
                    pr['base'].get('ref') == 'main' and
                    type(pr['head'].get('repo')) is dict and type(pr['base'].get('repo')) is dict and
                    pr['head']['repo'].get('full_name') == full and
                    pr['base']['repo'].get('full_name') == full,
                    'GITHUB_PUBLISHER_TASK_PR_REQUIRED')
            self.github.task_branch(repo, ref)
        return self.github.backend.fetch_bundle(repo, ref, expected)

    def _dispatch(self,path,body,credential,actor):
        core=self.broker.core
        if path in ('/v1/powershell/submit','/v1/powershell/result',
                    '/v1/powershell/capabilities'):
            from ..powershell_machine import MachinePowerShellAdapter
            adapter=core.adapters.get('powershell')
            configured=(type(adapter) is MachinePowerShellAdapter and
                        adapter.core is core and actor == adapter.actor and
                        core._policy(actor,dict(service='powershell',
                            operation='execute',target=adapter.target))=='ASK')
            if path=='/v1/powershell/capabilities':
                require(not body,'MACHINE_POWERSHELL_PARAMS_DENIED')
                return dict(configured=configured,
                            policy='ASK' if configured else 'DENY',
                            machineExecutionAutoApprove=False,version=1)
            require(configured,'MACHINE_POWERSHELL_DISABLED')
            if path=='/v1/powershell/submit':
                require(set(body)=={'requestId','target','command'},
                        'MACHINE_POWERSHELL_PARAMS_DENIED')
                require(body['target']==adapter.target,
                        'MACHINE_POWERSHELL_TARGET_DENIED')
                payload=dict(requestId=body['requestId'],service='powershell',
                    operation='execute',target=body['target'],
                    params={'command':body['command']},expectedVersion=0,
                    reason='Fortis Repo AI PowerShell request: owner ASK required')
                row=core.client(credential,'submit',payload)
                return dict(requestId=row['requestId'],state=row['state'],
                            fingerprint=row['fingerprint'])
            require(set(body)=={'requestId'},'MACHINE_POWERSHELL_PARAMS_DENIED')
            row=core.client(credential,'status',body['requestId'])
            require(row['request']['service']=='powershell' and
                    row['request']['target']==adapter.target,
                    'MACHINE_POWERSHELL_RESULT_SCOPE_DENIED')
            return dict(requestId=row['requestId'],state=row['state'],
                        result=row['result'],failure=row['failure'])
        if path=='/v1/workspace/capabilities':
            require(not body,'WORKFLOW_PARAMS_INVALID')
            if actor == PUBLISHER_ACTOR:
                available = True
                try:
                    self.publisher.validate_composition(core, self.broker, self.actor, self.github.config)
                except ValueError:
                    available = False
                return self.publisher.capabilities(self.github.config.owner, self.actor, available=available)
            pr_policy=core._policy(actor,dict(service='github',operation='create_pull_request',target=self.github.config.repository))
            visual_policy=core._policy(actor,dict(service='github',operation='publish_visual_review',target='visual-workspace'))
            revision_policy=core._policy(actor,dict(service='github',operation='append_visual_revision',target='visual-workspace'))
            dynamic=getattr(self.github.config,'dynamic_repositories',False)
            require(type(dynamic) is bool,'WORKFLOW_DYNAMIC_FLAG_INVALID')
            return dict(owner=self.github.config.owner,repository=self.github.config.repository,
                dynamicRepositories=dynamic,branchPrefix='task/',workspaceOperations=sorted(WORKSPACE_OPS),
                allowGitHub=['push_commits']+(['create_pull_request'] if pr_policy=='ALLOW' else [])+
                    (['publish_visual_review'] if visual_policy=='ALLOW' else []),
                askGitHub=(['create_pull_request'] if pr_policy=='ASK' else [])+['mark_pr_ready','merge_pull_request','update_pull_request','update_workflow_file',
                     'create_release_label','add_pr_release_labels','remove_pr_release_label']+
                    (['publish_visual_review'] if visual_policy=='ASK' else [])+
                    (['append_visual_revision'] if revision_policy=='ASK' else []),
                githubIssueReads=['list_issues','get_issue','list_issue_comments'],
                githubTargetReads={'version':1,'branch':'repository-access-checked-v1',
                    'pullRequests':'same-repository-head-base-v1'},
                githubReleaseLabelReads=['list_repository_labels','list_pr_labels',
                    'get_pr_release_label_context'],
                githubReleaseImpactReads=['get_pr_release_impact_evidence'],
                githubReleaseLabelWrites={'policy':'ASK','commands':[
                    'create_release_label','add_pr_release_labels','remove_pr_release_label'],
                    'scope':'registered-open-same-repo-task-PR-only',
                    'unknownEffect':'STOP','automaticPublisher':'NOT_ACTIVE'},
                githubIssueMaxPageSize=30,
                visualReview={'repository':'visual-workspace','publishPolicy':visual_policy,
                              'media':'png-only','maxFiles':5,'maxBytesPerFile':10*1024*1024,
                              'attachmentReadback':'markdown-links-only','retryUnknown':'STOP',
                              'appendRevisionPolicy':revision_policy,
                              'appendRevision':'issue-comments-v1-source-gated'},
                sensitivePush='ASK',gitHubCredentialInRepo=False,
                cleanupTask={'merged':'ALLOW','unmerged':'ASK','proof':'github-main-v1'},
                githubCiReads=sorted(CI_READ_NAMES),
                githubCiControls={'default':'DENY','optIn':'ASK',
                    'repositories':list(getattr(self.github.config,'ci_control_repositories',()))},
                incidentInventory={'readOnly':True,'actorScoped':True,
                    'maxPageSize':100,'diagnostic':'evidence-stage-v1'},
                globalRequestInventory={'readOnly':True,'actorScoped':False,
                    'maxPageSize':100,'metadataOnly':True,'supportsHistory':True,
                    'crossActorDetails':True},
                workerActivity={'readOnly':True,'actorScoped':True,'maxPageSize':100,
                                'signal':'heartbeat-observation-v1','quiescenceProof':False},
                workerDiagnostics={'codes':'bounded-class-v1','rawExceptionText':False},
                diagnosticContract=advertised_diagnostic_capability())
        if path=='/v1/github/visual-review/stage':
            require(set(body)=={'requestId','repository','runId','index','name','sha256','data'},
                    'VISUAL_MEDIA_PARAMS_INVALID')
            require(type(body['data']) is str and len(body['data'])<=10*1024*1024*4//3+4,
                    'VISUAL_MEDIA_LIMIT')
            self.github._access(body['repository'])
            try:data=base64.b64decode(body['data'],validate=True)
            except (ValueError,TypeError):raise Denied('VISUAL_MEDIA_INVALID') from None
            # Fail closed on unknown Core request IDs with pending/unconfirmed effects.
            return self.store.stage_visual_png(actor,body['requestId'],body['repository'],
                body['runId'],body['index'],body['name'],body['sha256'],data)
        if path=='/v1/git/fetch':
            require(set(body)=={'repository','ref','expectedSha'},'WORKFLOW_PARAMS_INVALID')
            if actor == PUBLISHER_ACTOR:
                return self._publisher_fetch(body)
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
            require(set(body) in ({'requestId','claim','result','error'},
                                  {'requestId','claim','result','error','diagnostic'}),
                    'WORKFLOW_PARAMS_INVALID')
            row=self._row(credential,body['requestId'])
            require(row['request']['service']=='workspace' and row['state'] in ('DISPATCHED','UNCERTAIN','EXECUTED','STALE'),'WORKFLOW_JOB_NOT_DISPATCHED')
            require(len(canonical(body['result']).encode())<=524288,'WORKFLOW_RESULT_LIMIT')
            if body['error'] is None:
                r=body['result']
                require(type(r) is dict and r.get('requestId')==body['requestId'] and
                    r.get('operation')==row['request']['operation'] and r.get('repository')==row['request']['target'],'WORKFLOW_RESULT_BINDING_INVALID')
            self.store.finish(actor,body['requestId'],body['claim'],body['result'],body['error'],
                              body.get('diagnostic'))
            return dict(recorded=True)
        if path=='/v1/workspace/heartbeat':
            require(set(body)=={'requestId','claim'},'WORKFLOW_PARAMS_INVALID')
            row=self._row(credential,body['requestId'])
            require(row['request']['service']=='workspace','WORKFLOW_HEARTBEAT_SERVICE_DENIED')
            self.store.heartbeat(actor,body['requestId'],body['claim'])
            return dict(observed=True)  # no claim token or other actor metadata
        if path=='/v1/workspace/activity':
            require(set(body)=={'offset','limit'},'WORKFLOW_PARAMS_INVALID')
            require(core.auth.authenticate(credential)==actor,'WORKFLOW_ACTOR_DENIED')
            return self.store.activity(actor,offset=body['offset'],limit=body['limit'])
        if path=='/v1/workspace/list_uncertain':
            require(set(body)=={'offset','limit'},'WORKFLOW_PARAMS_INVALID')
            return list_uncertain(core,credential,offset=body['offset'],limit=body['limit'])
        if path=='/v1/workspace/list_requests':
            require(set(body)=={'offset','limit','unresolvedOnly'},'WORKFLOW_PARAMS_INVALID')
            require(core.auth.authenticate(credential)==actor,'WORKFLOW_ACTOR_DENIED')
            return list_requests(core,credential,offset=body['offset'],limit=body['limit'],
                                 unresolved_only=body['unresolvedOnly'])
        if path=='/v1/workspace/details':
            require(set(body)=={'requestId','eventOffset','eventLimit'},
                    'WORKFLOW_PARAMS_INVALID')
            require(callable(getattr(core,'machine_request_details',None)),
                    'INCIDENT_DETAIL_NOT_SUPPORTED')
            require(core.auth.authenticate(credential)==actor,'WORKFLOW_ACTOR_DENIED')
            if actor == PUBLISHER_ACTOR:
                self._row(credential, body['requestId'])  # own labels only, before global details lookup
            details=core.machine_request_details(
                credential,body['requestId'],
                event_offset=body['eventOffset'],event_limit=body['eventLimit'])
            details['diagnostic']=diagnose(details)
            details['diagnosticV2']=diagnose_v2(details)
            # Core returns a request *record* containing the nested intent.
            # Reading fields on the outer record silently disabled visual evidence.
            record=details.get('request')
            intent=record.get('request') if type(record) is dict else None
            if (type(intent) is dict and intent.get('service')=='github' and
                    intent.get('operation')=='publish_visual_review'):
                details['visualReview']=self.github.visual_evidence(body['requestId'])
            return details
        if path in ('/v1/workspace/result','/v1/workspace/reconcile'):
            require(set(body)=={'requestId'},'WORKFLOW_PARAMS_INVALID')
            try:row=self._row(credential,body['requestId'])
            except Denied as exc:
                if str(exc)=='REQUEST_NOT_AVAILABLE':
                    return dict(requestId=body['requestId'],state='NOT_FOUND',result=None,failure=None)
                raise
            require(row['request']['service'] in ('workspace','github'),'WORKFLOW_RESULT_SERVICE_DENIED')
            if path.endswith('/reconcile') and row['state'] in ('DISPATCHED','UNCERTAIN'):
                if actor == PUBLISHER_ACTOR:
                    intent = row['request']
                    receipt = self.github.receipt(body['requestId'])
                    require(release_label_receipt_matches(intent['operation'], intent['target'],
                            intent['params'], body['requestId'], receipt),
                            'GITHUB_PUBLISHER_POSITIVE_RECEIPT_REQUIRED')
                row=core.reconcile(body['requestId'])
            return dict(requestId=row['requestId'],state=row['state'],result=row['result'],failure=row['failure'])
        raise Denied('WORKFLOW_ROUTE_DENIED')

    def __call__(self,env,start):
        path=env.get('PATH_INFO','')
        if path not in NATIVE_PATHS:return self.base(env,start)
        acquired=False
        try:
            require(self.base._environment(env) and env.get('REQUEST_METHOD')=='POST','WORKFLOW_ROUTE_DENIED')
            credential,actor=self.base._credential(env)
            # All authenticated AI actors may READ a global request inventory
            # or full request details. Every other native route stays scoped to
            # the configured Repo actor (including claim/result/reconcile).
            global_read=path in ('/v1/workspace/list_requests','/v1/workspace/details')
            if actor == PUBLISHER_ACTOR:
                require(path in ('/v1/workspace/capabilities','/v1/workspace/result',
                    '/v1/workspace/reconcile','/v1/workspace/details','/v1/git/fetch'),
                    'WORKFLOW_ACTOR_DENIED')
            else:
                require(actor==self.actor or global_read,'WORKFLOW_ACTOR_DENIED')
            if not self.limiter.take(actor):return RepoIngress._reply(start,429,dict(error='WORKFLOW_RATE_LIMIT'),
                retry_after_seconds=self.limiter.retry_after(actor))
            if (path in ('/v1/git/artifact','/v1/github/visual-review/stage') or
                    actor == PUBLISHER_ACTOR and path == '/v1/git/fetch') and not self.upload_limiter.take(actor):
                return RepoIngress._reply(start,429,dict(error='WORKFLOW_UPLOAD_RATE_LIMIT'),
                    retry_after_seconds=self.upload_limiter.retry_after(actor))
            if path.startswith('/v1/git/'):
                acquired=self.git_slot.acquire(blocking=False)
                if not acquired:return RepoIngress._reply(start,429,dict(error='WORKFLOW_GIT_BUSY'),
                    retry_after_seconds=1)
            result=self._dispatch(path,self._body(env,path),credential,actor)
            return RepoIngress._reply(start,202 if result.get('state')=='PENDING' else 200,result)
        except Conflict:return RepoIngress._reply(start,409,dict(error='WORKFLOW_CONFLICT'))
        except (GitCommandFailure,GitCommandTimeout) as exc:
            if path in ('/v1/git/artifact','/v1/git/fetch'):
                return RepoIngress._reply(start,500,dict(error='WORKFLOW_GIT_FAILED'),
                    diagnostic_contract=True,
                    artifact_diagnostic=bounded_artifact_error(exc),
                    artifact_phase=bounded_artifact_phase(exc),
                    retry_after_seconds=60 if str(exc)=='GIT_RATE_LIMIT_REPORTED' else None)
            return RepoIngress._reply(start,500,dict(error='WORKFLOW_OUTCOME_UNCONFIRMED'))
        except (Denied,Stale) as exc:
            if path=='/v1/git/artifact':
                return RepoIngress._reply(start,403,dict(error='WORKFLOW_DENIED'),
                    diagnostic_contract=True,
                    artifact_diagnostic=bounded_artifact_error(exc),
                    artifact_phase=bounded_artifact_phase(exc))
            return RepoIngress._reply(start,403,dict(error='WORKFLOW_DENIED'))
        except (ApprovalError,ValueError,KeyError,TypeError,UnicodeError):
            return RepoIngress._reply(start,400,dict(error='WORKFLOW_REQUEST_INVALID'))
        except (OSError,RuntimeError):
            return RepoIngress._reply(start,500,dict(error='WORKFLOW_OUTCOME_UNCONFIRMED'))
        finally:
            if acquired:self.git_slot.release()

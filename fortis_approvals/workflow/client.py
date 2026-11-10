"""Workflow client/CLI. Every command uses the authenticated Gateway boundary."""
import argparse
import base64
import hashlib
import json
import sys
from threading import Thread
import time
import uuid

from ..clients.gateway_transport import GatewayTransport
from ..core import Denied
from ..integrations.github.repo_client.client import GitHubClient
from .common import require
from .ingress import NATIVE_PATHS
from .worker import Worker


class WorkflowTransport(GatewayTransport):
    def __init__(self,**kw):
        super().__init__(**kw)
        self.post_paths=self.post_paths|NATIVE_PATHS
        self.max_response_bytes=36*1024*1024
        self.timeout=180


class WorkflowClient:
    def __init__(self,*,gateway,worker):
        self.gateway=gateway;self.worker=worker;self.github=GitHubClient(gateway=gateway)

    def result(self,ident,reconcile=False):
        return self.gateway.post('/v1/workspace/'+('reconcile' if reconcile else 'result'),dict(requestId=ident),accept_202=True)

    def details(self,ident,*,event_offset=0,event_limit=100):
        """Full owner-equivalent request + audit and worker evidence, read-only.

        Scoped by the existing Repo machine grant to requests initiated by
        that actor. No owner cookie, credentials, claim token or retry.
        """
        return self.gateway.post('/v1/workspace/details',
            dict(requestId=ident,eventOffset=event_offset,eventLimit=event_limit))

    def list_uncertain(self, *, offset=0, limit=100):
        """List this machine actor's current UNCERTAIN UUIDs without owner routes.

        The result is paginated. Recheck across concurrent request transitions
        before asserting an exact inventory for a controlled release.
        """
        return self.gateway.post('/v1/workspace/list_uncertain',
            dict(offset=offset,limit=limit))

    def _finish_claim(self, ident, job):
        # A worker exception can happen before its local journal is created, or
        # after an unknown partial effect. Never infer NOT_EXECUTED or replay.
        # Persist the uncertainty with the original claim if Gateway is reachable.
        try:
            result, error = self.worker.execute(job)
        except Exception:
            result, error = None, 'UNCERTAIN'
        # A lost finish acknowledgement must propagate; do not retry finish or
        # claim the job again while its durable outcome is unknown.
        self.gateway.post('/v1/workspace/finish', dict(
            requestId=ident, claim=job['claim'], result=result, error=error))

    def command(self,operation,repository,params,*,request_id,reason,wait_owner=False):
        response={};failure=[]
        def submit():
            try:response.update(self.gateway.post('/v1/workspace/submit',
                dict(requestId=request_id,operation=operation,target=repository,params=params,reason=reason),accept_202=True))
            except Exception as e:failure.append(e)
        thread=Thread(target=submit,daemon=True);thread.start()
        deadline=time.monotonic()+190
        while time.monotonic()<deadline:
            job=self.gateway.post('/v1/workspace/claim',dict(requestId=request_id))['job']
            if job and job.get('payload'):
                self._finish_claim(request_id, job)
                thread.join(timeout=3)
                return self.result(request_id,reconcile=True)
            if not thread.is_alive():
                if failure:raise failure[0]
                if response.get('state')=='UNCERTAIN':return self.result(request_id,reconcile=True)
                if response.get('state')=='PENDING' and not wait_owner:return response
                if response.get('state') not in ('PENDING','APPROVED','DISPATCHED','UNCERTAIN'):
                    return self.result(request_id)
            time.sleep(.15)
        raise Denied('WORKFLOW_WORKER_WAIT_TIMEOUT')

    def resume(self,ident):
        row=self.result(ident)
        if row['state']=='UNCERTAIN':return self.result(ident,reconcile=True)
        if row['state'] in ('EXECUTED','REJECTED','STALE','EXPIRED','REVOKED',
                            'CLOSED_UNCONFIRMED'):return row
        deadline=time.monotonic()+100
        while time.monotonic()<deadline:
            job=self.gateway.post('/v1/workspace/claim',dict(requestId=ident))['job']
            if job and job.get('payload'):
                self._finish_claim(ident, job)
                return self.result(ident,reconcile=True)
            time.sleep(.2)
        return self.result(ident,reconcile=True)

    def update_main_from_pr(self,repository,*,expected_head_sha,number,
                            expected_pr_head_sha,expected_merge_sha,request_id,reason):
        """Owner-merged GitHub PR: prove exact remote PR/main, then local ff-only."""
        return self.command('update_main_from_pr',repository,
            dict(expectedHeadSha=expected_head_sha,number=number,
                 expectedPrHeadSha=expected_pr_head_sha,expectedMergeSha=expected_merge_sha),
            request_id=request_id,reason=reason)

    def cleanup_task(self,repository,task,expected_head_sha,*,request_id,reason,wait_owner=False):
        """Merged clean task: ALLOW; otherwise owner ASK. No remote deletion."""
        return self.command('cleanup_task',repository,
            dict(task=task,expectedHeadSha=expected_head_sha),
            request_id=request_id,reason=reason,wait_owner=wait_owner)

    def publish(self,repository,task,expected_old,new_sha,*,request_id,reason):
        # Existing local commit objects are bundled, never reconstructed from file contents.
        data=self.worker.publish_package(repository,task,expected_old,new_sha,request_id,reason)
        artifact=hashlib.sha256(data).hexdigest()
        prior=self.result(request_id)
        if prior['state']!='NOT_FOUND':
            # Re-entry goes straight to Core's immutable request-ID comparison, never to another push.
            return self.github.push_commits(repository,task,artifact,expected_old,new_sha,
                request_id=request_id,reason=reason)
        uploaded=self.gateway.post('/v1/git/artifact',dict(repository=repository,task=task,
            expectedHeadSha=expected_old,newSha=new_sha,bundle=base64.b64encode(data).decode()))
        require(uploaded['artifactSha256']==hashlib.sha256(data).hexdigest() and uploaded['newSha']==new_sha,
                'WORKFLOW_ARTIFACT_BINDING_MISMATCH')
        return self.github.push_commits(repository,task,uploaded['artifactSha256'],expected_old,new_sha,
            request_id=request_id,reason=reason)


def default_client(endpoint='https://host.docker.internal:19204'):
    gateway=WorkflowTransport(endpoint=endpoint)
    capabilities=gateway.post('/v1/workspace/capabilities',{})
    repo=capabilities['repository']
    dynamic=capabilities.get('dynamicRepositories',False)
    require(type(dynamic) is bool,'WORKFLOW_DYNAMIC_FLAG_INVALID')
    worker=Worker(owner=capabilities['owner'],
        repositories={} if dynamic else {repo:'/workspace/repo/Repos/'+repo},
        worktrees={} if dynamic else {repo:'/workspace/repo/Worktrees/'+repo},gateway=gateway,
        dynamic_repositories=dynamic,repository_root='/workspace/repo/Repos',
        worktree_root='/workspace/repo/Worktrees')
    return WorkflowClient(gateway=gateway,worker=worker)


def main():
    parser=argparse.ArgumentParser(description='Typed worktree workflow; no direct GitHub credential/helper.')
    parser.add_argument('operation')
    parser.add_argument('--request-id',required=True)
    parser.add_argument('--repository',default='fortis-approvals')
    parser.add_argument('--reason',default='Authorized task worktree workflow')
    args=parser.parse_args()
    body=json.load(sys.stdin)
    client=default_client()
    if args.operation=='resume':result=client.resume(args.request_id)
    elif args.operation=='publish':
        result=client.publish(args.repository,body['task'],body['expectedHeadSha'],body['newSha'],
            request_id=args.request_id,reason=args.reason)
    elif args.operation=='result':result=client.result(args.request_id)
    elif args.operation=='details':
        result=client.details(args.request_id,
            event_offset=body.get('eventOffset',0),
            event_limit=body.get('eventLimit',100))
    else:
        result=client.command(args.operation,args.repository,body,request_id=args.request_id,reason=args.reason)
    print(json.dumps(result,sort_keys=True))


if __name__=='__main__':main()

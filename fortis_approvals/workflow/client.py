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
        return self.gateway.post('/v1/workspace/'+('reconcile' if reconcile else 'result'),dict(requestId=ident))

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
                result,error=self.worker.execute(job)
                self.gateway.post('/v1/workspace/finish',dict(requestId=request_id,claim=job['claim'],result=result,error=error))
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
        if row['state'] in ('EXECUTED','REJECTED','STALE','EXPIRED','REVOKED'):return row
        deadline=time.monotonic()+100
        while time.monotonic()<deadline:
            job=self.gateway.post('/v1/workspace/claim',dict(requestId=ident))['job']
            if job and job.get('payload'):
                result,error=self.worker.execute(job)
                self.gateway.post('/v1/workspace/finish',dict(requestId=ident,claim=job['claim'],result=result,error=error))
                return self.result(ident,reconcile=True)
            time.sleep(.2)
        return self.result(ident,reconcile=True)

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
    else:
        result=client.command(args.operation,args.repository,body,request_id=args.request_id,reason=args.reason)
    print(json.dumps(result,sort_keys=True))


if __name__=='__main__':main()

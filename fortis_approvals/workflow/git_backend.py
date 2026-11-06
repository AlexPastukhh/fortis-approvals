"""Gateway native Git object transfer. Fixed GitHub origin; no credentials in Repo."""
from contextlib import contextmanager
import base64
import hashlib
import os
from pathlib import Path
import re
import tempfile
from functools import wraps
from threading import RLock

def serialized(method):
    @wraps(method)
    def call(self,*args,**kwargs):
        with self.lock:return method(self,*args,**kwargs)
    return call

from ..core import Denied, Stale, canonical
from ..integrations.github.gateway.transport import _read_token
from .common import Git, MAX_BUNDLE, MAX_NEW_COMMITS, branch, file_path, require, secure_dir, sha


class GitHubGitBackend:
    def __init__(self, root, *, owner, repositories, token_path='/run/github-token/token'):
        self.root=secure_dir(root);self.owner=owner;self.repositories=frozenset(repositories);self.token_path=token_path
        self.git=Git(self.root/'runner',protocols='https');self.lock=RLock()

    def url(self,repo):
        require(repo in self.repositories,'GIT_REPOSITORY_DENIED')
        require(re.fullmatch('[A-Za-z0-9_.-]{1,100}',self.owner) and re.fullmatch('[A-Za-z0-9_.-]{1,100}',repo),'GIT_REPOSITORY_DENIED')
        return 'https://github.com/'+self.owner+'/'+repo+'.git'

    @contextmanager
    def credentials(self,repo):
        token=_read_token(self.token_path,expected_uid=10001)
        with tempfile.TemporaryDirectory(prefix='git-auth-',dir=self.root) as folder:
            p=Path(folder)/'config'
            header=base64.b64encode(('x-access-token:'+token).encode()).decode()
            text='[http "'+self.url(repo)+'"]\n\textraHeader = Authorization: Basic '+header+'\n'
            fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
            with os.fdopen(fd,'w') as f:f.write(text)
            token=None;header=None;text=None
            yield p

    @serialized
    def refs(self,repo):
        with self.credentials(repo) as config:
            raw=self.git.text(['ls-remote','--heads',self.url(repo)],config=config)
        result={}
        for line in raw.splitlines():
            oid,ref=line.split('\t');sha(oid)
            require(ref.startswith('refs/heads/'),'GIT_REMOTE_REF_INVALID')
            result[ref[11:]]=oid
        return result

    def _init(self,folder):
        bare=Path(folder)/'repo.git'
        self.git.run(['init','--bare',bare])
        return bare

    def _fetch(self,repo,bare,ref,dest,config):
        # Explicit refspec and URL only. No origin, hooks, helper, tags or submodules.
        self.git.run(['-c','protocol.file.allow=never','fetch','--no-tags','--no-write-fetch-head',
                      self.url(repo),'refs/heads/'+ref+':'+dest],cwd=bare,config=config)

    @serialized
    def fetch_bundle(self,repo,ref,expected=None):
        require(ref=='main' or re.fullmatch('task/[a-z0-9][a-z0-9-]{0,99}',ref),'GIT_FETCH_REF_DENIED')
        if expected is not None:sha(expected)
        with tempfile.TemporaryDirectory(prefix='git-fetch-',dir=self.root) as folder,self.credentials(repo) as config:
            bare=self._init(folder)
            self._fetch(repo,bare,ref,'refs/heads/transfer',config)
            head=self.git.text(['rev-parse','refs/heads/transfer'],cwd=bare)
            if expected is not None and head!=expected:raise Stale('GIT_FETCH_HEAD_CHANGED')
            p=Path(folder)/'transfer.bundle'
            self.git.run(['bundle','create',p,'refs/heads/transfer'],cwd=bare)
            require(p.stat().st_size<=MAX_BUNDLE,'GIT_BUNDLE_LIMIT')
            data=p.read_bytes()
            return dict(repository=repo,ref=ref,sha=head,bundleSha256=hashlib.sha256(data).hexdigest(),
                        bundle=base64.b64encode(data).decode())

    @serialized
    def validate(self,repo,task,old,new,data):
        sha(old,optional=True);sha(new);branch(task['branch'])
        require(type(data) is bytes and 0<len(data)<=MAX_BUNDLE,'GIT_BUNDLE_LIMIT')
        with tempfile.TemporaryDirectory(prefix='git-validate-',dir=self.root) as folder,self.credentials(repo) as config:
            bare=self._init(folder);p=Path(folder)/'input.bundle';p.write_bytes(data);p.chmod(0o600)
            # Fetch trusted main first. Any bundle prerequisites must already be in this bare quarantine.
            self._fetch(repo,bare,'main','refs/remotes/verify/main',config)
            main=self.git.text(['rev-parse','refs/remotes/verify/main'],cwd=bare)
            refs=self.refs(repo)
            if refs.get(task['branch'])!=old:raise Stale('GIT_REMOTE_HEAD_CHANGED')
            if old is not None:
                self._fetch(repo,bare,task['branch'],'refs/remotes/verify/task',config)
                if self.git.text(['rev-parse','refs/remotes/verify/task'],cwd=bare)!=old:raise Stale('GIT_REMOTE_HEAD_CHANGED')
            heads=self.git.text(['bundle','list-heads',p],cwd=bare).splitlines()
            require(heads==[new+' refs/heads/'+task['branch']],'GIT_BUNDLE_REF_MISMATCH')
            self.git.run(['bundle','verify',p],cwd=bare)
            self.git.run(['-c','protocol.file.allow=always','fetch','--no-tags','--no-write-fetch-head',
                          p,'refs/heads/'+task['branch']+':refs/heads/candidate'],cwd=bare,
                          protocols='file')
            require(self.git.text(['cat-file','-t',new],cwd=bare)=='commit','GIT_COMMIT_REQUIRED')
            self.git.run(['fsck','--strict','--full','--no-reflogs'],cwd=bare)
            objects=self.git.text(['cat-file','--batch-check','--batch-all-objects'],cwd=bare).splitlines()
            require(len(objects)<=100000 and sum(int(x.rsplit(' ',1)[1]) for x in objects)<=256*1024*1024,'GIT_OBJECT_LIMIT')
            base=old or task['baseSha'];sha(base)
            code,_=self.git.run(['merge-base','--is-ancestor',base,new],cwd=bare,ok=(0,1))
            require(code==0,'GIT_NON_FAST_FORWARD_DENIED')
            commits=self.git.text(['rev-list',new,'^'+base],cwd=bare).splitlines()
            require(0<len(commits)<=MAX_NEW_COMMITS,'GIT_COMMIT_RANGE_LIMIT')
            paths=set();sensitive=set()
            for commit in commits:
                # Inspect every new commit and every merge parent, including reverted intermediate changes.
                raw=self.git.run(['diff-tree','--root','-m','-r','--no-commit-id','--name-only','-z',commit],cwd=bare)[1]
                for item in raw.split(b'\0'):
                    if not item:continue
                    name=file_path(item.decode('utf-8','strict'));paths.add(name)
                    if name=='.github/workflows' or name.startswith('.github/workflows/'):sensitive.add(name)
            require(len(paths)<=1000,'GIT_CHANGED_PATH_LIMIT')
            diff=self.git.run(['diff','--no-ext-diff','--binary',base,new],cwd=bare)[1]
            preview=[]
            for name in sorted(sensitive):
                # Git object reads never check out files or invoke filters.
                code,blob=self.git.run(['show',new+':'+name],cwd=bare,ok=(0,128))
                if code:content=None
                else:
                    require(len(blob)<=64000,'GIT_WORKFLOW_PREVIEW_LIMIT')
                    content=blob.decode('utf-8','strict')
                preview.append(dict(path=name,after=content))
            require(len(canonical(preview).encode())<=200000,'GIT_WORKFLOW_PREVIEW_LIMIT')
            return dict(repository=repo,task=task['task'],branch=task['branch'],baseSha=task['baseSha'],
                expectedHeadSha=old,newSha=new,bundleSha256=hashlib.sha256(data).hexdigest(),commits=commits,
                paths=sorted(paths),sensitivePaths=sorted(sensitive),sensitivePreview=preview,
                diffSha256=hashlib.sha256(diff).hexdigest())

    @serialized
    def push(self,repo,task,old,new,data):
        # Revalidate the bundle and ancestry. The explicit lease is CAS, never permission to rewrite history.
        metadata=self.validate(repo,task,old,new,data)
        with tempfile.TemporaryDirectory(prefix='git-push-',dir=self.root) as folder,self.credentials(repo) as config:
            bare=self._init(folder);p=Path(folder)/'input.bundle';p.write_bytes(data);p.chmod(0o600)
            self._fetch(repo,bare,'main','refs/remotes/verify/main',config)
            if old is not None:self._fetch(repo,bare,task['branch'],'refs/remotes/verify/task',config)
            self.git.run(['-c','protocol.file.allow=always','fetch','--no-tags','--no-write-fetch-head',
                          p,'refs/heads/'+task['branch']+':refs/heads/candidate'],cwd=bare,protocols='file')
            base=old or task['baseSha']
            require(self.git.run(['merge-base','--is-ancestor',base,new],cwd=bare,ok=(0,1))[0]==0,'GIT_NON_FAST_FORWARD_DENIED')
            lease='--force-with-lease=refs/heads/'+task['branch']+':'+(old or '')
            self.git.run(['push','--porcelain','--no-follow-tags',lease,self.url(repo),
                          new+':refs/heads/'+task['branch']],cwd=bare,config=config,timeout=80)
            if self.refs(repo).get(task['branch'])!=new:raise RuntimeError('GIT_PUSH_READBACK_UNCONFIRMED')
            return metadata

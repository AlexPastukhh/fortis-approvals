"""Repo-local typed executor. No provider network, credentials or arbitrary shell."""
import base64
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import stat
import tempfile

from ..core import Denied, Stale, canonical
from .common import Git, digest, file_path, repository_lock, require, secure_dir, sha, slug


class Worker:
    def __init__(self, *, owner, repositories, worktrees, gateway):
        self.owner=owner;self.repositories={k:Path(v) for k,v in repositories.items()}
        self.worktrees={k:Path(v) for k,v in worktrees.items()};self.gateway=gateway

    def _open(self,repo):
        require(repo in self.repositories and repo in self.worktrees,'WORKER_REPOSITORY_DENIED')
        root=self.repositories[repo];require(root.is_absolute() and root==root.resolve() and
            root.is_dir() and not root.is_symlink() and (root/'.git').is_dir() and not (root/'.git').is_symlink(),'WORKER_PRIMARY_INVALID')
        state=secure_dir(root/'.git'/'fortis-workflow-worker')
        git=Git(state/'runner')
        def run(args,cwd=None,ok=(0,)):
            # Disable repository-configured filters in addition to global hooks/helpers.
            _,raw=git.run(['config','--name-only','--get-regexp',r'^filter\..*\.(clean|smudge|process|required)$'],cwd=root,ok=(0,1))
            extra=[]
            for key in raw.decode('utf-8','strict').splitlines():
                require(0<len(key)<=240 and '\0' not in key and '\n' not in key,'WORKER_FILTER_CONFIG_INVALID')
                extra+=['-c',key+'='+('false' if key.endswith('.required') else '')]
            return git.run([*extra,*args],cwd=cwd or root,ok=ok)[1]
        def text(args,cwd=None,ok=(0,)):return run(args,cwd,ok).decode('utf-8','strict').strip()
        common=Path(text(['rev-parse','--path-format=absolute','--git-common-dir'])).resolve()
        require(common==(root/'.git').resolve() and Path(text(['rev-parse','--show-toplevel'])).resolve()==root,'WORKER_COMMON_GIT_DIR_MISMATCH')
        origin=text(['config','--get','remote.origin.url'])
        allowed='https://github.com/'+self.owner+'/'+repo
        require(origin in (allowed,allowed+'.git'),'WORKER_ORIGIN_MISMATCH')
        return root,state,run,text

    @staticmethod
    def _inventory(run,root):
        raw=run(['worktree','list','--porcelain','-z'],root)
        result=[]
        for chunk in raw.split(b'\0\0'):
            if not chunk:continue
            row={}
            for line in chunk.split(b'\0'):
                if not line:continue
                key,_,value=line.partition(b' ')
                row[key.decode()]=value.decode('utf-8','strict')
            result.append(row)
        return result

    def _target(self,repo,task,root,run,text,*,existing=True):
        if task is None:return root
        slug(task);parent=self.worktrees[repo]
        require(parent.is_absolute() and parent==parent.resolve() and parent.is_dir(),'WORKER_WORKTREE_ROOT_INVALID')
        path=parent/task
        require(not path.is_symlink() and path.parent==parent,'WORKER_WORKTREE_PATH_INVALID')
        if existing:
            rows=self._inventory(run,root)
            row=next((x for x in rows if Path(x.get('worktree','')).resolve()==path),None)
            require(row and row.get('branch')=='refs/heads/task/'+task and not row.get('bare') and 'locked' not in row,'WORKER_REGISTERED_WORKTREE_REQUIRED')
            require(path.is_dir() and Path(text(['rev-parse','--path-format=absolute','--git-common-dir'],path)).resolve()==(root/'.git').resolve() and
                Path(text(['rev-parse','--show-toplevel'],path)).resolve()==path,'WORKER_COMMON_GIT_DIR_MISMATCH')
        return path

    @staticmethod
    def _safe_path(root,name):
        file_path(name);path=root/name
        require(path.parent.resolve().is_relative_to(root.resolve()),'WORKER_PATH_ESCAPE')
        return path

    def _snapshot(self,repo,task,root,run,text):
        target=self._target(repo,task,root,run,text)
        head=text(['rev-parse','HEAD'],target);current=text(['symbolic-ref','--short','HEAD'],target)
        require(current==('main' if task is None else 'task/'+task),'WORKER_BRANCH_MISMATCH')
        status=run(['status','--porcelain=v1','-z','--untracked-files=all'],target)
        diff=run(['diff','--no-ext-diff','--no-textconv','--binary','HEAD','--'],target)
        raw=run(['ls-files','--others','--exclude-standard','-z'],target)
        names=[x.decode('utf-8','strict') for x in raw.split(b'\0') if x]
        require(len(names)<=500,'WORKER_UNTRACKED_LIMIT')
        untracked={}
        for name in names:
            p=self._safe_path(target,name)
            if p.is_symlink():content=os.readlink(p).encode()
            else:
                require(p.is_file() and p.stat().st_size<=32*1024*1024,'WORKER_UNTRACKED_FILE_LIMIT')
                content=p.read_bytes()
            untracked[name]=dict(sha256=hashlib.sha256(content).hexdigest(),mode=stat.S_IMODE(p.lstat().st_mode))
        index=Path(text(['rev-parse','--path-format=absolute','--git-path','index'],target))
        require(index.resolve().is_relative_to((root/'.git').resolve()) and not index.is_symlink(),'WORKER_INDEX_PATH_INVALID')
        indexhash=hashlib.sha256(index.read_bytes() if index.exists() else b'').hexdigest()
        tree=digest(dict(head=head,index=indexhash,status=base64.b64encode(status).decode(),diff=hashlib.sha256(diff).hexdigest(),untracked=untracked))
        return dict(headSha=head,branch=current,clean=not bool(status),indexSha256=indexhash,treeSha256=tree,
            status=base64.b64encode(status).decode(),diff=diff[:65536].decode('utf-8','replace'),diffTruncated=len(diff)>65536,
            untracked=untracked)

    def _fetch(self,repo,root,ref,expected,run,text):
        out=self.gateway.post('/v1/git/fetch',dict(repository=repo,ref=ref,expectedSha=expected))
        require(out.get('repository')==repo and out.get('ref')==ref and out.get('sha')==expected,'WORKER_FETCH_BINDING_MISMATCH')
        data=base64.b64decode(out['bundle'],validate=True)
        require(hashlib.sha256(data).hexdigest()==out['bundleSha256'],'WORKER_FETCH_BUNDLE_CHANGED')
        with tempfile.TemporaryDirectory(prefix='fetch-',dir=root/'.git'/'fortis-workflow-worker') as folder:
            p=Path(folder)/'fetch.bundle';p.write_bytes(data);p.chmod(0o600)
            require(text(['bundle','list-heads',p])==expected+' refs/heads/transfer','WORKER_FETCH_REF_MISMATCH')
            run(['bundle','verify',p])
            run(['fetch','--no-tags','--no-write-fetch-head',p,'refs/heads/transfer:refs/remotes/origin/'+ref])
        require(text(['rev-parse','refs/remotes/origin/'+ref])==expected,'WORKER_FETCH_READBACK_MISMATCH')
        return dict(ref=ref,sha=expected,bundleSha256=out['bundleSha256'])

    def _prepare(self,job,root,run,text):
        repo=job['target'];op=job['operation'];p=job['params'];task=p.get('task')
        if op in ('edit','check','stage','commit','sync_task','cleanup_task','update_main'):
            s=self._snapshot(repo,None if op=='update_main' else task,root,run,text)
            if s['headSha']!=p['expectedHeadSha']:raise Stale('WORKER_HEAD_CHANGED')
            if op in ('stage','edit') and s['treeSha256']!=p['expectedTreeSha256']:raise Stale('WORKER_TREE_CHANGED')
            if op=='commit' and s['indexSha256']!=p['expectedIndexSha256']:raise Stale('WORKER_INDEX_CHANGED')
            if op in ('sync_task','update_main','cleanup_task') and not s['clean']:raise Stale('WORKER_CLEAN_TREE_REQUIRED')
        if op=='edit':
            target=self._target(repo,task,root,run,text)
            for change in p['changes']:
                path=self._safe_path(target,change['path'])
                require(not path.is_symlink() and (not path.exists() or path.is_file()),'WORKER_EDIT_FILE_INVALID')
        if op=='sync_task':
            require(not run(['config','--get-regexp',r'^merge\..*\.driver$'],root,ok=(0,1)),
                    'WORKER_CUSTOM_MERGE_DRIVER_DENIED')
        if op=='create_task':
            primary=self._snapshot(repo,None,root,run,text)
            require(primary['clean'],'WORKER_CLEAN_MAIN_REQUIRED')
            target=self._target(repo,task,root,run,text,existing=False)
            sha(p['baseSha'])
            text(['cat-file','-t',p['baseSha']])
            if p['adoptHeadSha'] is None:
                require(not target.exists(),'WORKER_TASK_PATH_EXISTS')
                require(not text(['branch','--list','task/'+task]),'WORKER_TASK_BRANCH_EXISTS')
            else:
                s=self._snapshot(repo,task,root,run,text)
                require(s['clean'] and s['headSha']==p['adoptHeadSha'],'WORKER_ADOPT_HEAD_MISMATCH')
                require(text(['merge-base',p['baseSha'],s['headSha']],target)==p['baseSha'],'WORKER_ADOPT_BASE_MISMATCH')
        if op=='cleanup_task':
            target=self._target(repo,task,root,run,text)
            ignored=run(['status','--porcelain=v1','--ignored','--untracked-files=all'],target)
            require(not ignored,'WORKER_CLEANUP_WOULD_LOSE_FILES')
            require(text(['rev-parse','HEAD'],root)==job['approvedPreview']['mergeSha'],'WORKER_APPROVED_MAIN_REQUIRED')
            require(text(['merge-base',p['expectedHeadSha'],job['approvedPreview']['mergeSha']],root)==p['expectedHeadSha'],'WORKER_TASK_NOT_MERGED')

    def _execute(self,job,root,run,text):
        repo=job['target'];op=job['operation'];p=job['params'];task=p.get('task')
        target=self._target(repo,task,root,run,text,existing=op!='create_task')
        if op=='inspect':
            value=self._snapshot(repo,task,root,run,text)
            value['worktrees']=self._inventory(run,root)
            return value
        if op=='fetch':return self._fetch(repo,root,p['ref'],job['approvedPreview']['remoteSha'],run,text)
        if op=='create_task':
            if p['adoptHeadSha'] is None:run(['worktree','add','-b','task/'+task,target,p['baseSha']])
            return self._snapshot(repo,task,root,run,text)
        if op=='edit':
            for change in p['changes']:
                path=self._safe_path(target,change['path'])
                if change['delete']:
                    require(path.is_file(),'WORKER_EDIT_DELETE_MISSING')
                    path.unlink()
                else:
                    path.parent.mkdir(parents=True,exist_ok=True)
                    # Recheck after making parents; no symlink traversal.
                    self._safe_path(target,change['path'])
                    fd,tmp=tempfile.mkstemp(prefix='.fortis-edit-',dir=path.parent)
                    try:
                        with os.fdopen(fd,'wb') as f:f.write(base64.b64decode(change['content'],validate=True));f.flush();os.fsync(f.fileno())
                        os.chmod(tmp,0o755 if change['executable'] else 0o644);os.replace(tmp,path)
                    finally:
                        if os.path.exists(tmp):os.unlink(tmp)
            return self._snapshot(repo,task,root,run,text)
        if op=='check':
            import subprocess,sys
            env={'PATH':os.defpath,'HOME':str(root/'.git'/'fortis-workflow-worker'/'runner'/'home'),
                 'GIT_CONFIG_NOSYSTEM':'1','GIT_CONFIG_GLOBAL':str(root/'.git'/'fortis-workflow-worker'/'runner'/'empty.config'),
                 'GIT_TERMINAL_PROMPT':'0','GIT_ALLOW_PROTOCOL':'file'}
            code="""from pathlib import Path
root=Path.cwd().resolve()
files=[p for p in root.rglob('*.py') if '.git' not in p.relative_to(root).parts]
assert len(files)<=2000
total=0
for p in files:
    assert p.is_file() and not p.is_symlink() and p.resolve().is_relative_to(root)
    total+=p.stat().st_size
    assert total<=32*1024*1024
    compile(p.read_bytes(),str(p),'exec')
print(len(files))
"""
            result=subprocess.run([sys.executable,'-I','-B','-c',code],cwd=target,env=env,
                capture_output=True,timeout=90)
            return dict(profile='syntax',passed=result.returncode==0,exitCode=result.returncode,
                        outputSha256=hashlib.sha256(result.stdout+result.stderr).hexdigest())
        if op=='stage':
            for name in p['paths']:self._safe_path(target,name)
            run(['add','--',*p['paths']],target)
            require(text(['rev-parse','HEAD'],target)==p['expectedHeadSha'],'WORKER_STAGE_HEAD_CHANGED')
            return self._snapshot(repo,task,root,run,text)
        if op=='commit':
            run(['commit','-m',p['message']],target)
            parents=text(['rev-list','--parents','-n','1','HEAD'],target).split()
            require(len(parents)>=2 and parents[1]==p['expectedHeadSha'],'WORKER_COMMIT_PARENT_CHANGED')
            return self._snapshot(repo,task,root,run,text)
        if op=='sync_task':
            self._fetch(repo,root,'main',p['baseSha'],run,text)
            run(['merge','--no-edit',p['baseSha']],target)
            return self._snapshot(repo,task,root,run,text)
        if op=='update_main':
            self._fetch(repo,root,'main',job['approvedPreview']['mergeSha'],run,text)
            if text(['rev-parse','HEAD'],root)!=p['expectedHeadSha']:raise Stale('WORKER_MAIN_CHANGED')
            run(['merge','--ff-only',job['approvedPreview']['mergeSha']],root)
            require(text(['rev-parse','HEAD'],root)==job['approvedPreview']['mergeSha'],'WORKER_MAIN_READBACK_CHANGED')
            return self._snapshot(repo,None,root,run,text)
        if op=='cleanup_task':
            run(['worktree','remove',target],root)
            run(['branch','-d','task/'+task],root)
            return dict(task=task,removed=True)
        raise Denied('WORKER_OPERATION_DENIED')

    def execute(self,job):
        payload=job['payload'];repo=payload['target']
        root,state,run,text=self._open(repo)
        with repository_lock(state/'repository.lock'):
            path=state/'receipts.sqlite'
            if not path.exists():
                fd=os.open(path,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600);os.close(fd)
            require(not path.is_symlink() and path.stat().st_mode & 0o777==0o600,'WORKER_JOURNAL_PERMISSIONS')
            with sqlite3.connect(path) as db:
                db.execute('PRAGMA synchronous=FULL')
                db.execute('CREATE TABLE IF NOT EXISTS journal(id TEXT PRIMARY KEY,digest TEXT,state TEXT,result TEXT,error TEXT)')
                fingerprint=digest(payload)
                row=db.execute('SELECT digest,state,result,error FROM journal WHERE id=?',(payload['requestId'],)).fetchone()
                if row:
                    require(row[0]==fingerprint,'WORKER_REQUEST_ID_CONFLICT')
                    if row[1]=='DONE':return json.loads(row[2]),None
                    return None,'STALE' if row[3]=='STALE' else 'UNCERTAIN'
                try:self._prepare(payload,root,run,text)
                except (Denied,Stale):
                    db.execute('INSERT INTO journal VALUES(?,?,?,NULL,?)',(payload['requestId'],fingerprint,'FAILED','STALE'));db.commit()
                    return None,'STALE'
                db.execute('INSERT INTO journal VALUES(?,?,?,NULL,NULL)',(payload['requestId'],fingerprint,'DISPATCHED'));db.commit()
                try:
                    result=dict(requestId=payload['requestId'],operation=payload['operation'],repository=repo,
                        data=self._execute(payload,root,run,text))
                    require(len(canonical(result).encode())<=500000,'WORKER_RESULT_LIMIT')
                except Exception:
                    db.execute("UPDATE journal SET state='FAILED',error='UNCERTAIN' WHERE id=?",(payload['requestId'],));db.commit()
                    return None,'UNCERTAIN'
                db.execute("UPDATE journal SET state='DONE',result=? WHERE id=?",(canonical(result),payload['requestId']));db.commit()
                return result,None

    def publish_package(self,repo,task,old,new,ident,reason):
        import uuid
        require(str(uuid.UUID(ident))==ident,'WORKER_REQUEST_ID_INVALID')
        root,state,run,text=self._open(repo)
        folder=secure_dir(state/'publish')
        metadata=dict(repository=repo,task=task,expectedHeadSha=old,newSha=new,reason=reason)
        with repository_lock(state/'repository.lock'):
            record=folder/(ident+'.json');bundle=folder/(ident+'.bundle')
            if record.exists():
                require(not record.is_symlink() and not bundle.is_symlink(),'WORKER_PUBLISH_JOURNAL_INVALID')
                saved=json.loads(record.read_text())
                require(saved['intent']==metadata,'WORKER_PUBLISH_REQUEST_CONFLICT')
                data=bundle.read_bytes()
                require(hashlib.sha256(data).hexdigest()==saved['bundleSha256'],'WORKER_PUBLISH_BUNDLE_CHANGED')
                return data
            target=self._target(repo,task,root,run,text)
            require(text(['rev-parse','HEAD'],target)==new,'WORKER_PUBLISH_HEAD_CHANGED')
            require(not bundle.exists(),'WORKER_PARTIAL_PUBLISH_PACKAGE_INSPECT')
            run(['bundle','create',bundle,'refs/heads/task/'+task],target)
            bundle.chmod(0o600)
            require(bundle.stat().st_size<=24*1024*1024,'WORKER_BUNDLE_LIMIT')
            data=bundle.read_bytes()
            require(text(['rev-parse','HEAD'],target)==new,'WORKER_PUBLISH_HEAD_CHANGED')
            fd=os.open(record,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
            with os.fdopen(fd,'w') as f:
                f.write(canonical(dict(intent=metadata,bundleSha256=hashlib.sha256(data).hexdigest())));f.flush();os.fsync(f.fileno())
            return data

    def bundle(self,repo,task,expected_head):
        root,state,run,text=self._open(repo)
        with repository_lock(state/'repository.lock'):
            target=self._target(repo,task,root,run,text)
            require(text(['rev-parse','HEAD'],target)==expected_head,'WORKER_PUBLISH_HEAD_CHANGED')
            with tempfile.TemporaryDirectory(prefix='publish-',dir=state) as folder:
                p=Path(folder)/'publish.bundle'
                run(['bundle','create',p,'refs/heads/task/'+task],target)
                require(p.stat().st_size<=24*1024*1024,'WORKER_BUNDLE_LIMIT')
                data=p.read_bytes()
            require(text(['rev-parse','HEAD'],target)==expected_head,'WORKER_PUBLISH_HEAD_CHANGED')
            return data

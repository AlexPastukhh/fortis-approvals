"""Closed workflow names, paths and isolated Git process execution."""
from contextlib import contextmanager
import hashlib
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import tempfile
import time

from ..core import Denied, Stale, canonical

MAX_BUNDLE = 24 * 1024 * 1024
MAX_NEW_COMMITS = 200
WORKSPACE_OPS = frozenset({'inspect','fetch','create_task','edit','check','stage','commit','sync_task','update_main','update_main_from_pr','cleanup_task'})
MUTATING_LOCAL = WORKSPACE_OPS - {'inspect','fetch'}


def require(value, code):
    if not value: raise Denied(code)


def sha(value, optional=False):
    require(optional and value is None or type(value) is str and re.fullmatch('[0-9a-f]{40}',value), 'WORKFLOW_SHA_INVALID')
    return value


def slug(value):
    require(type(value) is str and re.fullmatch('[a-z0-9][a-z0-9-]{0,99}',value), 'WORKFLOW_TASK_INVALID')
    return value


def file_path(value):
    require(type(value) is str and 0 < len(value) <= 240 and not value.startswith('/') and
        '\\' not in value and ':' not in value and all(ord(x)>=32 for x in value), 'WORKFLOW_PATH_INVALID')
    for part in value.split('/'):
        stem=part.split('.')[0].upper()
        require(part not in ('','.','..') and part.lower()!='.git' and not part.endswith((' ','.')) and
            stem not in {'CON','PRN','AUX','NUL',*[f'COM{i}' for i in range(1,10)],*[f'LPT{i}' for i in range(1,10)]}, 'WORKFLOW_PATH_INVALID')
    return value


def branch(value, prefix='task/'):
    require(type(value) is str and value.startswith(prefix) and value==prefix+slug(value[len(prefix):]), 'WORKFLOW_BRANCH_INVALID')
    return value


def digest(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def secure_dir(path):
    path=Path(path)
    require(not path.is_symlink(),'WORKFLOW_DIRECTORY_SYMLINK')
    path.mkdir(mode=0o700,parents=True,exist_ok=True)
    require(path.is_dir() and path.stat().st_uid==os.geteuid() and not path.stat().st_mode & 0o077,'WORKFLOW_DIRECTORY_PERMISSIONS')
    return path


class Git:
    """No shell, inherited credentials, hooks, prompts, tracing, or URL rewriting config."""
    def __init__(self, state, *, protocols='file'):
        self.state=secure_dir(state);self.protocols=protocols
        self.home=secure_dir(self.state/'home');self.hooks=secure_dir(self.state/'empty-hooks')
        self.config=self.state/'empty.config'
        if not self.config.exists():
            fd=os.open(self.config,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600);os.close(fd)

    def run(self, args, *, cwd=None, config=None, data=None, ok=(0,), timeout=40, protocols=None):
        env={'PATH':os.defpath,'HOME':str(self.home),'LANG':'C.UTF-8','LC_ALL':'C.UTF-8',
            'GIT_CONFIG_NOSYSTEM':'1','GIT_CONFIG_GLOBAL':str(config or self.config),
            'GIT_TERMINAL_PROMPT':'0','GIT_ALLOW_PROTOCOL':protocols or self.protocols,
            'GIT_OPTIONAL_LOCKS':'0','GIT_PAGER':'cat'}
        cmd=['git','--no-pager','-c','credential.helper=','-c','core.hooksPath='+str(self.hooks),
            '-c','core.fsmonitor=false','-c','commit.gpgSign=false','-c','submodule.recurse=false',
            '-c','http.followRedirects=false','-c','http.proxy=','-c','http.sslVerify=true',
            '-c','merge.verifySignatures=false','-c','merge.autoStash=false',
            '-c','core.autocrlf=false','-c','pack.threads=1','-c','core.deltaBaseCacheLimit=16m',
            '-c','protocol.ext.allow=never',*map(str,args)]
        with tempfile.TemporaryFile(dir=self.state) as out,tempfile.TemporaryFile(dir=self.state) as err:
            guard="import os,resource,sys;resource.setrlimit(resource.RLIMIT_AS,(402653184,402653184));resource.setrlimit(resource.RLIMIT_FSIZE,(268435456,268435456));resource.setrlimit(resource.RLIMIT_CPU,(80,80));os.execvp(sys.argv[1],sys.argv[1:])"
            p=subprocess.Popen([sys.executable,'-I','-c',guard,*cmd],cwd=cwd,env=env,stdin=subprocess.PIPE if data is not None else subprocess.DEVNULL,
                stdout=out,stderr=err,start_new_session=True)
            try: p.communicate(data,timeout=timeout)
            except subprocess.TimeoutExpired:
                os.killpg(p.pid,signal.SIGKILL);p.wait();raise RuntimeError('GIT_OUTCOME_TIMEOUT') from None
            require(p.returncode in ok,'GIT_COMMAND_FAILED')
            require(out.tell()<=64*1024*1024,'GIT_OUTPUT_LIMIT')
            out.seek(0);return p.returncode,out.read()

    def text(self,args,**kw):
        return self.run(args,**kw)[1].decode('utf-8','strict').strip()


@contextmanager
def repository_lock(path):
    # One lock in the shared Git directory serializes all registered linked worktrees.
    import fcntl
    fd=os.open(path,os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'a+b') as f:
        require(os.fstat(f.fileno()).st_uid==os.geteuid(),'WORKFLOW_LOCK_OWNER_INVALID')
        os.fchmod(f.fileno(),0o600);fcntl.flock(f.fileno(),fcntl.LOCK_EX)
        try:yield
        finally:fcntl.flock(f.fileno(),fcntl.LOCK_UN)

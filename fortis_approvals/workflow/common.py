"""Closed workflow names, paths and isolated Git process execution."""
from contextlib import contextmanager
import hashlib
import logging
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

GIT_FAILURE_CODES = frozenset({
    'GIT_COMMAND_FAILED', 'GIT_OUTCOME_TIMEOUT', 'GIT_PROCESS_SIGNALLED',
    'GIT_AUTH_FAILURE_REPORTED', 'GIT_REMOTE_ACCESS_DENIED',
    'GIT_RATE_LIMIT_REPORTED', 'GIT_TLS_FAILURE_REPORTED',
    'GIT_NETWORK_FAILURE_REPORTED', 'GIT_RESOURCE_FAILURE_REPORTED',
    'GIT_UPSTREAM_HTTP_FAILURE',
})
_git_log = logging.getLogger(__name__)


class GitCommandFailure(Denied):
    """A bounded process observation, never raw stderr or an effect verdict."""
    def __init__(self, code, *, returncode, elapsed_ms):
        if code not in GIT_FAILURE_CODES:
            raise ValueError('GIT_FAILURE_CODE_INVALID')
        self.returncode, self.elapsed_ms = returncode, elapsed_ms
        super().__init__(code)


class GitCommandTimeout(RuntimeError):
    def __init__(self):
        super().__init__('GIT_OUTCOME_TIMEOUT')


def git_failure_code(stderr, returncode):
    """Classify fixed Git/curl reports; unrecognized failures stay unknown.

    The message is examined only inside the runner and is never returned,
    journaled or logged. A reported symptom is not a proven root cause.
    """
    if returncode < 0:
        return 'GIT_PROCESS_SIGNALLED'
    text = stderr[:32768].lower()
    checks = (
        ('GIT_RATE_LIMIT_REPORTED', (b'error: 429', b'too many requests')),
        ('GIT_AUTH_FAILURE_REPORTED', (b'error: 401', b'fatal: authentication failed')),
        ('GIT_REMOTE_ACCESS_DENIED', (b'error: 403',)),
        ('GIT_TLS_FAILURE_REPORTED', (b'ssl certificate problem', b'server certificate verification failed')),
        ('GIT_RESOURCE_FAILURE_REPORTED', (b'no space left on device', b'cannot allocate memory',
             b'out of memory', b'resource temporarily unavailable', b'unable to mmap')),
        ('GIT_UPSTREAM_HTTP_FAILURE', (b'error: 500', b'error: 502', b'error: 503', b'error: 504')),
        ('GIT_NETWORK_FAILURE_REPORTED', (b'could not resolve host:', b'failed to connect to',
             b'connection reset by peer', b'connection timed out', b'curl 56 ', b'curl 92 ',
             b'remote end hung up unexpectedly')),
    )
    for code, patterns in checks:
        if any(pattern in text for pattern in patterns):
            return code
    return 'GIT_COMMAND_FAILED'


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
            started=time.monotonic()
            p=subprocess.Popen([sys.executable,'-I','-c',guard,*cmd],cwd=cwd,env=env,stdin=subprocess.PIPE if data is not None else subprocess.DEVNULL,
                stdout=out,stderr=err,start_new_session=True)
            try: p.communicate(data,timeout=timeout)
            except subprocess.TimeoutExpired:
                os.killpg(p.pid,signal.SIGKILL);p.wait()
                elapsed=max(0,int((time.monotonic()-started)*1000))
                _git_log.error('GIT_COMMAND_DIAGNOSTIC code=%s elapsedMs=%d exitCode=%d',
                               'GIT_OUTCOME_TIMEOUT',elapsed,p.returncode)
                raise GitCommandTimeout() from None
            if p.returncode not in ok:
                err.seek(0)
                code=git_failure_code(err.read(32768),p.returncode)
                elapsed=max(0,int((time.monotonic()-started)*1000))
                _git_log.error('GIT_COMMAND_DIAGNOSTIC code=%s elapsedMs=%d exitCode=%d',
                               code,elapsed,p.returncode)
                raise GitCommandFailure(code,returncode=p.returncode,elapsed_ms=elapsed)
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

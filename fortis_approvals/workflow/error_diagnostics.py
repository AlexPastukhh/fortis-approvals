"""Bounded error categories; never serialize exception messages or traceback.

These describe the Python exception *family*, not a provider root cause or
whether an external effect occurred. No third-party error strings are accepted.
"""
import sqlite3
from functools import wraps

from ..core import Stale, Denied
from ..integrations.github.gateway.transport import GitHubTransportError

ERROR_CODES = frozenset({
    'TIMEOUT', 'CONNECTION', 'PERMISSION', 'NOT_FOUND', 'DATABASE',
    'OPERATING_SYSTEM', 'STALE_PRECONDITION', 'DOMAIN_REJECTION',
    'RUNTIME_ERROR', 'INTERNAL_ERROR', 'UNKNOWN',
    'GITHUB_TRANSPORT_ERROR', 'GITHUB_HTTP_401', 'GITHUB_HTTP_403',
    'GITHUB_HTTP_404', 'GITHUB_HTTP_422',
    'GITHUB_VISUAL_UPLOAD_HTTP_401', 'GITHUB_VISUAL_UPLOAD_HTTP_403',
    'GITHUB_VISUAL_UPLOAD_HTTP_404', 'GITHUB_VISUAL_UPLOAD_HTTP_422',
    'GITHUB_VISUAL_UPLOAD_URL_INVALID', 'GITHUB_VISUAL_UPLOAD_UNCONFIRMED',
})
ERROR_STAGES = frozenset({'WORKSPACE_ADAPTER', 'GITHUB_ADAPTER',
                          'WORKER_EXECUTE', 'WORKER_CLIENT'})


def category(exc):
    """Classify by known exception type alone; do not call str()/repr()."""
    if isinstance(exc, TimeoutError):return 'TIMEOUT'
    if isinstance(exc, ConnectionError):return 'CONNECTION'
    if isinstance(exc, PermissionError):return 'PERMISSION'
    if isinstance(exc, FileNotFoundError):return 'NOT_FOUND'
    if isinstance(exc, sqlite3.Error):return 'DATABASE'
    if isinstance(exc, OSError):return 'OPERATING_SYSTEM'
    # GitHub transport creates fixed, redacted codes. Never forward arbitrary
    # provider exception text (including tokens/URLs) to a machine audit event.
    if isinstance(exc, GitHubTransportError):
        code=exc.args[0] if len(exc.args)==1 else None
        return code if type(code) is str and code in ERROR_CODES else 'GITHUB_TRANSPORT_ERROR'
    # Core subclasses have no external API error-message requirement here.
    if isinstance(exc, Stale):return 'STALE_PRECONDITION'
    if isinstance(exc, Denied):return 'DOMAIN_REJECTION'
    if isinstance(exc, RuntimeError):return 'RUNTIME_ERROR'
    return 'INTERNAL_ERROR'


def evidence(stage, code):
    if type(stage) is not str or stage not in ERROR_STAGES or type(code) is not str or code not in ERROR_CODES:
        raise ValueError('WORKER_DIAGNOSTIC_INVALID')
    return {'stage':stage,'code':code}


def record_adapter_failure(core, request_id, stage, exc):
    """Best-effort bounded Core audit observation; never changes request state.

    The baseline Core implementation and its storage schema are immutable.
    This event captures a typed exception at its *adapter* boundary before
    baseline Core reduces it to REMOTE_OUTCOME_UNCONFIRMED. If audit storage
    itself fails, the original exception is propagated unchanged.
    """
    if core is None or type(request_id) is not str:
        return
    details=evidence(stage, category(exc))
    try:
        with core._db() as db:
            db.execute('BEGIN IMMEDIATE')
            row=db.execute('SELECT state FROM requests WHERE id=?',(request_id,)).fetchone()
            if row is not None and row['state']=='DISPATCHED':
                core._event(db,request_id,'ERROR_OBSERVED',details)
    except Exception:
        # A failed telemetry write cannot change execution or retry policy.
        pass


def observe_adapter(stage):
    """Wrap native apply without changing persistence-pinned Core bytes."""
    evidence(stage,'UNKNOWN')  # validate fixed code-defined stage up front
    def decorate(method):
        @wraps(method)
        def wrapped(self, request):
            try:
                return method(self,request)
            except Exception as exc:
                core=getattr(self,'core',None)
                if core is None:core=getattr(self,'observation_core',None)
                request_id=request.get('requestId') if type(request) is dict else None
                record_adapter_failure(core,request_id,stage,exc)
                raise
        return wrapped
    return decorate

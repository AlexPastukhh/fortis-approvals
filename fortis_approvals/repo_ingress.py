"""Strict WSGI Repo action/status + typed Sonar READ routes; no listener.

The machine request bears a Fortis ingress grant, NEVER the SonarCloud token.
Owner/admin/executor/generic proxy routes are unavailable. Source-only R3 tests
use an isolated localhost server; the Windows A3 synthetic image has no Sonar
reader, and production source/TLS/secret admission remains OPEN.
"""
import json
import re
import threading
import time

from .core import ApprovalError, Conflict, Denied
from .repo_action_contract import validate_intent
from .integrations.github.contract import GITHUB_ACTION_OPERATIONS
from .integrations.github.gateway.transport import GitHubTransportError
from .integrations.github.read_failure_codes import (
    bounded_read_failure_code,valid_read_failure_signal,
    bounded_transport_read_metadata,
    PROVIDER_ROUTE_CLASS_HEADER,PROVIDER_METHOD_CLASS_HEADER,
    PROVIDER_RATE_RESET_HEADER,READ_ROUTE_CLASSES,READ_METHOD_CLASSES)
from .diagnostic_contract import DIAGNOSTIC_VERSION_HEADER, DIAGNOSTIC_VERSION_TEXT
from .workflow.artifact_diagnostics import (
    ARTIFACT_FAILURE_CODES, ARTIFACT_FAILURE_HEADER,
    ARTIFACT_VALIDATION_PHASES, ARTIFACT_PHASE_HEADER)


_ID_PATH = re.compile(r'/v1/requests/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\Z')
_HOST = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.:-]{0,199}\Z')
_AUTH = re.compile(r'Bearer ([A-Za-z0-9._~+/=-]{8,512})\Z')
_ALLOWED_METHODS = frozenset(('POST','GET'))
_PROXY_FIELDS = ('HTTP_X_FORWARDED_FOR','HTTP_X_FORWARDED_HOST',
                 'HTTP_X_FORWARDED_PROTO','HTTP_X_FORWARDED_PORT',
                 'HTTP_FORWARDED','HTTP_X_REAL_IP','HTTP_PROXY_AUTHORIZATION',
                 'HTTP_PROXY_CONNECTION','HTTP_X_HTTP_METHOD_OVERRIDE',
                 'HTTP_X_METHOD_OVERRIDE')


def _unique_json_pairs(pairs):
    data = {}
    for key, value in pairs:
        if key in data:
            raise ValueError('JSON_DUPLICATE_FIELD')
        data[key] = value
    return data


def _bad_constant(_):
    raise ValueError('JSON_NONFINITE_DENIED')


class _PerActorWindow:
    """In-memory defense-in-depth only; not cross-worker/shared rate policy."""
    def __init__(self, *, max_requests, seconds, clock):
        if type(max_requests) is not int or not 1 <= max_requests <= 10000:
            raise ValueError('RATE_LIMIT_INVALID')
        if type(seconds) not in (int,float) or not 1 <= seconds <= 86400:
            raise ValueError('RATE_WINDOW_INVALID')
        self.max_requests = max_requests
        self.seconds = seconds
        self.clock = clock
        self.lock = threading.Lock()
        self.records = {}

    def take(self, actor):
        now = self.clock()
        with self.lock:
            previous = self.records.get(actor, ())
            current = [n for n in previous if now - n < self.seconds]
            if len(current) >= self.max_requests:
                self.records[actor] = current
                return False
            current.append(now)
            self.records[actor] = current
            return True

    def retry_after(self, actor):
        import math
        now = self.clock()
        with self.lock:
            current = [n for n in self.records.get(actor, ()) if now - n < self.seconds]
            return max(1, math.ceil(self.seconds - (now - current[0]))) if current else 1


class RepoIngress:
    """No direct Core/owner HTTP dispatch; broker actions/status/typed reads.

    `allow_http_local_test` is deliberately test-only and checks loopback
    connection metadata. It is NOT a deployment setting to use for live Repo.
    """
    def __init__(self, broker, *, host, max_bytes=8192,
                 max_requests=30, rate_seconds=60, clock=None,
                 allow_http_local_test=False, max_read_response_bytes=65536):
        if type(host) is not str or not _HOST.fullmatch(host):
            raise ValueError('REPO_HOST_INVALID')
        if type(max_bytes) is not int or not 128 <= max_bytes <= 524288:
            raise ValueError('REPO_BODY_LIMIT_INVALID')
        if type(allow_http_local_test) is not bool:
            raise ValueError('REPO_LOCAL_TEST_INVALID')
        if (type(max_read_response_bytes) is not int or
                not 1024 <= max_read_response_bytes <= 262144):
            raise ValueError('REPO_READ_RESPONSE_LIMIT_INVALID')
        if allow_http_local_test and not host.startswith(('localhost:', '127.0.0.1:')):
            raise ValueError('REPO_LOCAL_TEST_HOST_REQUIRED')
        self.broker = broker
        self.host = host
        self.max_bytes = max_bytes
        self.max_read_response_bytes = max_read_response_bytes
        self.allow_http_local_test = allow_http_local_test
        self.limiter = _PerActorWindow(max_requests=max_requests,
                        seconds=rate_seconds,clock=clock or time.monotonic)

    @staticmethod
    def _reply(start, code, content, *, pre_core_validation=False,
               diagnostic_contract=False, artifact_diagnostic=None, artifact_phase=None,
               provider_read_metadata=None, retry_after_seconds=None):
        body = json.dumps(content,ensure_ascii=False,separators=(',',':'),
                          allow_nan=False).encode('utf-8')
        label = {200:'OK',202:'Accepted',400:'Bad Request',401:'Unauthorized',
                 403:'Forbidden',404:'Not Found',409:'Conflict',
                 413:'Content Too Large',429:'Too Many Requests',
                 500:'Internal Server Error'}[code]
        headers=[('Content-Type','application/json; charset=utf-8'),
             ('Content-Length',str(len(body))),('Cache-Control','no-store'),
             ('Pragma','no-cache'),('X-Content-Type-Options','nosniff'),
             ('Referrer-Policy','no-referrer'),('X-Frame-Options','DENY'),
             ('Content-Security-Policy',"default-src 'none'; frame-ancestors 'none'"),
             ('Vary','Authorization')]
        if pre_core_validation:
            # This HTTP attempt was rejected before calling broker/Core.
            # NOT proof of any previous attempt with the same requestId.
            headers.append(('X-Fortis-Admission','PRE_CORE_VALIDATION_REJECTED'))
        if artifact_diagnostic is not None:
            if (type(artifact_diagnostic) is not str or
                    artifact_diagnostic not in ARTIFACT_FAILURE_CODES):
                raise ValueError('ARTIFACT_DIAGNOSTIC_INVALID')
            headers.append((ARTIFACT_FAILURE_HEADER,artifact_diagnostic))
        if artifact_phase is not None:
            if (artifact_diagnostic is None or type(artifact_phase) is not str or
                    artifact_phase not in ARTIFACT_VALIDATION_PHASES):
                raise ValueError('ARTIFACT_PHASE_INVALID')
            headers.append((ARTIFACT_PHASE_HEADER,artifact_phase))
        if provider_read_metadata is not None:
            if (type(provider_read_metadata) is not dict or
                    set(provider_read_metadata) not in (
                        {'routeClass','methodClass'},
                        {'routeClass','methodClass','rateLimitReset'})):
                raise ValueError('GITHUB_READ_METADATA_INVALID')
            # Revalidate at wire edge, no repo/URL/provider text.
            route=provider_read_metadata['routeClass']
            method=provider_read_metadata['methodClass']
            if (type(route) is not str or route not in READ_ROUTE_CLASSES or
                    type(method) is not str or method not in READ_METHOD_CLASSES):
                raise ValueError('GITHUB_READ_METADATA_INVALID')
            headers.append((PROVIDER_ROUTE_CLASS_HEADER,route))
            headers.append((PROVIDER_METHOD_CLASS_HEADER,method))
            if 'rateLimitReset' in provider_read_metadata:
                reset=provider_read_metadata['rateLimitReset']
                if type(reset) is not int or not 946684800<=reset<=4102444800:
                    raise ValueError('GITHUB_READ_RESET_INVALID')
                headers.append((PROVIDER_RATE_RESET_HEADER,str(reset)))
        if type(retry_after_seconds) is int and 1 <= retry_after_seconds <= 604800:
            headers.append(('Retry-After', str(retry_after_seconds)))
        if pre_core_validation or diagnostic_contract:
            headers.append((DIAGNOSTIC_VERSION_HEADER,DIAGNOSTIC_VERSION_TEXT))
        start(f'{code} {label}',headers)
        return [body]

    def _environment(self, env):
        if (env.get('HTTP_HOST') != self.host or env.get('QUERY_STRING') or
                env.get('SCRIPT_NAME') or
                any(env.get(field) for field in _PROXY_FIELDS) or
                any(env.get(field) for field in ('HTTP_COOKIE','HTTP_ORIGIN',
                    'HTTP_REFERER','HTTP_X_FORTIS_CSRF','HTTP_X_FORWARDED_PREFIX')) or
                env.get('HTTP_TRANSFER_ENCODING') or
                env.get('HTTP_CONNECTION','').lower() == 'upgrade'):
            raise Denied('REPO_INGRESS_DENIED')
        if env.get('wsgi.url_scheme') != 'https':
            if not (self.allow_http_local_test and
                    env.get('wsgi.url_scheme') == 'http' and
                    env.get('REMOTE_ADDR') in ('127.0.0.1','::1')):
                raise Denied('REPO_TLS_REQUIRED')
        if env.get('REQUEST_METHOD') not in _ALLOWED_METHODS:
            return False
        return True

    def _credential(self, env):
        header = env.get('HTTP_AUTHORIZATION','')
        match = _AUTH.fullmatch(header) if type(header) is str else None
        if match is None:
            raise Denied('REPO_AUTH_REQUIRED')
        credential = match.group(1)
        # A distinct ingress credential, never the external Sonar bearer.
        actor = self.broker.core.auth.authenticate(credential)
        return credential, actor

    def _body(self, env):
        if env.get('CONTENT_TYPE') != 'application/json':
            raise Denied('REPO_CONTENT_TYPE_DENIED')
        length = env.get('CONTENT_LENGTH')
        if type(length) is not str or not length.isdecimal() or length.startswith('0'):
            raise Denied('REPO_CONTENT_LENGTH_DENIED')
        length = int(length)
        if length > self.max_bytes:
            return None
        if length == 0:
            raise Denied('REPO_CONTENT_LENGTH_DENIED')
        stream = env.get('wsgi.input')
        if stream is None:
            raise Denied('REPO_CONTENT_LENGTH_DENIED')
        raw = stream.read(length)
        if len(raw) != length:
            raise Denied('REPO_CONTENT_LENGTH_DENIED')
        try:
            return json.loads(raw.decode('utf-8'),object_pairs_hook=_unique_json_pairs,
                              parse_constant=_bad_constant)
        except (ValueError,TypeError,UnicodeError,RecursionError):
            raise Denied('REPO_JSON_DENIED') from None

    def __call__(self, env, start):
        is_github_read=False
        try:
            if not self._environment(env):
                return self._reply(start,404,{'error':'ROUTE_NOT_FOUND'})
            method, path = env.get('REQUEST_METHOD'),env.get('PATH_INFO','')
            if not (method == 'POST' and path in ('/v1/actions', '/v1/reads') or
                    method == 'GET' and _ID_PATH.fullmatch(path)):
                return self._reply(start,404,{'error':'ROUTE_NOT_FOUND'})
            credential, actor = self._credential(env)
            if not self.limiter.take(actor):
                return self._reply(start,429,{'error':'REPO_RATE_LIMITED'},
                                   retry_after_seconds=self.limiter.retry_after(actor))
            if method == 'POST':
                action = self._body(env)
                if action is None:
                    return self._reply(start,413,{'error':'REPO_BODY_TOO_LARGE'})
                if path == '/v1/reads':
                    is_github_read=(type(action) is dict and action.get('service')=='github')
                    out = self.broker.read(credential, action)
                    raw = json.dumps(out, ensure_ascii=False, separators=(',', ':'),
                                     allow_nan=False).encode('utf-8')
                    if len(raw) > self.max_read_response_bytes:
                        return self._reply(start,413,
                                           {'error':'REPO_READ_RESPONSE_TOO_LARGE'})
                    return self._reply(start,200,out)
                # Only known GitHub ACTION schemas receive this additive
                # attempt-level marker. Unknown operations and READ sent on
                # WRITE routes retain their established rejection behavior.
                typed_github_action=(type(action) is dict and
                    type(action.get('service')) is str and
                    type(action.get('operation')) is str and
                    (action['service'],action['operation']) in GITHUB_ACTION_OPERATIONS)
                if typed_github_action:
                    try:
                        validate_intent(action)
                    except Denied:
                        # Keep legacy 403 body unchanged. This HTTP attempt
                        # was never passed to broker.submit.
                        return self._reply(start,403,{'error':'REPO_DENIED'},
                            pre_core_validation=True)
                out = self.broker.submit(credential,action)
                return self._reply(start,202 if out['state']=='PENDING' else 200,out)
            # The Python wsgiref server synthesizes CONTENT_TYPE='text/plain'
            # for a bodyless GET even when the HTTP client sends no Content-Type.
            # Reject any actual Content-Length/body; accept CGI's benign default.
            if (env.get('CONTENT_LENGTH') not in (None,'','0') or
                env.get('CONTENT_TYPE') not in (None,'','text/plain')):
                raise Denied('REPO_GET_NO_BODY')
            out = self.broker.status(credential,_ID_PATH.fullmatch(path).group(1))
            return self._reply(start,200,out)
        except Conflict:
            return self._reply(start,409,{'error':'REPO_REQUEST_ID_CONFLICT'})
        except Denied as exc:
            code = 401 if str(exc) in ('REPO_AUTH_REQUIRED','CLIENT_UNAUTHORIZED') else 403
            # Stable public categories; no secrets or upstream response leakage.
            return self._reply(start,code,{'error':'REPO_UNAUTHORIZED' if code==401 else 'REPO_DENIED'})
        except (ApprovalError,ValueError,TypeError,KeyError,UnicodeError):
            return self._reply(start,400,{'error':'REPO_REQUEST_INVALID'})
        except GitHubTransportError as exc:
            if is_github_read:
                # Additive bounded READ-only envelope. Keep HTTP 500 so older
                # Repo clients retain their previous FORTIS_HTTP_500 behavior.
                # Do not confuse this with a local policy 403 or WRITE outcome.
                provider_code=bounded_read_failure_code(exc)
                details={'error':'REPO_GITHUB_READ_FAILED','providerCode':provider_code}
                signal=getattr(exc,'signal',None)
                if valid_read_failure_signal(provider_code,signal):
                    details['signal']=signal
                return self._reply(start,500,details,diagnostic_contract=True,
                    provider_read_metadata=bounded_transport_read_metadata(exc,provider_code),
                    retry_after_seconds=getattr(exc,'retry_after_seconds',None))
            return self._reply(start,500,{'error':'REPO_OUTCOME_UNCONFIRMED'})
        except (OSError,RuntimeError):
            return self._reply(start,500,{'error':'REPO_OUTCOME_UNCONFIRMED'})

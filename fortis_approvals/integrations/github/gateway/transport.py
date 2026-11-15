"""Pinned GitHub REST transport. Gateway-only; no generic URL proxy."""
import json
import math
import os
from pathlib import Path
import re
import ssl
import stat
from urllib import error, request
from urllib.parse import urlencode

from ....core import Denied
from ....clients.retries import seconds_header
from ..read_failure_codes import (
    classify_read_http_signal,bounded_rate_limit_reset,
    safe_read_route_class,safe_write_route_class)

API_ORIGIN = "https://api.github.com"
TOKEN_FILE = "/run/github-token/token"
MAX_RESPONSE_BYTES = 1_048_576
_BASE = r"/repos/[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}"
_ROUTES = (
    ("GET", re.compile(r"/user/repos$")),
    ("GET", re.compile(_BASE + r"$")),
    ("GET", re.compile(_BASE + r"/(branches|commits|pulls|issues|actions/runs)$")),
    ("GET", re.compile(_BASE + r"/branches/[A-Za-z0-9_.%~-]+$")),
    ("GET", re.compile(_BASE + r"/labels$")),
    ("GET", re.compile(_BASE + r"/issues/[1-9][0-9]*/labels$")),
    ("POST", re.compile(_BASE + r"/labels$")),
    ("POST", re.compile(_BASE + r"/issues/[1-9][0-9]*/labels$")),
    ("DELETE", re.compile(_BASE + r"/issues/[1-9][0-9]*/labels/(?:build%3A|release%3A)[a-z0-9-]+$")),
    ("GET", re.compile(_BASE + r"/actions/runs/[1-9][0-9]*$")),
    ("GET", re.compile(_BASE + r"/rules/branches/main$")),
    ("GET", re.compile(_BASE + r"/compare/[0-9a-f]{40}\.\.\.[0-9a-f]{40}$")),
    ("GET", re.compile(_BASE + r"/commits/[0-9a-f]{40}/pulls$")),
    ("GET", re.compile(_BASE + r"/pulls/[1-9][0-9]*$")),
    ("PATCH", re.compile(_BASE + r"/pulls/[1-9][0-9]*$")),
    ("GET", re.compile(_BASE + r"/actions/workflows/[A-Za-z0-9_.-]+$")),
    ("GET", re.compile(_BASE + r"/commits/[A-Za-z0-9_.%~-]+/(check-runs|status)$")),
    ("GET", re.compile(_BASE + r"/git/ref/heads/[A-Za-z0-9_.%~-]+$")),
    ("GET", re.compile(_BASE + r"/git/commits/[0-9a-f]{40}$")),
    ("GET", re.compile(_BASE + r"/contents/[A-Za-z0-9_.%~/-]+$")),
    ("POST", re.compile(_BASE + r"/git/(blobs|trees|commits|refs)$")),
    ("POST", re.compile(_BASE + r"/pulls$")),
    ("POST", re.compile(_BASE + r"/issues$")),
    ("PATCH", re.compile(_BASE + r"/issues/[1-9][0-9]*$")),
    ("GET", re.compile(_BASE + r"/issues/[1-9][0-9]*$")),
    ("GET", re.compile(_BASE + r"/issues/[1-9][0-9]*/comments$")),
    ("POST", re.compile(_BASE + r"/actions/workflows/[A-Za-z0-9_.-]+/dispatches$")),
    ("POST", re.compile(_BASE + r"/actions/runs/[1-9][0-9]*/(rerun|cancel|approve)$")),
    ("PATCH", re.compile(_BASE + r"/git/refs/heads/[A-Za-z0-9_.%~-]+$")),
    ("PUT", re.compile(_BASE + r"/pulls/[1-9][0-9]*/merge$")),
    ("PUT", re.compile(_BASE + r"/contents/[A-Za-z0-9_.%~/-]+$")),
)
_ROUTES += (
    ("GET", re.compile(_BASE + r"/actions/runs/[1-9][0-9]*/attempts/[1-9][0-9]*(?:/jobs)?$")),
    ("GET", re.compile(_BASE + r"/actions/runs/[1-9][0-9]*/artifacts$")),
    ("GET", re.compile(_BASE + r"/actions/jobs/[1-9][0-9]*$")),
    ("GET", re.compile(_BASE + r"/actions/artifacts/[1-9][0-9]*$")),
    ("GET", re.compile(_BASE + r"/check-runs/[1-9][0-9]*(?:/annotations)?$")),
    ("POST", re.compile(_BASE + r"/actions/jobs/[1-9][0-9]*/rerun$")),
    ("POST", re.compile(_BASE + r"/actions/runs/[1-9][0-9]*/rerun-failed-jobs$")),
)
_QUERY_KEYS = frozenset({"head_sha", "event", "branch", "page", "per_page", "state", "head", "base", "ref", "affiliation"})


class GitHubTransportError(RuntimeError):
    """Redacted provider failure; carries only a bounded signal, never headers."""
    def __init__(self, code, *, signal=None, route_class=None,
                 method_class=None, rate_limit_reset=None, retry_after_seconds=None):
        super().__init__(code)
        self.signal=signal
        self.route_class=route_class
        self.method_class=method_class
        self.rate_limit_reset=rate_limit_reset
        self.retry_after_seconds=retry_after_seconds


class _NoRedirect(request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise GitHubTransportError("GITHUB_REDIRECT_DENIED")


def _unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("GITHUB_DUPLICATE_JSON_FIELD")
        result[key] = value
    return result


def _reject_constant(_value):
    raise ValueError("GITHUB_NONFINITE_JSON_DENIED")


def _finite_float(value):
    number = float(value)
    if not math.isfinite(number):
        raise ValueError("GITHUB_NONFINITE_JSON_DENIED")
    return number


def _read_token(path=TOKEN_FILE, *, expected_uid=10001):
    if type(expected_uid) is not int or expected_uid < 0:
        raise Denied("GITHUB_TOKEN_FILE_INSECURE")
    try:
        item = Path(path)
    except (TypeError, ValueError):
        raise Denied("GITHUB_TOKEN_FILE_REQUIRED") from None
    if item != Path(TOKEN_FILE) and expected_uid == 10001:
        raise Denied("GITHUB_TOKEN_PATH_DENIED")
    if not item.is_absolute():
        raise Denied("GITHUB_TOKEN_FILE_REQUIRED")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(item, flags)
    except OSError:
        raise Denied("GITHUB_TOKEN_FILE_REQUIRED") from None
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != expected_uid or
                stat.S_IMODE(info.st_mode) != 0o600 or not 30 <= info.st_size <= 512):
            raise Denied("GITHUB_TOKEN_FILE_INSECURE")
        raw = b""
        while len(raw) <= 512:
            chunk = os.read(fd, 513 - len(raw))
            if not chunk:
                break
            raw += chunk
        if len(raw) != info.st_size:
            raise Denied("GITHUB_TOKEN_FILE_CHANGED")
    finally:
        os.close(fd)
    if raw.endswith(b"\r\n"):
        raw = raw[:-2]
    elif raw.endswith(b"\n"):
        raw = raw[:-1]
    try:
        token = raw.decode("ascii")
    except UnicodeError:
        raise Denied("GITHUB_TOKEN_INVALID") from None
    if not re.fullmatch(r"[A-Za-z0-9_]{30,512}", token):
        raise Denied("GITHUB_TOKEN_INVALID")
    return token


class GitHubHTTPTransport:
    """Fixed api.github.com origin, fixed route catalogue, no redirects."""
    def __init__(self, token, *, timeout=12, opener=None):
        if type(token) is not str or not re.fullmatch(r"[A-Za-z0-9_]{30,512}", token):
            raise Denied("GITHUB_TOKEN_INVALID")
        if type(timeout) not in (int, float) or not 1 <= timeout <= 30:
            raise Denied("GITHUB_TIMEOUT_INVALID")
        self._token = token
        self._timeout = timeout
        self._opener = opener

    @classmethod
    def from_file(cls, path=TOKEN_FILE, *, expected_uid=10001, timeout=12):
        return cls(_read_token(path, expected_uid=expected_uid), timeout=timeout)

    @staticmethod
    def _route_allowed(method, path):
        return (type(method) is str and type(path) is str and
                any(verb == method and pattern.fullmatch(path)
                    for verb, pattern in _ROUTES))

    def mark_ready(self, node_id):
        # One fixed GraphQL mutation; no caller-controlled query, URL or selection.
        if type(node_id) is not str or not re.fullmatch(r"[A-Za-z0-9_+=/-]{1,240}",node_id):
            raise Denied("GITHUB_PR_NODE_INVALID")
        body={"query":"mutation FortisReady($id:ID!){markPullRequestReadyForReview(input:{pullRequestId:$id}){pullRequest{id isDraft}}}",
              "variables":{"id":node_id}}
        outgoing=request.Request(API_ORIGIN+"/graphql",method="POST",
            data=json.dumps(body,separators=(",",":")).encode("ascii"),
            headers={"Authorization":"Bearer "+self._token,"Content-Type":"application/json","Accept":"application/json"})
        opener=self._opener or request.build_opener(request.ProxyHandler({}),
            request.HTTPSHandler(context=ssl.create_default_context()),_NoRedirect())
        try:
            with opener.open(outgoing,timeout=self._timeout) as response:
                if response.status!=200:raise GitHubTransportError("GITHUB_READY_FAILED")
                raw=response.read(MAX_RESPONSE_BYTES+1)
                if len(raw)>MAX_RESPONSE_BYTES:raise GitHubTransportError("GITHUB_READY_FAILED")
                result=json.loads(raw,object_pairs_hook=_unique_pairs,parse_constant=_reject_constant)
                row=result.get("data",{}).get("markPullRequestReadyForReview",{}).get("pullRequest",{})
                if result.get("errors") or row.get("id")!=node_id or row.get("isDraft") is not False:
                    raise GitHubTransportError("GITHUB_READY_FAILED")
        except GitHubTransportError:raise
        except (error.HTTPError,error.URLError,OSError,ValueError,TypeError,AttributeError):
            raise GitHubTransportError("GITHUB_READY_FAILED") from None

    def request(self, method, path, *, params=None, body=None,
                expected_statuses=(200,), allow_not_found=False):
        if not self._route_allowed(method, path):
            raise Denied("GITHUB_HTTP_ROUTE_DENIED")
        if (params is not None and
                (type(params) is not dict or not set(params) <= _QUERY_KEYS or
                 any(type(k) is not str or type(v) not in (str, int) for k, v in params.items()))):
            raise Denied("GITHUB_QUERY_PARAMS_DENIED")
        if body is not None and type(body) is not dict:
            raise Denied("GITHUB_JSON_BODY_REQUIRED")
        encoded_body = None
        if body is not None:
            try:
                encoded_body = json.dumps(
                    body, separators=(",", ":"), ensure_ascii=True,
                    allow_nan=False).encode("ascii")
            except (TypeError, ValueError, UnicodeError, RecursionError):
                raise Denied("GITHUB_JSON_BODY_INVALID") from None
        query = "?" + urlencode(params) if params else ""
        outgoing = request.Request(
            API_ORIGIN + path + query,
            data=encoded_body,
            method=method,
            headers={
                "Authorization": "Bearer " + self._token,
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
                **({"Content-Type": "application/json"} if body is not None else {}),
            },
        )
        opener = self._opener or request.build_opener(
            request.ProxyHandler({}),
            request.HTTPSHandler(context=ssl.create_default_context()),
            _NoRedirect(),
        )
        try:
            with opener.open(outgoing, timeout=self._timeout) as response:
                status = response.status
                if status not in expected_statuses:
                    raise GitHubTransportError("GITHUB_HTTP_UNEXPECTED_STATUS")
                content = response.read(MAX_RESPONSE_BYTES + 1)
                if len(content) > MAX_RESPONSE_BYTES:
                    raise GitHubTransportError("GITHUB_RESPONSE_TOO_LARGE")
                if not content:
                    return {"_httpStatus": status}
                result = json.loads(content, object_pairs_hook=_unique_pairs,
                                    parse_constant=_reject_constant,
                                    parse_float=_finite_float)
                if type(result) not in (dict, list):
                    raise GitHubTransportError("GITHUB_RESPONSE_INVALID")
                return result
        except error.HTTPError as exc:
            status = exc.code
            retry_after = seconds_header(exc.headers)
            signal=classify_read_http_signal(status, exc.headers) if method=='GET' else None
            reset=bounded_rate_limit_reset(status,exc.headers)
            route_class=(safe_read_route_class(method,path) if method=='GET' else
                         safe_write_route_class(method,path))
            exc.close()
            if allow_not_found and status == 404:
                return {"_httpStatus": 404}
            if 300 <= status < 400:
                raise GitHubTransportError("GITHUB_REDIRECT_DENIED") from None
            raise GitHubTransportError("GITHUB_HTTP_" + str(status),signal=signal,
                route_class=route_class,
                method_class=('READ' if method=='GET' else 'WRITE') if route_class else None,
                rate_limit_reset=reset if route_class else None,
                retry_after_seconds=retry_after if method=='GET' else None) from None
        except GitHubTransportError:
            raise
        except (error.URLError, TimeoutError, OSError, UnicodeError,
                ValueError, RecursionError):
            raise GitHubTransportError("GITHUB_UPSTREAM_UNAVAILABLE_OR_INVALID") from None

    def upload_visual_png(self, repository_id, name, data):
        """Dedicated fixed upload destination; no arbitrary caller URL or redirects."""
        if (type(repository_id) is not int or not 0<repository_id<2**63 or
                type(name) is not str or not re.fullmatch(r'[a-zA-Z0-9_.-]{1,100}\.png',name) or
                type(data) is not bytes or not 24<=len(data)<=10*1024*1024 or
                not data.startswith(b'\x89PNG\r\n\x1a\n') or data[12:16]!=b'IHDR'):
            raise Denied('GITHUB_VISUAL_UPLOAD_INVALID')
        url='https://uploads.github.com/user-attachments/assets?'+urlencode({
            'name':name,'content_type':'image/png','repository_id':repository_id})
        outgoing=request.Request(url,data=data,method='POST',headers={
            'Authorization':'Bearer '+self._token,'Accept':'application/json',
            'Content-Type':'image/png'})
        opener=self._opener or request.build_opener(request.ProxyHandler({}),
            request.HTTPSHandler(context=ssl.create_default_context()),_NoRedirect())
        try:
            with opener.open(outgoing,timeout=self._timeout) as response:
                if response.status!=201:raise GitHubTransportError('GITHUB_VISUAL_UPLOAD_STATUS_INVALID')
                raw=response.read(4097)
                if len(raw)>4096:raise GitHubTransportError('GITHUB_VISUAL_UPLOAD_RESPONSE_INVALID')
                item=json.loads(raw,object_pairs_hook=_unique_pairs,parse_constant=_reject_constant)
                url=item.get('url') if type(item) is dict else None
                if (type(url) is not str or not re.fullmatch(
                    r'https://github\.com/user-attachments/assets/[A-Za-z0-9_-]{1,200}',url)):
                    raise GitHubTransportError('GITHUB_VISUAL_UPLOAD_URL_INVALID')
                return url
        except error.HTTPError as exc:
            status=exc.code;exc.close()
            raise GitHubTransportError('GITHUB_VISUAL_UPLOAD_HTTP_'+str(status)) from None
        except GitHubTransportError:raise
        except (error.URLError,TimeoutError,OSError,UnicodeError,ValueError,TypeError):
            raise GitHubTransportError('GITHUB_VISUAL_UPLOAD_UNCONFIRMED') from None

    def redact(self, value):
        value = value.replace(self._token, '[REDACTED]')
        value = re.sub(r'(?i)(authorization\s*[:=]\s*)([^\r\n]+)', r'\1[REDACTED]', value)
        value = re.sub(r'\b(?:gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,}|sq[a-z]_[A-Za-z0-9_]{20,})', '[REDACTED]', value)
        return value

    def download(self, path, *, maximum):
        """Two hops only. API bearer never follows a download redirect."""
        from urllib.parse import urlsplit
        if (type(path) is not str or
                not re.fullmatch(_BASE + r'/(?:actions/jobs/[1-9][0-9]*/logs|actions/artifacts/[1-9][0-9]*/zip)', path)):
            raise Denied('GITHUB_DOWNLOAD_ROUTE_DENIED')
        if type(maximum) is not int or not 1 <= maximum <= 2*1024*1024:
            raise Denied('GITHUB_DOWNLOAD_LIMIT_INVALID')

        class NoFollow(request.HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, headers, newurl):
                return None

        opener = self._opener or request.build_opener(request.ProxyHandler({}),
            request.HTTPSHandler(context=ssl.create_default_context()), NoFollow())
        first = request.Request(API_ORIGIN + path, headers={
            'Authorization': 'Bearer ' + self._token, 'Accept': 'application/vnd.github+json',
            'X-GitHub-Api-Version': '2022-11-28'})
        location = None
        try:
            with opener.open(first, timeout=self._timeout) as response:
                if response.status == 302: location = response.headers.get('Location')
                else: raise GitHubTransportError('GITHUB_DOWNLOAD_REDIRECT_REQUIRED')
        except error.HTTPError as exc:
            if exc.code == 302: location = exc.headers.get('Location')
            exc.close()
            if location is None: raise GitHubTransportError('GITHUB_DOWNLOAD_UNAVAILABLE') from None
        except (error.URLError, OSError, ValueError):
            raise GitHubTransportError('GITHUB_DOWNLOAD_UNAVAILABLE') from None
        try:
            parts = urlsplit(location)
            # Narrow GitHub-owned Azure account names, not arbitrary Azure tenants.
            allowed = re.fullmatch(r'(?:productionresultssa[0-9]+|pipelinesghubeus[0-9]+)\.blob\.core\.windows\.net', parts.hostname or '')
            if (parts.scheme != 'https' or not allowed or parts.port not in (None, 443) or
                    parts.username or parts.password or parts.fragment):
                raise GitHubTransportError('GITHUB_DOWNLOAD_HOST_DENIED')
            second = request.Request(location, headers={'Accept-Encoding': 'identity'})
            with opener.open(second, timeout=self._timeout) as response:
                if response.status != 200: raise GitHubTransportError('GITHUB_DOWNLOAD_UNAVAILABLE')
                content = response.read(maximum + 1)
                if len(content) > maximum: raise GitHubTransportError('GITHUB_DOWNLOAD_TOO_LARGE')
                return content
        except GitHubTransportError:
            raise
        except (error.HTTPError, error.URLError, OSError, ValueError, TypeError):
            raise GitHubTransportError('GITHUB_DOWNLOAD_UNAVAILABLE') from None

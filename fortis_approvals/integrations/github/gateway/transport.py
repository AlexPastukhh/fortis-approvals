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

API_ORIGIN = "https://api.github.com"
TOKEN_FILE = "/run/github-token/token"
MAX_RESPONSE_BYTES = 1_048_576
_BASE = r"/repos/[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}"
_ROUTES = (
    ("GET", re.compile(_BASE + r"$")),
    ("GET", re.compile(_BASE + r"/(branches|commits|pulls|actions/runs)$")),
    ("GET", re.compile(_BASE + r"/actions/runs/[1-9][0-9]*$")),
    ("GET", re.compile(_BASE + r"/pulls/[1-9][0-9]*$")),
    ("GET", re.compile(_BASE + r"/actions/workflows/[A-Za-z0-9_.-]+$")),
    ("GET", re.compile(_BASE + r"/commits/[A-Za-z0-9_.%~-]+/(check-runs|status)$")),
    ("GET", re.compile(_BASE + r"/git/ref/heads/[A-Za-z0-9_.%~-]+$")),
    ("GET", re.compile(_BASE + r"/git/commits/[0-9a-f]{40}$")),
    ("GET", re.compile(_BASE + r"/contents/[A-Za-z0-9_.%~/-]+$")),
    ("POST", re.compile(_BASE + r"/git/(blobs|trees|commits|refs)$")),
    ("POST", re.compile(_BASE + r"/pulls$")),
    ("POST", re.compile(_BASE + r"/actions/workflows/[A-Za-z0-9_.-]+/dispatches$")),
    ("POST", re.compile(_BASE + r"/actions/runs/[1-9][0-9]*/(rerun|cancel|approve)$")),
    ("PATCH", re.compile(_BASE + r"/git/refs/heads/[A-Za-z0-9_.%~-]+$")),
    ("PUT", re.compile(_BASE + r"/pulls/[1-9][0-9]*/merge$")),
    ("PUT", re.compile(_BASE + r"/contents/[A-Za-z0-9_.%~/-]+$")),
)
_QUERY_KEYS = frozenset({"head_sha", "event", "branch","page", "per_page", "state", "head", "base", "ref"})


class GitHubTransportError(RuntimeError):
    """Redacted provider failure; never carries headers or response body."""


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
            exc.close()
            if allow_not_found and status == 404:
                return {"_httpStatus": 404}
            if 300 <= status < 400:
                raise GitHubTransportError("GITHUB_REDIRECT_DENIED") from None
            raise GitHubTransportError("GITHUB_HTTP_" + str(status)) from None
        except GitHubTransportError:
            raise
        except (error.URLError, TimeoutError, OSError, UnicodeError,
                ValueError, RecursionError):
            raise GitHubTransportError("GITHUB_UPSTREAM_UNAVAILABLE_OR_INVALID") from None

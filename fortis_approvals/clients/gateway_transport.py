"""Shared typed HTTPS transport for Fortis Repo -> Approvals Gateway.

This transport authenticates only with the limited machine ingress grant.
It never accepts a provider URL, HTTP method, upstream credential or owner
route. Provider-specific clients validate their own request/response schemas.
"""
import json
import math
import os
from pathlib import Path
import re
import ssl
import stat
from urllib import error, request
from urllib.parse import urlsplit

from ..core import Denied

DEFAULT_ENDPOINT = "https://host.docker.internal:19104"
DEFAULT_CERTIFICATE = "/run/fortis-client/server.crt"
DEFAULT_GRANT = "/run/fortis-client/grant"
MAX_RESPONSE_BYTES = 65536
_STATUS_PATH = re.compile(
    r"/v1/requests/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
)
_POST_PATHS = frozenset({"/v1/reads", "/v1/actions"})
class _NoRedirectHandler(request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _reject_nonfinite(_value):
    raise ValueError("FORTIS_NONFINITE_RESPONSE")


def _parse_finite_float(value):
    number = float(value)
    if not math.isfinite(number):
        raise ValueError("FORTIS_NONFINITE_RESPONSE")
    return number


def _unique_json_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("FORTIS_DUPLICATE_JSON_FIELD")
        result[key] = value
    return result


def read_machine_grant(path=DEFAULT_GRANT):
    item = Path(path)
    if not item.is_absolute() or item.is_symlink() or not item.is_file():
        raise Denied("FORTIS_MACHINE_GRANT_FILE_REQUIRED")
    info = item.stat()
    if (not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600 or
            info.st_uid != os.geteuid() or not 32 <= info.st_size <= 257 or
            any(item.is_relative_to(root) for root in (
                Path("/workspace/repo"), Path("/workspace/repos")))):
        raise Denied("FORTIS_MACHINE_GRANT_FILE_INSECURE")
    data = item.read_bytes()
    if data.endswith(b"\n"):
        data = data[:-1]
    try:
        credential = data.decode("ascii")
    except UnicodeError:
        raise Denied("FORTIS_MACHINE_GRANT_INVALID") from None
    if not re.fullmatch(r"[A-Za-z0-9._~+/=-]{32,256}", credential):
        raise Denied("FORTIS_MACHINE_GRANT_INVALID")
    return credential


class GatewayTransport:
    """POST only to the two typed ingress routes; GET only actor status."""
    def __init__(self, *, endpoint=DEFAULT_ENDPOINT, grant_path=DEFAULT_GRANT,
                 certificate_path=DEFAULT_CERTIFICATE, opener=None, timeout=12,
                 max_response_bytes=MAX_RESPONSE_BYTES, allow_test_endpoint=False):
        parsed = urlsplit(endpoint)
        if type(allow_test_endpoint) is not bool:
            raise Denied("FORTIS_GATEWAY_ENDPOINT_DENIED")
        local_http_test = (parsed.scheme == "http" and parsed.hostname in
                           ("127.0.0.1", "localhost", "::1") and parsed.port is not None)
        pinned_https = (parsed.scheme == "https" and
                        parsed.hostname == "host.docker.internal" and
                        parsed.port == 19104)
        injected_https_test = (allow_test_endpoint and parsed.scheme == "https" and
                               parsed.hostname == "host.docker.internal" and
                               parsed.port is not None)
        if (not (pinned_https or local_http_test or injected_https_test) or parsed.username or
                parsed.password or parsed.query or parsed.fragment or
                parsed.path not in ("", "/")):
            raise Denied("FORTIS_GATEWAY_ENDPOINT_DENIED")
        if type(timeout) not in (int, float) or not 1 <= timeout <= 30:
            raise Denied("FORTIS_GATEWAY_TIMEOUT_INVALID")
        if type(max_response_bytes) is not int or not 1024 <= max_response_bytes <= 262144:
            raise Denied("FORTIS_RESPONSE_LIMIT_INVALID")
        self.endpoint = endpoint.rstrip("/")
        self.grant_path = grant_path
        self.certificate_path = certificate_path
        self.opener = opener
        self.timeout = timeout
        self.max_response_bytes = max_response_bytes

    def _open(self, method, path, payload=None, *, accept_202=False):
        if method == "POST":
            if path not in _POST_PATHS or type(payload) is not dict:
                raise Denied("FORTIS_GATEWAY_ROUTE_DENIED")
        elif method == "GET":
            if payload is not None or not _STATUS_PATH.fullmatch(path):
                raise Denied("FORTIS_GATEWAY_ROUTE_DENIED")
        else:
            raise Denied("FORTIS_GATEWAY_METHOD_DENIED")
        grant = read_machine_grant(self.grant_path)
        cert = Path(self.certificate_path)
        if (not cert.is_absolute() or cert.is_symlink() or not cert.is_file() or
                cert.stat().st_size > 16384):
            raise Denied("FORTIS_TRUSTED_PUBLIC_CERT_REQUIRED")
        parsed = urlsplit(self.endpoint)
        if parsed.scheme == "https":
            context = ssl.create_default_context(cafile=str(cert))
            context.minimum_version = ssl.TLSVersion.TLSv1_3
            opener = self.opener or request.build_opener(
                request.ProxyHandler({}), request.HTTPSHandler(context=context),
                _NoRedirectHandler())
        else:
            # Explicit loopback-only test path; production endpoint is pinned HTTPS.
            opener = self.opener or request.build_opener(
                request.ProxyHandler({}), _NoRedirectHandler())
        raw = (json.dumps(payload, separators=(",", ":"), ensure_ascii=True).encode("ascii")
               if payload is not None else None)
        host_header = ("host.docker.internal:19104" if parsed.hostname == "host.docker.internal" else parsed.netloc)
        headers = {"Host": host_header, "Accept": "application/json",
                   "Authorization": "Bearer " + grant}
        if raw is not None:
            headers["Content-Type"] = "application/json"
        req = request.Request(self.endpoint + path, data=raw, headers=headers,
                              method=method)
        try:
            with opener.open(req, timeout=self.timeout) as response:
                allowed = (response.status == 200 or
                           (accept_202 and response.status == 202))
                if not allowed:
                    raise Denied("FORTIS_HTTP_UNEXPECTED_STATUS")
                content = response.read(self.max_response_bytes + 1)
                if len(content) > self.max_response_bytes:
                    raise Denied("FORTIS_RESPONSE_TOO_LARGE")
                result = json.loads(content, parse_constant=_reject_nonfinite,
                                    parse_float=_parse_finite_float,
                                    object_pairs_hook=_unique_json_pairs)
        except error.HTTPError as exc:
            status = exc.code
            exc.close()
            if 300 <= status < 400:
                raise Denied("FORTIS_REDIRECT_DENIED") from None
            raise Denied("FORTIS_HTTP_" + str(status)) from None
        except Denied:
            raise
        except (error.URLError, TimeoutError, OSError, UnicodeError, ValueError,
                RecursionError):
            raise Denied("FORTIS_UPSTREAM_UNAVAILABLE_OR_INVALID") from None
        if type(result) is not dict:
            raise Denied("FORTIS_RESPONSE_INVALID")
        return result

    def post(self, path, payload, *, accept_202=False):
        return self._open("POST", path, payload, accept_202=accept_202)

    def get_status(self, request_id):
        path = "/v1/requests/" + request_id
        return self._open("GET", path)

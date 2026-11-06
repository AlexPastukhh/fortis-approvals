"""Fixed named JSON routes for trusted provider code. No caller-selected URLs.

No environment proxies, redirects, raw upstream errors or unbounded bodies.
Authentication is injected only inside Gateway from the operation's secret.
"""
from dataclasses import dataclass
import json
import re
import ssl
from urllib import error, request
from urllib.parse import quote, urlencode, urlsplit

from ..core import Denied, canonical, loads_strict
from .model import check, ident


class NoRedirect(request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


@dataclass(frozen=True)
class Route:
    name: str
    method: str
    path: str
    readonly: bool = False
    query_keys: tuple = ()
    idempotency_header: str = None
    statuses: tuple = (200,)

    def __post_init__(self):
        ident(self.name)
        check(self.method in ('GET', 'POST', 'PUT', 'PATCH', 'DELETE'))
        check(type(self.path) is str and self.path.startswith('/') and not self.path.startswith('//') and
              not any(x in self.path for x in ('?', '#', '\\')) and
              all(ord(x) >= 32 for x in self.path))
        check(type(self.readonly) is bool and (self.method != 'GET' or self.readonly))
        check(type(self.query_keys) is tuple and all(ident(x) for x in self.query_keys))
        check(type(self.statuses) is tuple and self.statuses and
              all(type(x) is int and 200 <= x < 300 for x in self.statuses))
        check(self.idempotency_header is None or self.idempotency_header in ('Idempotency-Key', 'X-Idempotency-Key'))


class JSONAPI:
    def __init__(self, origin, routes, *, auth_header='Authorization', auth_prefix='Bearer ',
                 timeout=15, max_response_bytes=262144, opener=None):
        url = urlsplit(origin)
        check(type(origin) is str and url.scheme == 'https' and url.hostname and
              url.path in ('', '/') and not (url.username or url.password or url.query or url.fragment) and
              url.port in (None, 443), 'INTEGRATION_ORIGIN_INVALID')
        check(type(routes) is tuple and all(isinstance(x, Route) for x in routes))
        check(len({x.name for x in routes}) == len(routes))
        check(type(auth_header) is str and re.fullmatch('[A-Za-z][A-Za-z0-9-]{0,63}', auth_header) and
              auth_header.lower() not in ('host', 'content-length', 'cookie', 'proxy-authorization', 'connection'))
        check(type(auth_prefix) is str and len(auth_prefix) <= 32 and
              all(32 <= ord(x) < 127 for x in auth_prefix))
        check(type(timeout) in (int, float) and 1 <= timeout <= 30)
        check(type(max_response_bytes) is int and 1024 <= max_response_bytes <= 1048576)
        self.origin, self.routes = origin.rstrip('/'), {x.name: x for x in routes}
        self.auth_header, self.auth_prefix = auth_header, auth_prefix
        self.timeout, self.max_bytes = timeout, max_response_bytes
        self.opener = opener or request.build_opener(request.ProxyHandler({}), NoRedirect(),
            request.HTTPSHandler(context=ssl.create_default_context()))

    def call(self, route_name, *, credential=None, path=None, query=None, body=None, request_id=None):
        check(route_name in self.routes, 'INTEGRATION_ROUTE_DENIED')
        route = self.routes[route_name]
        path, query = {} if path is None else path, {} if query is None else query
        keys = re.findall(r'\{([a-z][a-z0-9_]*)\}', route.path)
        check(type(path) is dict and set(path) == set(keys) and
              all(type(x) is str and 0 < len(x.encode()) <= 256 and x not in ('.', '..') and
                  all(ord(c) >= 32 for c in x) for x in path.values()), 'INTEGRATION_PATH_PARAMS_INVALID')
        check(type(query) is dict and set(query) <= set(route.query_keys), 'INTEGRATION_QUERY_INVALID')
        for value in query.values():
            check(type(value) in (str, int, bool) and len(str(value)) <= 2000, 'INTEGRATION_QUERY_INVALID')
        resolved = route.path
        for key, value in path.items(): resolved = resolved.replace('{' + key + '}', quote(value, safe=''))
        check('{' not in resolved and '}' not in resolved, 'INTEGRATION_PATH_TEMPLATE_INVALID')
        headers = {'Accept': 'application/json'}
        if credential is not None:
            token = credential.reveal()
            check(all(32 <= ord(x) < 127 for x in token), 'CREDENTIAL_HTTP_FORMAT_INVALID')
            headers[self.auth_header] = self.auth_prefix + token
        raw = None
        if body is not None:
            check(route.method != 'GET', 'INTEGRATION_GET_BODY_DENIED')
            raw = canonical(body).encode()
            check(len(raw) <= 262144, 'INTEGRATION_REQUEST_LIMIT')
            headers['Content-Type'] = 'application/json'
        if route.idempotency_header:
            check(type(request_id) is str, 'INTEGRATION_REQUEST_ID_REQUIRED')
            headers[route.idempotency_header] = request_id
        url = self.origin + resolved + ('?' + urlencode(query) if query else '')
        try:
            req = request.Request(url, data=raw, headers=headers, method=route.method)
            with self.opener.open(req, timeout=self.timeout) as response:
                check(response.status in route.statuses, 'INTEGRATION_UPSTREAM_STATUS')
                check(response.geturl() == url, 'INTEGRATION_REDIRECT_DENIED')
                data = response.read(self.max_bytes + 1)
                check(len(data) <= self.max_bytes, 'INTEGRATION_RESPONSE_LIMIT')
            return loads_strict(data)
        except Denied:
            raise
        except Exception:
            raise Denied('INTEGRATION_UPSTREAM_FAILED') from None

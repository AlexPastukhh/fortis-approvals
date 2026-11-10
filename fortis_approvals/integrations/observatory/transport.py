"""Trusted fixed-route transport for the existing Observatory V1 Gateway.

Not a generic HTTP proxy: no caller-specified origin, Host, method, headers,
redirect, cookies, URL or provider credential. Observatory currently only
offers host.docker.internal:18756 over HTTP, which the shared HTTPS JSONAPI
intentionally rejects. This scoped transport is an explicit interoperability
exception, not permission to weaken shared JSONAPI. Deployment and transport
trust review are separate from source tests.
"""
from http.client import HTTPConnection
from urllib.parse import quote, urlencode
import re

from ...core import Denied, canonical, loads_strict
from ...extensions.http import Route
from ...extensions.model import check

_GATEWAY_HOST = 'host.docker.internal'
_GATEWAY_PORT = 18756
_GATEWAY_AUTHORITY = 'fortis-observatory-api:18756'
_MAX_BYTES = 262144
_PATH_VALUE = re.compile(r'[A-Za-z0-9_:-]{1,100}\Z')


class ObservatoryTransport:
    def __init__(self, routes, *, connect=None):
        check(type(routes) is tuple and routes and
              all(isinstance(route, Route) for route in routes))
        check(len({route.name for route in routes}) == len(routes))
        self.routes = {route.name: route for route in routes}
        self._connect = connect or (lambda: HTTPConnection(
            _GATEWAY_HOST, _GATEWAY_PORT, timeout=5))

    def call(self, route_name, *, credential=None, path=None, query=None,
             body=None, request_id=None):
        check(route_name in self.routes, 'OBS_ROUTE_DENIED')
        route = self.routes[route_name]
        path = {} if path is None else path
        query = {} if query is None else query
        slots = re.findall(r'\{([a-z][a-z0-9_]*)\}', route.path)
        check(type(path) is dict and set(path) == set(slots) and all(
            type(x) is str and _PATH_VALUE.fullmatch(x) for x in path.values()),
            'OBS_PATH_DENIED')
        check(type(query) is dict and set(query) <= set(route.query_keys) and all(
            type(x) is str and _PATH_VALUE.fullmatch(x) for x in query.values()),
            'OBS_QUERY_DENIED')
        check(credential is not None, 'OBS_CREDENTIAL_REQUIRED')
        token = credential.reveal()
        check(type(token) is str and 16 <= len(token) <= 256 and all(
            33 <= ord(c) <= 126 for c in token), 'OBS_CREDENTIAL_FORMAT_DENIED')
        uri = route.path
        for slot, value in path.items():
            uri = uri.replace('{' + slot + '}', quote(value, safe=''))
        check('{' not in uri and '}' not in uri and uri.startswith('/') and
              not uri.startswith('//'), 'OBS_URI_DENIED')
        if query: uri += '?' + urlencode(query)
        headers = {
            'Host': _GATEWAY_AUTHORITY,
            'Authorization': 'Bearer ' + token,
            'Accept': 'application/json',
            'Connection': 'close',
        }
        payload = None
        if body is not None:
            check(route.method == 'POST', 'OBS_BODY_METHOD_DENIED')
            payload = canonical(body).encode('utf-8')
            check(len(payload) <= 65536, 'OBS_REQUEST_LIMIT')
            headers['Content-Type'] = 'application/json'
        if route.idempotency_header:
            check(type(request_id) is str and len(request_id) <= 100,
                  'OBS_REQUEST_ID_DENIED')
            headers[route.idempotency_header] = request_id
        connection = None
        try:
            connection = self._connect()
            connection.request(route.method, uri, body=payload, headers=headers)
            response = connection.getresponse()
            # Never follow redirects or return raw upstream error bodies.
            check(response.status in route.statuses, 'OBS_UPSTREAM_STATUS')
            raw = response.read(_MAX_BYTES + 1)
            check(len(raw) <= _MAX_BYTES, 'OBS_RESPONSE_LIMIT')
            value = loads_strict(raw)
            check(type(value) is dict, 'OBS_RESPONSE_SCHEMA')
            return value
        except Denied:
            raise
        except Exception:
            raise Denied('OBS_UPSTREAM_FAILED') from None
        finally:
            if connection is not None:
                connection.close()

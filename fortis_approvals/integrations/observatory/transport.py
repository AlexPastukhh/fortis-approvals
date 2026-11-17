"""Fixed Observatory DOCKER-HTTPS/443 upstream transport for two READ routes.

The owner-managed per-service CA is loaded afresh, with hostname verification
and no default trust store. Never follow redirects or proxy, use HTTP/18756,
accept caller-selected origins, or expose staging POST through this provider.
"""
from http.client import HTTPSConnection
from pathlib import Path
import os
import re
import ssl
import stat

from ...core import Denied, loads_strict
from ...extensions.http import Route
from ...extensions.model import check
from ...extensions.vault import Secret

_GATEWAY_HOST = 'fortis-observatory-api'
_GATEWAY_PORT = 443
_GATEWAY_AUTHORITY = 'fortis-observatory-api'
_CA_PATH = Path('/run/fortis-secrets/observatory-read/ca.pem')
_MAX_BYTES = 262144
_ALLOWED = {'health': '/v1/health', 'sessions': '/v1/sessions'}
_PEM = re.compile(
    rb'\s*-----BEGIN CERTIFICATE-----\s*'
    rb'[A-Za-z0-9+/=\r\n]+-----END CERTIFICATE-----\s*')


def observatory_context():
    """Trust exactly the owner-provisioned CA; missing/unsafe CA is STOP."""
    try:
        if _CA_PATH.parent.is_symlink() or _CA_PATH.parent.parent.is_symlink():
            raise ValueError('ca_parent_symlink')
        fd = os.open(_CA_PATH, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            metadata = os.fstat(fd)
            if (not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1
                    or stat.S_IMODE(metadata.st_mode) & 0o022
                    or not 0 < metadata.st_size <= 16384):
                raise ValueError('ca_unsafe_file')
            with os.fdopen(fd, 'rb', closefd=False) as inp:
                pem = inp.read(16385)
            if len(pem) > 16384 or _PEM.fullmatch(pem) is None:
                raise ValueError('ca_invalid_pem')
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.load_verify_locations(cadata=pem.decode('ascii'))
            if not context.check_hostname or context.verify_mode != ssl.CERT_REQUIRED:
                raise ValueError('ca_tls_verification_disabled')
            return context
        finally:
            os.close(fd)
    except (OSError, UnicodeError, ValueError, ssl.SSLError):
        raise Denied('OBS_CA_UNAVAILABLE') from None


class ObservatoryTransport:
    def __init__(self, routes, *, connect=None):
        check(type(routes) is tuple and len(routes) == 2 and all(
            isinstance(route, Route) and route.readonly
            and route.method == 'GET' and _ALLOWED.get(route.name) == route.path
            and not route.query_keys and not route.idempotency_header
            for route in routes), 'OBS_READ_ROUTES_REQUIRED')
        check({route.name for route in routes} == set(_ALLOWED),
              'OBS_READ_ROUTES_REQUIRED')
        check(connect is None or callable(connect), 'OBS_CONNECT_INVALID')
        self.routes = {route.name: route for route in routes}
        self._connect = connect

    def call(self, route_name, *, credential=None, path=None, query=None,
             body=None, request_id=None):
        check(route_name in self.routes, 'OBS_ROUTE_DENIED')
        check(path in (None, {}) and query in (None, {}) and body is None
              and request_id is None, 'OBS_READ_ONLY_ROUTE')
        check(isinstance(credential, Secret), 'OBS_CREDENTIAL_REQUIRED')
        token = credential.reveal()
        check(type(token) is str and 32 <= len(token) <= 128 and
              re.fullmatch(r'[A-Za-z0-9_-]+', token), 'OBS_CREDENTIAL_FORMAT_DENIED')
        connection = None
        try:
            connection = (self._connect() if self._connect is not None
                          else HTTPSConnection(_GATEWAY_HOST, _GATEWAY_PORT,
                                               timeout=5, context=observatory_context()))
            connection.request('GET', self.routes[route_name].path,
                               headers={'Host': _GATEWAY_AUTHORITY,
                                        'Authorization': 'Bearer ' + token,
                                        'Accept': 'application/json',
                                        'Connection': 'close'})
            response = connection.getresponse()
            # No redirects, no raw error bodies, bounded and duplicate-key strict.
            check(response.status == 200, 'OBS_UPSTREAM_STATUS')
            check(response.getheader('Content-Type') == 'application/json; charset=utf-8',
                  'OBS_RESPONSE_CONTENT_TYPE')
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

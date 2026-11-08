"""Trusted owner-only HTTP-to-Windows executor transport (never machine API).

This opt-in client uses a fixed HTTPS target, system-trusted configuration,
mutual TLS, and an independent bearer secret. The browser never receives
these credentials. No arbitrary URL, host, or operation can be supplied.
"""
import json
import os
from pathlib import Path
import re
import ssl
import stat
from urllib import request, error

from .core import Denied, loads_strict


class ShellTransportUnavailable(RuntimeError):
    pass


class OwnerShellClient:
    def __init__(self, *, port, server_ca, client_cert, client_key, secret_file):
        if type(port) is not int or not 1024 <= port <= 65535:
            raise Denied('OWNER_SHELL_PORT_INVALID')
        paths = (server_ca, client_cert, client_key, secret_file)
        if any(type(path) is not str or not Path(path).is_absolute() or
               Path(path).is_symlink() or not Path(path).is_file() for path in paths):
            raise Denied('OWNER_SHELL_PRIVATE_CONFIG_REQUIRED')
        for private_path in (client_key, secret_file):
            meta = Path(private_path).stat()
            if (meta.st_uid != os.geteuid() or
                    stat.S_IMODE(meta.st_mode) & 0o077):
                raise Denied('OWNER_SHELL_PRIVATE_CONFIG_REQUIRED')
        self.port = port
        self.origin = 'https://host.docker.internal:' + str(port)
        self.context = ssl.create_default_context(cafile=server_ca)
        self.context.minimum_version = ssl.TLSVersion.TLSv1_2
        self.context.load_cert_chain(certfile=client_cert, keyfile=client_key)
        self.secret = Path(secret_file).read_text(encoding='ascii').strip()
        if not 32 <= len(self.secret) <= 256 or any(ord(c) < 33 or ord(c) > 126 for c in self.secret):
            raise Denied('OWNER_SHELL_SECRET_INVALID')
        class NoRedirect(request.HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, headers, newurl):
                raise ShellTransportUnavailable('OWNER_SHELL_REDIRECT_DENIED')
        self.opener = request.build_opener(request.ProxyHandler({}),
                                           request.HTTPSHandler(context=self.context), NoRedirect())

    @classmethod
    def from_environment(cls, env=None):
        env = os.environ if env is None else env
        raw = env.get('FORTIS_OWNER_SHELL_CONFIG')
        if raw is None:
            return None
        if type(raw) is not str or not 0 < len(raw.encode('utf-8')) < 4096:
            raise Denied('OWNER_SHELL_CONFIG_INVALID')
        try:
            value = loads_strict(raw.encode('utf-8'))
        except (ValueError, TypeError, UnicodeError):
            raise Denied('OWNER_SHELL_CONFIG_INVALID') from None
        if (type(value) is not dict or set(value) !=
                {'port', 'serverCA', 'clientCert', 'clientKey', 'secretFile'}):
            raise Denied('OWNER_SHELL_CONFIG_INVALID')
        return cls(port=value['port'], server_ca=value['serverCA'],
                   client_cert=value['clientCert'], client_key=value['clientKey'],
                   secret_file=value['secretFile'])

    def _send(self, path, *, body=None, request_id=None):
        if not re.fullmatch(r'/owner-shell/v1/(?:capabilities|execute|results/[0-9a-f-]{36})', path):
            raise Denied('OWNER_SHELL_ROUTE_DENIED')
        headers = {'Authorization': 'Bearer ' + self.secret, 'Accept': 'application/json'}
        data = None
        if body is not None:
            data = json.dumps(body, ensure_ascii=False, separators=(',', ':')).encode('utf-8')
            headers.update({'Content-Type': 'application/json', 'Idempotency-Key': request_id})
        req = request.Request(self.origin + path, data=data, headers=headers,
                              method='POST' if data is not None else 'GET')
        try:
            with self.opener.open(req, timeout=90) as response:
                if response.status != 200:
                    raise ShellTransportUnavailable('OWNER_SHELL_NOT_READY')
                raw = response.read(2 * 65536 + 8192 + 1)
                if len(raw) > 2 * 65536 + 8192:
                    raise ShellTransportUnavailable('OWNER_SHELL_RESPONSE_TOO_LARGE')
        except (OSError, error.HTTPError, error.URLError, TimeoutError) as exc:
            raise ShellTransportUnavailable('OWNER_SHELL_OUTCOME_UNCONFIRMED') from None
        try:
            result = json.loads(raw)
        except (ValueError, UnicodeError):
            raise ShellTransportUnavailable('OWNER_SHELL_RESPONSE_INVALID') from None
        if type(result) is not dict:
            raise ShellTransportUnavailable('OWNER_SHELL_RESPONSE_INVALID')
        return result

    def execute(self, command, request_id):
        return self._send('/owner-shell/v1/execute',
                          body={'command': command, 'requestId': request_id}, request_id=request_id)

    def status(self, request_id):
        return self._send('/owner-shell/v1/results/' + request_id)

    def capabilities(self):
        return self._send('/owner-shell/v1/capabilities')

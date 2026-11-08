"""Owner-only PowerShell routes as a WSGI extension of the pinned OwnerPortal.

Do not change the release-pinned owner_portal.py/runtime.py storage contract.
All original passkey, approval, storage and static routes are delegated unchanged.
Only a narrow, separately configured, owner-authenticated PowerShell surface is
provided here; it is NOT available to machine ingress or linked to Analyzer/AI.
"""
import re

from .core import ApprovalError, Denied
from .owner_portal import OwnerPortal
from .owner_shell import ShellTransportUnavailable


REQUEST_ID = re.compile(r'[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\Z')
RESULT_ROUTE = re.compile(r'/v1/owner/powershell/results/([0-9a-f-]{36})\Z')


class OwnerShellPortal(OwnerPortal):
    """Owner Portal with optional one-shot PowerShell, disabled by default."""

    def __init__(self, core, authenticator, *, owner_shell=None, **kwargs):
        super().__init__(core, authenticator, **kwargs)
        self.owner_shell = owner_shell

    @staticmethod
    def _reply(start, status, content, mime='application/json; charset=utf-8', extras=()):
        # Reuse baseline OwnerPortal security headers (CSP, no-store, no frame).
        # It predates the optional shell and does not list HTTP 503.
        if status == 503:
            def unavailable(_status, headers):
                return start('503 Service Unavailable', headers)
            return OwnerPortal._reply(unavailable, 500, content, mime, extras)
        return OwnerPortal._reply(start, status, content, mime, extras)

    def __call__(self, env, start):
        method = env.get('REQUEST_METHOD')
        path = env.get('PATH_INFO', '')
        is_caps = method == 'GET' and path == '/v1/owner/powershell/capabilities'
        result_match = RESULT_ROUTE.fullmatch(path) if method == 'GET' else None
        is_execute = method == 'POST' and path == '/v1/owner/powershell/execute'
        if not (is_caps or result_match or is_execute):
            return super().__call__(env, start)
        try:
            if (env.get('HTTP_HOST') != self.host or env.get('QUERY_STRING') or
                any(env.get(key) for key in ('HTTP_X_FORWARDED_HOST', 'HTTP_FORWARDED',
                                               'HTTP_PROXY_AUTHORIZATION', 'HTTP_AUTHORIZATION'))):
                raise Denied('HOST_DENIED')
            token = self._cookie(env)
            if is_caps:
                self.auth.session(token)
                return self._reply(start, 200, {
                    'configured': self.owner_shell is not None and not self.read_only_banner,
                    'mode': 'owner_one_shot',
                    'analysisAvailable': False,
                    'otherAIAvailable': False,
                })
            if result_match:
                self.auth.session(token)
                if self.owner_shell is None or self.read_only_banner or not REQUEST_ID.fullmatch(result_match.group(1)):
                    raise Denied('OWNER_SHELL_NOT_CONFIGURED')
                return self._reply(start, 200, self.owner_shell.status(result_match.group(1)))
            # Only the current WebAuthn owner session may submit. Browser
            # requests must satisfy the same exact Host/Origin/CSRF invariants
            # as the baseline OwnerPortal's privileged approval mutations.
            if env.get('HTTP_ORIGIN') != self.origin:
                raise Denied('ORIGIN_DENIED')
            body = self._json(env)
            csrf = env.get('HTTP_X_FORTIS_CSRF')
            if not csrf:
                raise Denied('CSRF_REQUIRED')
            self.auth.session(token, csrf)
            if self.owner_shell is None or self.read_only_banner:
                raise Denied('OWNER_SHELL_NOT_CONFIGURED')
            if (set(body) != {'command', 'requestId'} or
                type(body['command']) is not str or not body['command'].strip() or
                '\x00' in body['command'] or len(body['command'].encode('utf-8')) > 8192 or
                type(body['requestId']) is not str or not REQUEST_ID.fullmatch(body['requestId'])):
                raise Denied('OWNER_SHELL_COMMAND_INVALID')
            return self._reply(start, 200, self.owner_shell.execute(body['command'], body['requestId']))
        except Denied as exc:
            return self._reply(start, 403, {'error': str(exc)})
        except (ApprovalError, ValueError, TypeError, KeyError, UnicodeError):
            return self._reply(start, 400, {'error': 'REQUEST_INVALID'})
        except ShellTransportUnavailable:
            return self._reply(start, 503, {'error': 'OWNER_SHELL_OUTCOME_UNCONFIRMED'})
        except (OSError, RuntimeError):
            return self._reply(start, 500, {'error': 'OUTCOME_UNCONFIRMED'})

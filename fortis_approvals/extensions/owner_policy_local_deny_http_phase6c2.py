"""Phase 6C.2 opt-in owner WSGI adapter for exact DENY-only policy changes.

A separate subclass, never mounted by default runtime or client/machine APIs.
No untrusted request may inject a store, signer, owner, config path or policy.
Protected Core / OwnerWebAuthn / OwnerPortal release source remains unchanged.
"""
import sqlite3

from ..core import ApprovalError, Denied, Stale
from ..incidents import IncidentOwnerPortal
from .owner_policy_local_deny_apply_phase6c1 import OwnerLocalDenyApply

_PREFIX = '/v1/owner/policy/local-deny'
_CAPS = _PREFIX + '/capabilities'
_BEGIN = _PREFIX + '/begin'
_FINISH = _PREFIX + '/finish'
_READBACK = _PREFIX + '/readback'
_POST = frozenset((_BEGIN, _FINISH, _READBACK))


class OwnerLocalDenyPortal(IncidentOwnerPortal):
    """Separate, trusted-host-injected owner WSGI surface; source-only.

    Its existence in the image does not cause default runtime integration:
    only explicit construction by a future reviewed owner-only host factory
    could make this policy restriction endpoint accessible. No runtime factory
    is modified by this module.
    """

    def __init__(self, core, authenticator, *, local_deny_apply=None, **kwargs):
        super().__init__(core, authenticator, **kwargs)
        if local_deny_apply is not None and (
                type(local_deny_apply) is not OwnerLocalDenyApply or
                local_deny_apply.core is not core or
                local_deny_apply.auth is not authenticator):
            raise Denied('OWNER_LOCAL_DENY_PORTAL_TRUSTED_BINDING_REQUIRED')
        self._local_deny_apply = local_deny_apply

    def __call__(self, env, start):
        method = env.get('REQUEST_METHOD')
        path = env.get('PATH_INFO', '')
        is_caps = method == 'GET' and path == _CAPS
        is_post = method == 'POST' and path in _POST
        if not (is_caps or is_post):
            return super().__call__(env, start)
        try:
            # Same narrow, owner-only HTTP protections as the existing
            # IncidentOwnerPortal. No forward-proxy/alternate Host fallback.
            if (env.get('HTTP_HOST') != self.host or env.get('QUERY_STRING') or
                    any(env.get(key) for key in (
                        'HTTP_X_FORWARDED_HOST', 'HTTP_FORWARDED',
                        'HTTP_PROXY_AUTHORIZATION', 'HTTP_AUTHORIZATION'))):
                raise Denied('HOST_DENIED')
            session = self._cookie(env)
            if is_caps:
                self.auth.session(session)
                ready = self._local_deny_apply is not None and not self.read_only_banner
                return self._reply(start, 200, {
                    'configured': ready,
                    'kind': 'OWNER_LOCAL_EXACT_DENY_ONLY',
                    'requiresFreshStrongWebAuthn': True,
                    'canGrantAllow': False,
                    'canRemoveDenial': False,
                    'ownerOnly': True,
                })
            if env.get('HTTP_ORIGIN') != self.origin:
                raise Denied('ORIGIN_DENIED')
            body = self._json(env)
            csrf = env.get('HTTP_X_FORTIS_CSRF')
            if not csrf:
                raise Denied('CSRF_REQUIRED')
            self.auth.session(session, csrf)
            if self.read_only_banner or self._local_deny_apply is None:
                raise Denied('OWNER_LOCAL_DENY_NOT_CONFIGURED')
            if path == _BEGIN and set(body) == {'candidate'}:
                return self._reply(start, 200, self._local_deny_apply.begin_deny(
                    session, csrf, body['candidate']))
            if path == _FINISH and set(body) == {'ceremonyId', 'change', 'response'}:
                return self._reply(start, 200, self._local_deny_apply.finish_deny(
                    session, csrf, body['ceremonyId'], body['response'], body['change']))
            if path == _READBACK and set(body) == {'requestId'}:
                # POST so even readback obeys Origin + CSRF; never replays apply.
                return self._reply(start, 200, self._local_deny_apply.readback(
                    session, csrf, body['requestId']))
            raise Denied('OWNER_LOCAL_DENY_REQUEST_SCHEMA')
        except Denied as exc:
            return self._reply(start, 403, {'error': str(exc)})
        except Stale as exc:
            return self._reply(start, 409, {'error': str(exc)})
        except (ApprovalError, ValueError, TypeError, KeyError, UnicodeError):
            return self._reply(start, 400, {'error': 'REQUEST_INVALID'})
        except (OSError, RuntimeError, sqlite3.DatabaseError):
            # A failed response does not prove that the transaction rolled back.
            return self._reply(start, 500, {'error': 'OUTCOME_UNCONFIRMED'})

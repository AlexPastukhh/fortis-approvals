"""Three closed typed routes on the existing machine TLS/auth boundary."""
from ..core import ApprovalError, Conflict, Denied
from ..repo_ingress import RepoIngress
from .model import check

PATHS = frozenset({'/v1/integrations/catalog', '/v1/integrations/call', '/v1/integrations/result'})


class ExtensionIngress:
    def __init__(self, base, runtime, *, delegate=None):
        self.base, self.runtime, self.broker = base, runtime, base.broker
        self.delegate = base if delegate is None else delegate

    def __call__(self, env, start):
        path = env.get('PATH_INFO', '')
        if path not in PATHS: return self.delegate(env, start)
        try:
            check(self.base._environment(env) and env.get('REQUEST_METHOD') == 'POST', 'INTEGRATION_ROUTE_DENIED')
            credential, actor = self.base._credential(env)
            if not self.base.limiter.take(actor): return RepoIngress._reply(start, 429, {'error': 'INTEGRATION_RATE_LIMIT'})
            body = self.base._body(env)
            if body is None: return RepoIngress._reply(start, 413, {'error': 'INTEGRATION_BODY_LIMIT'})
            if path.endswith('/catalog'):
                check(body == {}, 'INTEGRATION_CATALOG_SCHEMA')
                result = self.runtime.catalog(credential)
            elif path.endswith('/call'):
                result = self.runtime.call(credential, body)
            else:
                check(type(body) is dict and {'requestId'} <= set(body) <= {'requestId', 'reconcile'}, 'INTEGRATION_RESULT_SCHEMA')
                result = self.runtime.result(credential, body['requestId'], reconcile=body.get('reconcile', False))
            return RepoIngress._reply(start, 202 if result.get('state') == 'PENDING' else 200, result)
        except Conflict:
            return RepoIngress._reply(start, 409, {'error': 'INTEGRATION_REQUEST_CONFLICT'})
        except Denied:
            return RepoIngress._reply(start, 403, {'error': 'INTEGRATION_DENIED'})
        except (ApprovalError, ValueError, TypeError, KeyError, UnicodeError):
            return RepoIngress._reply(start, 400, {'error': 'INTEGRATION_REQUEST_INVALID'})
        except Exception:
            return RepoIngress._reply(start, 500, {'error': 'INTEGRATION_OUTCOME_UNCONFIRMED'})

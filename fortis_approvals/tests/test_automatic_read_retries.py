"""Real shared transport: READ retry budgets, backoff and zero WRITE replay."""
from io import BytesIO
import json
from pathlib import Path
import tempfile
import unittest
from urllib.error import HTTPError, URLError

from fortis_approvals.clients.gateway_transport import GatewayTransport
from fortis_approvals.clients.retries import RetryPolicy, seconds_header
from fortis_approvals.core import Denied
from fortis_approvals.repo_ingress import _PerActorWindow


class Response(BytesIO):
    status = 200


class Opener:
    def __init__(self, outcomes):
        self.outcomes = list(outcomes)
        self.calls = []

    def open(self, req, timeout):
        self.calls.append((req.method, req.full_url, req.data))
        item = self.outcomes.pop(0)
        if isinstance(item, Exception):
            raise item
        return Response(json.dumps(item).encode())


def failure(status, body=None, headers=None):
    return HTTPError('http://localhost:19123/v1/reads', status, 'synthetic',
        headers or {}, BytesIO(json.dumps(body or {'error': 'synthetic'}).encode()))


class AutomaticReadTests(unittest.TestCase):
    def client(self, outcomes):
        tmp = tempfile.TemporaryDirectory(); self.addCleanup(tmp.cleanup)
        root = Path(tmp.name); grant = root / 'grant'; cert = root / 'cert'
        grant.write_text('f' * 48); grant.chmod(0o600); cert.write_text('test')
        self.waits = []; opener = Opener(outcomes)
        transport = GatewayTransport(endpoint='http://localhost:19123',
            grant_path=str(grant), certificate_path=str(cert), opener=opener,
            retry_policy=RetryPolicy(sleep=self.waits.append, clock=lambda: 100))
        return transport, opener

    def test_read_500_and_network_failure_then_success_same_query(self):
        t, o = self.client([failure(500), URLError('private-secret'), {'ok': True}])
        self.assertEqual(t.post('/v1/reads', {'query': 1}), {'ok': True})
        self.assertEqual(len(o.calls), 3)
        self.assertEqual(len({x[2] for x in o.calls}), 1)
        self.assertEqual(self.waits, [1, 2])

    def test_local_429_respects_backoff(self):
        t, _ = self.client([failure(429, headers={'Retry-After': '17'}), {'ok': True}])
        t.post('/v1/reads', {})
        self.assertEqual(self.waits, [17])

    def test_old_gateway_429_waits_full_window(self):
        t, _ = self.client([failure(429), {'ok': True}])
        t.post('/v1/reads', {})
        self.assertEqual(self.waits, [60])

    def test_github_429_inside_500_is_retried(self):
        body = {'error': 'REPO_GITHUB_READ_FAILED', 'providerCode': 'GITHUB_HTTP_429'}
        t, _ = self.client([failure(500, body), {'ok': True}])
        t.post('/v1/reads', {})
        self.assertEqual(self.waits, [60])

    def test_rate_limited_403_retry_but_permission_403_does_not(self):
        for signal, retry in [('BACKOFF_HEADER_PRESENT', True),
                              ('PERMISSION_REQUIREMENTS_ADVERTISED', False)]:
            with self.subTest(signal=signal):
                body = {'error': 'REPO_GITHUB_READ_FAILED',
                        'providerCode': 'GITHUB_HTTP_403', 'signal': signal}
                t, o = self.client([failure(500, body), {'ok': True}])
                if retry:
                    t.post('/v1/reads', {})
                    self.assertEqual(len(o.calls), 2)
                else:
                    with self.assertRaises(Denied): t.post('/v1/reads', {})
                    self.assertEqual(len(o.calls), 1)

    def test_policy_auth_and_validation_failures_not_retried(self):
        for status in (400, 401, 403, 404, 409, 422):
            with self.subTest(status=status):
                t, o = self.client([failure(status)])
                with self.assertRaisesRegex(Denied, 'FORTIS_HTTP_' + str(status)):
                    t.post('/v1/reads', {})
                self.assertEqual(len(o.calls), 1)

    def test_write_post_is_never_retried_by_transport(self):
        t, o = self.client([failure(500)])
        with self.assertRaises(Denied): t.post('/v1/actions', {})
        self.assertEqual(len(o.calls), 1)
        self.assertEqual(self.waits, [])

    def test_native_effect_routes_excluded(self):
        for route in ('/v1/workspace/submit', '/v1/workspace/claim',
                      '/v1/workspace/finish', '/v1/workspace/reconcile', '/v1/git/artifact'):
            with self.subTest(route=route):
                t, o = self.client([failure(500)])
                t.post_paths = t.post_paths | {route}
                with self.assertRaises(Denied): t.post(route, {})
                self.assertEqual(len(o.calls), 1)

    def test_native_metadata_read_posts_are_retried(self):
        for route in ('/v1/workspace/details', '/v1/workspace/capabilities',
                      '/v1/workspace/list_requests', '/v1/workspace/result'):
            with self.subTest(route=route):
                t, o = self.client([failure(503), {'ok': True}])
                t.post_paths = t.post_paths | {route}
                t.post(route, {})
                self.assertEqual(len(o.calls), 2)

    def test_exhaustion_preserves_error_category(self):
        t, o = self.client([failure(503), failure(503), failure(503)])
        with self.assertRaisesRegex(Denied, '^FORTIS_HTTP_503$'):
            t.post('/v1/reads', {})
        self.assertEqual(len(o.calls), 3)

    def test_long_backoff_does_not_retry_early(self):
        t, o = self.client([failure(429, headers={'Retry-After': '600'})])
        with self.assertRaises(Denied) as caught: t.post('/v1/reads', {})
        self.assertEqual(caught.exception.retry_after_seconds, 600)
        self.assertEqual(len(o.calls), 1)
        self.assertEqual(self.waits, [])

    def test_later_manual_read_on_same_client_does_not_ignore_known_backoff(self):
        t, o = self.client([failure(429, headers={'Retry-After': '600'}), {'ok': True}])
        now = [100]
        t.read_retry.clock = lambda: now[0]
        with self.assertRaises(Denied): t.post('/v1/reads', {'service': 'github'})
        with self.assertRaises(Denied): t.post('/v1/reads', {'service': 'github'})
        self.assertEqual(len(o.calls), 1)
        now[0] = 701
        self.assertEqual(t.post('/v1/reads', {'service': 'github'}), {'ok': True})
        self.assertEqual(len(o.calls), 2)

    def test_bounded_headers_and_limiter_reset(self):
        for value in ('-1', 'secret', '1.5', '604801', '\n60', '9999999999'):
            self.assertIsNone(seconds_header({'Retry-After': value}))
        now = [0]
        limiter = _PerActorWindow(max_requests=1, seconds=60, clock=lambda: now[0])
        self.assertTrue(limiter.take('actor')); self.assertFalse(limiter.take('actor'))
        now[0] = 10.2
        self.assertEqual(limiter.retry_after('actor'), 50)
        now[0] = 60.01
        self.assertTrue(limiter.take('actor'))


if __name__ == '__main__': unittest.main()

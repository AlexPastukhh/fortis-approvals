"""Offline contract/security tests; never contact production Observatory."""
import json
import unittest

from fortis_approvals.core import Denied
from fortis_approvals.extensions.vault import Secret
from fortis_approvals.extensions.model import discover
from fortis_approvals.integrations.observatory.extension import (
    PROVIDER, _read_health, _list_sessions, _sessions_result)
from fortis_approvals.integrations.observatory.transport import ObservatoryTransport


class Token:
    def reveal(self):
        return 'test-only-fake-token-1234567890123456'


class Context:
    def __init__(self, target, response):
        self.target = target
        self.response = response
        self.route = None

    def call(self, route):
        self.route = route
        return self.response


class Tests(unittest.TestCase):
    def test_provider_is_discoverable_without_registry_modification(self):
        p = discover(('observatory',))[0]
        self.assertEqual(p.name, 'observatory')
        self.assertEqual(tuple(op.name for op in p.operations),
                         ('health', 'list_sessions'))
        self.assertTrue(all(op.ready and op.kind == 'read' and op.credential == 'api'
                            for op in p.operations))
        self.assertIsNotNone(p.source_digest)

    def test_health_projects_closed_response(self):
        ctx = Context('service', {'ok': True, 'service': 'fortis-observatory-api',
                                  'mode': 'staging_only', 'debugToken': 'not-returned'})
        data = _read_health(ctx)
        self.assertEqual(ctx.route, 'health')
        self.assertEqual(set(data), {'ok', 'service', 'mode'})
        with self.assertRaises(Denied):
            _read_health(Context('other', ctx.response))
        with self.assertRaises(Denied):
            _read_health(Context('service', {'ok': False, 'service': 'fortis-observatory-api',
                                            'mode': 'staging_only'}))

    def test_sessions_are_minimally_projected(self):
        ctx = Context('registry', {'ok': True, 'sessions': [
            {'conversation_id': '12345678-1234-1234-1234-123456789abc',
             'reporting_session_id': 'rs_'+'a'*32, 'title': 'private title',
             'route': 'direct', 'state': 'active', 'events_count': 0,
             'last_task_id': None, 'last_signal_at': None, 'messages': ['sensitive']},
        ]})
        result = _list_sessions(ctx)
        self.assertEqual(ctx.route, 'sessions')
        self.assertEqual(result['sessions'], [{'conversation_id': '12345678-1234-1234-1234-123456789abc',
                                               'session_id': 'rs_'+'a'*32}])
        with self.assertRaises(Denied):
            _list_sessions(Context('service', ctx.response))
        with self.assertRaises(Denied):
            _sessions_result({'ok': True, 'sessions': [result['sessions'][0]] * 2})
        with self.assertRaises(Denied):
            _list_sessions(Context('registry', {'ok': True, 'sessions': [{'title': 'oops'}]}))

    def test_transport_fixed_host_bearer_and_no_redirect(self):
        # The previous regression tested HTTP/18756 with one route. V2
        # deliberately requires both reviewed GET routes and a Secret
        # credential; never allow an HTTP fallback to make that test green.
        token = 'T' * 48
        credential = Secret('synthetic', token)

        class Response:
            status = 200

            def getheader(self, name):
                self.assert_header = name
                return 'application/json; charset=utf-8'

            def read(self, limit):
                if limit != 262145:
                    raise AssertionError('response bound changed')
                return json.dumps({'ok': True,
                                   'service': 'fortis-observatory-api',
                                   'mode': 'staging_only'}).encode()

        class SyntheticTLS:
            def __init__(self):
                self.requests = []
                self.responses = [Response()]
                self.closed = False

            def request(self, method, path, *, headers):
                self.requests.append((method, path, dict(headers)))

            def getresponse(self):
                return self.responses[-1]

            def close(self):
                self.closed = True

        wire = SyntheticTLS()
        transport = ObservatoryTransport(tuple(PROVIDER.api.routes.values()),
                                         connect=lambda: wire)
        self.assertTrue(transport.call('health', credential=credential)['ok'])
        self.assertTrue(wire.closed)
        self.assertEqual(len(wire.requests), 1)
        method, path, headers = wire.requests[0]
        self.assertEqual((method, path), ('GET', '/v1/health'))
        self.assertEqual(headers['Host'], 'fortis-observatory-api')
        self.assertEqual(headers['Authorization'], 'Bearer ' + token)
        self.assertEqual(headers['Connection'], 'close')
        self.assertNotIn('18756', str(wire.requests))
        for route in ('other', '/v1/health', '../health'):
            with self.assertRaises(Denied):
                transport.call(route, credential=credential)
        for kwargs in ({'path': {'extra': 'xxx'}},
                       {'query': {'custom': 'xxx'}},
                       {'body': {'foo': 'bar'}}):
            with self.assertRaises(Denied):
                transport.call('health', credential=credential, **kwargs)
        for invalid in (None, Token()):
            with self.assertRaises(Denied):
                transport.call('health', credential=invalid)
        wire.responses[-1].status = 302
        with self.assertRaises(Denied):
            transport.call('health', credential=credential)
        self.assertEqual(len(wire.requests), 2)  # Never follow redirect.



if __name__ == '__main__':
    unittest.main()

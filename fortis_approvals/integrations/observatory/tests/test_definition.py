"""Offline contract/security tests; never contact production Observatory."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import threading
import unittest
from http.client import HTTPConnection

from fortis_approvals.core import Denied
from fortis_approvals.extensions.http import Route
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
             'session_id': 'rs_'+'a'*32, 'title': 'private title', 'messages': ['sensitive']},
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
        token = Token().reveal()

        class Handler(BaseHTTPRequestHandler):
            response_status = 200

            def log_message(self, *_):
                pass

            def do_GET(self):
                good = self.path == '/v1/health' and (
                    self.headers.get('Host') == 'fortis-observatory-api:18756'
                    and self.headers.get('Authorization') == 'Bearer ' + token)
                content = json.dumps({'ok': good, 'service': 'fortis-observatory-api',
                                      'mode': 'staging_only'}).encode()
                self.send_response(self.response_status if good else 403)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(content)))
                if self.response_status == 302:
                    self.send_header('Location', 'https://example.invalid')
                self.end_headers()
                self.wfile.write(content)

        server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        transport = ObservatoryTransport((
            Route('health', 'GET', '/v1/health', readonly=True),
        ), connect=lambda: HTTPConnection('127.0.0.1', server.server_port, timeout=2))
        self.assertTrue(transport.call('health', credential=Token())['ok'])
        for route in ('other', '/v1/health', '../health'):
            with self.assertRaises(Denied):
                transport.call(route, credential=Token())
        with self.assertRaises(Denied):
            transport.call('health', credential=Token(), path={'extra': 'xxx'})
        with self.assertRaises(Denied):
            transport.call('health', credential=Token(), query={'custom': 'xxx'})
        with self.assertRaises(Denied):
            transport.call('health', credential=Token(), body={'foo': 'bar'})
        with self.assertRaises(Denied):
            transport.call('health', credential=None)
        Handler.response_status = 302
        with self.assertRaises(Denied):
            transport.call('health', credential=Token())


if __name__ == '__main__':
    unittest.main()

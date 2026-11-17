"""Offline Observatory fixed Docker HTTPS transport acceptance; no live services.

Synthetic OpenSSL cert, localhost ephemeral TLS server and fake vault Secret.
"""
import hashlib
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import shutil
import socket
import ssl
import subprocess
import tempfile
import threading
import unittest
from unittest import mock

from fortis_approvals.core import Denied
from fortis_approvals.extensions.vault import Secret
from fortis_approvals.integrations.observatory.extension import PROVIDER
from fortis_approvals.integrations.observatory import transport as obs


class LoopbackTLS(http.client.HTTPSConnection):
    def connect(self):
        raw=socket.create_connection(('127.0.0.1',self.port),timeout=3)
        try:
            self.sock=self._context.wrap_socket(raw,server_hostname=self.host)
        except BaseException:
            raw.close()
            raise


class TestOnlyHandler(BaseHTTPRequestHandler):
    mode='normal'
    requests=[]
    def log_message(self,*args):
        pass
    def do_GET(self):
        self.__class__.requests.append((self.command,self.path,self.headers.get('Host')))
        value={'ok':True,'service':'fortis-observatory-api','mode':'staging_only'}
        if self.path == '/v1/sessions':
            value={'ok':True,'sessions':[]}
        status=200
        if self.__class__.mode=='redirect':
            status=302
        if self.__class__.mode=='duplicate':
            raw=b'{"ok":true,"ok":false}'
        elif self.__class__.mode=='oversize':
            raw=b'x'*262145
        else:
            raw=json.dumps(value).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', 'text/plain' if self.__class__.mode=='type' else
                         'application/json; charset=utf-8')
        if status==302:
            self.send_header('Location','http://localhost:18756/v1/health')
        self.send_header('Content-Length',str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


@unittest.skipUnless(shutil.which('openssl'), 'OpenSSL synthetic cert needed')
class ObservatoryHTTPSOnlyTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix='fortis-obs-https-test-')
        self.addCleanup(self.tmp.cleanup)
        root=Path(self.tmp.name)
        self.cert=root/'cert.pem'
        self.key=root/'key.pem'
        subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes',
                        '-days','1','-subj','/CN=fortis-observatory-api',
                        '-addext','subjectAltName=DNS:fortis-observatory-api',
                        '-out',str(self.cert),'-keyout',str(self.key)],
                       check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        self.cert.chmod(0o644)
        self.key.chmod(0o600)
        self.pinner=mock.patch.object(obs,'_CA_PATH',self.cert)
        self.pinner.start()
        self.addCleanup(self.pinner.stop)
        self.context=obs.observatory_context()
        TestOnlyHandler.mode='normal'
        TestOnlyHandler.requests=[]
        self.server=ThreadingHTTPServer(('127.0.0.1',0),TestOnlyHandler)
        tls=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.load_cert_chain(str(self.cert),str(self.key))
        self.server.socket=tls.wrap_socket(self.server.socket,server_side=True)
        self.thread=threading.Thread(target=self.server.serve_forever,daemon=True)
        self.thread.start()
        self.addCleanup(self.shutdown)
        self.secret=Secret('synthetic','T'*48)
        self.transport=self.make_transport()

    def shutdown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=3)

    def make_transport(self,context=None,dns='fortis-observatory-api'):
        return obs.ObservatoryTransport(tuple(PROVIDER.api.routes.values()),
          connect=lambda:LoopbackTLS(dns,self.server.server_port,timeout=3,
                                     context=context or obs.observatory_context()))
    def test_fixed_https_get_health_and_sessions(self):
        self.assertEqual(self.transport.call('health',credential=self.secret),
                         {'ok':True,'service':'fortis-observatory-api','mode':'staging_only'})
        self.assertEqual(self.transport.call('sessions',credential=self.secret),
                         {'ok':True,'sessions':[]})
        self.assertEqual(TestOnlyHandler.requests,
                         [('GET','/v1/health','fortis-observatory-api'),
                          ('GET','/v1/sessions','fortis-observatory-api')])

    def test_provider_exports_two_read_operations_only(self):
        self.assertEqual({o.name for o in PROVIDER.operations}, {'health','list_sessions'})
        self.assertTrue(all(o.kind=='read' for o in PROVIDER.operations))
        self.assertTrue(all(o.routes and o.credential=='api' for o in PROVIDER.operations))

    def test_unknown_route_denied_without_upstream_request(self):
        with self.assertRaises(Denied):
            self.transport.call('stage_message',credential=self.secret)
        self.assertEqual(TestOnlyHandler.requests,[])

    def test_no_post_query_path_or_idempotency(self):
        for kwargs in ({'body':{'x':1}}, {'query':{'x':'a'}}, {'path':{'id':'a'}},
                       {'request_id':'req_'+'a'*32}):
            with self.subTest(kwargs=kwargs):
                with self.assertRaises(Denied):
                    self.transport.call('health',credential=self.secret,**kwargs)
        self.assertEqual(TestOnlyHandler.requests,[])

    def test_credential_required_and_format(self):
        for credential in (None,object(),Secret('synthetic','!')):
            with self.subTest(credential=type(credential).__name__):
                with self.assertRaises(Denied):
                    self.transport.call('health',credential=credential)
        self.assertEqual(TestOnlyHandler.requests,[])

    def test_missing_or_unreadable_ca_is_stop(self):
        with mock.patch.object(obs,'_CA_PATH',self.cert.parent/'missing-ca.pem'):
            with self.assertRaisesRegex(Denied,'OBS_CA_UNAVAILABLE'):
                obs.observatory_context()
        with mock.patch.object(obs,'_CA_PATH',self.cert):
            self.cert.chmod(0o666)
            with self.assertRaisesRegex(Denied,'OBS_CA_UNAVAILABLE'):
                obs.observatory_context()

    def test_ca_symlink_is_stop(self):
        linked=self.cert.parent/'link.pem'
        linked.symlink_to(self.cert)
        with mock.patch.object(obs,'_CA_PATH',linked):
            with self.assertRaisesRegex(Denied,'OBS_CA_UNAVAILABLE'):
                obs.observatory_context()

    def test_wrong_ca_fails_closed(self):
        client=self.make_transport(context=ssl.create_default_context())
        with self.assertRaisesRegex(Denied,'OBS_UPSTREAM_FAILED'):
            client.call('health',credential=self.secret)

    def test_wrong_dns_san_fails_closed(self):
        client=self.make_transport(dns='other.invalid')
        with self.assertRaisesRegex(Denied,'OBS_UPSTREAM_FAILED'):
            client.call('health',credential=self.secret)

    def test_redirect_not_followed(self):
        TestOnlyHandler.mode='redirect'
        with self.assertRaisesRegex(Denied,'OBS_UPSTREAM_STATUS'):
            self.transport.call('health',credential=self.secret)
        self.assertEqual(len(TestOnlyHandler.requests),1)

    def test_content_type_wrong_refused(self):
        TestOnlyHandler.mode='type'
        with self.assertRaisesRegex(Denied,'OBS_RESPONSE_CONTENT_TYPE'):
            self.transport.call('health',credential=self.secret)

    def test_duplicate_json_denied(self):
        TestOnlyHandler.mode='duplicate'
        with self.assertRaises(Denied):
            self.transport.call('health',credential=self.secret)

    def test_oversize_json_denied(self):
        TestOnlyHandler.mode='oversize'
        with self.assertRaisesRegex(Denied,'OBS_RESPONSE_LIMIT'):
            self.transport.call('health',credential=self.secret)

    def test_default_connection_has_no_http_fallback(self):
        with mock.patch.object(obs,'HTTPSConnection') as ctor:
            answer=mock.Mock()
            answer.status=200
            answer.getheader.return_value='application/json; charset=utf-8'
            answer.read.return_value=b'{"ok":true}'
            ctor.return_value.getresponse.return_value=answer
            self.assertEqual(self.transport.routes['health'].method,'GET')
            real=obs.ObservatoryTransport(tuple(PROVIDER.api.routes.values()))
            self.assertEqual(real.call('health',credential=self.secret),{'ok':True})
            self.assertEqual(ctor.call_args.args,('fortis-observatory-api',443))
            self.assertIsInstance(ctor.call_args.kwargs['context'],ssl.SSLContext)
            self.assertEqual(ctor.return_value.request.call_args.args,('GET','/v1/health'))
            self.assertNotIn('18756',str(ctor.call_args))


if __name__=='__main__':
    unittest.main()

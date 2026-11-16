"""Offline real TLS wire for Mirror-specific CA, hostname, fail-closed policy.

No Gateway, Windows, Docker, remote endpoint, vault or production mutation.
"""
import subprocess
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import socket
import ssl
import tempfile
import threading
import unittest
from unittest.mock import patch


from fortis_approvals.core import Denied
from fortis_approvals.extensions.vault import Secret
from fortis_approvals.integrations.mirror import tls


def openssl(root, *args):
    subprocess.check_call(("openssl", *args), cwd=root, stdout=subprocess.DEVNULL,
                          stderr=subprocess.DEVNULL, timeout=15)


class WireFixture(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.ca_path = self.root/"ca.pem"
        self.ca_key = self.root/"ca.key"
        self.generate_ca(self.ca_path,self.ca_key)
        self.original_ca = self.ca_path.read_bytes()
        self.patch_ca = patch.object(tls,"CA_PATH",self.ca_path)
        self.patch_ca.start()
        self.addCleanup(self.patch_ca.stop)
        self.calls = []

    def generate_ca(self, cert, key):
        openssl(self.root,"req","-x509","-newkey","rsa:2048","-nodes",
                "-days","2","-sha256","-subj","/CN=Mirror offline test CA",
                "-addext","basicConstraints=critical,CA:TRUE",
                "-addext","keyUsage=critical,keyCertSign,cRLSign",
                "-keyout",str(key),"-out",str(cert))

    def start_server(self,hostname="host.docker.internal"):
        key_path=self.root/"leaf.key"
        cert_path=self.root/"leaf.pem"
        csr=self.root/"leaf.csr"
        extensions=self.root/"leaf.ext"
        extensions.write_text("basicConstraints=critical,CA:FALSE\n"
                              "extendedKeyUsage=serverAuth\n"
                              "subjectAltName=DNS:"+hostname+"\n")
        openssl(self.root,"req","-new","-newkey","rsa:2048","-nodes",
                "-subj","/CN="+hostname,"-keyout",str(key_path),"-out",str(csr))
        openssl(self.root,"x509","-req","-sha256","-days","2",
                "-in",str(csr),"-CA",str(self.ca_path),"-CAkey",str(self.ca_key),
                "-set_serial","0x1234567890abcdef","-out",str(cert_path),
                "-extfile",str(extensions))

        fixture=self
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                fixture.calls.append((self.path,self.headers.get("Authorization"),
                                      self.headers.get("Host")))
                body=b'{"schemaVersion":1,"repository":{"repoId":"fortis-approvals"}}'
                self.send_response(200)
                self.send_header("Content-Type","application/json")
                self.send_header("Content-Length",str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            def log_message(self,*args):
                return

        server=ThreadingHTTPServer(("127.0.0.1",0),Handler)
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile=str(cert_path),keyfile=str(key_path))
        server.socket=context.wrap_socket(server.socket,server_side=True)
        thread=threading.Thread(target=server.serve_forever,daemon=True)
        thread.start()
        self.addCleanup(lambda:(server.shutdown(),thread.join(timeout=2),
                                server.server_close()))
        real_create=socket.create_connection
        def redirected(address,*args,**kwargs):
            if address!=("host.docker.internal",443):
                raise AssertionError("UNEXPECTED_TARGET")
            return real_create(("127.0.0.1",server.server_port),*args,**kwargs)
        patched=patch("socket.create_connection",side_effect=redirected)
        patched.start()
        self.addCleanup(patched.stop)

    def api_get(self):
        return tls.MirrorPinnedAPI().call(
            "get_repo",credential=Secret("test-generation","x"*48),
            path={"repo_id":"fortis-approvals"})

    def test_real_https_read_validates_ca_hostname_and_injects_bearer(self):
        self.start_server()
        ctx=tls.mirror_context()
        self.assertTrue(ctx.check_hostname)
        self.assertEqual(ssl.CERT_REQUIRED,ctx.verify_mode)
        self.assertEqual("https://host.docker.internal",tls.MirrorPinnedAPI().origin)
        self.assertEqual("fortis-approvals",self.api_get()["repository"]["repoId"])
        self.assertEqual([("/gateway/v1/repositories/fortis-approvals",
                           "Bearer "+"x"*48,"host.docker.internal")],self.calls)

    def test_wrong_hostname_with_trusted_ca_denied_before_http(self):
        self.start_server(hostname="another.invalid")
        with self.assertRaises(Denied) as raised:
            self.api_get()
        self.assertEqual("INTEGRATION_UPSTREAM_FAILED",str(raised.exception))
        self.assertFalse(self.calls)

    def test_wrong_ca_denied_before_http(self):
        self.start_server()
        other_cert=self.root/"other-ca.pem"
        other_key=self.root/"other-ca.key"
        self.generate_ca(other_cert,other_key)
        self.ca_path.write_bytes(other_cert.read_bytes())
        with self.assertRaises(Denied) as raised:
            self.api_get()
        self.assertEqual("INTEGRATION_UPSTREAM_FAILED",str(raised.exception))
        self.assertFalse(self.calls)

    def test_missing_malformed_oversized_and_symlink_ca_fail_closed(self):
        for value in (None,b"not a certificate",b"x"*16385):
            with self.subTest(value="missing" if value is None else len(value)):
                if value is None:
                    self.ca_path.unlink(missing_ok=True)
                else:
                    self.ca_path.write_bytes(value)
                with self.assertRaises(Denied) as raised:
                    self.api_get()
                self.assertEqual("MIRROR_CA_UNAVAILABLE",str(raised.exception))
        other=self.root/"valid-ca.pem"
        other.write_bytes(self.original_ca)
        self.ca_path.unlink()
        self.ca_path.symlink_to(other)
        with self.assertRaises(Denied) as raised:
            self.api_get()
        self.assertEqual("MIRROR_CA_UNAVAILABLE",str(raised.exception))
        self.assertEqual([],self.calls)

    def test_write_routes_and_caller_url_not_accepted(self):
        self.assertIn("get_repo", tls.MirrorPinnedAPI().routes)
        self.assertTrue(all(route.method == "GET" and route.readonly
                            for route in tls.MirrorPinnedAPI().routes.values()))
        for route in ("pull_main","post","unknown"):
            with self.subTest(route=route), self.assertRaises(Denied):
                tls.MirrorPinnedAPI().call(route,path={"repo_id":"fortis-approvals"})
        with self.assertRaises(Denied):
            tls.MirrorPinnedAPI().call("get_repo",
                path={"repo_id":"fortis-approvals"},query={"remote":"true"})
        self.assertFalse(self.calls)


if __name__=="__main__":
    unittest.main()

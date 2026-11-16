"""Offline real-TLS tests for Action Core's fixed DOCKER-HTTPS transport."""
import json
import os
import socket
import ssl
import subprocess
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

from fortis_approvals.core import Denied
from fortis_approvals.extensions.vault import Secret
from fortis_approvals.integrations.action_core import tls


def openssl(root, *args):
    subprocess.check_call(
        ("openssl", *args),
        cwd=root,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=15,
    )


class ActionCoreTLSWireTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.ca_path = self.root / "ca.pem"
        self.ca_key = self.root / "ca.key"
        self.generate_ca(self.ca_path, self.ca_key)
        self.original_ca = self.ca_path.read_bytes()
        patcher = patch.object(tls, "CA_PATH", self.ca_path)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.calls = []
        self.destinations = []
        self.valid_body = json.dumps({
            "action_id": 3,
            "name": "Research",
            "category": "research",
            "current_version_number": 3,
            "definition_yaml": "name: Research\ninstruction: Read only\n",
            "schedule_active": False,
        }).encode()

    def generate_ca(self, certificate, key):
        openssl(
            self.root, "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-days", "2", "-sha256", "-subj", "/CN=Action Core test CA",
            "-addext", "basicConstraints=critical,CA:TRUE",
            "-addext", "keyUsage=critical,keyCertSign,cRLSign",
            "-keyout", str(key), "-out", str(certificate),
        )

    def start_server(self, *, hostname="action-core-gw", body=None, redirect=False):
        key_path = self.root / "leaf.key"
        cert_path = self.root / "leaf.pem"
        csr = self.root / "leaf.csr"
        extensions = self.root / "leaf.ext"
        extensions.write_text(
            "basicConstraints=critical,CA:FALSE\n"
            "extendedKeyUsage=serverAuth\n"
            "subjectAltName=DNS:" + hostname + "\n",
            encoding="ascii",
        )
        openssl(
            self.root, "req", "-new", "-newkey", "rsa:2048", "-nodes",
            "-subj", "/CN=" + hostname, "-keyout", str(key_path),
            "-out", str(csr),
        )
        openssl(
            self.root, "x509", "-req", "-sha256", "-days", "2",
            "-in", str(csr), "-CA", str(self.ca_path), "-CAkey", str(self.ca_key),
            "-set_serial", "0x1234567890abcdef", "-out", str(cert_path),
            "-extfile", str(extensions),
        )
        fixture = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                fixture.calls.append((
                    self.command, self.path, self.headers.get("Host"),
                    self.headers.get("Authorization"),
                ))
                if redirect:
                    self.send_response(302)
                    self.send_header("Location", "http://host.docker.internal:8000/actions")
                    self.end_headers()
                    return
                payload = fixture.valid_body if body is None else body
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, *_args):
                return
        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))
        server.socket = context.wrap_socket(server.socket, server_side=True)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(lambda: (
            server.shutdown(), thread.join(timeout=2), server.server_close(),
        ))
        real_create = socket.create_connection

        def redirected(address, *args, **kwargs):
            self.destinations.append(address)
            if address != ("action-core-gw", 443):
                raise AssertionError("UNEXPECTED_TLS_DESTINATION")
            return real_create(("127.0.0.1", server.server_port), *args, **kwargs)

        patcher = patch("socket.create_connection", side_effect=redirected)
        patcher.start()
        self.addCleanup(patcher.stop)

    def api_call(self):
        return tls.ActionCorePinnedAPI().call(
            "read_action",
            credential=Secret("test-generation", "x" * 48),
            path={"action_id": "3"},
        )

    def test_real_https_read_pins_ca_hostname_and_injects_gateway_bearer(self):
        self.start_server()
        context = tls.action_core_context()
        self.assertTrue(context.check_hostname)
        self.assertEqual(ssl.CERT_REQUIRED, context.verify_mode)
        self.assertEqual(1, len(context.get_ca_certs()))
        self.assertEqual("https://action-core-gw", tls.ActionCorePinnedAPI().origin)
        self.assertEqual(json.loads(self.valid_body), self.api_call())
        self.assertEqual([(
            "GET", "/gateway/v1/actions/3", "action-core-gw", "Bearer " + "x" * 48,
        )], self.calls)

    def test_wrong_hostname_with_trusted_ca_is_denied_before_http(self):
        self.start_server(hostname="wrong-name.invalid")
        with self.assertRaises(Denied) as raised:
            self.api_call()
        self.assertEqual("INTEGRATION_UPSTREAM_FAILED", str(raised.exception))
        self.assertEqual([], self.calls)

    def test_wrong_ca_is_denied_before_http(self):
        self.start_server()
        other_certificate = self.root / "other-ca.pem"
        other_key = self.root / "other-ca.key"
        self.generate_ca(other_certificate, other_key)
        self.ca_path.write_bytes(other_certificate.read_bytes())
        with self.assertRaises(Denied) as raised:
            self.api_call()
        self.assertEqual("INTEGRATION_UPSTREAM_FAILED", str(raised.exception))
        self.assertEqual([], self.calls)

    def test_missing_malformed_oversized_and_symlink_ca_fail_closed(self):
        for value in (
            None,
            b"not a certificate",
            b"-----BEGIN PRIVATE KEY-----\\nnot-a-public-ca\\n-----END PRIVATE KEY-----\\n",
            b"x" * 16385,
        ):
            with self.subTest(value="missing" if value is None else len(value)):
                if value is None:
                    self.ca_path.unlink(missing_ok=True)
                else:
                    self.ca_path.write_bytes(value)
                with self.assertRaises(Denied) as raised:
                    tls.action_core_context()
                self.assertEqual("ACTION_CORE_CA_UNAVAILABLE", str(raised.exception))
        other = self.root / "valid-ca.pem"
        other.write_bytes(self.original_ca)
        self.ca_path.unlink()
        self.ca_path.symlink_to(other)
        with self.assertRaises(Denied) as raised:
            tls.action_core_context()
        self.assertEqual("ACTION_CORE_CA_UNAVAILABLE", str(raised.exception))

    def test_writable_or_hardlinked_ca_is_rejected(self):
        self.ca_path.chmod(0o664)
        with self.assertRaises(Denied) as raised:
            tls.action_core_context()
        self.assertEqual("ACTION_CORE_CA_UNAVAILABLE", str(raised.exception))

        self.ca_path.chmod(0o644)
        hardlink = self.root / "ca-hardlink.pem"
        os.link(self.ca_path, hardlink)
        with self.assertRaises(Denied) as raised:
            tls.action_core_context()
        self.assertEqual("ACTION_CORE_CA_UNAVAILABLE", str(raised.exception))

    def test_redirect_is_not_followed_or_downgraded_to_http(self):
        self.start_server(redirect=True)
        with self.assertRaises(Denied) as raised:
            self.api_call()
        self.assertEqual("INTEGRATION_UPSTREAM_FAILED", str(raised.exception))
        self.assertEqual(1, len(self.calls))
        self.assertEqual([("action-core-gw", 443)], self.destinations)

    def test_malformed_json_is_rejected(self):
        self.start_server(body=b"not-json")
        with self.assertRaises(Denied):
            self.api_call()
        self.assertEqual(1, len(self.calls))

    def test_oversized_json_is_rejected_without_truncation(self):
        self.start_server(body=b"{" + b"x" * 65_536 + b"}")
        with self.assertRaises(Denied):
            self.api_call()
        self.assertEqual(1, len(self.calls))

    def test_missing_credential_and_out_of_scope_target_are_denied_before_tls(self):
        api = tls.ActionCorePinnedAPI()
        secret = Secret("test-generation", "x" * 48)
        with self.assertRaises(Denied) as raised:
            api.call("read_action", path={"action_id": "3"})
        self.assertEqual("ACTION_CORE_CREDENTIAL_REQUIRED", str(raised.exception))
        with self.assertRaises(Denied) as raised:
            api.call("read_action", credential=secret, path={"action_id": "5"})
        self.assertEqual("ACTION_CORE_TARGET_DENIED", str(raised.exception))
        self.assertEqual([], self.destinations)

    def test_route_query_body_and_http_fallback_are_not_available(self):
        api = tls.ActionCorePinnedAPI()
        self.assertTrue(api.origin.startswith("https://"))
        with self.assertRaises(Denied):
            api.call("write_action")
        self.start_server()
        secret = Secret("test-generation", "x" * 48)
        with self.assertRaises(Denied):
            api.call("read_action", credential=secret, path={"action_id": "3"},
                     query={"version": "3"})
        with self.assertRaises(Denied):
            api.call("read_action", credential=secret, path={"action_id": "3"},
                     body={"anything": True})
        self.assertEqual([], self.calls)


if __name__ == "__main__":
    unittest.main()

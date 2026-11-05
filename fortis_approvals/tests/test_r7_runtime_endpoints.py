"""Runtime endpoint validation for side-by-side R7 review deployments."""
import os
import unittest
from unittest.mock import patch

from fortis_approvals import r7_unified_server as server


class R7RuntimeEndpointConfigTests(unittest.TestCase):
    def test_default_endpoints_preserve_production_ports(self):
        with patch.dict(os.environ, {}, clear=True):
            self.assertEqual(server.runtime_endpoints(), (
                "http://localhost:19103", "host.docker.internal:19104"))

    def test_alternate_host_ports_are_supported_for_isolated_review(self):
        with patch.dict(os.environ, {
                "FORTIS_OWNER_ORIGIN": "http://localhost:19203",
                "FORTIS_MACHINE_HOST": "host.docker.internal:19204",
        }, clear=True):
            self.assertEqual(server.runtime_endpoints(), (
                "http://localhost:19203", "host.docker.internal:19204"))

    def test_non_local_or_malformed_endpoints_are_rejected(self):
        invalid = (
            ({"FORTIS_OWNER_ORIGIN": "http://example.com:19203"},
             "R7_OWNER_ORIGIN_INVALID"),
            ({"FORTIS_OWNER_ORIGIN": "http://localhost:80"},
             "R7_OWNER_ORIGIN_INVALID"),
            ({"FORTIS_MACHINE_HOST": "example.com:19204"},
             "R7_MACHINE_HOST_INVALID"),
            ({"FORTIS_MACHINE_HOST": "host.docker.internal:70000"},
             "R7_MACHINE_HOST_INVALID"),
        )
        for values, error in invalid:
            with self.subTest(values=values), patch.dict(
                    os.environ, values, clear=True):
                with self.assertRaisesRegex(RuntimeError, error):
                    server.runtime_endpoints()


if __name__ == "__main__":
    unittest.main()

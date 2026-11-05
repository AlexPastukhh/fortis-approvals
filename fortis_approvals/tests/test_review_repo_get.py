"""Review GET source pin and endpoint selection, with no real network/grant."""
import importlib.util
from contextlib import redirect_stdout
from io import StringIO
import json
import hashlib
from pathlib import Path
import unittest
from unittest.mock import patch
from fortis_approvals.integrations.sonarcloud.repo_client import client

ROOT = Path(__file__).resolve().parents[2]
PATH = ROOT / 'fortis_approvals/deploy/review_repo_get.py'
spec = importlib.util.spec_from_file_location('review_get', PATH)
helper = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helper)


class ReviewRepoGetTests(unittest.TestCase):
    def test_only_review_endpoint_used_after_source_verification(self):
        pinned = json.loads((PATH.parent / 'review-repo-source-hashes-20261105.json').read_text())
        # Endpoint-selection fixture uses current source bytes; the historical
        # built-image pin remains immutable and is checked separately below.
        hashes = {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in pinned}
        calls = []
        def call(operation, *, target, request_id):
            calls.append((client.ENDPOINT, client.ALLOW_TEST_ENDPOINTS, operation, target))
            return {'requestId': request_id, 'service': 'sonarcloud',
                    'operation': 'get_quality_gate', 'data': {'status': 'OK'}}
        with (patch.object(helper, 'ROOT', ROOT), patch.object(client, 'call', side_effect=call),
              patch.object(client, 'ENDPOINT', client.ENDPOINT),
              patch.object(client, 'ALLOW_TEST_ENDPOINTS', client.ALLOW_TEST_ENDPOINTS),
              patch.object(helper.sys, 'path', list(helper.sys.path))):
            with redirect_stdout(StringIO()):
                helper.run(hashes)
        self.assertEqual(calls, [('https://host.docker.internal:19204', True,
            'sonar.get_quality_gate', 'AlexPastukhh_obs-planning-docs')])

    def test_changed_client_source_is_rejected_before_any_call(self):
        with patch.object(helper, 'ROOT', ROOT), patch.object(client, 'call') as call:
            with self.assertRaisesRegex(RuntimeError, 'SOURCE_HASH_MISMATCH'):
                helper.run({'fortis_approvals/clients/gateway_transport.py': '0' * 64})
            call.assert_not_called()

    def test_historical_review_pin_is_not_silently_retargeted(self):
        pinned = json.loads((PATH.parent / 'review-repo-source-hashes-20261105.json').read_text())
        with patch.object(helper, 'ROOT', ROOT), patch.object(client, 'call') as call:
            with self.assertRaisesRegex(RuntimeError, 'SOURCE_HASH_MISMATCH'):
                helper.run(pinned)
            call.assert_not_called()

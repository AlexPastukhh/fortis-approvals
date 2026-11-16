"""Offline own-API doctor + acceptance contract; no live network."""
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock
import uuid

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
import own_api_doctor as doctor
import own_api_acceptance as accept


def manifest(name):
    return doctor.manifest_checker.load(
        (ROOT / "docs/templates/own-api" / name).resolve())


class FakeClient:
    def __init__(self, service="mirror", operation="get_repository",
                 target="fortis-approvals", *, digest="a" * 64, ready=True):
        self.service, self.operation, self.target = service, operation, target
        self.digest, self.ready = digest, ready
        self.calls = 0
        self.lookups = 0
        self.reply = {"state": "EXECUTED", "data": {
            "schemaVersion": 1, "repository": {
                "repoId": "fortis-approvals",
                "docker": {
                    "primary": {
                        "branch": "main", "head": "b" * 40,
                        "clean": True, "targetEligible": True
                    },
                    "worktrees": []
                },
                "windows": {
                    "source": "windows", "checkedAt": "2026-11-13T00:00:00+00:00",
                    "exists": True, "branch": "main", "head": "b" * 40,
                    "clean": True, "originValid": True, "relation": "equal",
                    "error": None
                },
                "github": {"verification": "NOT_CHECKED"}
            }
        }}

    def catalog(self):
        return {"schemaVersion": 1, "configurationDigest": self.digest,
                "operations": [{"service": self.service, "operation": self.operation,
                                "target": self.target, "kind": "read", "policy": "ALLOW",
                                "version": "1", "ready": self.ready,
                                "credential": {"ready": True}}]}

    def call(self, service, operation, target, params, *, reason, request_id):
        self.calls += 1
        return {**self.reply, "requestId": request_id}

    def result(self, request_id, *, reconcile):
        assert reconcile is False
        self.lookups += 1
        return {**self.reply, "requestId": request_id}


class DoctorTests(unittest.TestCase):
    def test_source_only_does_not_claim_live(self):
        out = doctor.diagnose(manifest("mirror-read.example.json"))
        self.assertEqual(out["status"], "SOURCE_MANIFEST_VALID")
        self.assertEqual(out["upstreamTls"], "NOT_CHECKED")
        self.assertEqual(out["liveRead"], "NOT_EXECUTED")
        self.assertEqual(out["catalog"]["status"], "UNKNOWN")

    def test_catalog_readiness_does_not_claim_live(self):
        example = manifest("mirror-read.example.json")
        out = doctor.diagnose(example, catalog=FakeClient().catalog())
        self.assertEqual(out["status"], "CATALOG_READY_READ_NOT_TESTED")
        self.assertEqual(out["liveRead"], "NOT_EXECUTED")
        self.assertEqual(out["workerQuiescence"], "NOT_PROVEN")

    def test_catalog_wrong_target_or_policy_is_stop(self):
        example = manifest("mirror-read.example.json")
        for changes in ({"target": "other"}, {"policy": "ASK"},
                        {"kind": "write"}, {"ready": False}):
            with self.subTest(changes=changes):
                c = FakeClient().catalog()
                c["operations"][0].update(changes)
                out = doctor.diagnose(example, catalog=c)
                self.assertEqual(out["status"], "STOP_CATALOG_MISMATCH")

    def test_truncated_inventory_never_claims_completeness(self):
        report = doctor.core_summary(
            {"items": [{"state": "UNCERTAIN"}], "truncated": True,
             "total": 120, "nextOffset": 100},
            {"claimed": 1, "queued": 0, "truncated": False})
        self.assertEqual(report["requestInventoryCoverage"], "PARTIAL")

    def test_core_summary_heartbeat_not_quiescence_proof(self):
        out = doctor.core_summary({"items": [
            {"state": "UNCERTAIN"}, {"state": "UNCERTAIN"},
            {"state": "APPROVED"}
        ], "truncated": False, "total": 3, "offset": 0},
            {"claimed": 1, "queued": 0, "quiescenceProven": False,
             "truncated": False})
        self.assertEqual(out["unresolvedStatesOnPage"]["UNCERTAIN"], 2)
        self.assertEqual(out["claimed"], 1)
        self.assertEqual(out["requestInventoryCoverage"], "COMPLETE_SNAPSHOT")
        self.assertEqual(out["workerQuiescence"], "OWNER_CONFIRMATION_REQUIRED")

    def test_missing_or_inconsistent_inventory_never_claims_complete(self):
        requests = {'items': [], 'total': 0, 'offset': 0, 'truncated': False}
        activity = {'claimed': 0, 'queued': 0, 'truncated': False}
        for req, act in (({'items': []}, activity),
                         (dict(requests, total=10), activity),
                         (dict(requests, offset=100), activity),
                         (requests, {'claimed': 0, 'queued': 0})):
            with self.subTest(requests=req, activity=act):
                report = doctor.core_summary(req, act)
                self.assertNotEqual('COMPLETE_SNAPSHOT', report['requestInventoryCoverage'])


class AcceptanceTests(unittest.TestCase):
    def setUp(self):
        self.m = manifest("mirror-read.example.json")
        self.client = FakeClient()
        self.uuid = str(uuid.uuid4())
        self.base = dict(operation="get_repository", target="fortis-approvals",
                         request_id=self.uuid, expected_digest="a" * 64,
                         client=self.client)

    def test_preview_only_never_creates_journal_or_calls(self):
        with tempfile.TemporaryDirectory() as directory:
            # Temporarily substitute accepted Workfiles journal root for offline tests.
            original = accept.intent_path
            accept.intent_path = lambda path: path
            try:
                path = Path(directory) / "read.json"
                out = accept.acceptance(self.m, journal=path, submit_read=False, **self.base)
                self.assertEqual(out["status"], "READY_FOR_ONE_SHOT_READ")
                self.assertFalse(path.exists())
                self.assertEqual(self.client.calls, 0)
            finally:
                accept.intent_path = original

    def test_one_submit_then_only_result_lookup(self):
        with tempfile.TemporaryDirectory() as directory:
            original = accept.intent_path
            accept.intent_path = lambda path: path
            try:
                path = Path(directory) / "read.json"
                first = accept.acceptance(self.m, journal=path, submit_read=True, **self.base)
                self.assertEqual(first["status"], "LIVE_TYPED_READ_VERIFIED")
                self.assertTrue(path.exists())
                self.assertEqual(self.client.calls, 1)
                second = accept.acceptance(self.m, journal=path, submit_read=True, **self.base)
                self.assertEqual(second["status"], "LIVE_TYPED_READ_VERIFIED")
                self.assertEqual(self.client.calls, 1)
                self.assertEqual(self.client.lookups, 1)
            finally:
                accept.intent_path = original

    def test_unknown_never_replayed(self):
        self.client.reply = {"state": "UNCERTAIN"}
        with tempfile.TemporaryDirectory() as directory:
            original = accept.intent_path
            accept.intent_path = lambda path: path
            try:
                path = Path(directory) / "read.json"
                out = accept.acceptance(self.m, journal=path, submit_read=True, **self.base)
                self.assertEqual(out["status"], "UNKNOWN_STOP_NO_REPLAY")
                accept.acceptance(self.m, journal=path, submit_read=True, **self.base)
                self.assertEqual(self.client.calls, 1)
            finally:
                accept.intent_path = original

    def test_wrong_digest_denied_before_journal_or_call(self):
        with tempfile.TemporaryDirectory() as directory:
            original = accept.intent_path
            accept.intent_path = lambda path: path
            try:
                path = Path(directory) / "read.json"
                data = dict(self.base, expected_digest="c" * 64)
                with self.assertRaises(accept.AcceptanceStop):
                    accept.acceptance(self.m, journal=path, submit_read=True, **data)
                self.assertEqual(self.client.calls, 0)
                self.assertFalse(path.exists())
            finally:
                accept.intent_path = original

    def test_journal_path_traversal_denied(self):
        with self.assertRaisesRegex(accept.AcceptanceStop, "JOURNAL_OWNER_WORKFILES_REQUIRED"):
            accept.intent_path(Path("/workspace/repo/Workfiles/../Repos/fortis-approvals/tmp.json"))

    def test_result_uuid_mismatch_denied(self):
        class WrongUuid(FakeClient):
            def call(self, *args, **kwargs):
                self.calls += 1
                return {**self.reply, "requestId": str(uuid.uuid4())}
        with tempfile.TemporaryDirectory() as directory:
            original = accept.intent_path
            accept.intent_path = lambda path: path
            try:
                with self.assertRaisesRegex(accept.AcceptanceStop, "RESPONSE_REQUEST_ID_MISMATCH"):
                    accept.acceptance(self.m, journal=Path(directory) / "read.json",
                                      submit_read=True, **dict(self.base, client=WrongUuid()))
            finally:
                accept.intent_path = original

    def test_unpinned_second_fixture_never_submits(self):
        with tempfile.TemporaryDirectory() as directory:
            original = accept.intent_path
            accept.intent_path = lambda path: path
            try:
                with self.assertRaisesRegex(accept.AcceptanceStop, "UPSTREAM_SOURCE_NOT_PINNED"):
                    accept.acceptance(manifest("second-api-docker.fixture.json"),
                                      journal=Path(directory) / "read.json",
                                      submit_read=True, **self.base)
                self.assertEqual(self.client.calls, 0)
            finally:
                accept.intent_path = original

    def test_invalid_journal_binding_denied(self):
        with tempfile.TemporaryDirectory() as directory:
            original = accept.intent_path
            accept.intent_path = lambda path: path
            try:
                path = Path(directory) / "read.json"
                accept.acceptance(self.m, journal=path, submit_read=True, **self.base)
                another = dict(self.base, request_id=str(uuid.uuid4()))
                with self.assertRaisesRegex(accept.AcceptanceStop, "JOURNAL_BINDING_CHANGED"):
                    accept.acceptance(self.m, journal=path, submit_read=True, **another)
                self.assertEqual(self.client.calls, 1)
            finally:
                accept.intent_path = original

    def test_local_provider_version_mismatch_stops_before_ready_or_submit(self):
        catalog = self.client.catalog()
        catalog['operations'][0]['version'] = '999'
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'read.json'
            with mock.patch.object(accept, 'intent_path', return_value=path), \
                 mock.patch.object(self.client, 'catalog', return_value=catalog):
                for submit in (False, True):
                    with self.assertRaisesRegex(accept.AcceptanceStop, 'PROVIDER_SOURCE_VERSION_CHANGED'):
                        accept.acceptance(self.m, journal=path, submit_read=submit, **self.base)
            self.assertFalse(path.exists())
            self.assertEqual(0, self.client.calls)

    def test_short_journal_write_never_submits(self):
        write = accept.os.write
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'read.json'
            with mock.patch.object(accept, 'intent_path', return_value=path), \
                 mock.patch.object(accept.os, 'write', side_effect=lambda fd, data: write(fd, data[:-1])):
                with self.assertRaisesRegex(accept.AcceptanceStop, 'JOURNAL_WRITE_INCOMPLETE'):
                    accept.acceptance(self.m, journal=path, submit_read=True, **self.base)
            self.assertEqual(0, self.client.calls)

    def test_directory_sync_failure_never_submits(self):
        fsync = accept.os.fsync
        def sync(fd):
            if accept.stat.S_ISDIR(accept.os.fstat(fd).st_mode):
                raise OSError('fixture directory sync failure')
            return fsync(fd)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'read.json'
            with mock.patch.object(accept, 'intent_path', return_value=path), \
                 mock.patch.object(accept.os, 'fsync', side_effect=sync):
                with self.assertRaises(OSError):
                    accept.acceptance(self.m, journal=path, submit_read=True, **self.base)
            self.assertEqual(0, self.client.calls)

    def test_other_provider_uses_its_manifest_response_limit(self):
        from types import SimpleNamespace
        example = manifest('mirror-read.example.json')
        example['serviceId'] = 'metricsprobe'
        example['operations'][0]['maxResponseBytes'] = 150000
        client = FakeClient(service='metricsprobe')
        client.reply = {'state': 'EXECUTED', 'data': {'payload': 'x' * 70000}}
        def result(value):
            self.assertEqual({'payload'}, set(value))
            self.assertIsInstance(value['payload'], str)
        op = SimpleNamespace(name='get_repository', kind='read', ready=True,
                             version='1', params=lambda value: value, result=result)
        provider = SimpleNamespace(operations=(op,))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'read.json'
            with mock.patch.object(accept, 'intent_path', return_value=path), \
                 mock.patch('fortis_approvals.extensions.model.discover', return_value=(provider,)):
                out = accept.acceptance(example, journal=path, submit_read=True,
                                        **dict(self.base, client=client))
                self.assertEqual('LIVE_TYPED_READ_VERIFIED', out['status'])
                self.assertGreater(out['resultBytes'], 65536)


if __name__ == "__main__":
    unittest.main()

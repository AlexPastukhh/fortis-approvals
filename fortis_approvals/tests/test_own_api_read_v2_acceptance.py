"""UC-GW-012 S2: strict READ v2 parameters, one-shot replay safety (offline)."""
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

V2 = ROOT / "docs/templates/own-api/mirror-read-v2.source.json"
V1 = ROOT / "docs/templates/own-api/mirror-read.example.json"
DIGEST = "a" * 64
TIME = "2026-11-20T10:00:00Z"


def fixture(operation, target, data, *, error=None):
    return {"schemaVersion": 2, "operation": operation, "target": target,
            "checkedAt": TIME, "data": data, "error": error}


def paged_result(operation="list_repositories_v2", target="mirror-pilot"):
    return fixture(operation, target, {"items": [], "nextOffset": None,
                                    "truncated": False, "inventoryRevision": "b" * 64})


def lookup_result(request_id, target="fortis-approvals"):
    return fixture("get_windows_pull_result_v2", target, {
        "requestId": request_id, "repoId": target, "workerState": "NOT_FOUND",
        "effect": "UNKNOWN", "observedHead": None, "expectedTarget": None,
        "checkedAt": TIME, "errorCode": None, "evidence": "NONE"})


class Client:
    def __init__(self, manifest, reply):
        self.manifest = manifest
        self.reply = {"state": "EXECUTED", "data": reply}
        self.catalog_reads = 0
        self.calls = []
        self.lookups = 0

    def catalog(self):
        self.catalog_reads += 1
        ops = []
        for row in self.manifest["operations"]:
            for target in row["targets"]:
                ops.append({"service": self.manifest["serviceId"],
                            "operation": row["name"], "target": target,
                            "kind": "read", "policy": "ALLOW",
                            "version": "1" if row["name"] == "get_repository" else "2",
                            "ready": True, "credential": {"ready": True}})
        return {"configurationDigest": DIGEST, "operations": ops}

    def call(self, service, operation, target, params, *, reason, request_id):
        self.calls.append((service, operation, target, params, request_id))
        return {**self.reply, "requestId": request_id}

    def result(self, request_id, *, reconcile):
        assert reconcile is False
        self.lookups += 1
        return {**self.reply, "requestId": request_id}


class ParamsTests(unittest.TestCase):
    def setUp(self):
        self.manifest = doctor.manifest_checker.load(V2)

    def test_doctor_source_only_paged_and_lookup(self):
        params = {"offset": 0, "limit": 5, "inventoryRevision": None}
        row = doctor.diagnose(self.manifest, operation="list_repositories_v2",
                              target="mirror-pilot", params=params)
        self.assertEqual(row["status"], "SOURCE_MANIFEST_VALID")
        self.assertFalse(row["typedParameters"]["liveVerified"])
        self.assertEqual(row["typedParameters"]["providerVersion"], "2")
        self.assertEqual(len(row["typedParameters"]["paramsDigest"]), 64)
        ident = str(uuid.uuid4())
        row = doctor.diagnose(self.manifest,
                operation="get_windows_pull_result_v2", target="fortis-approvals",
                params={"requestId": ident})
        self.assertEqual(row["typedParameters"]["status"], "SOURCE_VALIDATED")

    def test_invalid_json_and_duplicate_keys_rejected_without_echo(self):
        for bad in ('[]', 'null', 'NaN', '{"offset":0,"offset":1}',
                    '{"offset":Infinity}', '{' + 'x'*2100 + '}', chr(0xD800)):
            with self.subTest(bad=bad[:25]), self.assertRaisesRegex(
                    doctor.TypedParamsStop, "PARAMS_JSON_INVALID"):
                doctor.parse_params_json(bad)
        self.assertEqual(doctor.parse_params_json('{}'), {})
        with self.assertRaisesRegex(doctor.TypedParamsStop, "PARAMS_JSON_INVALID"):
            doctor.params_digest({"amount": float('nan')})

    def test_wrong_scope_paging_uuid_and_unknown_fields_fail_closed(self):
        valid = {"offset": 0, "limit": 5, "inventoryRevision": None}
        for op, target, values, code in (
            ("list_repositories_v2", "fortis-approvals", valid, "OPERATION_NOT_ALLOWLISTED"),
            ("list_repositories_v2", "mirror-pilot", {}, "PROVIDER_PARAMS_SCHEMA_INVALID"),
            ("list_worktrees_v2", "fortis-approvals",
             {"offset": 5, "limit": 5, "inventoryRevision": None}, "PROVIDER_PARAMS_SCHEMA_INVALID"),
            ("get_github_status_v2", "fortis-approvals",
             {"offset": 0, "limit": 101, "inventoryRevision": None}, "PROVIDER_PARAMS_SCHEMA_INVALID"),
            ("get_windows_pull_result_v2", "fortis-approvals",
             {"requestId": "not-a-uuid"}, "PROVIDER_PARAMS_SCHEMA_INVALID"),
            ("get_windows_pull_result_v2", "fortis-approvals",
             {"requestId": str(uuid.uuid4()), "url": "https://evil.test"}, "PROVIDER_PARAMS_SCHEMA_INVALID"),
            ("get_capabilities_v2", "mirror-pilot", valid, "PROVIDER_PARAMS_SCHEMA_INVALID"),
        ):
            with self.subTest(op=op,code=code), self.assertRaisesRegex(
                    doctor.TypedParamsStop, code):
                doctor.typed_source_operation(self.manifest, op, target, values)
        self.assertEqual(doctor.typed_source_operation(self.manifest,
            "list_worktrees_v2", "fortis-approvals",
            {"offset": 5, "limit": 5, "inventoryRevision": "f" * 64})[0].version, "2")


class AcceptanceTests(unittest.TestCase):
    def setUp(self):
        self.manifest = doctor.manifest_checker.load(V2)
        self.request = str(uuid.uuid4())
        self.page = {"offset": 0, "limit": 5, "inventoryRevision": None}
        self.client = Client(self.manifest, paged_result())
        self.common = dict(operation="list_repositories_v2", target="mirror-pilot",
            request_id=self.request, expected_digest=DIGEST, client=self.client)

    def perform(self, path, submit_read=True, **overrides):
        kwargs = dict(self.common, params=self.page)
        kwargs.update(overrides)
        with mock.patch.object(accept, "intent_path", return_value=path):
            return accept.acceptance(self.manifest, journal=path,
                                     submit_read=submit_read, **kwargs)

    def test_paged_read_propagates_exact_params_and_replay_reads_only_result(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "paged.json"
            ready = self.perform(path, submit_read=False)
            self.assertEqual(ready["status"], "READY_FOR_ONE_SHOT_READ")
            self.assertFalse(path.exists())
            self.assertEqual(self.client.calls, [])
            first = self.perform(path)
            self.assertEqual(first["status"], "LIVE_TYPED_READ_VERIFIED")
            self.assertEqual(len(self.client.calls), 1)
            self.assertEqual(self.client.calls[0][3], self.page)
            intent = json.loads(path.read_text())
            self.assertEqual(intent["paramsDigest"], doctor.params_digest(self.page))
            second = self.perform(path)
            self.assertEqual(second["status"], "LIVE_TYPED_READ_VERIFIED")
            self.assertEqual(len(self.client.calls), 1)
            self.assertEqual(self.client.lookups, 1)

    def test_changed_params_same_uuid_is_rejected_without_replay(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "paged.json"
            self.perform(path)
            with self.assertRaisesRegex(accept.AcceptanceStop, "JOURNAL_BINDING_CHANGED"):
                self.perform(path, params={"offset": 0, "limit": 6,
                                            "inventoryRevision": None})
            self.assertEqual(len(self.client.calls), 1)
            self.assertEqual(self.client.lookups, 0)

    def test_invalid_params_fail_before_catalog_or_submit(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "bad.json"
            with self.assertRaisesRegex(accept.AcceptanceStop, "PROVIDER_PARAMS_SCHEMA_INVALID"):
                self.perform(path, params={"offset": 1, "limit": 5, "inventoryRevision": None})
            self.assertEqual(self.client.catalog_reads, 0)
            self.assertFalse(path.exists())
            self.assertFalse(self.client.calls)

    def test_v2_outer_request_uuid_requires_version4_before_catalog(self):
        wrong_version = "00000000-0000-1000-8000-000000000000"
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "bad-version.json"
            with self.assertRaisesRegex(accept.AcceptanceStop, "UUID_V4_REQUIRED"):
                self.perform(path, request_id=wrong_version)
            self.assertEqual(self.client.catalog_reads, 0)
            self.assertFalse(path.exists())
            self.assertFalse(self.client.calls)

    def test_lookup_bound_uuid_is_sent_and_checked(self):
        rid = str(uuid.uuid4())
        self.client.reply = {"state": "EXECUTED", "data": lookup_result(rid)}
        with tempfile.TemporaryDirectory() as folder:
            row = self.perform(Path(folder) / "lookup.json", operation="get_windows_pull_result_v2",
                               target="fortis-approvals", params={"requestId": rid})
            self.assertEqual(row["status"], "LIVE_TYPED_READ_VERIFIED")
            self.assertEqual(self.client.calls[0][3], {"requestId": rid})

    def test_wrong_target_receipt_or_error_fails_without_false_verified(self):
        rid = str(uuid.uuid4())
        with tempfile.TemporaryDirectory() as folder:
            for name, data in (
                ("wrong-target", lookup_result(rid, target="other-repo")),
                ("wrong-id", lookup_result(str(uuid.uuid4()))),
                ("upstream-error", fixture("get_windows_pull_result_v2", "fortis-approvals",
                     None, error={"code": "TIMEOUT", "retryable": False})),
            ):
                with self.subTest(name=name):
                    self.client.reply = {"state": "EXECUTED", "data": data}
                    with self.assertRaisesRegex(accept.AcceptanceStop, "MIRROR_V2_RESULT_SCOPE_CHANGED"):
                        self.perform(Path(folder) / (name + ".json"),
                            operation="get_windows_pull_result_v2", target="fortis-approvals",
                            params={"requestId": rid}, request_id=str(uuid.uuid4()))
            self.assertEqual(len(self.client.calls), 3)

    def test_unknown_no_replay_even_with_params(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "unknown.json"
            self.client.reply = {"state": "UNCERTAIN"}
            self.assertEqual(self.perform(path)["status"], "UNKNOWN_STOP_NO_REPLAY")
            self.assertEqual(self.perform(path)["status"], "UNKNOWN_STOP_NO_REPLAY")
            self.assertEqual(len(self.client.calls), 1)
            self.assertEqual(self.client.lookups, 1)

    def test_v1_empty_params_journal_shape_unchanged(self):
        v1 = doctor.manifest_checker.load(V1)
        old = Client(v1, {"schemaVersion": 1, "repository": {}})
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "old.json"
            with mock.patch.object(accept, "intent_path", return_value=path), \
                 mock.patch.object(accept, "validate_data", return_value=15):
                accept.acceptance(v1, operation="get_repository", target="fortis-approvals",
                    request_id=self.request, expected_digest=DIGEST,
                    journal=path, submit_read=True, client=old)
            payload = json.loads(path.read_text())
            self.assertNotIn("paramsDigest", payload)
            self.assertEqual(old.calls[0][3], {})


if __name__ == "__main__":
    unittest.main()

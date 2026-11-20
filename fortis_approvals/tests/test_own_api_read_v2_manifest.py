"""UC-GW-012 S1: source-only fixed Mirror READ v2 manifest, no live grant."""
import copy
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "scripts/check-own-api-manifest.py"
SPEC = importlib.util.spec_from_file_location("ucgw012_s1_checker", TOOL)
checker = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(checker)
SOURCE = ROOT / "docs/templates/own-api/mirror-read-v2.source.json"
LEGACY = ROOT / "docs/templates/own-api/mirror-read.example.json"


class MirrorReadV2SourceManifestTests(unittest.TestCase):
    def setUp(self):
        self.manifest = json.loads(SOURCE.read_text(encoding="utf-8"))
        self.lookup = next(op for op in self.manifest["operations"]
                           if op["name"] == "get_windows_pull_result_v2")

    def denied(self, reason, mutate):
        x = copy.deepcopy(self.manifest)
        row = next(op for op in x["operations"]
                   if op["name"] == "get_windows_pull_result_v2")
        mutate(row)
        with self.assertRaises(checker.ManifestStop) as ctx:
            checker.validate(x)
        self.assertEqual(str(ctx.exception), reason)

    def test_all_eight_read_v2_and_v1_manifest_only(self):
        from fortis_approvals.integrations.mirror.tls import ROUTES
        from fortis_approvals.integrations.mirror.read_v2 import READS
        result = checker.validate(self.manifest)
        self.assertEqual(result["operationCount"], 9)
        self.assertEqual(result["status"], "SOURCE_MANIFEST_VALID")
        self.assertFalse(result["liveVerified"])
        self.assertFalse(result["readyToDeploy"])
        self.assertEqual(self.manifest["sourceSha"],
                         "77382f489bbf057aac53e3ee99664df87f017732")
        opmap = {op["name"]: op for op in self.manifest["operations"]}
        self.assertEqual(set(opmap), {"get_repository"} | set(READS))
        for route in ROUTES:
            op = opmap["get_repository" if route.name == "get_repo" else route.name]
            self.assertEqual((op["method"], op["path"]), (route.method, route.path))
            self.assertTrue(route.readonly)
            self.assertEqual((op["effect"], op["policy"]), ("READ", "ALLOW"))
        self.assertEqual(self.lookup["pathParameters"], {"request_id": "uuid4"})
        self.assertEqual(self.lookup["targets"], ["fortis-approvals"])
        self.assertEqual(checker.validate(json.loads(LEGACY.read_text()))["operationCount"], 1)

    def test_duplicate_unknown_or_mistyped_extras_fail_closed(self):
        for value in ({}, {"request_id": "string"},
                      {"request_id": "uuid4", "extra": "uuid4"},
                      ["request_id"], "request_id", None):
            with self.subTest(value=value):
                self.denied("ROUTE_PATH_PARAMETERS_INVALID",
                            lambda row: row.update(pathParameters=value))

    def test_receipt_path_requires_exact_target_then_uuid(self):
        for path in ("/gateway/v2/repositories/{repo_id}/pull-results/{wrong}",
                     "/gateway/v2/repositories/{request_id}/pull-results/{repo_id}",
                     "/gateway/v2/repositories/{repo_id}/pull-results/{request_id}/{request_id}",
                     "/gateway/v2/repositories/{repo_id}/pull-results",):
            with self.subTest(path=path):
                self.denied("ROUTE_TARGET_BINDING_INVALID",
                            lambda row: row.update(path=path))
        self.denied("ROUTE_TARGET_BINDING_INVALID",
                    lambda row: row.update(targetBinding=None))
        self.denied("ROUTE_NOT_CLOSED",
                    lambda row: row.update(path=row["path"] + "?raw=true"))
        self.denied("MANIFEST_READ_ONLY_REQUIRED",
                    lambda row: row.update(method="POST"))
        self.denied("MANIFEST_READ_ONLY_REQUIRED",
                    lambda row: row.update(policy="ASK"))
        self.denied("MANIFEST_TARGET_SCOPE_INVALID",
                    lambda row: row.update(targets=["*"]))

    def test_extra_marker_cannot_be_added_to_unbound_route(self):
        x = copy.deepcopy(self.manifest)
        row = next(op for op in x["operations"] if op["name"] == "get_capabilities_v2")
        row["pathParameters"] = {"request_id": "uuid4"}
        with self.assertRaisesRegex(checker.ManifestStop, "ROUTE_TARGET_BINDING_INVALID"):
            checker.validate(x)


if __name__ == "__main__":
    unittest.main()

"""Offline second-API onboarding rehearsal; no network/Docker/vault effects."""
import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/check-own-api-manifest.py"
DOC = ROOT / "docs/templates/own-api"
MIRROR = DOC / "mirror-read.example.json"
SECOND = DOC / "second-api-docker.fixture.json"
ACTION_CORE = DOC / "action-core-read.json"
UC = ROOT / "docs/use-cases/own-api.md"

spec = importlib.util.spec_from_file_location("own_api_manifest_source", SCRIPT)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def fixture(path):
    return json.loads(path.read_text(encoding="utf-8"))


class OwnApiOnboardingTests(unittest.TestCase):
    def setUp(self):
        self.mirror = fixture(MIRROR)
        self.second = fixture(SECOND)
        self.action_core = fixture(ACTION_CORE)

    def denied(self, modified, reason):
        with self.assertRaises(module.ManifestStop) as error:
            module.validate(modified)
        self.assertEqual(str(error.exception), reason)

    def test_real_mirror_source_manifest_is_syntax_valid_but_not_live(self):
        evidence = module.validate(self.mirror)
        self.assertEqual(evidence["status"], "SOURCE_MANIFEST_VALID")
        self.assertEqual(evidence["serviceId"], "mirror")
        self.assertEqual(evidence["transportProfile"], "WIN-HTTPS")
        self.assertTrue(evidence["sourcePinned"])
        self.assertFalse(evidence["liveVerified"])
        self.assertFalse(evidence["readyToDeploy"])
        from_source = (ROOT / "fortis_approvals/integrations/mirror/tls.py").read_text()
        from_provider = (ROOT / "fortis_approvals/integrations/mirror/extension.py").read_text()
        self.assertIn("https://host.docker.internal", from_source)
        self.assertIn("/run/fortis-secrets/mirror-read/ca.pem", from_source)
        self.assertIn("get_repository", from_provider)

    def test_second_independent_docker_api_exercise_is_explicitly_unpinned(self):
        evidence = module.validate(self.second)
        self.assertEqual(evidence["transportProfile"], "DOCKER-HTTPS")
        self.assertEqual(evidence["serviceId"], "metricsprobe")
        self.assertEqual(evidence["operationCount"], 1)
        self.assertFalse(evidence["sourcePinned"])
        self.assertFalse(evidence["liveVerified"])
        self.assertFalse(evidence["readyToDeploy"])
        self.assertNotEqual(self.mirror["credential"]["vaultAlias"],
                            self.second["credential"]["vaultAlias"])
        self.assertNotEqual(self.mirror["transport"]["pinnedCaPath"],
                            self.second["transport"]["pinnedCaPath"])

    def test_action_core_pinned_source_manifest_matches_provider(self):
        from fortis_approvals.integrations.action_core.extension import PROVIDER
        from fortis_approvals.integrations.action_core.tls import CA_PATH

        manifest = self.action_core
        evidence = module.validate(manifest)
        self.assertEqual("SOURCE_MANIFEST_VALID", evidence["status"])
        self.assertEqual("action_core", evidence["serviceId"])
        self.assertEqual("DOCKER-HTTPS", evidence["transportProfile"])
        self.assertTrue(evidence["sourcePinned"])
        self.assertFalse(evidence["readyToDeploy"])
        self.assertFalse(evidence["liveVerified"])
        self.assertEqual(
            "cb22a03591e5c77739e192794d8f1d8323a68c4d",
            manifest["sourceSha"],
        )
        self.assertEqual("feed_and_search_and_bank_and_brain",
                         manifest["ownerRepository"])
        self.assertEqual("https://action-core-gw:443",
                         manifest["transport"]["origin"])
        self.assertEqual("fortis-actioncore-net",
                         manifest["transport"]["gatewayDockerNetwork"])
        self.assertEqual("action-core-gw",
                         manifest["transport"]["tlsServerName"])
        self.assertEqual(str(CA_PATH),
                         manifest["transport"]["pinnedCaPath"])
        self.assertEqual("action-core-read",
                         manifest["credential"]["vaultAlias"])
        self.assertEqual("action-core-gateway-reader",
                         manifest["credential"]["upstreamPrincipal"])
        self.assertEqual("OWNER_ONLY",
                         manifest["credential"]["vaultOwner"])
        self.assertEqual("action_core", PROVIDER.name)
        self.assertEqual(PROVIDER.api.origin + ":443",
                         manifest["transport"]["origin"])
        self.assertEqual(1, len(PROVIDER.operations))
        op, = manifest["operations"]
        provider_op, = PROVIDER.operations
        self.assertEqual(op["name"], provider_op.name)
        self.assertEqual("read", provider_op.kind)
        self.assertEqual("read", provider_op.credential)
        self.assertEqual(("read_action",), provider_op.routes)
        route = PROVIDER.api.routes[provider_op.routes[0]]
        self.assertEqual((route.method, route.path, route.readonly),
                         (op["method"], op["path"], True))
        self.assertEqual(("action_id", ["3", "4"], 65536),
                         (op["targetBinding"], op["targets"],
                          op["maxResponseBytes"]))
        self.assertEqual(("READ", "ALLOW"), (op["effect"], op["policy"]))

    def test_action_core_manifest_rejects_broader_scope_and_unsafe_transport(self):
        entry = self.action_core
        for mutation, expected in (
            (lambda d: d["operations"][0].update(method="POST"),
             "MANIFEST_READ_ONLY_REQUIRED"),
            (lambda d: d["operations"][0].update(targets=["*"]),
             "MANIFEST_TARGET_SCOPE_INVALID"),
            (lambda d: d["transport"].update(
                origin="http://action-core-gw:443"),
             "MANIFEST_TLS_ORIGIN_INVALID"),
            (lambda d: d["transport"].update(
                tlsServerName="wrong-name"),
             "MANIFEST_TLS_ORIGIN_INVALID"),
            (lambda d: d["transport"].update(
                gatewayDockerNetwork=None),
             "MANIFEST_DOCKER_TRANSPORT_INVALID"),
            (lambda d: d["credential"].update(
                bearerToken="NOT-A-SECRET"),
             "MANIFEST_CREDENTIAL_INVALID"),
        ):
            altered = copy.deepcopy(entry)
            mutation(altered)
            self.denied(altered, expected)

    def test_unknown_manifest_fields_fail_closed(self):
        x = copy.deepcopy(self.mirror)
        x["token"] = "DO-NOT-ECHO"
        self.denied(x, "MANIFEST_FIELDS_INVALID")

    def test_credential_value_is_not_allowed_even_if_named_secret(self):
        x = copy.deepcopy(self.mirror)
        x["credential"]["bearerToken"] = "DO-NOT-ECHO"
        self.denied(x, "MANIFEST_CREDENTIAL_INVALID")

    def test_unsupported_profile_fails(self):
        x = copy.deepcopy(self.second)
        x["transport"]["profile"] = "HTTP"
        self.denied(x, "MANIFEST_PROFILE_INVALID")

    def test_http_is_rejected_not_auto_upgraded(self):
        x = copy.deepcopy(self.second)
        x["transport"]["origin"] = "http://metricsprobe:443"
        self.denied(x, "MANIFEST_TLS_ORIGIN_INVALID")

    def test_explicit_other_port_is_rejected(self):
        x = copy.deepcopy(self.second)
        x["transport"]["origin"] = "https://metricsprobe:18756"
        self.denied(x, "MANIFEST_TLS_ORIGIN_INVALID")

    def test_ca_wrong_name_or_origin_injection_denied(self):
        x = copy.deepcopy(self.mirror)
        x["transport"]["tlsServerName"] = "localhost"
        self.denied(x, "MANIFEST_TLS_ORIGIN_INVALID")
        x["transport"]["tlsServerName"] = "host.docker.internal"
        x["transport"]["origin"] = "https://host.docker.internal:443/extra"
        self.denied(x, "MANIFEST_TLS_ORIGIN_INVALID")
        x["transport"]["origin"] = "https://user:password@host.docker.internal:443"
        self.denied(x, "MANIFEST_TLS_ORIGIN_INVALID")
        x["transport"]["origin"] = "https://host.docker.internal:443?#"
        self.denied(x, "MANIFEST_TLS_ORIGIN_INVALID")

    def test_invalid_ca_path_fails_without_trust_fallback(self):
        x = copy.deepcopy(self.second)
        x["transport"]["pinnedCaPath"] = "/etc/ssl/certs/ca-certificates.crt"
        self.denied(x, "MANIFEST_PINNED_CA_PATH_INVALID")
        x["transport"]["pinnedCaPath"] = "/run/fortis-secrets/../owner-shell/ca.pem"
        self.denied(x, "MANIFEST_PINNED_CA_PATH_INVALID")

    def test_windows_docker_boundaries_are_distinct(self):
        x = copy.deepcopy(self.mirror)
        x["transport"]["gatewayDockerNetwork"] = "bridge"
        self.denied(x, "MANIFEST_WINDOWS_TRANSPORT_INVALID")
        x = copy.deepcopy(self.second)
        x["transport"]["origin"] = "https://host.docker.internal:443"
        x["transport"]["tlsServerName"] = "host.docker.internal"
        self.denied(x, "MANIFEST_DOCKER_TRANSPORT_INVALID")
        x = copy.deepcopy(self.second)
        x["transport"]["gatewayDockerNetwork"] = None
        self.denied(x, "MANIFEST_DOCKER_TRANSPORT_INVALID")

    def test_wildcard_target_fails(self):
        x = copy.deepcopy(self.mirror)
        x["operations"][0]["targets"] = ["*"]
        self.denied(x, "MANIFEST_TARGET_SCOPE_INVALID")

    def test_post_or_ask_cannot_sneak_into_read_manifest(self):
        x = copy.deepcopy(self.mirror)
        x["operations"][0]["method"] = "POST"
        self.denied(x, "MANIFEST_READ_ONLY_REQUIRED")
        x = copy.deepcopy(self.mirror)
        x["operations"][0]["policy"] = "ASK"
        self.denied(x, "MANIFEST_READ_ONLY_REQUIRED")
        x = copy.deepcopy(self.mirror)
        x["operations"][0]["effect"] = "WRITE"
        self.denied(x, "MANIFEST_READ_ONLY_REQUIRED")

    def test_duplicate_operation_denied(self):
        x = copy.deepcopy(self.mirror)
        x["operations"].append(copy.deepcopy(x["operations"][0]))
        self.denied(x, "MANIFEST_OPERATION_ID_INVALID")

    def test_wrong_target_binding_and_query_denied(self):
        x = copy.deepcopy(self.mirror)
        x["operations"][0]["targetBinding"] = None
        self.denied(x, "ROUTE_TARGET_BINDING_INVALID")
        x = copy.deepcopy(self.mirror)
        x["operations"][0]["path"] = "/gateway/v1/repositories/{wrong}"
        self.denied(x, "ROUTE_TARGET_BINDING_INVALID")
        x = copy.deepcopy(self.mirror)
        x["operations"][0]["path"] = "/gateway/v1/repositories/{repo_id}?write=true"
        self.denied(x, "ROUTE_NOT_CLOSED")

    def test_traversal_and_unbounded_result_denied(self):
        x = copy.deepcopy(self.second)
        x["operations"][0]["path"] = "/v1/../status"
        self.denied(x, "ROUTE_NOT_CLOSED")
        x = copy.deepcopy(self.second)
        x["operations"][0]["maxResponseBytes"] = 999999
        self.denied(x, "MANIFEST_RESPONSE_LIMIT_INVALID")

    def test_unpinned_fixture_cannot_be_claimed_live_by_linter(self):
        x = copy.deepcopy(self.second)
        x["ownerValidated"] = True
        self.denied(x, "MANIFEST_FIELDS_INVALID")
        self.assertFalse(module.validate(self.second)["readyToDeploy"])

    def test_duplicate_json_key_denied_at_load(self):
        with tempfile.TemporaryDirectory() as name:
            p = Path(name) / "dup.json"
            p.write_text('{"schemaVersion": 1, "schemaVersion": 1}')
            with self.assertRaises(module.ManifestStop) as e:
                module.load(p)
            self.assertEqual(str(e.exception), "DUPLICATE_JSON_KEY")

    def test_symlinked_manifest_is_rejected(self):
        with tempfile.TemporaryDirectory() as name:
            target = Path(name) / "actual.json"
            target.write_text(json.dumps(self.mirror))
            link = Path(name) / "link.json"
            link.symlink_to(target)
            with self.assertRaises(module.ManifestStop):
                module.load(link)

    def test_offline_cli_prints_only_allowlisted_evidence(self):
        args = ["python3", "-B", str(SCRIPT), "--manifest", str(SECOND)]
        p = subprocess.run(args, capture_output=True, text=True, timeout=15,
                           check=False)
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        data = json.loads(p.stdout)
        self.assertFalse(data["liveVerified"])
        self.assertFalse(data["sourcePinned"])
        self.assertNotIn("vaultAlias", data)
        self.assertNotIn("origin", data)

    def test_uc_has_no_live_claim_for_source_only_exercise(self):
        text = UC.read_text()
        self.assertIn("UC-GW-012", text)
        self.assertIn("SOURCE_MANIFEST_VALID", text)
        self.assertIn("LIVE_API_VERIFIED", text)
        self.assertIn("UC-GW-009", text)
        self.assertIn("UC-CONT-022", text)
        self.assertIn("OWNER", text.upper())
        self.assertIn("WIN-HTTPS", text)
        self.assertIn("DOCKER-HTTPS", text)
        self.assertIn("Owner Shell", text)


if __name__ == "__main__":
    unittest.main()

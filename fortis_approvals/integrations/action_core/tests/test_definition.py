"""Offline closed-schema and target-scope tests for Action Core READ."""
import os
import tempfile
import unittest

from fortis_approvals.core import Denied
from fortis_approvals.extensions.model import discover
from fortis_approvals.extensions.runtime import ExtensionConfig, ExtensionRuntime
from fortis_approvals.extensions.vault import CredentialVault
from fortis_approvals.integrations.action_core.extension import (
    PROVIDER,
    _no_params,
    read_action,
    validate_result,
)


def sample(action_id=3):
    return {
        "action_id": action_id,
        "name": "Research" if action_id == 3 else "Monitoring",
        "category": "research" if action_id == 3 else "monitoring",
        "current_version_number": 3 if action_id == 3 else 1,
        "definition_yaml": "name: Research\ninstruction: Read only\n",
        "schedule_active": False,
    }


class FakeContext:
    def __init__(self, target, response=None):
        self.target = target
        try:
            action_id = int(target)
        except (TypeError, ValueError):
            action_id = 3
        self.response = sample(action_id) if response is None else response
        self.calls = []

    def call(self, route, *, path):
        self.calls.append((route, path))
        return self.response


class ActionCoreDefinitionTests(unittest.TestCase):
    def test_provider_is_one_read_only_operation_and_one_fixed_get(self):
        self.assertEqual("action_core", PROVIDER.name)
        self.assertEqual(["read_action"], [op.name for op in PROVIDER.operations])
        operation = PROVIDER.operations[0]
        self.assertEqual("read", operation.kind)
        self.assertEqual("read", operation.credential)
        self.assertEqual(("read_action",), operation.routes)
        self.assertEqual("https://action-core-gw", PROVIDER.api.origin)
        route = PROVIDER.api.routes["read_action"]
        self.assertEqual(("GET", "/gateway/v1/actions/{action_id}", True),
                         (route.method, route.path, route.readonly))
        self.assertEqual(("read_action",), tuple(PROVIDER.api.routes))

    def test_standard_extension_discovery_loads_this_provider(self):
        providers = discover(("action_core",))
        self.assertEqual(1, len(providers))
        self.assertEqual("action_core", providers[0].name)
        self.assertEqual(PROVIDER.operations, providers[0].operations)
        self.assertRegex(providers[0].source_digest, r"^[0-9a-f]{64}$")

    def test_standard_runtime_config_grants_only_declared_action_targets(self):
        with tempfile.TemporaryDirectory() as root:
            os.chmod(root, 0o700)
            vault = CredentialVault(root, uid=os.getuid(), gid=os.getgid())
            vault.initialize()
            vault.provision("action-core-read", "x" * 48)
            config = ExtensionConfig({
                "schemaVersion": 1,
                "providers": {
                    "action_core": {
                        "credentials": {"read": "action-core-read"},
                        "operations": {
                            "read_action": {"policy": "ALLOW", "targets": ["3", "4"]},
                        },
                    },
                },
            })
            runtime = ExtensionRuntime(
                config,
                providers=discover(("action_core",)),
                actors=("repo-sonar-read-proposal-actor",),
                default_actor="repo-sonar-read-proposal-actor",
                vault=vault,
            )
            rows = runtime.catalog_for("repo-sonar-read-proposal-actor")["operations"]
            self.assertEqual(["3", "4"], [row["target"] for row in rows])
            self.assertTrue(all(
                row["kind"] == "read" and row["policy"] == "ALLOW" and row["ready"]
                for row in rows
            ))

    def test_positive_read_uses_exact_target_and_projects_closed_result(self):
        context = FakeContext("3")
        result = read_action(context)
        self.assertEqual(
            [("read_action", {"action_id": "3"})],
            context.calls,
        )
        self.assertEqual(sample(), result)
        validate_result(result)

    def test_action_four_uses_exact_target(self):
        context = FakeContext("4")
        self.assertEqual(sample(4), read_action(context))
        self.assertEqual([("read_action", {"action_id": "4"})], context.calls)

    def test_unknown_or_noncanonical_target_is_denied_before_network(self):
        for target in ("2", "5", "03", "../3", "3/4", "", 3, None):
            with self.subTest(target=target):
                context = FakeContext(target)
                with self.assertRaises(Denied):
                    read_action(context)
                self.assertEqual([], context.calls)

    def test_upstream_action_id_must_match_trusted_target(self):
        context = FakeContext("3", sample(4))
        with self.assertRaises(Denied):
            read_action(context)
        self.assertEqual([("read_action", {"action_id": "3"})], context.calls)

    def test_result_rejects_missing_extra_and_wrongly_typed_fields(self):
        invalid = []
        missing = sample()
        missing.pop("schedule_active")
        invalid.append(missing)
        extra = sample()
        extra["executor_id"] = "must-not-exist"
        invalid.append(extra)
        invalid.append(dict(sample(), action_id=True))
        invalid.append(dict(sample(), current_version_number=True))
        invalid.append(dict(sample(), schedule_active=1))
        invalid.append(dict(sample(), category="Research"))
        invalid.append(dict(sample(), name=""))
        invalid.append(dict(sample(), definition_yaml=""))
        for value in invalid:
            with self.subTest(value=value):
                with self.assertRaises(Denied):
                    validate_result(value)

    def test_result_limit_is_enforced_without_truncation(self):
        value = sample()
        value["definition_yaml"] = "x" * 65_536
        with self.assertRaises(Denied):
            validate_result(value)

    def test_empty_params_only(self):
        _no_params({})
        for value in ({"action_id": 3}, {"url": "https://example.invalid"}, None, []):
            with self.subTest(value=value), self.assertRaises(Denied):
                _no_params(value)


if __name__ == "__main__":
    unittest.main()

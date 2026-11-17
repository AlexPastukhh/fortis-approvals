"""Offline exact Docker network admission for Action Core Gateway READ."""
import copy
import unittest

from fortis_approvals.tests.test_github_pilot_package import AdmissionTests, HELPERS


class ActionCoreNetworkGuardTests(unittest.TestCase):
    def setUp(self):
        self.container, self.expected = AdmissionTests().fixture()
        self.ids = {
            "fortis-gateway-egress": "c" * 64,
            "fortis-actioncore-net": "d" * 64,
        }
        self.expected["gatewayNetworks"] = copy.deepcopy(self.ids)
        self.container["HostConfig"]["NetworkMode"] = "fortis-gateway-egress"
        self.container["NetworkSettings"] = {
            "Networks": {name: {"NetworkID": value}
                         for name, value in self.ids.items()},
        }

    def check(self, expected=None, container=None):
        return HELPERS.admit(container or self.container,
                             expected or self.expected, pilot=True)

    def test_exact_network_names_and_ids_admitted(self):
        self.assertEqual({"admission": "PASS"}, self.check())

    def test_unexpected_third_network_denied(self):
        self.container["NetworkSettings"]["Networks"]["bridge"] = {
            "NetworkID": "e" * 64}
        with self.assertRaisesRegex(RuntimeError,
                                    "PILOT_UNREVIEWED_NETWORK_ATTACHMENT"):
            self.check()

    def test_missing_ingress_network_denied(self):
        self.container["NetworkSettings"]["Networks"].pop("fortis-actioncore-net")
        with self.assertRaisesRegex(RuntimeError,
                                    "PILOT_UNREVIEWED_NETWORK_ATTACHMENT"):
            self.check()

    def test_network_id_swap_denied(self):
        self.container["NetworkSettings"]["Networks"]["fortis-actioncore-net"]["NetworkID"] = "f" * 64
        with self.assertRaisesRegex(RuntimeError,
                                    "PILOT_GATEWAY_NETWORK_ID_MISMATCH"):
            self.check()

    def test_wrong_primary_network_mode_denied(self):
        self.container["HostConfig"]["NetworkMode"] = "bridge"
        with self.assertRaisesRegex(RuntimeError,
                                    "PILOT_RESOURCE_OR_NETWORK_MISMATCH"):
            self.check()

    def test_untrusted_network_record_denied(self):
        for change in (
            {"fortis-gateway-egress": "c" * 64, "other": "d" * 64},
            {"fortis-gateway-egress": "bad", "fortis-actioncore-net": "d" * 64},
            {"fortis-gateway-egress": "c" * 64,
             "fortis-actioncore-net": "c" * 64},
        ):
            with self.subTest(change=change):
                self.expected["gatewayNetworks"] = change
                with self.assertRaisesRegex(RuntimeError,
                                            "PILOT_GATEWAY_NETWORK_RECORD_INVALID"):
                    self.check()

    def test_pending_ingress_only_for_never_started_return(self):
        self.expected["allowPendingActionNetwork"] = True
        self.container["NetworkSettings"]["Networks"].pop("fortis-actioncore-net")
        self.assertEqual({"admission": "PASS"}, self.check())
        self.expected["status"] = "running"
        self.container["State"]["Status"] = "running"
        with self.assertRaisesRegex(RuntimeError, "PILOT_PENDING_NETWORK_NOT_PRISTINE"):
            self.check()

    def test_legacy_bridge_rejects_extra_attachments(self):
        self.expected.pop("gatewayNetworks")
        self.container["HostConfig"]["NetworkMode"] = "bridge"
        self.container["NetworkSettings"]["Networks"] = {"bridge": {"NetworkID": "a"*64}}
        self.assertEqual({"admission": "PASS"}, self.check())
        self.container["NetworkSettings"]["Networks"]["fortis-actioncore-net"] = {
            "NetworkID": "d"*64}
        with self.assertRaisesRegex(RuntimeError,
                                    "PILOT_UNREVIEWED_NETWORK_ATTACHMENT"):
            self.check()

    def test_review_cannot_receive_action_core_network(self):
        self.expected["stateVolume"] = "fortis-r7-state-review-20261105"
        with self.assertRaisesRegex(RuntimeError,
                                    "PILOT_GATEWAY_NETWORK_RECORD_INVALID"):
            HELPERS.admit_gateway_networks(self.container, self.expected, pilot=False)


if __name__ == "__main__":
    unittest.main()

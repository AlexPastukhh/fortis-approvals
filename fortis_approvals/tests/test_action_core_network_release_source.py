"""Static Windows owner release checks (never runs Docker/Firewall)."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
PS = (ROOT / "fortis_approvals/deploy/Manage-Integrations.ps1").read_text()
PILOT = (ROOT / "fortis_approvals/deploy/Run-GitHub-Pilot-E2E.ps1").read_text()
HELPER = (ROOT / "fortis_approvals/deploy/github_pilot_helpers.py").read_text()


class ActionCoreReleaseSourceTests(unittest.TestCase):
    def test_network_flag_is_opt_in_checked_and_not_auto(self):
        for text in (
            "[switch]$EnableActionCoreNetwork",
            "RELEASE_ACTION_CORE_NETWORK_REQUIRES_APPROVED_IMAGE_BUILD",
            "RELEASE_ACTION_CORE_NETWORK_DOWNGRADE_DENIED",
            "RELEASE_ACTION_CORE_NETWORK_REQUIRED",
            "RELEASE_ACTION_CORE_FLAG_FORWARDING_SELFTEST_FAILED",
            "enableActionCoreNetwork=[bool]$EnableActionCoreNetwork",
            "gatewayNetworks=$script:ActionCoreNetworks",
            "if($EnableActionCoreNetwork){$Runtime.gatewayNetworks=$script:ActionCoreNetworks}",
        ):
            with self.subTest(text=text):
                self.assertIn(text, PS)
        self.assertGreaterEqual(PS.count("$EnableActionCoreNetwork -or"), 2)

    def test_owner_firewall_probe_is_read_only_and_closed(self):
        for text in (
            "Get-CimInstance Win32_Process",
            "Get-NetFirewallRule -Name 'Fortis-DockerBackend-Block-TCP8000'",
            "-PolicyStore ActiveStore",
            "Get-NetFirewallApplicationFilter",
            "Get-NetFirewallPortFilter",
            "Get-NetFirewallAddressFilter",
            "Get-NetFirewallServiceFilter",
            "Get-NetFirewallProfile -PolicyStore ActiveStore",
            "RELEASE_ACTION_CORE_FIREWALL_SCOPE_INVALID",
            "RELEASE_ACTION_CORE_FIREWALL_PROFILE_DISABLED",
            "Get-ActionCoreLocalApiAddress",
            "RELEASE_ACTION_CORE_WINDOWS_LOCAL_READ_FAILED",
        ):
            self.assertIn(text, PS)
        self.assertNotIn("New-NetFirewallRule", PS)
        self.assertNotIn("Set-NetFirewallRule", PS)
        self.assertNotIn("Remove-NetFirewallRule", PS)

    def test_exact_reviewed_networks_and_ids(self):
        self.assertIn("Read-ActionCoreDockerNetwork", PS)
        self.assertIn("-Internal:$false -Owner 'fortis-approvals'", PS)
        self.assertIn("-Internal:$true -Owner 'feed_and_search_and_bank_and_brain'", PS)
        self.assertIn("NetworkID=[string]$Endpoint.Value.NetworkID", PILOT)
        self.assertIn("admit_gateway_networks(container, expected, pilot=pilot)", HELPER)
        self.assertIn("PILOT_UNREVIEWED_NETWORK_ATTACHMENT", HELPER)
        self.assertIn("PILOT_GATEWAY_NETWORK_ID_MISMATCH", HELPER)

    def test_pre_stop_boundary_and_staged_negative_checks(self):
        before_stop = PS.index("Step 'ACTION_CORE_BOUNDARY_FINAL_PREFLIGHT'")
        stop = PS.index("Step 'STOP_SOURCE'")
        self.assertLess(before_stop, stop)
        self.assertIn("Step 'VERIFY_ACTION_CORE_HTTP8000_DENIAL'", PS)
        self.assertIn('must_refuse("host.docker.internal")', PS)
        self.assertIn('must_refuse(sys.argv[1])', PS)
        self.assertIn("ACTION_CORE_HTTP8000_BOTH_DENIED", PS)
        negative = PS.index("Step 'VERIFY_ACTION_CORE_HTTP8000_DENIAL'")
        activate = PS.index("Step 'ACTIVATE'")
        self.assertLess(negative, activate)

    def test_controller_only_secondary_attach_and_recovery(self):
        self.assertIn("'fortis-gateway-egress'}else{'bridge'}", PS)
        self.assertEqual(1, PS.count("@('network','connect','fortis-actioncore-net',$C.Id)"))
        self.assertIn("function Complete-ActionCoreNetwork", PS)
        self.assertIn("RELEASE_PENDING_ACTION_CORE_NETWORK_NOT_PRISTINE", PS)
        self.assertIn("FORTIS_ACTION_CORE_RETURN_UNSTARTED_PARTIAL_NETWORK", PS)
        self.assertIn("Admit $C $P -AllowUnhealthy -AllowPendingIngress", PS)
        self.assertIn("Admit $C $P -AllowUnhealthy", PS)
        self.assertLess(PS.index("function Complete-ActionCoreNetwork"),
                        PS.index("function Resume-Target"))
        self.assertNotIn("'--network','host'", PS)
        self.assertNotIn("'--privileged'", PS)

    def test_contract_is_source_only_no_auto_provision(self):
        doc = (ROOT / "docs/ACTION-CORE-NETWORK-ISOLATION.md").read_text()
        self.assertIn("source-only candidate", doc)
        self.assertIn("NOT executed", doc)
        self.assertIn("Do not manually attach", doc)
        self.assertIn("must_refuse(\"host.docker.internal\")", PS)


if __name__ == "__main__":
    unittest.main()

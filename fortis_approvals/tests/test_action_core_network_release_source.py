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

    def test_optional_network_identity_uses_one_fail_closed_reader(self):
        # Legacy Primary has no gatewayNetworks. In PS5.1 StrictMode an
        # absent PSCustomObject property raises before Check reaches its
        # state preflight; never access the optional field directly.
        self.assertIn('function Read-GatewayNetworks {', PS)
        self.assertIn("$Record.PSObject.Properties['gatewayNetworks']", PS)
        self.assertIn("$Record.Contains('gatewayNetworks')", PS)
        self.assertIn('RELEASE_ACTION_CORE_NETWORK_RECORD_INVALID', PS)
        for marker in (
            '$Networks=Read-GatewayNetworks $P',
            '$Expected.gatewayNetworks=$Networks',
            'if($null -eq $Networks -or',
            'if((Read-GatewayNetworks $P) -and',
            'if($null -eq $Networks){return $C}',
            'Same-Json $Now $Networks',
            'if(Read-GatewayNetworks $P){',
            'if((Read-GatewayNetworks $SourceForOwnerShell.runtime) -and',
            '$(if(Read-GatewayNetworks $Runtime)',
        ):
            with self.subTest(marker=marker):
                self.assertIn(marker, PS)
        # A network identity can only be written to a candidate when the
        # explicit owner-only Action Core network flag was approved.
        self.assertIn('if($EnableActionCoreNetwork){$Runtime.gatewayNetworks=$script:ActionCoreNetworks}', PS)
        for forbidden in (
            '$P.gatewayNetworks',
            '$SourceForOwnerShell.runtime.gatewayNetworks',
            'if($Runtime.gatewayNetworks)',
        ):
            self.assertNotIn(forbidden, PS)

    def test_default_auto_config_allows_absent_action_core_provider(self):
        self.assertIn('function Read-ActionCoreProvider {', PS)
        self.assertIn("$Field.Value.PSObject.Properties['action_core']", PS)
        self.assertIn('RELEASE_ACTION_CORE_CONFIG_INVALID', PS)
        self.assertIn("if($null -eq $Action){return $null}",PS)
        self.assertIn("if($Action.Value -isnot [pscustomobject])",PS)
        self.assertIn('providers\":null}',PS)
        self.assertIn('action_core\":null}',PS)
        self.assertIn('$Provider=Read-ActionCoreProvider $Config', PS)
        self.assertIn('if((Read-ActionCoreProvider $PublicConfig) -and -not $EnableActionCoreNetwork)', PS)
        self.assertNotIn('$PublicConfig.providers.action_core', PS)
        self.assertNotIn('$Config.providers.action_core', PS)

    def test_strict_owner_and_ci_selftest_execute_live_shaped_fixtures(self):
        self.assertIn('function Assert-OptionalActionCoreSelfTest {', PS)
        self.assertIn('FORTIS_ACTION_CORE_OPTIONAL_FIELDS_SELFTEST_PASS', PS)
        self.assertIn('Set-StrictMode -Version Latest', PS)
        self.assertIn('    Assert-OptionalActionCoreSelfTest', PS)
        self.assertIn('LegacyMap=[ordered]@', PS)
        self.assertIn('Read-GatewayNetworks $Legacy', PS)
        self.assertIn('Read-GatewayNetworks $LegacyMap', PS)
        self.assertIn('Read-GatewayNetworks $Bad', PS)
        self.assertIn('Read-ActionCoreProvider $NoAction', PS)
        self.assertIn('Read-ActionCoreProvider $HasAction', PS)
        w=(ROOT/'.github/workflows/source-ci.yml').read_text()
        self.assertIn('& $files[4] -Action SelfTest', w)
        self.assertIn('shell: powershell', w)

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

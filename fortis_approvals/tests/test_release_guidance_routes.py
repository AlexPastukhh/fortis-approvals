"""Single-owner documentation routes for the checked Gateway release.

Historical release evidence is allowed, but it must not replace the
canonical use case and owner release entrypoint.
"""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
UC = (ROOT/'docs/use-cases/releases.md').read_text()
RUNBOOK = (ROOT/'docs/PRIMARY-GATEWAY-OPERATIONS.md').read_text()
CONTRACT = (ROOT/'docs/UNCERTAIN-GROWTH-RELEASE-2026-11-17.md').read_text()
AGENT = (ROOT/'AGENTS.md').read_text()
INDEX = (ROOT/'docs/use-cases/README.md').read_text()
DEPLOY = (ROOT/'fortis_approvals/deploy/README.md').read_text()
RELEASE_TARGETS = (ROOT/'release/targets.yaml').read_text()
PUBLISHER = (ROOT/'docs/P3-4-PUBLISHER-OWNER-STARTUP.md').read_text()
SCRIPT = (ROOT/'fortis_approvals/deploy/Manage-Integrations.ps1').read_text()


class ReleaseDocumentationRoutes(unittest.TestCase):
    def test_uses_existing_uc_not_parallel_use_case(self):
        self.assertIn('## UC-GW-005',UC)
        self.assertEqual(INDEX.count('[UC-GW-005](releases.md#uc-gw-005)'),1)
        self.assertIn('UC-GW-005', AGENT)
        self.assertIn('docs/use-cases/releases.md#uc-gw-005',AGENT)
        self.assertIn('UC-CONT-002',AGENT)
        self.assertIn('UC-CONT-003',AGENT)

    def test_shared_auto_recipe_is_single_owner_runbook(self):
        for action in ('Check','Apply','Backup','Promote'):
            self.assertIn('-Action '+action+' -Auto',RUNBOOK)
        self.assertIn('lightweight-owner-release-path-pr4b',RUNBOOK)
        self.assertIn('PRIMARY-GATEWAY-OPERATIONS.md#lightweight-owner-release-path-pr4b',UC)
        self.assertIn('UC-GW-005',CONTRACT)
        self.assertIn('PRIMARY-GATEWAY-OPERATIONS.md#lightweight-owner-release-path-pr4b',CONTRACT)

    def test_auto_is_default_after_owner_install_but_manual_stays_explicit(self):
        self.assertIn('Check -Auto',UC)
        self.assertIn('Apply -Auto',UC)
        self.assertIn('AllowUncertainGrowth',CONTRACT)
        self.assertIn('PR #128',CONTRACT)
        self.assertIn('source candidate',CONTRACT.lower())
        self.assertIn('NOT YET INSTALLED',CONTRACT)
        self.assertIn('manual',CONTRACT.lower())
        self.assertIn('For owner-reviewed manual exceptions',CONTRACT)
        self.assertIn('$AllowUncertainGrowth=[switch]$true',SCRIPT)
        self.assertIn('RELEASE_AUTO_MANUAL_ARGUMENTS_DENIED',SCRIPT)
        self.assertIn('RELEASE_AUTO_CHECK_GROWTH_WITNESS_REQUIRED',SCRIPT)
        self.assertIn('allowUncertainGrowth=[bool]$AllowUncertainGrowth',SCRIPT)

    def test_historical_guidance_is_labeled_and_not_standard(self):
        self.assertIn('Historical exact-scope UNCERTAIN',DEPLOY)
        self.assertIn('not the current standard Auto',DEPLOY)
        self.assertIn('UC-GW-005',DEPLOY)
        self.assertIn('  - fortis_approvals/deploy/README.md',RELEASE_TARGETS)
        self.assertNotIn('  - fortis_approvals/deploy/**',RELEASE_TARGETS)
        self.assertIn('first-time publisher volume activation',PUBLISHER.lower())
        self.assertIn('-EnablePublisherMount',PUBLISHER)
        self.assertIn('not for provisioning a new publisher principal',PUBLISHER)

    def test_security_and_owner_boundary_visible(self):
        for marker in ('APPROVED','CLAIMED','PENDING','DISPATCHED',
                       'STOP','quiescence','Owner','Windows',
                       'audit','source','after'):
            with self.subTest(marker=marker):
                self.assertIn(marker,CONTRACT)
        self.assertIn('not Windows/Production installation',RUNBOOK)
        self.assertIn('Do not treat source merge',AGENT) if 'Do not treat source merge' in AGENT else self.assertIn('Never treat source merge',AGENT)
        self.assertIn('not live',UC.lower()) if 'not live' in UC.lower() else self.assertIn('owner-установки',UC)


if __name__ == '__main__':
    unittest.main()

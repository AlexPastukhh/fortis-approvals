"""Source-level guards for opt-in Owner Shell deployment and config consistency.

The release controller is PowerShell 5.1: parse and SelfTest run on Windows CI.
"""
import json
from pathlib import Path
import re
import unittest

ROOT=Path(__file__).resolve().parents[2]
PS=(ROOT/'fortis_approvals/deploy/Manage-Integrations.ps1').read_text()
HELPER=(ROOT/'fortis_approvals/deploy/github_pilot_helpers.py').read_text()
DOCKERFILE=(ROOT/'fortis_approvals/deploy/Dockerfile-Gateway-Modularized-Candidate').read_text()
OWNER_SHELL_ENV=json.dumps(dict(port=10443,
    serverCA='/run/fortis-secrets/owner-shell/server-ca.pem',
    clientCert='/run/fortis-secrets/owner-shell/client.pem',
    clientKey='/run/fortis-secrets/owner-shell/client.key',
    secretFile='/run/fortis-secrets/owner-shell/secret.txt'),separators=(',',':'))

class ReleaseContractSourceTests(unittest.TestCase):
    def test_two_trusted_config_expressions_match_exact_contract(self):
        expr=re.search(r'\$script:OwnerShellJson=\x27([^\x27]+)\x27', PS)
        self.assertIsNotNone(expr)
        self.assertEqual(expr.group(1),OWNER_SHELL_ENV)
        self.assertIn("required['FORTIS_OWNER_SHELL_CONFIG']='"+OWNER_SHELL_ENV+"'",HELPER)
        self.assertEqual(set(json.loads(OWNER_SHELL_ENV)),
                         {'port','serverCA','clientCert','clientKey','secretFile'})

    def test_owner_shell_optin_requires_exact_approved_image(self):
        self.assertIn('[switch]$EnableOwnerShell',PS)
        self.assertIn('RELEASE_OWNER_SHELL_REQUIRES_APPROVED_IMAGE_BUILD',PS)
        self.assertIn("$SourceSha -cnotmatch '^[0-9a-f]{40}$'",PS)
        self.assertIn("$Action -cnotin @('Apply','Check')",PS)
        self.assertIn('ownerShell=$OwnerShellEnabled;runId=$RunId',PS)
        self.assertIn('ownerShell=(Read-OwnerShellFlag $P)',PS)
        self.assertIn("-not $_.StartsWith('FORTIS_OWNER_SHELL_CONFIG=')",PS)
        self.assertIn('$EnvLines+=@(OwnerShell-EnvLines $Runtime.ownerShell)',PS)
        self.assertIn('Check-OwnerShellEnv $EnvLines $Runtime.ownerShell',PS)
        self.assertIn('RELEASE_OWNER_SHELL_RECORD_INVALID',PS)
        self.assertIn('RELEASE_OWNER_SHELL_ENV_MISMATCH',PS)
        self.assertIn('RELEASE_OWNER_SHELL_FLAG_FORWARDING_SELFTEST_FAILED',PS)

    def test_preflight_and_live_probe_are_read_only_capabilities(self):
        self.assertIn('Image-OwnerShell-Preflight',PS)
        self.assertIn("'--network','none','--read-only'",PS)
        self.assertIn("'--user','10001:10001','--cap-drop','ALL'",PS)
        self.assertIn('owner_shell_release import verify_material',PS)
        self.assertIn('Running-OwnerShell-Check $C.Id',PS)
        self.assertIn("data=client.capabilities()",PS)
        self.assertNotIn('client.execute(',PS)
        self.assertIn("Step 'VERIFY_STAGED_OWNER_SHELL_MTLS'",PS)
        self.assertIn('fortis_approvals/owner_shell_release.py',DOCKERFILE)

if __name__=='__main__':unittest.main()

"""Phase 6A pure authority admission tests; no policy mutation or live calls."""
import unittest

from fortis_approvals.core import Denied
from fortis_approvals.extensions.owner_policy_authority_phase6 import ExactPolicyBaseline


R = ('machine-a', 'example', 'read_one', 'target-a')
P = ('machine-a', 'powershell', 'execute', 'windows-owner')


class ExactAuthorityPhase6Tests(unittest.TestCase):
    def authority(self, policies=None, extensions=None, services=None):
        return ExactPolicyBaseline(
            core_policies={R: 'ASK'} if policies is None else policies,
            loaded_services={'example'} if services is None else services,
            extension_rules=extensions,
            extension_services={'example'} if extensions is not None else frozenset())

    def change(self, **overrides):
        return {**dict(actor=R[0], provider=R[1], operation=R[2],
                        target=R[3], expectedPolicy='ASK',
                        desiredPolicy='DENY'), **overrides}

    def test_exact_transition_inert_and_digest_deterministic(self):
        authority = self.authority()
        result = authority.preview(self.change())
        self.assertEqual('ASK', authority.rules[R])
        self.assertFalse(result['canApply'])
        self.assertFalse(result['policyActivated'])
        self.assertEqual(result['baselineDigest'], self.authority().digest)
        self.assertEqual(result['identity']['target'], R[3])
        with self.assertRaises(TypeError):
            authority.rules[R] = 'ALLOW'

    def test_policy_change_missing_or_unknown_coordinates_denied(self):
        authority = self.authority()
        for change in (self.change(actor='machine-b'), self.change(target='target-b'),
                       self.change(operation='other'), self.change(provider='unknown'),
                       self.change(target='../invalid'), self.change(extra='ALLOW'),
                       self.change(expectedPolicy='DENY'), self.change(desiredPolicy='ASK'),
                       self.change(desiredPolicy='UNKNOWN')):
            with self.subTest(change=change), self.assertRaises(Denied):
                authority.preview(change)

    def test_legacy_callable_global_actor_wildcard_and_bad_values_denied(self):
        cases = ({R: lambda *_: 'ASK'}, {R: 'ALLOW', ('example', 'read_one'): 'DENY'},
                 {R: 'ASK', (R[0], R[1], R[2]): 'DENY'},
                 {(R[0], R[1], R[2], '*'): 'ASK'},
                 {R: 'NOT_A_POLICY'}, {('unexpected',): 'ALLOW'},
                 {('machine-a', 'missing', 'op', 'target-a'): 'ASK'})
        for policy in cases:
            with self.subTest(policy=policy), self.assertRaises(Denied):
                self.authority(policy)

    def test_extension_config_must_match_core_and_loaded_provider(self):
        self.assertEqual('ASK', self.authority(extensions={R: 'ASK'}).rules[R])
        for ext, policies, services in (
            ({R: 'DENY'}, {R: 'ASK'}, {'example'}),
            ({R: 'ASK'}, {}, {'example'}),
            ({R: 'ASK'}, {R: 'ASK'}, set()),
            ({R: 'ASK'}, {R: 'ASK', ('machine-b','example','read_one','target-a'):'ALLOW'}, {'example'}),
        ):
            with self.subTest(ext=ext, policies=policies), self.assertRaises(Denied):
                self.authority(policies, ext, services)

    def test_declared_extension_service_without_exact_grant_is_rejected(self):
        with self.assertRaisesRegex(Denied, 'PHASE6_EXTENSION_GRANT_MISSING'):
            ExactPolicyBaseline(core_policies={R: 'ASK'}, loaded_services={'example'},
                                extension_rules={}, extension_services={'example'})

    def test_duplicate_native_extension_authority_must_not_drift(self):
        with self.assertRaisesRegex(Denied, 'PHASE6_EXTENSION_CORE_AUTHORITY_DRIFT'):
            ExactPolicyBaseline(core_policies={R: 'ASK'}, loaded_services={'example'},
                                extension_rules={R: 'DENY'}, extension_services={'example'})

    def test_powershell_must_never_gain_allow_without_windows_v2(self):
        a = self.authority({P: 'ASK'}, services={'powershell'})
        with self.assertRaisesRegex(Denied, 'PHASE6_POWERSHELL_V2_GATE_REQUIRED'):
            a.preview(dict(actor=P[0],provider=P[1],operation=P[2],target=P[3],
                           expectedPolicy='ASK',desiredPolicy='ALLOW'))
        result = a.preview(dict(actor=P[0],provider=P[1],operation=P[2],target=P[3],
                                expectedPolicy='ASK',desiredPolicy='DENY'))
        self.assertFalse(result['canApply'])


if __name__ == '__main__':
    unittest.main()

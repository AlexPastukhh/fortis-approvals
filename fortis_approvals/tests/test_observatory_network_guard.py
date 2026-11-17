"""Strict 2-/3-network Gateway admission and owner controller source guard.

Pure source/unit tests; no Docker, Windows, credentials or live network effects.
"""
import copy
from pathlib import Path
import unittest

from fortis_approvals.tests.test_github_pilot_package import AdmissionTests, HELPERS


ROOT=Path(__file__).resolve().parents[2]
CONTROLLER=(ROOT/'fortis_approvals/deploy/Manage-Integrations.ps1').read_text()
HELPER=(ROOT/'fortis_approvals/deploy/github_pilot_helpers.py').read_text()
EGRESS='fortis-gateway-egress'
ACTION='fortis-actioncore-net'
OBS='fortis-observatory-gw-net'
IDS={EGRESS:'a'*64,ACTION:'b'*64,OBS:'c'*64}


class ObservatoryNetworkGuardTests(unittest.TestCase):
    def setUp(self):
        self.container,self.expected=AdmissionTests().fixture()
        self.container['HostConfig']['NetworkMode']=EGRESS

    def network(self, names, *, pending=False):
        mapping={k:IDS[k] for k in names}
        self.expected['gatewayNetworks']=mapping
        self.container['NetworkSettings']={'Networks':{
            k:{'NetworkID':IDS[k]} for k in (names if not pending else
                ([EGRESS] if not isinstance(pending,tuple) else pending))
        }}
        if pending:
            self.expected['allowPendingActionNetwork']=True
        else:
            self.expected.pop('allowPendingActionNetwork',None)

    def checked(self):
        return HELPERS.admit(self.container,self.expected,pilot=True)

    def test_observatory_only_admitted_exact_id(self):
        self.network((EGRESS,OBS))
        self.assertEqual(self.checked(),{'admission':'PASS'})

    def test_both_integrations_admitted_exact_id(self):
        self.network((EGRESS,ACTION,OBS))
        self.assertEqual(self.checked(),{'admission':'PASS'})

    def test_unexpected_extra_network_denied(self):
        self.network((EGRESS,OBS))
        self.container['NetworkSettings']['Networks']['rogue']={'NetworkID':'d'*64}
        with self.assertRaisesRegex(RuntimeError,'PILOT_UNREVIEWED_NETWORK_ATTACHMENT'):
            self.checked()

    def test_unapproved_network_name_record_denied(self):
        self.network((EGRESS,OBS))
        self.expected['gatewayNetworks']={EGRESS:IDS[EGRESS], 'rogue':IDS[OBS]}
        with self.assertRaisesRegex(RuntimeError,'PILOT_GATEWAY_NETWORK_RECORD_INVALID'):
            self.checked()

    def test_action_core_not_implicitly_required_or_attached(self):
        self.network((EGRESS,OBS))
        self.assertNotIn(ACTION,self.expected['gatewayNetworks'])
        self.assertEqual(self.checked(),{'admission':'PASS'})

    def test_id_swap_and_duplicate_denied(self):
        self.network((EGRESS,ACTION,OBS))
        self.container['NetworkSettings']['Networks'][OBS]['NetworkID']='f'*64
        with self.assertRaisesRegex(RuntimeError,'PILOT_GATEWAY_NETWORK_ID_MISMATCH'):
            self.checked()
        self.network((EGRESS,OBS))
        self.expected['gatewayNetworks'][OBS]=IDS[EGRESS]
        with self.assertRaisesRegex(RuntimeError,'PILOT_GATEWAY_NETWORK_RECORD_INVALID'):
            self.checked()

    def test_missing_final_attachment_denied(self):
        self.network((EGRESS,ACTION,OBS))
        self.container['NetworkSettings']['Networks'].pop(OBS)
        with self.assertRaisesRegex(RuntimeError,'PILOT_UNREVIEWED_NETWORK_ATTACHMENT'):
            self.checked()

    def test_pending_subset_only_on_never_started_candidate(self):
        self.network((EGRESS,ACTION,OBS),pending=(EGRESS,ACTION))
        self.assertEqual(self.checked(),{'admission':'PASS'})
        self.expected['status']='running'
        self.container['State']['Status']='running'
        with self.assertRaisesRegex(RuntimeError,'PILOT_PENDING_NETWORK_NOT_PRISTINE'):
            self.checked()

    def test_pending_unknown_endpoint_and_full_set_denied(self):
        self.network((EGRESS,OBS),pending=True)
        self.container['NetworkSettings']['Networks']['rogue']={'NetworkID':'d'*64}
        with self.assertRaisesRegex(RuntimeError,'PILOT_PENDING_NETWORK_NOT_PRISTINE'):
            self.checked()
        self.network((EGRESS,OBS),pending=True)
        self.container['NetworkSettings']['Networks'][OBS]={'NetworkID':IDS[OBS]}
        with self.assertRaisesRegex(RuntimeError,'PILOT_PENDING_NETWORK_NOT_PRISTINE'):
            self.checked()

    def test_legacy_bridge_and_review_cannot_attach(self):
        self.network((EGRESS,OBS))
        with self.assertRaisesRegex(RuntimeError,'PILOT_GATEWAY_NETWORK_RECORD_INVALID'):
            HELPERS.admit_gateway_networks(self.container,self.expected,pilot=False)

    def test_controller_has_optin_guarded_all_three_modes(self):
        for marker in (
            '[switch]$EnableObservatoryNetwork',
            'RELEASE_OBSERVATORY_NETWORK_REQUIRES_APPROVED_IMAGE_BUILD',
            'RELEASE_OBSERVATORY_NETWORK_DOWNGRADE_DENIED',
            'RELEASE_OBSERVATORY_NETWORK_REQUIRED',
            'RELEASE_OBSERVATORY_READ_ONLY_CONFIG_REQUIRED',
            'Read-GatewayNetworkBoundary',
            "if($EnableObservatoryNetwork){Assert-ObservatoryConfig $ConfigText}",
            'FORTIS_OBSERVATORY_NETWORK_DOCKER_ONLY_PASS',
            "Step 'ATTACH_OBSERVATORY_NETWORK'",
            "Assert-ObservatoryPrivateTlsRead $C.Id",
            "Assert-ObservatoryNoLegacyHttp $C.Id",
            'RELEASE_GATEWAY_BOUNDARY_CHANGED',
            'enableObservatoryNetwork=[bool]$EnableObservatoryNetwork',
            'PILOT_UNREVIEWED_NETWORK_ATTACHMENT',
        ):
            if marker.startswith('PILOT_'):
                self.assertIn(marker,HELPER)
            else:
                self.assertIn(marker,CONTROLLER)

    def test_controller_guard_checks_before_stop_and_activation(self):
        self.assertLess(CONTROLLER.index("Step 'ACTION_CORE_BOUNDARY_FINAL_PREFLIGHT'"),
                        CONTROLLER.index("Step 'STOP_SOURCE'"))
        self.assertLess(CONTROLLER.index("Step 'VERIFY_OBSERVATORY_TLS443_AUTH_GATE'"),
                        CONTROLLER.index("Step 'ACTIVATE'"))
        self.assertLess(CONTROLLER.index("Step 'VERIFY_OBSERVATORY_HTTP18756_DENIAL'"),
                        CONTROLLER.index("Step 'ACTIVATE'"))
        self.assertEqual(CONTROLLER.count("@('network','connect','fortis-observatory-gw-net',$C.Id)"),1)
        self.assertNotIn("'--privileged'",CONTROLLER)
        self.assertNotIn("'--network','host'",CONTROLLER)


if __name__=='__main__':
    unittest.main()

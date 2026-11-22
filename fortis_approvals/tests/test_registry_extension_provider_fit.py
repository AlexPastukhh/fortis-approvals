"""E1.0: standard extension provider / Owner Policy V2 fit with existing Registry AF_UNIX.

Source-only same-UID fixture. Synthetic owner WebAuthn and patched peer/UID
checks are NOT live host acceptance, issued grants, or authoritative Desired.
No Registry extension is installed in the ordinary Gateway image by this test.
"""
import uuid
import unittest
from unittest.mock import patch

from fortis_approvals.core import Denied
from fortis_approvals.extensions.model import Operation, Provider
from fortis_approvals.extensions.runtime import ExtensionConfig
from fortis_approvals.extensions.owner_policy_r7_v2 import R7UnifiedPolicySourceOptIn
from fortis_approvals.integrations.registry.candidate_gateway import GatewayRegistryUnixCandidateRead
from fortis_approvals.integrations.registry.read_contract import (
    GATEWAY_TARGET, REPOSITORY, validate_gateway_read_query,
    validate_gateway_read_projection,
)
from fortis_approvals.r7_unified_candidate import ACTOR, build_r7_unified_candidate
from fortis_approvals.tests.test_owner_policy_local_deny_http_phase6c2 import HTTPFixtureWebAuthn
from fortis_approvals.tests import test_registry_gateway_unix_candidate as unix_fixture

GRANT = unix_fixture.GRANT


class RegistryExtensionProviderFit(unittest.TestCase):
    def setUp(self):
        self.fixture = unix_fixture.GatewayUnixCandidateTests(
            'test_r7_candidate_adapter_opt_in_has_no_automatic_registry_grant')
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.accept()
        self.fixture.setup_broker()  # Real AF_UNIX + schema-3 DB, test identity.
        self.calls = []

        def params(value):
            validate_gateway_read_query('candidate_head', GATEWAY_TARGET, value)

        def result(value):
            validate_gateway_read_projection('candidate_head', value)

        def read(ctx):
            self.calls.append(ctx.request_id)
            return self.fixture.reader.read({
                'service': 'registry', 'operation': 'candidate_head',
                'target': ctx.target, 'params': ctx.params,
                'requestId': ctx.request_id,
            })

        # Reuse standard trusted Operation/Provider definitions: no custom
        # policy engine, catalog, ingress or additional Registry HTTP API.
        provider = Provider('registry', (Operation(
            'candidate_head', 'Read source-only Registry candidate head',
            'read', params, result, read,
            allowed_targets=(GATEWAY_TARGET,)),))
        config = ExtensionConfig({
            'schemaVersion': 1, 'providers': {'registry': {
                'credentials': {}, 'operations': {'candidate_head': {
                    'policy': 'DENY', 'targets': [GATEWAY_TARGET],
                }},
            }},
        })
        self.owner = HTTPFixtureWebAuthn()
        self.owner.origin = 'http://localhost:19503'
        state = self.fixture.path.parent / 'e1-provider-fit'
        state.mkdir(mode=0o700)

        class NoSonar:
            def call(self, *args):
                raise AssertionError('No unrelated provider IO permitted')

        with patch('fortis_approvals.r7_unified_candidate.IncidentOwnerWebAuthn',
                   return_value=self.owner), patch.object(
                       GatewayRegistryUnixCandidateRead, '_check_identity',
                       return_value=None):
            self.core, _, self.portal, self.ingress = build_r7_unified_candidate(
                state=state, owner_origin='http://localhost:19503',
                ingress_host='host.docker.internal:19504', ingress_grant=GRANT,
                sonar_transport=NoSonar(), organizations=('fortis-test',),
                extensions=config, extension_providers=(provider,),
                unified_policy_source_opt_in=R7UnifiedPolicySourceOptIn(
                    'a' * 64, lambda: 'b' * 64,
                    allow_all_method_policy_upgrade=True))
        self.runtime = self.portal._extension_runtime
        self.coord = (ACTOR, 'registry', 'candidate_head', GATEWAY_TARGET)

    def request(self, *, target=GATEWAY_TARGET, params=None):
        return {'requestId': str(uuid.uuid4()), 'service': 'registry',
                'operation': 'candidate_head', 'target': target,
                'params': {'repository': REPOSITORY} if params is None else params,
                'reason': 'Offline Registry integration fit, no host grant'}

    def policy_change(self, before, after):
        with self.core._db() as db:
            revision, _, _ = self.core._snapshot(db)
        candidate = dict(actor=ACTOR, provider='registry',
                         operation='candidate_head', scope='exact',
                         target=GATEWAY_TARGET, expectedPolicy=before,
                         desiredPolicy=after, expectedRevision=revision,
                         expectedPolicyVersion=self.core.policy_version,
                         reasonCode='OWNER_POLICY_CHANGE')
        begin = self.portal.editor.begin(
            self.owner._session, self.owner._csrf, candidate)
        return self.portal.editor.finish(
            self.owner._session, self.owner._csrf, begin['ceremonyId'],
            {'syntheticTestOnlyUv': True}, begin['change'])

    def test_existing_extension_registers_registry_and_reads_real_unix(self):
        self.assertIn('registry', self.core.adapters)
        self.assertNotIn('registry', self.ingress.base.broker.read_adapters)
        self.assertEqual(self.core.authority.choices[self.coord],
                         frozenset(('DENY', 'ASK', 'ALLOW')))
        rows = self.portal.editor.inventory(self.runtime)['operations']
        row = next(row for row in rows if (
            row['actor'], row['provider'], row['operation'], row['target'])
            == self.coord)
        self.assertEqual((row['currentPolicy'], row['editablePolicies']),
                         ('DENY', ['ALLOW', 'ASK', 'DENY']))
        catalog = self.runtime.catalog(GRANT)['operations']
        self.assertEqual(len(catalog), 1)
        self.assertEqual((catalog[0]['service'], catalog[0]['operation'],
                          catalog[0]['policy'], catalog[0]['ready']),
                         ('registry', 'candidate_head', 'DENY', False))
        with self.assertRaises(Denied):
            self.runtime.call(GRANT, self.request())
        self.assertEqual(self.calls, [])

        self.policy_change('DENY', 'ALLOW')  # Synthetic test owner only.
        request = self.request()
        with patch.object(GatewayRegistryUnixCandidateRead, '_check_identity',
                          return_value=None), patch.object(
                              GatewayRegistryUnixCandidateRead, '_peer',
                              return_value=self.fixture.reader._registry):
            issued = self.runtime.call(GRANT, request)
            self.assertEqual(issued['state'], 'EXECUTED')
            # Original Core requestId is not executed a second time on replay.
            self.assertEqual(self.runtime.call(GRANT, request), issued)
            data = self.runtime.result(GRANT, request['requestId'])['data']
            self.assertEqual(data['result'], 'SOURCE_ONLY_CANDIDATE_READ')
            self.assertEqual(data['data']['localCheckpoint']['revision'], 1)
            self.assertIs(data['writeEnabled'], False)
            self.assertIs(data['admissionAllowed'], False)
        self.assertEqual(self.calls, [request['requestId']])
        self.assertEqual(self.fixture.failures, [])

    def test_existing_policy_and_actor_guards_block_unreviewed_access(self):
        self.policy_change('DENY', 'ALLOW')
        for grant, request in (
            ('unknown-actor-credential', self.request()),
            (GRANT, self.request(target='other')),
            (GRANT, self.request(params={'repository': REPOSITORY, 'sql': 'x'})),
        ):
            with self.subTest(grant=grant, request=request), self.assertRaises(Denied):
                self.runtime.call(grant, request)
        self.assertEqual(self.calls, [])
        self.policy_change('ALLOW', 'ASK')
        pending = self.runtime.call(GRANT, self.request())
        self.assertEqual(pending['state'], 'PENDING')
        self.assertEqual(self.calls, [])  # ASK cannot read socket before owner.
        self.policy_change('ASK', 'DENY')
        with self.assertRaises(Denied):
            self.runtime.call(GRANT, self.request())
        self.assertEqual(self.calls, [])
        # The old candidate /v1/reads seam has no accidental actor grant.
        self.assertNotIn(('registry', 'candidate_head'),
                         self.ingress.base.broker.actor_read_operations[ACTOR])


if __name__ == '__main__':
    unittest.main()

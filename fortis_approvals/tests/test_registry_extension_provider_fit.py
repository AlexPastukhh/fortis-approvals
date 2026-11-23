"""E1.0: standard extension provider / Owner Policy V2 fit with existing Registry AF_UNIX.

Source-only same-UID fixture. Synthetic owner WebAuthn and patched peer/UID
checks are NOT live host acceptance, issued grants, or authoritative Desired.
No Registry extension is installed in the ordinary Gateway image by this test.
"""
import io
import json
import uuid
import unittest
from unittest.mock import patch

from fortis_approvals.core import Denied
from fortis_approvals.extensions.model import discover
from fortis_approvals.extensions.runtime import ExtensionConfig
from fortis_approvals.extensions.owner_policy_r7_v2 import R7UnifiedPolicySourceOptIn
from fortis_approvals.integrations.registry.candidate_gateway import GatewayRegistryUnixCandidateRead
from fortis_approvals.integrations.registry.read_contract import (
    GATEWAY_TARGET, REPOSITORY,
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

        # The E1.1 packaged provider now supplies these operations. Recording
        # real socket reads here proves there is no extra bypassing route.
        original = self.fixture.reader.read
        def observed(request):
            self.calls.append(request['requestId'])
            return original(request)
        self.fixture.reader.read = observed

        config = ExtensionConfig({
            'schemaVersion': 1, 'providers': {'registry': {
                'credentials': {}, 'operations': {
                    name: {'policy': 'DENY', 'targets': [GATEWAY_TARGET]}
                    for name in ('candidate_head', 'candidate_list_desired',
                                 'candidate_original_operation')
                },
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
                extensions=config, registry_candidate_reader=self.fixture.reader,
                unified_policy_source_opt_in=R7UnifiedPolicySourceOptIn(
                    'a' * 64, lambda: 'b' * 64,
                    allow_all_method_policy_upgrade=True))
        self.runtime = self.portal._extension_runtime
        self.coord = (ACTOR, 'registry', 'candidate_head', GATEWAY_TARGET)

    def request(self, *, target=GATEWAY_TARGET, params=None, operation='candidate_head'):
        return {'requestId': str(uuid.uuid4()), 'service': 'registry',
                'operation': operation, 'target': target,
                'params': {'repository': REPOSITORY} if params is None else params,
                'reason': 'Offline Registry integration fit, no host grant'}

    def policy_change(self, before, after, operation='candidate_head'):
        with self.core._db() as db:
            revision, _, _ = self.core._snapshot(db)
        candidate = dict(actor=ACTOR, provider='registry',
                         operation=operation, scope='exact',
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
        self.assertEqual(tuple(op.name for op in discover(('registry',))[0].operations),
                         ('candidate_head', 'candidate_list_desired',
                          'candidate_original_operation'))
        self.assertTrue(all(not op.ready for op in discover(('registry',))[0].operations))
        self.assertTrue(all(op.ready for op in self.runtime.providers['registry'].operations))
        self.assertIs(self.runtime.providers['registry'].api, self.fixture.reader)
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
        self.assertEqual(len(catalog), 3)
        catalog = [row for row in catalog if row['operation'] == 'candidate_head']
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

    def test_all_packaged_candidate_reads_share_extension_core_and_socket(self):
        from fortis_approvals.extensions.client import IntegrationClient
        self.assertIsNotNone(IntegrationClient)  # Existing generic Repo client.
        original_id = self.fixture.operations[0][0]['operation_id']
        self.policy_change('DENY', 'ALLOW', 'candidate_list_desired')
        self.policy_change('DENY', 'ALLOW', 'candidate_original_operation')
        with patch.object(GatewayRegistryUnixCandidateRead, '_check_identity',
                          return_value=None), patch.object(
                              GatewayRegistryUnixCandidateRead, '_peer',
                              return_value=self.fixture.reader._registry):
            for operation, params, expected in (
                ('candidate_list_desired',
                 {'repository': REPOSITORY, 'limit': 10, 'cursor': None},
                 'LOCAL_DESIRED_CANDIDATE_PAGE'),
                ('candidate_original_operation',
                 {'repository': REPOSITORY, 'operationId': original_id},
                 'LOCAL_DESIRED_CANDIDATE_COMMITTED'),
            ):
                with self.subTest(operation=operation):
                    request = self.request(params=params, operation=operation)
                    issued = self.runtime.call(GRANT, request)
                    self.assertEqual(issued['state'], 'EXECUTED')
                    value = self.runtime.result(GRANT, request['requestId'])['data']
                    self.assertEqual(value['result'], 'SOURCE_ONLY_CANDIDATE_READ')
                    self.assertEqual(value['candidateOperation'], operation)
                    self.assertEqual(value['data']['result'], expected)
                    self.assertIs(value['admissionAllowed'], False)
                    self.assertIs(value['writeEnabled'], False)
        self.assertEqual(len(self.calls), 2)
        self.assertNotIn('registry', self.ingress.base.broker.read_adapters)
        self.assertFalse(self.fixture.failures)

    def test_packaged_provider_uses_only_existing_typed_http_machine_routes(self):
        from fortis_approvals.extensions.owner_inventory import owner_policy_inventory
        inv = owner_policy_inventory(self.core, self.runtime)
        item = next(row for row in inv['providers'] if row['provider'] == 'registry')
        self.assertEqual(item['type'], 'extension')
        self.assertTrue(item['active'])
        self.assertEqual(len([row for row in inv['operations']
                              if row['provider'] == 'registry']), 3)
        self.policy_change('DENY', 'ALLOW')
        request = self.request()

        def post(path, payload, *, grant=GRANT):
            raw = json.dumps(payload).encode('utf-8')
            statuses = []
            env = {'REQUEST_METHOD': 'POST', 'PATH_INFO': path,
                   'HTTP_HOST': 'host.docker.internal:19504',
                   'QUERY_STRING': '', 'CONTENT_TYPE': 'application/json',
                   'CONTENT_LENGTH': str(len(raw)),
                   'HTTP_AUTHORIZATION': 'Bearer ' + grant,
                   'wsgi.url_scheme': 'https', 'wsgi.input': io.BytesIO(raw)}
            data = b''.join(self.ingress(
                env, lambda status, headers: statuses.append(status)))
            return int(statuses[0].split()[0]), json.loads(data)

        with patch.object(GatewayRegistryUnixCandidateRead, '_check_identity',
                          return_value=None), patch.object(
                              GatewayRegistryUnixCandidateRead, '_peer',
                              return_value=self.fixture.reader._registry):
            status, output = post('/v1/integrations/catalog', {})
            self.assertEqual(status, 200)
            self.assertEqual({r['operation'] for r in output['operations']},
                             {'candidate_head', 'candidate_list_desired',
                              'candidate_original_operation'})
            status, output = post('/v1/integrations/call', request)
            self.assertEqual(status, 200)
            self.assertEqual(output['state'], 'EXECUTED')
            status, result = post('/v1/integrations/result',
                                  {'requestId': request['requestId']})
            self.assertEqual(status, 200)
            self.assertEqual(result['data']['result'], 'SOURCE_ONLY_CANDIDATE_READ')
            status, result = post('/v1/reads', request)
            self.assertNotEqual(status, 200)  # No parallel native public API.
            status, result = post('/v1/integrations/call', self.request(),
                                  grant='invalid-machine-grant')
            self.assertEqual(status, 403)
        self.assertEqual(self.calls, [request['requestId']])
        self.assertEqual(self.fixture.failures, [])

    def test_unbound_registry_fails_before_core_or_owner_state(self):
        state = self.fixture.path.parent / 'unbound-r7'
        state.mkdir(mode=0o700)
        from fortis_approvals.r7_unified_candidate import MARKER
        config = ExtensionConfig({'schemaVersion': 1, 'providers': {
            'registry': {'credentials': {}, 'operations': {
                'candidate_head': {'policy': 'DENY', 'targets': [GATEWAY_TARGET]}
            }}}})
        with self.assertRaisesRegex(Denied, 'R7_REGISTRY_EXTENSION_TRUSTED_BINDING_REQUIRED'):
            build_r7_unified_candidate(state=state,
                owner_origin='http://localhost:19503',
                ingress_host='host.docker.internal:19504', ingress_grant=GRANT,
                sonar_transport=object(), organizations=('fortis-test',),
                extensions=config)
        self.assertFalse((state / MARKER).exists())
        with self.assertRaisesRegex(Denied, 'R7_REGISTRY_EXTENSION_TRUSTED_BINDING_REQUIRED'):
            build_r7_unified_candidate(state=state,
                owner_origin='http://localhost:19503',
                ingress_host='host.docker.internal:19504', ingress_grant=GRANT,
                sonar_transport=object(), organizations=('fortis-test',),
                extensions=config,
                extension_providers=(discover(('registry',))[0],),
                registry_candidate_reader=self.fixture.reader)
        self.assertFalse((state / MARKER).exists())

    def test_unbound_discovered_operations_reject_enable_and_direct_execution(self):
        from fortis_approvals.extensions.runtime import ExtensionRuntime
        p = discover(('registry',))[0]
        self.assertEqual(len(p.operations), 3)
        self.assertTrue(all(not x.ready for x in p.operations))
        self.assertIsNone(p.api)
        with self.assertRaisesRegex(Denied, 'REGISTRY_EXTENSION_CONTEXT_DENIED'):
            p.operations[0].execute(None)
        config = ExtensionConfig({'schemaVersion': 1, 'providers': {
            'registry': {'credentials': {}, 'operations': {
                'candidate_head': {'policy': 'ALLOW', 'targets': [GATEWAY_TARGET]}
            }}}})
        with self.assertRaisesRegex(Denied, 'INTEGRATION_HANDLER_NOT_READY'):
            ExtensionRuntime(config, providers=(p,), actors=(ACTOR,),
                             default_actor=ACTOR)

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

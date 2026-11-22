"""P5 source-only Gateway -> Registry reads via existing Core/Broker.

Test-only credentials, policy, owner and SQLite; no installed R7 routes,
real owner approval, protected checkpoint, Registry queue or WRITE.
"""
import copy
import io
import json
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest.mock import patch

from fortis_approvals.core import Authenticator, Core, Denied, canonical
from fortis_approvals.repo_action_contract import (
    RepoIntentBroker, validate_read_query, validate_intent)
from fortis_approvals.repo_ingress import RepoIngress
from fortis_approvals.registry import boundary as b
from fortis_approvals.tests.test_registry_boundary import (
    EVIDENCE, snapshot, digest)
from fortis_approvals.extensions.owner_policy_engine_v2 import UnifiedPolicyCore
from fortis_approvals.extensions.owner_policy_r7_v2 import derive_admission
from fortis_approvals.extensions.owner_policy_editor_v2 import (
    OwnerPolicyEditor, UnifiedPolicyPortal)
from fortis_approvals.read_approval import install_owner_read_approval
from fortis_approvals.tests.test_owner_policy_local_deny_http_phase6c2 import (
    HTTPFixtureWebAuthn)

ACTOR = 'registry-source-reader-test'
GRANT = 'registry-source-grant-000001'
TARGET = b.GATEWAY_TARGET
SERVICE = 'registry'


class GatewayRegistryReadTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix='registry-gateway-source-')
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.boundary_auth = Authenticator({'source-reader-private': b.READER,
                                            'source-planner-private': b.PLANNER})
        self.observation = snapshot()
        self.evidence_calls = []
        def evidence(ident):
            self.evidence_calls.append(ident)
            return copy.deepcopy(self.observation)
        self.boundary = b.RegistryBoundary(
            authenticator=self.boundary_auth, evidence_reader=evidence)
        self.reader = b.GatewayRegistryReadCandidate(
            boundary=self.boundary, reader_credential='source-reader-private')
        self.auth = Authenticator({GRANT: ACTOR, 'ungranted-test-grant': 'other-actor'})
        self.policies = {
            (ACTOR, SERVICE, 'capabilities'): 'ALLOW',
            (ACTOR, SERVICE, 'preview_merged'): 'ALLOW',
            (ACTOR, SERVICE, 'list_records'): 'ALLOW',
            (ACTOR, SERVICE, 'get_record'): 'ALLOW',
            (ACTOR, SERVICE, 'get_operation'): 'ALLOW',
        }
        self.core = Core(self.root/'core.sqlite', adapters={SERVICE: object()},
                         policies=self.policies, authenticator=self.auth)
        self.broker = RepoIntentBroker(
            self.core, actor_operations={ACTOR: {('synthetic', 'set_ask')}},
            actor_read_operations={ACTOR: b.GATEWAY_READ_OPERATIONS},
            read_adapters={SERVICE: self.reader})

    def query(self, operation='capabilities', **params):
        return dict(requestId=str(uuid.uuid4()), service=SERVICE,
                    operation=operation, target=TARGET,
                    params={'repository': b.REPOSITORY, **params},
                    reason='Source-only Registry read; no runtime effects')

    def test_capabilities_via_existing_broker_are_explicitly_source_only(self):
        result = self.broker.read(GRANT, self.query())
        self.assertEqual(result['service'], SERVICE)
        self.assertEqual(result['operation'], 'capabilities')
        self.assertEqual(result['data']['activationState'], 'SOURCE_ONLY')
        self.assertEqual(result['data']['liveOperations'], [])
        self.assertFalse(result['data']['writeEnabled'])
        self.assertFalse(result['data']['storeAvailable'])
        self.assertEqual(self.evidence_calls, [])

    def test_preview_returns_blocked_not_queue_or_admission(self):
        query = self.query('preview_merged', evidenceId=EVIDENCE,
                           evidenceDigest=digest(self.observation))
        result = self.broker.read(GRANT, query)['data']
        self.assertEqual(result['result'], 'BLOCKED_EVIDENCE_GAP')
        self.assertEqual(result['evidenceClass'], 'SOURCE_CANDIDATE_ONLY')
        self.assertEqual(self.evidence_calls, [EVIDENCE])
        self.assertFalse(result['admissionAllowed'])
        for key in ('records', 'recordCount', 'actual', 'receipt', 'deployment'):
            self.assertNotIn(key, result)

    def test_queue_and_original_receipt_remain_unavailable(self):
        calls = [
            ('list_records', {'limit': 2, 'cursor': None}),
            ('get_record', {'recordId': 'a'*64}),
            ('get_operation', {'operationId': str(uuid.uuid4())}),
        ]
        for operation, params in calls:
            with self.subTest(operation=operation), self.assertRaisesRegex(
                    Denied, 'REGISTRY_STORAGE_UNAVAILABLE'):
                self.broker.read(GRANT, self.query(operation, **params))
        self.assertEqual(self.evidence_calls, [])

    def test_ungranted_unknown_and_revoked_actor_fail_before_registry(self):
        with self.assertRaisesRegex(Denied, 'REPO_READ_GRANT_DENIED'):
            self.broker.read('ungranted-test-grant', self.query())
        with self.assertRaises(Denied):
            self.broker.read('bogus-test-grant', self.query())
        self.auth.revoke(GRANT)
        with self.assertRaises(Denied):
            self.broker.read(GRANT, self.query())
        self.assertEqual(self.evidence_calls, [])

    def test_deny_ask_without_owner_path_and_no_bypass(self):
        key = (ACTOR, SERVICE, 'preview_merged')
        self.core.policies[key] = 'DENY'
        with self.assertRaises(Denied):
            self.broker.read(GRANT, self.query(
                'preview_merged', evidenceId=EVIDENCE,
                evidenceDigest=digest(self.observation)))
        self.core.policies[key] = 'ASK'
        with self.assertRaisesRegex(Denied, 'REPO_SONAR_READ_ALLOW_REQUIRED'):
            self.broker.read(GRANT, self.query(
                'preview_merged', evidenceId=EVIDENCE,
                evidenceDigest=digest(self.observation)))
        self.assertEqual(self.evidence_calls, [])

    def test_strict_target_schema_no_actor_and_write_never_registered(self):
        for changes in (
            {'target': 'fortis-container'},
            {'params': {'repository': 'other/repo'}},
            {'params': {'repository': b.REPOSITORY, 'actor': ACTOR}},
            {'params': {'repository': b.REPOSITORY, 'path': '/tmp/state'}},
        ):
            with self.subTest(changes=changes), self.assertRaises(Denied):
                validate_read_query({**self.query(), **changes})
        for params in ({'limit': True, 'cursor': None},
                       {'limit': 101, 'cursor': None},
                       {'limit': 1, 'cursor': '../secret'}):
            with self.subTest(params=params), self.assertRaises(Denied):
                validate_read_query(self.query('list_records', **params))
        for operation in ('ingest_merged', 'deploy', 'report_manual_complete'):
            with self.assertRaisesRegex(Denied, 'REPO_OPERATION_NOT_SUPPORTED'):
                validate_read_query(self.query(operation))
        with self.assertRaisesRegex(Denied, 'REPO_OPERATION_NOT_SUPPORTED'):
            validate_intent(self.query('ingest_merged'))
        self.assertEqual(self.evidence_calls, [])

    def test_only_bound_reader_credential_is_accepted(self):
        for credential in ('source-planner-private', 'bad', '', None):
            with self.subTest(credential=credential), self.assertRaisesRegex(
                    Denied, 'REGISTRY_GATEWAY_BINDING_DENIED'):
                b.GatewayRegistryReadCandidate(
                    boundary=self.boundary, reader_credential=credential)
        self.boundary_auth.revoke('source-reader-private')
        with self.assertRaisesRegex(Denied, 'REGISTRY_ACTOR_DENIED'):
            self.broker.read(GRANT, self.query())

    def test_forged_adapter_projection_cannot_claim_queue_or_live(self):
        original = self.reader.read
        def fake(request):
            result = original(request)
            if request['operation'] == 'capabilities':
                return {**result, 'activationState': 'LIVE', 'writeEnabled': True}
            return {**result, 'admissionAllowed': True, 'records': []}
        with patch.object(self.reader, 'read', side_effect=fake):
            with self.assertRaisesRegex(Denied, 'REGISTRY_GATEWAY_PROJECTION_DENIED'):
                self.broker.read(GRANT, self.query())
            with self.assertRaisesRegex(Denied, 'REGISTRY_GATEWAY_PROJECTION_DENIED'):
                self.broker.read(GRANT, self.query(
                    'preview_merged', evidenceId=EVIDENCE,
                    evidenceDigest=digest(self.observation)))

    def test_existing_wsgi_read_ingress_only_with_explicit_registration(self):
        app = RepoIngress(self.broker, host='localhost:19555',
                          allow_http_local_test=True)
        query = self.query()
        raw = canonical(query).encode()
        response = []
        def start(status, headers):
            response.append((status, headers))
        env = dict(REQUEST_METHOD='POST', PATH_INFO='/v1/reads',
                   HTTP_HOST='localhost:19555', QUERY_STRING='',
                   CONTENT_TYPE='application/json', CONTENT_LENGTH=str(len(raw)),
                   HTTP_AUTHORIZATION='Bearer '+GRANT,
                   **{'wsgi.url_scheme': 'http', 'REMOTE_ADDR': '127.0.0.1',
                      'wsgi.input': io.BytesIO(raw)})
        data = json.loads(b''.join(app(env, start)))
        self.assertEqual(response[0][0], '200 OK')
        self.assertEqual(data['data']['activationState'], 'SOURCE_ONLY')
        self.assertNotIn('owner', data)
        self.assertEqual(self.evidence_calls, [])

    def test_revoked_actor_mid_read_does_not_receive_source_data(self):
        original = self.reader.read
        def revoke(request):
            result = original(request)
            self.auth.revoke(GRANT)
            return result
        with patch.object(self.reader, 'read', side_effect=revoke):
            with self.assertRaises(Denied):
                self.broker.read(GRANT, self.query())
        self.assertEqual(self.evidence_calls, [])

    def test_policy_change_mid_read_fails_closed(self):
        original = self.reader.read
        def change(request):
            result = original(request)
            self.core.policies[(ACTOR, SERVICE, 'capabilities')] = 'DENY'
            return result
        with patch.object(self.reader, 'read', side_effect=change):
            with self.assertRaises(Denied):
                self.broker.read(GRANT, self.query())
        self.assertEqual(self.evidence_calls, [])

    def test_packaged_shared_contract_not_registry_runtime(self):
        root = Path(__file__).resolve().parents[2]
        deploy = root / 'fortis_approvals' / 'deploy'
        primary = (deploy / 'Dockerfile-Gateway-Modularized-Candidate').read_text()
        publisher = (deploy / 'Dockerfile-P3-Release-Label-Publisher').read_text()
        self.assertIn('COPY fortis_approvals/integrations/ /opt/fortis/', primary)
        self.assertIn('fortis_approvals/integrations/registry/read_contract.py', publisher)
        self.assertNotIn('COPY fortis_approvals/registry/', primary)
        self.assertNotIn('COPY fortis_approvals/registry/', publisher)

    def test_ingest_action_is_denied_by_existing_gateway_ingress(self):
        app = RepoIngress(self.broker, host='localhost:19555',
                          allow_http_local_test=True)
        query = self.query('ingest_merged')
        raw = canonical(query).encode()
        observed = []
        env = dict(REQUEST_METHOD='POST', PATH_INFO='/v1/actions',
                   HTTP_HOST='localhost:19555', QUERY_STRING='',
                   CONTENT_TYPE='application/json', CONTENT_LENGTH=str(len(raw)),
                   HTTP_AUTHORIZATION='Bearer ' + GRANT,
                   **{'wsgi.url_scheme': 'http', 'REMOTE_ADDR': '127.0.0.1',
                      'wsgi.input': io.BytesIO(raw)})
        _ = b''.join(app(env, lambda status, headers: observed.append(status)))
        self.assertEqual(observed, ['403 Forbidden'])
        self.assertEqual(self.evidence_calls, [])

    def test_registered_owner_policy_admission_reuses_existing_core(self):
        owner = HTTPFixtureWebAuthn()
        owner.origin = 'http://localhost:18990'
        core = UnifiedPolicyCore(self.root/'owner-policy.sqlite',
                                 adapters={'registry': object()},
                                 policies={(ACTOR, SERVICE, 'capabilities'): 'ALLOW'},
                                 authenticator=Authenticator({GRANT: ACTOR}),
                                 owner_verifier=owner,
                                 policy_version='registry-source-read-v1')
        broker = RepoIntentBroker(
            core, actor_operations={ACTOR: {('synthetic', 'set_ask')}},
            actor_read_operations={ACTOR: {('registry', 'capabilities')}},
            read_adapters={'registry': self.reader})
        admission = derive_admission(core, broker, native=None,
                                     extension_runtime=None,
                                     allow_all_method_policy_upgrade=True)
        self.assertEqual(admission[(ACTOR, SERVICE, 'capabilities')],
                         frozenset(('DENY', 'ASK', 'ALLOW')))
        self.assertEqual(set(admission), {(ACTOR, SERVICE, 'capabilities')})
        core.install_policy_authority(admission)
        portal = UnifiedPolicyPortal(core, owner)
        install_owner_read_approval(core, broker, portal)
        editor = OwnerPolicyEditor(core, owner, source_digest='a'*64,
                                   credential_generation=lambda: 'b'*64)
        portal.bind_editor(editor)
        initial = broker.read(GRANT, self.query())
        self.assertEqual(initial['data']['activationState'], 'SOURCE_ONLY')
        candidate = dict(actor=ACTOR, provider=SERVICE, operation='capabilities',
                         scope='actor', target=None, expectedPolicy='ALLOW',
                         desiredPolicy='ASK', expectedRevision=0,
                         expectedPolicyVersion=core.policy_version,
                         reasonCode='OWNER_POLICY_CHANGE')
        started = editor.begin(owner._session, owner._csrf, candidate)
        editor.finish(owner._session, owner._csrf, started['ceremonyId'],
                      {'syntheticTestOnlyUv': True}, started['change'])
        request = self.query()
        pending = broker.read(GRANT, request)
        self.assertEqual(pending['state'], 'PENDING')
        self.assertEqual(self.evidence_calls, [])
        with patch.object(owner, 'verify', return_value='offline-owner', create=True):
            approved = core.owner_decide(request['requestId'], 'approve',
                                        {'offlineFakeProof': True})
        self.assertEqual(approved['state'], 'EXECUTED')
        result = broker.read(GRANT, request)
        self.assertEqual(result['data']['activationState'], 'SOURCE_ONLY')
        with self.assertRaisesRegex(Denied, 'ALREADY_USED'):
            broker.read(GRANT, request)


if __name__ == '__main__':
    unittest.main()

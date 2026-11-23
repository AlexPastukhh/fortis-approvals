"""E1.2: packaged Registry provider + real owner FIDO2 policy editor over HTTP.

No owner credential, Registry grant, image or runtime is modified. P-256 key
is created inside this isolated test fixture only. Private AF_UNIX peer/UID
checks are separate E1.3 host gates (no real cross-UID boundary here).
"""
from io import BytesIO
import json
from pathlib import Path
import unittest
import uuid
from unittest.mock import patch

from fortis_approvals.extensions.runtime import ExtensionConfig
from fortis_approvals.extensions.owner_policy_r7_v2 import R7UnifiedPolicySourceOptIn
from fortis_approvals.integrations.registry.candidate_gateway import GatewayRegistryUnixCandidateRead
from fortis_approvals.integrations.registry.read_contract import GATEWAY_TARGET, REPOSITORY
from fortis_approvals.owner_auth import OwnerWebAuthn
from fortis_approvals.r7_unified_candidate import ACTOR, build_r7_unified_candidate
from fortis_approvals.tests import test_registry_gateway_unix_candidate as unix_fixture
from test_owner_portal import VirtualKey

GRANT = unix_fixture.GRANT
OWNER_ORIGIN = 'http://localhost:19503'
PREFIX = '/v1/owner/policy/editor'
READS = ('candidate_head', 'candidate_list_desired', 'candidate_original_operation')


class RegistryVirtualKey(VirtualKey):
    # Reuse the accepted actual ES256 virtual authenticator for an R7-allowed
    # Owner origin; the existing virtual fixture defaults to port 18990.
    def client_data(self, opts, typ, *, origin=OWNER_ORIGIN, cross_origin=False):
        return super().client_data(opts, typ, origin=origin,
                                   cross_origin=cross_origin)

    def assert_(self, begin, *, origin=OWNER_ORIGIN, uv=True, cross_origin=False):
        return super().assert_(begin, origin=origin, uv=uv,
                               cross_origin=cross_origin)


class RegistryOwnerPolicyRealWebAuthn(unittest.TestCase):
    def setUp(self):
        self.fixture = unix_fixture.GatewayUnixCandidateTests(
            'test_r7_candidate_adapter_opt_in_has_no_automatic_registry_grant')
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.accept()
        self.fixture.setup_broker()
        self.calls = []
        original = self.fixture.reader.read

        def observe(request):
            self.calls.append(request['requestId'])
            return original(request)
        self.fixture.reader.read = observe

        config = ExtensionConfig({'schemaVersion': 1, 'providers': {
            'registry': {'credentials': {}, 'operations': {
                operation: {'policy': 'DENY', 'targets': [GATEWAY_TARGET]}
                for operation in READS
            }},
        }})
        self.state = self.fixture.path.parent/'real-crypto-e12'
        self.state.mkdir(mode=0o700)

        class NoSonar:
            def call(self, *args):
                raise AssertionError('Unrelated provider network IO forbidden')

        # This patch is ONLY the host-identity fixture; actual owner
        # FIDO2/WebAuthn verification is NOT patched.
        with patch.object(GatewayRegistryUnixCandidateRead, '_check_identity',
                          return_value=None):
            self.core, self.owner, self.portal, self.ingress = build_r7_unified_candidate(
                state=self.state, owner_origin=OWNER_ORIGIN,
                ingress_host='host.docker.internal:19504', ingress_grant=GRANT,
                sonar_transport=NoSonar(), organizations=('fortis-test',),
                extensions=config, registry_candidate_reader=self.fixture.reader,
                unified_policy_source_opt_in=R7UnifiedPolicySourceOptIn(
                    'a'*64, lambda: 'b'*64,
                    allow_all_method_policy_upgrade=True))
        self.assertIsInstance(self.portal.auth, OwnerWebAuthn)
        self.assertIs(self.portal.auth, self.owner)
        self.runtime = self.portal._extension_runtime
        self.key = RegistryVirtualKey()
        invitation = self.owner.issue_invitation()  # operator-only test fixture
        enrollment = self.owner.begin_enrollment(invitation)
        self.owner.finish_enrollment(enrollment['ceremonyId'],
                                     self.key.enroll(enrollment))
        login = self.owner.begin_login()
        self.session, self.csrf = self.owner.finish_login(
            login['ceremonyId'], self.key.assert_(login))

    def owner_http(self, path, body=None, *, cookie=None, csrf=None,
                   origin=OWNER_ORIGIN, host='localhost:19503',
                   extra=None, query=''):
        raw = json.dumps(body or {}).encode()
        env = {'REQUEST_METHOD': 'GET' if body is None else 'POST',
               'PATH_INFO': path, 'HTTP_HOST': host, 'QUERY_STRING': query,
               'wsgi.input': BytesIO(raw), 'CONTENT_TYPE': 'application/json',
               'CONTENT_LENGTH': str(len(raw))}
        if cookie is not False:
            env['HTTP_COOKIE'] = 'fortis_owner=' + (
                self.session if cookie is None else cookie)
        if csrf is not False:
            env['HTTP_X_FORTIS_CSRF'] = self.csrf if csrf is None else csrf
        if origin is not None:
            env['HTTP_ORIGIN'] = origin
        if extra:
            env.update(extra)
        headers = []
        data = b''.join(self.portal(env,
                        lambda status, values: headers.append((status, dict(values)))))
        return int(headers[0][0].split()[0]), json.loads(data), headers[0][1]

    def inventory(self):
        status, value, _ = self.owner_http('/v1/owner/provider-inventory')
        self.assertEqual(status, 200, value)
        return value

    def coordinate(self, operation='candidate_head', *, actor=ACTOR,
                   target=GATEWAY_TARGET, before=None, after='ALLOW'):
        inventory = self.inventory()
        row = next(row for row in inventory['operations'] if
                   row['actor'] == ACTOR and row['provider'] == 'registry'
                   and row['operation'] == operation
                   and row['target'] == GATEWAY_TARGET and row['scope'] == 'exact')
        return dict(actor=actor, provider='registry', operation=operation,
                    scope='exact', target=target,
                    expectedPolicy=row['currentPolicy'] if before is None else before,
                    desiredPolicy=after, expectedRevision=inventory['policyRevision'],
                    expectedPolicyVersion=inventory['policyVersion'],
                    reasonCode='OWNER_POLICY_CHANGE')

    def begin(self, candidate):
        return self.owner_http(PREFIX+'/begin', {'candidate': candidate})

    def finish(self, started, response, *, change=None, **kwargs):
        return self.owner_http(PREFIX+'/finish', {
            'ceremonyId': started['ceremonyId'],
            'response': response,
            'change': started['change'] if change is None else change,
        }, **kwargs)

    def change(self, *, operation='candidate_head', after='ALLOW'):
        candidate = self.coordinate(operation, after=after)
        code, started, _ = self.begin(candidate)
        self.assertEqual(code, 200, started)
        code, result, _ = self.finish(started, self.key.assert_(started))
        self.assertEqual(code, 200, result)
        code, readback, _ = self.owner_http(PREFIX+'/readback',
                             {'requestId': started['change']['requestId']})
        self.assertEqual(code, 200, readback)
        self.assertTrue(readback['found'])
        return result

    def machine_request(self, operation='candidate_head'):
        return dict(requestId=str(uuid.uuid4()), service='registry',
                    operation=operation, target=GATEWAY_TARGET,
                    params={'repository': REPOSITORY},
                    reason='E1.2 real cryptographic owner fixture, not installed')

    def machine_http(self, path, payload, *, grant=GRANT):
        raw = json.dumps(payload).encode()
        statuses = []
        env = {'REQUEST_METHOD': 'POST', 'PATH_INFO': path,
               'HTTP_HOST': 'host.docker.internal:19504',
               'QUERY_STRING': '', 'CONTENT_TYPE': 'application/json',
               'CONTENT_LENGTH': str(len(raw)),
               'HTTP_AUTHORIZATION': 'Bearer ' + grant,
               'wsgi.url_scheme': 'https', 'wsgi.input': BytesIO(raw)}
        result = b''.join(self.ingress(
            env, lambda status, headers: statuses.append(status)))
        return int(statuses[0].split()[0]), json.loads(result)

    def test_inventory_real_p256_deny_allow_readback_and_revoke(self):
        inv = self.inventory()
        self.assertEqual(inv['policyEditorVersion'], 2)
        self.assertEqual({row['provider'] for row in inv['providers'] if
                          row['provider'] == 'registry'}, {'registry'})
        self.assertEqual(next(row['type'] for row in inv['providers']
                              if row['provider'] == 'registry'), 'extension')
        rows = [row for row in inv['operations'] if row['provider'] == 'registry']
        self.assertEqual({row['operation'] for row in rows}, set(READS))
        self.assertEqual(len(rows), 3)
        for row in rows:
            self.assertEqual(row['currentPolicy'], 'DENY')
            self.assertEqual(set(row['editablePolicies']), {'DENY', 'ASK', 'ALLOW'})
            self.assertEqual(row['actor'], ACTOR)
            self.assertEqual(row['target'], GATEWAY_TARGET)
        code, _ = self.machine_http('/v1/integrations/call', self.machine_request())
        self.assertEqual(code, 403)
        self.assertEqual(self.calls, [])

        self.change()
        self.assertEqual(self.coordinate()['expectedPolicy'], 'ALLOW')
        self.assertEqual(self.coordinate('candidate_list_desired')['expectedPolicy'],
                         'DENY')
        request = self.machine_request()
        with patch.object(GatewayRegistryUnixCandidateRead, '_check_identity',
                          return_value=None), patch.object(
                              GatewayRegistryUnixCandidateRead, '_peer',
                              return_value=self.fixture.reader._registry):
            code, issued = self.machine_http('/v1/integrations/call', request)
            self.assertEqual(code, 200, issued)
            self.assertEqual(issued['state'], 'EXECUTED')
            self.assertEqual(self.machine_http('/v1/integrations/call', request),
                             (code, issued))
            code, response = self.machine_http('/v1/integrations/result',
                             {'requestId': request['requestId']})
            self.assertEqual(code, 200, response)
            value = response['data']
            self.assertEqual(value['result'], 'SOURCE_ONLY_CANDIDATE_READ')
            self.assertFalse(value['liveRegistryAvailable'])
            self.assertFalse(value['writeEnabled'])
        self.assertEqual(self.calls, [request['requestId']])

        code, _ = self.machine_http('/v1/integrations/call',
                                    self.machine_request(), grant='wrong-grant')
        self.assertEqual(code, 403)  # Policy edit is not a machine grant.
        self.change(after='ASK')
        code, pending = self.machine_http('/v1/integrations/call',
                                          self.machine_request())
        self.assertEqual(code, 202, pending)
        self.assertEqual(pending['state'], 'PENDING')
        self.assertEqual(len(self.calls), 1)  # No Unix IO before owner decision.
        self.change(after='DENY')
        code, _ = self.machine_http('/v1/integrations/call',
                                    self.machine_request())
        self.assertEqual(code, 403)
        self.assertEqual(len(self.calls), 1)
        self.assertNotIn('registry', self.ingress.base.broker.read_adapters)

    def test_bad_uv_origin_wrong_change_and_ceremony_replay_never_allow(self):
        for issue in ('uv', 'origin', 'crossorigin', 'tampered_change', 'session_only'):
            with self.subTest(issue=issue):
                code, started, _ = self.begin(self.coordinate())
                self.assertEqual(code, 200, started)
                if issue == 'uv':
                    response = self.key.assert_(started, uv=False)
                    kwargs = {}
                elif issue == 'origin':
                    response = self.key.assert_(started,
                                                origin='https://evil.invalid')
                    kwargs = {}
                elif issue == 'crossorigin':
                    response = self.key.assert_(started, cross_origin=True)
                    kwargs = {}
                elif issue == 'session_only':
                    response = {'mode': 'session', 'session': self.session}
                    kwargs = {}
                else:
                    response = self.key.assert_(started)
                    kwargs = {'change': {**started['change'],
                                         'desiredPolicy': 'ASK'}}
                status, _, _ = self.finish(started, response, **kwargs)
                self.assertEqual(status, 403)
                self.assertEqual(self.finish(started,
                                 self.key.assert_(started))[0], 403)
        self.assertEqual(self.coordinate()['expectedPolicy'], 'DENY')
        self.assertEqual(self.calls, [])

    def test_owner_http_guards_unknown_actor_target_and_stale_proof(self):
        candidate = self.coordinate()
        initial_pending = len(self.owner.pending)
        for bad in (
            {'cookie': False}, {'csrf': False}, {'origin': 'https://evil.invalid'},
            {'host': 'evil.invalid'}, {'extra': {'HTTP_X_FORWARDED_HOST': 'evil'}},
            {'query': 'ignored=1'},
        ):
            with self.subTest(bad=bad):
                status, _, _ = self.owner_http(PREFIX+'/begin',
                                             {'candidate': candidate}, **bad)
                self.assertEqual(status, 403)
        self.assertEqual(len(self.owner.pending), initial_pending)
        self.assertEqual(self.begin({**candidate, 'actor': 'ungranted-actor'})[0],
                         403)
        self.assertEqual(self.begin({**candidate, 'target': 'wrong-target'})[0],
                         403)
        self.assertEqual(self.calls, [])
        self.assertNotIn('registry', self.ingress.base.broker.read_adapters)

        code, first, _ = self.begin(self.coordinate())
        self.assertEqual(code, 200, first)
        self.change(operation='candidate_list_desired')  # Advance owner revision.
        code, _, _ = self.finish(first, self.key.assert_(first))
        self.assertIn(code, (403, 409))
        self.assertEqual(self.coordinate()['expectedPolicy'], 'DENY')
        self.assertEqual(self.coordinate('candidate_list_desired')['expectedPolicy'],
                         'ALLOW')
        self.assertEqual(self.calls, [])


if __name__ == '__main__':
    unittest.main()

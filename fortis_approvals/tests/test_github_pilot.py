"""Offline GitHub pilot through real TLS and cryptographic owner WebAuthn.

GitHub/Sonar are fake; no provider token, Docker, Windows or live write.
"""
import http.client
import json
import os
from pathlib import Path
import socket
import ssl
import tempfile
from threading import Thread
import unittest
from unittest.mock import patch
from urllib.parse import unquote
import uuid

from fortis_approvals.clients.gateway_transport import GatewayTransport
from fortis_approvals.core import Denied
from fortis_approvals.integrations.github.pilot import GitHubPilotConfig, config_from_environment
from fortis_approvals.integrations.github.repo_client.client import GitHubClient
from fortis_approvals.r7_unified_candidate import ACTOR, build_r7_unified_candidate
from fortis_approvals import r7_unified_server as server
from test_r5_lifecycle_offline import R5VirtualKey, create_test_identity
from test_r6_repo_sonar_read_to_approvals_tls_offline import ReadAndProposalFakeSonar, ORG, PROJECT

GRANT = 'OFFLINE-GITHUB-PILOT-MACHINE-GRANT-000001'
SHA = 'a' * 40
CONFIG = GitHubPilotConfig('PilotOwner', 'sandbox')


class FakeGitHub:
    def __init__(self):
        self.calls = []
        self.branches = {'main': SHA}
        self.mutations = 0
        self.lose_reply = False

    def request(self, method, path, *, params=None, body=None, expected_statuses=(200,), allow_not_found=False):
        self.calls.append((method, path))
        base = '/repos/PilotOwner/sandbox'
        if path == base and method == 'GET':
            return dict(name='sandbox', full_name='PilotOwner/sandbox', private=True,
                        default_branch='main', archived=False, disabled=False,
                        html_url='https://github.com/PilotOwner/sandbox', pushed_at=None)
        if path == base + '/branches' and method == 'GET':
            rows = [dict(name=name, commit={'sha': sha}, protected=name == 'main')
                    for name, sha in sorted(self.branches.items())]
            start = (params['page'] - 1) * params['per_page']
            return rows[start:start + params['per_page']]
        if path.startswith(base + '/git/ref/heads/') and method == 'GET':
            name = unquote(path.split('/git/ref/heads/', 1)[1])
            if name not in self.branches and allow_not_found:
                return {'_httpStatus': 404}
            return {'object': {'sha': self.branches[name]}}
        if path == base + '/git/commits/' + SHA and method == 'GET':
            return {'sha': SHA}
        if path == base + '/git/refs' and method == 'POST':
            name = body['ref'].removeprefix('refs/heads/')
            assert name not in self.branches
            self.branches[name] = body['sha']
            self.mutations += 1
            if self.lose_reply:
                raise TimeoutError('OFFLINE_SIMULATED_REPLY_LOSS')
            return {'ref': body['ref']}
        raise AssertionError((method, path))


class ConfigTests(unittest.TestCase):
    def test_explicit_opt_in_and_exact_scope(self):
        self.assertIsNone(config_from_environment({}))
        self.assertIsNone(config_from_environment({'FORTIS_GITHUB_PILOT': '0'}))
        self.assertEqual(config_from_environment({'FORTIS_GITHUB_PILOT': '1',
            'FORTIS_GITHUB_OWNER': 'PilotOwner', 'FORTIS_GITHUB_REPOSITORY': 'sandbox'}), CONFIG)
        for env in ({'FORTIS_GITHUB_PILOT': 'true'}, {'FORTIS_GITHUB_OWNER': 'PilotOwner'},
                    {'FORTIS_GITHUB_PILOT': '1'}):
            with self.assertRaises(ValueError): config_from_environment(env)
        for prefix in ('', 'main/', 'master/', '../', 'fortis-e2e', 'a/b/', 'x//'):
            with self.assertRaises(ValueError): GitHubPilotConfig('PilotOwner', 'sandbox', prefix)
        with self.assertRaises(Denied): CONFIG.check_endpoints('http://localhost:19103', 'host.docker.internal:19104')

    def test_default_disabled_does_not_read_token_or_create_receipt(self):
        with tempfile.TemporaryDirectory() as folder:
            state = Path(folder) / 'private'
            state.mkdir(mode=0o700)
            with patch('fortis_approvals.integrations.github.pilot.GitHubHTTPTransport.from_file',
                       side_effect=AssertionError('TOKEN_MUST_NOT_BE_READ')):
                core, _, _, ingress = build_r7_unified_candidate(
                    state=state, owner_origin='http://localhost:19203', ingress_host='host.docker.internal:19204',
                    ingress_grant=GRANT, sonar_transport=ReadAndProposalFakeSonar(), organizations=(ORG,), project_keys=(PROJECT,))
            self.assertNotIn('github', core.adapters)
            self.assertNotIn('github', ingress.broker.read_adapters)
            self.assertFalse((state / 'github-receipts.sqlite').exists())

    def test_primary_actor_only_and_scope_denied_before_upstream(self):
        with tempfile.TemporaryDirectory() as folder:
            state = Path(folder) / 'private'
            state.mkdir(mode=0o700)
            remote = FakeGitHub()
            second = 'OFFLINE-OTHER-MACHINE-GRANT-000000000002'
            core, _, portal, ingress = build_r7_unified_candidate(
                state=state, owner_origin='http://localhost:19203', ingress_host='host.docker.internal:19204',
                ingress_grant=GRANT, actor_grants={GRANT: ACTOR, second: 'other-actor'},
                sonar_transport=ReadAndProposalFakeSonar(), organizations=(ORG,), project_keys=(PROJECT,),
                github_pilot=CONFIG, github_transport=remote)
            broker = ingress.broker
            self.assertIs(portal.core, broker.core)
            self.assertIn(('github', 'create_branch'), portal.strong_operations)
            def envelope(op, target='sandbox', params=None):
                return dict(requestId=str(uuid.uuid4()), service='github', operation=op,
                            target=target, params=params or {}, reason='offline scope check')
            for grant, query in ((second, envelope('get_repository')),
                    (GRANT, envelope('get_repository', 'foreign')),
                    (GRANT, envelope('list_commits', params={'page': 1, 'perPage': 10}))):
                with self.assertRaises(Denied): broker.read(grant, query)
            with self.assertRaises(Denied):
                broker.submit(GRANT, envelope('create_branch', params={'branch': 'other/test', 'sourceSha': SHA}))
            self.assertEqual(remote.calls, [])
            self.assertEqual(core.policy_version, 'r7-p1-sonar-accept-issue-write-v1')


class PilotTLSWebAuthnTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='github-pilot-real-tls-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        state = self.root / 'private'
        state.mkdir(mode=0o700)
        self.remote = FakeGitHub()
        self.sonar = ReadAndProposalFakeSonar()
        self.grant = self.root / 'grant'
        self.grant.write_text(GRANT + '\n'); self.grant.chmod(0o600)
        token = self.root / 'sonar'
        token.write_text('OFFLINE-ONLY-FAKE-SONAR-CREDENTIAL'); token.chmod(0o600)
        self.cert, key = self.root / 'server.crt', self.root / 'server.key'
        create_test_identity(self.cert, key)
        with (patch.object(server, 'OWNER_PORT', 0), patch.object(server, 'MACHINE_PORT', 0),
              patch.object(server, 'SonarHTTPTransport', return_value=self.sonar),
              patch('fortis_approvals.integrations.github.pilot.GitHubHTTPTransport.from_file', return_value=self.remote),
              patch.dict(os.environ, {'FORTIS_OWNER_ORIGIN': 'http://localhost:19203',
                                    'FORTIS_MACHINE_HOST': 'host.docker.internal:19204'})):
            self.web, self.machine = server.create_servers(state=state, grant_path=self.grant,
                sonar_token_path=token, cert_path=self.cert, key_path=key, region='eu',
                organizations=(ORG,), project_key=PROJECT, bind_host='127.0.0.1', github_pilot=CONFIG)
        self.threads = []
        for item in (self.web, self.machine):
            thread = Thread(target=item.serve_forever, daemon=True)
            thread.start(); self.threads.append(thread)
        self.addCleanup(self.stop)
        original = socket.create_connection
        def connect(address, timeout=None, source_address=None):
            if address[0] == 'host.docker.internal': address = ('127.0.0.1', self.machine.server_port)
            return original(address, timeout=timeout, source_address=source_address)
        self.socket_patch = patch('socket.create_connection', side_effect=connect)
        self.socket_patch.start(); self.addCleanup(self.socket_patch.stop)
        self.client = GitHubClient(gateway=GatewayTransport(endpoint='https://host.docker.internal:19204',
            grant_path=self.grant, certificate_path=self.cert, allow_test_endpoint=True))
        self.portal = self.web.get_app()
        self.core = self.portal.core
        class PilotKey(R5VirtualKey):
            def client_data(self, opts, typ, *, origin='http://localhost:19203', cross_origin=False):
                return super().client_data(opts, typ, origin=origin, cross_origin=cross_origin)
        self.key = PilotKey()
        self.cookie = None; self.csrf = None

    def stop(self):
        for item in (self.machine, self.web): item.shutdown()
        for thread in self.threads: thread.join(timeout=3)
        for item in (self.machine, self.web): item.server_close()

    def owner_call(self, path, body=None):
        headers = {'Host': 'localhost:19203'}
        if self.cookie: headers['Cookie'] = 'fortis_owner=' + self.cookie
        if self.csrf: headers['X-Fortis-Csrf'] = self.csrf
        raw = None
        if body is not None:
            headers.update({'Origin': 'http://localhost:19203', 'Content-Type': 'application/json'})
            raw = json.dumps(body).encode()
        connection = http.client.HTTPConnection('127.0.0.1', self.web.server_port, timeout=5)
        try:
            connection.request('POST' if body is not None else 'GET', path, body=raw, headers=headers)
            response = connection.getresponse()
            return response.status, json.loads(response.read()), dict(response.getheaders())
        finally: connection.close()

    def login(self):
        code, begin, _ = self.owner_call('/v1/enroll/begin', {'invitation': self.portal.auth.issue_invitation()})
        self.assertEqual(code, 200)
        self.assertEqual(self.owner_call('/v1/enroll/finish', {'ceremonyId': begin['ceremonyId'],
            'response': self.key.enroll(begin)})[0], 200)
        code, begin, _ = self.owner_call('/v1/login/begin', {})
        self.assertEqual(code, 200)
        code, data, headers = self.owner_call('/v1/login/finish', {'ceremonyId': begin['ceremonyId'],
            'response': self.key.assert_(begin, origin='http://localhost:19203')})
        self.assertEqual(code, 200)
        self.cookie = headers['Set-Cookie'].split(';', 1)[0].split('=', 1)[1]
        self.csrf = data['csrf']

    def decide(self, ident, decision, uv=True):
        code, begin, _ = self.owner_call('/v1/owner/decision/begin', {'requestId': ident, 'decision': decision})
        self.assertEqual(code, 200)
        return self.owner_call('/v1/owner/decision/finish', {'requestId': ident, 'decision': decision,
            'ceremonyId': begin['ceremonyId'], 'response': self.key.assert_(begin, origin='http://localhost:19203', uv=uv)})

    def propose(self, suffix):
        ident = str(uuid.uuid4())
        result = self.client.create_branch('sandbox', 'fortis-e2e/' + suffix, SHA,
            request_id=ident, reason='Offline exact GitHub approval')
        self.assertEqual(result['state'], 'PENDING')
        return ident

    def test_read_reject_approve_readback_and_completed_replay(self):
        self.assertEqual(self.client.get_repository('sandbox')['repository']['default_branch'], 'main')
        rejected = self.propose('reject')
        self.login()
        code, row, _ = self.decide(rejected, 'reject')
        self.assertEqual((code, row['state']), (200, 'REJECTED'))
        self.assertEqual(self.client.status(rejected)['state'], 'REJECTED')
        self.assertNotIn('fortis-e2e/reject', self.remote.branches)
        approved = self.propose('approve')
        code, rows, _ = self.owner_call('/v1/owner/pending')
        row = next(x for x in rows if x['requestId'] == approved)
        self.assertTrue(row['requiresStrongProof'])
        self.assertEqual(self.owner_call('/v1/owner/decision/session', {'requestId': approved,
            'decision': 'approve', 'fingerprint': row['fingerprint']})[0], 403)
        code, row, _ = self.decide(approved, 'approve')
        self.assertEqual((code, row['state']), (200, 'EXECUTED'))
        self.assertEqual(self.client.status(approved)['state'], 'EXECUTED')
        branches = {x['name']: x['sha'] for x in self.client.list_branches('sandbox')['items']}
        self.assertEqual(branches['fortis-e2e/approve'], SHA)
        self.assertEqual(self.remote.mutations, 1)
        self.assertEqual(self.core.adapters['github'].receipt(approved)['sha'], SHA)
        before = list(self.remote.calls)
        self.assertEqual(self.client.create_branch('sandbox', 'fortis-e2e/approve', SHA,
            request_id=approved, reason='Offline exact GitHub approval')['state'], 'EXECUTED')
        self.assertEqual(self.remote.calls, before)
        self.assertEqual(self.remote.mutations, 1)
        result = self.machine.get_app().broker.read(GRANT, dict(requestId=str(uuid.uuid4()),
            service='sonarcloud', operation='get_quality_gate', target=PROJECT, params={}, reason='Sonar regression'))
        self.assertEqual(result['data']['status'], 'ERROR')
        self.assertEqual(self.sonar.posts, 0)

    def test_missing_user_verification_cannot_execute(self):
        ident = self.propose('uv-required')
        self.login()
        self.assertEqual(self.decide(ident, 'approve', uv=False)[0], 403)
        self.assertEqual(self.client.status(ident)['state'], 'PENDING')
        self.assertEqual(self.remote.mutations, 0)

    def test_ambiguous_upstream_result_never_retries(self):
        ident = self.propose('uncertain')
        self.login(); self.remote.lose_reply = True
        code, row, _ = self.decide(ident, 'approve')
        self.assertEqual((code, row['state']), (200, 'UNCERTAIN'))
        self.assertEqual(self.client.status(ident)['state'], 'UNCERTAIN')
        self.assertEqual(self.client.create_branch('sandbox', 'fortis-e2e/uncertain', SHA,
            request_id=ident, reason='Offline exact GitHub approval')['state'], 'UNCERTAIN')
        self.assertEqual(self.remote.mutations, 1)

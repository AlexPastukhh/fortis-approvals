"""Extension registration, real Core lifecycle, secure volume IO and typed ingress.

No host/Docker imitation and no provider credentials/network. Shared WebAuthn
checks remain in the existing suite; these Core tests use its TEST-only verifier.
"""
from copy import deepcopy
from dataclasses import replace
import io
import json
import os
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch
import uuid

from fortis_approvals.core import Authenticator, Core, Denied, Conflict
from fortis_approvals.extensions.vault import CredentialVault
from fortis_approvals.extensions.model import Operation, Provider
from fortis_approvals.extensions.runtime import ExtensionConfig, ExtensionRuntime
from fortis_approvals.extensions.ingress import ExtensionIngress
from fortis_approvals.extensions.client import IntegrationClient
from fortis_approvals.integrations.review_schema import object_schema, text
from fortis_approvals.repo_ingress import RepoIngress
from test_core import SyntheticOwnerVerifier

EMPTY = object_schema({})
DATA = object_schema({'value': text})
TOKEN = 'OFFLINE_PROVIDER_TOKEN_NOT_A_REAL_CREDENTIAL'
GRANT = 'OFFLINE-EXTENSION-MACHINE-GRANT-00000001'


class ExtensionTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(); self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name); self.vault_root = self.root / 'vault'; self.vault_root.mkdir(mode=0o700)
        self.vault = CredentialVault(self.vault_root, uid=os.geteuid(), gid=os.getegid())
        self.provisioned = self.vault.provision('tickets-test', TOKEN)
        self.calls = []; self.value = 'before'; self.receipts = {}; self.lose_reply = False
        self.provider = Provider('tickets', (
            Operation('read_item', 'Read one permitted record', 'read', EMPTY, DATA,
                      self.read, credential='api'),
            Operation('set_item', 'Set one permitted record', 'write', DATA, DATA,
                      self.write, preview=lambda ctx: {'value': self.value}, preview_result=DATA,
                      lookup=lambda ctx: self.receipts.get(ctx.request_id), credential='api')))
        self.settings = {'schemaVersion': 1, 'providers': {'tickets': {
            'credentials': {'api': 'tickets-test'}, 'operations': {
                'read_item': {'policy': 'ALLOW', 'targets': ['record']},
                'set_item': {'policy': 'ASK', 'targets': ['record']}}}}}
        self.owner = SyntheticOwnerVerifier()
        self.core = Core(self.root / 'core.sqlite', adapters={}, policies={},
            authenticator=Authenticator({GRANT: 'actor', 'OFFLINE-SECOND-MACHINE-GRANT-0001': 'other'}), owner_verifier=self.owner)
        self.portal = SimpleNamespace(strong_operations=frozenset())
        self.runtime = self.build()
        base = RepoIngress(SimpleNamespace(core=self.core), host='localhost:19999', allow_http_local_test=True)
        self.ingress = ExtensionIngress(base, self.runtime)

    def build(self):
        return ExtensionRuntime(ExtensionConfig(self.settings), providers=(self.provider,), actors=('actor', 'other'),
            default_actor='actor', vault=self.vault).install(self.core, self.portal)

    def read(self, ctx):
        self.calls.append(('read', ctx.target))
        return {'value': self.value}

    def write(self, ctx):
        self.calls.append(('write', ctx.target)); self.value = ctx.params['value']
        self.receipts[ctx.request_id] = {'value': self.value}
        if self.lose_reply: raise TimeoutError('OFFLINE lost response')
        return {'value': self.value}

    def call(self, op='read_item', params=None, **changes):
        body = dict(requestId=str(uuid.uuid4()), service='tickets', operation=op,
                    target='record', params={} if params is None else params, reason='Offline typed operation')
        body.update(changes)
        return body

    def decide(self, request_id, decision):
        row = self.core._read(request_id)
        proof = self.owner.proof(request_id, row['fingerprint'], decision)
        return self.core.owner_decide(request_id, decision, proof)

    def post(self, path, body, *, grant=GRANT, **changes):
        raw = json.dumps(body).encode(); response = []
        env = {'REQUEST_METHOD': 'POST', 'PATH_INFO': path, 'HTTP_HOST': 'localhost:19999',
            'wsgi.url_scheme': 'http', 'REMOTE_ADDR': '127.0.0.1', 'CONTENT_TYPE': 'application/json',
            'CONTENT_LENGTH': str(len(raw)), 'HTTP_AUTHORIZATION': 'Bearer ' + grant, 'wsgi.input': io.BytesIO(raw)}
        env.update(changes)
        data = b''.join(self.ingress(env, lambda status, headers: response.append(status)))
        return int(response[0].split()[0]), json.loads(data)

    def test_allow_read_and_result_share_existing_core_and_replay(self):
        body = self.call(); row = self.runtime.call(GRANT, body)
        self.assertEqual(row['state'], 'EXECUTED')
        self.assertEqual(self.runtime.result(GRANT, row['requestId'])['data'], {'value': 'before'})
        self.assertEqual(self.runtime.call(GRANT, body), row)
        self.assertEqual(self.calls, [('read', 'record')])
        self.assertNotIn(TOKEN, self.core.path.read_bytes().decode(errors='ignore'))

    def test_ask_read_does_not_contact_provider_before_approve_or_after_reject(self):
        self.core.policies[('actor', 'tickets', 'read_item', 'record')] = 'ASK'
        body = self.call(); row = self.runtime.call(GRANT, body)
        self.assertEqual(row['state'], 'PENDING'); self.assertEqual(self.calls, [])
        self.assertIsNone(self.runtime.result(GRANT, row['requestId'])['data'])
        self.decide(row['requestId'], 'reject'); self.assertEqual(self.calls, [])
        body = self.call(); row = self.runtime.call(GRANT, body); self.decide(row['requestId'], 'approve')
        self.assertEqual(self.runtime.result(GRANT, row['requestId'])['data']['value'], 'before')

    def test_write_asks_strong_owner_and_rechecks_preview(self):
        row = self.runtime.call(GRANT, self.call('set_item', {'value': 'after'}))
        self.assertIn(('tickets', 'set_item'), self.portal.strong_operations)
        self.assertEqual(self.calls, [])
        self.value = 'external change'
        self.assertEqual(self.decide(row['requestId'], 'approve')['state'], 'STALE')
        self.assertEqual(self.calls, [])

    def test_approve_write_once_and_frozen_params_conflict(self):
        body = self.call('set_item', {'value': 'after'}); row = self.runtime.call(GRANT, body)
        self.assertEqual(self.decide(row['requestId'], 'approve')['state'], 'EXECUTED')
        self.assertEqual(self.runtime.call(GRANT, body)['state'], 'EXECUTED')
        self.assertEqual(self.calls, [('write', 'record')])
        body['params']['value'] = 'different'
        with self.assertRaises(Conflict): self.runtime.call(GRANT, body)

    def test_authenticated_preapproval_actor_is_core_bound_and_revalidated(self):
        # P4 prerequisite: the actor exists before Core has inserted a row.
        # Only Core's authenticated preparation path may supply it.
        seen = []
        original = self.runtime.operations[('tickets', 'set_item')]

        def preview(ctx):
            seen.append(('preview', ctx.phase, ctx.authenticated_actor))
            return {'value': ctx.authenticated_actor}

        def execute(ctx):
            seen.append(('execute', ctx.phase, ctx.authenticated_actor))
            return self.write(ctx)

        self.runtime.operations[('tickets', 'set_item')] = replace(
            original, preview=preview, execute=execute)
        body = self.call('set_item', {'value': 'after'})
        row = self.runtime.call(GRANT, body)
        self.assertEqual('PENDING', row['state'])
        self.assertEqual('actor', self.core._read(row['requestId'])['preview']['before']['value'])
        self.assertEqual([], self.calls)
        self.assertEqual([('preview', 'preview', 'actor')], seen)
        self.assertEqual('EXECUTED', self.decide(row['requestId'], 'approve')['state'])
        self.assertEqual([('write', 'record')], self.calls)
        # Core.execute does one revalidation and ExtensionAdapter.apply another.
        self.assertEqual(3, len([item for item in seen if item[0] == 'preview']))
        self.assertEqual(('execute', 'execute', 'actor'), seen[-1])
        self.assertEqual('EXECUTED', self.runtime.call(GRANT, body)['state'])
        self.assertEqual([('write', 'record')], self.calls)

        # A direct legacy adapter.prepare is *not* an authenticated Core
        # entry point, and may not derive the actor from public params.
        with self.assertRaises(Denied):
            self.core.adapters['tickets'].prepare({**body, 'expectedVersion': 0})

    def test_authenticated_actor_rejects_spoofing_reject_and_policy_stale(self):
        seen = []
        original = self.runtime.operations[('tickets', 'set_item')]

        def preview(ctx):
            seen.append(ctx.authenticated_actor)
            return {'value': ctx.authenticated_actor}

        self.runtime.operations[('tickets', 'set_item')] = replace(original, preview=preview)
        for body in (self.call('set_item', {'value': 'after', 'actor': 'other'}),
                     self.call('set_item', {'value': 'after'}, actor='other'),
                     self.call('set_item', {'value': 'after'}, approved=True)):
            with self.subTest(body=body), self.assertRaises(Denied):
                self.runtime.call(GRANT, body)
        with self.assertRaises(Denied):
            self.runtime.call('OFFLINE-SECOND-MACHINE-GRANT-0001',
                              self.call('set_item', {'value': 'after'}))
        self.assertEqual([], seen)
        row = self.runtime.call(GRANT, self.call('set_item', {'value': 'after'}))
        self.assertEqual('REJECTED', self.decide(row['requestId'], 'reject')['state'])
        self.assertEqual([], self.calls)
        row = self.runtime.call(GRANT, self.call('set_item', {'value': 'after'}))
        self.core.policies[('actor', 'tickets', 'set_item', 'record')] = 'DENY'
        with self.assertRaises(Denied):
            self.decide(row['requestId'], 'approve')
        self.assertEqual('PENDING', self.core._read(row['requestId'])['state'])
        self.assertEqual([], self.calls)

    def test_authenticated_actor_preview_stales_on_changed_semantics(self):
        original = self.runtime.operations[('tickets', 'set_item')]
        self.runtime.operations[('tickets', 'set_item')] = replace(
            original, preview=lambda ctx: {'value': ctx.authenticated_actor})
        row = self.runtime.call(GRANT, self.call('set_item', {'value': 'after'}))
        self.assertEqual('PENDING', row['state'])
        self.runtime.operations[('tickets', 'set_item')] = replace(
            original, preview=lambda ctx: {'value': 'unexpected'})
        self.assertEqual('STALE', self.decide(row['requestId'], 'approve')['state'])
        self.assertEqual([], self.calls)

    def test_authenticated_actor_direct_apply_cannot_bypass_core_dispatch(self):
        body = self.call('set_item', {'value': 'after'})
        row = self.runtime.call(GRANT, body)
        self.assertEqual('PENDING', row['state'])
        with self.assertRaises(Denied):
            self.core.adapters['tickets'].apply({**body, 'expectedVersion': 0})
        self.assertEqual('PENDING', self.core._read(row['requestId'])['state'])
        self.assertEqual([], self.calls)

    def test_allow_write_executes_without_owner_and_keeps_request_id(self):
        self.core.policies[('actor', 'tickets', 'set_item', 'record')] = 'ALLOW'
        body = self.call('set_item', {'value': 'after'})
        row = self.runtime.call(GRANT, body)
        self.assertEqual(row['state'], 'EXECUTED')
        self.assertEqual(self.runtime.call(GRANT, body), row)
        self.assertEqual(self.calls, [('write', 'record')])

    def test_rotation_stales_pending_approval_without_effect(self):
        row = self.runtime.call(GRANT, self.call('set_item', {'value': 'after'}))
        self.vault.provision('tickets-test', TOKEN + '_ROTATED', expected_generation=self.provisioned['generation'])
        self.assertEqual(self.decide(row['requestId'], 'approve')['state'], 'STALE')
        self.assertEqual(self.calls, [])

    def test_lost_response_reconciles_readonly_and_never_replays_effect(self):
        self.lose_reply = True; body = self.call('set_item', {'value': 'after'})
        row = self.runtime.call(GRANT, body); self.assertEqual(self.decide(row['requestId'], 'approve')['state'], 'UNCERTAIN')
        self.assertEqual(self.runtime.call(GRANT, body)['state'], 'UNCERTAIN')
        self.assertEqual(self.runtime.result(GRANT, row['requestId'], reconcile=True)['state'], 'EXECUTED')
        self.assertEqual(self.calls, [('write', 'record')])

    def test_wrong_actor_scope_policy_and_parameters_deny_before_secret_or_upstream(self):
        for change in ({'target': 'foreign'}, {'operation': 'unknown'}, {'service': 'unknown'},
                       {'params': {'token': TOKEN}}, {'params': {'extra': 1}}, {'policy': 'ALLOW'}):
            with self.subTest(change=change), patch.object(self.vault, 'get', side_effect=AssertionError('SECRET_READ')):
                with self.assertRaises(Denied): self.runtime.call(GRANT, self.call(**change))
        with self.assertRaises(Denied): self.runtime.call('OFFLINE-SECOND-MACHINE-GRANT-0001', self.call())
        self.assertEqual(self.calls, [])

    def test_actor_owned_results_do_not_survive_revocation(self):
        row = self.runtime.call(GRANT, self.call())
        with self.assertRaises(Denied): self.runtime.result('OFFLINE-SECOND-MACHINE-GRANT-0001', row['requestId'])
        self.core.policies[('actor', 'tickets', 'read_item', 'record')] = 'DENY'
        with self.assertRaises(Denied): self.runtime.result(GRANT, row['requestId'])

    def test_catalog_is_actor_scoped_and_reports_readiness_without_values(self):
        data = self.runtime.catalog(GRANT)
        self.assertTrue(all(x['ready'] for x in data['operations']))
        self.assertNotIn(TOKEN, json.dumps(data)); self.assertNotIn('tickets-test', json.dumps(data))
        self.assertEqual(self.runtime.catalog('OFFLINE-SECOND-MACHINE-GRANT-0001')['operations'], [])
        (self.vault_root / 'tickets-test.json').unlink()
        self.assertTrue(all(not x['ready'] for x in self.runtime.catalog(GRANT)['operations']))
        with self.assertRaises(Denied): self.runtime.call(GRANT, self.call())

    def test_caller_cannot_get_owner_routes_or_override_identity(self):
        self.assertEqual(self.post('/v1/owner/decision/finish', {})[0], 404)
        self.assertEqual(self.post('/v1/integrations/call', {**self.call(), 'actor': 'owner'})[0], 403)
        self.assertEqual(self.post('/v1/integrations/call', self.call(), HTTP_COOKIE='fortis_owner=forged')[0], 403)
        self.assertEqual(self.post('/v1/integrations/catalog', {}, grant='UNKNOWN-MACHINE-GRANT')[0], 403)

    def test_pending_http_202_and_result_route(self):
        status, row = self.post('/v1/integrations/call', self.call('set_item', {'value': 'after'}))
        self.assertEqual((status, row['state']), (202, 'PENDING'))
        status, result = self.post('/v1/integrations/result', {'requestId': row['requestId']})
        self.assertEqual((status, result['state'], result['data']), (202, 'PENDING', None))
        self.assertEqual(self.post('/v1/integrations/result', {'requestId': row['requestId'], 'approve': True})[0], 403)

    def test_client_accepts_202_and_never_submits_approval(self):
        calls = []
        class Gateway:
            def post(self, path, body, **kwargs): calls.append((path, body, kwargs)); return {'state': 'PENDING'}
        client = IntegrationClient(gateway=Gateway()); ident = str(uuid.uuid4())
        client.call('tickets', 'set_item', 'record', {'value': 'after'}, reason='typed', request_id=ident)
        client.result(ident)
        self.assertTrue(all(x[2]['accept_202'] for x in calls))
        self.assertTrue(all('owner' not in x[0] for x in calls))

    def test_invalid_and_unrelated_configs_fail_without_loading_tokens(self):
        for change in ('unknown_provider', 'unknown_operation', 'unknown_actor', 'path_credential', 'extra_field', 'invalid_policy'):
            config = deepcopy(self.settings); settings = config['providers']['tickets']
            if change == 'unknown_provider': config['providers']['other'] = config['providers'].pop('tickets')
            elif change == 'unknown_operation': settings['operations']['unknown'] = settings['operations'].pop('read_item')
            elif change == 'unknown_actor': settings['operations']['read_item']['actors'] = ['unknown']
            elif change == 'path_credential': settings['credentials']['api'] = '../token'
            elif change == 'extra_field': settings['arbitraryUrl'] = 'https://evil.invalid'
            else: settings['operations']['read_item']['policy'] = 'allow'
            with self.subTest(change=change), self.assertRaises(Denied):
                ExtensionRuntime(ExtensionConfig(config), providers=(self.provider,), actors=('actor',), default_actor='actor', vault=self.vault)

    def test_disabled_scope_does_not_require_or_read_credentials(self):
        config = deepcopy(self.settings)
        config['providers']['tickets']['credentials'] = {}
        for rule in config['providers']['tickets']['operations'].values(): rule['policy'] = 'DENY'
        with patch.object(self.vault, 'get', side_effect=AssertionError('SECRET_READ')):
            runtime = ExtensionRuntime(ExtensionConfig(config), providers=(self.provider,), actors=('actor',), default_actor='actor', vault=self.vault)
            self.assertTrue(all(not row['ready'] for row in runtime.catalog_for('actor')['operations']))


class VaultTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(); self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name); self.vault = CredentialVault(self.root, uid=os.geteuid(), gid=os.getegid())
        self.vault.initialize()

    def test_atomic_create_rotation_and_generation_cas(self):
        first = self.vault.provision('service-api', TOKEN)
        self.assertNotIn(TOKEN, repr(self.vault.get('service-api')))
        with self.assertRaises(Denied): self.vault.provision('service-api', 'OTHER_TOKEN')
        second = self.vault.provision('service-api', 'ROTATED_OFFLINE_TOKEN', expected_generation=first['generation'])
        self.assertNotEqual(first['generation'], second['generation'])
        with self.assertRaises(Denied): self.vault.provision('service-api', TOKEN, expected_generation=first['generation'])
        self.assertEqual((self.root / 'service-api.json').stat().st_mode & 0o777, 0o600)

    def test_names_permissions_and_symlinks_are_rejected(self):
        for value in ('../token', '/tmp/key', 'UPPER', 'x.json', 'a/b'):
            with self.assertRaises(Denied): self.vault.get(value)
        self.vault.provision('service-api', TOKEN); path = self.root / 'service-api.json'; path.chmod(0o644)
        self.assertFalse(self.vault.readiness('service-api')['ready'])
        path.chmod(0o600); (self.root / 'alias.json').symlink_to(path)
        self.assertFalse(self.vault.readiness('alias')['ready'])

    def test_root_symlink_and_workspace_credential_roots_are_denied(self):
        link = self.root / 'linked'; link.symlink_to(self.root, target_is_directory=True)
        vault = CredentialVault(link, uid=os.geteuid(), gid=os.getegid())
        with self.assertRaises(Denied): vault.initialize()
        with self.assertRaises(Denied): CredentialVault('/workspace/repo/token')

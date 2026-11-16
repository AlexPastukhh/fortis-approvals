"""Closed v2 schemas, scope and dispatch using Mirror-produced P0 wire fixtures."""
import copy
import hashlib
import json
from pathlib import Path
import unittest
from types import SimpleNamespace

from fortis_approvals.core import Denied, canonical
from fortis_approvals.extensions.runtime import ExtensionConfig, ExtensionRuntime
from fortis_approvals.integrations.mirror.extension import PROVIDER
from fortis_approvals.integrations.mirror import read_v2 as v2

FIXTURES = json.loads(Path(__file__).with_name('read-v2-fixtures.json').read_text())
VALUES = {item['value']['operation']: item['value'] for item in FIXTURES[:8]}
PARAMS = {'offset': 0, 'limit': 32, 'inventoryRevision': None}


class Fake:
    def __init__(self, operation, response=None):
        self.target = 'mirror-pilot' if operation in ('list_repositories_v2', 'get_capabilities_v2') else 'fortis-approvals'
        self.params = ({'requestId': '2166d435-e811-41d3-a8c8-c7d807942c25'} if operation == 'get_windows_pull_result_v2' else
                       dict(PARAMS) if operation in ('list_repositories_v2', 'list_worktrees_v2', 'get_github_status_v2') else {})
        self.response = copy.deepcopy(VALUES[operation] if response is None else response)
        self.calls = []
        self.request_id, self.phase, self.generation = '0ec61e55-b834-47b7-8e6c-b8027553a4bf', 'execute', 'fixture-generation'
        self.operation = SimpleNamespace(name=operation)
        self.core_row = {'state': 'DISPATCHED', 'actor': 'repo:fixture', 'policyVersion': 'fixture-policy', 'request': {
            'requestId': self.request_id, 'service': 'mirror', 'operation': operation,
            'target': self.target, 'params': copy.deepcopy(self.params)}}
        self.runtime = SimpleNamespace(digest='f'*64, core=SimpleNamespace(_read=lambda _: self.core_row))

    def call(self, route, *, path, query):
        self.calls.append((route, path, query))
        return self.response


class MirrorV2Tests(unittest.TestCase):
    def test_all_mirror_fixtures_validate_and_dispatch_through_closed_get_routes(self):
        for operation in v2.READS:
            with self.subTest(operation=operation):
                ctx = Fake(operation)
                self.assertEqual(ctx.response, v2.execute(operation, ctx))
                route, path, query = ctx.calls[0]
                self.assertEqual(operation, route)
                if ctx.target == 'mirror-pilot':
                    self.assertEqual({}, path)
                    expected = hashlib.sha256(canonical(['fortis-approvals']).encode()).hexdigest()
                    self.assertEqual(expected, query['scope_digest'])
                else:
                    self.assertEqual(ctx.target, path['repo_id'])
                    if operation in v2.BOUND_READS:
                        self.assertEqual('repo:fixture', query['principal'])
                        self.assertNotIn('actor', ctx.params)
        for fixture in FIXTURES:
            value = fixture['value']
            v2.validate_result(value['operation'], value)

    def test_unconfigured_v2_remains_deny_and_no_write_or_lookup_is_registered(self):
        self.assertEqual({'get_repository'} | set(v2.READS), {op.name for op in PROVIDER.operations})
        for operation in PROVIDER.operations:
            self.assertEqual('read', operation.kind)
            self.assertEqual('link', operation.credential)
            if operation.name not in v2.BOUND_READS:
                self.assertIsNone(operation.lookup)
        self.assertTrue(set(v2.DEFERRED).isdisjoint(PROVIDER.api.routes))
        config = ExtensionConfig({'schemaVersion': 1, 'providers': {'mirror': {
            'credentials': {'link': 'mirror-link'}, 'operations': {'get_repository': {
                'policy': 'ALLOW', 'targets': ['fortis-approvals']}}}}})
        runtime = ExtensionRuntime(config, providers=(PROVIDER,), actors=['fixture'], default_actor='fixture')
        runtime.core = SimpleNamespace(auth=SimpleNamespace(authenticate=lambda _: 'fixture'))
        for operation in v2.READS:
            with self.subTest(operation=operation), self.assertRaisesRegex(Denied, 'INTEGRATION_GRANT_DENIED'):
                runtime._access('fixture-credential', 'mirror', operation, 'fortis-approvals')

    def test_public_params_cannot_supply_identity_scope_proof_or_transport(self):
        for operation in v2.READS:
            for field in ('actor', 'approved', 'proof', 'target', 'inventory', 'scope_digest', 'url', 'path', 'headers'):
                ctx = Fake(operation)
                ctx.params[field] = 'spoof'
                with self.subTest(operation=operation, field=field), self.assertRaises(Denied):
                    v2.execute(operation, ctx)
                self.assertEqual([], ctx.calls)
        for params in (dict(PARAMS, offset=True), dict(PARAMS, offset=1), dict(PARAMS, limit=101)):
            with self.assertRaises(Denied): v2.validate_params('get_github_status_v2', params)

    def test_unknown_inventory_and_traversal_do_not_make_upstream_call(self):
        for target in ('other-inventory', '../other', 'fortis-approvals'):
            ctx = Fake('list_repositories_v2'); ctx.target = target
            with self.subTest(target=target), self.assertRaises(Denied):
                v2.execute('list_repositories_v2', ctx)
            self.assertEqual([], ctx.calls)

    def test_target_schema_and_private_field_spoof_fail_closed(self):
        for mode in ('outer-target', 'inner-target', 'extra-field', 'bool-version', 'both-data-error', 'null-source-equal'):
            ctx = Fake('get_repository_v2')
            if mode == 'outer-target': ctx.response['target'] = 'other'
            elif mode == 'inner-target': ctx.response['data']['repoId'] = 'other'
            elif mode == 'extra-field': ctx.response['data']['windows']['origin'] = 'private'
            elif mode == 'bool-version': ctx.response['schemaVersion'] = True
            elif mode == 'both-data-error': ctx.response['error'] = {'code': 'TIMEOUT', 'retryable': False}
            else: ctx.response['data']['relation'] = 'equal'
            with self.subTest(mode=mode), self.assertRaises(Denied):
                v2.execute('get_repository_v2', ctx)

    def test_scope_and_page_cannot_expand_or_silently_shrink_pilot_inventory(self):
        for mode in ('unknown-member', 'missing-member', 'wrong-revision', 'duplicate-member', 'wrong-next', 'wrong-truncation'):
            ctx = Fake('list_repositories_v2'); data = ctx.response['data']
            if mode == 'unknown-member': data['items'] = ['other']
            elif mode == 'missing-member': data['items'] = []
            elif mode == 'wrong-revision': data['inventoryRevision'] = 'f' * 64
            elif mode == 'duplicate-member': data['items'] *= 2
            elif mode == 'wrong-next': data['nextOffset'] = 1
            else: data['truncated'] = True
            with self.subTest(mode=mode), self.assertRaises(Denied):
                v2.execute('list_repositories_v2', ctx)

    def test_required_ci_is_never_inferred_and_limits_are_not_broadened(self):
        ctx = Fake('get_github_status_v2')
        ctx.response['data']['requiredCI'] = 'VERIFIED'
        with self.assertRaises(Denied): v2.execute('get_github_status_v2', ctx)
        ctx = Fake('list_worktrees_v2')
        ctx.response['data']['items'] *= 100
        with self.assertRaises(Denied): v2.execute('list_worktrees_v2', ctx)
        ctx = Fake('get_capabilities_v2'); ctx.response['data'][0]['blockers'] = ['RAW_SECRET']
        with self.assertRaises(Denied): v2.execute('get_capabilities_v2', ctx)


    def test_principal_comes_from_persisted_core_identity_and_is_bound_to_request(self):
        for operation in v2.BOUND_READS:
            ctx = Fake(operation)
            ctx.actor = 'caller-spoof'
            v2.execute(operation, ctx)
            self.assertEqual('repo:fixture', ctx.calls[0][2]['principal'])
            original = v2.trusted_identity(ctx)[1]
            ctx.core_row['policyVersion'] = 'rotated-policy'
            self.assertNotEqual(original, v2.trusted_identity(ctx)[1])
            ctx.generation = 'rotated-credential'
            self.assertNotEqual(original, v2.trusted_identity(ctx)[1])
            for mode in ('phase', 'state', 'params', 'repo', 'operation', 'actor'):
                bad = Fake(operation)
                if mode == 'phase': bad.phase = 'preview'
                elif mode == 'state': bad.core_row['state'] = 'APPROVED'
                elif mode == 'params': bad.core_row['request']['params'] = {'actor': 'spoof'}
                elif mode == 'repo': bad.core_row['request']['target'] = 'other'
                elif mode == 'operation': bad.core_row['request']['operation'] = 'other'
                else: bad.core_row['actor'] = 'untrusted/actor'
                with self.subTest(operation=operation, mode=mode), self.assertRaises(Denied):
                    v2.execute(operation, bad)
                self.assertEqual([], bad.calls)

    def test_unknown_outcomes_and_missing_preview_evidence_cannot_be_success(self):
        ctx = Fake('get_windows_pull_result_v2')
        ctx.response['data'].update(workerState='NOT_FOUND', effect='NONE')
        with self.assertRaises(Denied): v2.execute('get_windows_pull_result_v2', ctx)
        ctx = Fake('preview_windows_pull_v2')
        ctx.response['data']['sourceEvidence']['windows']['verification'] = 'UNKNOWN'
        ctx.response['data']['sourceEvidence']['windows']['errorCode'] = 'SOURCE_UNAVAILABLE'
        with self.assertRaises(Denied): v2.execute('preview_windows_pull_v2', ctx)


if __name__ == '__main__':
    unittest.main()

"""Focused source-only GitHub PR description update security tests."""
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from fortis_approvals.core import Denied, Stale
from fortis_approvals.integrations.github.gateway.adapter import GitHubAdapter
from fortis_approvals.integrations.github.gateway.transport import GitHubHTTPTransport, GitHubTransportError
from fortis_approvals.workflow.adapters import NativeGitHubAdapter

SHA = 'a' * 40
OTHER_SHA = 'b' * 40
PR = '/repos/Alex/tunnel/pulls/7'


class PRTransport:
    def __init__(self):
        self.body = 'old body'
        self.head = SHA
        self.base = 'main'
        self.state = 'open'
        self.draft = False
        self.remote_head_repo = 'Alex/tunnel'
        self.remote_base_repo = 'Alex/tunnel'
        self.calls = []
        self.patch_count = 0
        self.get_count = 0
        self.on_get = None
        self.readback_stale = False

    def request(self, method, path, *, params=None, body=None,
                expected_statuses=(200,), allow_not_found=False):
        self.calls.append((method, path, body))
        if not GitHubHTTPTransport._route_allowed(method, path):
            raise Denied('GITHUB_HTTP_ROUTE_DENIED')
        if path != PR:
            raise AssertionError('unexpected route: ' + path)
        if method == 'PATCH':
            if set(body) != {'body'}:
                raise AssertionError('body-only PATCH required')
            self.patch_count += 1
            if not self.readback_stale:
                self.body = body['body']
        elif method == 'GET':
            self.get_count += 1
            if self.on_get is not None:
                self.on_get(self.get_count)
        else:
            raise AssertionError('unexpected method: ' + method)
        return {'number': 7, 'title': 'Original title', 'state': self.state,
                'body': self.body, 'draft': self.draft, 'merged': False,
                'head': {'ref': 'task/pr-metadata', 'sha': self.head,
                         'repo': {'full_name': self.remote_head_repo}},
                'base': {'ref': self.base, 'sha': OTHER_SHA,
                         'repo': {'full_name': self.remote_base_repo}},
                'html_url': 'https://github.com/Alex/tunnel/pull/7'}


class TaskRegistry:
    def __init__(self):
        self.found = True

    def task(self, actor, repo, task):
        if not self.found or (actor, repo, task) != ('agent', 'tunnel', 'pr-metadata'):
            raise Denied('WORKFLOW_TASK_NOT_REGISTERED')
        return {'branch': 'task/pr-metadata', 'task': 'pr-metadata', 'baseSha': OTHER_SHA}


class PRDescriptionTests(unittest.TestCase):
    def setUp(self):
        td = tempfile.TemporaryDirectory(prefix='fortis-pr-description-')
        self.addCleanup(td.cleanup)
        self.transport = PRTransport()
        self.adapter = GitHubAdapter(self.transport, owner='Alex', repositories=('tunnel',),
            receipt_store=str(Path(td.name) / 'receipts.sqlite'))
        self.params = dict(number=7, expectedHeadSha=SHA, body='replacement')
        self.request = dict(requestId='00000000-0000-4000-8000-000000000087',
                            operation='update_pull_request', service='github',
                            target='tunnel', params=self.params)
        self.native = NativeGitHubAdapter(self.transport,
            config=SimpleNamespace(owner='Alex', repository='tunnel', dynamic_repositories=False),
            root=Path(td.name), actor='agent', backend=None, store=TaskRegistry())

    def test_transport_is_closed_to_other_verbs_and_methods(self):
        self.assertTrue(GitHubHTTPTransport._route_allowed('PATCH', PR))
        for method, route in [('DELETE', PR), ('POST', PR), ('PATCH', PR + '/merge'),
                              ('PATCH', '/repos/Alex/tunnel/issues/7/comments')]:
            with self.subTest(method=method, route=route):
                self.assertFalse(GitHubHTTPTransport._route_allowed(method, route))

    def test_native_scope_requires_registered_open_same_repo_pr_exact_head(self):
        ok = self.native.prepare(self.request)
        self.assertEqual(ok['head']['sha'], SHA)
        for field, value in [('remote_head_repo', 'Other/repo'),
                             ('remote_base_repo', 'Other/repo'), ('base', 'feature'),
                             ('state', 'closed'), ('head', OTHER_SHA)]:
            with self.subTest(field=field):
                prior = getattr(self.transport, field)
                setattr(self.transport, field, value)
                with self.assertRaises((Denied, Stale)):
                    self.native.prepare(self.request)
                setattr(self.transport, field, prior)
        self.native.workflow.found = False
        with self.assertRaises(Denied):
            self.native.prepare(self.request)

    def test_prepare_rejects_changed_description_before_patch(self):
        def modify(count):
            if count == 2:
                self.transport.body = 'external owner edit'
        self.transport.on_get = modify
        with self.assertRaisesRegex(Stale, 'GITHUB_PR_CHANGED_BEFORE_UPDATE'):
            self.adapter.apply(self.request)
        self.assertEqual(self.transport.patch_count, 0)
        self.assertIsNone(self.adapter.receipt(self.request['requestId']))

    def test_patch_receipt_exact_readback_and_repeat(self):
        result = self.native.apply(self.request)
        self.assertEqual(self.transport.patch_count, 1)
        self.assertEqual(self.transport.body, 'replacement')
        self.assertEqual(result['number'], 7)
        self.assertEqual(result['headSha'], SHA)
        self.assertEqual(self.native.apply(self.request), result)
        self.assertEqual(self.transport.patch_count, 1)
        self.assertTrue(self.native.confirm(self.request['requestId'], result))

    def test_unknown_outcome_has_no_confirmed_receipt(self):
        self.transport.readback_stale = True
        with self.assertRaisesRegex(GitHubTransportError, 'GITHUB_PR_UPDATE_UNCONFIRMED'):
            self.native.apply(self.request)
        self.assertEqual(self.transport.patch_count, 1)
        self.assertIsNone(self.native.receipt(self.request['requestId']))
        # The Gateway Core/worker must never re-dispatch this UUID after
        # UNKNOWN; an absent receipt is NOT authorization to retry.

    def test_reject_unknown_metadata_mutations(self):
        for extras in ({'title': 'Injected'}, {'state': 'closed'}, {'draft': False},
                       {'base': 'other'}, {'head': 'other'}, {'mergeMethod': 'squash'},
                       {'url': 'https://evil.example'}):
            request = {**self.request, 'params': {**self.params, **extras}}
            with self.subTest(extras=extras), self.assertRaises(Denied):
                self.native.prepare(request)


if __name__ == '__main__':
    unittest.main()

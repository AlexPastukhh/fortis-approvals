"""Offline timeout and bounded diagnostic coverage for native Git publication."""
import json
from contextlib import nullcontext
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import uuid

from fortis_approvals.core import Authenticator, Core, Stale
from fortis_approvals.workflow.git_backend import (
    GitHubGitBackend, GitPushFailure, push_phase,
)


class FailingAdapter:
    def __init__(self, error):
        self.error = error

    def prepare(self, payload):
        return {'verified': True}

    def apply(self, payload):
        raise self.error

    def confirm(self, request_id, result):
        return False


class DiagnosticTests(unittest.TestCase):
    def _backend(self, root):
        return GitHubGitBackend(root / 'backend', owner='testowner', repositories={'repo'})

    def _core_result(self, exc, *, operation='push_commits'):
        with tempfile.TemporaryDirectory() as name:
            core = Core(Path(name) / 'requests.sqlite',
                        adapters={'github': FailingAdapter(exc)},
                        policies={('actor', 'github', operation): 'ALLOW'},
                        authenticator=Authenticator({'test-grant': 'actor'}))
            ident = str(uuid.uuid4())
            row = core.submit('actor', {
                'requestId': ident, 'service': 'github', 'operation': operation,
                'target': 'repo', 'params': {}, 'expectedVersion': 0,
                'reason': 'offline diagnostic regression test',
            })
            events = core.events(ident)
            return row, json.loads(events[-1]['detail'])

    def test_git_fetch_has_bounded_network_specific_timeout(self):
        with tempfile.TemporaryDirectory() as name:
            backend = self._backend(Path(name))
            with patch.object(backend.git, 'run', return_value=(0, b'')) as run:
                backend._fetch('repo', Path(name), 'main',
                               'refs/remotes/verify/main', Path(name) / 'config')
            self.assertEqual(run.call_args.kwargs['timeout'], 90)
            self.assertEqual(run.call_args.kwargs['protocols'] if 'protocols' in run.call_args.kwargs else 'https', 'https')

    def test_revalidation_timeout_identifies_phase(self):
        with tempfile.TemporaryDirectory() as name:
            backend = self._backend(Path(name))
            with patch.object(backend, 'validate', side_effect=RuntimeError('GIT_OUTCOME_TIMEOUT')):
                with self.assertRaises(GitPushFailure) as caught:
                    backend.push('repo', {}, None, '0'*40, b'fixture')
            self.assertEqual((caught.exception.phase, caught.exception.code),
                             ('revalidate', 'GIT_OUTCOME_TIMEOUT'))

    def _push_after_validation(self, *, fail_push=False, refs=None):
        with tempfile.TemporaryDirectory() as name:
            backend = self._backend(Path(name))
            root = Path(name)
            task = {'branch': 'task/example', 'baseSha': '1'*40}
            def fake_run(args, **kwargs):
                if args[0] == 'push' and fail_push:
                    raise RuntimeError('GIT_OUTCOME_TIMEOUT')
                return (0, b'')
            with patch.object(backend, 'validate', return_value={'ok': True}), \
                 patch.object(backend, 'credentials', return_value=nullcontext(root / 'dummy')), \
                 patch.object(backend, '_init', return_value=root), \
                 patch.object(backend, '_fetch', return_value=None), \
                 patch.object(backend.git, 'run', side_effect=fake_run), \
                 patch.object(backend, 'refs', return_value={} if refs is None else refs):
                with self.assertRaises(GitPushFailure) as caught:
                    backend.push('repo', task, None, '2'*40, b'fixture')
                return caught.exception.phase, caught.exception.code

    def test_push_timeout_identifies_remote_effect_phase(self):
        self.assertEqual(self._push_after_validation(fail_push=True),
                         ('push', 'GIT_OUTCOME_TIMEOUT'))

    def test_readback_mismatch_is_distinguished(self):
        self.assertEqual(self._push_after_validation(),
                         ('readback', 'GIT_PUSH_READBACK_UNCONFIRMED'))

    def test_push_audit_records_only_known_safe_identifiers(self):
        row, detail = self._core_result(GitPushFailure('push', 'GIT_OUTCOME_TIMEOUT'))
        self.assertEqual((row['state'], row['failure']),
                         ('UNCERTAIN', 'REMOTE_OUTCOME_UNCONFIRMED'))
        self.assertEqual(detail, {'gitPhase': 'push', 'gitCode': 'GIT_OUTCOME_TIMEOUT'})
        self.assertIsNone(row['result'])

    def test_arbitrary_exception_is_not_stored(self):
        row, detail = self._core_result(RuntimeError('PRIVATE-MARKER-DO-NOT-STORE'))
        self.assertEqual(row['state'], 'UNCERTAIN')
        self.assertEqual(detail, {})
        self.assertNotIn('PRIVATE-MARKER', json.dumps(row))

    def test_non_push_operation_does_not_get_git_audit(self):
        row, detail = self._core_result(GitPushFailure('push', 'GIT_OUTCOME_TIMEOUT'),
                                        operation='other_operation')
        self.assertEqual(row['state'], 'UNCERTAIN')
        self.assertEqual(detail, {})

    def test_stale_precondition_is_not_wrapped(self):
        with self.assertRaises(Stale) as caught:
            with push_phase('revalidate'):
                raise Stale('GIT_REMOTE_HEAD_CHANGED')
        self.assertEqual(str(caught.exception), 'GIT_REMOTE_HEAD_CHANGED')

    def test_unknown_git_error_is_redacted_to_fixed_code(self):
        with self.assertRaises(GitPushFailure) as caught:
            with push_phase('fetch_main'):
                raise RuntimeError('untrusted-secret-from-provider')
        self.assertEqual((caught.exception.phase, caught.exception.code),
                         ('fetch_main', 'GIT_PUSH_STEP_UNCONFIRMED'))
        self.assertNotIn('untrusted-secret', str(caught.exception))


if __name__ == '__main__':
    unittest.main()

"""Real temporary Git worktrees: bounded recovery never overwrites changed work."""
from pathlib import Path
import subprocess
import tempfile
import unittest

from fortis_approvals.core import Denied
from fortis_approvals.workflow.worker import Worker
from test_command_intents import Client, SHA


class WorkspaceIntentTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        folder = Path(self.tmp.name)
        self.root = folder / 'source'; self.root.mkdir()
        self.tasks = folder / 'tasks'; self.tasks.mkdir()
        self.git('init', '-q', '-b', 'main')
        self.git('config', 'user.name', 'Offline fixture')
        self.git('config', 'user.email', 'offline@example.invalid')
        self.git('remote', 'add', 'origin', 'https://github.com/owner/sandbox.git')
        (self.root / 'file').write_text('base')
        self.git('add', 'file'); self.git('commit', '-qm', 'base')
        self.base = self.git('rev-parse', 'HEAD')
        self.client = Client(folder / 'intents')
        self.client.worker = Worker(owner='owner', repositories={'sandbox': self.root},
            worktrees={'sandbox': self.tasks}, gateway=self.client.gateway)
        self.main = self.base; self.branch = None
        self.client.github.list_branches = lambda *a, **kw: {'items':
            [{'name': 'main', 'sha': self.main}] +
            ([{'name': 'task/agent', 'sha': self.branch}] if self.branch else [])}
        self.calls = []; self.outcomes = []

        def command(op, repo, params, *, request_id, reason, **kw):
            self.calls.append(request_id)
            outcome = self.outcomes.pop(0) if self.outcomes else 'success'
            if outcome == 'before': raise Denied('FORTIS_HTTP_500')
            self.client.rows[request_id] = {'state': 'EXECUTED', 'request': {
                'requestId': request_id, 'operation': op, 'target': repo, 'params': params}}
            if op == 'create_task':
                self.git('worktree', 'add', '-q', '-b', 'task/' + params['task'],
                         str(self.tasks / params['task']), params['baseSha'])
            else:
                self.git('merge', '--ff-only', params['expectedMergeSha'])
            if outcome == 'lost': raise TimeoutError('lost ACK after local effect')
            return {'requestId': request_id, 'state': 'EXECUTED'}
        self.client._command_once = command

    def git(self, *args):
        return subprocess.check_output(['git', '-C', str(self.root), *args],
            text=True, stderr=subprocess.DEVNULL).strip()

    def create(self):
        return self.client.intent.command('create_task', 'sandbox',
            dict(task='agent', baseSha=self.base, adoptHeadSha=None), reason='Create task')

    def test_create_task_failure_before_effect_retries_with_new_uuid(self):
        self.outcomes = ['before', 'success']
        result = self.create()
        self.assertEqual(result['status'], 'DONE')
        self.assertEqual(len(set(self.calls)), 2)
        self.assertTrue((self.tasks / 'agent').is_dir())
        self.assertEqual(self.git('branch', '--show-current'), 'main')

    def test_created_task_with_lost_reply_is_not_created_again(self):
        self.outcomes = ['lost']
        result = self.create()
        self.assertEqual(result['status'], 'DONE')
        self.assertEqual(len(self.calls), 1)
        self.assertEqual(self.create()['status'], 'DONE')
        self.assertEqual(len(self.calls), 1)

    def test_dirty_main_or_changed_remote_base_prevents_creation(self):
        (self.root / 'file').write_text('unsaved owner work')
        self.assertEqual(self.create()['status'], 'STOP')
        self.assertEqual(self.calls, [])
        (self.root / 'file').write_text('base'); self.main = 'c' * 40
        self.assertEqual(self.create()['status'], 'STOP')
        self.assertEqual(self.calls, [])

    def test_existing_unregistered_worktree_is_not_adopted_silently(self):
        self.git('worktree', 'add', '-q', '-b', 'task/agent',
                 str(self.tasks / 'agent'), self.base)
        self.assertEqual(self.create()['status'], 'STOP')
        self.assertEqual(self.calls, [])

    def test_main_ff_lost_reply_completes_without_another_update(self):
        self.git('checkout', '-qb', 'fixture')
        (self.root / 'file').write_text('merged')
        self.git('commit', '-qam', 'merged'); merged = self.git('rev-parse', 'HEAD')
        self.git('checkout', '-q', 'main'); self.main = merged
        self.client.github.get_pull_request = lambda *a: {'pullRequest': {
            'merged': True, 'head': {'sha': SHA}}}
        self.outcomes = ['before', 'lost']
        params = dict(expectedHeadSha=self.base, number=7,
                      expectedPrHeadSha=SHA, expectedMergeSha=merged)
        result = self.client.intent.command('update_main_from_pr', 'sandbox', params,
                                            reason='Update verified merged main')
        self.assertEqual(result['status'], 'DONE')
        self.assertEqual(len(set(self.calls)), 2)
        self.assertEqual(self.git('rev-parse', 'HEAD'), merged)

    def test_push_retries_keep_exact_old_sha_and_skip_completed_effect(self):
        self.git('worktree', 'add', '-q', '-b', 'task/agent', str(self.tasks / 'agent'), self.base)
        calls = []
        def publish(repo, task, old, new, *, request_id, reason):
            calls.append((request_id, old, new))
            if len(calls) == 1: raise Denied('FORTIS_HTTP_500')
            self.branch = new
            self.client.rows[request_id] = {'state': 'UNCERTAIN', 'request': {
                'requestId': request_id, 'operation': 'push_commits', 'target': repo,
                'params': dict(task=task, expectedHeadSha=old, newSha=new)}}
            raise TimeoutError('lost push reply')
        self.client._publish_once = publish
        result = self.client.intent.publish('sandbox', 'agent', None, self.base)
        self.assertEqual(result['status'], 'DONE')
        self.assertEqual(len(calls), 2)
        self.assertEqual(len({r[0] for r in calls}), 2)
        self.assertTrue(all(row[1] is None and row[2] == self.base for row in calls))
        self.assertEqual(self.client.intent.retry(result['intentId'])['status'], 'DONE')
        self.assertEqual(len(calls), 2)


if __name__ == '__main__': unittest.main()

"""Fault-injected intent tests: fresh attempt UUIDs and exact goal continuation."""
import copy
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest

from fortis_approvals.core import Denied
from fortis_approvals.clients.retries import RetryPolicy
from fortis_approvals.workflow.intents import IntentClient

SHA = 'b' * 40
OLD = 'a' * 40
IDENT = '11111111-1111-4111-8111-111111111111'


class GitHub:
    def __init__(self, parent):
        self.parent = parent
        self.head = SHA; self.prs = []; self.issues = {}
        self.outcomes = []; self.posts = []; self.issue_reads = 0

    def list_branches(self, repo, **kw):
        return {'items': [{'name': 'main', 'sha': OLD}, {'name': 'task/agent', 'sha': self.head}]}

    def list_pull_requests(self, repo, **kw): return {'items': copy.deepcopy(self.prs)}
    def get_pull_request(self, repo, number): return {'pullRequest': copy.deepcopy(self.prs[number - 1])}

    def _action_once(self, operation, repo, params, *, request_id, reason):
        self.posts.append(request_id)
        # The attempt ID must already be on disk before the first network call.
        saved = [self.parent.intent.journal.load(p.stem)
                 for p in self.parent.intent.journal.root.glob('*.json')]
        assert any(request_id in [a['requestId'] for a in r['attempts']] for r in saved)
        outcome = self.outcomes.pop(0) if self.outcomes else 'success'
        if outcome == 'before': raise Denied('FORTIS_HTTP_500')
        if outcome == 'denied': raise Denied('FORTIS_HTTP_403')
        row = {'requestId': request_id, 'target': repo, 'operation': operation,
               'params': copy.deepcopy(params)}
        self.parent.rows[request_id] = {'request': row, 'state': 'UNCERTAIN'}
        if outcome in ('success', 'lost'):
            self.prs.append(dict(number=len(self.prs) + 1, state='open', merged=False, draft=False,
                head={'ref': params['head'], 'sha': self.head}, base={'ref': 'main', 'sha': OLD},
                url='https://github.com/owner/sandbox/pull/1'))
        if outcome == 'pending':
            self.parent.rows[request_id]['state'] = 'PENDING'
            return {'requestId': request_id, 'state': 'PENDING'}
        if outcome == 'competing': self.head = 'c' * 40
        if outcome in ('lost', 'missing', 'competing', 'claimed'):
            if outcome == 'claimed': self.parent.workers[request_id] = 'CLAIMED'
            raise TimeoutError('untrusted message')
        self.parent.rows[request_id]['state'] = 'EXECUTED'
        return {'requestId': request_id, 'state': 'EXECUTED'}

    def prepare_visual_review(self, **kwargs): return {'payloadSha256': 'a' * 64}

    def find_visual_review_run(self, repo, run):
        self.issue_reads += 1
        issue = self.issues.get(run)
        return {'found': issue is not None, 'complete': True, 'issue': issue}

    def _publish_visual_review_once(self, *, publication_run_id, request_id, reason, **kwargs):
        self.posts.append(request_id)
        outcome = self.outcomes.pop(0) if self.outcomes else 'success'
        self.parent.rows[request_id] = {'state': 'UNCERTAIN', 'request': {
            'requestId': request_id, 'operation': 'publish_visual_review',
            'target': kwargs['repository'], 'params': {'runId': publication_run_id}}}
        if outcome == 'missing': raise TimeoutError('unknown effect')
        self.issues[publication_run_id] = {'title': kwargs['title'], 'number': len(self.issues) + 1}
        self.parent.rows[request_id]['state'] = 'EXECUTED'
        self.reads_at_success = self.issue_reads
        return {'requestId': request_id, 'state': 'EXECUTED'}


class Client:
    def __init__(self, root):
        self.rows = {}; self.workers = {}
        self.gateway = SimpleNamespace(endpoint='https://host.docker.internal:19204', post=lambda *a:
            {'globalRequestInventory': {'crossActorDetails': True}})
        self.github = GitHub(self)
        self.intent = IntentClient(self, root=root, retry_policy=RetryPolicy(sleep=lambda _: None))

    def result(self, ident, reconcile=False):
        row = self.rows.get(ident, {'state': 'NOT_FOUND'})
        return {'requestId': ident, 'state': row['state'], 'result': None}

    def details(self, ident):
        state = self.workers.get(ident)
        return {'request': copy.deepcopy(self.rows[ident]),
                'worker': {'state': state} if state else None}


class IntentTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.client = Client(Path(self.tmp.name) / 'journal')

    def pr(self, ident=None):
        return self.client.intent.github_action('create_pull_request', 'sandbox',
            dict(head='task/agent', base='main', title='review', body='body', draft=False),
            request_id=ident, reason='Review exact task')

    def test_transient_failures_get_fresh_uuids_then_complete(self):
        self.client.github.outcomes = ['before', 'missing', 'success']
        result = self.pr()
        self.assertEqual(result['status'], 'DONE')
        self.assertEqual(len(result['attemptIds']), 3)
        self.assertEqual(len(set(result['attemptIds'])), 3)
        self.assertEqual(result['attemptIds'], self.client.github.posts)
        self.assertNotIn(result['intentId'], result['attemptIds'])

    def test_lost_ack_existing_pr_skips_new_post_and_reentry(self):
        self.client.github.outcomes = ['lost']
        first = self.pr()
        second = self.pr()
        self.assertEqual(first['status'], 'DONE')
        self.assertEqual(first['intentId'], second['intentId'])
        self.assertEqual(second['status'], 'DONE')
        self.assertEqual(len(self.client.github.posts), 1)
        self.assertEqual(self.client.rows[first['requestId']]['state'], 'UNCERTAIN')

    def test_explicit_retry_after_exhaustion_creates_new_attempt_not_old_uuid(self):
        self.client.github.outcomes = ['before'] * 3
        result = self.pr(IDENT)
        self.assertEqual(result['status'], 'RETRY_EXHAUSTED')
        self.assertEqual(result['attemptIds'][0], IDENT)
        self.assertEqual(self.pr(IDENT)['status'], 'RETRY_EXHAUSTED')
        self.assertEqual(len(self.client.github.posts), 3)
        second = self.client.intent.retry(result['intentId'])
        self.assertEqual(second['status'], 'DONE')
        self.assertEqual(second['intentId'], IDENT)
        self.assertEqual(len(set(second['attemptIds'])), 4)
        self.assertNotEqual(second['requestId'], IDENT)

    def test_journal_survives_client_restart(self):
        self.client.github.outcomes = ['before'] * 3
        first = self.pr()
        self.client.intent = IntentClient(self.client,
            root=Path(self.tmp.name) / 'journal', retry_policy=RetryPolicy(sleep=lambda _: None))
        self.assertEqual(self.pr()['status'], 'RETRY_EXHAUSTED')
        self.assertEqual(self.client.intent.retry(first['intentId'])['status'], 'DONE')

    def test_manual_retry_waits_until_persisted_backoff_expires(self):
        now = [100]
        self.client.intent.policy = RetryPolicy(clock=lambda: now[0], sleep=lambda _: None, max_wait=1)
        original = self.client.github._action_once
        def delayed(*args, **kwargs):
            if not self.client.github.posts:
                self.client.github.posts.append(kwargs['request_id'])
                problem = Denied('FORTIS_HTTP_429'); problem.retry_after_seconds = 600
                raise problem
            return original(*args, **kwargs)
        self.client.github._action_once = delayed
        first = self.pr()
        self.assertEqual(first['status'], 'WAITING')
        self.assertEqual(len(self.client.github.posts), 1)
        self.assertEqual(self.client.intent.retry(first['intentId'])['status'], 'WAITING')
        self.assertEqual(len(self.client.github.posts), 1)
        now[0] = 701
        self.assertEqual(self.client.intent.retry(first['intentId'])['status'], 'DONE')
        self.assertEqual(len(self.client.github.posts), 2)

    def test_pending_and_active_worker_do_not_get_new_attempts(self):
        for outcome in ('pending', 'claimed'):
            with self.subTest(outcome=outcome):
                self.client = Client(Path(self.tmp.name) / outcome)
                self.client.github.outcomes = [outcome]
                first = self.pr()
                self.assertEqual(first['status'], 'WAITING')
                self.assertEqual(self.client.intent.retry(first['intentId'])['status'], 'WAITING')
                self.assertEqual(len(self.client.github.posts), 1)

    def test_changed_sha_does_not_rebind_retry_to_competing_head(self):
        self.client.github.outcomes = ['competing']
        self.assertEqual(self.pr()['status'], 'STOP')
        self.assertEqual(len(self.client.github.posts), 1)

    def test_denied_write_not_retried(self):
        self.client.github.outcomes = ['denied']
        result = self.pr()
        self.assertEqual(result['status'], 'STOP')
        self.assertEqual(len(self.client.github.posts), 1)
        self.assertEqual(self.client.intent.retry(result['intentId'])['status'], 'STOP')

    def test_parameters_immutable_under_stable_intent_id(self):
        self.pr(IDENT)
        with self.assertRaisesRegex(Denied, 'INTENT_PAYLOAD_CHANGED'):
            self.client.intent.github_action('create_pull_request', 'sandbox',
                dict(head='task/other', base='main', title='changed', body='body', draft=False),
                request_id=IDENT, reason='Review exact task')

    def test_incomplete_inventory_or_denied_read_stops_before_post(self):
        self.client.github.list_branches = lambda *a, **kw: {'items': [{'name': str(i), 'sha': SHA} for i in range(100)]}
        self.assertEqual(self.pr()['status'], 'STOP')
        self.assertEqual(self.client.github.posts, [])

    def test_issue_retries_accept_duplicates_new_run_ids_and_no_final_duplicate_scan(self):
        self.client.github.outcomes = ['missing', 'success']
        result = self.client.intent.publish_visual_review(repository='sandbox', run_id='original',
            title='review', description='description', media=[], qa_summary='QA',
            duration_seconds=12, reason='Publish visual review')
        self.assertEqual(result['status'], 'DONE')
        self.assertEqual(len(set(result['attemptIds'])), 2)
        self.assertEqual(len(set(result['runIds'])), 2)
        self.assertEqual(result['runIds'][0], 'original')
        self.assertTrue(result['manualDuplicateCheckRequired'])
        self.assertEqual(self.client.github.issue_reads, self.client.github.reads_at_success)

    def test_cross_actor_or_unavailable_result_does_not_authorize_write(self):
        self.client.github.outcomes = ['before']
        original = self.client.result
        def unavailable(ident, **kw): raise Denied('FORTIS_HTTP_403')
        self.client.result = unavailable
        self.assertEqual(self.pr()['status'], 'STOP')
        self.assertEqual(len(self.client.github.posts), 1)
        self.client.result = original

    def test_unrecognized_result_state_does_not_authorize_a_new_attempt(self):
        self.client.github.outcomes = ['before']
        self.client.result = lambda ident, **kw: {'requestId': ident, 'state': 'UNRECOGNIZED'}
        self.assertEqual(self.pr()['code'], 'INTENT_STATE_INVALID')
        self.assertEqual(len(self.client.github.posts), 1)

    def test_partial_visual_issue_is_not_mistaken_for_completed_publication(self):
        self.client.github.issues['original'] = {'title': 'review', 'number': 9,
                                                'body': 'only the initial Issue was created'}
        result = self.client.intent.publish_visual_review(repository='sandbox', run_id='original',
            title='review', description='description', media=[{'name': 'screen', 'path': '/unused'}],
            qa_summary='QA', duration_seconds=12, reason='Publish visual review')
        self.assertEqual(result['status'], 'STOP')
        self.assertEqual(result['code'], 'INTENT_ISSUE_PARTIAL_PUBLICATION')
        self.assertEqual(result['targetState']['issueNumber'], 9)
        self.assertEqual(self.client.github.posts, [])
        self.assertTrue(result['manualDuplicateCheckRequired'])

    def test_journal_symlink_and_endpoint_swap_rejected(self):
        result = self.pr()
        self.client.gateway.endpoint = 'https://other.example'
        with self.assertRaisesRegex(Denied, 'INTENT_ENDPOINT_CHANGED'):
            self.client.intent.retry(result['intentId'])
        self.client.gateway.endpoint = 'https://host.docker.internal:19204'
        path = self.client.intent.journal.root / (result['intentId'] + '.json')
        path.unlink(); path.symlink_to(Path(self.tmp.name) / 'elsewhere')
        with self.assertRaises(Denied): self.client.intent.retry(result['intentId'])


if __name__ == '__main__': unittest.main()

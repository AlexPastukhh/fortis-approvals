"""Intent coordinator through existing offline TLS/Core/real Git worker fixture."""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import test_native_workflow as native
from fortis_approvals.clients.retries import RetryPolicy
from fortis_approvals.core import Denied
from fortis_approvals.workflow.intents import IntentClient


class IntentNativeIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.case = native.NativeTLS('test_visual_issues_capabilities_are_policy_scoped')
        self.case.setUp(); self.addCleanup(self.case.doCleanups)
        tmp = tempfile.TemporaryDirectory(); self.addCleanup(tmp.cleanup)
        flow = self.case.flow
        flow.automatic_recovery = True
        flow.intents = IntentClient(flow, root=Path(tmp.name) / 'intents',
                                   retry_policy=RetryPolicy(sleep=lambda _: None))
        flow.github.intent_client = flow.intents

    def test_create_retries_fresh_uuid_through_real_admission_and_worker(self):
        original = self.case.gateway.post; submits = []
        def post(path, body, **kw):
            if path == '/v1/workspace/submit' and body['operation'] == 'create_task':
                submits.append(body['requestId'])
                if len(submits) == 1: raise Denied('FORTIS_HTTP_500')
            return original(path, body, **kw)
        with patch.object(self.case.gateway, 'post', side_effect=post):
            response = self.case.flow.command('create_task', 'sandbox',
                dict(task='real-cycle', baseSha=self.case.fixture.base, adoptHeadSha=None),
                reason='Create through bounded intent coordinator')
        self.assertEqual(response['status'], 'DONE', response)
        self.assertEqual(response['state'], 'EXECUTED')
        self.assertEqual(len(set(submits)), 2)
        self.assertEqual(self.case.flow.result(submits[0])['state'], 'NOT_FOUND')
        self.assertEqual(self.case.flow.result(submits[1])['state'], 'EXECUTED')
        self.assertTrue((self.case.fixture.worktrees / 'real-cycle').is_dir())

    def test_pr_lost_reply_reuses_target_and_preserves_one_provider_post(self):
        self.case.create()
        head = self.case.edit_commit()['headSha']
        pushed = self.case.flow.publish('sandbox', 'real-cycle', None, head,
                                       reason='Publish fixture for PR intent')
        self.assertEqual(pushed['status'], 'DONE', pushed)
        original = self.case.gateway.post; submits = []
        def post(path, body, **kw):
            reply = original(path, body, **kw)
            if path == '/v1/actions' and body['operation'] == 'create_pull_request':
                submits.append(body['requestId'])
                raise TimeoutError('synthetic lost ACK after durable execution')
            return reply
        with patch.object(self.case.gateway, 'post', side_effect=post):
            response = self.case.flow.github.create_pull_request('sandbox',
                'task/real-cycle', 'main', 'Review exact fixture', body='description',
                reason='Create PR through intent coordinator')
        self.assertEqual(response['status'], 'DONE', response)
        self.assertEqual(len(submits), 1)
        self.assertEqual(len(self.case.api.pulls), 1)
        self.assertEqual(self.case.flow.result(submits[0])['state'], 'EXECUTED')


if __name__ == '__main__': unittest.main()

"""Worker fault recovery: never infer a local effect, replay, or leak error text."""
import unittest
from unittest.mock import Mock, patch
import uuid
import test_native_workflow as native
from fortis_approvals.workflow.client import WorkflowClient


class WorkerExceptionTLS(unittest.TestCase):
    setUp = native.NativeTLS.setUp
    stop = native.NativeTLS.stop

    def test_exception_before_worker_journal_finishes_unknown_without_replay(self):
        app = self.machine.get_app()
        app.workspace.wait_seconds = 1
        ident = str(uuid.uuid4())
        with patch.object(self.worker, 'execute', side_effect=OSError('PRIVATE_WORKER_ERROR')) as execute:
            result = self.flow.command('inspect', 'sandbox', {'task': None},
                request_id=ident, reason='Offline fault before worker journal')
        self.assertEqual(result['state'], 'UNCERTAIN')
        execute.assert_called_once()
        job = app.store.job(ident)
        self.assertEqual(job['state'], 'FAILED')
        self.assertEqual(job['error'], 'UNCERTAIN')
        self.assertIsNone(self.flow.details(ident)['receipt'])
        with patch.object(self.worker, 'execute', side_effect=AssertionError('REPLAY_FORBIDDEN')):
            self.assertEqual(self.flow.resume(ident)['state'], 'UNCERTAIN')
        self.assertEqual(self.api.posts, 0)

    def test_exception_after_possible_effect_does_not_claim_not_executed(self):
        app = self.machine.get_app()
        app.workspace.wait_seconds = 1
        ident = str(uuid.uuid4())
        marker = self.fixture.root / 'possible-partial-effect'
        def unknown_worker_outcome(job):
            marker.write_text('effect may have occurred')
            raise RuntimeError('PRIVATE_AFTER_EFFECT')
        with patch.object(self.worker, 'execute', side_effect=unknown_worker_outcome) as execute:
            result = self.flow.command('inspect', 'sandbox', {'task': None},
                request_id=ident, reason='Offline possible worker effect before exception')
        self.assertEqual(result['state'], 'UNCERTAIN')
        self.assertEqual(app.store.job(ident)['state'], 'FAILED')
        self.assertEqual(app.store.job(ident)['error'], 'UNCERTAIN')
        self.assertEqual(marker.read_text(), 'effect may have occurred')
        execute.assert_called_once()
        self.assertIsNone(self.flow.details(ident)['receipt'])
        with patch.object(self.worker, 'execute', side_effect=AssertionError('REPLAY_FORBIDDEN')):
            self.assertEqual(self.flow.resume(ident)['state'], 'UNCERTAIN')
        self.assertEqual(marker.read_text(), 'effect may have occurred')

    def test_finish_ack_loss_has_durable_receipt_and_no_duplicate_execution(self):
        app = self.machine.get_app()
        app.workspace.wait_seconds = 1
        ident = str(uuid.uuid4())
        original = self.gateway.post
        def lost_ack(path, body, **kwargs):
            result = original(path, body, **kwargs)
            if path == '/v1/workspace/finish':
                raise OSError('FINISH_ACK_LOST')
            return result
        with patch.object(self.gateway, 'post', side_effect=lost_ack):
            with self.assertRaisesRegex(OSError, 'FINISH_ACK_LOST'):
                self.flow.command('inspect', 'sandbox', {'task': None},
                    request_id=ident, reason='Offline lost finish acknowledgement')
        self.assertEqual(app.store.job(ident)['state'], 'DONE')
        self.assertIsNotNone(self.flow.details(ident)['receipt'])
        with patch.object(self.worker, 'execute', side_effect=AssertionError('REPLAY_FORBIDDEN')):
            self.assertEqual(self.flow.result(ident, reconcile=True)['state'], 'EXECUTED')
        self.assertEqual(self.api.posts, 0)


class ResumeWorkerException(unittest.TestCase):
    def test_resume_finishes_unknown_on_worker_exception(self):
        ident = str(uuid.uuid4())
        class FakeGateway:
            finished = None
            def post(self, path, body, **kwargs):
                if path.endswith('/claim'):
                    return {'job': {'claim': 'offline-claim', 'payload': {'requestId': ident}}}
                if path.endswith('/finish'):
                    self.finished = body
                    return {'recorded': True}
                if path.endswith('/result') or path.endswith('/reconcile'):
                    return {'requestId': ident, 'state': 'UNCERTAIN' if self.finished else 'DISPATCHED',
                            'result': None, 'failure': 'REMOTE_OUTCOME_UNCONFIRMED' if self.finished else None}
                raise AssertionError(path)
        gateway = FakeGateway()
        worker = Mock()
        worker.execute.side_effect = RuntimeError('PRIVATE_WORKER_ERROR')
        flow = WorkflowClient(gateway=gateway, worker=worker)
        self.assertEqual(flow.resume(ident)['state'], 'UNCERTAIN')
        self.assertEqual(gateway.finished['result'], None)
        self.assertEqual(gateway.finished['error'], 'UNCERTAIN')
        worker.execute.assert_called_once()


if __name__ == '__main__':
    unittest.main()

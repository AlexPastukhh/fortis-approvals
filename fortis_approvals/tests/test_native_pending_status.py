"""Real TLS regression: pending workspace status is HTTP 202, without another effect."""
import unittest
import uuid
import test_native_workflow as native


class PendingStatusTLS(unittest.TestCase):
    setUp = native.NativeTLS.setUp
    stop = native.NativeTLS.stop

    def test_pending_status_and_reconcile_are_readable_without_dispatch(self):
        ingress = self.machine.get_app()
        self.core.policies[(ingress.actor, 'workspace', 'inspect')] = 'ASK'
        ident = str(uuid.uuid4())
        proposed = self.flow.command('inspect', 'sandbox', {'task': None},
            request_id=ident, reason='Pending status transport regression')
        self.assertEqual(proposed['state'], 'PENDING')
        for reconcile in (False, True):
            row = self.flow.result(ident, reconcile=reconcile)
            self.assertEqual(row['state'], 'PENDING')
            self.assertIsNone(row['result'])
        self.assertIsNone(ingress.store.job(ident))
        self.assertEqual(self.api.posts, 0)

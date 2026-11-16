"""P2: label intent recovery and independent READ never replay an effect."""
import copy
import tempfile
import unittest
from pathlib import Path

from fortis_approvals.core import Denied
from fortis_approvals.clients.retries import RetryPolicy
from fortis_approvals.integrations.github.release_label_contract import names_hash
from fortis_approvals.workflow.client import WorkflowClient
from fortis_approvals.workflow.intents import IntentClient
from fortis_approvals.integrations.github.release_label_evidence import release_label_receipt_matches
from test_command_intents import Client
from test_pr2_incident_inspector import FakeGateway, UUID

HEAD = 'a' * 40
BASE = 'b' * 40
BODY = 'c' * 64
BEFORE = ['human:keep', 'build:old']
ADD = 'build:api'
INTENT = '11111111-1111-4111-8111-111111111111'


def params(operation='add_pr_release_labels', before=None):
    values = dict(number=76, expectedHeadSha=HEAD, expectedBaseSha=BASE,
                  expectedBodySha256=BODY,
                  expectedLabelsSha256=names_hash(BEFORE if before is None else before))
    values.update(labels=[ADD] if operation == 'add_pr_release_labels' else None)
    if operation == 'remove_pr_release_label':
        values.pop('labels')
        values['name'] = 'build:old'
    return values


class LabelGitHub:
    def __init__(self, parent):
        self.parent = parent
        self.labels = list(BEFORE)
        self.posts = []
        self.outcomes = []
        self.overrides = {}
        self.drift = {}
        self.reads = 0

    def get_pr_release_label_context(self, repo, number):
        self.reads += 1
        value = dict(operation='get_pr_release_label_context', number=number,
                     headSha=HEAD, baseSha=BASE, bodySha256=BODY,
                     labels=sorted(self.labels), labelsSha256=names_hash(self.labels),
                     branch='task/one')
        return copy.deepcopy({**value, **self.overrides})

    def _action_once(self, operation, repo, values, *, request_id, reason):
        self.posts.append(request_id)
        saved = self.parent.intent.journal.load(INTENT)
        assert saved['intent']['params'] == values
        assert saved['attempts'][-1]['requestId'] == request_id
        outcome = self.outcomes.pop(0) if self.outcomes else 'executed'
        if outcome == 'pre-core':
            raise Denied('FORTIS_HTTP_503')
        row = dict(request=dict(requestId=request_id, service='github',
                                operation=operation, target=repo,
                                params=copy.deepcopy(values)), state='PENDING')
        self.parent.rows[request_id] = row
        if outcome == 'pending':
            return dict(requestId=request_id, state='PENDING')
        if outcome == 'denied':
            row['state'] = 'DENIED'
            return dict(requestId=request_id, state='DENIED')
        if outcome == 'unknown':
            row['state'] = 'UNCERTAIN'
            self.overrides.update(self.drift)
            raise TimeoutError('untrusted transport detail')
        before = set(self.labels)
        if operation == 'add_pr_release_labels':
            self.labels = sorted(before | set(values['labels']))
        else:
            self.labels = sorted(before - {values['name']})
        row['state'] = 'EXECUTED'
        row['result'] = dict(requestId=request_id, operation=operation,
                             repository=repo, number=values['number'], headSha=HEAD,
                             changed=set(self.labels) != before, labels=list(self.labels))
        if outcome == 'lost-executed':
            raise TimeoutError('ACK lost after durable execution')
        return dict(requestId=request_id, state='EXECUTED')


class LabelIntentRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.client = Client(Path(self.temp.name) / 'journal')
        self.client.github = LabelGitHub(self.client)

    def submit(self, operation='add_pr_release_labels', values=None):
        return self.client.intent.github_action(
            operation, 'test-repo', values or params(operation),
            request_id=INTENT, reason='Reviewed label recovery test')

    def restart(self):
        self.client.intent = IntentClient(
            self.client, root=Path(self.temp.name) / 'journal',
            retry_policy=RetryPolicy(sleep=lambda _: None))

    def test_add_and_remove_preserve_human_labels_and_exact_head(self):
        for operation in ('add_pr_release_labels', 'remove_pr_release_label'):
            with self.subTest(operation=operation):
                with tempfile.TemporaryDirectory() as folder:
                    self.client = Client(Path(folder) / 'journal')
                    self.client.github = LabelGitHub(self.client)
                    result = self.submit(operation)
                    self.assertEqual(result['status'], 'DONE', result)
                    self.assertEqual(result['effect'], dict(state='EXECUTED', requestId=INTENT))
                    self.assertIn('human:keep', result['targetState']['labels'])
                    self.assertEqual(self.client.rows[INTENT]['result']['headSha'], HEAD)
                    self.assertEqual(self.client.github.posts, [INTENT])

    def test_pending_reentry_and_restart_keep_one_ask(self):
        self.client.github.outcomes = ['pending']
        first = self.submit()
        self.restart()
        for response in (self.submit(), self.client.intent.retry(INTENT)):
            self.assertEqual(response['attemptIds'], [INTENT])
            self.assertEqual(response['nextAction']['kind'], 'WAIT_OWNER')
        self.assertEqual(first['intentId'], INTENT)
        self.assertEqual(self.client.github.posts, [INTENT])

    def test_lost_ack_recovers_original_receipt_without_second_write(self):
        self.client.github.outcomes = ['lost-executed']
        result = self.submit()
        self.restart()
        recovered = self.submit()
        for response in (result, recovered):
            self.assertEqual(response['status'], 'DONE', response)
            self.assertEqual(response['requestId'], INTENT)
            self.assertEqual(response['attemptIds'], [INTENT])
        self.assertEqual(self.client.github.posts, [INTENT])

    def test_executed_missing_result_remains_read_only_after_restart(self):
        original = self.client.result
        def missing(ident, **kwargs):
            value = original(ident, **kwargs)
            value['result'] = None
            return value
        self.client.result = missing
        first = self.submit()
        self.assertEqual(first['effect']['state'], 'EXECUTED')
        self.assertEqual(first['nextAction']['kind'], 'RETRY_READ')
        self.restart()
        self.assertEqual(self.submit()['nextAction']['kind'], 'RETRY_READ')
        self.client.result = original
        self.assertEqual(self.submit()['status'], 'DONE')
        self.assertEqual(self.client.github.posts, [INTENT])

    def test_safe_pre_core_continuation_keeps_first_id_and_new_attempt_id(self):
        self.client.github.outcomes = ['pre-core', 'pending']
        result = self.submit()
        self.assertEqual(result['intentId'], INTENT)
        self.assertEqual(result['attemptIds'][0], INTENT)
        self.assertEqual(len(set(result['attemptIds'])), 2)
        self.assertNotEqual(result['requestId'], INTENT)
        self.assertEqual(result['nextAction']['kind'], 'WAIT_OWNER')
        self.restart()
        self.assertEqual(self.submit()['attemptIds'], result['attemptIds'])
        self.assertEqual(self.client.github.posts, result['attemptIds'])

    def test_stale_fingerprints_stop_before_any_new_attempt(self):
        for key, value in [('headSha', 'd' * 40), ('baseSha', 'd' * 40),
                           ('bodySha256', 'd' * 64), ('labelsSha256', 'd' * 64)]:
            with self.subTest(field=key):
                with tempfile.TemporaryDirectory() as folder:
                    self.client = Client(Path(folder) / 'journal')
                    self.client.github = LabelGitHub(self.client)
                    self.client.github.outcomes = ['unknown']
                    self.client.github.drift = {key: value}
                    result = self.submit()
                    self.assertEqual(result['status'], 'STOP', result)
                    self.assertEqual(result['effect']['state'], 'UNCONFIRMED')
                    self.assertEqual(self.client.github.posts, [INTENT])

    def test_immutable_pending_parameters_cannot_be_rebound(self):
        self.client.github.outcomes = ['pending']
        self.submit()
        for key, value in [('expectedHeadSha', 'd' * 40),
                           ('expectedBaseSha', 'd' * 40),
                           ('expectedBodySha256', 'd' * 64),
                           ('expectedLabelsSha256', 'd' * 64),
                           ('labels', ['release:no-deployment'])]:
            with self.subTest(field=key):
                with self.assertRaisesRegex(Denied, 'INTENT_PAYLOAD_CHANGED'):
                    self.submit(values={**params(), key: value})
        self.assertEqual(self.client.github.posts, [INTENT])

    def test_denied_or_active_existing_request_never_gets_another_write(self):
        self.client.github.outcomes = ['pending']
        self.submit()
        for state, worker in [('PENDING', None), ('APPROVED', None),
                               ('DISPATCHED', None), ('UNCERTAIN', 'CLAIMED'),
                               ('DENIED', None), ('STALE', None)]:
            with self.subTest(state=state, worker=worker):
                self.client.rows[INTENT]['state'] = state
                self.client.workers[INTENT] = worker
                response = self.client.intent.retry(INTENT)
                self.assertIn(response['status'], ('WAITING', 'STOP'))
                self.assertEqual(self.client.github.posts, [INTENT])

    def test_erroneous_label_receipts_cannot_confirm_execution(self):
        cases = [dict(requestId='22222222-2222-4222-8222-222222222222'),
                 dict(operation='remove_pr_release_label'), dict(repository='other'),
                 dict(number=77), dict(headSha='d' * 40), dict(labels=BEFORE),
                 dict(labels=[ADD]), dict(labels=BEFORE + [ADD, ADD]),
                 dict(labels=BEFORE + [ADD, 'human:unexpected']),
                 dict(changed=False), dict(changed='true')]
        for patch in cases:
            with self.subTest(patch=patch):
                with tempfile.TemporaryDirectory() as folder:
                    self.client = Client(Path(folder) / 'journal')
                    self.client.github = LabelGitHub(self.client)
                    original = self.client.result
                    def invalid(ident, **kwargs):
                        response = original(ident, **kwargs)
                        if response.get('result'):
                            response['result'].update(patch)
                        return response
                    self.client.result = invalid
                    response = self.submit()
                    self.assertEqual(response['status'], 'STOP', response)
                    self.assertEqual(response['code'], 'INTENT_RECEIPT_BINDING_INVALID')
                    self.assertEqual(self.client.github.posts, [INTENT])


class LabelReceiptContractTests(unittest.TestCase):
    def test_full_delta_accepts_preexisting_adds_and_idempotent_removal(self):
        cases = [
            ('add_pr_release_labels', BEFORE, [ADD], sorted(BEFORE + [ADD]), True),
            ('add_pr_release_labels', BEFORE + [ADD], [ADD], sorted(BEFORE + [ADD]), False),
            ('add_pr_release_labels', BEFORE + [ADD], [ADD, 'build:second'],
             sorted(BEFORE + [ADD, 'build:second']), True),
            ('add_pr_release_labels', BEFORE + ['build:a', 'build:c'],
             ['build:a', 'build:b', 'build:c', 'build:d', 'build:e'],
             sorted(BEFORE + ['build:a', 'build:b', 'build:c', 'build:d', 'build:e']), True),
            ('remove_pr_release_label', BEFORE, None, ['human:keep'], True),
            ('remove_pr_release_label', ['human:keep'], None, ['human:keep'], False),
        ]
        for operation, before, selected, after, changed in cases:
            with self.subTest(operation=operation, before=before):
                values = params(operation, before)
                if selected is not None:
                    values['labels'] = selected
                receipt = dict(requestId=INTENT, operation=operation, repository='test-repo',
                               number=76, headSha=HEAD, labels=after, changed=changed)
                self.assertTrue(release_label_receipt_matches(
                    operation, 'test-repo', values, INTENT, receipt))
                receipt['changed'] = not changed
                self.assertFalse(release_label_receipt_matches(
                    operation, 'test-repo', values, INTENT, receipt))

    def test_remove_receipt_cannot_erase_another_label_or_clear_review_flag(self):
        values = params('remove_pr_release_label')
        receipt = dict(requestId=INTENT, operation='remove_pr_release_label',
                       repository='test-repo', number=76, headSha=HEAD,
                       labels=[], changed=True)
        self.assertFalse(release_label_receipt_matches(
            'remove_pr_release_label', 'test-repo', values, INTENT, receipt))
        values['name'] = 'release:review-required'
        self.assertFalse(release_label_receipt_matches(
            'remove_pr_release_label', 'test-repo', values, INTENT, receipt))


class LabelInspectorTests(unittest.TestCase):
    def flow(self, operation='add_pr_release_labels', state='EXECUTED'):
        values = params(operation)
        after = sorted(set(BEFORE) | {ADD}) if operation == 'add_pr_release_labels' else ['human:keep']
        receipt = dict(source='github-receipts', result=dict(
            requestId=UUID, operation=operation, repository='test-repo', number=76,
            headSha=HEAD, changed=True, labels=after)) if state == 'EXECUTED' else None
        gateway = FakeGateway(state=state, count=4, receipt=receipt)
        gateway.operation = operation
        gateway.params = values
        gateway.events = [dict(seq=n, state=s, detail={}, at=n)
                          for n, s in zip([8665, 8672, 8673, 8674],
                                          ['PENDING', 'APPROVED', 'DISPATCHED', 'EXECUTED'])]
        gateway.events[-1]['state'] = state
        if state == 'CANCELLED_BEFORE_DISPATCH':
            gateway.events = [dict(seq=1, state='PENDING', detail={}, at=1),
                              dict(seq=8, state=state, detail={}, at=8)]
        original_post = gateway.post
        gateway.post = lambda path, body: copy.deepcopy(original_post(path, body))
        client = WorkflowClient(gateway=gateway, worker=None)
        provider = LabelGitHub(None)
        provider.labels = after if state == 'EXECUTED' else list(BEFORE)
        client.github = provider
        return client, gateway, provider

    def inspect(self, client, gateway):
        report = client.incidents.inspect(UUID)
        self.assertEqual(report['retryAuthorization'], 'NONE')
        self.assertEqual({path for path, _ in gateway.calls},
                         {'/v1/workspace/capabilities', '/v1/workspace/details'})
        return report

    def test_bound_receipt_and_independent_complete_labels_confirm_applied(self):
        for operation in ('add_pr_release_labels', 'remove_pr_release_label'):
            with self.subTest(operation=operation):
                client, gateway, provider = self.flow(operation)
                report = self.inspect(client, gateway)
                self.assertEqual(report['assessment'], 'CONFIRMED_EXECUTED')
                self.assertEqual(report['releaseLabelReconciliation']['state'], 'CONFIRMED_APPLIED')
                self.assertTrue(report['provider']['receiptLabelsMatch'])
                self.assertEqual(provider.reads, 2)
                self.assertNotIn('human:keep', str(report))

    def test_proven_cancel_plus_unchanged_context_confirms_not_applied(self):
        client, gateway, _ = self.flow(state='CANCELLED_BEFORE_DISPATCH')
        report = self.inspect(client, gateway)
        self.assertEqual(report['releaseLabelReconciliation']['state'], 'CONFIRMED_NOT_APPLIED')

    def test_provider_target_alone_does_not_attribute_unknown_effect(self):
        client, gateway, provider = self.flow(state='UNCERTAIN')
        provider.labels = sorted(BEFORE + [ADD])
        report = self.inspect(client, gateway)
        self.assertEqual(report['releaseLabelReconciliation']['state'], 'UNKNOWN_STOP')
        self.assertEqual(report['effectAttribution'], 'NOT_PROVEN')
        self.assertEqual(report['outcomeAssessment'], 'TARGET_STATE_CONFIRMED_ATTRIBUTION_UNKNOWN')

    def test_stale_head_base_body_or_changed_full_labels_stop_projection(self):
        for key, value in [('headSha', 'd' * 40), ('baseSha', 'd' * 40),
                           ('bodySha256', 'd' * 64)]:
            with self.subTest(field=key):
                client, gateway, provider = self.flow()
                provider.overrides[key] = value
                report = self.inspect(client, gateway)
                self.assertEqual(report['assessment'], 'CONFIRMED_EXECUTED')
                self.assertEqual(report['releaseLabelReconciliation']['state'], 'UNKNOWN_STOP')
        client, gateway, provider = self.flow()
        provider.labels.remove('human:keep')
        self.assertEqual(self.inspect(client, gateway)['releaseLabelReconciliation']['state'], 'UNKNOWN_STOP')

    def test_read_disabled_or_unavailable_preserves_effect_without_confirming_projection(self):
        client, gateway, provider = self.flow()
        report = client.incidents.inspect(UUID, github_reads=False)
        self.assertEqual(report['assessment'], 'CONFIRMED_EXECUTED')
        self.assertEqual(report['releaseLabelReconciliation']['state'], 'UNKNOWN_STOP')
        self.assertEqual(provider.reads, 0)
        def denied(*args, **kwargs):
            raise Denied('GITHUB_RELEASE_PR_NOT_OPEN')
        provider.get_pr_release_label_context = denied
        report = self.inspect(client, gateway)
        self.assertEqual(report['assessment'], 'CONFIRMED_EXECUTED')
        self.assertEqual(report['releaseLabelReconciliation']['state'], 'UNKNOWN_STOP')

    def test_receipt_or_audit_drift_during_provider_reads_stops_projection(self):
        client, gateway, provider = self.flow()
        original = provider.get_pr_release_label_context
        def changed(*args, **kwargs):
            value = original(*args, **kwargs)
            if provider.reads == 2:
                gateway.receipt['result']['labels'].append('human:concurrent')
            return value
        provider.get_pr_release_label_context = changed
        report = self.inspect(client, gateway)
        self.assertEqual(report['releaseLabelReconciliation']['state'], 'UNKNOWN_STOP')
        self.assertIn('EVIDENCE_CHANGED_DURING_READ', report['missingEvidence'])


    def test_invalid_or_changed_context_cannot_confirm_projection(self):
        cases = [dict(labels=[ADD, ADD]), dict(labelsSha256='d' * 64),
                 dict(number=77), dict(headSha='not-a-sha'),
                 dict(labels=['human:' + str(i) for i in range(251)])]
        for patch in cases:
            with self.subTest(patch=patch):
                client, gateway, provider = self.flow()
                provider.overrides = patch
                report = self.inspect(client, gateway)
                self.assertEqual(report['assessment'], 'CONFIRMED_EXECUTED')
                self.assertEqual(report['releaseLabelReconciliation']['state'], 'UNKNOWN_STOP')
                self.assertIn('PROVIDER_READ_UNAVAILABLE', report['missingEvidence'])
        client, gateway, provider = self.flow()
        original = provider.get_pr_release_label_context
        def moving(*args, **kwargs):
            row = original(*args, **kwargs)
            if provider.reads == 2:
                row['bodySha256'] = 'd' * 64
            return row
        provider.get_pr_release_label_context = moving
        self.assertEqual(self.inspect(client, gateway)['releaseLabelReconciliation']['state'], 'UNKNOWN_STOP')

    def test_late_original_receipt_can_confirm_without_any_write_route(self):
        client, gateway, provider = self.flow(state='UNCERTAIN')
        provider.labels = sorted(BEFORE + [ADD])
        self.assertEqual(self.inspect(client, gateway)['releaseLabelReconciliation']['state'], 'UNKNOWN_STOP')
        gateway.state = 'EXECUTED'
        gateway.receipt = dict(source='github-receipts', result=dict(
            requestId=UUID, operation=gateway.operation, repository='test-repo', number=76,
            headSha=HEAD, changed=True, labels=sorted(BEFORE + [ADD])))
        gateway.events.append(dict(seq=9000, state='EXECUTED', detail={}, at=9000))
        report = self.inspect(client, gateway)
        self.assertEqual(report['releaseLabelReconciliation']['state'], 'CONFIRMED_APPLIED')
        self.assertEqual(report['releaseLabelReconciliation']['requestId'], UUID)

    def test_wrong_receipt_never_becomes_confirmed_even_if_provider_matches(self):
        for patch in [dict(number=77), dict(headSha='d' * 40), dict(labels=[ADD]),
                      dict(changed=False), dict(changed='true')]:
            with self.subTest(patch=patch):
                client, gateway, _ = self.flow()
                gateway.receipt['result'].update(patch)
                report = self.inspect(client, gateway)
                self.assertEqual(report['assessment'], 'UNCONFIRMED')
                self.assertEqual(report['releaseLabelReconciliation']['state'], 'UNKNOWN_STOP')
                self.assertIn('LABEL_RECEIPT_BINDING_INVALID', report['missingEvidence'])

    def test_unavailable_final_core_read_keeps_known_execution_but_not_projection(self):
        client, gateway, _ = self.flow()
        original = client.details
        calls = []
        def unavailable(ident, **kwargs):
            calls.append(kwargs)
            if len(calls) == 3:
                raise Denied('FORTIS_HTTP_503')
            return original(ident, **kwargs)
        client.details = unavailable
        report = self.inspect(client, gateway)
        self.assertEqual(report['assessment'], 'CONFIRMED_EXECUTED')
        self.assertEqual(report['releaseLabelReconciliation']['state'], 'UNKNOWN_STOP')
        self.assertIn('LABEL_CORE_RECHECK_UNAVAILABLE', report['missingEvidence'])

    def test_cancel_with_worker_or_receipt_is_not_a_nonexecution_proof(self):
        for evidence in ('worker', 'receipt'):
            with self.subTest(evidence=evidence):
                client, gateway, _ = self.flow(state='CANCELLED_BEFORE_DISPATCH')
                if evidence == 'worker':
                    gateway.worker = {'state': 'CLAIMED'}
                else:
                    gateway.receipt = {'source': 'github-receipts', 'result': {}}
                self.assertEqual(self.inspect(client, gateway)['releaseLabelReconciliation']['state'], 'UNKNOWN_STOP')


if __name__ == '__main__':
    unittest.main()

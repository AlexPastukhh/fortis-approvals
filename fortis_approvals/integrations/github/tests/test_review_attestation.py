"""Exercise actual Core ASK/decision/audit with test-only verifier."""
import sqlite3
import unittest
import uuid

from fortis_approvals.core import Authenticator, Core, Denied, Stale
from fortis_approvals.integrations.github.gateway.review_attestation import (
    ACTOR, SERVICE, OPERATION, ReviewAttestationAdapter, read_bound_owner_decision, review_policy,
)
from fortis_approvals.integrations.github.tests import test_review_capture as fixture

class TestVerifier:
    def verify(self, request_id, fingerprint, decision, proof):
        if proof != {'requestId': request_id, 'fingerprint': fingerprint, 'decision': decision}:
            raise Denied('TEST_PROOF_MISMATCH')
        return 'test-owner'


class AttestationTests(unittest.TestCase):
    def setUp(self):
        fixture.CaptureTests.setUp(self)
        capture = self.store.capture(self.adapter, **self.args)
        self.anchor = self.store.checkpoint()
        self.review_adapter = ReviewAttestationAdapter(
            store=self.store, provider=self.adapter, checkpoint_reader=lambda: self.anchor)
        self.core = self.make_core()
        self.payload = {'requestId': str(uuid.uuid4()), 'service': SERVICE,
                        'operation': OPERATION, 'target': fixture.REPO,
                        'reason': 'Review exact captured body',
                        'expectedVersion': self.anchor['revision'],
                        'params': {'captureOperationId': capture['operationId'],
                                   'captureEventDigest': capture['eventDigest'],
                                   'headSha': fixture.HEAD, 'bodySha256': fixture.DIGEST,
                                   'number':42, 'checkpointDigest': self.anchor['eventDigest']}}

    def make_core(self, policy=review_policy, suffix='main'):
        return Core(self.root / ('core-' + suffix + '.sqlite'),
                    adapters={SERVICE: self.review_adapter},
                    policies={(SERVICE, OPERATION): policy},
                    authenticator=Authenticator({'fixture-credential': ACTOR}),
                    owner_verifier=TestVerifier())

    def submit(self):
        return self.core.client('fixture-credential', 'submit', self.payload)

    def decide(self, row, decision='approve'):
        return self.core.owner_decide(row['requestId'], decision,
            {'requestId':row['requestId'], 'fingerprint':row['fingerprint'], 'decision':decision})

    def bound(self, owner='test-owner'):
        return read_bound_owner_decision(self.core, self.payload['requestId'], owner=owner)

    def test_exact_ask_review_survives_post_merge_body_edit(self):
        row = self.submit()
        self.assertEqual(row['state'], 'PENDING')
        self.assertNotIn(fixture.BODY, repr(row))
        self.assertEqual(self.decide(row)['state'], 'EXECUTED')
        count = len(self.provider.calls)
        self.provider.pr.update(state='closed', merged=True, body='edited after merge')
        decision = self.bound()
        self.assertEqual(decision['result'], 'OWNER_CAPTURE_DECISION_BOUND')
        self.assertEqual(decision['bodySha256'], fixture.DIGEST)
        self.assertTrue(decision['ownerDecisionBound'])
        for flag in ('historicalMergeCutoffVerified','evidenceVerified','admissionAllowed','deploymentAllowed'):
            self.assertIs(decision[flag], False)
        self.assertEqual(len(self.provider.calls), count)
        self.assertEqual(self.store.checkpoint(), self.anchor)

    def test_pending_not_attestation(self):
        self.submit()
        with self.assertRaises(Denied): self.bound()

    def test_rejected_not_attestation(self):
        self.assertEqual(self.decide(self.submit(), 'reject')['state'], 'REJECTED')
        with self.assertRaises(Denied): self.bound()

    def test_allow_without_owner_not_attestation(self):
        self.core = self.make_core('ALLOW', 'allow')
        self.assertEqual(self.submit()['state'], 'EXECUTED')
        with self.assertRaises(Denied): self.bound()

    def test_actor_and_repo_scope(self):
        self.assertEqual(review_policy('other', self.payload), 'DENY')
        self.payload['target'] = 'fortis-container'
        with self.assertRaises(Denied): self.submit()

    def test_wrong_capture_fields(self):
        for field in ('bodySha256','captureEventDigest'):
            value=self.payload['params'][field]
            self.payload['params'][field]='f'*64
            with self.subTest(field=field), self.assertRaises(Denied): self.submit()
            self.payload['params'][field]=value

    def test_forged_checkpoint(self):
        self.payload['params']['checkpointDigest']='e'*64
        with self.assertRaises(Stale): self.submit()

    def test_body_drift_after_pending(self):
        row=self.submit(); self.provider.pr['body']+='changed'
        self.assertEqual(self.decide(row)['state'],'STALE')
        with self.assertRaises(Denied): self.bound()

    def test_merge_before_decision(self):
        row=self.submit(); self.provider.pr.update(state='closed',merged=True)
        self.assertEqual(self.decide(row)['state'],'STALE')
        with self.assertRaises(Denied): self.bound()

    def test_anchor_drift_after_pending(self):
        row=self.submit();self.anchor={'revision':2,'eventDigest':'a'*64}
        self.assertEqual(self.decide(row)['state'],'STALE')
        with self.assertRaises(Denied): self.bound()

    def test_wrong_owner_and_proof(self):
        row=self.submit()
        with self.assertRaises(Denied):
            self.core.owner_decide(row['requestId'],'approve',{'fingerprint':'bad'})
        self.decide(row)
        with self.assertRaises(Denied): self.bound('other-owner')

    def test_audit_tamper_denied(self):
        self.decide(self.submit())
        with sqlite3.connect(self.core.path) as db:
            db.execute("UPDATE events SET detail='{}' WHERE state='APPROVED'")
        with self.assertRaises(Denied): self.bound()

    def test_no_synthetic_receipt(self):
        self.assertIsNone(self.review_adapter.receipt(self.payload['requestId']))
        self.assertFalse(self.review_adapter.confirm(self.payload['requestId'],{}))

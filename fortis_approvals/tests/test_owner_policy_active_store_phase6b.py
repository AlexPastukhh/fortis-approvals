"""Phase 6B unconnected active-store-candidate protected PREPARED barrier tests."""
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor
import hashlib
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
import uuid

from fortis_approvals.core import Denied, Stale
from fortis_approvals.extensions.owner_policy_authority_phase6 import ExactPolicyBaseline
from fortis_approvals.extensions.owner_policy_active_store_phase6b import (
    ProtectedActivePolicyStoreCandidate as Candidate)

COORD = ('repo-ai','github','create_pull_request','fortis-approvals')
PWSH = ('repo-ai','powershell','execute','windows-owner')
SOURCE = hashlib.sha256(b'trusted-installed-source').hexdigest()
CRED = hashlib.sha256(b'trusted-generation-not-secret').hexdigest()
GENESIS = '0'*64


def _process_prepare(path, request_id):
    baseline=ExactPolicyBaseline(core_policies={COORD:'ASK',PWSH:'ASK'},
                                 loaded_services={'github','powershell'})
    candidate=Candidate(path,baseline=baseline,source_digest=SOURCE,
                        credential_generation_digest=CRED,policy_version='test-v1')
    change=dict(actor=COORD[0],provider=COORD[1],operation=COORD[2],
                target=COORD[3],expectedPolicy='ASK',desiredPolicy='DENY')
    try:
        candidate.prepare_change(change,request_id=request_id,expected_revision=0,
            expected_audit_hash=GENESIS,expected_source_digest=SOURCE,
            expected_credential_generation_digest=CRED,
            expected_policy_version='test-v1',reason_code='OWNER_PREPARE')
        return 'PREPARED'
    except Stale:
        return 'STOP'


class ProtectedPhase6BTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name)/'active.sqlite'
        self.baseline = ExactPolicyBaseline(
            core_policies={COORD:'ASK',PWSH:'ASK'},
            loaded_services={'github','powershell'})
        self.kw = dict(baseline=self.baseline,source_digest=SOURCE,
                       credential_generation_digest=CRED,policy_version='test-v1')
        self.store = Candidate(self.path,**self.kw)

    def pins(self, **overrides):
        p = dict(request_id=str(uuid.uuid4()),expected_revision=0,
                 expected_audit_hash=GENESIS,expected_source_digest=SOURCE,
                 expected_credential_generation_digest=CRED,
                 expected_policy_version='test-v1',reason_code='OWNER_PREPARE')
        p.update(overrides)
        return p

    def change(self,**overrides):
        c = dict(actor=COORD[0],provider=COORD[1],operation=COORD[2],
                 target=COORD[3],expectedPolicy='ASK',desiredPolicy='DENY')
        c.update(overrides)
        return c

    def test_initial_state_is_private_inert_baseline(self):
        state = self.store.snapshot()
        self.assertEqual('READY',state['gate'])
        self.assertEqual(0,state['revision'])
        self.assertEqual(GENESIS,state['auditHeadHash'])
        self.assertFalse(state['canApply'])
        self.assertEqual('NOT_CONNECTED',state['runtimeIntegration'])
        self.assertFalse(state['externalAnchorVerified'])
        self.assertEqual(0,self.path.stat().st_mode & 0o077)
        self.assertFalse(hasattr(self.store,'activate'))
        self.assertFalse(hasattr(self.store,'commit'))
        self.assertFalse(hasattr(self.store,'apply'))
        with sqlite3.connect(self.path) as db:
            self.assertEqual([('ASK',),('ASK',)],
                db.execute('SELECT policy FROM active_rules ORDER BY coordinate').fetchall())

    def test_prepared_is_durable_readback_and_is_not_active_grant(self):
        request = str(uuid.uuid4())
        first = self.store.prepare_change(self.change(),**self.pins(request_id=request))
        self.assertTrue(first['prepared'])
        self.assertFalse(first['alreadyPrepared'])
        self.assertFalse(first['canApply'])
        snap = self.store.snapshot()
        self.assertEqual('PREPARED',snap['gate'])
        self.assertEqual(request,snap['pendingRequestId'])
        self.assertEqual(first['prepareHash'],snap['auditHeadHash'])
        self.assertEqual(1,snap['auditSequence'])
        self.assertEqual(0,snap['revision'])
        self.assertEqual(snap,Candidate(self.path,**self.kw).snapshot())
        with sqlite3.connect(self.path) as db:
            self.assertEqual(0,db.execute("SELECT COUNT(*) FROM active_rules WHERE policy='DENY'").fetchone()[0])

    def test_same_request_retries_readback_not_second_prepare(self):
        p=self.pins()
        first=self.store.prepare_change(self.change(),**p)
        again=self.store.prepare_change(self.change(),**p)
        self.assertTrue(again['alreadyPrepared'])
        self.assertEqual(first['prepareHash'],again['prepareHash'])
        self.assertEqual(1,self.store.snapshot()['auditSequence'])
        with self.assertRaisesRegex(Stale,'PHASE6B_PREPARED_BARRIER_BLOCKS'):
            self.store.prepare_change(self.change(),**self.pins())
        with self.assertRaisesRegex(Stale,'PHASE6B_PREPARED_BARRIER_BLOCKS'):
            self.store.prepare_change(self.change(desiredPolicy='ALLOW'),**p)

    def test_two_connections_have_one_atomic_prepared_winner(self):
        inputs=[self.pins(),self.pins()]
        def attempt(p):
            try:
                s=Candidate(self.path,**self.kw)
                s.prepare_change(self.change(),**p)
                return 'PREPARED'
            except Stale:
                return 'STOP'
        with ThreadPoolExecutor(max_workers=2) as pool:
            result=list(pool.map(attempt,inputs))
        self.assertEqual(['PREPARED','STOP'],sorted(result))
        self.assertEqual(1,self.store.snapshot()['auditSequence'])
        self.assertEqual('PREPARED',self.store.snapshot()['gate'])

    def test_two_processes_cannot_both_prepare(self):
        inputs=[str(uuid.uuid4()),str(uuid.uuid4())]
        with ProcessPoolExecutor(max_workers=2) as pool:
            outcomes=list(pool.map(_process_prepare,[str(self.path)]*2,inputs))
        self.assertEqual(['PREPARED','STOP'],sorted(outcomes))
        self.assertEqual(1,self.store.snapshot()['auditSequence'])

    def test_reopen_same_request_after_lost_ack_only_reads_prepared(self):
        pins=self.pins()
        initial=self.store.prepare_change(self.change(),**pins)
        after_restart=Candidate(self.path,**self.kw)
        replay=after_restart.prepare_change(self.change(),**pins)
        self.assertTrue(replay['alreadyPrepared'])
        self.assertEqual(initial['prepareHash'],replay['prepareHash'])
        self.assertFalse(replay['canApply'])

    def test_wrong_identity_stale_pins_and_unsafe_commands_denied(self):
        for changed in (self.change(actor='other'),self.change(target='wrong'),
                        self.change(provider='missing'),self.change(desiredPolicy='ASK'),
                        self.change(desiredPolicy='EXECUTE'),self.change(extra='bad')):
            with self.subTest(change=changed),self.assertRaises(Denied):
                self.store.prepare_change(changed,**self.pins())
        for pins in (self.pins(expected_revision=1),
                     self.pins(expected_audit_hash='f'*64),
                     self.pins(expected_source_digest='f'*64),
                     self.pins(expected_credential_generation_digest='f'*64),
                     self.pins(expected_policy_version='test-v2')):
            with self.subTest(pins=pins),self.assertRaises(Stale):
                self.store.prepare_change(self.change(),**pins)
        with self.assertRaisesRegex(Denied,'PHASE6_POWERSHELL_V2_GATE_REQUIRED'):
            self.store.prepare_change(dict(actor=PWSH[0],provider=PWSH[1],
                operation=PWSH[2],target=PWSH[3],expectedPolicy='ASK',
                desiredPolicy='ALLOW'),**self.pins())
        self.assertEqual('READY',self.store.snapshot()['gate'])

    def test_uuid_reason_and_baseline_reopen_mismatch_rejected(self):
        for pins in (self.pins(request_id='not-uuid'),self.pins(reason_code='bad-reason'),
                     self.pins(expected_revision=True)):
            with self.assertRaises((Denied,Stale)):
                self.store.prepare_change(self.change(),**pins)
        for kw in (dict(source_digest='f'*64),
                   dict(credential_generation_digest='f'*64),
                   dict(policy_version='different'),
                   dict(baseline=ExactPolicyBaseline(
                       core_policies={COORD:'ALLOW',PWSH:'ASK'},loaded_services={'github','powershell'}))):
            with self.subTest(kw=kw),self.assertRaises(Denied):
                Candidate(self.path,**{**self.kw,**kw})

    def test_tamper_event_hash_pending_or_policy_stops_readback_and_reopen(self):
        for query in ("UPDATE active_events SET event_hash=? WHERE seq=1",
                      "UPDATE active_pending SET event_hash=? WHERE id=1",
                      "UPDATE active_rules SET policy=? WHERE coordinate=(SELECT coordinate FROM active_rules LIMIT 1)",
                      "UPDATE active_meta SET audit_hash=? WHERE id=1"):
            # Use a fresh file per subtest to isolate each corruption.
            with self.subTest(query=query),tempfile.TemporaryDirectory() as d:
                path=Path(d)/'protected.sqlite'
                s=Candidate(path,**self.kw)
                s.prepare_change(self.change(),**self.pins())
                with sqlite3.connect(path) as db:
                    db.execute(query,('z'*64 if 'event_hash' in query or 'audit_hash' in query else 'DENY',))
                with self.assertRaises(Denied):
                    s.snapshot()
                with self.assertRaises(Denied):
                    Candidate(path,**self.kw)

    def test_path_owner_mode_and_hardlink_fail_closed(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            path=root/'db.sqlite'
            os.chmod(root,0o755)
            with self.assertRaisesRegex(Denied,'PHASE6B_PROTECTED_PARENT_PERMISSIONS'):
                Candidate(path,**self.kw)
            os.chmod(root,0o700)
            store=Candidate(path,**self.kw)
            self.assertEqual('READY',store.snapshot()['gate'])
            other=root/'hardlink.sqlite'
            os.link(path,other)
            with self.assertRaisesRegex(Denied,'PHASE6B_PROTECTED_STORE_PERMISSIONS'):
                store.snapshot()
            os.unlink(other)
            os.chmod(path,0o644)
            with self.assertRaises(Denied):
                store.snapshot()
            os.chmod(path,0o600)
            other.symlink_to(path)
            with self.assertRaises(Denied):
                Candidate(other,**self.kw)

    def test_locked_prepared_gate_never_reset_on_restart(self):
        self.store.prepare_change(self.change(),**self.pins())
        for _ in range(3):
            store=Candidate(self.path,**self.kw)
            self.assertEqual('PREPARED',store.snapshot()['gate'])
            with self.assertRaises(Stale):
                store.prepare_change(self.change(),**self.pins())


if __name__=='__main__':
    unittest.main()

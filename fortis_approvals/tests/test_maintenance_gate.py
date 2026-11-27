"""Isolated controller contract and real local Registry hold synchronization."""
import copy
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
import multiprocessing
from unittest.mock import patch
import unittest
from concurrent.futures import ThreadPoolExecutor
from threading import Event

from fortis_approvals.core import Denied
from fortis_approvals.extensions.maintenance_gate import MaintenanceGate, Coordinate
from fortis_approvals.extensions.maintenance_transport import MaintenanceRegistryTransport
from fortis_approvals.integrations.registry_contracts import maintenance_contract as mc
from fortis_approvals.integrations.registry_contracts import semantic_contract as sc
from fortis_approvals.tests import test_registry_release_domain as fixture
from fortis_approvals.tests.test_registry_state_journal import uid

OLD='a'*64
NEW='b'*64
MUTATE=Coordinate('github','merge_pull_request')
OTHER=Coordinate('sonarcloud','accept_issue')


class Controller:
    """Test-only in-memory controller; not a host writer or real GO."""
    def __init__(self,instance,scope,generation=OLD):
        self.record={'schemaVersion':1,'registryInstanceId':instance,'scopeDigest':scope,
                     'sequence':0,'previousDigest':None,'phase':'NORMAL','generation':generation,
                     'attempt':None,'proofDigest':None}
        self.pin=sc.digest(self.record)
        self.available=True

    def read(self):
        if not self.available:
            raise OSError('fixture offline')
        return copy.deepcopy(self.record),self.pin

    def advance(self,phase,*,attempt=None,generation=None):
        next_record={**self.record,'sequence':self.record['sequence']+1,
                     'previousDigest':sc.digest(self.record),'phase':phase,'proofDigest':'c'*64,
                     'attempt':self.record['attempt'] if attempt is None else attempt,
                     'generation':self.record['generation'] if generation is None else generation}
        self.record=mc.validate_transition(self.record,next_record)
        self.pin=sc.digest(self.record)


class GateTests(unittest.TestCase):
    append=fixture.DomainTests.append
    clone=fixture.DomainTests.clone
    component=fixture.DomainTests.component
    params=fixture.DomainTests.params
    report=fixture.DomainTests.report
    rebind=fixture.DomainTests.rebind

    def setUp(self):
        fixture.DomainTests.setUp(self)
        self.profile['subjects'][0]['maintenance']=fixture.maintenance(True,True)
        self.rebind()
        self.ctrl=Controller(self.store.instance_id,self.witness['scopeDigest'])
        self.gate=self.make_gate()
        self.transport=self.make_transport(self.gate)

    def make_gate(self,generation=OLD):
        return MaintenanceGate(instance_id=self.store.instance_id,scope_digest=self.witness['scopeDigest'],
                generation=generation,read_interlock=self.ctrl.read,read_holds=self.domain.maintenance_snapshot)

    def make_transport(self,gate):
        return MaintenanceRegistryTransport(self.service,gate,preflight=lambda a,op,p:a=='agent-1')

    def attempt(self):
        h=self.domain.maintenance_snapshot()['holds'][0]
        return {k:h[k] for k in ('attemptId','subject','source','restrictionDigest')} | {
            'sourceGeneration':OLD,'targetGeneration':NEW}

    def start(self):
        ident=uid()
        result=self.transport.owner_write('agent-1','begin_release',self.params(),
              operation_id=ident,assertion_source='OWNER_TRANSCRIBED')
        self.assertEqual(result['operationId'],ident)
        self.ctrl.advance('DRAINING',attempt=self.attempt())
        return ident

    def advance_to_completion(self):
        for phase in ('FROZEN_BEFORE_CHECK','CHECK_SEALED','APPLY_STOP'):
            self.ctrl.advance(phase)
        self.ctrl.advance('STAGED_TARGET_FROZEN',generation=NEW)
        for phase in ('BACKUP_FROZEN','PROMOTE_FROZEN','COMPLETION_PENDING'):
            self.ctrl.advance(phase)

    def deny(self,gate=None,code='RELEASE_MAINTENANCE',coordinate=MUTATE):
        with self.assertRaisesRegex(Denied,code):
            with (gate or self.gate).reserve(coordinate):
                self.fail('unexpected mutable admission')

    def test_protected_directory_detects_reservations_from_another_process(self):
        from fortis_approvals.extensions.maintenance_interlock_reader import InterlockReservations

        root=self.domain.store.path.parent/'interlock'
        root.mkdir(mode=0o555)
        ctx=multiprocessing.get_context('fork')
        ready,release=ctx.Event(),ctx.Event()
        lock=InterlockReservations(Path(root))

        def hold():
            with lock.reserve():
                ready.set()
                if not release.wait(10):
                    raise RuntimeError('fixture timeout')

        # Unprivileged source test exercises real Linux flock on one inode.
        # Mount ownership checks belong to an independently provisioned host.
        with patch('fortis_approvals.extensions.maintenance_interlock_reader._check_owner_readonly_mount'), \
             patch('fortis_approvals.extensions.maintenance_interlock_reader.os.fstat',
                   side_effect=lambda fd: type('Directory',(),{
                       'st_uid':0,'st_mode':root.stat().st_mode,
                       'st_dev':root.stat().st_dev,'st_ino':root.stat().st_ino})()):
            process=ctx.Process(target=hold)
            process.start()
            try:
                self.assertTrue(ready.wait(5))
                self.start()
                self.gate._shared=lock
                self.assertFalse(self.gate.drain_status()['ready'])
                self.deny()
            finally:
                release.set()
                process.join(5)
                if process.is_alive():
                    process.terminate()
                    process.join(5)
            self.assertEqual(process.exitcode,0)
            self.assertTrue(self.gate.drain_status()['ready'])

    def test_existing_reservation_drains_no_new_effect_and_own_begin_settles(self):
        with self.gate.reserve(MUTATE) as token:
            self.start()
            self.deny()
            self.assertFalse(self.gate.drain_status()['ready'])
            with self.assertRaisesRegex(Denied,'RELEASE_MAINTENANCE'):
                with self.gate.effect(token):
                    self.fail('new effect after fence')
        self.assertTrue(self.gate.drain_status()['ready'])
        self.assertEqual(self.gate.drain_status()['reservations'],0)

    def test_inflight_effect_can_settle_but_not_start_again(self):
        ready,release=Event(),Event()
        def effect():
            with self.gate.reserve(MUTATE) as token:
                with self.gate.effect(token):
                    ready.set()
                    if not release.wait(5):
                        raise RuntimeError('fixture timeout')
                with self.assertRaises(Denied):
                    with self.gate.effect(token):pass
        with ThreadPoolExecutor(max_workers=1) as pool:
            future=pool.submit(effect)
            try:
                self.assertTrue(ready.wait(5))
                self.start()
                self.assertFalse(self.gate.drain_status()['ready'])
                self.deny()
            finally:
                release.set()
            future.result(timeout=5)
        self.assertTrue(self.gate.drain_status()['ready'])

    def test_global_begin_blocks_before_controller_drain_and_ordinary_report(self):
        ident=uid()
        self.transport.owner_write('agent-1','begin_release',self.params(),operation_id=ident,
                                   assertion_source='OWNER_TRANSCRIBED')
        self.deny()
        self.assertFalse(self.gate.drain_status()['ready'])
        with self.assertRaises(Denied):
            self.transport.owner_write('agent-1','report_release_result',self.report(attemptId=ident),
                operation_id=uid(),assertion_source='OWNER_TRANSCRIBED')
        self.assertEqual(self.domain.snapshot()['snapshotRevision'],1)

    def test_generation_handover_and_two_stage_completion(self):
        ident=self.start()
        self.advance_to_completion()
        self.deny(code='MAINTENANCE_STATE_UNKNOWN')
        candidate=self.make_gate(NEW)
        self.deny(candidate)
        self.verify=True
        operation=uid()
        def close():
            return self.domain.protected_event('RELEASE_HOLD_CLOSED',
                {**self.params(),'attemptId':ident,'controllerReceiptDigest':'d'*64,
                 'readbackDigest':'e'*64,'observedAt':100},actor='controller',
                 operation_id=operation,recorded_at=101)
        with self.assertRaisesRegex(Denied,'COMPLETION_DENIED'):
            candidate.completion(expected_attempt=ident,expected_operation=operation,
                                 verify=lambda *_:False,write=close)
        result=candidate.completion(expected_attempt=ident,expected_operation=operation,
                                    verify=lambda *_:True,write=close)
        self.assertEqual(result['operationId'],operation)
        self.assertIsNone(self.component()['activeAttempt'])
        # Crash between Registry close and controller release remains closed.
        self.deny(self.make_gate(NEW))
        self.ctrl.advance('NORMAL')
        with self.make_gate(NEW).reserve(MUTATE):pass
        self.deny(code='MAINTENANCE_STATE_UNKNOWN')

    def test_frozen_startup_checks_target_return_and_exact_live_hold(self):
        from fortis_approvals.extensions.maintenance_interlock_reader import InterlockReservations

        self.gate.verify_startup()
        ident=self.start()
        with self.assertRaisesRegex(Denied,'MAINTENANCE_STARTUP_HANDOFF_REQUIRED'):
            self.gate.verify_startup()
        for phase in ('FROZEN_BEFORE_CHECK','CHECK_SEALED','APPLY_STOP'):
            self.ctrl.advance(phase)
        self.ctrl.advance('STAGED_TARGET_FROZEN',generation=NEW)
        root=self.domain.store.path.parent/'startup-interlock'
        root.mkdir(mode=0o555)
        lock=InterlockReservations(root)

        def handoff(role):
            return {'role':role,'attemptId':ident,
                    'restrictionDigest':self.ctrl.record['attempt']['restrictionDigest'],
                    'interlockDigest':self.ctrl.pin,
                    'registryDigest':sc.digest(self.domain.maintenance_snapshot())}

        target=self.make_gate(NEW)
        next_start=handoff('staged_target')
        with self.assertRaisesRegex(Denied,'MAINTENANCE_RESERVATION_REQUIRED'):
            target.verify_startup(next_start)
        target._shared=self.gate._shared=lock
        info=root.stat()
        with patch('fortis_approvals.extensions.maintenance_interlock_reader._check_owner_readonly_mount'), \
             patch('fortis_approvals.extensions.maintenance_interlock_reader.os.fstat',
                   return_value=SimpleNamespace(st_uid=0,st_mode=info.st_mode,
                                                st_dev=info.st_dev,st_ino=info.st_ino)):
            target.verify_startup(next_start)
            self.deny(target)
            with self.assertRaisesRegex(Denied,'MAINTENANCE_STARTUP_HANDOFF_CHANGED'):
                target.verify_startup({**next_start,'role':'return_source'})
            with self.assertRaisesRegex(Denied,'MAINTENANCE_STARTUP_HOLD_CHANGED'):
                target.verify_startup({**next_start,'registryDigest':'f'*64})
            with self.assertRaisesRegex(Denied,'MAINTENANCE_STARTUP_HANDOFF_CHANGED'):
                target.verify_startup({**next_start,'interlockDigest':'e'*64})
            stale=self.make_gate(NEW)
            stale._shared=lock
            missing={**self.domain.maintenance_snapshot(),'holds':[]}
            stale._holds=lambda:missing
            with self.assertRaisesRegex(Denied,'MAINTENANCE_STARTUP_HOLD_CHANGED'):
                stale.verify_startup({**next_start,'registryDigest':sc.digest(missing)})
            self.ctrl.advance('RECOVERY_HOLD',generation=OLD)
            restored=self.make_gate()
            restored._shared=lock
            restored.verify_startup(handoff('return_source'))
            self.deny(restored)
            with self.assertRaisesRegex(Denied,'MAINTENANCE_STARTUP_HANDOFF_CHANGED'):
                restored.verify_startup(handoff('staged_target'))
            with self.assertRaisesRegex(Denied,'MAINTENANCE_STATE_UNKNOWN'):
                target.verify_startup(next_start)

    def test_controller_normal_with_still_open_hold_is_not_permission(self):
        self.start()
        self.advance_to_completion()
        self.ctrl.advance('NORMAL')
        self.deny(self.make_gate(NEW),code='MAINTENANCE_STATE_UNKNOWN')

    def test_recovery_hold_cannot_clear_directly(self):
        self.start()
        self.ctrl.advance('RECOVERY_HOLD')
        self.deny()
        with self.assertRaises(Denied):
            self.ctrl.advance('NORMAL')
        self.assertIsNotNone(self.component()['activeAttempt'])

    def test_missing_and_stale_interlock_or_registry_fail_closed(self):
        with self.gate.reserve(MUTATE):pass
        old,pin=self.ctrl.read()
        self.start()
        self.gate.drain_status()
        self.ctrl.record,self.ctrl.pin=old,pin
        self.deny(code='MAINTENANCE_STATE_UNKNOWN')
        self.ctrl.available=False
        self.deny(code='MAINTENANCE_STATE_UNKNOWN')
        self.assertFalse(self.gate.drain_status()['ready'])

    def test_unknown_begin_ack_latches_and_preserves_receipt(self):
        ident=uid()
        with self.gate.reserve(Coordinate('registry','begin_release')) as token:
            def lost():
                self.service.owner_write('agent-1','begin_release',self.params(),operation_id=ident,
                                          assertion_source='OWNER_TRANSCRIBED')
                return {'result':'UNKNOWN_OUTCOME','operationId':ident}
            with self.assertRaisesRegex(Denied,'MAINTENANCE_STATE_UNKNOWN'):
                self.gate.register_hold(token,lost,operation_ids=(ident,))
        self.deny(code='MAINTENANCE_STATE_UNKNOWN')
        self.assertEqual(self.component()['activeAttempt']['attemptId'],ident)
        self.assertIsNotNone(self.store.release_operation(ident))

    def test_scoped_union_and_unaffected_operation(self):
        for p,coord in zip(self.profile['subjects'],(MUTATE,OTHER)):
            p['maintenance']=fixture.maintenance(True)
            p['maintenance']['blockedOperations']=[{'service':coord.service,'operation':coord.operation}]
        self.rebind()
        self.gate=self.make_gate()
        self.transport=self.make_transport(self.gate)
        ids=[uid(),uid()]
        result=self.transport.begin_group('agent-1',{'items':[self.params(0),self.params(1)]},
            operation_ids=ids,parent_id=uid(),assertion_source='OWNER_TRANSCRIBED')
        self.assertEqual([r['operationId'] for r in result],ids)
        self.deny(coordinate=MUTATE)
        self.deny(coordinate=OTHER)
        self.deny(coordinate=None)
        with self.gate.reserve(Coordinate('github','get_branch')):pass

    def test_explicit_scope_preflight_precedes_maintenance(self):
        self.start()
        with self.assertRaisesRegex(Denied,'POLICY_DENIED'):
            self.transport.owner_write('other','begin_release',self.params(1),
                   operation_id=uid(),assertion_source='OWNER_TRANSCRIBED')

    def test_wrong_restriction_digest_never_drain_ready(self):
        ident=uid()
        self.transport.owner_write('agent-1','begin_release',self.params(),operation_id=ident,
                                   assertion_source='OWNER_TRANSCRIBED')
        self.ctrl.advance('DRAINING',attempt={**self.attempt(),'restrictionDigest':'f'*64})
        self.assertFalse(self.gate.drain_status()['ready'])
        self.deny()


if __name__=='__main__':
    unittest.main()

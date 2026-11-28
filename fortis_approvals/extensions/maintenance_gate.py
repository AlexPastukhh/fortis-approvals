"""Opt-in local admission/drain gate, separate from configured policies.

No controller writes, no automatic unlock, no network/host operations.
All callers must use the same gate before mutable admission and at actual
effect boundaries. Production cross-generation synchronization and
protected latest-record pin provisioning remain independent requirements.
"""
from contextlib import contextmanager, nullcontext
from dataclasses import dataclass
from threading import RLock
import uuid

from ..core import Denied
from ..integrations.registry_contracts import semantic_contract as sc
from ..integrations.registry_contracts.maintenance_contract import (
    bind_record, bind_startup_handoff, validate_transition, paired_subjects, paired_operation_id, matching_holds,
    latest_startup, hold_snapshot, maintenance_coordinate,
)


@dataclass(frozen=True)
class Coordinate:
    service: str
    operation: str

    def __post_init__(self):
        maintenance_coordinate(self.service,self.operation)


@dataclass(frozen=True)
class Reservation:
    ident: str
    coordinate: Coordinate | None


class MaintenanceGate:
    def __init__(self, *, instance_id, scope_digest, generation, read_interlock,
                 read_holds, shared_reservations=None, read_latest=None):
        sc.uuid_id(instance_id)
        sc.hex_id(scope_digest,64)
        sc.hex_id(generation,64)
        sc.need(callable(read_interlock) and callable(read_holds)
                and (read_latest is None or callable(read_latest)))
        self.instance_id,self.scope_digest,self.generation=instance_id,scope_digest,generation
        self._interlock,self._holds=read_interlock,read_holds
        from .maintenance_interlock_reader import InterlockReservations
        sc.need(shared_reservations is None or type(shared_reservations) is InterlockReservations,
                'MAINTENANCE_RESERVATION_REQUIRED')
        self._shared=shared_reservations
        self._latest=read_latest
        self._lock=RLock()
        self._active={}
        self._last_interlock=None
        self._last_holds=None
        self._local_uncertain=False

    def _snapshot(self):
        try:
            record,pin=self._interlock()
            record=bind_record(record,instance_id=self.instance_id,scope_digest=self.scope_digest,
                               generation=self.generation,expected_digest=pin)
            holds=hold_snapshot(self._holds())
            sc.need(holds['instanceId']==self.instance_id and holds['scopeDigest']==self.scope_digest)
            again, again_pin=self._interlock()
            sc.need(again_pin==pin and bind_record(again,instance_id=self.instance_id,
                scope_digest=self.scope_digest,generation=self.generation,
                expected_digest=again_pin)==record)

            if self._last_interlock is not None:
                previous=self._last_interlock
                seq=previous['sequence']
                sc.need(record['sequence']>=seq and
                        (record['sequence']!=seq or record==previous))
                if record['sequence']==seq+1:
                    validate_transition(previous,record)
            if self._last_holds is not None:
                rev,old=self._last_holds
                sc.need(holds['snapshotRevision']>=rev and
                        (holds['snapshotRevision']!=rev or sc.digest(holds)==old))
            self._last_interlock=record
            self._last_holds=(holds['snapshotRevision'],sc.digest(holds))
            # NORMAL may coexist with ordinary scoped holds, never a global
            # freeze that has no controller interlock yet. Both block.
            return record,holds
        except Exception:
            raise Denied('MAINTENANCE_STATE_UNKNOWN') from None

    def verify_startup(self,handoff=None,*,release_active=None):
        """Read-only admission before serving a reviewed runtime."""
        frozen=handoff is not None or self._latest is not None
        if frozen:
            sc.need(self._shared is not None,'MAINTENANCE_RESERVATION_REQUIRED')
        shared=self._shared.reserve() if frozen else nullcontext()
        with shared,self._lock:
            sc.need(not self._local_uncertain,'MAINTENANCE_STATE_UNKNOWN')
            record,holds=self._snapshot()
            if self._latest is not None:
                current,projection=self._latest()
                sc.need(current==record,'MAINTENANCE_STATE_UNKNOWN')
                latest_startup(record,projection,holds)
                phase=record['phase']
                if phase=='STAGED_TARGET_FROZEN':
                    sc.need(handoff is not None,'MAINTENANCE_STARTUP_HANDOFF_REQUIRED')
                    bind_startup_handoff(handoff,record)
                    sc.need(handoff['registryDigest']==projection['registryDigest'],
                            'MAINTENANCE_STARTUP_HOLD_CHANGED')
                else:
                    # The pre-construction read can validate phase first;
                    # install rechecks the actual root-owned activation marker.
                    sc.need(release_active is not False,'MAINTENANCE_STARTUP_HANDOFF_REQUIRED')
                    if phase in ('BACKUP_FROZEN','PROMOTE_FROZEN','COMPLETION_PENDING') or (
                            phase=='RECOVERY_HOLD' and record['generation']==record['attempt']['targetGeneration']):
                        sc.need(handoff is not None and record['attempt']['attemptId']==handoff['attemptId']
                                and record['attempt']['restrictionDigest']==handoff['restrictionDigest'],
                                'MAINTENANCE_STARTUP_HANDOFF_CHANGED')
                # The controller's read-only delivery preflight must bind
                # its PROFILE replay to this exact verified phase/hold view.
                return record,holds,projection
            if handoff is None:
                sc.need(record['phase']=='NORMAL' and not any(h['stateFreeze'] for h in holds['holds']),
                        'MAINTENANCE_STARTUP_HANDOFF_REQUIRED')
                return
            current=bind_startup_handoff(handoff,record)
            attempt=current['attempt']
            sc.need(sc.digest(holds)==handoff['registryDigest'] and matching_holds(holds['holds'],attempt),
                    'MAINTENANCE_STARTUP_HOLD_CHANGED')

    def verify_running_source_delivery(self):
        """Read-only inspection of an already running, draining source.

        Not startup admission: a process restart in these phases must still
        fail verify_startup. The owner controller checks the live identity.
        """
        from ..integrations.registry_contracts.maintenance_contract import bind_latest_projection
        sc.need(self._latest is not None and self._shared is not None,
                'MAINTENANCE_RESERVATION_REQUIRED')
        with self._shared.reserve(),self._lock:
            sc.need(not self._local_uncertain,'MAINTENANCE_STATE_UNKNOWN')
            record,holds=self._snapshot()
            current,projection=self._latest()
            sc.need(current==record,'MAINTENANCE_STATE_UNKNOWN')
            bind_latest_projection(projection,record)
            sc.need(record['phase'] in ('DRAINING','FROZEN_BEFORE_CHECK','CHECK_SEALED','APPLY_STOP')
                    and sc.digest(holds)==projection['registryDigest']
                    and matching_holds(holds['holds'],record['attempt']),
                    'MAINTENANCE_STARTUP_HOLD_CHANGED')
            return record,holds,projection

    def _decision(self,coordinate):
        if self._local_uncertain:
            raise Denied('MAINTENANCE_STATE_UNKNOWN')
        record,holds=self._snapshot()
        if record['phase']!='NORMAL':
            raise Denied('RELEASE_MAINTENANCE')
        if record['attempt'] is not None and any(
                h['attemptId']==record['attempt']['attemptId'] for h in holds['holds']):
            raise Denied('MAINTENANCE_STATE_UNKNOWN')
        for h in holds['holds']:
            if h['stateFreeze'] or (coordinate is None and h['blockedOperations']) or (
                    coordinate is not None and
                    any(coordinate==Coordinate(**op) for op in h['blockedOperations'])):
                raise Denied('RELEASE_MAINTENANCE')

    def passive_read(self,coordinate):
        """Only reviewed passive operations; not a new policy grant."""
        from ..integrations.registry_contracts.semantic_contract import READ_METHODS
        sc.need(type(coordinate) is Coordinate and (
            (coordinate.service=='registry' and coordinate.operation in READ_METHODS)
            or (coordinate.service,coordinate.operation)==('github','list_branches')))
        with self._lock:
            if self._local_uncertain:
                raise Denied('MAINTENANCE_STATE_UNKNOWN')
            _,holds=self._snapshot()
            if any(coordinate==Coordinate(**op) for h in holds['holds'] for op in h['blockedOperations']):
                raise Denied('RELEASE_MAINTENANCE')

    @contextmanager
    def reserve(self,coordinate=None):
        """Reserve a mutable ingress or internal operation; unknown scope is broad."""
        sc.need(coordinate is None or type(coordinate) is Coordinate)
        shared=self._shared.reserve() if self._shared is not None else nullcontext()
        with shared:
            with self._lock:
                self._decision(coordinate)
                token=Reservation(str(uuid.uuid4()),coordinate)
                self._active[token.ident]=[token,False,False]
            try:
                yield token
            finally:
                with self._lock:
                    self._active.pop(token.ident,None)

    @contextmanager
    def effect(self,token):
        """New effect must pass current gate; already started work can settle."""
        with self._lock:
            active=self._active.get(token.ident)
            sc.need(active is not None and active[0] is token and not active[1] and not active[2],
                    'MAINTENANCE_RESERVATION_REQUIRED')
            self._decision(token.coordinate)
            active[1]=True
        try:
            yield
        finally:
            with self._lock:
                active[1]=False

    def check_effect(self,token):
        with self._lock:
            active=self._active.get(token.ident)
            sc.need(active is not None and active[0] is token and active[1] and not active[2],
                    'MAINTENANCE_RESERVATION_REQUIRED')
            self._decision(token.coordinate)

    def register_hold(self,token,write,*,operation_ids):
        """Exact trusted admitted begin, synchronized with new effect admission.

        The begin receipt and parent settlement stay within the existing
        reservation. No subsequent unrelated effect under this reservation.
        Ambiguous local write latches unknown until reviewed recovery/restart;
        there is deliberately no in-process force-clear method.
        """
        sc.need(type(operation_ids) is tuple and 1<=len(operation_ids)<=20)
        for ident in operation_ids:
            sc.uuid_id(ident)
        sc.need(len(set(operation_ids))==len(operation_ids))
        op='begin_release' if len(operation_ids)==1 else 'begin_release_group'
        with self._lock:
            active=self._active.get(token.ident)
            sc.need(active is not None and active[0] is token and
                    token.coordinate==Coordinate('registry',op) and not active[1] and not active[2],
                    'MAINTENANCE_BEGIN_RESERVATION_REQUIRED')
            self._decision(token.coordinate)
            active[2]=True
            try:
                result=write()
                rows=[result] if op=='begin_release' else result
                sc.need(type(rows) is list and len(rows)==len(operation_ids) and
                        all(type(r) is dict and r.get('result')!='UNKNOWN_OUTCOME' and
                            r.get('operationId')==ident for r,ident in zip(rows,operation_ids)),
                        'MAINTENANCE_BEGIN_UNKNOWN')
                _,holds=self._snapshot()
                sc.need(set(operation_ids)<={h['attemptId'] for h in holds['holds']},
                        'MAINTENANCE_BEGIN_HOLD_MISSING')
                return result
            except Exception:
                self._local_uncertain=True
                raise Denied('MAINTENANCE_STATE_UNKNOWN') from None

    def effective_status(self):
        with self._lock:
            sc.need(not self._local_uncertain,'MAINTENANCE_STATE_UNKNOWN')
            record,holds=self._snapshot()
            blocks={sc.canonical(op):op for hold in holds['holds']
                    for op in hold['blockedOperations']}
            return {'phase':record['phase'],
                    'stateFreeze':record['phase']!='NORMAL' or
                                  any(h['stateFreeze'] for h in holds['holds']),
                    'blockedOperations':[blocks[k] for k in sorted(blocks)],
                    'snapshotRevision':holds['snapshotRevision'],
                    'eventDigest':holds['eventDigest']}

    def drain_status(self):
        """No mutation; not an independent quiescence proof or GO."""
        with self._lock:
            try:
                record,holds=self._snapshot()
                drained=(not self._active and
                         (self._shared is None or self._shared.drained()))
                if drained and self._shared is not None:
                    sc.need(self._snapshot()==(record,holds),'MAINTENANCE_STATE_UNKNOWN')
            except (Denied,OSError):
                return {'status':'UNKNOWN','reservations':len(self._active),'ready':False}
            phase=record['phase']
            attempt=record['attempt']
            matching=matching_holds(holds['holds'],attempt)
            return {'status':phase,'reservations':len(self._active),
                    'interlockDigest':sc.digest(record),'registryDigest':sc.digest(holds),
                    'attemptId':attempt['attemptId'] if attempt else None,
                    'generation':record['generation'],
                    'ready':drained and matching and not self._local_uncertain
                    and phase=='DRAINING'}

    def completion(self, *, expected_attempt, expected_operation, verify, write):
        """Apply only the verified protected completion for this attempt."""
        sc.uuid_id(expected_attempt)
        sc.uuid_id(expected_operation)
        with self._lock:
            record,holds=self._snapshot()
            sc.need(record['phase']=='COMPLETION_PENDING' and not self._active
                    and (self._shared is None or self._shared.drained())
                    and record['attempt']['attemptId']==expected_attempt
                    and not self._local_uncertain and verify(record,holds) is True,
                    'MAINTENANCE_COMPLETION_DENIED')
            try:
                result=write()
                sc.need(type(result) is dict and result.get('result')!='UNKNOWN_OUTCOME'
                        and result.get('operationId')==expected_operation,'MAINTENANCE_COMPLETION_UNKNOWN')
                _,current=self._snapshot()
                sc.need(not any(h['attemptId']==expected_attempt or h.get('pairId')==expected_attempt
                                for h in current['holds']),
                        'MAINTENANCE_COMPLETION_HOLD_REMAINS')
                return result
            except Exception:
                self._local_uncertain=True
                raise Denied('MAINTENANCE_STATE_UNKNOWN') from None

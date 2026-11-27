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
    bind_record, bind_startup_handoff, validate_transition,
)


@dataclass(frozen=True)
class Coordinate:
    service: str
    operation: str

    def __post_init__(self):
        for v in (self.service,self.operation):
            sc.need(type(v) is str and 0<len(v)<=64 and
                    all(c.isascii() and (c.islower() or c.isdigit() or c in '_-') for c in v))


@dataclass(frozen=True)
class Reservation:
    ident: str
    coordinate: Coordinate | None


def hold_snapshot(value):
    """Trusted Registry-derived aggregate, not a public filtered READ DTO."""
    sc.fields(value,('instanceId','scopeDigest','snapshotRevision','eventDigest','holds'))
    sc.uuid_id(value['instanceId'])
    sc.hex_id(value['scopeDigest'],64)
    sc.revision(value['snapshotRevision'])
    sc.hex_id(value['eventDigest'],64)
    sc.need(type(value['holds']) is list and len(value['holds'])<=200)
    seen=set()
    for hold in value['holds']:
        sc.fields(hold,('attemptId','subject','source','restrictionDigest','stateFreeze',
                        'blockedOperations'))
        sc.uuid_id(hold['attemptId'])
        sc.subject(hold['subject'])
        sc.source(hold['source'])
        sc.hex_id(hold['restrictionDigest'],64)
        sc.need(hold['attemptId'] not in seen and type(hold['stateFreeze']) is bool)
        seen.add(hold['attemptId'])
        sc.need(type(hold['blockedOperations']) is list and len(hold['blockedOperations'])<=100)
        coords=set()
        for op in hold['blockedOperations']:
            sc.fields(op,('service','operation'))
            coord=Coordinate(**op)
            sc.need(coord not in coords)
            coords.add(coord)
    return sc.loads_strict(sc.canonical(value))


class MaintenanceGate:
    def __init__(self, *, instance_id, scope_digest, generation, read_interlock,
                 read_holds, shared_reservations=None):
        sc.uuid_id(instance_id)
        sc.hex_id(scope_digest,64)
        sc.hex_id(generation,64)
        sc.need(callable(read_interlock) and callable(read_holds))
        self.instance_id,self.scope_digest,self.generation=instance_id,scope_digest,generation
        self._interlock,self._holds=read_interlock,read_holds
        from .maintenance_interlock_reader import InterlockReservations
        sc.need(shared_reservations is None or type(shared_reservations) is InterlockReservations,
                'MAINTENANCE_RESERVATION_REQUIRED')
        self._shared=shared_reservations
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

    def verify_startup(self,handoff=None):
        """Read-only admission before serving a reviewed runtime."""
        if handoff is not None:
            sc.need(self._shared is not None,'MAINTENANCE_RESERVATION_REQUIRED')
        shared=self._shared.reserve() if handoff is not None else nullcontext()
        with shared,self._lock:
            sc.need(not self._local_uncertain,'MAINTENANCE_STATE_UNKNOWN')
            record,holds=self._snapshot()
            if handoff is None:
                sc.need(record['phase']=='NORMAL' and not any(h['stateFreeze'] for h in holds['holds']),
                        'MAINTENANCE_STARTUP_HANDOFF_REQUIRED')
                return
            current=bind_startup_handoff(handoff,record)
            attempt=current['attempt']
            sc.need(sc.digest(holds)==handoff['registryDigest'] and len(holds['holds'])==1,
                    'MAINTENANCE_STARTUP_HOLD_CHANGED')
            hold=holds['holds'][0]
            sc.need(hold['stateFreeze'] and all(hold[k]==attempt[k] for k in
                    ('attemptId','subject','source','restrictionDigest')),
                    'MAINTENANCE_STARTUP_HOLD_CHANGED')

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
        """For independently proved passive semantic reads ONLY."""
        from ..integrations.registry_contracts.semantic_contract import READ_METHODS
        sc.need(type(coordinate) is Coordinate and coordinate.service=='registry'
                and coordinate.operation in READ_METHODS)
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
            matching=bool(attempt and any(
                h['attemptId']==attempt['attemptId'] and h['subject']==attempt['subject']
                and h['source']==attempt['source'] and h['restrictionDigest']==attempt['restrictionDigest']
                and h['stateFreeze'] for h in holds['holds']))
            return {'status':phase,'reservations':len(self._active),
                    'interlockDigest':sc.digest(record),'registryDigest':sc.digest(holds),
                    'attemptId':attempt['attemptId'] if attempt else None,
                    'generation':record['generation'],
                    'ready':drained and matching and len(holds['holds'])==1 and not self._local_uncertain
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
                sc.need(not any(h['attemptId']==expected_attempt for h in current['holds']),
                        'MAINTENANCE_COMPLETION_HOLD_REMAINS')
                return result
            except Exception:
                self._local_uncertain=True
                raise Denied('MAINTENANCE_STATE_UNKNOWN') from None

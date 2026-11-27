"""Opt-in local Core lifecycle boundary; not selected by existing R7.

This covers the named Core mutating methods. It does not claim coverage
of direct provider, native worker, auth or startup writes. The actual
reviewed composition must guard those separately and prove drain.
"""
from ..core import Denied
from ..integrations.registry_contracts import semantic_contract as sc
from .maintenance_gate import Coordinate, MaintenanceGate


class MaintenanceCoreMixin:
    def bind_maintenance(self, gate):
        sc.need(type(gate) is MaintenanceGate and not hasattr(self,'_maintenance'),
                'MAINTENANCE_COMPOSITION_INVALID')
        self._maintenance=gate

    def _gate(self):
        gate=getattr(self,'_maintenance',None)
        sc.need(type(gate) is MaintenanceGate,'MAINTENANCE_STATE_UNKNOWN')
        return gate

    def _coord(self, ident):
        p=self._read(ident)['request']
        return Coordinate(p['service'],p['operation'])

    def submit(self,actor,payload):
        self._payload(payload)
        sc.need(self.auth.active(actor) and self._policy(actor,payload) in ('ALLOW','ASK'),
                'POLICY_DENIED')
        with self._gate().reserve(Coordinate(payload['service'],payload['operation'])):
            return super().submit(actor,payload)

    def execute(self,ident):
        # The existing Core still checks persisted approval and authority.
        # Mark the whole execution boundary as admitted work; the individual
        # real provider must independently recheck at actual effect time.
        with self._gate().reserve(self._coord(ident)) as token:
            with self._gate().effect(token):
                return super().execute(ident)

    def owner_decide(self,request_id,*args,**kwargs):
        with self._gate().reserve(self._coord(request_id)):
            return super().owner_decide(request_id,*args,**kwargs)

    def reconcile(self,ident):
        with self._gate().reserve(self._coord(ident)) as token:
            with self._gate().effect(token):
                return super().reconcile(ident)

    def commit_verified_change(self,*args,**kwargs):
        with self._gate().reserve():
            return super().commit_verified_change(*args,**kwargs)

    def owner_close_simple(self,*args,**kwargs):
        with self._gate().reserve():
            return super().owner_close_simple(*args,**kwargs)

    def owner_cancel_approved(self,*args,**kwargs):
        with self._gate().reserve():
            return super().owner_cancel_approved(*args,**kwargs)

    def owner_close_uncertain(self,*args,**kwargs):
        with self._gate().reserve():
            return super().owner_close_uncertain(*args,**kwargs)

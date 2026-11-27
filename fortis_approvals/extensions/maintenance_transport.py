"""Local synchronization wrapper for the reviewed Registry transport interface.

Not registered in R7. Real admission and transport must authenticate the
actor, enforce the effect-time guard, and ensure every hold write crosses
this same boundary. Never mount the Registry DB in Gateway.
"""
from ..integrations.registry_contracts import semantic_contract as sc
from .maintenance_gate import Coordinate, MaintenanceGate


class MaintenanceRegistryTransport:
    def __init__(self,transport,gate,*,preflight):
        sc.need(type(gate) is MaintenanceGate and callable(preflight))
        self.transport,self.gate,self.preflight=transport,gate,preflight

    def read(self,actor,operation,params):
        sc.need(operation in sc.READ_METHODS)
        return self.transport.read(actor,operation,params)

    def owner_write(self,actor,operation,params,*,operation_id,assertion_source,parent_id=None):
        sc.need(operation in ('begin_release','report_release_result'))
        params=sc.validate_params(operation,params)
        sc.uuid_id(operation_id)
        sc.need(self.preflight(actor,operation,params) is True,'POLICY_DENIED')
        with self.gate.reserve(Coordinate('registry',operation)) as reservation:
            def write():
                return self.transport.owner_write(actor,operation,params,operation_id=operation_id,
                    assertion_source=assertion_source,parent_id=parent_id)
            if operation=='begin_release':
                return self.gate.register_hold(reservation,write,operation_ids=(operation_id,))
            # An ordinary report may settle its own optional window only;
            # mandatory protected closure is never a route here.
            with self.gate.effect(reservation):
                return write()

    def begin_group(self,actor,params,*,operation_ids,parent_id,assertion_source):
        params=sc.validate_params('begin_release_group',params)
        sc.need(type(operation_ids) is list and len(operation_ids)==len(params['items']))
        sc.need(self.preflight(actor,'begin_release_group',params) is True,'POLICY_DENIED')
        with self.gate.reserve(Coordinate('registry','begin_release_group')) as reservation:
            return self.gate.register_hold(reservation,
                lambda:self.transport.begin_group(actor,params,operation_ids=operation_ids,
                      parent_id=parent_id,assertion_source=assertion_source),
                operation_ids=tuple(operation_ids))

"""Conservative opt-in ingress adapter; never an authentication replacement.

No production route selection or R7 startup change. The trusted route
classifier must validate the existing authentication/scope before supplying
a coordinate or passive designation. Every unspecified route is considered
possibly mutating. Streaming iterable remains inside the reservation.
"""
from dataclasses import dataclass

from ..core import Denied
from ..repo_ingress import RepoIngress
from .maintenance_gate import Coordinate, MaintenanceGate


@dataclass(frozen=True)
class RouteAdmission:
    passive: bool
    coordinate: Coordinate | None = None

    def __post_init__(self):
        if (type(self.passive) is not bool or
                (self.coordinate is not None and type(self.coordinate) is not Coordinate)
                or (self.passive and self.coordinate is not None)):
            raise Denied('MAINTENANCE_ROUTE_INVALID')


class _ReservedBody:
    """Release reservation even if the server closes before first iteration."""
    def __init__(self,response,reservation):
        self.response,self.reservation=response,reservation
        self.iterator=iter(response)
        self.closed=False

    def __iter__(self):
        return self

    def __next__(self):
        try:
            return next(self.iterator)
        except BaseException:
            self.close()
            raise

    def close(self):
        if not self.closed:
            self.closed=True
            try:
                close=getattr(self.response,'close',None)
                if callable(close):
                    close()
            finally:
                self.reservation.__exit__(None,None,None)


class MaintenanceIngress:
    def __init__(self, delegate, gate, *, classify):
        if type(gate) is not MaintenanceGate or not callable(classify):
            raise Denied('MAINTENANCE_COMPOSITION_INVALID')
        self.delegate,self.gate,self.classify=delegate,gate,classify

    def __call__(self, env, start):
        try:
            admission=self.classify(env)
            if type(admission) is not RouteAdmission:
                raise Denied('POLICY_DENIED')
        except Denied:
            return RepoIngress._reply(start,403,{'error':'POLICY_DENIED'})
        if admission.passive:
            return self.delegate(env,start)
        reservation=self.gate.reserve(admission.coordinate)
        try:
            reservation.__enter__()
        except Denied as exc:
            code=str(exc)
            if code not in ('RELEASE_MAINTENANCE','MAINTENANCE_STATE_UNKNOWN'):
                code='MAINTENANCE_STATE_UNKNOWN'
            return RepoIngress._reply(start,403,{'error':code})
        try:
            response=self.delegate(env,start)
        except BaseException:
            reservation.__exit__(None,None,None)
            raise
        try:
            return _ReservedBody(response,reservation)
        except BaseException:
            reservation.__exit__(None,None,None)
            raise


def owner_passive_route(env):
    """Only existing static asset routes are preclassified here.

    Other GETs require independently reviewed no-mutation proof and scope.
    No generic GET, reason, actor label or caller header bypass.
    """
    return (env.get('REQUEST_METHOD')=='GET' and env.get('PATH_INFO') in
            ('/','/app.js','/style.css') and env.get('CONTENT_LENGTH') in (None,'','0'))

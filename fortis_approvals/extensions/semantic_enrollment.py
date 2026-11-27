"""Finite semantic scope relation, bound to existing reviewed policy epoch.

No runtime policy values, credentials or automatic grants. Owner-only
principal identity is distinct from machine authentication.
"""
from ..core import Denied
from ..integrations.registry_contracts import semantic_contract as sc
from .semantic_access import READ,WRITE
from .owner_policy_engine_v2 import _coordinate


class SemanticEnrollment:
    def __init__(self,rows,*,source_digest,expected_digest):
        sc.hex_id(source_digest,64);sc.hex_id(expected_digest,64)
        sc.need(type(rows) is list and 0<len(rows)<=2000)
        clean=[]
        for row in rows:
            sc.fields(row,('actor','service','operation','target','subject'))
            coord=_coordinate(tuple(row[k] for k in ('actor','service','operation','target')))
            action=coord[1:3]
            sc.need(action in READ|WRITE|{('github','list_pull_requests')})
            subject=row['subject']
            if set(subject)=={'repository'}:
                sc.repository(subject['repository'])
            else:
                sc.subject(subject)
            if action==('github','list_pull_requests'):
                sc.need(set(subject)=={'repository'} and coord[3]==subject['repository'].split('/')[1])
            clean.append(sc.loads_strict(sc.canonical(row)))
        clean.sort(key=sc.canonical)
        sc.need(len({sc.canonical(r) for r in clean})==len(clean))
        self._raw=sc.canonical({'schemaVersion':1,'sourceDigest':source_digest,'grants':clean})
        sc.need(sc.digest(sc.loads_strict(self._raw))==expected_digest,'SEMANTIC_SCOPE_PIN_CHANGED')
        self.sha=expected_digest
        self._keys=frozenset(sc.canonical(r) for r in clean)

    def metadata(self):
        return sc.loads_strict(self._raw)

    def coordinates(self):
        return {tuple(r[k] for k in ('actor','service','operation','target'))
                for r in self.metadata()['grants']}

    def allows(self,actor,service,operation,target,subject):
        value={'actor':actor,'service':service,'operation':operation,'target':target,'subject':subject}
        return sc.canonical(value) in self._keys


class OwnerPrincipalAuth:
    """Trusted in-process composition; owner principal cannot use bearer API.

    Owner session authentication is still exclusively the existing Portal.
    active_owner is an independent current owner-credential readiness check.
    """
    def __init__(self,machine,*,owners,active_owner):
        sc.need(type(owners) is dict and bool(owners) and callable(active_owner)
                and all(type(k) is str and bool(k) and type(v) is str and bool(v)
                        for k,v in owners.items()) and len(set(owners.values()))==len(owners))
        sc.need(not any(machine.active(a) for a in owners.values()),'OWNER_PRINCIPAL_COLLISION')
        self.machine=machine
        self._owners=dict(owners)
        self._active_owner=active_owner

    def authenticate(self,credential):
        actor=self.machine.authenticate(credential)
        sc.need(actor not in self._owners.values(),'CLIENT_UNAUTHORIZED')
        return actor

    def active(self,actor):
        owner=next((k for k,v in self._owners.items() if v==actor),None)
        return self._active_owner(owner) is True if owner is not None else self.machine.active(actor)

    def revoke(self,credential):
        return self.machine.revoke(credential)

    def owner_actor(self,name):
        actor=self._owners.get(name)
        return actor if actor and self.active(actor) else None

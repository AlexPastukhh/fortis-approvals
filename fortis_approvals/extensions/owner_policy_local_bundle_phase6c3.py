"""Phase 6C.3 source-only single-process composition, NOT a runtime factory.

No listener, deployment, worker launcher, migration or external attestation.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING
from ..core import Denied

if TYPE_CHECKING:
    from ..gateway import ClientGateway
from .model import bounded
from ..owner_auth import OwnerWebAuthn
from .owner_inventory import owner_policy_inventory
from .owner_policy_local_core_phase6c import LocalDenyCore
from .owner_policy_local_deny_apply_phase6c1 import OwnerLocalDenyApply
from .owner_policy_local_deny_http_phase6c2 import OwnerLocalDenyPortal


def owner_local_deny_inventory(core, extension_runtime=None):
    """Return exact effective local DENY readback without running callables."""
    if type(core) is not LocalDenyCore:
        raise Denied('OWNER_LOCAL_INVENTORY_GUARDED_CORE_REQUIRED')
    result=owner_policy_inventory(core,extension_runtime)
    with core._db() as db:
        db.execute('BEGIN')
        revision=core._local_revision(db)
        if result['policyVersion'] != core._baseline_policy_version+'|owner-local-deny:'+str(revision):
            raise Denied('OWNER_LOCAL_INVENTORY_REVISION_CHANGED')
        local=db.execute('''SELECT actor,service,operation,target,decision
            FROM owner_local_denials ORDER BY actor,service,operation,target''').fetchall()
    denied=set()
    for row in local:
        if row['decision']!='DENY':
            raise Denied('OWNER_LOCAL_INVENTORY_CORRUPT_DENIAL')
        denied.add((row['actor'],row['service'],row['operation'],row['target']))
    seen=set()
    for row in result['operations']:
        coord=(row['actor'],row['provider'],row['operation'],row['target'])
        if coord not in denied:
            row['localDenialApplied']=False
            continue
        if (row['scope']!='exact' or row['configuredPolicy'] not in ('ASK','ALLOW') or
                coord in seen):
            raise Denied('OWNER_LOCAL_INVENTORY_DENIAL_UNRESOLVED')
        seen.add(coord)
        row['effectivePolicy']='DENY'
        row['localDenialApplied']=True
    for coord in sorted(denied - seen):
        # An actor-scoped ASK/ALLOW may be narrowed for ONE exact target,
        # not converted to an actor-wide policy or an implied new grant.
        # Refuse exact shadowing or unknown/callable/global-only policies.
        if coord in core.policies:
            raise Denied('OWNER_LOCAL_INVENTORY_DENIAL_UNRESOLVED')
        parent = core.policies.get(coord[:3])
        if type(parent) is not str or parent not in ('ASK','ALLOW'):
            raise Denied('OWNER_LOCAL_INVENTORY_DENIAL_UNRESOLVED')
        matching = [row for row in result['operations']
            if row['scope']=='actor' and row['actor']==coord[0] and
               row['provider']==coord[1] and row['operation']==coord[2] and
               row['providerType']=='native' and row['configuredPolicy']==parent]
        if len(matching)!=1:
            raise Denied('OWNER_LOCAL_INVENTORY_DENIAL_UNRESOLVED')
        inherited = dict(matching[0], scope='exact', target=coord[3],
                         configuredPolicy=parent, effectivePolicy='DENY',
                         configuredSourceScope='actor', localDenialApplied=True)
        result['operations'].append(inherited)
        seen.add(coord)
    if seen!=denied:
        raise Denied('OWNER_LOCAL_INVENTORY_DENIAL_UNRESOLVED')
    result.update(localPolicyRevision=revision,localDenyOnly=True,
                  localDeniedExactRules=len(denied),
                  allWorkersVerified=False,externalRollbackProof=False)
    return bounded(result,262144)


class OwnerLocalDenyInventoryPortal(OwnerLocalDenyPortal):
    """Optional owner portal correctly projects same-DB restrictive DENY."""
    def __call__(self,env,start):
        if (env.get('REQUEST_METHOD')!='GET' or
                env.get('PATH_INFO')!='/v1/owner/provider-inventory'):
            return super().__call__(env,start)
        try:
            if (env.get('HTTP_HOST')!=self.host or env.get('QUERY_STRING') or
                    any(env.get(x) for x in ('HTTP_X_FORWARDED_HOST','HTTP_FORWARDED',
                                             'HTTP_PROXY_AUTHORIZATION','HTTP_AUTHORIZATION'))):
                raise Denied('HOST_DENIED')
            self.auth.session(self._cookie(env))
            inventory=owner_local_deny_inventory(
                self.core,getattr(self,'_extension_runtime',None))
            if self._local_deny_apply is not None:
                for row in inventory['operations']:
                    coord=(row['actor'],row['provider'],row['operation'],row['target'])
                    row['localDenyEditable']=self._local_deny_apply.editable_coordinate(coord)
            return self._reply(start,200,bounded(inventory,262144))
        except Denied as exc:
            return self._reply(start,403,{'error':str(exc)})


@dataclass(frozen=True)
class SourceOnlyLocalPolicyBundle:
    core: LocalDenyCore
    client_gateway: ClientGateway
    owner_portal: OwnerLocalDenyInventoryPortal
    local_deny_apply: OwnerLocalDenyApply

    def status(self):
        if (type(self.core) is not LocalDenyCore or
                self.client_gateway.core is not self.core or
                self.owner_portal.core is not self.core or
                self.owner_portal.auth is not self.core.owner_verifier or
                self.owner_portal._local_deny_apply is not self.local_deny_apply or
                self.local_deny_apply.core is not self.core):
            raise Denied('OWNER_LOCAL_BUNDLE_IDENTITY_DRIFT')
        with self.core._db() as db:
            revision=self.core._local_revision(db)
        return {'kind':'OWNER_LOCAL_POLICY_SOURCE_BUNDLE_ONLY',
                'localDenyOnly':True,'revision':revision,
                'allInProcessEntrypointsBound':True,
                'externalWorkersVerified':False,
                'hostSourceAttested':False,'hostCredentialGenerationAttested':False,
                'rollbackProtected':False,'runtimeIntegrated':False,'canDeploy':False}


def bind_source_only_local_policy_bundle(*,core,owner_auth,client_host,
                                          source_digest,
                                          credential_generation_digest):
    """Bind one preconstructed Core to in-process WSGI objects; no listeners."""
    if (type(core) is not LocalDenyCore or
            not isinstance(owner_auth,OwnerWebAuthn) or
            core.owner_verifier is not owner_auth):
        raise Denied('OWNER_LOCAL_BUNDLE_TRUSTED_CORE_REQUIRED')
    with core._db() as db:
        core._local_revision(db)
    apply=OwnerLocalDenyApply(core,owner_auth,source_digest=source_digest,
                             credential_generation_digest=credential_generation_digest)
    # Legacy ClientGateway belongs only to this isolated source test bundle.
    # The production R7 image uses RepoIngress and does not package it.
    from ..gateway import ClientGateway
    client=ClientGateway(core,host=client_host)
    portal=OwnerLocalDenyInventoryPortal(core,owner_auth,local_deny_apply=apply)
    bundle=SourceOnlyLocalPolicyBundle(core,client,portal,apply)
    bundle.status()
    return bundle

"""Unified owner-only WebAuthn + HTTP editor, source candidate.

Bind to a trusted UnifiedPolicyCore before serving; no machine mutation route.
No owner approval is inferred from a session, preview, or draft review.
"""
import re
import sqlite3
import uuid

from ..core import ApprovalError, Denied, Stale
from ..incidents import IncidentOwnerPortal
from ..owner_auth import OwnerWebAuthn, _hash
from .model import bounded
from .owner_inventory import owner_policy_inventory
from .owner_policy_engine_v2 import UnifiedPolicyCore, digest, _FIELDS, _PURPOSE

_PREFIX = "/v1/owner/policy/editor"
_CEREMONY = "owner_unified_policy_apply_v2"
_DESCRIPTOR = _FIELDS | {"purpose","requestId","authorityDigest","sourceDigest",
                         "credentialGenerationDigest","expiresAt"}


def _hex(value):
    if type(value) is not str or not re.fullmatch(r"[0-9a-f]{64}",value):
        raise Denied("OWNER_POLICY_TRUSTED_DIGEST_REQUIRED")
    return value


def is_reviewed_group_coordinate(core, coord):
    from .composite_successor import is_reviewed_successor
    return (is_reviewed_successor(core) and len(coord)==4
            and core._composite({"service":coord[1],"operation":coord[2]}) is not None)


class OwnerPolicyEditor:
    def __init__(self, core, owner, *, source_digest, credential_generation):
        from .composite_successor import is_reviewed_successor
        if ((type(core) is not UnifiedPolicyCore and not is_reviewed_successor(core))
                or core.authority is None or
                not isinstance(owner,OwnerWebAuthn) or core.owner_verifier is not owner
                or not callable(credential_generation)):
            raise Denied("OWNER_POLICY_EDITOR_BINDING_REQUIRED")
        self.core = core
        self.auth = owner
        self.source_digest = _hex(source_digest)
        self.credential_generation = credential_generation

    def generation(self):
        # Trusted runtime callback must bind loaded provider credential
        # identity AND owner key generation (not WebAuthn counters).
        return _hex(self.credential_generation())

    def begin(self, session, csrf, candidate):
        if type(csrf) is not str or not csrf:
            raise Denied("CSRF_REQUIRED")
        with self.auth.lock:
            self.auth.session(session,csrf)
            preview = self.core.preview_change(candidate)
            change = {**candidate,"purpose":_PURPOSE,"requestId":str(uuid.uuid4()),
                      "authorityDigest":self.core.authority.sha,
                      "sourceDigest":self.source_digest,
                      "credentialGenerationDigest":self.generation(),
                      "expiresAt":int(self.auth.clock())+90}
            sha = digest(change)
            started = self.auth._begin_assertion(_CEREMONY,session_hash=_hash(session),
                                                 change_digest=sha,expires_at=change["expiresAt"])
            return {**started,"kind":"OWNER_UNIFIED_POLICY_CEREMONY_V2",
                    "change":change,"changeDigest":sha,"preview":preview}

    def finish(self, session, csrf, ceremony, response, change):
        if type(csrf) is not str or not csrf:
            raise Denied("CSRF_REQUIRED")
        with self.auth.lock:
            self.auth.session(session,csrf)
            state,data = self.auth._take(ceremony,_CEREMONY)
            if type(change) is not dict or set(change)!=_DESCRIPTOR:
                raise Denied("OWNER_POLICY_DESCRIPTOR_INVALID")
            def valid():
                self.auth.session(session,csrf)
                now = int(self.auth.clock())
                return (change["purpose"]==_PURPOSE and
                        change["authorityDigest"]==self.core.authority.sha and
                        change["sourceDigest"]==self.source_digest and
                        change["credentialGenerationDigest"]==self.generation() and
                        type(change["expiresAt"]) is int and now<change["expiresAt"]<=now+90 and
                        data["session_hash"]==_hash(session) and
                        data["change_digest"]==digest(change) and
                        data["expires_at"]==change["expiresAt"] and
                        type(change["requestId"]) is str and
                        str(uuid.UUID(change["requestId"]))==change["requestId"])
            if not valid():
                raise Denied("OWNER_POLICY_PROOF_BINDING_INVALID")
            owner = self.auth._finish_assertion(state,data,response)
            if type(owner) is not str or not owner:
                raise Denied("OWNER_POLICY_OWNER_INVALID")
            result = self.core.commit_verified_change(change,owner,now=self.auth.clock,verified=valid)
            if result["found"] is not True or result["change"]!=change:
                raise Denied("OWNER_POLICY_COMMIT_READBACK_UNCONFIRMED")
            return result

    def inventory(self, extension_runtime=None):
        core = self.core
        result = owner_policy_inventory(core,extension_runtime)
        with core._db() as db:
            db.execute("BEGIN")
            revision, overlay, legacy = core._snapshot(db)
            if result["policyVersion"]!=core._version(revision):
                raise Stale("OWNER_POLICY_INVENTORY_CHANGED")
            rows = result["operations"]
            existing = set()
            for row in rows:
                if row["scope"] not in ("actor","exact"):
                    row["editablePolicies"]=[]
                    continue
                coord = (row["actor"], row["provider"], row["operation"])
                if row["scope"]=="exact":
                    coord += (row["target"],)
                existing.add(coord)
                try:
                    _, permitted = core.authority.admitted(coord)
                    current = core.authority.decision(coord,overlay,legacy)
                except Denied:
                    row["editablePolicies"]=[]
                    if coord in legacy:
                        row["effectivePolicy"]="DENY"
                    continue
                row["currentPolicy"]=current
                row["editablePolicies"]=sorted(permitted)
                # The owner changes the OUTER method policy. A trusted
                # provider or Windows guard can still require ASK or DENY,
                # even with outer ALLOW. The actor-wide target-free overview
                # cannot claim a single effective policy for every target.
                effective="UNKNOWN"
                if len(coord)==4:
                    baseline=core.authority.baseline.get(
                        coord,core.authority.baseline.get(coord[:3]))
                    is_composite = (is_reviewed_group_coordinate(core, coord))
                    from .semantic_access import READ,WRITE
                    semantic=(coord[1],coord[2]) in READ|WRITE
                    if is_composite:
                        from .composite_contract import definition
                        meta=definition(coord[1],coord[2]).metadata()
                        row.update(operationKind='composite',version=meta['version'],kind='composite',
                                   children=meta['children'],protectedOwnerGate=meta['protectedOwnerGate'])
                    elif semantic:
                        row.update(operationKind='read' if (coord[1],coord[2]) in READ else 'write',
                                   version=1,kind='read' if (coord[1],coord[2]) in READ else 'write')
                    if is_composite or semantic:
                        effective = "DENY" if current == "DENY" else "UNKNOWN"
                    elif not callable(baseline):
                        effective=core._inner_guard(row["actor"],dict(
                            service=row["provider"],operation=row["operation"],
                            target=row["target"],params={}),current)
                row["effectivePolicy"]=effective
                row["localPolicyApplied"]=coord in overlay or coord in legacy
            for coord in sorted((set(overlay)|set(legacy))-existing):
                parent=next((row for row in rows if row["scope"]=="actor" and
                             (row["actor"],row["provider"],row["operation"])==coord[:3]),None)
                if len(coord)!=4 or parent is None:
                    raise Denied("OWNER_POLICY_INVENTORY_ORPHAN_OVERRIDE")
                try:
                    original,permitted=core.authority.admitted(coord)
                    current=core.authority.decision(coord,overlay,legacy)
                except Denied:
                    if coord not in legacy:
                        raise
                    original=parent["configuredPolicy"]; permitted=(); current="DENY"
                underlying=core.authority.baseline.get(coord,
                               core.authority.baseline.get(coord[:3]))
                effective=("UNKNOWN" if callable(underlying) else
                    core._inner_guard(coord[0],dict(service=coord[1],
                        operation=coord[2],target=coord[3],params={}),current))
                rows.append(dict(parent,scope="exact",target=coord[3],
                                 configuredPolicy=original,currentPolicy=current,
                                 effectivePolicy=effective,editablePolicies=sorted(permitted),
                                 localPolicyApplied=True))
            result.update(policyEditorVersion=2,policyRevision=revision,
                          externalRollbackProof=False,localDenyOnly=False)
        return bounded(result,262144)


class UnifiedPolicyPortal(IncidentOwnerPortal):
    def __init__(self, core, authenticator, *, editor=None, **kwargs):
        super().__init__(core,authenticator,**kwargs)
        self.editor = None
        if editor is not None:
            self.bind_editor(editor)

    def bind_editor(self, editor):
        if (self.editor is not None or type(editor) is not OwnerPolicyEditor or
                editor.core is not self.core or editor.auth is not self.auth):
            raise Denied("OWNER_POLICY_PORTAL_BINDING_REQUIRED")
        self.editor = editor

    def __call__(self, env, start):
        method,path = env.get("REQUEST_METHOD"),env.get("PATH_INFO","")
        if not (path=="/v1/owner/provider-inventory" or path.startswith(_PREFIX+"/")):
            return super().__call__(env,start)
        try:
            if (env.get("HTTP_HOST")!=self.host or env.get("QUERY_STRING") or
                    any(env.get(x) for x in ("HTTP_X_FORWARDED_HOST","HTTP_FORWARDED",
                                             "HTTP_PROXY_AUTHORIZATION","HTTP_AUTHORIZATION"))):
                raise Denied("HOST_DENIED")
            if self.editor is None:
                raise Denied("OWNER_POLICY_EDITOR_NOT_BOUND")
            session=self._cookie(env)
            if method=="GET":
                self.auth.session(session)
                if path=="/v1/owner/provider-inventory":
                    return self._reply(start,200,self.editor.inventory(getattr(self,"_extension_runtime",None)))
                if path==_PREFIX+"/capabilities":
                    return self._reply(start,200,{"configured":not self.read_only_banner,
                        "version":2,"ownerOnly":True,"requiresFreshStrongWebAuthn":True})
                raise Denied("OWNER_POLICY_ROUTE_DENIED")
            if method!="POST" or env.get("HTTP_ORIGIN")!=self.origin or self.read_only_banner:
                raise Denied("OWNER_POLICY_WRITE_DENIED")
            csrf=env.get("HTTP_X_FORTIS_CSRF")
            if not csrf:
                raise Denied("CSRF_REQUIRED")
            self.auth.session(session,csrf)
            body=self._json(env)
            if path==_PREFIX+"/preview" and set(body)=={"candidate"}:
                return self._reply(start,200,self.core.preview_change(body["candidate"]))
            if path==_PREFIX+"/begin" and set(body)=={"candidate"}:
                return self._reply(start,200,self.editor.begin(session,csrf,body["candidate"]))
            if path==_PREFIX+"/finish" and set(body)=={"ceremonyId","response","change"}:
                return self._reply(start,200,self.editor.finish(session,csrf,body["ceremonyId"],body["response"],body["change"]))
            if path==_PREFIX+"/readback" and set(body)=={"requestId"}:
                return self._reply(start,200,self.core.policy_readback(body["requestId"]))
            raise Denied("OWNER_POLICY_ROUTE_DENIED")
        except Stale as exc:
            return self._reply(start,409,{"error":str(exc)})
        except Denied as exc:
            return self._reply(start,403,{"error":str(exc)})
        except (ApprovalError,ValueError,KeyError,TypeError,UnicodeError):
            return self._reply(start,400,{"error":"REQUEST_INVALID"})
        except (sqlite3.DatabaseError,OSError,RuntimeError):
            return self._reply(start,500,{"error":"OUTCOME_UNCONFIRMED"})

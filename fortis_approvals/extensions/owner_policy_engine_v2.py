"""Unified owner policy authority, same Core transaction domain (source candidate).

Explicit trusted transition admission is required; no new provider grants or
conditional-policy replacement. No production composition is enabled here.
The legacy exact-DENY audit is preserved byte-for-byte and remains a fallback
unless the owner explicitly changes the exact coordinate via V2.
"""
import hashlib
import re
import uuid
from types import MappingProxyType

from ..core import Denied, Stale, canonical, loads_strict
from ..incidents import IncidentCore

POLICIES = frozenset(("DENY", "ASK", "ALLOW"))
_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_V1 = frozenset(("owner_local_policy_meta", "owner_local_denials",
                 "owner_local_policy_events"))
_V2 = frozenset(("owner_local_policy_v2_meta", "owner_local_policy_v2_rules",
                 "owner_local_policy_v2_events"))
_EPOCHS = "owner_local_policy_v2_authority_epochs"
_ALLOWED_TABLES = _V1 | _V2 | {_EPOCHS}
_FIELDS = frozenset(("actor", "provider", "operation", "scope", "target",
                     "expectedPolicy", "desiredPolicy", "expectedRevision",
                     "expectedPolicyVersion", "reasonCode"))
_PURPOSE = "OWNER_UNIFIED_POLICY_APPLY_V2"


def digest(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def _name(value):
    if type(value) is not str or not _NAME.fullmatch(value):
        raise Denied("OWNER_POLICY_COORDINATE_INVALID")
    return value


def _coordinate(value):
    if type(value) is not tuple or len(value) not in (3, 4):
        raise Denied("OWNER_POLICY_SCOPE_INVALID")
    return tuple(_name(part) for part in value)


def _names(db):
    return {r[0] for r in db.execute(
        "SELECT name FROM sqlite_master WHERE name GLOB 'owner_local_*'")}


def _legacy(db):
    names = _names(db)
    if not names & _V1:
        return None, {}
    if not _V1 <= names:
        raise Denied("OWNER_POLICY_LEGACY_SCHEMA_INCOMPLETE")
    meta = [list(r) for r in db.execute("SELECT * FROM owner_local_policy_meta")]
    rules = [list(r) for r in db.execute(
        "SELECT * FROM owner_local_denials ORDER BY actor,service,operation,target")]
    events = [list(r) for r in db.execute(
        "SELECT * FROM owner_local_policy_events ORDER BY applied_revision")]
    if (len(meta) != 1 or len(meta[0]) != 4 or meta[0][:2] != [1, 1]
            or type(meta[0][2]) is not int or meta[0][2] < 0
            or meta[0][3] != "READY"
            or len(events) != meta[0][2] or len(rules) != meta[0][2]):
        raise Denied("OWNER_POLICY_LEGACY_NOT_READY")
    exact = {}
    for actor, service, operation, target, policy in rules:
        coord = _coordinate((actor, service, operation, target))
        if policy != "DENY" or coord in exact:
            raise Denied("OWNER_POLICY_LEGACY_RULE_INVALID")
        exact[coord] = policy
    recorded = set()
    for index, (ident, at, owner, raw, previous, applied) in enumerate(events):
        change = loads_strict(raw)
        coord = _coordinate(tuple(change[k] for k in
                          ("actor","provider","operation","target")))
        if (coord not in exact or coord in recorded or
                change.get("purpose") != "OWNER_LOCAL_EXACT_DENY_APPLY_V1" or
                change.get("newPolicy") != "DENY" or
                change.get("requestId") != ident or
                change.get("expectedRevision") != index or
                previous != index or applied != index + 1 or
                type(owner) is not str or not owner or type(at) is not int or
                str(uuid.UUID(ident)) != ident):
            raise Denied("OWNER_POLICY_LEGACY_AUDIT_INVALID")
        recorded.add(coord)
    if set(exact) != recorded:
        raise Denied("OWNER_POLICY_LEGACY_AUDIT_INVALID")
    return digest([meta, rules, events]), exact


class PolicyAdmission:
    """Trusted composition supplies ceiling/transition choices per literal rule.

    An actor rule may have exact overrides, including configured exact DENY.
    Changing the actor rule does not alter any exact override. Arbitrary
    coordinates, global fallback and callbacks cannot be converted into grants.
    """

    def __init__(self, core, choices, *, scope_binding=None):
        if type(choices) is not dict or not choices:
            raise Denied("OWNER_POLICY_ADMISSION_REQUIRED")
        accepted = {}
        for key, permitted in choices.items():
            coord = _coordinate(key)
            baseline = core.policies.get(coord)
            if (not (type(baseline) is str and baseline in POLICIES or callable(baseline))
                    or type(permitted) not in (set, frozenset, tuple)
                    or not set(permitted) <= POLICIES
                    or not {"DENY"} <= set(permitted)
                    or type(baseline) is str and baseline not in permitted
                    or coord[1] not in core.adapters or not core.auth.active(coord[0])):
                raise Denied("OWNER_POLICY_ADMISSION_INVALID")
            accepted[coord] = frozenset(permitted)
        self.core = core
        self.choices = MappingProxyType(accepted)
        self.scope_binding = scope_binding
        # Bind ALL literal/conditional coordinates, including exceptions,
        # rather than just editable rows. Authority drift stops startup.
        self.baseline = MappingProxyType(dict(core.policies))
        self.sha = digest({
            "baseline":[[[*k],v if type(v) is str else "CONDITIONAL"]
                         for k,v in sorted(self.baseline.items(),key=lambda item:repr(item[0]))],
            "choices":[[list(k),sorted(v)] for k,v in sorted(accepted.items())],
            "scope":scope_binding})

    def admitted(self, coord):
        coord = _coordinate(coord)
        key = coord
        if len(coord) == 4 and coord not in self.baseline:
            key = coord[:3]
        if (key not in self.choices or not self.core.auth.active(coord[0])
                or coord[1] not in self.core.adapters):
            raise Denied("OWNER_POLICY_NOT_ADMITTED")
        # Baseline is immutable in a running, composed worker.
        if self.core.policies.get(key) != self.baseline[key] or (
                len(coord)==4 and (coord in self.core.policies) != (coord in self.baseline)):
            raise Denied("OWNER_POLICY_AUTHORITY_DRIFT")
        return self.baseline[key], self.choices[key]

    def decision(self, coord, overlay, legacy):
        # Explicit target override wins, then configured exact rule or legacy
        # exact DENY; actor-level owner policy does not shadow exceptions.
        if coord in overlay:
            self.admitted(coord)
            return overlay[coord]
        if coord in legacy:
            return "DENY"
        if len(coord)==4 and coord not in self.baseline and coord[:3] in overlay:
            self.admitted(coord)
            return overlay[coord[:3]]
        baseline = self.admitted(coord)[0]
        # A conditional handler is independent runtime enforcement. The
        # owner's default outer setting is ALLOW, which does not override
        # a callback's target/params-specific DENY or ASK result.
        return "ALLOW" if callable(baseline) else baseline


class UnifiedPolicyCore(IncidentCore):
    """New guarded Core; never enabled by default R7. Install before serving.

    Core admission/dispatch already serializes on the same SQLite write lock.
    The revision is part of existing request fingerprints. Commit never
    replays an operation or rewrites existing request states.
    """

    def __init__(self, *args, **kwargs):
        self._constructing = True
        self.authority = None
        super().__init__(*args, **kwargs)
        self._constructing = False
        self._composing = False

    def install_policy_authority(self, choices, *, scope_binding=None,
                                 reviewed_upgrade_from=None):
        if self.authority is not None:
            raise Denied("OWNER_POLICY_ALREADY_INSTALLED")
        authority = PolicyAdmission(self,choices,scope_binding=scope_binding)
        with self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            names = _names(db)
            if names - _ALLOWED_TABLES or names & _V2 and not _V2 <= names:
                raise Denied("OWNER_POLICY_SCHEMA_INCOMPLETE")
            legacy_hash, legacy = _legacy(db)
            for statement in (
                """CREATE TABLE IF NOT EXISTS owner_local_policy_v2_meta(
                id INTEGER PRIMARY KEY CHECK(id=1), revision INTEGER NOT NULL CHECK(revision>=0),
                authority TEXT NOT NULL, legacy_digest TEXT NOT NULL)""",
                """CREATE TABLE IF NOT EXISTS owner_local_policy_v2_rules(
                coordinate TEXT PRIMARY KEY, policy TEXT NOT NULL CHECK(policy IN ('DENY','ASK','ALLOW')))""",
                """CREATE TABLE IF NOT EXISTS owner_local_policy_v2_events(
                revision INTEGER PRIMARY KEY CHECK(revision>0), request_id TEXT NOT NULL UNIQUE,
                at INTEGER NOT NULL, owner TEXT NOT NULL, change TEXT NOT NULL)"""):
                db.execute(statement)
            if not names & _V2:
                db.execute("INSERT INTO owner_local_policy_v2_meta VALUES(1,0,?,?)",
                           (authority.sha,legacy_hash or "NONE"))
            elif reviewed_upgrade_from is not None:
                # The protected owner release explicitly names the exact
                # PREVIOUS admission. Never infer or overwrite historical UV
                # decisions. Validate its entire event projection first.
                previous = PolicyAdmission(self,reviewed_upgrade_from,
                                           scope_binding=scope_binding)
                meta = db.execute("SELECT * FROM owner_local_policy_v2_meta").fetchall()
                if len(meta)!=1 or meta[0]["id"]!=1:
                    raise Denied("OWNER_POLICY_AUTHORITY_UPGRADE_REVIEW_REQUIRED")
                if meta[0]["authority"] != authority.sha:
                    # Only an actual owner-reviewed change may add the epoch
                    # schema. Restarts with the same authority are read-only.
                    db.execute("""CREATE TABLE IF NOT EXISTS owner_local_policy_v2_authority_epochs(
                        id INTEGER PRIMARY KEY CHECK(id>=1),
                        through_revision INTEGER NOT NULL CHECK(through_revision>=0),
                        old_authority TEXT NOT NULL, new_authority TEXT NOT NULL,
                        old_choices TEXT NOT NULL)""")
                    if (meta[0]["authority"]!=previous.sha
                            or meta[0]["legacy_digest"]!=(legacy_hash or "NONE")
                            or not all(coord in authority.choices and
                                set(permitted) <= set(authority.choices[coord])
                                for coord,permitted in previous.choices.items())):
                        raise Denied("OWNER_POLICY_AUTHORITY_UPGRADE_REVIEW_REQUIRED")
                    # In particular, policy event and projection tampering
                    # cannot be disguised by a requested authority upgrade.
                    revision,_,_ = self._snapshot(db,authority=previous)
                    if db.execute("""SELECT 1 FROM requests
                        WHERE state IN ('PENDING','APPROVED','DISPATCHED')
                        LIMIT 1""").fetchone():
                        raise Denied("OWNER_POLICY_AUTHORITY_UPGRADE_IN_FLIGHT")
                    old_choices = canonical([[list(coord),sorted(permitted)]
                        for coord,permitted in sorted(previous.choices.items())])
                    db.execute("""INSERT INTO owner_local_policy_v2_authority_epochs
                        (through_revision,old_authority,new_authority,old_choices)
                        VALUES(?,?,?,?)""",
                        (revision,previous.sha,authority.sha,old_choices))
                    db.execute("""UPDATE owner_local_policy_v2_meta SET authority=?
                        WHERE id=1 AND authority=? AND revision=?""",
                        (authority.sha,previous.sha,revision))
                    if db.execute("SELECT changes()").fetchone()[0]!=1:
                        raise Denied("OWNER_POLICY_AUTHORITY_UPGRADE_RACED")
            self._snapshot(db, authority=authority)
        self.authority = authority

    @property
    def policy_version(self):
        if self._constructing or self._composing:
            return self._baseline_policy_version
        with self._db() as db:
            db.execute("BEGIN")
            rev, _, _ = self._snapshot(db)
        return self._version(rev)

    @policy_version.setter
    def policy_version(self, value):
        self._baseline_policy_version = value

    def _version(self, revision):
        if self.authority is None:
            raise Denied("OWNER_POLICY_AUTHORITY_NOT_INSTALLED")
        return self._baseline_policy_version + "|owner-policy-v2:" + str(revision)

    def _snapshot(self, db, *, authority=None):
        authority = authority or self.authority
        if authority is None:
            raise Denied("OWNER_POLICY_AUTHORITY_NOT_INSTALLED")
        if self.policies != authority.baseline:
            raise Denied("OWNER_POLICY_AUTHORITY_DRIFT")
        names = _names(db)
        if not _V2 <= names or names - _ALLOWED_TABLES:
            raise Denied("OWNER_POLICY_SCHEMA_INCOMPLETE")
        legacy_hash, legacy = _legacy(db)
        meta = db.execute("SELECT * FROM owner_local_policy_v2_meta").fetchall()
        if (len(meta)!=1 or meta[0]["id"]!=1 or meta[0]["authority"]!=authority.sha
                or meta[0]["legacy_digest"]!=(legacy_hash or "NONE")
                or type(meta[0]["revision"]) is not int or meta[0]["revision"]<0):
            raise Denied("OWNER_POLICY_STATE_BINDING_CHANGED")
        rev = meta[0]["revision"]
        # An epoch records the EXACT admission that signed earlier owner UV
        # changes. No event is rewritten when authority is widened.
        history = []
        current_end = -1
        next_sha = None
        epoch_rows=(db.execute(
                "SELECT * FROM owner_local_policy_v2_authority_epochs ORDER BY id")
                if _EPOCHS in names else ())
        for index, row in enumerate(epoch_rows,1):
            if (row["id"] != index or type(row["through_revision"]) is not int
                    or row["through_revision"] < current_end
                    or row["through_revision"] > rev or
                    (next_sha is not None and next_sha != row["old_authority"])):
                raise Denied("OWNER_POLICY_AUTHORITY_EPOCH_INVALID")
            entries = loads_strict(row["old_choices"])
            if type(entries) is not list or not entries or len(entries)>1000:
                raise Denied("OWNER_POLICY_AUTHORITY_EPOCH_INVALID")
            prior_choices = {}
            for item in entries:
                if (type(item) is not list or len(item)!=2
                        or type(item[0]) is not list
                        or type(item[1]) is not list):
                    raise Denied("OWNER_POLICY_AUTHORITY_EPOCH_INVALID")
                coord = _coordinate(tuple(item[0]))
                if coord in prior_choices or not item[1]:
                    raise Denied("OWNER_POLICY_AUTHORITY_EPOCH_INVALID")
                prior_choices[coord] = tuple(item[1])
            prior = PolicyAdmission(self,prior_choices,
                                    scope_binding=authority.scope_binding)
            if (prior.sha != row["old_authority"] or
                    not all(k in authority.choices and
                        set(v)<=set(authority.choices[k])
                        for k,v in prior.choices.items())):
                raise Denied("OWNER_POLICY_AUTHORITY_EPOCH_INVALID")
            history.append((row["through_revision"],prior))
            current_end = row["through_revision"]
            next_sha = row["new_authority"]
        if next_sha is not None and next_sha!=authority.sha:
            raise Denied("OWNER_POLICY_AUTHORITY_EPOCH_INVALID")
        overlay = {}
        for row in db.execute("SELECT * FROM owner_local_policy_v2_rules"):
            coord = _coordinate(tuple(loads_strict(row["coordinate"])))
            _, allowed = authority.admitted(coord)
            if row["policy"] not in allowed or row["coordinate"] != canonical(list(coord)):
                raise Denied("OWNER_POLICY_RULE_INVALID")
            overlay[coord] = row["policy"]
        # Verify event ordering and exact projection by replay. A V2 event
        # may override a legacy DENY only for that authorized coordinate.
        replay = {}
        count = 0
        for row in db.execute("SELECT * FROM owner_local_policy_v2_events ORDER BY revision"):
            change = loads_strict(row["change"])
            coord = self.coordinate(change)
            count += 1
            original = next((prior for through,prior in history
                             if count<=through),authority)
            _, allowed = original.admitted(coord)
            if (row["revision"] != count or change.get("purpose") != _PURPOSE
                    or change.get("requestId") != row["request_id"]
                    or change.get("expectedRevision") != count-1
                    or change.get("authorityDigest") != original.sha
                    or change.get("desiredPolicy") not in allowed
                    or change.get("expectedPolicy") != original.decision(coord,replay,legacy)
                    or change["expectedPolicy"] == change["desiredPolicy"]
                    or type(row["owner"]) is not str or not row["owner"]
                    or str(uuid.UUID(row["request_id"])) != row["request_id"]):
                raise Denied("OWNER_POLICY_EVENT_INVALID")
            replay[coord] = change["desiredPolicy"]
        if count != rev or overlay != replay:
            raise Denied("OWNER_POLICY_PROJECTION_MISMATCH")
        return rev, overlay, legacy

    @staticmethod
    def coordinate(candidate):
        if type(candidate) is not dict:
            raise Denied("OWNER_POLICY_CANDIDATE_SCHEMA")
        coord = tuple(candidate.get(k) for k in ("actor","provider","operation"))
        if candidate.get("scope")=="actor" and candidate.get("target") is None:
            return _coordinate(coord)
        if candidate.get("scope")=="exact":
            return _coordinate((*coord,candidate.get("target")))
        raise Denied("OWNER_POLICY_SCOPE_INVALID")

    def _inner_guard(self,actor,payload,outer):
        # The owner controls the OUTER autonomy level. Trusted provider
        # adapters independently enforce their own required approval and
        # scope. Never turn an inner ASK/DENY into automatic execution.
        adapter=self.adapters.get(payload['service'])
        predicate=getattr(adapter,'inner_policy',None)
        if not callable(predicate):
            return outer
        inner=predicate(actor,payload)
        if inner not in POLICIES:
            raise Denied('OWNER_POLICY_INNER_INVALID')
        return min((outer,inner),
                   key={'DENY':0,'ASK':1,'ALLOW':2}.__getitem__)

    def _policy(self, actor, payload):
        if self._constructing or self._composing:
            return super()._policy(actor,payload)
        # A private Core ASK adapter represents one synchronous READ
        # authorization. It has no machine-write policy coordinate or
        # externally addressable direct Core route.
        read_approval=getattr(self,'_owner_read_approval',None)
        if (read_approval is not None and
                (payload.get('service'),payload.get('operation')) ==
                ('read-authorization','approve')):
            return read_approval.policy(actor,payload)
        coord = (actor,payload["service"],payload["operation"],payload["target"])
        with self._db() as db:
            db.execute("BEGIN")
            _, overlay, legacy = self._snapshot(db)
            if coord in legacy and coord not in overlay:
                return "DENY"
            if (coord in overlay or
                    coord not in self.authority.baseline and coord[:3] in overlay):
                outer = self.authority.decision(coord,overlay,legacy)
                baseline = self.authority.baseline.get(coord,
                    self.authority.baseline.get(coord[:3]))
                if callable(baseline):
                    inner=super()._policy(actor,payload)
                    # Independent dynamic safety veto always wins.
                    if inner not in POLICIES:
                        raise Denied("OWNER_POLICY_CONDITIONAL_INVALID")
                    outer=min((outer,inner),key={"DENY":0,"ASK":1,"ALLOW":2}.__getitem__)
                return self._inner_guard(actor,payload,outer)
        return self._inner_guard(actor,payload,super()._policy(actor,payload))

    def _check_change(self, db, candidate):
        if type(candidate) is not dict or set(candidate)!=_FIELDS:
            raise Denied("OWNER_POLICY_CANDIDATE_SCHEMA")
        coord = self.coordinate(candidate)
        _, allowed = self.authority.admitted(coord)
        rev, overlay, legacy = self._snapshot(db)
        if (type(candidate["expectedRevision"]) is not int or
                candidate["expectedRevision"]!=rev or
                candidate["expectedPolicyVersion"]!=self._version(rev)):
            raise Stale("OWNER_POLICY_REVISION_CHANGED")
        current = self.authority.decision(coord,overlay,legacy)
        desired = candidate["desiredPolicy"]
        if (type(desired) is not str or desired not in allowed or
                desired==current or candidate["expectedPolicy"]!=current or
                type(candidate["reasonCode"]) is not str or
                not re.fullmatch(r"[A-Z][A-Z0-9_]{1,79}",candidate["reasonCode"])):
            raise Denied("OWNER_POLICY_TRANSITION_DENIED")
        # No new decisions while dispatched work could still perform effects.
        # Pending/approved fingerprints are revision-bound and cannot dispatch
        # on the previous revision. UNCERTAIN is preserved, never replayed.
        where = """actor=? AND json_extract(payload,'$.service')=?
                   AND json_extract(payload,'$.operation')=?"""
        args = coord
        if len(coord)==4:
            where += " AND json_extract(payload,'$.target')=?"
        counts = dict.fromkeys(("PENDING","APPROVED","DISPATCHED","UNCERTAIN"),0)
        for state, count in db.execute("SELECT state,COUNT(*) FROM requests WHERE "+where+
                " AND state IN ('PENDING','APPROVED','DISPATCHED','UNCERTAIN') GROUP BY state",args):
            counts[state]=count
        global_counts = dict.fromkeys(("PENDING","APPROVED","DISPATCHED"),0)
        for state, count in db.execute(
                "SELECT state,COUNT(*) FROM requests WHERE state IN ('PENDING','APPROVED','DISPATCHED') GROUP BY state"):
            global_counts[state]=count
        # The revision is global, including unrelated methods. Never invalidate
        # an in-flight effect or hide the broader pending-request consequence.
        if global_counts["DISPATCHED"]:
            raise Denied("OWNER_POLICY_DISPATCHED_OPERATION")
        exceptions = len({k for k in set(self.authority.baseline)|set(overlay)|set(legacy)
                          if len(k)==4 and len(coord)==3 and k[:3]==coord})
        return {"revision":rev,"oldPolicy":current,"newPolicy":desired,
                "allowedPolicies":sorted(allowed),"exactExceptions":exceptions,
                "unresolvedRequests":counts,"globalRevisionImpact":global_counts,
                "risk":"EXPANDS" if ("DENY","ASK","ALLOW").index(desired)>
                                     ("DENY","ASK","ALLOW").index(current) else "RESTRICTS"}

    def preview_change(self,candidate):
        with self._db() as db:
            db.execute("BEGIN")
            return self._check_change(db,candidate)

    def commit_verified_change(self, change, owner, *, now, verified):
        # Trusted in-process ceremony callback; no machine/HTTP access. The
        # caller checks one-shot proof, expiry, owner identity and source pins
        # again INSIDE this transaction, before the state CAS.
        candidate = {key:change[key] for key in _FIELDS}
        coord = self.coordinate(candidate)
        with self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            if verified() is not True:
                raise Denied("OWNER_POLICY_PROOF_INVALID")
            preview = self._check_change(db,candidate)
            # Audit/queue checks may take time: recheck proof and expiry at
            # the actual mutation boundary under the same SQLite lock.
            if verified() is not True:
                raise Denied("OWNER_POLICY_PROOF_INVALID")
            at = int(now())
            if at >= change["expiresAt"]:
                raise Denied("OWNER_POLICY_PROOF_EXPIRED")
            rev = preview["revision"]
            if change["authorityDigest"] != self.authority.sha or change["purpose"]!=_PURPOSE:
                raise Denied("OWNER_POLICY_BOUNDARY_CHANGED")
            db.execute("""INSERT INTO owner_local_policy_v2_rules VALUES(?,?)
                ON CONFLICT(coordinate) DO UPDATE SET policy=excluded.policy""",
                (canonical(list(coord)),candidate["desiredPolicy"]))
            db.execute("INSERT INTO owner_local_policy_v2_events VALUES(?,?,?,?,?)",
                       (rev+1,change["requestId"],at,owner,canonical(change)))
            db.execute("UPDATE owner_local_policy_v2_meta SET revision=revision+1 WHERE id=1 AND revision=?",(rev,))
            if db.execute("SELECT changes()").fetchone()[0]!=1:
                raise Stale("OWNER_POLICY_COMMIT_RACED")
            self._snapshot(db)
        return self.policy_readback(change["requestId"])

    def policy_readback(self,ident):
        if type(ident) is not str or str(uuid.UUID(ident))!=ident:
            raise Denied("OWNER_POLICY_REQUEST_ID_INVALID")
        with self._db() as db:
            db.execute("BEGIN")
            revision,_,_ = self._snapshot(db)
            row = db.execute("SELECT revision,change FROM owner_local_policy_v2_events WHERE request_id=?",(ident,)).fetchone()
            return {"requestId":ident,"found":row is not None,"currentRevision":revision,
                    "appliedRevision":row["revision"] if row else None,
                    "change":loads_strict(row["change"]) if row else None}

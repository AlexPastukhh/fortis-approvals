"""Phase 6C.1 owner-only, opt-in LOCAL DENY apply ceremony (unwired source).

Purpose-specific, fresh UV WebAuthn and same-Core-SQLite CAS + local audit.
NEVER an AI/machine route, not a provider grant editor and NOT deployed.
No ALLOW/ASK, denial removal, wildcard, PowerShell bypass, or old draft reuse.
"""
import hashlib
import re
import sqlite3
import uuid

from ..core import Denied, Stale, canonical
from ..owner_auth import OwnerWebAuthn, _hash
from .owner_policy_local_core_phase6c import LocalDenyCore

_PURPOSE = 'OWNER_LOCAL_EXACT_DENY_APPLY_V1'
_CEREMONY = 'owner_local_exact_deny_apply_v1'
_KEYS = frozenset(('actor', 'provider', 'operation', 'target',
                   'expectedConfiguredPolicy', 'expectedPolicyVersion',
                   'expectedRevision', 'reasonCode'))
_SCOPE = 'expectedConfiguredScope'
_ACTOR_KEYS = _KEYS | frozenset((_SCOPE,))
_DESCRIPTOR = _KEYS | frozenset(('purpose', 'requestId', 'newPolicy',
                                 'sourceDigest', 'credentialGenerationDigest',
                                 'expiresAt'))
_ACTOR_DESCRIPTOR = _DESCRIPTOR | frozenset((_SCOPE,))
_COORDINATE = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z')
_DIGEST = re.compile(r'[0-9a-f]{64}\Z')
_REASON = re.compile(r'[A-Z][A-Z0-9_]{1,79}\Z')


def _digest(value):
    if type(value) is not str or not _DIGEST.fullmatch(value):
        raise Denied('OWNER_LOCAL_APPLY_TRUSTED_DIGEST_INVALID')
    return value


class OwnerLocalDenyApply:
    """Source-only owner-side adapter. No machine ingress/HTTP is wired.

    Trusted constructor injection is NOT host attestation. A future release
    must pin and independently read installed source and credential identity.
    """

    def __init__(self, core, owner_auth, *, source_digest,
                 credential_generation_digest):
        if (type(core) is not LocalDenyCore or
                not isinstance(owner_auth, OwnerWebAuthn) or
                core.owner_verifier is not owner_auth):
            raise Denied('OWNER_LOCAL_APPLY_TRUSTED_BOUNDARY_REQUIRED')
        self.core = core
        self.auth = owner_auth
        self.source_digest = _digest(source_digest)
        self.credential_generation_digest = _digest(credential_generation_digest)

    @staticmethod
    def _candidate(candidate):
        if (type(candidate) is not dict or
                set(candidate) not in (_KEYS, _ACTOR_KEYS)):
            raise Denied('OWNER_LOCAL_APPLY_CANDIDATE_SCHEMA')
        if _SCOPE in candidate and candidate[_SCOPE] != 'actor':
            raise Denied('OWNER_LOCAL_APPLY_CONFIGURED_SCOPE_INVALID')
        coord = tuple(candidate[k] for k in ('actor','provider','operation','target'))
        if any(type(k) is not str or not _COORDINATE.fullmatch(k) for k in coord):
            raise Denied('OWNER_LOCAL_APPLY_COORDINATES_INVALID')
        if (type(candidate['expectedConfiguredPolicy']) is not str or
                candidate['expectedConfiguredPolicy'] not in ('ASK','ALLOW') or
                type(candidate['expectedRevision']) is not int or
                candidate['expectedRevision'] < 0 or
                type(candidate['expectedPolicyVersion']) is not str or
                type(candidate['reasonCode']) is not str or
                not _REASON.fullmatch(candidate['reasonCode'])):
            raise Denied('OWNER_LOCAL_APPLY_CHANGE_SCHEMA')
        return coord

    def _check(self, db, candidate):
        coord = self._candidate(candidate)
        revision = self.core._local_revision(db)
        if revision != candidate['expectedRevision']:
            raise Stale('OWNER_LOCAL_APPLY_STALE_REVISION')
        current = self.core._baseline_policy_version + '|owner-local-deny:' + str(revision)
        if candidate['expectedPolicyVersion'] != current:
            raise Stale('OWNER_LOCAL_APPLY_STALE_POLICY_VERSION')
        if candidate.get(_SCOPE) == 'actor':
            # The owner authorizes a DENY for ONE exact target inherited from
            # a configured actor-scoped literal rule, never an actor-wide edit.
            # An exact override, including DENY/callable, must not be hidden.
            if coord in self.core.policies:
                raise Denied('OWNER_LOCAL_APPLY_ACTOR_SCOPE_SHADOWED')
            configured = self.core.policies.get(coord[:3])
            if type(configured) is not str or configured != candidate['expectedConfiguredPolicy']:
                raise Denied('OWNER_LOCAL_APPLY_ACTOR_SCOPE_NOT_LITERAL')
        else:
            configured = self.core.policies.get(coord)
            if type(configured) is not str or configured != candidate['expectedConfiguredPolicy']:
                raise Denied('OWNER_LOCAL_APPLY_EXACT_CONFIGURED_GRANT_REQUIRED')
        if coord[1] not in self.core.adapters or not self.core.auth.active(coord[0]):
            raise Denied('OWNER_LOCAL_APPLY_GRANT_NOT_ACTIVE')
        if db.execute('''SELECT 1 FROM owner_local_denials WHERE
                actor=? AND service=? AND operation=? AND target=?''',
                coord).fetchone():
            raise Stale('OWNER_LOCAL_APPLY_ALREADY_DENIED')
        return revision

    def begin_deny(self, session, csrf, candidate):
        """Owner-only UI boundary should require exact Host/Origin/CSRF first."""
        if type(csrf) is not str or not csrf:
            raise Denied('OWNER_LOCAL_APPLY_CSRF_REQUIRED')
        owner = self.auth
        with owner.lock:
            owner.session(session, csrf)
            with self.core._db() as db:
                db.execute('BEGIN IMMEDIATE')
                self._check(db, candidate)
            now = int(owner.clock())
            change = {**candidate, 'purpose': _PURPOSE,
                      'newPolicy': 'DENY', 'requestId': str(uuid.uuid4()),
                      'sourceDigest': self.source_digest,
                      'credentialGenerationDigest': self.credential_generation_digest,
                      'expiresAt': now + 90}
            hashed = hashlib.sha256(canonical(change).encode()).hexdigest()
            started = owner._begin_assertion(_CEREMONY,
                session_hash=_hash(session), change_digest=hashed,
                expires_at=change['expiresAt'])
            return {'kind':'OWNER_LOCAL_DENY_APPLY_CEREMONY',
                    'ceremonyId':started['ceremonyId'],
                    'options':started['options'], 'change':change,
                    'changeDigest':hashed, 'newPolicy':'DENY',
                    'runtimeIntegrated':False}

    def finish_deny(self, session, csrf, ceremony, response, change):
        """One-time proof; atomically add EXACT DENY and audit in Core SQLite.

        A failed FIDO2 challenge is consumed. A lost response requires owner
        readback by the original UUID, not blind retry or new privilege.
        """
        if type(csrf) is not str or not csrf:
            raise Denied('OWNER_LOCAL_APPLY_CSRF_REQUIRED')
        owner = self.auth
        with owner.lock:
            owner.session(session, csrf)
            state, data = owner._take(ceremony, _CEREMONY)
            if (type(change) is not dict or
                    set(change) not in (_DESCRIPTOR, _ACTOR_DESCRIPTOR)):
                raise Denied('OWNER_LOCAL_APPLY_DESCRIPTOR_SCHEMA')
            core_fields = {key:change[key] for key in _KEYS}
            if _SCOPE in change:
                core_fields[_SCOPE] = change[_SCOPE]
            self._candidate(core_fields)
            try:
                if type(change['requestId']) is not str or str(uuid.UUID(change['requestId'])) != change['requestId']:
                    raise ValueError('request id')
            except (ValueError, TypeError, AttributeError):
                raise Denied('OWNER_LOCAL_APPLY_REQUEST_ID_INVALID') from None
            if (change['purpose'] != _PURPOSE or change['newPolicy'] != 'DENY' or
                    change['sourceDigest'] != self.source_digest or
                    change['credentialGenerationDigest'] != self.credential_generation_digest or
                    type(change['expiresAt']) is not int or
                    not int(owner.clock()) < change['expiresAt'] <= int(owner.clock())+90):
                raise Denied('OWNER_LOCAL_APPLY_DESCRIPTOR_INVALID')
            hashed = hashlib.sha256(canonical(change).encode()).hexdigest()
            if (data['session_hash'] != _hash(session) or
                    data['change_digest'] != hashed or
                    data['expires_at'] != change['expiresAt']):
                raise Denied('OWNER_LOCAL_APPLY_ASSERTION_BINDING_MISMATCH')
            verified_owner = owner._finish_assertion(state, data, response)
            if type(verified_owner) is not str or not verified_owner:
                raise Denied('OWNER_LOCAL_APPLY_VERIFICATION_FAILED')
            with self.core._db() as db:
                db.execute('BEGIN IMMEDIATE')
                previous = self._check(db, core_fields)
                coord = tuple(change[k] for k in ('actor','provider','operation','target'))
                db.execute('''INSERT INTO owner_local_denials
                    (actor,service,operation,target,decision) VALUES(?,?,?,?,'DENY')''',coord)
                db.execute('''UPDATE owner_local_policy_meta SET revision=revision+1
                    WHERE id=1 AND revision=? AND gate='READY' ''',(previous,))
                if db.execute('SELECT changes()').fetchone()[0] != 1:
                    raise Stale('OWNER_LOCAL_APPLY_COMMIT_RACED')
                db.execute('''INSERT INTO owner_local_policy_events
                    (request_id,at,owner,change,expected_revision,applied_revision)
                    VALUES(?,?,?,?,?,?)''',(
                        change['requestId'],int(owner.clock()),verified_owner,
                        canonical(change),previous,previous+1))
            # Separate readback: a response lost after commit is not proof
            # that the mutation did not happen.
            with self.core._db() as db:
                revision = self.core._local_revision(db)
                receipt = db.execute('''SELECT request_id,applied_revision
                    FROM owner_local_policy_events WHERE request_id=?''',
                    (change['requestId'],)).fetchone()
                denied = db.execute('''SELECT 1 FROM owner_local_denials
                    WHERE actor=? AND service=? AND operation=? AND target=?''',
                    coord).fetchone()
                if (receipt is None or denied is None or
                        receipt['applied_revision'] > revision):
                    raise Denied('OWNER_LOCAL_APPLY_READBACK_UNCONFIRMED')
            return {'kind':'OWNER_LOCAL_DENY_ONLY_COMMIT',
                    'requestId':change['requestId'],'oldPolicy':change['expectedConfiguredPolicy'],
                    'newPolicy':'DENY','appliedRevision':previous+1,
                    'currentRevision':revision,'localDenyCommitted':True,
                    'runtimeIntegrated':False,'canGrantAllow':False}

    def readback(self, session, csrf, request_id):
        """Owner-only lost-ACK readback, with no WebAuthn retry/side effect."""
        if type(csrf) is not str or not csrf:
            raise Denied('OWNER_LOCAL_APPLY_CSRF_REQUIRED')
        self.auth.session(session, csrf)
        try:
            if type(request_id) is not str or str(uuid.UUID(request_id)) != request_id:
                raise ValueError('request')
        except (ValueError,TypeError,AttributeError):
            raise Denied('OWNER_LOCAL_APPLY_REQUEST_ID_INVALID') from None
        with self.core._db() as db:
            revision = self.core._local_revision(db)
            row = db.execute('''SELECT applied_revision FROM owner_local_policy_events
                WHERE request_id=?''',(request_id,)).fetchone()
            return {'requestId':request_id,'found':row is not None,
                    'appliedRevision':row['applied_revision'] if row else None,
                    'currentRevision':revision,'runtimeIntegrated':False}

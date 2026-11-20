"""Phase 6B.3 INERT independent monotonically witnessed state verifier.

No provider/service implementation, grant activation, owner HTTP or Core hook.
The external authority MUST maintain a non-rollbackable latest checkpoint in
a separate trust domain and authenticate a fresh nonce in each readback.
A local file/DB or an AI-supplied callback is NOT a qualifying authority.
"""
import hashlib
import hmac
import re
import secrets

from ..core import Denied, Stale, canonical
from .owner_policy_active_store_phase6b import ProtectedActivePolicyStoreCandidate
from .owner_policy_audit_witness_phase6b2 import OwnerPolicyAuditWitnessCandidate

_PURPOSE = 'PHASE6B3_LATEST_PREPARED_CHECKPOINT_V1'
_FIELDS = frozenset(('purpose', 'nonce', 'installationDigest',
                     'epoch', 'gate', 'requestId', 'auditHeadHash',
                     'auditSequence', 'revision', 'baselineDigest',
                     'sourceDigest', 'credentialGenerationDigest',
                     'policyVersion'))
_WRAPPER = frozenset(('payload', 'hmacSha256'))
_DIGEST = re.compile(r'[0-9a-f]{64}\Z')


class MonotonicPolicyFenceCandidate:
    """Verify latest external quote against exact inert store and witness.

    Source-only. The injected quote issuer is a TRUSTED OWNER ISOLATE
    supplying the latest monotonic state, not an untrusted provider payload.
    There is no fallback, bootstrap, reset, commit or policy evaluation.
    """
    def __init__(self, *, store, witness, installation_digest,
                 quote_latest, owner_quote_key):
        if (type(store) is not ProtectedActivePolicyStoreCandidate or
                type(witness) is not OwnerPolicyAuditWitnessCandidate or
                witness.store is not store):
            raise Denied('PHASE6B3_TRUSTED_STORE_WITNESS_REQUIRED')
        if (type(installation_digest) is not str or
                _DIGEST.fullmatch(installation_digest) is None or
                type(owner_quote_key) is not bytes or
                not 32 <= len(owner_quote_key) <= 128 or
                not callable(quote_latest)):
            raise Denied('PHASE6B3_TRUSTED_OWNER_ANCHOR_REQUIRED')
        self.store = store
        self.witness = witness
        self.installation_digest = installation_digest
        self._quote_latest = quote_latest
        self._key = owner_quote_key

    def verify_prepared(self, *, request_id, audit_head):
        """Fail closed unless independently attested LATEST state matches.

        This is NOT an apply proof. In particular, no call to this method
        ever clears the store's PREPARED gate or changes effective permissions.
        """
        # Must verify both local sources before consulting external authority.
        verified = self.witness.verify(request_id=request_id,
                                       audit_head=audit_head)
        if (verified['signatureVerified'] is not True or
                verified['databaseMatchesWitness'] is not True or
                verified['canApply'] is not False):
            raise Denied('PHASE6B3_LOCAL_WITNESS_INVALID')
        snap = self.store.snapshot()
        if (snap['gate'] != 'PREPARED' or snap['revision'] != 0 or
                snap['auditSequence'] != 1 or
                snap['pendingRequestId'] != request_id or
                snap['auditHeadHash'] != audit_head or
                snap['canApply'] is not False or
                snap['runtimeIntegration'] != 'NOT_CONNECTED'):
            raise Stale('PHASE6B3_PREPARED_STATE_STALE')
        nonce = secrets.token_hex(32)  # unique fresh challenge: never caller-supplied
        try:
            quote = self._quote_latest(nonce)
        except Exception:
            # A 500/timeout is not evidence that the anchor is absent.
            raise Denied('PHASE6B3_OWNER_ANCHOR_UNAVAILABLE') from None
        if (type(quote) is not dict or set(quote) != _WRAPPER or
                type(quote.get('payload')) is not dict or
                set(quote['payload']) != _FIELDS or
                type(quote.get('hmacSha256')) is not str or
                _DIGEST.fullmatch(quote['hmacSha256']) is None or
                len(canonical(quote)) > 4096):
            raise Denied('PHASE6B3_QUOTE_SCHEMA_INVALID')
        payload = quote['payload']
        expected = dict(purpose=_PURPOSE, nonce=nonce,
                        installationDigest=self.installation_digest,
                        gate='PREPARED',requestId=request_id,
                        auditHeadHash=audit_head, auditSequence=1,
                        revision=0, baselineDigest=snap['baselineDigest'],
                        sourceDigest=self.store.source_digest,
                        credentialGenerationDigest=self.store.credential_generation_digest,
                        policyVersion=self.store.policy_version)
        if (type(payload['epoch']) is not int or payload['epoch'] < 1 or
                any(payload[field] != value for field,value in expected.items())):
            raise Stale('PHASE6B3_MONOTONIC_CHECKPOINT_MISMATCH')
        message = ('FORTIS_OWNER_MONOTONIC_QUOTE_V1\n'+canonical(payload)).encode()
        signature = hmac.new(self._key,message,hashlib.sha256).hexdigest()
        if not hmac.compare_digest(quote['hmacSha256'],signature):
            raise Denied('PHASE6B3_CHECKPOINT_SIGNATURE_INVALID')
        # Guard against mutation of local stores during external readback.
        self.witness.verify(request_id=request_id,audit_head=audit_head)
        again = self.store.snapshot()
        if again != snap:
            raise Stale('PHASE6B3_CONCURRENT_STORE_CHANGED')
        return {'kind':_PURPOSE, 'latestCheckpointVerified':True,
                'epoch':payload['epoch'], 'requestId':request_id,
                'auditHeadHash':audit_head,'canApply':False,
                'activePolicyChanged':False, 'runtimeIntegration':'NOT_CONNECTED'}

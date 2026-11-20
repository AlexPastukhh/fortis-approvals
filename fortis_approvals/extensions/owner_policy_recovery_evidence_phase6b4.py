"""Phase 6B.4 inert owner-side recovery *evidence* classifier.

This is an inspection-only source candidate. It never heals a store, issues
WebAuthn, clears PREPARED, emits an owner approval or authorizes an action.
All decisions are HOLD, including externally attested PREPARED: no policy
commit/release mechanism exists and installed Core is not using this store.
"""
import sqlite3

from ..core import Denied, Stale
from .owner_policy_active_store_phase6b import ProtectedActivePolicyStoreCandidate
from .owner_policy_audit_witness_phase6b2 import OwnerPolicyAuditWitnessCandidate
from .owner_policy_monotonic_fence_phase6b3 import MonotonicPolicyFenceCandidate


_CODES = frozenset((
    'PHASE6B4_LOCAL_STORE_UNVERIFIABLE',
    'PHASE6B4_NOT_PREPARED',
    'PHASE6B4_REQUEST_OR_HEAD_MISMATCH',
    'PHASE6B4_WITNESS_UNVERIFIABLE',
    'PHASE6B4_EXTERNAL_CHECKPOINT_UNVERIFIABLE',
    'PHASE6B4_ATTESTED_PREPARED_STILL_BLOCKED',
))


def _hold(code, *, local_verified=False, witness_verified=False,
          latest_checkpoint_verified=False):
    if code not in _CODES:
        raise Denied('PHASE6B4_CLASSIFICATION_INVALID')
    return {
        'schemaVersion': 1, 'kind': 'PHASE6B4_OWNER_RECOVERY_EVIDENCE_ONLY',
        'classification': code, 'disposition': 'HOLD_OWNER_REVIEW',
        'localStoreVerified': local_verified,
        'witnessVerified': witness_verified,
        'latestCheckpointVerified': latest_checkpoint_verified,
        'canApply': False, 'canRecoverAutomatically': False,
        'canResumeDispatch': False, 'activePolicyChanged': False,
        'inFlightRequestsReconciled': False, 'policyCommitConfirmed': False,
        'runtimeIntegration': 'NOT_CONNECTED',
    }


class OwnerPolicyRecoveryInspectorCandidate:
    """Inspect exactly one inert prepared revision with three independent reads.

    The Phase 6B.3 fence requires a truly independent owner monotonic authority;
    supplying an in-memory mock is allowed ONLY for offline tests, not for
    deployment or security acceptance.
    """
    def __init__(self, *, store, witness, monotonic_fence):
        if (type(store) is not ProtectedActivePolicyStoreCandidate or
                type(witness) is not OwnerPolicyAuditWitnessCandidate or
                type(monotonic_fence) is not MonotonicPolicyFenceCandidate or
                witness.store is not store or monotonic_fence.store is not store or
                monotonic_fence.witness is not witness):
            raise Denied('PHASE6B4_TRUSTED_EVIDENCE_OBJECTS_REQUIRED')
        self.store = store
        self.witness = witness
        self.monotonic_fence = monotonic_fence

    def inspect(self, *, request_id, audit_head):
        """Read-only recovery classification. NEVER a release/authorization.

        A missing witness, latest checkpoint, valid request or readback is
        always a HOLD. Errors are redacted to stable classes; do not convert
        absence of a remote response into proof that it did not execute.
        """
        # Do not call an external authority with a malformed identity.
        if (type(request_id) is not str or len(request_id) != 36 or
                type(audit_head) is not str or len(audit_head) != 64):
            return _hold('PHASE6B4_REQUEST_OR_HEAD_MISMATCH')
        try:
            snap = self.store.snapshot()
        except (Denied, Stale, sqlite3.Error, OSError, ValueError, TypeError):
            return _hold('PHASE6B4_LOCAL_STORE_UNVERIFIABLE')
        if snap['gate'] != 'PREPARED':
            # READY alone is not proof of absence of a rolled-back PREPARED.
            return _hold('PHASE6B4_NOT_PREPARED', local_verified=True)
        if (snap['revision'] != 0 or snap['auditSequence'] != 1 or
                snap['pendingRequestId'] != request_id or
                snap['auditHeadHash'] != audit_head or
                snap['canApply'] is not False or
                snap['runtimeIntegration'] != 'NOT_CONNECTED'):
            return _hold('PHASE6B4_REQUEST_OR_HEAD_MISMATCH', local_verified=True)
        try:
            witness = self.witness.verify(request_id=request_id,
                                          audit_head=audit_head)
            if (witness['signatureVerified'] is not True or
                    witness['databaseMatchesWitness'] is not True or
                    witness['canApply'] is not False):
                return _hold('PHASE6B4_WITNESS_UNVERIFIABLE',
                             local_verified=True)
        except (Denied, Stale, sqlite3.Error, OSError, ValueError, TypeError):
            return _hold('PHASE6B4_WITNESS_UNVERIFIABLE',
                         local_verified=True)
        try:
            quote = self.monotonic_fence.verify_prepared(
                request_id=request_id, audit_head=audit_head)
            if (quote['latestCheckpointVerified'] is not True or
                    quote['canApply'] is not False or
                    quote['runtimeIntegration'] != 'NOT_CONNECTED'):
                return _hold('PHASE6B4_EXTERNAL_CHECKPOINT_UNVERIFIABLE',
                             local_verified=True, witness_verified=True)
        except (Denied, Stale, sqlite3.Error, OSError, ValueError, TypeError):
            return _hold('PHASE6B4_EXTERNAL_CHECKPOINT_UNVERIFIABLE',
                         local_verified=True, witness_verified=True)
        # Even fresh authenticated latest state does NOT verify a real active
        # commit, absence of in-flight effects, or an owner WebAuthn ceremony.
        return _hold('PHASE6B4_ATTESTED_PREPARED_STILL_BLOCKED',
                     local_verified=True,witness_verified=True,
                     latest_checkpoint_verified=True)

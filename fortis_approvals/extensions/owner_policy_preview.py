"""Pure, owner-session-only policy change preview. NO policy mutations.

Do not expand this module into an apply path without a separately reviewed
fresh WebAuthn ceremony, durable versioned store and concurrent CAS.
"""
import hashlib
import sqlite3

from ..core import Denied, canonical
from .model import bounded
from .owner_inventory import owner_policy_inventory


POLICIES = frozenset(('DENY', 'ASK', 'ALLOW'))
CANDIDATE_FIELDS = frozenset(('provider', 'operation', 'actor', 'target',
                             'desiredPolicy', 'expectedPolicyVersion', 'expectedConfiguredPolicy'))


def _open_requests(core, actor, service, operation, target):
    # Query the real Core state; do not infer effects from absence of receipts.
    # Do not return request params, actor credentials or audit contents.
    statuses = {s: 0 for s in ('PENDING', 'APPROVED', 'DISPATCHED', 'UNCERTAIN')}
    try:
        with core._db() as db:
            cursor = db.execute("""SELECT state, COUNT(*) AS amount FROM requests
                WHERE actor=? AND json_extract(payload,'$.service')=?
                  AND json_extract(payload,'$.operation')=?
                  AND json_extract(payload,'$.target')=?
                  AND state IN ('PENDING','APPROVED','DISPATCHED','UNCERTAIN')
                GROUP BY state""", (actor, service, operation, target))
            for state, amount in cursor:
                if state in statuses:
                    statuses[state] = amount
    except sqlite3.DatabaseError:
        raise Denied('OWNER_POLICY_PREVIEW_PENDING_STATE_UNAVAILABLE') from None
    return statuses


def preview_policy_change(core, extension_runtime, candidate):
    """Validate one existing exact-scope row and return read-only candidate diff."""
    if type(candidate) is not dict or set(candidate) != CANDIDATE_FIELDS:
        raise Denied('OWNER_POLICY_PREVIEW_SCHEMA')
    for field in ('provider', 'operation', 'actor', 'target'):
        value = candidate[field]
        if type(value) is not str or not 1 <= len(value) <= 120:
            raise Denied('OWNER_POLICY_PREVIEW_COORDINATES')
    target_policy = candidate['desiredPolicy']
    previous = candidate['expectedConfiguredPolicy']
    if type(target_policy) is not str or target_policy not in POLICIES or        type(previous) is not str or previous not in POLICIES:
        raise Denied('OWNER_POLICY_PREVIEW_POLICY')
    if type(candidate['expectedPolicyVersion']) is not str or not        1 <= len(candidate['expectedPolicyVersion']) <= 512:
        raise Denied('OWNER_POLICY_PREVIEW_VERSION')
    # A preview is bound to one loaded version and one exact configured row.
    # Do not enable new grants or overwrite global/actor predicates by guessing.
    if candidate['expectedPolicyVersion'] != core.policy_version:
        raise Denied('OWNER_POLICY_PREVIEW_STALE_VERSION')
    inventory = owner_policy_inventory(core, extension_runtime)
    rows = [row for row in inventory['operations']
        if row['provider'] == candidate['provider'] and
           row['operation'] == candidate['operation'] and
           row['actor'] == candidate['actor'] and
           row['target'] == candidate['target'] and
           row['scope'] == 'exact' and row['configured'] and row['active']]
    if len(rows) != 1:
        raise Denied('OWNER_POLICY_PREVIEW_EXACT_GRANT_REQUIRED')
    current = rows[0]
    if current['configuredPolicy'] != previous:
        raise Denied('OWNER_POLICY_PREVIEW_STALE_RULE')
    if current['configuredPolicy'] not in POLICIES or current['effectivePolicy'] not in POLICIES:
        raise Denied('OWNER_POLICY_PREVIEW_UNKNOWN_EFFECTIVE_RULE')
    if current['providerType'] not in ('native', 'extension'):
        raise Denied('OWNER_POLICY_PREVIEW_PROVIDER_TYPE')
    # No speculative upstream requests or credential generation access.
    pending = _open_requests(core, candidate['actor'],candidate['provider'],
                             candidate['operation'],candidate['target'])
    changed = previous != target_policy
    high_risk = (target_policy == 'ALLOW' and previous != 'ALLOW') or                 current['kind'] != 'read' or candidate['provider'] == 'powershell'
    risk = ('CRITICAL' if candidate['provider'] == 'powershell' else
            'HIGH' if high_risk else 'LOW')
    identity = {'provider': candidate['provider'], 'operation': candidate['operation'],
        'actor': candidate['actor'], 'target': candidate['target'],
        'from': previous, 'to': target_policy,
        'policyVersion': core.policy_version,
        'sourceDigest': (next((p['sourceDigest'] for p in inventory['providers']
            if p['provider'] == current['provider']), None)),
        'configurationDigest': (extension_runtime.digest if extension_runtime is not None
            else None)}
    return bounded({'schemaVersion': 1, 'kind': 'OWNER_READ_ONLY_POLICY_PREVIEW',
        'scope': 'EXACT_EXISTING_GRANT_ONLY', 'identity': identity,
        'previewFingerprint': hashlib.sha256(canonical(identity).encode()).hexdigest(),
        'current': {'configuredPolicy': previous,
                    'effectivePolicy': current['effectivePolicy']},
        'proposed': {'configuredPolicy': target_policy,
                     'effectivePolicy': target_policy},
        'changed': changed, 'risk': risk,
        'unresolvedRequests': pending,
        'requires': ['FRESH_STRONG_OWNER_WEBAUTHN', 'POLICY_STORE_CAS',
                     'AUDIT_AND_ROLLBACK', 'FRESH_CREDENTIAL_AND_TARGET_READBACK'],
        'canApply': False, 'applyEnabled': False,
        'note': 'NOT_AUTHORIZATION_OR_APPLY; no policy, credential or Core state was changed',
        'upstreamStatus': 'UNVERIFIED'}, 32768)

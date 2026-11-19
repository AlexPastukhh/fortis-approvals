"""Exact, short-lived WebAuthn challenge descriptor for INACTIVE policy draft review.

Pure readback only. The WebAuthn assertion is NOT permission to activate policy.
Do not reuse a review result as a future authorization proof.
"""
import hashlib
import re
import uuid

from ..core import Denied, Stale, canonical


FIELDS = frozenset(('purpose', 'requestId', 'actor', 'provider', 'operation', 'target',
    'oldPolicy', 'newPolicy', 'expectedRevision', 'expectedAuditHash',
    'baselineDigest', 'sourceDigest', 'credentialGenerationDigest',
    'policyVersion', 'reasonCode', 'expiresAt'))
COORD = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z')
DIGEST = re.compile(r'[0-9a-f]{64}\Z')
REASON = re.compile(r'[A-Z][A-Z0-9_]{1,79}\Z')
POLICIES = frozenset(('DENY', 'ASK', 'ALLOW'))
PURPOSE = 'REVIEW_INACTIVE_POLICY_DRAFT_V1'


def checked_change(ledger, change, now):
    """Pin exact policy source, credentials, revision and grant without mutations."""
    if type(change) is not dict or set(change) != FIELDS:
        raise Denied('POLICY_CHANGE_SCHEMA_INVALID')
    if type(now) is not int:
        raise Denied('POLICY_CHANGE_CLOCK_INVALID')
    if change['purpose'] != PURPOSE or type(change['purpose']) is not str:
        raise Denied('POLICY_CHANGE_PURPOSE_INVALID')
    ident = change['requestId']
    try:
        if type(ident) is not str or str(uuid.UUID(ident)) != ident:
            raise ValueError('uuid')
    except (ValueError, TypeError, AttributeError):
        raise Denied('POLICY_CHANGE_REQUEST_ID_INVALID') from None
    coordinate = tuple(change.get(k) for k in ('actor', 'provider', 'operation', 'target'))
    if not all(type(x) is str and COORD.fullmatch(x) for x in coordinate):
        raise Denied('POLICY_CHANGE_COORDINATES_INVALID')
    old, new = change['oldPolicy'], change['newPolicy']
    if type(old) is not str or type(new) is not str or old not in POLICIES or new not in POLICIES or old == new:
        raise Denied('POLICY_CHANGE_TRANSITION_INVALID')
    if type(change['expectedRevision']) is not int or change['expectedRevision'] < 0:
        raise Denied('POLICY_CHANGE_REVISION_INVALID')
    for key in ('expectedAuditHash','baselineDigest','sourceDigest','credentialGenerationDigest'):
        value = change[key]
        if type(value) is not str or not DIGEST.fullmatch(value):
            raise Denied('POLICY_CHANGE_DIGEST_INVALID')
    if type(change['policyVersion']) is not str or not 1 <= len(change['policyVersion']) <= 512:
        raise Denied('POLICY_CHANGE_POLICY_VERSION_INVALID')
    if type(change['reasonCode']) is not str or not REASON.fullmatch(change['reasonCode']):
        raise Denied('POLICY_CHANGE_REASON_INVALID')
    expiry = change['expiresAt']
    if type(expiry) is not int or not now < expiry <= now + 120:
        raise Denied('POLICY_CHANGE_EXPIRED_OR_TOO_LONG')
    # This is a validated, pinned snapshot from the *inactive* draft ledger.
    snapshot = ledger.snapshot()
    if snapshot['kind'] != 'INACTIVE_POLICY_DRAFT_LEDGER' or snapshot['canApply'] is not False or \
       snapshot['runtimeIntegration'] != 'NOT_CONNECTED':
        raise Denied('POLICY_CHANGE_UNEXPECTED_ACTIVE_STORE')
    for key, value in (('revision',change['expectedRevision']),
        ('auditHash',change['expectedAuditHash']),
        ('baselineDigest',change['baselineDigest']),
        ('sourceDigest',change['sourceDigest']),
        ('credentialGenerationDigest',change['credentialGenerationDigest']),
        ('policyVersion',change['policyVersion'])):
        if snapshot[key] != value:
            raise Stale('POLICY_CHANGE_STALE_' + key.upper())
    rows = [row for row in snapshot['drafts'] if
        tuple(row[k] for k in ('actor','provider','operation','target')) == coordinate]
    if len(rows) != 1:
        raise Denied('POLICY_CHANGE_UNKNOWN_EXACT_GRANT')
    if rows[0]['draftPolicy'] != old:
        raise Stale('POLICY_CHANGE_STALE_OLD_POLICY')
    digest = hashlib.sha256(canonical(change).encode('utf-8')).hexdigest()
    return {'digest':digest, 'expiry':expiry, 'coordinate':coordinate}

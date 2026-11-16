"""Source-only P4 Ed25519 ASK proof builder. Not an admitted Mirror WRITE.

Only a trusted, post-Core-approval extension execution context can call this
module. The owner provisions seed material separately in CredentialVault, and
Windows must pin the matching public key before any WRITE admission. This
module never selects credentials, URLs, keys or policy from machine params.
"""
import base64
import binascii
import hashlib
import re
import time

from fortis_approvals.core import Denied, canonical
from fortis_approvals.extensions.model import check
from fortis_approvals.extensions.vault import Secret

DOMAIN = b'FORTIS-MIRROR-ASK-V1\n'
IDENTITY_FIELDS = frozenset({'issuer', 'audience', 'service', 'operation', 'requestId',
    'actor', 'repoId', 'previewId', 'expectedHead', 'targetSha', 'configGeneration'})
UUID = r'[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}'
REPO = r'[A-Za-z0-9_][A-Za-z0-9_.-]{0,119}'
ACTOR = r'[A-Za-z0-9_.:-]{1,120}'
SHA = r'[0-9a-f]{40}'
DIGEST = r'[0-9a-f]{64}'
KEY_ID = r'[A-Za-z0-9_.-]{1,64}'
MAX_TIME = 4102444800


def _matches(value, expression):
    return type(value) is str and re.fullmatch(expression, value) is not None


def _identity(identity):
    check(type(identity) is dict and set(identity) == IDENTITY_FIELDS,
          'MIRROR_SIGNING_IDENTITY_INVALID')
    for name, expected in [('issuer', 'fortis-gateway'), ('audience', 'fortis-mirror'),
                           ('service', 'mirror'), ('operation', 'execute_windows_pull_v2')]:
        check(identity[name] == expected and type(identity[name]) is str,
              'MIRROR_SIGNING_IDENTITY_INVALID')
    for name, expression in [('requestId', UUID), ('actor', ACTOR), ('repoId', REPO),
                             ('previewId', UUID), ('expectedHead', SHA),
                             ('targetSha', SHA), ('configGeneration', DIGEST)]:
        check(_matches(identity[name], expression), 'MIRROR_SIGNING_IDENTITY_INVALID')
    check(identity['expectedHead'] != identity['targetSha'], 'MIRROR_SIGNING_IDENTITY_INVALID')
    return identity


def _seed(secret):
    check(isinstance(secret, Secret), 'MIRROR_SIGNING_CREDENTIAL_UNAVAILABLE')
    value = secret.reveal()
    check(_matches(value, r'[A-Za-z0-9_-]{43}'), 'MIRROR_SIGNING_KEY_INVALID')
    try:
        decoded = base64.urlsafe_b64decode(value + '=')
        check(len(decoded) == 32 and
              base64.urlsafe_b64encode(decoded).decode('ascii').rstrip('=') == value,
              'MIRROR_SIGNING_KEY_INVALID')
    except (ValueError, binascii.Error):
        raise Denied('MIRROR_SIGNING_KEY_INVALID') from None
    return decoded


def sign_dispatch_identity(identity, *, key_id, secret, preview_expires_at, now=None):
    """Sign closed ASCII claims with one fixed owner-pinned Ed25519 key.

    `identity` and `preview_expires_at` must come from a checked persisted
    preview, not a caller payload. This function is cryptographic construction,
    not persisted-preview authorization or transport admission.
    """
    _identity(identity)
    check(_matches(key_id, KEY_ID), 'MIRROR_SIGNING_KEY_ID_INVALID')
    issued = int(time.time()) if now is None else now
    check(type(issued) is int and 0 <= issued < MAX_TIME and
          type(preview_expires_at) is int and 0 < preview_expires_at <= MAX_TIME,
          'MIRROR_SIGNING_TIME_INVALID')
    expires = min(issued + 120, preview_expires_at)
    check(issued < expires <= issued + 120, 'MIRROR_SIGNING_PREVIEW_EXPIRED')
    # Fingerprint binds only the immutable identity. Issued/expiry times
    # deliberately do not change that identity on retransmission.
    fingerprint = hashlib.sha256(canonical(identity).encode('ascii')).hexdigest()
    claims = {**identity, 'fingerprint': fingerprint,
              'issuedAt': issued, 'expiresAt': expires}
    signed = DOMAIN + canonical(claims).encode('ascii')
    key_bytes = _seed(secret)
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    except ImportError:
        raise Denied('MIRROR_SIGNING_DEPENDENCY_UNAVAILABLE') from None
    try:
        signature = Ed25519PrivateKey.from_private_bytes(key_bytes).sign(signed)
    except (ValueError, TypeError):
        raise Denied('MIRROR_SIGNING_KEY_INVALID') from None
    check(len(signature) == 64, 'MIRROR_SIGNING_SIGNATURE_INVALID')
    return {'schemaVersion': 1, 'keyId': key_id, 'claims': claims,
            'signature': base64.urlsafe_b64encode(signature).decode('ascii').rstrip('=')}

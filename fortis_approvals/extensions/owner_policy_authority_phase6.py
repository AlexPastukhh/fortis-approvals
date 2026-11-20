"""Phase 6A pure policy-authority admission candidate. NO active policy writes.

This deliberately rejects ambiguous scopes and never calls policy predicates,
provider adapters, vaults, WebAuthn endpoints or protected storage.
Not used by Core, Owner Portal or any machine route.
"""
import hashlib
from types import MappingProxyType

from ..core import Denied, canonical


POLICIES = frozenset(('DENY', 'ASK', 'ALLOW'))
_COORD_FIELDS = frozenset(('actor', 'provider', 'operation', 'target'))
_CHANGE_FIELDS = _COORD_FIELDS | frozenset(('expectedPolicy', 'desiredPolicy'))
_ALLOWED_CHARS = frozenset('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.:-')


def _name(value):
    if type(value) is not str or not 1 <= len(value) <= 120 or \
            value[0] not in _ALLOWED_CHARS or \
            any(char not in _ALLOWED_CHARS for char in value):
        raise Denied('PHASE6_COORDINATE_INVALID')
    return value


def _coordinate(value):
    if type(value) is not tuple or len(value) != 4:
        raise Denied('PHASE6_COORDINATE_INVALID')
    return tuple(_name(part) for part in value)


def _rule(value):
    if type(value) is not str or value not in POLICIES:
        raise Denied('PHASE6_LITERAL_POLICY_REQUIRED')
    return value


class ExactPolicyBaseline:
    """Frozen candidate baseline; no claims about runtime installation."""

    def __init__(self, *, core_policies, loaded_services, extension_rules=None,
                 extension_services=frozenset()):
        if (type(core_policies) is not dict or
                type(loaded_services) not in (dict, set, frozenset) or
                type(extension_rules) is not dict and extension_rules is not None):
            raise Denied('PHASE6_BASELINE_SCHEMA')
        services = set(loaded_services)
        if type(extension_services) not in (set, frozenset) or not extension_services <= services:
            raise Denied('PHASE6_EXTENSION_SERVICES_INVALID')
        if any(type(s) is not str for s in services | extension_services):
            raise Denied('PHASE6_BASELINE_SERVICES')
        extensions = dict(extension_rules or {})
        for key, value in extensions.items():
            _coordinate(key)
            _rule(value)
            if key[1] not in extension_services:
                raise Denied('PHASE6_EXTENSION_NOT_LOADED')
        rules = {}
        broad = set()
        for key, value in core_policies.items():
            if type(key) is not tuple or len(key) not in (2, 3, 4) or \
                    any(type(s) is not str for s in key):
                raise Denied('PHASE6_UNKNOWN_POLICY_SCOPE')
            if len(key) == 4:
                coord = _coordinate(key)
                if coord[1] not in services:
                    raise Denied('PHASE6_PROVIDER_NOT_LOADED')
                rules[coord] = _rule(value)
            else:
                # Broad or conditional policies remain trusted legacy config,
                # but may not be silently converted into exact active grants.
                broad.add((key[-2], key[-1]))
        for coord in rules:
            if (coord[1], coord[2]) in broad:
                raise Denied('PHASE6_AMBIGUOUS_INHERITED_POLICY')
        for coord, policy in extensions.items():
            if coord not in rules or rules[coord] != policy:
                raise Denied('PHASE6_EXTENSION_CORE_AUTHORITY_DRIFT')
        # Do not accidentally treat a native Core exact rule as an extension
        # without a matching configured extension grant.
        for coord in rules:
            if coord[1] in extension_services and coord not in extensions:
                raise Denied('PHASE6_EXTENSION_GRANT_MISSING')
        self.rules = MappingProxyType(dict(sorted(rules.items())))
        self.digest = hashlib.sha256(canonical(
            [[*coord, rule] for coord, rule in self.rules.items()]).encode()).hexdigest()

    def preview(self, change):
        """Strict exact transition descriptor for future owner-only design.

        Never returns apply permission. Caller must separately attest live
        identity and grants; no AI-facing endpoint is provided.
        """
        if type(change) is not dict or set(change) != _CHANGE_FIELDS:
            raise Denied('PHASE6_CHANGE_SCHEMA')
        coord = _coordinate(tuple(change[k] for k in
            ('actor', 'provider', 'operation', 'target')))
        if coord not in self.rules:
            raise Denied('PHASE6_UNKNOWN_EXACT_GRANT')
        old = _rule(change['expectedPolicy'])
        new = _rule(change['desiredPolicy'])
        if old != self.rules[coord]:
            raise Denied('PHASE6_STALE_POLICY')
        if new == old:
            raise Denied('PHASE6_NOOP')
        if coord[1] == 'powershell' and coord[2] == 'execute' and new == 'ALLOW':
            # No trusted evidence for Executor Dynamic ASK/V2 here.
            raise Denied('PHASE6_POWERSHELL_V2_GATE_REQUIRED')
        return {'scope': 'EXACT_EXISTING_GRANT_ONLY',
                'identity': {'actor': coord[0], 'provider': coord[1],
                    'operation': coord[2], 'target': coord[3]},
                'oldPolicy': old, 'desiredPolicy': new,
                'baselineDigest': self.digest, 'canApply': False,
                'policyActivated': False}

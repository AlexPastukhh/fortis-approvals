"""Versioned own-label evidence mode; existing AI global investigation is unchanged."""
from ...core import Denied
from .publisher_profile import ACTOR, REPOSITORY, WRITES


def own_label_evidence(cap):
    scope = cap.get('requestEvidence')
    if scope is None:
        return None
    if (type(scope) is not dict or type(scope.get('version')) is not int or scope['version'] != 1 or
            scope.get('scope') != 'own-release-label-requests' or scope.get('actor') != ACTOR or
            scope.get('repository') != REPOSITORY or scope.get('readOnly') is not True or
            scope.get('crossActorDetails') is not False or type(scope.get('operations')) is not list or
            len(scope['operations']) != len(WRITES) or
            any(type(op) is not str for op in scope['operations']) or set(scope['operations']) != WRITES or
            (cap.get('globalRequestInventory') or {}).get('crossActorDetails') is True):
        raise Denied('OWN_LABEL_EVIDENCE_CAPABILITY_INVALID')
    return scope


def allow_intent_details(cap, intent):
    scope = own_label_evidence(cap)
    if scope is None:
        return (cap.get('globalRequestInventory') or {}).get('crossActorDetails') is True
    return (intent.get('kind') == 'github' and intent.get('operation') in WRITES and
            intent.get('repository') == REPOSITORY)


def check_own_record(scope, record):
    if scope is None:
        return
    request = record.get('request', {})
    if (record.get('actor') != ACTOR or request.get('service') != 'github' or
            request.get('target') != REPOSITORY or request.get('operation') not in WRITES):
        raise Denied('OWN_LABEL_EVIDENCE_RECORD_INVALID')

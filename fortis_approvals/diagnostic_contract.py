"""Additive, read-only error-diagnostic capability contract (NOT an effect verdict).

Wire schema remains unchanged for legacy clients. New clients interpret
optional fixed version headers; never enable replays or owner decisions.
"""
from copy import deepcopy

DIAGNOSTIC_VERSION=2
DIAGNOSTIC_VERSION_TEXT='2'
DIAGNOSTIC_VERSION_HEADER='X-Fortis-Diagnostic-Contract'

_CAPABILITY={
    'schemaVersion':DIAGNOSTIC_VERSION,
    'githubReadErrors':'bounded-code-and-signal-v1',
    'githubReadMetadata':'bounded-route-method-reset-v1',
    'preCoreAdmission':'typed-github-validation-v1',
    'githubWriteAudit':{
        'phaseCodes':['push_commits','create_pull_request'],
        'prCreateCheckpoints':'native-core-bound-only',
    },
    'artifactFailure':'bounded-code-and-stage-v2',
    'newBranchHeadMismatch':'GIT_EXPECTED_REMOTE_HEAD_MISMATCH',
    'incidentEvidence':'bounded-read-only-projection-v2',
    'effectAssessment':'NOT_AN_OUTCOME_VERDICT',
    'outcomeResolver':'NOT_IMPLEMENTED',
    'automaticRetry':False,
}

def advertised_diagnostic_capability():
    """Safe for the existing machine actor's /workspace/capabilities READ."""
    return deepcopy(_CAPABILITY)

def inspect_diagnostic_capability(data):
    """Treat missing/unfamiliar feature declarations as unsupported.

    This is a schema check, not proof that the runtime can safely retry.
    """
    if data is None:
        return {'status':'NOT_ADVERTISED','version':None,'automaticRetry':False}
    if (type(data) is dict and set(data)==set(_CAPABILITY) and
            all(type(data[key]) is type(value) and data[key]==value
                for key,value in _CAPABILITY.items())):
        return {'status':'SUPPORTED','version':DIAGNOSTIC_VERSION,
                'automaticRetry':False}
    return {'status':'UNRECOGNIZED','version':None,'automaticRetry':False}

def compatible_error_header(value):
    """No header is legacy v1; an explicit header must match v2 exactly."""
    return value is None or type(value) is str and value==DIAGNOSTIC_VERSION_TEXT

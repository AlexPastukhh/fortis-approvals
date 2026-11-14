"""Bounded native Git artifact error diagnostics. No non-effect claim.

The artifact route performs local validation and may write an artifact store.
An HTTP error does not establish that the old request was never dispatched.
"""
from ..core import Denied, Stale

ARTIFACT_PHASE_HEADER='X-Fortis-Artifact-Phase'
ARTIFACT_VALIDATION_PHASES=frozenset({
    'SETUP','FETCH_MAIN','READ_REMOTE_REFS','FETCH_TASK','BUNDLE_IDENTITY',
    'BUNDLE_IMPORT','COMMIT_INTEGRITY','ANCESTRY','PATH_PROJECTION',
})

def bounded_artifact_phase(exc):
    phase=getattr(exc,'artifact_phase',None)
    return (phase if isinstance(exc,(Denied,Stale)) and
            type(phase) is str and phase in ARTIFACT_VALIDATION_PHASES else None)

ARTIFACT_FAILURE_HEADER='X-Fortis-Artifact-Diagnostic'
ARTIFACT_FAILURE_CODES=frozenset({
    'WORKFLOW_PARAMS_INVALID','WORKFLOW_SHA_INVALID','WORKFLOW_TASK_INVALID',
    'GIT_ARTIFACT_CHANGED','GIT_BUNDLE_LIMIT','GIT_BUNDLE_INVALID',
    'GIT_REPOSITORY_DENIED','GIT_BUNDLE_REF_MISMATCH',
    'GIT_REMOTE_HEAD_CHANGED','GIT_EXPECTED_REMOTE_HEAD_MISMATCH','GIT_FETCH_HEAD_CHANGED',
    'GIT_NON_FAST_FORWARD_DENIED','GIT_COMMIT_REQUIRED',
    'GIT_COMMAND_FAILED','GIT_COMMIT_RANGE_LIMIT',
    'GIT_OBJECT_LIMIT','GIT_OUTPUT_LIMIT','GIT_CHANGED_PATH_LIMIT',
    'GIT_WORKFLOW_PREVIEW_LIMIT','GIT_SOURCE_HEAD_CHANGED',
    'GIT_ARTIFACT_REJECTION_UNCLASSIFIED',
})

def bounded_artifact_error(exc):
    """Never forward a raw exception, Git stderr or user-supplied value."""
    if not isinstance(exc,(Denied,Stale)):
        return 'GIT_ARTIFACT_REJECTION_UNCLASSIFIED'
    code=exc.args[0] if len(exc.args)==1 else None
    if type(code) is str and code in ARTIFACT_FAILURE_CODES:
        return code
    return 'GIT_ARTIFACT_REJECTION_UNCLASSIFIED'

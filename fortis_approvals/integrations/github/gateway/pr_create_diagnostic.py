"""Closed PR-create phase observations; no outcome verdict or replay permission."""
from contextlib import contextmanager

from ....core import Stale
from ..read_failure_codes import READ_FAILURE_CODES
from .transport import GitHubTransportError

PR_CREATE_PHASES=frozenset({
    'revalidate', 'post', 'post_response', 'readback', 'receipt'
})
PR_CREATE_CODES=READ_FAILURE_CODES | frozenset({
    'GITHUB_PR_CREATE_STEP_UNCONFIRMED',
    'GITHUB_PR_READBACK_UNCONFIRMED',
})

class GitHubPRCreateFailure(GitHubTransportError):
    """A bounded observed phase, never proof that a remote PR was/wasn't created."""
    def __init__(self, phase, code):
        if type(phase) is not str or phase not in PR_CREATE_PHASES:
            raise ValueError('GITHUB_PR_CREATE_PHASE_INVALID')
        safe=(code if type(code) is str and code in PR_CREATE_CODES
              else 'GITHUB_PR_CREATE_STEP_UNCONFIRMED')
        super().__init__(safe)
        self.phase=phase

@contextmanager
def pr_create_phase(phase):
    if phase not in PR_CREATE_PHASES:raise ValueError('GITHUB_PR_CREATE_PHASE_INVALID')
    try:
        yield
    except Stale:
        # Preserve Core's existing stale behavior; no attempt-level recovery.
        raise
    except Exception as exc:
        code=None
        if isinstance(exc, GitHubTransportError) and len(exc.args)==1:
            code=exc.args[0]
        raise GitHubPRCreateFailure(phase,code) from None

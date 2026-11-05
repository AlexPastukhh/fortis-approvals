"""Compatibility import path; implementation lives in integrations.sonarcloud.repo_client/workflows.py."""
import sys
from .integrations.sonarcloud.repo_client import workflows as _implementation
if __name__ == "__main__":
    raise SystemExit(_implementation.main())
sys.modules[__name__] = _implementation

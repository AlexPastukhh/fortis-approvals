"""Compatibility import path; implementation lives in integrations.sonarcloud.gateway/preflight.py."""
import sys
from .integrations.sonarcloud.gateway import preflight as _implementation
if __name__ == "__main__":
    raise SystemExit(_implementation.main())
sys.modules[__name__] = _implementation

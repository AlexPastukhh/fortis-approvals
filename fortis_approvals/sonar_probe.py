"""Compatibility import path; implementation lives in integrations.sonarcloud.gateway/probe.py."""
import sys
from .integrations.sonarcloud.gateway import probe as _implementation
if __name__ == "__main__":
    raise SystemExit(_implementation.main())
sys.modules[__name__] = _implementation

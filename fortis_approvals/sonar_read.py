"""Compatibility import path; implementation lives in integrations.sonarcloud.gateway/read_adapter.py."""
import sys
from .integrations.sonarcloud.gateway import read_adapter as _implementation
sys.modules[__name__] = _implementation

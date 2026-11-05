"""Compatibility import path; implementation lives in integrations.sonarcloud.gateway/sonar.py."""
import sys
from .integrations.sonarcloud.gateway import sonar as _implementation
sys.modules[__name__] = _implementation

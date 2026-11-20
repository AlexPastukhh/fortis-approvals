"""Phase 6C.4 R7 source-only opt-in selector, NOT a deployment credential.

Constructing this immutable selector makes no claim about owner host identity,
deployed workers, source digests, restore/rollback, or permission activation.
The default r7_unified_server DOES NOT construct/pass this selector.
"""
from dataclasses import dataclass
import re
from ..core import Denied

_HEX = re.compile(r'[0-9a-f]{64}\Z')


@dataclass(frozen=True)
class R7LocalDenySourceOptIn:
    source_digest: str
    credential_generation_digest: str

    def __post_init__(self):
        if (type(self.source_digest) is not str or
                _HEX.fullmatch(self.source_digest) is None or
                type(self.credential_generation_digest) is not str or
                _HEX.fullmatch(self.credential_generation_digest) is None):
            raise Denied('R7_LOCAL_DENY_SOURCE_IDENTITY_INVALID')

    @property
    def runtime_verified(self):
        # This selector must never be treated as host authorization evidence.
        return False

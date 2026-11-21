"""Phase 6C.4 R7 source-only opt-in selector, NOT a deployment credential.

Constructing this immutable selector makes no claim about owner host identity,
deployed workers, source digests, restore/rollback, or permission activation.
The runtime server constructs the restricted selector only from an explicit
owner-reviewed release configuration; it is not external host attestation.
"""
from dataclasses import dataclass
import re
from ..core import Denied

_HEX = re.compile(r'[0-9a-f]{64}\Z')


@dataclass(frozen=True)
class R7LocalDenySourceOptIn:
    source_digest: str
    credential_generation_digest: str
    runtime_sonar_only: bool = False

    def __post_init__(self):
        if (type(self.runtime_sonar_only) is not bool or
                type(self.source_digest) is not str or
                _HEX.fullmatch(self.source_digest) is None or
                type(self.credential_generation_digest) is not str or
                _HEX.fullmatch(self.credential_generation_digest) is None):
            raise Denied('R7_LOCAL_DENY_SOURCE_IDENTITY_INVALID')

    @property
    def runtime_verified(self):
        # This selector must never be treated as host authorization evidence.
        return False

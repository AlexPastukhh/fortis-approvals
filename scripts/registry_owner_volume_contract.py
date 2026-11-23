"""Pure source-only E1.3b Registry private-volume layout planner.

This does NOT connect to Docker, open paths, choose owner scope, grant GO,
provision/chown volumes, or attest live filesystem permissions. Any
host operation requires a separately reviewed owner-run implementation.
"""
from dataclasses import dataclass
import re


@dataclass(frozen=True)
class PrivateVolumeRoot:
    name: str
    mount: str
    uid: int
    gid: int
    mode: int


def plan_private_volume_roots(owner_suffix: str) -> tuple[PrivateVolumeRoot, ...]:
    """Return required, non-authoritative root layout; no I/O or side effects.

    An independently chosen owner suffix is mandatory. Existing names,
    Docker mappings, RW writers and real ownership are NOT examined here.
    """
    if type(owner_suffix) is not str or re.fullmatch(r"[0-9a-f]{8,32}", owner_suffix) is None:
        raise ValueError("REGISTRY_OWNER_VOLUME_SUFFIX_INVALID")
    return (
        PrivateVolumeRoot(
            f"fortis-registry-state-e13b-{owner_suffix}",
            "/run/fortis-registry-state", 20002, 20002, 0o700,
        ),
        PrivateVolumeRoot(
            f"fortis-registry-config-e13b-{owner_suffix}",
            "/run/fortis-registry-runtime", 20002, 20002, 0o700,
        ),
        PrivateVolumeRoot(
            "fortis-registry-read",
            "/run/fortis-registry-read", 20002, 10001, 0o2710,
        ),
    )

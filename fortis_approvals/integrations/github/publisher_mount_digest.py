"""Protected, offline owner-mount source-binding digest; never returns credentials.

Used by the Windows Gateway release controller in a network-disabled,
read-only uid-10001 Docker verification container. The checked digest goes
only into owner-protected release records, never Git/Repo/logs/PR data.
"""
import hashlib
from pathlib import Path

from .publisher_owner_mount import _owner_file, load_owner_publisher_mount


def reviewed_mount_digest(root=Path('/run/r7-publisher-activation')):
    root = Path(root)
    profile, grant = load_owner_publisher_mount(root)
    if profile is None or grant is None or not profile.enabled:
        raise RuntimeError('R7_PUBLISHER_ACTIVATION_VOLUME_EMPTY')
    # Read exact validated files through no-follow, owner/mode checks.
    raw_profile = _owner_file(root, 'profile.json', 2048)
    raw_grant = _owner_file(root, 'grant', 257)
    again, again_grant = load_owner_publisher_mount(root)
    if again != profile or again_grant != grant:
        raise RuntimeError('R7_PUBLISHER_ACTIVATION_VOLUME_CHANGED')
    if (raw_profile != _owner_file(root, 'profile.json', 2048) or
            raw_grant != _owner_file(root, 'grant', 257)):
        raise RuntimeError('R7_PUBLISHER_ACTIVATION_VOLUME_CHANGED')
    digest = hashlib.sha256(b'fortis-publisher-owner-mount-v1\x00')
    for name, data in ((b'profile.json', raw_profile), (b'grant', raw_grant)):
        digest.update(len(name).to_bytes(2, 'big'))
        digest.update(name)
        digest.update(len(data).to_bytes(4, 'big'))
        digest.update(data)
    return digest.hexdigest()

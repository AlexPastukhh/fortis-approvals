"""Owner Shell release preflight: never expose client credentials in stdout.

Run as UID 10001 from an immutable image, with the exact vault mounted read-only
and no network access. This is material validation, not a live HTTPS probe.
"""
import os
from pathlib import Path
import stat

from .owner_shell import OwnerShellClient

ROOT = Path('/run/fortis-secrets/owner-shell')
NAMES = ('server-ca.pem','client.pem','client.key','secret.txt')


def verify_material(root=ROOT, *, uid=10001, gid=10001):
    """Reject symlinks, unexpected entries, ownership/mode drift and invalid TLS."""
    root = Path(root)
    info = root.lstat()
    if not (stat.S_ISDIR(info.st_mode) and info.st_uid == uid and
            info.st_gid == gid and stat.S_IMODE(info.st_mode) == 0o700):
        raise RuntimeError('OWNER_SHELL_DIRECTORY_INVALID')
    if {entry.name for entry in root.iterdir()} != set(NAMES):
        raise RuntimeError('OWNER_SHELL_FILES_CHANGED')
    for name in NAMES:
        file = root / name
        info = file.lstat()
        if not (stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and
                info.st_uid == uid and info.st_gid == gid and
                stat.S_IMODE(info.st_mode) == 0o600 and 1 <= info.st_size <= 65536):
            raise RuntimeError('OWNER_SHELL_FILE_INVALID')
    if os.geteuid() != uid:
        raise RuntimeError('OWNER_SHELL_EXECUTOR_IDENTITY_INVALID')
    client = OwnerShellClient(port=10443,
        server_ca=str(root/'server-ca.pem'), client_cert=str(root/'client.pem'),
        client_key=str(root/'client.key'), secret_file=str(root/'secret.txt'))
    if client.origin != 'https://host.docker.internal:10443':
        raise RuntimeError('OWNER_SHELL_ENDPOINT_INVALID')
    return True

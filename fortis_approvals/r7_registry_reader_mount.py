"""E1.3 SOURCE DRAFT: owner-fixed, read-only mount for a private Registry reader.

This does not provision anything, start Registry or activate a grant. The
owner creates a mount at a *fixed* trusted path and pins process/socket IDs.
Only owner-reviewed source/image and host can make the mount usable; caller
requests, Repo params and runtime environment have no path override.
"""
import os
from pathlib import Path
import stat
import uuid

from .core import Denied, canonical, loads_strict
from .integrations.registry.candidate_gateway import GatewayRegistryUnixCandidateRead
from .integrations.registry.owner_pinned_pidfd import _boot_id

MOUNT = Path('/run/r7-registry-reader')
_FILE = 'profile.json'
_MAX_BYTES = 2048
_FIELDS = frozenset({
    'schemaVersion', 'enabled', 'purpose', 'releaseNonce',
    'gatewaySourceDigest', 'instanceId', 'scopeDigest', 'socketPath',
    'registryUid', 'registryGid', 'registryPidfdInode', 'registryKernelBootId',
    'readerUid', 'readerGid', 'socketDevice', 'socketInode',
})


def _stop(code):
    raise Denied('R7_REGISTRY_MOUNT_' + code)


def _uuid(value):
    try:
        return type(value) is str and str(uuid.UUID(value)) == value
    except (TypeError, ValueError, AttributeError):
        return False


def _hex(value):
    return (type(value) is str and len(value) == 64 and
            all(c in '0123456789abcdef' for c in value))


def _exact_readonly_mountinfo(raw, root):
    """Closed mountinfo parser; no prefix or duplicate mountpoint accepted."""
    if type(raw) is not bytes or not 1 <= len(raw) <= 524288:
        return False
    path = os.fsencode(root)
    matches = []
    for line in raw.splitlines():
        fields = line.split(b' - ', 1)[0].split()
        if len(fields) >= 6 and fields[4] == path:
            matches.append(fields)
    return len(matches) == 1 and b'ro' in matches[0][5].split(b',')


def _check_owner_readonly_mount(root):
    """Exactly one owner-installed, read-only mount at the reviewed path.

    `statvfs` alone is not sufficient: a read-only root filesystem does not
    prove the owner installed a *dedicated* Registry activation mount.
    Source-only test fixtures replace this proc view with exact test rows.
    """
    try:
        raw = Path('/proc/self/mountinfo').read_bytes()
        if (not _exact_readonly_mountinfo(raw, root)
                or not os.statvfs(root).f_flag & getattr(os, 'ST_RDONLY', 1)):
            _stop('READONLY_REQUIRED')
    except Denied:
        raise
    except (OSError, OverflowError, ValueError):
        _stop('MOUNTINFO_UNAVAILABLE')


def load_owner_registry_reader(*, expected_release_nonce,
                               expected_source_digest, root=MOUNT):
    """Only a reviewed, mount-sealed Registry READ profile may bind R7.

    Absence means disabled. Root override is for offline test source ONLY;
    server.main() must call this with the fixed default root. All guards run
    before returning a transport; no automatic grant or WRITE is created.
    """
    if not isinstance(root, Path) or not root.is_absolute():
        _stop('PATH_DENIED')
    if not root.exists() and not root.is_symlink():
        return None
    if (root.is_symlink() or not root.is_dir()
            or os.geteuid() == 0 or os.getegid() == 0):
        _stop('DIRECTORY_DENIED')
    meta = root.lstat()
    if (not stat.S_ISDIR(meta.st_mode) or meta.st_uid != os.geteuid()
            or stat.S_IMODE(meta.st_mode) != 0o700):
        _stop('DIRECTORY_DENIED')
    try:
        if len(list(root.iterdir())) != 1 or not (root / _FILE).exists():
            _stop('FILES_DENIED')
        # Neither a process running as Gateway UID nor an untrusted Repo actor
        # can rewrite the owner-pinned mount while it is active.
        _check_owner_readonly_mount(root)
        fd = os.open(root / _FILE, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        with os.fdopen(fd, 'rb') as stream:
            info = os.fstat(stream.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                    or stat.S_IMODE(info.st_mode) != 0o600
                    or info.st_nlink != 1 or not 1 <= info.st_size <= _MAX_BYTES):
                _stop('FILE_DENIED')
            raw = stream.read(_MAX_BYTES + 1)
        if len(raw) != info.st_size:
            _stop('FILE_CHANGED')
        value = loads_strict(raw)
        if (type(value) is not dict or set(value) != _FIELDS
                or canonical(value).encode('utf-8') != raw
                or type(value['schemaVersion']) is not int
                or value['schemaVersion'] != 2
                or value['enabled'] is not True
                or value['purpose'] != 'registry-candidate-read-v1'
                or not _uuid(value['releaseNonce'])
                or value['releaseNonce'] != expected_release_nonce
                or not _hex(value['gatewaySourceDigest'])
                or value['gatewaySourceDigest'] != expected_source_digest
                or not _uuid(value['instanceId'])
                or not _hex(value['scopeDigest'])
                or type(value['registryPidfdInode']) is not int
                or not (0 < value['registryPidfdInode'] < 2**64)
                or not _uuid(value['registryKernelBootId'])
                or value['registryKernelBootId'] != _boot_id()):
            _stop('PROFILE_DENIED')
        # Reader validates exact real credentials and Linux pinned AF_UNIX
        # owner/permission/device/inode; a configured but absent listener STOP.
        reader = GatewayRegistryUnixCandidateRead(
            socket_path=value['socketPath'],
            instance_id=value['instanceId'], scope_digest=value['scopeDigest'],
            registry_uid=value['registryUid'], registry_gid=value['registryGid'],
            registry_pidfd_inode=value['registryPidfdInode'],
            registry_boot_id=value['registryKernelBootId'],
            reader_uid=value['readerUid'], reader_gid=value['readerGid'],
            socket_device=value['socketDevice'], socket_inode=value['socketInode'])
        reader._check_socket()
        # Verify our mounted identity and current source still match. This is
        # NOT a substitute for the independent owner-host mount/UID audit.
        if (root.lstat().st_ino != meta.st_ino
                or root.lstat().st_dev != meta.st_dev
                ):
            _stop('DIRECTORY_CHANGED')
        _check_owner_readonly_mount(root)
        return reader
    except Denied:
        raise
    except (OSError, ValueError, TypeError, UnicodeError,
            OverflowError, RecursionError):
        _stop('PROFILE_UNAVAILABLE')

"""E1.3 SOURCE DRAFT: owner-fixed, read-only mount for a private Registry reader.

This does not provision anything, start Registry or activate a grant. The
owner creates a mount at a *fixed* trusted path and pins process/socket IDs.
Only owner-reviewed source/image and host can make the mount usable; caller
requests, Repo params and runtime environment have no path override.
"""
import hashlib
import os
from pathlib import Path
import socket
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
        files={p.name for p in root.iterdir()}
        if files not in ({_FILE},{_FILE,'functional.json','planner.key'}):
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
        functional=(type(value) is dict and value.get('schemaVersion')==3)
        fields=_FIELDS | {'functionalConfigSha256','plannerKeySha256'} if functional else _FIELDS
        if (type(value) is not dict or set(value) != fields
                or canonical(value).encode('utf-8') != raw
                or type(value['schemaVersion']) is not int
                or value['schemaVersion'] not in (2,3)
                or files!=({_FILE,'functional.json','planner.key'} if functional else {_FILE})
                or value['enabled'] is not True
                or value['purpose'] != ('registry-functional-local-candidate-v1' if functional else 'registry-candidate-read-v1')
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
        if functional:
            from .integrations.github.gateway.functional_review_runtime import FunctionalRegistryConfiguration
            from .integrations.registry.read_contract import private_planner_key
            if not _hex(value['functionalConfigSha256']) or not _hex(value['plannerKeySha256']):
                _stop('FUNCTIONAL_PIN_DENIED')
            fd=os.open(root/'functional.json',os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
            with os.fdopen(fd,'rb') as stream:
                info=os.fstat(stream.fileno())
                if (not stat.S_ISREG(info.st_mode) or info.st_uid!=os.geteuid()
                        or stat.S_IMODE(info.st_mode)!=0o600 or info.st_nlink!=1
                        or not 0<info.st_size<=65536):
                    _stop('FUNCTIONAL_FILE_DENIED')
                raw_config=stream.read(65537)
            parsed=loads_strict(raw_config)
            if (len(raw_config)!=info.st_size or canonical(parsed).encode()!=raw_config
                    or hashlib.sha256(raw_config).hexdigest()!=value['functionalConfigSha256']):
                _stop('FUNCTIONAL_PIN_DENIED')
            key=private_planner_key(root/'planner.key',value['plannerKeySha256'])
            reader._functional_config=FunctionalRegistryConfiguration(parsed,key,
                scope_digest=value['scopeDigest'])
            reader._release_nonce=value['releaseNonce']
            reader._gateway_source_digest=value['gatewaySourceDigest']
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


def reviewed_registry_reader_mount_digest(*, expected_release_nonce,
                                          expected_source_digest, root=MOUNT):
    """Check owner-sealed profile and live pinned socket WITHOUT Registry READ.

    For the existing protected owner Check/Apply controller to call only after
    it has been independently extended to accept TWO exact readonly volumes,
    an owner-chosen reviewed nonce and a source/image binding. This function
    does not create, seal, install or authorize any mount/process/grant.
    """
    reader = load_owner_registry_reader(
        expected_release_nonce=expected_release_nonce,
        expected_source_digest=expected_source_digest, root=root)
    if reader is None:
        _stop('NOT_ENABLED')
    initial = reader._check_socket()
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(2)
            sock.connect(str(reader._path))
            peer = reader._peer(sock)
            if reader._peer(sock) != peer:
                _stop('PEER_CHANGED')
    except Denied:
        raise
    except (OSError, TimeoutError):
        _stop('PEER_UNAVAILABLE')
    reader._check_identity()
    if reader._check_socket() != initial:
        _stop('SOCKET_CHANGED')
    _check_owner_readonly_mount(root)
    try:
        path = root / _FILE
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            row = os.fstat(fd)
            if (not stat.S_ISREG(row.st_mode) or row.st_nlink != 1
                    or row.st_uid != os.geteuid()
                    or stat.S_IMODE(row.st_mode) != 0o600
                    or not 1 <= row.st_size <= _MAX_BYTES):
                _stop('FILE_DENIED')
            raw = os.read(fd, _MAX_BYTES+1)
            if len(raw) != row.st_size:
                _stop('FILE_CHANGED')
        finally:
            os.close(fd)
    except Denied:
        raise
    except OSError:
        _stop('FILE_UNAVAILABLE')
    _check_owner_readonly_mount(root)
    return hashlib.sha256(raw).hexdigest()

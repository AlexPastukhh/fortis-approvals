"""Owner-sealed read-only configuration for the private Registry reader.

The trusted mount selects the release, instance and scope. A legacy profile
uses exact boot/process/socket pins; a managed functional profile binds the
same materials and authenticates each current listener under the owner key.
The successor profile also pins the authenticated semantic Registry service.
"""
import hashlib
import os
import re
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
_SEMANTIC_FIELDS = frozenset((
    'semanticFrameKeySha256','semanticGeneration','semanticProfileDigest','semanticInternalActor',
    'policyHistorySha256', 'successorSha256',
))
_FUNCTIONAL_FILES = {_FILE,'functional.json','planner.key'}
_SEMANTIC_FILES = _FUNCTIONAL_FILES | {'semantic-frame.key', 'policy-history.json', 'successor.json'}
_LIVE_PEER_FIELDS = frozenset({
    'registryPidfdInode', 'registryKernelBootId', 'socketDevice', 'socketInode',
})
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


def _exact_mountinfo(raw, root, mode):
    """Closed mountinfo parser; no prefix or duplicate mountpoint accepted."""
    if type(raw) is not bytes or not 1 <= len(raw) <= 524288:
        return False
    path = os.fsencode(root)
    matches = []
    for line in raw.splitlines():
        fields = line.split(b' - ', 1)[0].split()
        if len(fields) >= 6 and fields[4] == path:
            matches.append(fields)
    return len(matches) == 1 and mode in matches[0][5].split(b',')


def _exact_readonly_mountinfo(raw, root):
    return _exact_mountinfo(raw,root,b'ro')


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
    result = _load_sealed_registry_reader(
        root, expected_release_nonce, expected_source_digest)
    if result is None:
        return None
    reader, _, _ = result
    if reader._peer_key is None:
        reader._check_socket()
    else:
        _check_live_peer(reader)
    return reader


def _load_sealed_registry_reader(root, expected_release_nonce, expected_source_digest, *, historical_boot_id=None):
    """Validate a sealed profile and material without using its socket."""
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
        if files not in ({_FILE},_FUNCTIONAL_FILES,_SEMANTIC_FILES):
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
        version = value.get('schemaVersion') if type(value) is dict else None
        functional = version in (3,4,5)
        managed = version in (4,5)
        semantic = version == 5
        fields = _FIELDS | {'functionalConfigSha256', 'plannerKeySha256'} if functional else _FIELDS
        if managed:
            fields = fields - _LIVE_PEER_FIELDS
        if semantic:
            fields = fields | _SEMANTIC_FIELDS
        expected_files = _FUNCTIONAL_FILES if functional else {_FILE}
        if semantic:
            expected_files = _SEMANTIC_FILES
        purpose=('registry-functional-successor-v1' if semantic else
                 'registry-functional-local-candidate-v1' if functional else 'registry-candidate-read-v1')
        if (type(value) is not dict or set(value) != fields
                or canonical(value).encode('utf-8') != raw
                or type(value['schemaVersion']) is not int
                or version not in (2,3,4,5)
                or files!=expected_files
                or value['enabled'] is not True
                or value['purpose'] != purpose
                or not _uuid(value['releaseNonce'])
                or value['releaseNonce'] != expected_release_nonce
                or not _hex(value['gatewaySourceDigest'])
                or value['gatewaySourceDigest'] != expected_source_digest
                or not _uuid(value['instanceId'])
                or not _hex(value['scopeDigest'])):
            _stop('PROFILE_DENIED')
        if not managed and (type(value['registryPidfdInode']) is not int
                or not (0 < value['registryPidfdInode'] < 2**64)
                or not _uuid(value['registryKernelBootId'])
                or value['registryKernelBootId'] != (historical_boot_id if historical_boot_id is not None else _boot_id())):
            _stop('PROFILE_DENIED')
        if functional:
            from .integrations.github.gateway.functional_review_runtime import FunctionalRegistryConfiguration
            from .integrations.registry.read_contract import private_planner_key
            if not _hex(value['functionalConfigSha256']) or not _hex(value['plannerKeySha256']):
                _stop('FUNCTIONAL_PIN_DENIED')
            parsed = _read_pinned_json(root/'functional.json', value['functionalConfigSha256'],
                                       max_bytes=65536, label='FUNCTIONAL')
            key=private_planner_key(root/'planner.key',value['plannerKeySha256'])
        if managed:
            peer = {'peer_key': key}
        else:
            peer = {
                'registry_pidfd_inode': value['registryPidfdInode'],
                'registry_boot_id': value['registryKernelBootId'],
                'socket_device': value['socketDevice'],
                'socket_inode': value['socketInode'],
            }
        reader = GatewayRegistryUnixCandidateRead(
            socket_path=value['socketPath'],
            instance_id=value['instanceId'], scope_digest=value['scopeDigest'],
            registry_uid=value['registryUid'], registry_gid=value['registryGid'],
            reader_uid=value['readerUid'], reader_gid=value['readerGid'], **peer)
        if functional:
            reader._functional_config = FunctionalRegistryConfiguration(
                parsed, key, scope_digest=value['scopeDigest'], preserve_incumbent=semantic)
            reader._release_nonce=value['releaseNonce']
            reader._gateway_source_digest=value['gatewaySourceDigest']
        if semantic:
            from .extensions.composite_successor import ReviewedHistoryEvidence
            from .extensions.semantic_gateway import GatewayRegistrySemanticTransport
            actor = value['semanticInternalActor']
            if (not all(_hex(value[field]) for field in (
                    'semanticFrameKeySha256', 'semanticGeneration', 'semanticProfileDigest',
                    'policyHistorySha256', 'successorSha256'))
                    or type(actor) is not str
                    or not re.fullmatch(r'[A-Za-z0-9._:-]{1,128}', actor)):
                _stop('SEMANTIC_PIN_DENIED')
            frame_key = private_planner_key(root/'semantic-frame.key', value['semanticFrameKeySha256'])
            reader._semantic_transport = GatewayRegistrySemanticTransport(
                reader, frame_key=frame_key, generation=value['semanticGeneration'], internal_actor=actor)
            reader._semantic_profile_digest = value['semanticProfileDigest']
            history_pin = value['policyHistorySha256']
            history = _read_pinned_json(root/'policy-history.json', history_pin,
                                        max_bytes=8192, label='POLICY_HISTORY')
            reader._policy_history = ReviewedHistoryEvidence(history, expected_digest=history_pin)
            from .extensions.successor_runtime import ProtectedRegistrySuccessor
            composition = _read_pinned_json(root/'successor.json', value['successorSha256'],
                                            max_bytes=262144, label='SUCCESSOR')
            reader._successor_config = ProtectedRegistrySuccessor(
                composition, source_digest=reader._gateway_source_digest)
        # Verify our mounted identity and current source still match. This is
        # NOT a substitute for the independent owner-host mount/UID audit.
        if (root.lstat().st_ino != meta.st_ino
                or root.lstat().st_dev != meta.st_dev
                ):
            _stop('DIRECTORY_CHANGED')
        _check_owner_readonly_mount(root)
        return reader, value, hashlib.sha256(raw).hexdigest()
    except Denied:
        raise
    except (OSError, ValueError, TypeError, UnicodeError,
            OverflowError, RecursionError):
        _stop('PROFILE_UNAVAILABLE')


def _read_pinned_json(path, expected_digest, *, max_bytes, label):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1
                or not 0 < info.st_size <= max_bytes):
            _stop(label + '_FILE_DENIED')
        raw = stream.read(max_bytes + 1)
    if len(raw) != info.st_size or hashlib.sha256(raw).hexdigest() != expected_digest:
        _stop(label + '_PIN_DENIED')
    value = loads_strict(raw)
    if canonical(value).encode() != raw:
        _stop(label + '_PIN_DENIED')
    return value


def reviewed_registry_reader_mount_digest(*, expected_release_nonce,
                                          expected_source_digest, root=MOUNT, legacy_only=False):
    """Check owner-sealed profile and live pinned socket WITHOUT Registry READ.

    For the existing protected owner Check/Apply controller to call only after
    it has been independently extended to accept TWO exact readonly volumes,
    an owner-chosen reviewed nonce and a source/image binding. This function
    does not create, seal, install or authorize any mount/process/grant.
    """
    result = _load_sealed_registry_reader(
        root, expected_release_nonce, expected_source_digest)
    if result is None:
        _stop('NOT_ENABLED')
    reader, profile, digest = result
    if legacy_only and profile['schemaVersion'] == 5:
        _stop('SUCCESSOR_DELIVERY_REQUIRED')
    _check_live_peer(reader)
    checked = _load_sealed_registry_reader(root, expected_release_nonce, expected_source_digest)
    if checked is None or checked[2] != digest:
        _stop('PROFILE_CHANGED')
    return digest


def reviewed_successor_delivery(*, expected_release_nonce, expected_source_digest,
                                expected_interlock_digest, incumbent_core=None, scratch_root=None, root=MOUNT):
    """Read both packages' exact delivery pins and optionally preview the clone."""
    result = _load_sealed_registry_reader(root, expected_release_nonce, expected_source_digest)
    if result is None or result[1]['schemaVersion'] != 5:
        _stop('SUCCESSOR_PROFILE_REQUIRED')
    reader, _, digest = result
    _check_live_peer(reader)
    receipt = reader._successor_config.checked_delivery(
        reader, expected_interlock_digest=expected_interlock_digest,
        incumbent_core=incumbent_core, scratch_root=scratch_root)
    if reviewed_registry_reader_mount_digest(
            expected_release_nonce=expected_release_nonce, expected_source_digest=expected_source_digest,
            root=root) != digest:
        _stop('PROFILE_CHANGED')
    return {**receipt, 'profileDigest':digest}


def _check_live_peer(reader):
    semantic = getattr(reader, '_semantic_transport', None)
    if semantic is not None:
        from .extensions.maintenance_gate import hold_snapshot
        if semantic.profile_digest() != reader._semantic_profile_digest:
            _stop('SEMANTIC_PROFILE_CHANGED')
        hold=hold_snapshot(semantic.maintenance_snapshot())
        if hold['instanceId'] != reader._instance or hold['scopeDigest'] != reader._scope:
            _stop('SEMANTIC_SCOPE_CHANGED')
        return
    initial = reader._check_socket()
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(2)
            sock.connect(str(reader._path))
            peer = reader._authenticate_peer(sock)
            if reader._peer(sock) != peer:
                _stop('PEER_CHANGED')
    except Denied:
        raise
    except (OSError, TimeoutError):
        _stop('PEER_UNAVAILABLE')
    reader._check_identity()
    if reader._check_socket() != initial:
        _stop('SOCKET_CHANGED')


# This path is mounted only by the owner recovery preflight. Server startup
# still uses MOUNT and validates the live peer normally.
RETAINED_MOUNT = Path('/run/r7-registry-reader-retained')


def reviewed_registry_return_profile(*, source_nonce, source_profile_digest,
                                     return_nonce, source_digest,
                                     retained_root=RETAINED_MOUNT, return_root=MOUNT, crash_boot_ids=None):
    """Review a new seal against exactly one retained functional release."""
    if retained_root == return_root or source_nonce == return_nonce:
        _stop('RETURN_PROFILE_DENIED')
    old_boot_id = None
    if crash_boot_ids is not None:
        if (type(crash_boot_ids) is not dict or set(crash_boot_ids) != {'previous', 'current'}
                or not all(_uuid(v) for v in crash_boot_ids.values())
                or crash_boot_ids['previous'] == crash_boot_ids['current']
                or crash_boot_ids['current'] != _boot_id()):
            _stop('RETURN_CRASH_BOOT_DENIED')
        old_boot_id = crash_boot_ids['previous']
    retained = _load_sealed_registry_reader(
        retained_root, source_nonce, source_digest, historical_boot_id=old_boot_id)
    replacement = _load_sealed_registry_reader(return_root, return_nonce, source_digest)
    if retained is None or replacement is None:
        _stop('RETURN_PROFILE_DENIED')
    _, old, old_digest = retained
    reader, new, new_digest = replacement
    # Stable identity, source, scope, config bytes and planner key must be
    # unchanged. Only nonce and live process/socket identity may differ.
    peer = {'releaseNonce', 'registryPidfdInode', 'socketDevice', 'socketInode'}
    if old_boot_id is not None:
        peer.add('registryKernelBootId')
    if (old_digest != source_profile_digest or old['schemaVersion'] not in (3, 4)
            or old['schemaVersion'] != new['schemaVersion']
            or {k: v for k, v in old.items() if k not in peer}
            != {k: v for k, v in new.items() if k not in peer}):
        _stop('RETURN_PROFILE_DENIED')
    _check_live_peer(reader)
    # Re-read both sealed projections after exercising the actual peer.
    checked_old = _load_sealed_registry_reader(
        retained_root, source_nonce, source_digest, historical_boot_id=old_boot_id)
    checked_new = _load_sealed_registry_reader(return_root, return_nonce, source_digest)
    if checked_old is None or checked_new is None or checked_old[2] != old_digest or checked_new[2] != new_digest:
        _stop('RETURN_PROFILE_CHANGED')
    return new_digest

"""Linux AF_UNIX peer identity for owner-configured Registry.

The kernel pidfd establishes liveness and continuity for a connection.
Legacy profiles pin the boot and process inode; managed functional profiles
also require proof under an independently owner-provisioned key.
"""
import hmac
import os
import platform
import re
from pathlib import Path
import select
import socket
import struct
import sys
import uuid

from ...core import Denied
from .read_contract import _hex, _need, _uuid

_SO_PEERPIDFD = 77  # Linux UAPI, since 6.5. CPython 3.11 has no symbol.
_CRED = struct.Struct('=3i')
_FD = struct.Struct('=i')
_BOOT_ID = Path('/proc/sys/kernel/random/boot_id')

_PEER_PROOF_DOMAIN = b'fortis-registry-functional-peer-v1\0'


def peer_proof(key, challenge, *, instance_id, scope_digest):
    """Authenticate the listener without reusing the planner frame MAC domain."""
    _need(type(key) is bytes and len(key) == 32 and
          _hex(challenge, 64) and _uuid(instance_id) and _hex(scope_digest, 64),
          'REGISTRY_FUNCTIONAL_PEER_PROOF_INVALID')
    material = (challenge + instance_id + scope_digest).encode('ascii')
    return hmac.digest(key, _PEER_PROOF_DOMAIN + material, 'sha256')



def _stop(suffix):
    raise Denied('REGISTRY_PIDFD_' + suffix)


def _boot_id():
    """Only kernel boot identity, never a peer or request-supplied boot ID."""
    try:
        raw = _BOOT_ID.read_bytes()
        if not 1 <= len(raw) <= 48:
            _stop('BOOT_UNAVAILABLE')
        value = raw.strip().decode('ascii')
        if str(uuid.UUID(value)) != value:
            _stop('BOOT_UNAVAILABLE')
        return value
    except Denied:
        raise
    except (OSError, ValueError, UnicodeError):
        _stop('BOOT_UNAVAILABLE')


def _require_pidfs():
    """No pidfd inode trust on pre-pidfs kernels (Linux 6.5–6.8).

    Before Linux 6.9 pidfds used anonymous inodes without the unique stable
    pidfs process inode that the owner-pinned contract needs. Backporting a
    pidfs implementation to an older kernel requires explicit source review.
    """
    match = re.match(r'^(\d+)\.(\d+)(?:\.|-)', platform.release())
    if (not match or (int(match[1]), int(match[2])) < (6, 9)):
        _stop('PIDFS_UNAVAILABLE')


def _credentials(sock):
    raw = sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, _CRED.size)
    if len(raw) != _CRED.size:
        _stop('CREDENTIALS_UNAVAILABLE')
    return _CRED.unpack(raw)


def kernel_live_peer(sock, *, expected_uid, expected_gid):
    """Kernel-authenticated UID/GID and alive pidfd for a private Unix peer.

    Registry server uses this for its existing mode: exact reader UID/GID
    plus filesystem AF_UNIX access, now requiring a real live pidfd even when
    pid=0 across namespaces. This does NOT independently owner-pin a peer
    process and MUST NOT be used to authenticate the Registry on Gateway.
    """
    if (sys.platform != 'linux' or struct.calcsize('P') != 8
            or type(expected_uid) is not int
            or type(expected_gid) is not int
            or not (0 < expected_uid < 2**31)
            or not (0 < expected_gid < 2**31)):
        _stop('CONFIG_DENIED')
    if (not isinstance(sock, socket.socket)
            or sock.family != socket.AF_UNIX
            or (sock.type & 0xf) != socket.SOCK_STREAM):
        _stop('UNIX_REQUIRED')
    _require_pidfs()
    fd = None
    try:
        pid, uid, gid = _credentials(sock)
        # Across Docker namespaces, SO_PEERCRED PID=0 is expected; the
        # pidfd itself must still identify a live kernel process.
        if pid < 0 or (uid, gid) != (expected_uid, expected_gid):
            _stop('CREDENTIALS_DENIED')
        raw = sock.getsockopt(socket.SOL_SOCKET, _SO_PEERPIDFD, _FD.size)
        if len(raw) != _FD.size:
            _stop('PROCESS_UNAVAILABLE')
        fd = _FD.unpack(raw)[0]
        if fd < 0:
            _stop('PROCESS_UNAVAILABLE')
        row = os.fstat(fd)
        if row.st_ino <= 0:
            _stop('PROCESS_UNAVAILABLE')
        poller = select.poll()
        poller.register(fd, select.POLLIN | select.POLLHUP |
                        select.POLLERR | select.POLLNVAL)
        if poller.poll(0):
            _stop('PROCESS_EXITED')
        boot = _boot_id()
        if _credentials(sock) != (pid, uid, gid):
            _stop('CREDENTIALS_CHANGED')
        return (pid, uid, gid, row.st_ino, boot)
    except Denied:
        raise
    except (OSError, TypeError, OverflowError, struct.error, ValueError):
        _stop('PROCESS_UNAVAILABLE')
    finally:
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass


def owner_pinned_peer(sock, *, expected_uid, expected_gid,
                      expected_pidfd_inode, expected_boot_id):
    """Compare the peer process to an *independently owner-sealed* pin.

    A peer's claimed inode is NOT a pin. The approved Registry process must
    have been inspected by the owner after it started and sealed into the
    fixed readonly R7 mount, bound to source/release/instance and current
    boot. A process exiting or changing at any boundary is DENY.
    """
    if (type(expected_pidfd_inode) is not int
            or not (0 < expected_pidfd_inode < 2**64)
            or type(expected_boot_id) is not str):
        _stop('CONFIG_DENIED')
    try:
        if str(uuid.UUID(expected_boot_id)) != expected_boot_id:
            _stop('CONFIG_DENIED')
    except (ValueError, UnicodeError):
        _stop('CONFIG_DENIED')
    if _boot_id() != expected_boot_id:
        _stop('BOOT_CHANGED')
    _, uid, gid, inode, boot = kernel_live_peer(
        sock, expected_uid=expected_uid, expected_gid=expected_gid)
    if inode != expected_pidfd_inode:
        _stop('PROCESS_NOT_PINNED')
    if boot != expected_boot_id or _boot_id() != expected_boot_id:
        _stop('BOOT_CHANGED')
    return (uid, gid, inode)

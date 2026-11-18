"""Explicit owner-private mount for ASK-only Windows machine PowerShell.

Absent fixed mount means disabled. No caller-provided path, token, or toggle.
Importing this module never enables a route or reads credentials.
"""
import os
from pathlib import Path
import re
import stat

from .core import loads_strict
from .powershell_machine import MachinePowerShellAdapter, MachineShellTransport

MOUNT = Path("/run/fortis-machine-powershell")
FILES = frozenset({
    "profile.json", "server-ca.pem", "client-cert.pem",
    "client-key.pem", "bearer", "proof-key",
})
_KEYS = frozenset({
    "version", "enabled", "actor", "target",
    "sourceSha256", "executorIdentity", "mode",
})
_HEX = re.compile(r"[0-9a-f]{64}\Z")
_ACTOR = re.compile(r"[a-z][a-z0-9-]{0,63}\Z")


def _private_file(root, name, limit):
    path = root / name
    if path.is_symlink():
        raise RuntimeError("MACHINE_POWERSHELL_MOUNT_INSECURE")
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except (OSError, ValueError):
        raise RuntimeError("MACHINE_POWERSHELL_MOUNT_INCOMPLETE") from None
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or
                info.st_uid != os.geteuid() or
                stat.S_IMODE(info.st_mode) != 0o600 or
                info.st_nlink != 1 or not 1 <= info.st_size <= limit):
            raise RuntimeError("MACHINE_POWERSHELL_MOUNT_INSECURE")
        result = stream.read(limit + 1)
        if len(result) != info.st_size:
            raise RuntimeError("MACHINE_POWERSHELL_MOUNT_CHANGED")
    return result


def load_machine_shell_mount(*, expected_actor, root=MOUNT):
    """Owner-only: return adapter or None. No machine trigger or activation API.

    The root override is for offline fixtures and trusted composition tests.
    In production the fixed source path is the only authorized mount.
    """
    directory = Path(root)
    if not directory.is_absolute():
        raise RuntimeError("MACHINE_POWERSHELL_MOUNT_PATH_INVALID")
    if not directory.exists() and not directory.is_symlink():
        return None
    if directory.is_symlink() or not directory.is_dir():
        raise RuntimeError("MACHINE_POWERSHELL_MOUNT_INSECURE")
    info = directory.stat()
    if (info.st_uid != os.geteuid() or
            stat.S_IMODE(info.st_mode) != 0o700 or
            not stat.S_ISDIR(info.st_mode)):
        raise RuntimeError("MACHINE_POWERSHELL_MOUNT_INSECURE")
    if {entry.name for entry in directory.iterdir()} != FILES:
        raise RuntimeError("MACHINE_POWERSHELL_MOUNT_INCOMPLETE")
    try:
        content = _private_file(directory, "profile.json", 2048)
        profile = loads_strict(content)
    except (ValueError, TypeError, UnicodeError, RecursionError):
        raise RuntimeError("MACHINE_POWERSHELL_PROFILE_INVALID") from None
    if (type(profile) is not dict or set(profile) != _KEYS or
            type(profile["version"]) is not int or profile["version"] != 1 or
            profile["enabled"] is not True or profile["mode"] != "ASK_ONLY" or
            type(profile["actor"]) is not str or
            profile["actor"] != expected_actor or
            _ACTOR.fullmatch(profile["actor"]) is None or
            type(profile["target"]) is not str or
            _ACTOR.fullmatch(profile["target"]) is None or
            type(profile["sourceSha256"]) is not str or
            _HEX.fullmatch(profile["sourceSha256"]) is None or
            type(profile["executorIdentity"]) is not str or
            not 1 <= len(profile["executorIdentity"]) <= 100):
        raise RuntimeError("MACHINE_POWERSHELL_PROFILE_DENIED")
    for name in FILES - {"profile.json"}:
        _private_file(directory, name, 8192)
    try:
        transport = MachineShellTransport(
            ca=str(directory / "server-ca.pem"),
            client_cert=str(directory / "client-cert.pem"),
            client_key=str(directory / "client-key.pem"),
            bearer_file=str(directory / "bearer"),
            proof_file=str(directory / "proof-key"))
        return MachinePowerShellAdapter(
            transport=transport, target=profile["target"],
            actor=profile["actor"], source_sha256=profile["sourceSha256"],
            executor_identity=profile["executorIdentity"])
    except (OSError, ValueError):
        raise RuntimeError("MACHINE_POWERSHELL_TRANSPORT_INVALID") from None


def reviewed_machine_mount_digest(*, expected_actor, root=MOUNT):
    """SHA256 of all *validated* owner-sealed bytes for protected release records.

    Must be called only in a network-disabled uid-10001 read-only image
    preflight. Never return the profile, TLS keys, bearer or HMAC key.
    """
    import hashlib

    directory = Path(root)
    if load_machine_shell_mount(expected_actor=expected_actor, root=directory) is None:
        raise RuntimeError("MACHINE_POWERSHELL_MOUNT_ABSENT")
    names = tuple(sorted(FILES))
    lengths = {"profile.json": 2048}
    initial = {name: _private_file(directory, name, lengths.get(name, 8192))
               for name in names}
    if load_machine_shell_mount(expected_actor=expected_actor, root=directory) is None:
        raise RuntimeError("MACHINE_POWERSHELL_MOUNT_CHANGED")
    for name in names:
        if _private_file(directory, name, lengths.get(name, 8192)) != initial[name]:
            raise RuntimeError("MACHINE_POWERSHELL_MOUNT_CHANGED")
    digest = hashlib.sha256(b"fortis-machine-powershell-mount-v1\x00")
    for name in names:
        key = name.encode("ascii")
        data = initial[name]
        digest.update(len(key).to_bytes(2, "big"))
        digest.update(key)
        digest.update(len(data).to_bytes(4, "big"))
        digest.update(data)
    return digest.hexdigest()

"""P3.4 owner-sealed startup input; absence means disabled (no env switch).

This loader only validates and reads a *pre-mounted* owner-private identity.
It neither provisions credentials nor authorizes a release or publisher ASK.
"""
import os
from pathlib import Path
import stat

from ...core import loads_strict
from .publisher_profile import ACTOR, REPOSITORY, PublisherProfile

MOUNT = Path('/run/r7-publisher-activation')
_FIELDS = frozenset({'schemaVersion', 'enabled', 'actor', 'repository',
                     'revision', 'validatorRevision', 'registryDelegation'})


def _owner_file(directory, name, maximum):
    path = directory / name
    if path.is_symlink():
        raise RuntimeError('R7_PUBLISHER_MOUNT_FILE_INSECURE')
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except (OSError, ValueError):
        raise RuntimeError('R7_PUBLISHER_MOUNT_FILE_REQUIRED') from None
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or
                stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1 or
                not 1 <= info.st_size <= maximum):
            raise RuntimeError('R7_PUBLISHER_MOUNT_FILE_INSECURE')
        data = stream.read(maximum + 1)
        if len(data) != info.st_size:
            raise RuntimeError('R7_PUBLISHER_MOUNT_FILE_CHANGED')
        return data


def load_owner_publisher_mount(root=MOUNT):
    """Return (profile, grant) or (None, None) when NO mount is installed.

    The default absolute path is fixed in trusted server source, not selected
    by PR, runtime environment or machine caller. The root override exists
    for offline tests and trusted unit composition only.
    """
    directory = Path(root)
    if not directory.is_absolute():
        raise RuntimeError('R7_PUBLISHER_MOUNT_PATH_INVALID')
    if not directory.exists() and not directory.is_symlink():
        return None, None
    if directory.is_symlink() or not directory.is_dir():
        raise RuntimeError('R7_PUBLISHER_MOUNT_INSECURE')
    info = directory.stat()
    if (info.st_uid != os.geteuid() or
            stat.S_IMODE(info.st_mode) != 0o700 or
            not stat.S_ISDIR(info.st_mode)):
        raise RuntimeError('R7_PUBLISHER_MOUNT_INSECURE')
    if {entry.name for entry in directory.iterdir()} != {'profile.json', 'grant'}:
        raise RuntimeError('R7_PUBLISHER_MOUNT_INCOMPLETE')
    try:
        raw = _owner_file(directory, 'profile.json', 2048)
        data = loads_strict(raw)
    except (UnicodeError, TypeError, ValueError) as exc:
        raise RuntimeError('R7_PUBLISHER_MOUNT_PROFILE_INVALID') from exc
    if (type(data) is not dict or set(data) != _FIELDS or
            data['schemaVersion'] != 1 or type(data['schemaVersion']) is not int or
            data['enabled'] is not True or
            data['actor'] != ACTOR or data['repository'] != REPOSITORY or
            data['registryDelegation'] is not True):
        raise RuntimeError('R7_PUBLISHER_MOUNT_PROFILE_DENIED')
    try:
        profile = PublisherProfile(
            enabled=True, revision=data['revision'],
            validator_revision=data['validatorRevision'],
            registry_delegation=True)
    except (TypeError, ValueError) as exc:
        raise RuntimeError('R7_PUBLISHER_MOUNT_REVIEW_PINS_INVALID') from exc
    try:
        grant = _owner_file(directory, 'grant', 257).decode('ascii')
    except UnicodeError:
        raise RuntimeError('R7_PUBLISHER_MOUNT_GRANT_INVALID') from None
    if grant.endswith('\n'):
        grant = grant[:-1]
    from ...r5_read_candidate import _GRANT
    if not _GRANT.fullmatch(grant):
        raise RuntimeError('R7_PUBLISHER_MOUNT_GRANT_INVALID')
    return profile, grant

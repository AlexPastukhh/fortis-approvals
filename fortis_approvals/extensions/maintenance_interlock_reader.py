"""Read-only controller record reader; no host command, writer, or fallback.

Actual owner mount and independently durable latest-pin provider are not
yet provisioned. The caller must bind the reviewed fixed mount in the
protected release composition. Missing or invalid record is a STOP.
"""
from contextlib import contextmanager
import fcntl
import os
from pathlib import Path
import stat

from ..core import Denied, loads_strict
from ..r7_registry_reader_mount import _check_owner_readonly_mount
from ..integrations.registry_contracts.maintenance_contract import bind_record

MOUNT=Path('/run/r7-maintenance')
LATEST_MOUNT=Path('/run/r7-maintenance-anchor')
_MAX_BYTES=8192


def _read_record(dirfd, *, name='record.json', maximum=_MAX_BYTES):
    fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=dirfd)
    with os.fdopen(fd,'rb') as source:
        info=os.fstat(source.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_nlink!=1
                or stat.S_IMODE(info.st_mode)!=0o444 or not 0<info.st_size<=maximum):
            raise Denied('MAINTENANCE_INTERLOCK_FILE')
        raw=source.read(maximum+1)
        if len(raw)!=info.st_size:
            raise Denied('MAINTENANCE_INTERLOCK_FILE')
    return loads_strict(raw)


def read_owner_interlock(*, instance_id, scope_digest, generation,
                         expected_digest, root=MOUNT):
    try:
        # Root override is for isolated source tests only; actual runtime
        # must use the fixed dedicated read-only mount above.
        if not isinstance(root,Path) or not root.is_absolute() or root.is_symlink():
            raise Denied('MAINTENANCE_INTERLOCK_DIRECTORY')
        _check_owner_readonly_mount(root)
        dirfd=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:
            info=os.fstat(dirfd)
            if info.st_uid!=0 or stat.S_IMODE(info.st_mode)!=0o555:
                raise Denied('MAINTENANCE_INTERLOCK_DIRECTORY')
            record=_read_record(dirfd)
        finally:
            os.close(dirfd)
        return bind_record(record,instance_id=instance_id,scope_digest=scope_digest,
                           generation=generation,expected_digest=expected_digest)
    except Exception:
        raise Denied('MAINTENANCE_STATE_UNKNOWN') from None



def _read_owner_latest(root):
    """Root-owned projection on its own exact read-only mount."""
    if not isinstance(root,Path) or not root.is_absolute() or root.is_symlink():
        raise Denied('MAINTENANCE_LATEST_PIN_DIRECTORY')
    _check_owner_readonly_mount(root)
    fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        info=os.fstat(fd)
        if info.st_uid!=0 or stat.S_IMODE(info.st_mode)!=0o555:
            raise Denied('MAINTENANCE_LATEST_PIN_DIRECTORY')
        pin=_read_record(fd)
        current=root.stat(follow_symlinks=False)
        if (info.st_dev,info.st_ino)!=(current.st_dev,current.st_ino):
            raise Denied('MAINTENANCE_LATEST_PIN_DIRECTORY')
        return pin,(info.st_dev,info.st_ino)
    finally:os.close(fd)


def read_latest_interlock(*, instance_id, scope_digest, generation,
                          root=MOUNT, latest_root=LATEST_MOUNT):
    """Never take an expected digest from the interlock itself.

    A missing, pending, stale, mixed or aliased projection is restrictive.
    The protected controller independently verifies its host anchor and both
    exact mounts before starting/returning a generation.
    """
    from ..integrations.registry_contracts.maintenance_contract import bind_latest_projection
    try:
        latest,identity=_read_owner_latest(latest_root)
        info=root.stat(follow_symlinks=False)
        original=(info.st_dev,info.st_ino)
        if latest['state']!='Committed' or original==identity:
            raise Denied('MAINTENANCE_LATEST_PIN_CHANGED')
        record=read_owner_interlock(instance_id=instance_id,scope_digest=scope_digest,
            generation=generation,expected_digest=latest['interlockDigest'],root=root)
        bind_latest_projection(latest,record)
        after=root.stat(follow_symlinks=False)
        if (after.st_dev,after.st_ino)!=original or _read_owner_latest(latest_root)!=(latest,identity):
            raise Denied('MAINTENANCE_LATEST_PIN_CHANGED')
        return record,latest
    except Exception:
        raise Denied('MAINTENANCE_STATE_UNKNOWN') from None


def read_controller_begin(*, expected_digest=None, root=LATEST_MOUNT):
    """Read the fixed root-owned intent, never a path or proof from a frame."""
    from ..integrations.registry_contracts import semantic_contract as sc
    from ..integrations.registry_contracts.maintenance_contract import controller_begin_projection
    if expected_digest is not None:sc.hex_id(expected_digest,64)
    _check_owner_readonly_mount(root)
    fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        info=os.fstat(fd)
        sc.need(info.st_uid==0 and stat.S_IMODE(info.st_mode)==0o555,
                'MAINTENANCE_CONTROLLER_BEGIN_MOUNT_REQUIRED')
        projection=controller_begin_projection(_read_record(fd,name='begin.json',maximum=65536))
        sc.need((expected_digest is None or sc.digest(projection['intent'])==expected_digest)
                and (info.st_dev,info.st_ino)==(root.stat().st_dev,root.stat().st_ino),
                'MAINTENANCE_CONTROLLER_BEGIN_CHANGED')
        return projection
    finally:os.close(fd)


class InterlockReservations:
    """Shared process reservations on the controller's stable mount inode.

    The directory is never exchanged while any participant uses it. The
    controller atomically replaces record.json under the existing host
    controller lock, then checks this inode from its isolated inspector.
    """

    def __init__(self, root=MOUNT):
        if not isinstance(root,Path) or not root.is_absolute():
            raise Denied('MAINTENANCE_INTERLOCK_DIRECTORY')
        self.root=root

    @contextmanager
    def _lock(self, mode, *, busy=False):
        descriptor=None
        try:
            _check_owner_readonly_mount(self.root)
            descriptor=os.open(self.root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
            directory=os.fstat(descriptor)
            if directory.st_uid!=0 or stat.S_IMODE(directory.st_mode)!=0o555:
                raise Denied('MAINTENANCE_INTERLOCK_DIRECTORY')
            try:
                fcntl.flock(descriptor,mode|fcntl.LOCK_NB)
            except BlockingIOError:
                if not busy:
                    raise Denied('RELEASE_MAINTENANCE') from None
                acquired=False
            else:
                acquired=True
            current=self.root.stat(follow_symlinks=False)
            if (current.st_dev,current.st_ino)!=(directory.st_dev,directory.st_ino):
                raise Denied('MAINTENANCE_INTERLOCK_DIRECTORY')
        except OSError:
            if descriptor is not None:
                os.close(descriptor)
            raise Denied('MAINTENANCE_STATE_UNKNOWN') from None
        except BaseException:
            if descriptor is not None:
                os.close(descriptor)
            raise
        try:
            yield acquired
        finally:
            if descriptor is not None:
                os.close(descriptor)

    def reserve(self):
        return self._lock(fcntl.LOCK_SH)

    @contextmanager
    def exclusive(self):
        """Hold a quiescent inode for the complete controller inspection."""
        with self._lock(fcntl.LOCK_EX,busy=True) as acquired:
            yield acquired

    def drained(self):
        with self.exclusive() as acquired:
            return acquired

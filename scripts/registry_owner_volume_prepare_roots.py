"""Owner-only Linux fresh-root helper, intended ONLY for reviewed isolated mounts.

No Docker/API/host path access. Separate owner GO and exclusive change fence are
prerequisites; this module never creates/deletes files or volumes. All three
roots must pass fresh-root checks before the first fchown. Partial effect STOP.
"""
import json
import os
import stat
from contextlib import ExitStack

ROOTS = (
    ('/run/fortis-registry-state', 20002, 20002, 0o700),
    ('/run/fortis-registry-runtime', 20002, 20002, 0o700),
    ('/run/fortis-registry-read', 20002, 10001, 0o2710),
)
IDENTITY_MAP = ('0', '0', '4294967295')


def require(condition, code):
    if not condition:
        raise RuntimeError(code)


def runtime(uid, gid, capabilities):
    # This proves the container's Linux VM view, not independent host identity.
    require(os.getresuid() == (uid,) * 3 and os.getresgid() == (gid,) * 3,
            'ROOT_HELPER_IDENTITY_INVALID')
    require(set(os.getgroups()) <= {gid}, 'ROOT_HELPER_GROUPS_INVALID')
    for path in ('/proc/self/uid_map', '/proc/self/gid_map'):
        with open(path, encoding='ascii') as f:
            require(tuple(f.read(4096).split()) == IDENTITY_MAP,
                    'ROOT_HELPER_MAP_NOT_IDENTITY')
    fields = {}
    needed = {'CapInh', 'CapPrm', 'CapEff', 'CapBnd', 'CapAmb',
              'NoNewPrivs', 'Seccomp', 'TracerPid'}
    with open('/proc/self/status', encoding='ascii') as f:
        for line in f:
            k, sep, v = line.partition(':')
            if sep and k in needed:
                require(k not in fields, 'ROOT_HELPER_STATUS_DUPLICATE')
                fields[k] = v.strip()
    require(set(fields) == needed, 'ROOT_HELPER_STATUS_MISSING')
    require(all(int(fields[k], 16) == capabilities
                for k in ('CapPrm', 'CapEff', 'CapBnd'))
            and all(int(fields[k], 16) == 0 for k in ('CapInh', 'CapAmb'))
            and fields['NoNewPrivs'] == '1' and fields['Seccomp'] == '2'
            and fields['TracerPid'] == '0', 'ROOT_HELPER_CONFINEMENT_INVALID')
    require(os.statvfs('/').f_flag & os.ST_RDONLY, 'ROOT_HELPER_ROOT_NOT_READONLY')


def mount_rows(readonly):
    with open('/proc/self/mountinfo', encoding='ascii') as f:
        raw = f.read(262145)
    require(len(raw) <= 262144, 'ROOT_HELPER_MOUNTINFO_TOO_LARGE')
    rows = [line.split() for line in raw.splitlines()]
    require(all(len(r) >= 10 and '-' in r for r in rows),
            'ROOT_HELPER_MOUNTINFO_INVALID')
    for path, *_ in ROOTS:
        matches = [r for r in rows if r[4] == path]
        require(len(matches) == 1 and not any(r[4].startswith(path + '/') for r in rows),
                'ROOT_HELPER_MOUNT_MISSING_OR_NESTED')
        flags = set(matches[0][5].split(','))
        require(('ro' in flags) == readonly and ('rw' in flags) != readonly,
                'ROOT_HELPER_MOUNT_ACCESS_INVALID')


def metadata(row):
    return {'uid': row.st_uid, 'gid': row.st_gid, 'mode': stat.S_IMODE(row.st_mode),
            'device': row.st_dev, 'inode': row.st_ino}


def open_root(stack, path, readonly):
    require(os.path.realpath(path) == path, 'ROOT_HELPER_PATH_ALIAS')
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    stack.callback(os.close, fd)
    row = os.fstat(fd)
    link = os.lstat(path)
    require(stat.S_ISDIR(row.st_mode) and stat.S_ISDIR(link.st_mode)
            and (row.st_dev, row.st_ino) == (link.st_dev, link.st_ino),
            'ROOT_HELPER_ROOT_ALIAS')
    require(bool(os.fstatvfs(fd).f_flag & os.ST_RDONLY) == readonly,
            'ROOT_HELPER_FD_ACCESS_INVALID')
    os.lseek(fd, 0, os.SEEK_SET)
    with os.scandir(fd) as entries:
        require(next(entries, None) is None, 'ROOT_HELPER_ROOT_NOT_EMPTY')
    return fd, row


def prepare():
    # CAP_CHOWN (0) and CAP_FOWNER (3) only; GID 10001 permits socket setgid.
    runtime(0, 10001, 0x9)
    mount_rows(False)
    with ExitStack() as stack:
        roots = []
        identities = set()
        for path, uid, gid, mode in ROOTS:
            fd, row = open_root(stack, path, False)
            require((row.st_uid, row.st_gid, stat.S_IMODE(row.st_mode)) == (0, 0, 0o755),
                    'ROOT_HELPER_NOT_FRESH_DEFAULT_ROOT')
            ident = (row.st_dev, row.st_ino)
            require(ident not in identities, 'ROOT_HELPER_ROOT_ALIAS')
            identities.add(ident)
            roots.append((path, fd, uid, gid, mode, ident))
        result = []
        for path, fd, uid, gid, mode, ident in roots:
            # No retries, recursion, compensation, path-based chmod or cleanup.
            before = os.fstat(fd)
            require((before.st_dev, before.st_ino) == ident
                    and (before.st_uid, before.st_gid, stat.S_IMODE(before.st_mode)) == (0, 0, 0o755),
                    'ROOT_HELPER_PREWRITE_STAT_CHANGED')
            os.lseek(fd, 0, os.SEEK_SET)
            with os.scandir(fd) as entries:
                require(next(entries, None) is None, 'ROOT_HELPER_PREWRITE_NOT_EMPTY')
            os.fchown(fd, uid, gid)
            os.fchmod(fd, mode)
            os.fsync(fd)
            after = os.fstat(fd)
            require((after.st_uid, after.st_gid, stat.S_IMODE(after.st_mode)) == (uid, gid, mode)
                    and (after.st_dev, after.st_ino) == ident, 'ROOT_HELPER_POSTSTAT_INVALID')
            row = dict(path=path, **metadata(after))
            result.append(row)
            print(json.dumps({'preparedRoot': row}, sort_keys=True), flush=True)
        print(json.dumps({'result': 'E13B_VOLUME_ROOT_PREPARE_PASS', 'roots': result},
                         sort_keys=True), flush=True)


if __name__ == '__main__':
    try:
        prepare()
    except Exception:
        print('E13B_VOLUME_ROOT_PREPARE_STOP_NO_RETRY_NO_CLEANUP', flush=True)
        raise

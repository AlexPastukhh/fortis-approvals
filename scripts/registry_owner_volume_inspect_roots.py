"""Independent non-root Linux volume inspector; no mutation primitives.

Mounts must be read-only; empty root ownership and inode are measured, not
assumed from the preparer receipt. This is not host acceptance or writer fencing.
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


def inspect_roots():
    runtime(20002, 20002, 0)
    mount_rows(True)
    with ExitStack() as stack:
        seen = set()
        result = []
        for path, uid, gid, mode in ROOTS:
            _, row = open_root(stack, path, True)
            require((row.st_uid, row.st_gid, stat.S_IMODE(row.st_mode)) == (uid, gid, mode),
                    'ROOT_INSPECT_OWNER_MODE_INVALID')
            ident = (row.st_dev, row.st_ino)
            require(ident not in seen, 'ROOT_INSPECT_ROOT_ALIAS')
            seen.add(ident)
            result.append(dict(path=path, **metadata(row)))
        print(json.dumps({'result': 'E13B_VOLUME_ROOT_INSPECT_READONLY_PASS', 'roots': result},
                         sort_keys=True), flush=True)


if __name__ == '__main__':
    inspect_roots()

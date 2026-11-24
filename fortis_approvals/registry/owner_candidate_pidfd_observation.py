"""Owner-invoked READ-ONLY Registry-process observation for E1.3b.

This source-only tool is run *separately* from the Registry service by the
owner, after Docker image/container/command/source review. It is NOT a
service endpoint, Registry process self-assertion, proof of Docker provenance,
protected witness, owner attestation, release GO or permission to seal a
Gateway mount automatically. The output MUST be independently correlated
with Docker Engine inspect/top, reviewed image SHA and the owner mount.
The selected numeric PID is *inside* the Registry container PID namespace;
the Docker Engine host PID cannot be passed in without independent mapping.

No DB read, write, process signal, Docker socket, privilege change or network.
One AF_UNIX connect WITHOUT a request body to correlate selected pidfd and
the actual socket peer; the Registry listener may count/reject this probe.
Only invoke against an explicitly approved non-Production Registry pilot.
"""
import argparse
import json
import os
import re
from pathlib import Path
import select
import socket
import stat
import sys

from ..core import Denied
from ..integrations.registry.owner_pinned_pidfd import (
    _boot_id, _require_pidfs, kernel_live_peer,
)

_SOCKET=Path('/run/fortis-registry-read/reader.sock')
_CONFIG=Path('/run/fortis-registry-runtime/profile.json')
_MODULE='fortis_approvals.registry.local_candidate_read_service'
_RESULT='SOURCE_ONLY_REGISTRY_PIDFD_PROCESS_OBSERVATION'


def _stop(name):
    raise Denied('REGISTRY_PIDFD_OBSERVATION_'+name)


def _read(path, limit):
    try:
        with path.open('rb') as stream:
            data=stream.read(limit+1)
        if not 0<len(data)<=limit:
            _stop('PROC_UNAVAILABLE')
        return data
    except Denied:
        raise
    except OSError:
        _stop('PROC_UNAVAILABLE')


def _process(pid, registry_uid, registry_gid, reader_gid, planner_key_digest=None):
    root=Path('/proc')/str(pid)
    raw=_read(root/'stat',8192).decode('ascii')
    prefix=str(pid)+' ('
    tail=raw.rfind(') ')
    if not raw.startswith(prefix) or tail<0:
        _stop('STAT_INVALID')
    parts=raw[tail+2:].split()
    if len(parts)<20 or parts[0] in ('Z','X','x','D'):
        _stop('PROCESS_NOT_LIVE')
    try:
        start=int(parts[19])
    except (ValueError, OverflowError):
        _stop('STAT_INVALID')
    if start<=0:
        _stop('STAT_INVALID')
    raw_cmd=_read(root/'cmdline',512)
    argv=raw_cmd.rstrip(b'\0').split(b'\0')
    expected=[b'-m',_MODULE.encode('ascii'),b'--owner-config',os.fsencode(_CONFIG)]
    if planner_key_digest is not None:
        if type(planner_key_digest) is not str or not re.fullmatch('[0-9a-f]{64}',planner_key_digest):
            _stop('PLANNER_DIGEST_DENIED')
        expected += [b'--functional-planner-key-digest',planner_key_digest.encode('ascii')]
    if (len(argv)!=len(expected)+1 or Path(os.fsdecode(argv[0])).name not in
        ('python','python3','python3.11') or argv[1:] != expected):
        _stop('COMMAND_MISMATCH')
    status=_read(root/'status',16384).decode('ascii')
    fields={}
    wanted={'Uid','Gid','Groups','CapInh','CapPrm','CapEff','CapBnd',
            'CapAmb','NoNewPrivs','Seccomp','TracerPid'}
    for line in status.splitlines():
        key,sep,value=line.partition(':')
        if sep and key in wanted:
            if key in fields:_stop('STATUS_INVALID')
            fields[key]=value.strip()
    if set(fields)!=wanted:_stop('STATUS_INVALID')
    try:
        uids=[int(x) for x in fields['Uid'].split()]
        gids=[int(x) for x in fields['Gid'].split()]
        groups=[int(x) for x in fields['Groups'].split()]
        caps=[int(fields[k],16) for k in
              ('CapInh','CapPrm','CapEff','CapBnd','CapAmb')]
        nop=int(fields['NoNewPrivs']); sec=int(fields['Seccomp'])
        tracer=int(fields['TracerPid'])
    except (ValueError,OverflowError):
        _stop('STATUS_INVALID')
    if (uids!=[registry_uid]*4 or gids!=[registry_gid]*4
            # Only the Registry's original primary group is allowed. Even
            # an unexpected root/owner supplementary group makes a host
            # process observation inadmissible, irrespective of CapDrop.
            or groups not in ([], [registry_gid]) or any(caps)
            or nop!=1 or sec!=2 or tracer!=0):
        _stop('PROCESS_ISOLATION_DENIED')
    return {'startTicks':start,'pid':pid,'uid':registry_uid,
            'gid':registry_gid,'groups':sorted(groups),
            'pidNamespace':os.readlink(root/'ns/pid')}


def _socket_stat(registry_uid,reader_gid):
    try:
        folder=_SOCKET.parent.lstat();row=_SOCKET.lstat()
        runtime=_CONFIG.parent.lstat();cfg=_CONFIG.lstat()
    except OSError:
        _stop('SOCKET_OR_CONFIG_UNAVAILABLE')
    if (not stat.S_ISDIR(folder.st_mode) or
        stat.S_IMODE(folder.st_mode)!=0o2710 or
        folder.st_uid!=registry_uid or folder.st_gid!=reader_gid or
        not stat.S_ISSOCK(row.st_mode) or row.st_nlink!=1 or
        stat.S_IMODE(row.st_mode)!=0o660 or
        row.st_uid!=registry_uid or row.st_gid!=reader_gid or
        not stat.S_ISDIR(runtime.st_mode) or
        stat.S_IMODE(runtime.st_mode)!=0o700 or
        runtime.st_uid!=registry_uid or
        not stat.S_ISREG(cfg.st_mode) or cfg.st_nlink!=1 or
        stat.S_IMODE(cfg.st_mode)!=0o600 or cfg.st_uid!=registry_uid):
        _stop('SOCKET_OR_CONFIG_PERMISSIONS_DENIED')
    return (row.st_dev,row.st_ino)


def observe(*,pid,registry_uid,registry_gid,reader_gid,planner_key_digest=None):
    """Check one owner-selected process, never find/assign its own identity."""
    if (type(pid) is not int or not 0<pid<2**31 or
        any(type(v) is not int or not 0<v<2**31 for v in
            (registry_uid,registry_gid,reader_gid)) or
        reader_gid==registry_gid or
        os.getresuid()!=(registry_uid,)*3 or
        os.getresgid()!=(registry_gid,)*3 or
        os.getpid()==pid):
        _stop('CALLER_OR_ARGUMENTS_DENIED')
    _require_pidfs()
    boot=_boot_id()
    extra=() if planner_key_digest is None else (planner_key_digest,)
    prior=_process(pid,registry_uid,registry_gid,reader_gid,*extra)
    socket_pair=_socket_stat(registry_uid,reader_gid)
    fd=None
    try:
        fd=os.pidfd_open(pid,0)
        inode=os.fstat(fd).st_ino
        if inode<=0:_stop('PROCESS_INODE_INVALID')
        poller=select.poll()
        poller.register(fd,select.POLLIN|select.POLLHUP|
                        select.POLLERR|select.POLLNVAL)
        if poller.poll(0):_stop('PROCESS_EXITED')
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as sock:
            sock.settimeout(2)
            sock.connect(str(_SOCKET))
            peer=kernel_live_peer(sock,
                expected_uid=registry_uid,expected_gid=registry_gid)
            if peer[0]!=pid or peer[3]!=inode or peer[4]!=boot:
                _stop('LISTENER_PROCESS_MISMATCH')
        if (_boot_id()!=boot or
                _process(pid,registry_uid,registry_gid,reader_gid,*extra)!=prior or
                _socket_stat(registry_uid,reader_gid)!=socket_pair or
                poller.poll(0)):
            _stop('OBSERVATION_STALE')
        return dict(schemaVersion=1,result=_RESULT,
                    selectedPid=pid,registryPidfdInode=inode,
                    registryKernelBootId=boot,
                    registryUid=registry_uid,registryGid=registry_gid,
                    readerGid=reader_gid,socketDevice=socket_pair[0],
                    socketInode=socket_pair[1],
                    pidNamespace=prior['pidNamespace'],
                    startTicks=prior['startTicks'],
                    containerImageVerified=False,
                    ownerAcceptanceVerified=False,
                    profileSealed=False,releaseAdmitted=False,
                    runtimeActivationAllowed=False)
    except Denied:
        raise
    except (OSError,ValueError,TypeError):
        _stop('OBSERVATION_UNAVAILABLE')
    finally:
        if fd is not None:
            try:os.close(fd)
            except OSError:pass


def main(argv=None):
    parser=argparse.ArgumentParser(description='Owner-only Registry pidfd read-only probe; never GO')
    parser.add_argument('--selected-pid',type=int,required=True)
    parser.add_argument('--registry-uid',type=int,required=True)
    parser.add_argument('--registry-gid',type=int,required=True)
    parser.add_argument('--reader-gid',type=int,required=True)
    parser.add_argument('--functional-planner-key-digest')
    opts=parser.parse_args(argv)
    try:
        output=observe(pid=opts.selected_pid,registry_uid=opts.registry_uid,
                       registry_gid=opts.registry_gid,reader_gid=opts.reader_gid,
                       planner_key_digest=opts.functional_planner_key_digest)
    except Denied as exc:
        print('REGISTRY_PIDFD_OBSERVATION_STOP: '+str(exc),file=sys.stderr)
        return 1
    print(json.dumps(output,sort_keys=True,separators=(',',':')))
    return 0


if __name__=='__main__':sys.exit(main())

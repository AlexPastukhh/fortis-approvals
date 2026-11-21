"""Linux owner/Registry runtime placement preflight, source-only and fail-closed.

This module reads an owner-pinned layout, /proc, the socket inode and private
state paths. It neither provisions a process, changes permissions nor attests
a protected anchor. Passing local checks NEVER enables Registry admission.
"""
import os
from pathlib import Path
import stat

from ..core import Denied, Stale
from .owner_peer_boundary import _endpoint, _profile
from .state_journal import _hash, _need, _hex, _uuid

_ROLES=('owner','registry','repo')
_LAYOUT_KEYS={'schemaVersion','format','peerProfileDigest','instanceId','scopeDigest','bootId',
              'ownerPid','registryPid','repoPid','ownerStatePath','registryStatePath',
              'repoUid','repoGid'}
_MAX_PROC_STATUS=16_384
_MAX_PROC_META=8_192


def _full_path(value):
    _need(type(value) is str and value.startswith('/') and
          len(os.fsencode(value))<=4096 and
          all(part not in ('..','.') for part in value.split('/')[1:]) and
          not value.endswith('/') and '//' not in value,
          'REGISTRY_ISOLATION_PATH_INVALID')
    return Path(value)


def _layout(value,digest,peer):
    _need(type(value) is dict and set(value)==_LAYOUT_KEYS
          and type(value['schemaVersion']) is int and value['schemaVersion']==1
          and value['format']=='owner-registry-linux-layout-candidate-v1'
          and value['peerProfileDigest']==_hash(peer)
          and value['instanceId']==peer['instanceId']
          and value['scopeDigest']==peer['scopeDigest']
          and _uuid(value['bootId'])
          and _hex(digest,64) and _hash(value)==digest,
          'REGISTRY_ISOLATION_PROFILE_INVALID')
    pids=[value[r+'Pid'] for r in _ROLES]
    _need(all(type(pid) is int and pid>1 for pid in pids)
          and len(set(pids))==len(pids)
          and all(type(value[k]) is int and 0<value[k]<2**31-1 for k in
                  ('repoUid','repoGid'))
          and len({value['repoUid'],peer['registryUid'],peer['authorityUid'],
                   peer['operatorUid']})==4,
          'REGISTRY_ISOLATION_PROFILE_INVALID')
    owner=_full_path(value['ownerStatePath'])
    registry=_full_path(value['registryStatePath'])
    _need(owner!=registry and owner.parent!=registry.parent
          and owner.parent!=Path(peer['socketPath']).parent
          and registry.parent!=Path(peer['socketPath']).parent
          and owner.name.endswith('.sqlite') and registry.name.endswith('.sqlite'),
          'REGISTRY_ISOLATION_PATH_INVALID')
    return value


def _proc_text(path,limit):
    try:
        with path.open('rb') as fd:
            raw=fd.read(limit+1)
        _need(len(raw)<=limit,'REGISTRY_ISOLATION_PROC_LIMIT')
        return raw.decode('ascii')
    except (OSError,UnicodeError):
        raise Denied('REGISTRY_ISOLATION_PROC_UNAVAILABLE') from None


def _boot_id():
    boot=_proc_text(Path('/proc/sys/kernel/random/boot_id'),128).strip()
    _need(_uuid(boot),'REGISTRY_ISOLATION_BOOT_ID_INVALID')
    return boot


def _start_ticks(raw,pid):
    # Linux /proc/PID/stat comm can contain spaces or parentheses; find
    # the final ') ' before state, then field 22 = index 19 after state.
    _need(raw.startswith(str(pid)+' ('),'REGISTRY_ISOLATION_PROC_INVALID')
    last=raw.rfind(') ')
    _need(last>0,'REGISTRY_ISOLATION_PROC_INVALID')
    parts=raw[last+2:].split()
    _need(len(parts)>=20 and parts[0] not in ('Z','X','x','D'),
          'REGISTRY_ISOLATION_PROC_INVALID')
    try:
        ticks=int(parts[19])
    except ValueError:
        raise Denied('REGISTRY_ISOLATION_PROC_INVALID') from None
    _need(ticks>0,'REGISTRY_ISOLATION_PROC_INVALID')
    return ticks


def _read_process(pid):
    """Real kernel read; injected snapshots only exist in private test seam."""
    prefix=Path('/proc')/str(pid)
    start=_start_ticks(_proc_text(prefix/'stat',_MAX_PROC_META),pid)
    status=_proc_text(prefix/'status',_MAX_PROC_STATUS)
    lines={}
    for line in status.splitlines():
        key,sep,value=line.partition(':')
        if sep and key in {'Uid','Gid','Groups','CapInh','CapPrm','CapEff',
                           'CapBnd','CapAmb','NoNewPrivs','Seccomp','TracerPid'}:
            _need(key not in lines,'REGISTRY_ISOLATION_PROC_INVALID')
            lines[key]=value.strip()
    _need(set(lines)=={'Uid','Gid','Groups','CapInh','CapPrm','CapEff',
                       'CapBnd','CapAmb','NoNewPrivs','Seccomp','TracerPid'},
          'REGISTRY_ISOLATION_PROC_INVALID')
    try:
        uids=[int(x) for x in lines['Uid'].split()]
        gids=[int(x) for x in lines['Gid'].split()]
        groups=[int(x) for x in lines['Groups'].split()]
        caps=[int(lines[x],16) for x in ('CapInh','CapPrm','CapEff','CapBnd','CapAmb')]
        nnp=int(lines['NoNewPrivs']);seccomp=int(lines['Seccomp'])
        tracer=int(lines['TracerPid'])
        mount=os.readlink(prefix/'ns/mnt')
        cg=_proc_text(prefix/'cgroup',_MAX_PROC_META)
    except (ValueError,OSError):
        raise Denied('REGISTRY_ISOLATION_PROC_INVALID') from None
    _need(len(uids)==4 and len(gids)==4 and len(set(groups))==len(groups)
          and groups==sorted(groups) and len(groups)<=64
          and len(mount)>8 and mount.startswith('mnt:[') and mount.endswith(']')
          and 0<len(cg.strip())<_MAX_PROC_META,
          'REGISTRY_ISOLATION_PROC_INVALID')
    end=_start_ticks(_proc_text(prefix/'stat',_MAX_PROC_META),pid)
    if start!=end:
        raise Stale('REGISTRY_ISOLATION_PROCESS_REPLACED')
    return {'pid':pid,'startTicks':start,'uids':uids,'gids':gids,
            'groups':groups,'capInh':caps[0],'capPrm':caps[1],
            'capEff':caps[2],'capBnd':caps[3],'capAmb':caps[4],
            'noNewPrivs':nnp,'seccomp':seccomp,'tracerPid':tracer,
            'mountNamespace':mount,'cgroup':cg}


def _check_nosymlink_components(path):
    _need(path.is_absolute(),'REGISTRY_ISOLATION_PATH_INVALID')
    # Symlink-free ancestors, as well as the exact file/parent, required.
    curr=Path('/')
    for part in path.parts[1:]:
        curr=curr/part
        try:
            info=curr.lstat()
        except OSError:
            raise Denied('REGISTRY_ISOLATION_PATH_UNAVAILABLE') from None
        _need(not stat.S_ISLNK(info.st_mode),'REGISTRY_ISOLATION_SYMLINK')
    return True


def _read_state_file(path):
    _check_nosymlink_components(path)
    try:
        parent=path.parent.lstat();entry=path.lstat()
    except OSError:
        raise Denied('REGISTRY_ISOLATION_PATH_UNAVAILABLE') from None
    _need(stat.S_ISDIR(parent.st_mode) and stat.S_ISREG(entry.st_mode)
          and entry.st_nlink==1,'REGISTRY_ISOLATION_STATE_TYPE')
    return {'path':str(path),'parentUid':parent.st_uid,
            'parentGid':parent.st_gid,'parentMode':stat.S_IMODE(parent.st_mode),
            'fileUid':entry.st_uid,'fileGid':entry.st_gid,
            'fileMode':stat.S_IMODE(entry.st_mode),
            'parentDev':parent.st_dev,'fileDev':entry.st_dev,
            'parentInode':parent.st_ino,'fileInode':entry.st_ino}


def _assess(layout,peer,processes,files,endpoint):
    """Structural assessment; facts alone cannot grant protected authority."""
    _need(type(processes) is dict and set(processes)==set(_ROLES)
          and type(files) is dict and set(files)=={'owner','registry'},
          'REGISTRY_ISOLATION_OBSERVATION_INVALID')
    expected={'owner':(peer['authorityUid'],peer['authorityGid']),
              'registry':(peer['registryUid'],peer['registryGid']),
              'repo':(layout['repoUid'],layout['repoGid'])}
    for role in _ROLES:
        row=processes[role];uid,gid=expected[role]
        _need(type(row) is dict and set(row)=={'pid','startTicks','uids','gids','groups',
                   'capInh','capPrm','capEff','capBnd','capAmb',
                   'noNewPrivs','seccomp','tracerPid','mountNamespace','cgroup'}
              and row['pid']==layout[role+'Pid']
              and type(row['startTicks']) is int and row['startTicks']>0
              and type(row['uids']) is list and row['uids']==[uid]*4
              and type(row['gids']) is list and row['gids']==[gid]*4
              and type(row['groups']) is list and len(row['groups'])<=64
              and all(type(x) is int and x>0 for x in row['groups'])
              and len(set(row['groups']))==len(row['groups'])
              and (role=='owner' or peer['authorityGid'] not in row['groups']),
              'REGISTRY_ISOLATION_PROCESS_IDENTITY')
        _need(all(type(row[k]) is int and row[k]==0 for k in
                  ('capInh','capPrm','capEff','capBnd','capAmb','tracerPid'))
              and type(row['noNewPrivs']) is int and row['noNewPrivs']==1
              and type(row['seccomp']) is int and row['seccomp']==2
              and type(row['mountNamespace']) is str
              and row['mountNamespace'].startswith('mnt:[')
              and type(row['cgroup']) is str and row['cgroup'].strip(),
              'REGISTRY_ISOLATION_PROCESS_PRIVILEGE')
    _need(len({processes[r]['mountNamespace'] for r in _ROLES})==3
          and len({processes[r]['cgroup'] for r in _ROLES})==3,
          'REGISTRY_ISOLATION_SHARED_RUNTIME')
    for role in ('owner','registry'):
        row=files[role];uid,gid=expected[role]
        _need(type(row) is dict and set(row)=={'path','parentUid','parentGid',
                  'parentMode','fileUid','fileGid','fileMode','parentDev','fileDev',
                  'parentInode','fileInode'}
              and row['path']==layout[role+'StatePath']
              and row['parentUid']==row['fileUid']==uid
              and row['parentGid']==row['fileGid']==gid
              and row['parentMode']==0o700 and row['fileMode']==0o600
              and row['parentDev']==row['fileDev']
              and all(type(row[k]) is int and row[k]>0 for k in
                  ('parentDev','fileDev','parentInode','fileInode')),
              'REGISTRY_ISOLATION_STATE_PERMISSIONS')
    _need(files['owner']['fileDev']!=files['registry']['fileDev']
          and files['owner']['parentDev']!=files['registry']['parentDev'],
          'REGISTRY_ISOLATION_SHARED_STATE_DEVICE')
    _need(type(endpoint) is tuple and len(endpoint)==2 and
          all(type(v) is int and v>0 for v in endpoint),
          'REGISTRY_ISOLATION_SOCKET_INVALID')
    projection={'schemaVersion':1,'format':'owner-registry-isolation-observation-v1',
                'instanceId':peer['instanceId'],
                'scopeDigest':peer['scopeDigest'],'bootId':layout['bootId'],
                'peerProfileDigest':_hash(peer),
                'layoutDigest':_hash(layout),
                'processes':processes,'stateFiles':files,
                'socketDev':endpoint[0],'socketInode':endpoint[1]}
    return {'result':'OWNER_RUNTIME_ISOLATION_OBSERVATION_CANDIDATE',
            'observation':projection,'observationDigest':_hash(projection),
            'protectedAnchorVerified':False,'enrollmentVerified':False,
            'hostStorageVerified':False,'ownerAcceptanceVerified':False,
            'runtimeActivationAllowed':False,'admissionAllowed':False}


def observe_host_isolation(*,layout_reader,expected_layout_digest,
                           peer_profile_reader,expected_peer_profile_digest):
    """Read only kernel identity, filesystem and socket; never change state.

    In production this must be called by a separately reviewed privileged
    host observer; a Repo/AI supplied matching profile is NOT authority.
    """
    _need(callable(layout_reader) and callable(peer_profile_reader),
          'REGISTRY_ISOLATION_READERS_REQUIRED')
    peer=_profile(peer_profile_reader(),expected_peer_profile_digest)
    layout=_layout(layout_reader(),expected_layout_digest,peer)
    before_boot=_boot_id()
    _need(before_boot==layout['bootId'],'REGISTRY_ISOLATION_BOOT_ID_MISMATCH')
    before=_endpoint(peer)
    processes={role:_read_process(layout[role+'Pid']) for role in _ROLES}
    files={role:_read_state_file(_full_path(layout[role+'StatePath']))
           for role in ('owner','registry')}
    result=_assess(layout,peer,processes,files,before)
    _need(_endpoint(peer)==before
          and _profile(peer_profile_reader(),expected_peer_profile_digest)==peer
          and _layout(layout_reader(),expected_layout_digest,peer)==layout,
          'REGISTRY_ISOLATION_CONFIGURATION_CHANGED')
    after={role:_read_process(layout[role+'Pid']) for role in _ROLES}
    after_files={role:_read_state_file(_full_path(layout[role+'StatePath']))
                 for role in ('owner','registry')}
    if after!=processes or after_files!=files or _boot_id()!=before_boot:
        raise Stale('REGISTRY_ISOLATION_RUNTIME_CHANGED')
    return result

#!/usr/bin/env python3
"""Owner-invoked *source-only* Linux cross-principal P5 access observation.

Run independently as the REAL existing reader and Repo process identities,
against an owner-pinned post-bind profile. This script has no sudo, setuid,
chmod, chown, schema init, socket bind, DB read or write functionality.
Only kernel EACCES/EPERM (not ENOENT/EROFS/ECONNREFUSED) proves denial.

It is not host attestation, owner authorization, Registry admission or GO.
The owner must independently inspect genuine process UID mappings, mounts,
ACLs, config provenance and original observation outputs.
"""
import argparse
import errno
import os
from pathlib import Path
import socket
import stat
import struct
import sys
import uuid

from fortis_approvals.core import Denied, canonical, loads_strict
from fortis_approvals.integrations.registry.owner_pinned_pidfd import (
    owner_pinned_peer, _boot_id,
)
from fortis_approvals.registry.state_journal import _hash, _hex, _need, _uuid

_PROFILE_FIELDS={
    'schemaVersion','format','ownerUid','registryUid','registryGid',
    'readerUid','readerGid','repoUid','repoGid',
    'serverPidfdInode','kernelBootId',
    'socketDev','socketInode','instanceId','scopeDigest',
    'registryStatePath','socketPath',
}
_FORMAT='functional-v1-host-access-profile-v2'
_RESULT='SOURCE_ONLY_CROSS_UID_ACCESS_OBSERVATION'
_MAX_CONFIG=4096
_MAX_REPLY=12289
_TIMEOUT=3.0


def _path(value, *, socket_name=False):
    _need(type(value) is str and value.startswith('/')
          and 1<len(os.fsencode(value)) <= (103 if socket_name else 4096)
          and not value.endswith('/') and '//' not in value
          and '\0' not in value
          and all(part not in ('','.','..') for part in value.split('/')[1:]),
          'REGISTRY_V1_ACCESS_PATH_INVALID')
    return Path(value)


def _profile(value, expected_digest):
    _need(type(value) is dict and set(value)==_PROFILE_FIELDS
          and type(value['schemaVersion']) is int
          and value['schemaVersion']==2 and value['format']==_FORMAT
          and _hex(expected_digest,64) and _hash(value)==expected_digest
          and _uuid(value['instanceId'])
          and _hex(value['scopeDigest'],64),
          'REGISTRY_V1_ACCESS_PROFILE_INVALID')
    for key in ('ownerUid','registryUid','registryGid','readerUid',
                'readerGid','repoUid','repoGid','socketDev',
                'socketInode'):
        _need(type(value[key]) is int and 0<value[key]<2**63,
              'REGISTRY_V1_ACCESS_PROFILE_INVALID')
    _need(len({value[k] for k in (
          'ownerUid','registryUid','readerUid','repoUid')})==4
          and len({value[k] for k in (
          'registryGid','readerGid','repoGid')})==3
          and all(value[k]<2**31 for k in (
          'ownerUid','registryUid','readerUid','repoUid',
          'registryGid','readerGid','repoGid'))
          and type(value['serverPidfdInode']) is int
          and 0<value['serverPidfdInode']<2**64
          and _uuid(value['kernelBootId'])
          and value['kernelBootId']==_boot_id(),
          'REGISTRY_V1_ACCESS_PROFILE_IDENTITY_CONFLICT')
    db=_path(value['registryStatePath'])
    sock=_path(value['socketPath'],socket_name=True)
    _need(db.name.endswith('.sqlite')
          and not sock.parent.is_relative_to(db.parent)
          and db.parent!=Path('/') and sock.parent!=Path('/'),
          'REGISTRY_V1_ACCESS_PATH_INVALID')
    return value


def load_profile(path, expected_digest):
    """A publicly readable owner-written *pin*, not an owner signature."""
    file=_path(path)
    try:
        parent=file.parent.lstat()
        fd=os.open(file,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
        with os.fdopen(fd,'rb') as f:
            info=os.fstat(f.fileno())
            data=f.read(_MAX_CONFIG+1)
        _need(stat.S_ISDIR(parent.st_mode)
              and not stat.S_ISLNK(parent.st_mode)
              and stat.S_IMODE(parent.st_mode)==0o755
              and stat.S_ISREG(info.st_mode) and info.st_nlink==1
              and stat.S_IMODE(info.st_mode)==0o444
              and 0<len(data)<=_MAX_CONFIG,
              'REGISTRY_V1_ACCESS_PROFILE_FILE_DENIED')
        raw=data.decode('utf-8')
        value=loads_strict(raw)
        _need(canonical(value).encode('utf-8')==data,
              'REGISTRY_V1_ACCESS_PROFILE_NONCANONICAL')
        value=_profile(value,expected_digest)
        _need(parent.st_uid==info.st_uid==value['ownerUid'],
              'REGISTRY_V1_ACCESS_PROFILE_OWNER_DENIED')
        return value
    except Denied:
        raise
    except (OSError,ValueError,UnicodeError,TypeError,RecursionError):
        raise Denied('REGISTRY_V1_ACCESS_PROFILE_UNAVAILABLE') from None


def _identity(role,profile):
    _need(role in ('reader','repo'),'REGISTRY_V1_ACCESS_ROLE_INVALID')
    uid,gid=(profile[role+'Uid'],profile[role+'Gid'])
    _need(uid not in (profile['registryUid'],profile['ownerUid'])
          and os.getuid()==os.geteuid()==uid
          and os.getgid()==os.getegid()==gid
          and os.getresuid()==(uid,uid,uid)
          and os.getresgid()==(gid,gid,gid)
          and os.getpid()>1,
          'REGISTRY_V1_ACCESS_NOT_REAL_PRINCIPAL')
    groups=os.getgroups()
    _need(len(groups)<=64 and len(set(groups))==len(groups)
          and profile['registryGid'] not in groups
          and (role!='repo' or profile['readerGid'] not in groups),
          'REGISTRY_V1_ACCESS_FORBIDDEN_GROUP')
    try:
        status=(Path('/proc')/str(os.getpid())/'status').read_text(
            encoding='ascii')
    except (OSError,UnicodeError):
        raise Denied('REGISTRY_V1_ACCESS_PROC_UNAVAILABLE') from None
    values={}
    for line in status.splitlines():
        key,sep,value=line.partition(':')
        if sep and key in ('CapEff','CapPrm','CapBnd','CapAmb','NoNewPrivs','Seccomp'):
            _need(key not in values,'REGISTRY_V1_ACCESS_PROC_INVALID')
            values[key]=value.strip()
    try:
        safe=set(values)=={
            'CapEff','CapPrm','CapBnd','CapAmb','NoNewPrivs','Seccomp'}
        safe=safe and all(int(values[name],16)==0 for name in
                     ('CapEff','CapPrm','CapBnd','CapAmb'))
        safe=safe and values['NoNewPrivs']=='1' and values['Seccomp']=='2'
    except (ValueError,KeyError):
        raise Denied('REGISTRY_V1_ACCESS_PROC_INVALID') from None
    _need(safe,'REGISTRY_V1_ACCESS_PROCESS_PRIVILEGE')
    return {'pid':os.getpid(),'uid':uid,'gid':gid,
            'groups':sorted(groups),'noNewPrivs':True,
            'seccompFilter':True,'effectiveCapabilities':0}


def _denied_open(path, flags):
    """Neither reads DB bytes nor writes/creates/truncates a single file."""
    try:
        fd=os.open(str(path),flags|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK)
    except OSError as err:
        if err.errno==errno.EACCES:
            return 'EACCES'
        if err.errno==errno.EPERM:
            return 'EPERM'
        raise Denied('REGISTRY_V1_ACCESS_NOT_PROVEN') from None
    os.close(fd)
    raise Denied('REGISTRY_V1_ACCESS_UNEXPECTEDLY_ALLOWED')


def _denied_state(profile):
    db=_path(profile['registryStatePath'])
    return {
        'registryParentRead':_denied_open(db.parent,
                                         os.O_RDONLY|os.O_DIRECTORY),
        'registryDbRead':_denied_open(db,os.O_RDONLY),
        'registryDbReadWrite':_denied_open(db,os.O_RDWR),
    }


def _socket_info(profile):
    path=_path(profile['socketPath'],socket_name=True)
    try:
        directory=path.parent.lstat()
        entry=path.lstat()
    except OSError:
        raise Denied('REGISTRY_V1_ACCESS_SOCKET_UNAVAILABLE') from None
    _need(stat.S_ISDIR(directory.st_mode)
          and stat.S_IMODE(directory.st_mode)==0o2710
          and directory.st_uid==profile['registryUid']
          and directory.st_gid==profile['readerGid']
          and stat.S_ISSOCK(entry.st_mode) and entry.st_nlink==1
          and stat.S_IMODE(entry.st_mode)==0o660
          and entry.st_uid==profile['registryUid']
          and entry.st_gid==profile['readerGid']
          and (entry.st_dev,entry.st_ino)==(
              profile['socketDev'],profile['socketInode']),
          'REGISTRY_V1_ACCESS_SOCKET_IDENTITY')
    return entry.st_dev,entry.st_ino


def _reader_socket(profile):
    """One real candidate.head READ; no live registry authority is inferred."""
    before=_socket_info(profile)
    request={
        'schemaVersion':1,'operation':'candidate.head',
        'instanceId':profile['instanceId'],
        'scopeDigest':profile['scopeDigest'],
        'requestId':str(uuid.uuid4()),'params':{},
    }
    wire=canonical(request).encode('utf-8')+b'\n'
    _need(len(wire)<=4096,'REGISTRY_V1_ACCESS_REQUEST_OVERSIZE')
    raw=bytearray()
    try:
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as client:
            client.settimeout(_TIMEOUT)
            client.connect(profile['socketPath'])
            # Owner profile pins an independently approved kernel process,
            # not the service's self-reported PID or uid/gid alone.
            try:
                peer=owner_pinned_peer(
                    client, expected_uid=profile['registryUid'],
                    expected_gid=profile['registryGid'],
                    expected_pidfd_inode=profile['serverPidfdInode'],
                    expected_boot_id=profile['kernelBootId'])
            except Denied:
                raise Denied('REGISTRY_V1_ACCESS_SERVER_PRINCIPAL_MISMATCH') from None
            client.sendall(wire)
            client.shutdown(socket.SHUT_WR)
            while True:
                chunk=client.recv(4096)
                if not chunk:
                    break
                raw.extend(chunk)
                _need(len(raw)<=_MAX_REPLY,
                      'REGISTRY_V1_ACCESS_RESPONSE_OVERSIZE')
    except (OSError,TimeoutError):
        raise Denied('REGISTRY_V1_ACCESS_SOCKET_REQUEST_FAILED') from None
    _need(len(raw)>2 and raw[-1:]==b'\n' and raw.count(b'\n')==1
          and _socket_info(profile)==before,
          'REGISTRY_V1_ACCESS_INVALID_RESPONSE')
    try:
        response=loads_strict(bytes(raw[:-1]))
        _need(canonical(response).encode('utf-8')==bytes(raw[:-1]),
              'REGISTRY_V1_ACCESS_INVALID_RESPONSE')
    except (ValueError,UnicodeError,TypeError,RecursionError):
        raise Denied('REGISTRY_V1_ACCESS_INVALID_RESPONSE') from None
    expected={'schemaVersion','result','requestId','operation','instanceId',
              'scopeDigest','data','authenticatedCollectorAvailable',
              'admissionAllowed','writeEnabled','deploymentAllowed',
              'runtimeActivationAllowed','rollbackProtected'}
    _need(type(response) is dict and set(response)==expected
          and type(response['schemaVersion']) is int
          and response['schemaVersion']==1
          and response['result']=='SOURCE_ONLY_CANDIDATE_READ'
          and response['requestId']==request['requestId']
          and response['operation']=='candidate.head'
          and response['instanceId']==profile['instanceId']
          and response['scopeDigest']==profile['scopeDigest']
          and all(response[field] is False for field in (
              'authenticatedCollectorAvailable','admissionAllowed',
              'writeEnabled','deploymentAllowed','runtimeActivationAllowed',
              'rollbackProtected')),
          'REGISTRY_V1_ACCESS_RESPONSE_AUTHORITY_DENIED')
    head=response['data']
    _need(type(head) is dict
          and head.get('result')=='LOCAL_SOURCE_CANDIDATE_HEAD'
          and head.get('integrityModel')=='LOCAL_EVENT_CHAIN_ONLY'
          and head.get('evidenceVerified') is False
          and head.get('admissionAllowed') is False
          and head.get('deploymentAllowed') is False
          and type(head.get('localCheckpoint')) is dict
          and type(head['localCheckpoint'].get('revision')) is int
          and 0<=head['localCheckpoint']['revision']<2**63,
          'REGISTRY_V1_ACCESS_RESPONSE_STATE_DENIED')
    return {
        'serverPidfdInode':peer[2], 'kernelBootId':profile['kernelBootId'],
        'serverUid':peer[0],'serverGid':peer[1],
        'socketDev':before[0],'socketInode':before[1],
        'localRevisionCandidate':head['localCheckpoint']['revision'],
        'stateAuthority':'LOCAL_EVENT_CHAIN_ONLY',
    }


def _repo_socket_denied(profile):
    """An absent/unbound socket is NEVER evidence of a permission denial."""
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as client:
        client.settimeout(_TIMEOUT)
        try:
            client.connect(profile['socketPath'])
        except OSError as err:
            if err.errno==errno.EACCES:
                return 'EACCES'
            if err.errno==errno.EPERM:
                return 'EPERM'
            raise Denied('REGISTRY_V1_ACCESS_SOCKET_DENIAL_NOT_PROVEN') from None
    raise Denied('REGISTRY_V1_ACCESS_SOCKET_UNEXPECTEDLY_ALLOWED')


def observe(role,profile,expected_digest):
    """One actual kernel-principal observation; NEVER an owner PASS/GO."""
    profile=_profile(profile,expected_digest)
    principal=_identity(role,profile)
    denials=_denied_state(profile)
    if role=='reader':
        socket_evidence=_reader_socket(profile)
    else:
        socket_evidence={'connectDenied':_repo_socket_denied(profile)}
    _need(_identity(role,profile)==principal,
          'REGISTRY_V1_ACCESS_PRINCIPAL_CHANGED')
    _need(_denied_state(profile)==denials,
          'REGISTRY_V1_ACCESS_DENIAL_CHANGED')
    if role=='reader':
        _need(_socket_info(profile)==(
              socket_evidence['socketDev'],socket_evidence['socketInode']),
              'REGISTRY_V1_ACCESS_SOCKET_CHANGED')
    evidence={
        'schemaVersion':2,'format':'functional-v1-host-access-observation-v2',
        'role':role,'profileDigest':expected_digest,
        'instanceId':profile['instanceId'],
        'scopeDigest':profile['scopeDigest'],
        'principal':principal,'denials':denials,
        'socketEvidence':socket_evidence,
    }
    return {
        'result':_RESULT,'evidence':evidence,
        'evidenceDigest':_hash(evidence),
        'originalHostVerified':False,'ownerAcceptanceVerified':False,
        'collectorAuthenticated':False,'liveRegistryAvailable':False,
        'admissionAllowed':False,'deploymentAllowed':False,
        'runtimeActivationAllowed':False,'rollbackProtected':False,
    }


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--role',required=True,choices=('reader','repo'))
    parser.add_argument('--profile',required=True)
    parser.add_argument('--expected-sha256',required=True)
    args=parser.parse_args(argv)
    value=load_profile(args.profile,args.expected_sha256)
    result=observe(args.role,value,args.expected_sha256)
    print(canonical(result))
    return 0


if __name__=='__main__':
    try:
        sys.exit(main())
    except Denied as err:
        print('REGISTRY_V1_ACCESS_STOP: '+str(err),file=sys.stderr)
        sys.exit(1)

"""P5 owner-checkpoint peer identity and read-only UDS envelope source candidate.

No server, socket bind/listen lifecycle, remote checkpoint read/advance,
credential issuance, protected enrollment or WebAuthn. The only entrypoint
observes a Linux accepted AF_UNIX/SOCK_STREAM socket using kernel SO_PEERCRED.
The resulting observation has dispatchAllowed=False in every case.
"""
import os
from pathlib import Path
import socket
import stat
import struct

from ..core import Denied, canonical, loads_strict
from .state_journal import _hash, _need, _uuid, _hex

_PROFILE_FIELDS={'schemaVersion','transport','socketPath','instanceId','scopeDigest',
                 'enrollmentReceiptDigest','authorityUid','authorityGid','socketGid',
                 'registryUid','registryGid','operatorUid','operatorGid'}
_BASE_FIELDS={'schemaVersion','operation','instanceId','scopeDigest','requestId'}
_MAX_FRAME=4096


def _profile(value,expected_digest):
    """Parse an exact host-pinned profile, not a caller-written actor grant."""
    _need(_hex(expected_digest,64) and type(value) is dict
          and set(value)==_PROFILE_FIELDS
          and type(value['schemaVersion']) is int and value['schemaVersion']==1
          and value['transport']=='linux-af-unix-stream-so-peercred-v1'
          and _uuid(value['instanceId'])
          and _hex(value['scopeDigest'],64)
          and _hex(value['enrollmentReceiptDigest'],64),
          'REGISTRY_PEER_PROFILE_INVALID')
    identities=('authorityUid','authorityGid','socketGid',
                'registryUid','registryGid','operatorUid','operatorGid')
    _need(all(type(value[x]) is int and 0<value[x]<=2**31-1 for x in identities)
          and len({value['authorityUid'],value['registryUid'],value['operatorUid']})==3
          and _hash(value)==expected_digest,'REGISTRY_PEER_PROFILE_INVALID')
    path=value['socketPath']
    _need(type(path) is str and path.startswith('/')
          and len(os.fsencode(path))<=103
          and Path(path).name not in ('','.','..')
          and Path(path).parent!=Path('/')
          and Path(path).parent.resolve()==Path(path).parent,
          'REGISTRY_PEER_SOCKET_PATH_INVALID')
    return loads_strict(canonical(value))


def _endpoint(profile):
    path=Path(profile['socketPath'])
    try:
        parent=path.parent.lstat()
        entry=path.lstat()
    except OSError:
        raise Denied('REGISTRY_PEER_SOCKET_UNAVAILABLE') from None
    _need(stat.S_ISDIR(parent.st_mode)
          and parent.st_uid==profile['authorityUid']
          and parent.st_gid==profile['socketGid']
          and stat.S_IMODE(parent.st_mode)==0o710
          and stat.S_ISSOCK(entry.st_mode)
          and entry.st_uid==profile['authorityUid']
          and entry.st_gid==profile['socketGid']
          and stat.S_IMODE(entry.st_mode)==0o660
          and entry.st_nlink==1,'REGISTRY_PEER_SOCKET_PERMISSIONS')
    return (entry.st_dev,entry.st_ino)


def _classify(profile,*,pid,uid,gid,request):
    """Synthetic test seam. Never use caller-provided peer tuple as authority."""
    _need(type(pid) is int and pid>0 and type(uid) is int and uid>0
          and type(gid) is int and gid>0,'REGISTRY_PEER_CREDENTIAL_INVALID')
    _need(type(request) is dict and request.get('schemaVersion')==1
          and type(request.get('schemaVersion')) is int
          and request.get('instanceId')==profile['instanceId']
          and request.get('scopeDigest')==profile['scopeDigest']
          and _uuid(request.get('requestId')),
          'REGISTRY_PEER_REQUEST_INVALID')
    operation=request.get('operation')
    # Even a permitted OS peer cannot self-authorize the owner-side CAS.
    # WebAuthn/owner ceremony and original-pending readback require their
    # own protected transport/authority, which this module lacks.
    _need(operation in ('checkpoint.get','checkpoint.original'),
          'REGISTRY_PEER_OPERATION_CLOSED')
    needed=(_BASE_FIELDS if operation=='checkpoint.get' else
            _BASE_FIELDS|{'operationId'})
    _need(set(request)==needed
          and (operation!='checkpoint.original' or _uuid(request['operationId'])),
          'REGISTRY_PEER_REQUEST_INVALID')
    if (uid,gid)==(profile['registryUid'],profile['registryGid']):
        _need(operation=='checkpoint.get','REGISTRY_PEER_ROLE_DENIED')
        role='registry-reader'
    elif (uid,gid)==(profile['operatorUid'],profile['operatorGid']):
        role='owner-operator'
    else:
        raise Denied('REGISTRY_PEER_UNAUTHORIZED')
    result={'result':'OWNER_PEER_BOUNDARY_CANDIDATE',
            'role':role,'operation':operation,'requestId':request['requestId'],
            'instanceId':profile['instanceId'],'scopeDigest':profile['scopeDigest'],
            'peerPid':pid,'peerUid':uid,'peerGid':gid,
            'protectedAuthorityVerified':False,'ownerAcceptanceVerified':False,
            'dispatchAllowed':False,'admissionAllowed':False}
    if operation=='checkpoint.original':
        result['operationId']=request['operationId']
    return result


def _one_frame(sock):
    """One bounded canonical UTF-8 JSON line. No second frame or pipelining."""
    previous=sock.gettimeout()
    try:
        sock.settimeout(2)
        raw=bytearray()
        while True:
            data=sock.recv(min(1024,_MAX_FRAME+2-len(raw)))
            _need(data and len(raw)+len(data)<=_MAX_FRAME+1,
                  'REGISTRY_PEER_FRAME_INVALID')
            raw.extend(data)
            if b'\n' in data:
                _need(raw[-1:]==b'\n' and raw.count(b'\n')==1,
                      'REGISTRY_PEER_FRAME_INVALID')
                break
        payload=bytes(raw[:-1])
        _need(0<len(payload)<=_MAX_FRAME,'REGISTRY_PEER_FRAME_INVALID')
        try:
            decoded=loads_strict(payload)
            _need(canonical(decoded).encode('utf-8')==payload,
                  'REGISTRY_PEER_FRAME_NONCANONICAL')
            return decoded
        except (ValueError,UnicodeError,TypeError,RecursionError):
            raise Denied('REGISTRY_PEER_FRAME_INVALID') from None
    except (OSError,TimeoutError):
        raise Denied('REGISTRY_PEER_FRAME_UNAVAILABLE') from None
    finally:
        try:sock.settimeout(previous)
        except OSError:pass


def observe_accepted_peer(*,connection,profile_reader,expected_profile_digest):
    """Host-side source candidate; no outbound response or checkpoint read.

    connection must be an accepted Linux filesystem Unix stream socket.
    Its kernel SO_PEERCRED is read here, never supplied by the request.
    """
    _need(callable(profile_reader) and _hex(expected_profile_digest,64)
          and isinstance(connection,socket.socket)
          and connection.family==socket.AF_UNIX
          and (connection.type & 0xf)==socket.SOCK_STREAM
          and hasattr(socket,'SO_PEERCRED'),
          'REGISTRY_PEER_UNIX_REQUIRED')
    profile=_profile(profile_reader(),expected_profile_digest)
    _need(os.geteuid()==profile['authorityUid']
          and os.getegid()==profile['authorityGid'],
          'REGISTRY_PEER_AUTHORITY_IDENTITY_MISMATCH')
    _need(connection.getsockname()==profile['socketPath'],
          'REGISTRY_PEER_WRONG_SOCKET')
    before=_endpoint(profile)
    try:
        raw=connection.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,
                                  struct.calcsize('3i'))
        _need(type(raw) is bytes and len(raw)==struct.calcsize('3i'),
              'REGISTRY_PEER_CREDENTIAL_INVALID')
        pid,uid,gid=struct.unpack('3i',raw)
    except OSError:
        raise Denied('REGISTRY_PEER_CREDENTIAL_UNAVAILABLE') from None
    request=_one_frame(connection)
    result=_classify(profile,pid=pid,uid=uid,gid=gid,request=request)
    _need(_endpoint(profile)==before
          and _profile(profile_reader(),expected_profile_digest)==profile,
          'REGISTRY_PEER_BINDING_CHANGED')
    return result

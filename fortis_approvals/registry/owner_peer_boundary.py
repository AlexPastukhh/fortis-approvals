"""P5 owner-checkpoint peer identity and read-only UDS envelope source candidate.

No listener/bind lifecycle, checkpoint advance, credential issuance,
protected enrollment or WebAuthn. Source-only accepted peer and one-shot
checkpoint.get response plus pinned outbound READ use Linux AF_UNIX/SO_PEERCRED
but never certify owner acceptance or independent anti-rollback protection.
All returned authority/admission flags remain false.
"""
import os
from pathlib import Path
import socket
import stat
import struct
from uuid import uuid4

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


def _one_frame(sock, *, limit=_MAX_FRAME):
    """One bounded canonical UTF-8 JSON line, with explicit size limit."""
    previous=sock.gettimeout()
    try:
        sock.settimeout(2)
        raw=bytearray()
        while True:
            data=sock.recv(min(1024,limit+2-len(raw)))
            _need(data and len(raw)+len(data)<=limit+1,
                  'REGISTRY_PEER_FRAME_INVALID')
            raw.extend(data)
            if b'\n' in data:
                _need(raw[-1:]==b'\n' and raw.count(b'\n')==1,
                      'REGISTRY_PEER_FRAME_INVALID')
                break
        payload=bytes(raw[:-1])
        _need(0<len(payload)<=limit,'REGISTRY_PEER_FRAME_INVALID')
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


def observe_accepted_peer(*,connection,profile_reader,expected_profile_digest,
                          require_request_eof=False):
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
    if require_request_eof:
        # No pipelined requests or trailing data may reach the ledger.
        # A single READ request must be half-closed by its client.
        previous=connection.gettimeout()
        try:
            connection.settimeout(2)
            _need(connection.recv(1)==b'', 'REGISTRY_PEER_TRAILING_REQUEST')
        except (OSError,TimeoutError):
            raise Denied('REGISTRY_PEER_REQUEST_EOF_UNAVAILABLE') from None
        finally:
            try:connection.settimeout(previous)
            except OSError:pass
    result=_classify(profile,pid=pid,uid=uid,gid=gid,request=request)
    _need(_endpoint(profile)==before
          and _profile(profile_reader(),expected_profile_digest)==profile,
          'REGISTRY_PEER_BINDING_CHANGED')
    return result


# Source-only fixed owner ledger READ adapter; no socket listener or CAS.
_MAX_RESPONSE_BYTES=8192


def read_accepted_checkpoint(*, connection, profile_reader, expected_profile_digest,
                             ledger, require_request_eof=False,
                             checkpoint_get_only=False):
    """Read one fixed owner ledger through a previously accepted connection.

    Caller must provision and own the Unix listener in a separate owner
    process. This function neither binds a socket nor sends network bytes.
    It intentionally cannot advance the checkpoint or authenticate a real
    WebAuthn owner decision. Positive fixture tests are NOT host isolation.
    """
    from .checkpoint_cas import OfflineCheckpointCAS
    _need(type(ledger) is OfflineCheckpointCAS and callable(profile_reader),
          'REGISTRY_OWNER_READ_LEDGER_REQUIRED')
    profile=_profile(profile_reader(),expected_profile_digest)
    _need(ledger.instance_id==profile['instanceId']
          and _hash(ledger.scope)==profile['scopeDigest']
          and ledger.enrollment_receipt_digest==profile['enrollmentReceiptDigest'],
          'REGISTRY_OWNER_READ_LEDGER_BINDING')
    before=_endpoint(profile)
    observed=observe_accepted_peer(connection=connection,
                                   profile_reader=profile_reader,
                                   expected_profile_digest=expected_profile_digest,
                                   **({'require_request_eof':True}
                                      if require_request_eof else {}))
    _need(type(observed) is dict
          and observed.get('result')=='OWNER_PEER_BOUNDARY_CANDIDATE'
          and observed.get('instanceId')==profile['instanceId']
          and observed.get('scopeDigest')==profile['scopeDigest']
          and observed.get('dispatchAllowed') is False
          and observed.get('protectedAuthorityVerified') is False
          and observed.get('ownerAcceptanceVerified') is False,
          'REGISTRY_OWNER_READ_PEER_INVALID')
    operation=observed.get('operation')
    if checkpoint_get_only:
        _need(operation=='checkpoint.get',
              'REGISTRY_OWNER_GET_ONLY_OPERATION_DENIED')
    if operation=='checkpoint.get':
        _need(observed.get('role') in ('registry-reader','owner-operator')
              and 'operationId' not in observed,
              'REGISTRY_OWNER_READ_ROLE_DENIED')
        payload=ledger.read_checkpoint()
    elif operation=='checkpoint.original':
        _need(observed.get('role')=='owner-operator'
              and _uuid(observed.get('operationId')),
              'REGISTRY_OWNER_READ_ROLE_DENIED')
        payload=ledger.original(observed['operationId'])
        _need(payload.get('result') in ('CHECKPOINT_CAS_CANDIDATE',
                                        'CHECKPOINT_OPERATION_NOT_FOUND'),
              'REGISTRY_OWNER_READ_ORIGINAL_INVALID')
        if payload['result']=='CHECKPOINT_CAS_CANDIDATE':
            _need(payload.get('receipt',{}).get('operationId')==observed['operationId'],
                  'REGISTRY_OWNER_READ_ORIGINAL_INVALID')
    else:
        raise Denied('REGISTRY_OWNER_READ_OPERATION_CLOSED')

    # Revalidate profile, socket identity and fixed ledger binding AFTER
    # reading; never use an untrusted request path or identity claim.
    _need(_endpoint(profile)==before
          and _profile(profile_reader(),expected_profile_digest)==profile
          and ledger.instance_id==profile['instanceId']
          and _hash(ledger.scope)==profile['scopeDigest']
          and ledger.enrollment_receipt_digest==profile['enrollmentReceiptDigest'],
          'REGISTRY_OWNER_READ_BINDING_CHANGED')
    result={'schemaVersion':1,'result':'OWNER_CHECKPOINT_READ_CANDIDATE',
            'requestId':observed['requestId'],
            'operation':operation,'instanceId':profile['instanceId'],
            'scopeDigest':profile['scopeDigest'],
            'data':payload,
            'protectedAuthorityVerified':False,
            'ownerAcceptanceVerified':False,
            'dispatchAllowed':False,'admissionAllowed':False}
    if operation=='checkpoint.original':
        result['operationId']=observed['operationId']
    _need(len(canonical(result).encode('utf-8'))<=_MAX_RESPONSE_BYTES,
          'REGISTRY_OWNER_READ_RESPONSE_LIMIT')
    return result


def _server_peer_credentials(connection,profile):
    """Read the server's real Linux peer identity; never accept JSON actor IDs."""
    _need(isinstance(connection,socket.socket)
          and connection.family==socket.AF_UNIX
          and (connection.type & 0xf)==socket.SOCK_STREAM
          and hasattr(socket,'SO_PEERCRED'),
          'REGISTRY_OWNER_CLIENT_UNIX_REQUIRED')
    try:
        raw=connection.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,
                                  struct.calcsize('3i'))
        _need(type(raw) is bytes and len(raw)==struct.calcsize('3i'),
              'REGISTRY_OWNER_CLIENT_CREDENTIAL_INVALID')
        pid,uid,gid=struct.unpack('3i',raw)
    except OSError:
        raise Denied('REGISTRY_OWNER_CLIENT_CREDENTIAL_UNAVAILABLE') from None
    _need(pid>1 and uid==profile['authorityUid']
          and gid==profile['authorityGid'],
          'REGISTRY_OWNER_CLIENT_SERVER_IDENTITY_DENIED')
    return (pid,uid,gid)


def _checkpoint_read_response(value,profile,request_id):
    """Exact unprivileged source READ projection; cannot turn into owner GO."""
    from .state_journal_v2 import MAX_REVISIONS
    _need(type(value) is dict and
          set(value)=={'schemaVersion','result','requestId','operation',
                       'instanceId','scopeDigest','data',
                       'protectedAuthorityVerified','ownerAcceptanceVerified',
                       'dispatchAllowed','admissionAllowed'} and
          type(value['schemaVersion']) is int and value['schemaVersion']==1 and
          value['result']=='OWNER_CHECKPOINT_READ_CANDIDATE' and
          value['requestId']==request_id and
          value['operation']=='checkpoint.get' and
          value['instanceId']==profile['instanceId'] and
          value['scopeDigest']==profile['scopeDigest'] and
          all(value[key] is False for key in
              ('protectedAuthorityVerified','ownerAcceptanceVerified',
               'dispatchAllowed','admissionAllowed')),
          'REGISTRY_OWNER_CLIENT_RESPONSE_INVALID')
    cp=value['data']
    _need(type(cp) is dict
          and set(cp)=={'schemaVersion','instanceId','scopeDigest',
                        'revision','eventDigest'}
          and type(cp['schemaVersion']) is int and cp['schemaVersion']==1
          and cp['instanceId']==profile['instanceId']
          and cp['scopeDigest']==profile['scopeDigest']
          and type(cp['revision']) is int and 0<=cp['revision']<=MAX_REVISIONS
          and _hex(cp['eventDigest'],64),
          'REGISTRY_OWNER_CLIENT_CHECKPOINT_INVALID')
    return value


def read_pinned_checkpoint(*,profile_reader,expected_profile_digest):
    """One-shot Registry-principal checkpoint.get over pinned Unix socket.

    Source-only: real server SO_PEERCRED and inode are checked, but no owner
    service is started and no protected witness/host/enrollment is attested.
    Only the owner-checkpoint READ-candidate envelope is permitted.
    """
    _need(callable(profile_reader) and _hex(expected_profile_digest,64),
          'REGISTRY_OWNER_CLIENT_PROFILE_REQUIRED')
    profile=_profile(profile_reader(),expected_profile_digest)
    _need(os.geteuid()==profile['registryUid']
          and os.getegid()==profile['registryGid'],
          'REGISTRY_OWNER_CLIENT_READER_IDENTITY_DENIED')
    endpoint=_endpoint(profile)
    request_id=str(uuid4())
    request={'schemaVersion':1,'operation':'checkpoint.get',
             'instanceId':profile['instanceId'],
             'scopeDigest':profile['scopeDigest'],
             'requestId':request_id}
    payload=canonical(request).encode('utf-8')+b'\n'
    _need(len(payload)<=_MAX_FRAME+1,
          'REGISTRY_OWNER_CLIENT_REQUEST_LIMIT')
    try:
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as connection:
            connection.settimeout(2)
            connection.connect(profile['socketPath'])
            _need(connection.getpeername()==profile['socketPath'],
                  'REGISTRY_OWNER_CLIENT_WRONG_SOCKET')
            server=_server_peer_credentials(connection,profile)
            _need(_endpoint(profile)==endpoint,
                  'REGISTRY_OWNER_CLIENT_SOCKET_CHANGED')
            connection.sendall(payload)
            connection.shutdown(socket.SHUT_WR)
            response=_one_frame(connection,limit=_MAX_RESPONSE_BYTES)
            _need(connection.recv(1)==b'',
                  'REGISTRY_OWNER_CLIENT_TRAILING_RESPONSE')
            _need(_server_peer_credentials(connection,profile)==server,
                  'REGISTRY_OWNER_CLIENT_PEER_CHANGED')
    except (OSError,TimeoutError):
        raise Denied('REGISTRY_OWNER_CLIENT_TRANSPORT_UNAVAILABLE') from None
    # Re-read pinned values and actual socket inode after all remote I/O.
    _need(_endpoint(profile)==endpoint
          and _profile(profile_reader(),expected_profile_digest)==profile,
          'REGISTRY_OWNER_CLIENT_BINDING_CHANGED')
    return _checkpoint_read_response(response,profile,request_id)


def respond_accepted_checkpoint_get(*, connection, profile_reader,
                                    expected_profile_digest, ledger):
    """Emit one bounded checkpoint.get response on a pre-accepted Unix socket.

    The caller owns the socket listener/lifetime. This source-only responder
    does not listen, authenticate the human owner, advance checkpoint state,
    or certify a protected host/witness. It never sends an error envelope.
    """
    _need(isinstance(connection,socket.socket)
          and connection.family==socket.AF_UNIX
          and (connection.type & 0xf)==socket.SOCK_STREAM,
          'REGISTRY_OWNER_RESPONDER_UNIX_REQUIRED')
    response=read_accepted_checkpoint(
        connection=connection,profile_reader=profile_reader,
        expected_profile_digest=expected_profile_digest,ledger=ledger,
        require_request_eof=True,checkpoint_get_only=True)
    profile=_profile(profile_reader(),expected_profile_digest)
    _checkpoint_read_response(response,profile,response['requestId'])
    # One complete, canonical line. Never stream database rows or raw errors.
    payload=canonical(response).encode('utf-8')+b'\n'
    _need(len(payload)<=_MAX_RESPONSE_BYTES+1,
          'REGISTRY_OWNER_READ_RESPONSE_LIMIT')
    previous=connection.gettimeout()
    try:
        connection.settimeout(2)
        connection.sendall(payload)
        connection.shutdown(socket.SHUT_WR)
    except (OSError,TimeoutError):
        raise Denied('REGISTRY_OWNER_RESPONDER_TRANSPORT_UNAVAILABLE') from None
    finally:
        try:connection.settimeout(previous)
        except OSError:pass
    # A socket write is not a durable client receipt or owner acceptance.
    return None

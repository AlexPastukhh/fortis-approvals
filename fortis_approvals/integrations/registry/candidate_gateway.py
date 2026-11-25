"""Opt-in Gateway READ adapter for a real private Registry candidate Unix socket.

No default Core grant, host install, Registry WRITE or authoritative records.
The socket is selected ONLY by a trusted host constructor, NEVER by Repo
request fields. A local event chain is not collector/owner authentication.
This module is packaged only with a future reviewed Gateway image source.
"""
import hashlib
from hmac import compare_digest
import os
from pathlib import Path
import secrets
import socket
import stat
import struct
import time
import uuid

from ...core import Denied, canonical, loads_strict
from .owner_pinned_pidfd import kernel_live_peer, owner_pinned_peer, peer_proof
from .read_contract import (
    REPOSITORY, _CANDIDATE_FLAGS, _uuid, _hex,
    validate_gateway_read_query, validate_gateway_read_projection,
    PLANNER_OPERATION, PLANNER_FRAME_LIMIT, planner_frame, planner_params,
)

_WIRE_OP = {
    'candidate_head': 'candidate.head',
    'candidate_list_desired': 'candidate.list_desired',
    'candidate_original_operation': 'candidate.original_operation',
}
_MAX_REPLY = 12289
_MAX_REQUEST = 4096
_TIMEOUT = 2.5


def _need(test, code='REGISTRY_CANDIDATE_TRANSPORT_DENIED'):
    if not test:
        raise Denied(code)


class GatewayRegistryUnixCandidateRead:
    """Reader-identity-pinned client of an *already running* private socket."""

    def __init__(self, *, socket_path, instance_id, scope_digest,
                 registry_uid, registry_gid, registry_pid=None,
                 reader_uid, reader_gid, socket_device=None, socket_inode=None,
                 registry_pidfd_inode=None, registry_boot_id=None, peer_key=None):
        _need(type(socket_path) is str and socket_path.startswith('/')
              and len(os.fsencode(socket_path)) <= 103
              and not socket_path.endswith('/') and '//' not in socket_path
              and '\x00' not in socket_path
              and all(part not in ('', '.', '..') for part in
                      socket_path.split('/')[1:]),
              'REGISTRY_CANDIDATE_CONFIG_DENIED')
        # Numeric PID is retained ONLY for legacy source-only offline
        # diagnostic construction. The owner R7 trusted mount uses strictly
        # boot-scoped pidfd process identity and cannot select this fallback.
        legacy = (type(registry_pid) is int and 0 < registry_pid < 2**31
                  and registry_pidfd_inode is None and registry_boot_id is None)
        owner_pidfd = (registry_pid is None
                       and type(registry_pidfd_inode) is int
                       and 0 < registry_pidfd_inode < 2**64
                       and _uuid(registry_boot_id))
        managed = (type(peer_key) is bytes and len(peer_key) == 32
                   and registry_pid is None and registry_pidfd_inode is None
                   and registry_boot_id is None and socket_device is None
                   and socket_inode is None)
        fixed = ((legacy or owner_pidfd) and peer_key is None and
                 all(type(v) is int and v > 0 for v in (socket_device, socket_inode)))
        _need(_uuid(instance_id) and _hex(scope_digest, 64)
              and all(type(v) is int and 0 < v < 2**31
                      for v in (registry_uid, registry_gid,
                                reader_uid, reader_gid))
              and reader_uid != registry_uid and
              reader_gid != registry_gid
              and (fixed or managed)
              and hasattr(socket, 'SO_PEERCRED'),
              'REGISTRY_CANDIDATE_CONFIG_DENIED')
        self._path = Path(socket_path)
        self._instance = instance_id
        self._scope = scope_digest
        self._registry = (registry_pid if legacy else 0,
                          registry_uid, registry_gid)
        self._owner_pidfd = ((registry_pidfd_inode, registry_boot_id)
                             if owner_pidfd else None)
        self._reader = (reader_uid, reader_gid)
        self._endpoint = None if managed else (socket_device, socket_inode)
        self._peer_key = peer_key
        # Host must grant the invoking Gateway reader identity before
        # any request. Never switch UIDs or derive identity from a payload.
        # A same-UID fixture may explicitly construct these pins, but is
        # not independent host acceptance or authorization.
        self._check_identity()

    def _check_identity(self):
        """Fail closed on the ACTUAL reader process, never claimed request IDs."""
        uid, gid = self._reader
        _need(os.getresuid() == (uid, uid, uid)
              and os.getresgid() == (gid, gid, gid)
              and os.getuid() == os.geteuid() == uid
              and os.getgid() == os.getegid() == gid,
              'REGISTRY_CANDIDATE_READER_IDENTITY_DENIED')
        groups = os.getgroups()
        _need(len(groups) <= 64 and len(set(groups)) == len(groups)
              and self._registry[2] not in groups,
              'REGISTRY_CANDIDATE_READER_GROUP_DENIED')
        try:
            raw = Path('/proc/self/status').read_bytes()
        except OSError:
            raise Denied('REGISTRY_CANDIDATE_PROC_UNAVAILABLE') from None
        _need(0 < len(raw) <= 16384, 'REGISTRY_CANDIDATE_PROC_DENIED')
        fields = {}
        names = {'Uid', 'Gid', 'Groups', 'CapInh', 'CapPrm',
                 'CapEff', 'CapBnd', 'CapAmb', 'NoNewPrivs',
                 'Seccomp', 'TracerPid'}
        try:
            for line in raw.decode('ascii').splitlines():
                key, sep, value = line.partition(':')
                if sep and key in names:
                    _need(key not in fields, 'REGISTRY_CANDIDATE_PROC_DENIED')
                    fields[key] = value.strip()
            _need(set(fields) == names, 'REGISTRY_CANDIDATE_PROC_DENIED')
            _need([int(v) for v in fields['Uid'].split()] == [uid] * 4
                  and [int(v) for v in fields['Gid'].split()] == [gid] * 4
                  and sorted(int(v) for v in fields['Groups'].split()) ==
                  sorted(groups),
                  'REGISTRY_CANDIDATE_READER_IDENTITY_DENIED')
            _need(all(int(fields[k], 16) == 0 for k in
                      ('CapInh', 'CapPrm', 'CapEff', 'CapBnd', 'CapAmb'))
                  and fields['NoNewPrivs'] == '1'
                  and fields['Seccomp'] == '2'
                  and fields['TracerPid'] == '0',
                  'REGISTRY_CANDIDATE_READER_PRIVILEGE_DENIED')
        except Denied:
            raise
        except (UnicodeError, ValueError, OverflowError):
            raise Denied('REGISTRY_CANDIDATE_PROC_DENIED') from None
        _need(os.getresuid() == (uid, uid, uid)
              and os.getresgid() == (gid, gid, gid)
              and os.getgroups() == groups,
              'REGISTRY_CANDIDATE_READER_IDENTITY_CHANGED')

    def _check_socket(self):
        path = self._path
        try:
            folder = path.parent.lstat()
            row = path.lstat()
        except OSError:
            raise Denied('REGISTRY_CANDIDATE_SOCKET_UNAVAILABLE') from None
        _need(stat.S_ISDIR(folder.st_mode)
              and not stat.S_ISLNK(folder.st_mode)
              and folder.st_uid == self._registry[1]
              and folder.st_gid == self._reader[1]
              and stat.S_IMODE(folder.st_mode) == 0o2710
              and stat.S_ISSOCK(row.st_mode) and row.st_nlink == 1
              and row.st_uid == self._registry[1]
              and row.st_gid == self._reader[1]
              and stat.S_IMODE(row.st_mode) == 0o660
              and (self._endpoint is None or
                   (row.st_dev, row.st_ino) == self._endpoint),
              'REGISTRY_CANDIDATE_SOCKET_CHANGED')
        return row.st_dev, row.st_ino

    def _peer(self, sock):
        if self._peer_key is not None:
            return kernel_live_peer(sock, expected_uid=self._registry[1],
                                    expected_gid=self._registry[2])
        if self._owner_pidfd is not None:
            # Owner R7 always pins the exact kernel process against the
            # immutable release mount. PID 0 across namespaces is not a
            # bypass: the process inode and current boot must match exactly.
            return owner_pinned_peer(
                sock, expected_uid=self._registry[1],
                expected_gid=self._registry[2],
                expected_pidfd_inode=self._owner_pidfd[0],
                expected_boot_id=self._owner_pidfd[1])
        # Legacy *offline diagnostic* constructor only. R7 owner mount v2
        # never selects numeric PID; there is no fallback on pidfd errors.
        try:
            peer = struct.unpack('3i', sock.getsockopt(
                socket.SOL_SOCKET, socket.SO_PEERCRED,
                struct.calcsize('3i')))
        except (OSError, struct.error):
            raise Denied('REGISTRY_CANDIDATE_SERVER_UNAVAILABLE') from None
        _need(peer == self._registry,
              'REGISTRY_CANDIDATE_SERVER_IDENTITY_DENIED')
        return peer

    def _authenticate_peer(self, sock):
        peer = self._peer(sock)
        if self._peer_key is None:
            return peer
        challenge = secrets.token_hex(32)
        expected = peer_proof(self._peer_key, challenge,
                              instance_id=self._instance, scope_digest=self._scope)
        previous = sock.gettimeout()
        deadline = time.monotonic() + _TIMEOUT
        try:
            sock.settimeout(_TIMEOUT)
            sock.sendall(challenge.encode('ascii'))
            reply = bytearray()
            while len(reply) < len(expected):
                remaining = deadline - time.monotonic()
                _need(remaining > 0, 'REGISTRY_FUNCTIONAL_PEER_PROOF_DENIED')
                sock.settimeout(remaining)
                chunk = sock.recv(len(expected) - len(reply))
                _need(chunk, 'REGISTRY_FUNCTIONAL_PEER_PROOF_DENIED')
                reply.extend(chunk)
            _need(compare_digest(reply, expected) and self._peer(sock) == peer,
                  'REGISTRY_FUNCTIONAL_PEER_PROOF_DENIED')
        finally:
            sock.settimeout(previous)
        return peer

    def _exchange(self, wire_request, *, limit, timeout):
        self._check_identity()
        endpoint = self._check_socket()
        raw = canonical(wire_request).encode('utf-8') + b'\n'
        _need(len(raw) <= limit + 1, 'REGISTRY_CANDIDATE_REQUEST_TOO_LARGE')
        reply = bytearray()
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                sock.connect(str(self._path))
                peer = self._authenticate_peer(sock)
                sock.sendall(raw)
                sock.shutdown(socket.SHUT_WR)
                while True:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    reply.extend(chunk)
                    _need(len(reply) <= _MAX_REPLY,
                          'REGISTRY_CANDIDATE_RESPONSE_TOO_LARGE')
                _need(self._peer(sock) == peer,
                      'REGISTRY_CANDIDATE_SERVER_CHANGED')
        except (OSError, TimeoutError):
            raise Denied('REGISTRY_CANDIDATE_TRANSPORT_UNAVAILABLE') from None
        self._check_identity()
        _need(self._check_socket() == endpoint
              and 2 <= len(reply) <= _MAX_REPLY
              and reply[-1:] == b'\n' and reply.count(b'\n') == 1,
              'REGISTRY_CANDIDATE_RESPONSE_DENIED')
        return reply

    def _socket_read(self, operation, params, request_id):
        wire_request = {
            'schemaVersion': 1, 'operation': _WIRE_OP[operation],
            'instanceId': self._instance, 'scopeDigest': self._scope,
            'requestId': request_id, 'params': params,
        }
        reply = self._exchange(wire_request, limit=_MAX_REQUEST, timeout=_TIMEOUT)
        try:
            envelope = loads_strict(bytes(reply[:-1]))
            _need(type(envelope) is dict
                  and canonical(envelope).encode('utf-8') == bytes(reply[:-1])
                  and set(envelope) == {
                      'schemaVersion', 'result', 'requestId', 'operation',
                      'instanceId', 'scopeDigest', 'data',
                      'authenticatedCollectorAvailable', 'admissionAllowed',
                      'writeEnabled', 'deploymentAllowed',
                      'runtimeActivationAllowed', 'rollbackProtected'}
                  and type(envelope['schemaVersion']) is int
                  and envelope['schemaVersion'] == 1
                  and envelope['result'] == 'SOURCE_ONLY_CANDIDATE_READ'
                  and envelope['requestId'] == request_id
                  and envelope['operation'] == _WIRE_OP[operation]
                  and envelope['instanceId'] == self._instance
                  and envelope['scopeDigest'] == self._scope
                  and all(envelope[f] is False for f in (
                      'authenticatedCollectorAvailable', 'admissionAllowed',
                      'writeEnabled', 'deploymentAllowed',
                      'runtimeActivationAllowed', 'rollbackProtected')),
                  'REGISTRY_CANDIDATE_RESPONSE_DENIED')
        except (ValueError, TypeError, UnicodeError, OverflowError,
                RecursionError):
            raise Denied('REGISTRY_CANDIDATE_RESPONSE_DENIED') from None
        return envelope['data']

    def _project(self, operation, data, params):
        if operation == 'candidate_original_operation':
            _need(type(data) is dict and set(data) == {
                'result', 'receipt', 'integrityModel',
                'evidenceVerified', 'admissionAllowed', 'deploymentAllowed'}
                  and data['result'] == 'LOCAL_DESIRED_CANDIDATE_COMMITTED'
                  and data['integrityModel'] == 'LOCAL_EVENT_CHAIN_ONLY'
                  and all(data[f] is False for f in (
                      'evidenceVerified', 'admissionAllowed',
                      'deploymentAllowed')),
                  'REGISTRY_CANDIDATE_OPERATION_DENIED')
            receipt = data['receipt']
            _need(type(receipt) is dict
                  and type(receipt.get('schemaVersion')) is int
                  and receipt['schemaVersion'] == 3
                  and receipt.get('operationId') == params['operationId']
                  and receipt.get('repository') == REPOSITORY
                  and receipt.get('integrityModel') == 'LOCAL_EVENT_CHAIN_ONLY'
                  and all(receipt.get(f) is False for f in (
                      'evidenceVerified', 'admissionAllowed',
                      'deploymentAllowed'))
                  and type(receipt.get('checkpoint')) is dict,
                  'REGISTRY_CANDIDATE_OPERATION_DENIED')
            output = {
                'result': 'LOCAL_DESIRED_CANDIDATE_COMMITTED',
                'operationId': params['operationId'],
                'localCheckpoint': receipt['checkpoint'],
                'candidateSourceSha': receipt.get('candidateCursor'),
                'recordIds': receipt.get('recordIds'),
                'supersessions': receipt.get('supersessions'),
                'receiptDigest': hashlib.sha256(
                    canonical(receipt).encode('utf-8')).hexdigest(),
                'integrityModel': 'LOCAL_EVENT_CHAIN_ONLY',
                'evidenceVerified': False, 'admissionAllowed': False,
                'deploymentAllowed': False,
            }
        else:
            output = data
            if operation == 'candidate_list_desired':
                # Reject a wrong page length even if the remote page is
                # individually schema-valid. No fabricated empty success.
                _need(type(data) is dict
                      and type(data.get('records')) is list
                      and len(data['records']) <= params['limit'],
                      'REGISTRY_CANDIDATE_PAGE_DENIED')
        projection = {
            'schemaVersion': 1, 'result': 'SOURCE_ONLY_CANDIDATE_READ',
            'candidateOperation': operation, 'repository': REPOSITORY,
            'instanceId': self._instance, 'scopeDigest': self._scope,
            'data': output,
            **{flag: False for flag in _CANDIDATE_FLAGS},
        }
        return validate_gateway_read_projection(operation, projection)

    def read(self, request):
        _need(type(request) is dict and request.get('service') == 'registry',
              'REGISTRY_CANDIDATE_SCOPE_DENIED')
        operation = request.get('operation')
        _name, params = validate_gateway_read_query(
            operation, request.get('target'), request.get('params'))
        _need(operation in _WIRE_OP and _uuid(request.get('requestId')),
              'REGISTRY_CANDIDATE_OPERATION_DISABLED')
        native_params = {
            'limit': params['limit'], 'cursor': params['cursor'],
        } if operation == 'candidate_list_desired' else (
            {'operationId': params['operationId']}
            if operation == 'candidate_original_operation' else {})
        data = self._socket_read(operation, native_params,
                                 request['requestId'])
        return self._project(operation, data, params)


class PinnedRegistryCursor:
    """Exact live candidate READ peer, not a caller-supplied checkpoint DTO."""
    def __init__(self, reader, scope):
        _need(type(reader) is GatewayRegistryUnixCandidateRead
              and (reader._owner_pidfd is not None or reader._peer_key is not None)
              and hashlib.sha256(canonical(scope).encode()).hexdigest() == reader._scope,
              'REGISTRY_PLANNER_CURSOR_BINDING')
        self.reader = reader
        self.scope = loads_strict(canonical(scope))

    def checkpoint(self):
        data = self.reader.read({'service':'registry', 'operation':'candidate_head',
            'target':'fortis-approvals', 'params':{'repository':REPOSITORY},
            'requestId':str(uuid.uuid4())})
        return data['data']


class GatewayRegistryUnixPlanner:
    """Internal-only transport; no public route, grant or automatic retry."""
    def __init__(self, reader, key):
        _need(type(reader) is GatewayRegistryUnixCandidateRead
              and (reader._owner_pidfd is not None or reader._peer_key is not None)
              and type(key) is bytes and len(key) == 32,
              'REGISTRY_PLANNER_BINDING_DENIED')
        self.reader, self._key = reader, key

    def _receipt(self, result, params, evidence):
        _need(type(result) is dict and set(result) == {
            'result','receipt','integrityModel','evidenceVerified','admissionAllowed','deploymentAllowed'}
              and result['result']=='LOCAL_DESIRED_CANDIDATE_COMMITTED'
              and result['integrityModel']=='LOCAL_EVENT_CHAIN_ONLY'
              and all(result[k] is False for k in ('evidenceVerified','admissionAllowed','deploymentAllowed')),
              'REGISTRY_PLANNER_ACK_UNKNOWN')
        r = result['receipt']; o=evidence['plan']['observation']
        _need(type(r) is dict and r.get('evidenceId') == params['evidenceId']
              and r.get('evidenceDigest') == hashlib.sha256(canonical(evidence).encode()).hexdigest()
              and r.get('previousCheckpoint',{}).get('revision') == params['expectedRevision']
              and r.get('checkpoint',{}).get('revision') == params['expectedRevision']+1
              and r.get('candidateCursor') == o['selectedMainSha']
              and r.get('cutoverGap') == o.get('cutoverGap')
              and r.get('recordIds') == sorted(row['recordId'] for row in o['recordCandidates'])
              and r.get('actor') == 'release-registry-planner-v1',
              'REGISTRY_PLANNER_RECEIPT_MISMATCH')
        # Reuse the exact candidate receipt/instance/scope projection contract.
        self.reader._project('candidate_original_operation', result,
            {'repository':REPOSITORY,'operationId':params['operationId']})
        return result

    def ingest(self, params, evidence):
        frame = planner_frame(self._key, instance_id=self.reader._instance,
            scope_digest=self.reader._scope, params=params, evidence=evidence)
        reply = self.reader._exchange(frame, limit=PLANNER_FRAME_LIMIT, timeout=15.0)
        try:
            value=loads_strict(bytes(reply[:-1]))
            _need(canonical(value).encode()==bytes(reply[:-1])
                  and type(value) is dict and set(value)=={
                      'schemaVersion','operation','instanceId','scopeDigest','requestId','data'}
                  and type(value['schemaVersion']) is int and value['schemaVersion']==1
                  and value['operation']==PLANNER_OPERATION
                  and value['instanceId']==self.reader._instance
                  and value['scopeDigest']==self.reader._scope
                  and value['requestId']==params['operationId'], 'REGISTRY_PLANNER_ACK_UNKNOWN')
            return self._receipt(value['data'],params,evidence)
        except (ValueError,TypeError,KeyError,AttributeError):
            raise Denied('REGISTRY_PLANNER_ACK_UNKNOWN') from None

    def lookup(self, params, evidence):
        planner_params(params)
        result=self.reader._socket_read('candidate_original_operation',
            {'operationId':params['operationId']}, str(uuid.uuid4()))
        if result == {'result':'LOCAL_CANDIDATE_OPERATION_NOT_FOUND',
                'integrityModel':'LOCAL_EVENT_CHAIN_ONLY','evidenceVerified':False,
                'admissionAllowed':False}:
            return None
        return self._receipt(result,params,evidence)

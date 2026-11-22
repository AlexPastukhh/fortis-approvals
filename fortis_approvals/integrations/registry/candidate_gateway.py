"""Opt-in Gateway READ adapter for a real private Registry candidate Unix socket.

No default Core grant, host install, Registry WRITE or authoritative records.
The socket is selected ONLY by a trusted host constructor, NEVER by Repo
request fields. A local event chain is not collector/owner authentication.
This module is packaged only with a future reviewed Gateway image source.
"""
import hashlib
import os
from pathlib import Path
import socket
import stat
import struct

from ...core import Denied, canonical, loads_strict
from .read_contract import (
    REPOSITORY, _CANDIDATE_FLAGS, _uuid, _hex,
    validate_gateway_read_query, validate_gateway_read_projection,
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
                 registry_uid, registry_gid, registry_pid,
                 reader_uid, reader_gid, socket_device, socket_inode):
        _need(type(socket_path) is str and socket_path.startswith('/')
              and len(os.fsencode(socket_path)) <= 103
              and not socket_path.endswith('/') and '//' not in socket_path
              and '\x00' not in socket_path
              and all(part not in ('', '.', '..') for part in
                      socket_path.split('/')[1:]),
              'REGISTRY_CANDIDATE_CONFIG_DENIED')
        _need(_uuid(instance_id) and _hex(scope_digest, 64)
              and all(type(v) is int and 0 < v < 2**31
                      for v in (registry_uid, registry_gid, registry_pid,
                                reader_uid, reader_gid))
              and all(type(v) is int and v > 0
                      for v in (socket_device, socket_inode))
              and reader_uid != registry_uid and
              reader_gid != registry_gid
              and hasattr(socket, 'SO_PEERCRED'),
              'REGISTRY_CANDIDATE_CONFIG_DENIED')
        self._path = Path(socket_path)
        self._instance = instance_id
        self._scope = scope_digest
        self._registry = (registry_pid, registry_uid, registry_gid)
        self._reader = (reader_uid, reader_gid)
        self._endpoint = (socket_device, socket_inode)
        # Host must grant the invoking Gateway reader identity before
        # any request. Never switch UIDs or derive identity from a payload.
        # A same-UID fixture may explicitly construct these pins, but is
        # not independent host acceptance or authorization.
        self._check_identity()

    def _check_identity(self):
        _need(os.getuid() == os.geteuid() == self._reader[0]
              and os.getgid() == os.getegid() == self._reader[1]
              and self._reader[0] > 0,
              'REGISTRY_CANDIDATE_READER_IDENTITY_DENIED')

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
              and stat.S_IMODE(folder.st_mode) == 0o710
              and stat.S_ISSOCK(row.st_mode) and row.st_nlink == 1
              and row.st_uid == self._registry[1]
              and row.st_gid == self._reader[1]
              and stat.S_IMODE(row.st_mode) == 0o660
              and (row.st_dev, row.st_ino) == self._endpoint,
              'REGISTRY_CANDIDATE_SOCKET_CHANGED')
        return self._endpoint

    def _peer(self, sock):
        try:
            peer = struct.unpack('3i', sock.getsockopt(
                socket.SOL_SOCKET, socket.SO_PEERCRED,
                struct.calcsize('3i')))
        except (OSError, struct.error):
            raise Denied('REGISTRY_CANDIDATE_SERVER_UNAVAILABLE') from None
        _need(peer == self._registry,
              'REGISTRY_CANDIDATE_SERVER_IDENTITY_DENIED')
        return peer

    def _socket_read(self, operation, params, request_id):
        self._check_identity()
        endpoint = self._check_socket()
        wire_request = {
            'schemaVersion': 1, 'operation': _WIRE_OP[operation],
            'instanceId': self._instance, 'scopeDigest': self._scope,
            'requestId': request_id, 'params': params,
        }
        raw = canonical(wire_request).encode('utf-8') + b'\n'
        _need(len(raw) <= _MAX_REQUEST + 1,
              'REGISTRY_CANDIDATE_REQUEST_TOO_LARGE')
        reply = bytearray()
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
                sock.settimeout(_TIMEOUT)
                sock.connect(str(self._path))
                peer = self._peer(sock)
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

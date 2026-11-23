"""Private Linux Unix-socket *candidate* Registry reader (no live authority).

This is a runnable, non-deployed source cut for the FIRST functional runtime.
The host, not a request, must select the immutable config, SQLite path,
listener directory, reader UID/GID and process identity. The process never
initializes/migrates the DB, invokes GitHub/Core, accepts a write, or claims
owner/collector admission. A same-UID test is NOT cross-principal host proof.

Do not package/deploy or grant this endpoint until a separate owner-approved
non-Production host/provenance review. This is NOT registry.list_records.
"""
import argparse
import os
from pathlib import Path
import socket
import stat
import struct
import sys

from ..core import Denied, Stale, canonical, loads_strict
from ..integrations.registry.owner_pinned_pidfd import kernel_live_peer
from .functional_v1_journal import FunctionalV1CandidateJournal
from .state_journal import _hash, _need, _scope, _uuid, PLANNER

_OPERATIONS = ('candidate.capabilities', 'candidate.head',
               'candidate.list_desired', 'candidate.original_operation')
_MAX_FRAME = 4096
_MAX_REPLY = 12288
_TIMEOUT = 2.0


def _absolute_path(value, *, socket_name=False):
    _need(type(value) is str and value.startswith('/')
          and len(os.fsencode(value)) <= (103 if socket_name else 4096)
          and not value.endswith('/') and '//' not in value
          and all(p not in ('', '.', '..') for p in value.split('/')[1:]),
          'REGISTRY_PRIVATE_READ_PATH_INVALID')
    path = Path(value)
    _need(path.parent != Path('/')
          and path.parent.resolve() == path.parent,
          'REGISTRY_PRIVATE_READ_PATH_INVALID')
    return path


def _private_socket_dir(path, gid):
    parent = path.parent
    try:
        row = parent.lstat()
    except OSError:
        raise Denied('REGISTRY_PRIVATE_READ_SOCKET_DIRECTORY_UNAVAILABLE') from None
    _need(stat.S_ISDIR(row.st_mode) and not stat.S_ISLNK(row.st_mode)
          and row.st_uid == os.geteuid() and row.st_gid == gid
          and stat.S_IMODE(row.st_mode) == 0o2710,
          'REGISTRY_PRIVATE_READ_SOCKET_DIRECTORY_DENIED')


def _canonical_frame(connection):
    previous = connection.gettimeout()
    try:
        connection.settimeout(_TIMEOUT)
        collected = bytearray()
        while True:
            data = connection.recv(min(1024, _MAX_FRAME + 2 - len(collected)))
            _need(bool(data) and len(collected) + len(data) <= _MAX_FRAME + 1,
                  'REGISTRY_PRIVATE_READ_FRAME_DENIED')
            collected.extend(data)
            if b'\n' in data:
                _need(collected[-1:] == b'\n'
                      and collected.count(b'\n') == 1,
                      'REGISTRY_PRIVATE_READ_FRAME_DENIED')
                break
        # Client must half-close; no request pipelining or trailing junk.
        _need(connection.recv(1) == b'',
              'REGISTRY_PRIVATE_READ_TRAILING_REQUEST')
        raw = bytes(collected[:-1])
        _need(0 < len(raw) <= _MAX_FRAME,
              'REGISTRY_PRIVATE_READ_FRAME_DENIED')
        try:
            value = loads_strict(raw)
            _need(canonical(value).encode('utf-8') == raw,
                  'REGISTRY_PRIVATE_READ_NONCANONICAL')
        except (TypeError, ValueError, UnicodeError, OverflowError,
                RecursionError):
            raise Denied('REGISTRY_PRIVATE_READ_FRAME_DENIED') from None
        return value
    except (OSError, TimeoutError):
        raise Denied('REGISTRY_PRIVATE_READ_TRANSPORT_UNAVAILABLE') from None
    finally:
        try:
            connection.settimeout(previous)
        except OSError:
            pass


def _request(value, store):
    _need(type(value) is dict and set(value) == {
        'schemaVersion', 'operation', 'instanceId',
        'scopeDigest', 'requestId', 'params'}
          and type(value['schemaVersion']) is int
          and value['schemaVersion'] == 1
          and value['operation'] in _OPERATIONS
          and value['instanceId'] == store.instance_id
          and value['scopeDigest'] == _hash(store.scope)
          and _uuid(value['requestId'])
          and type(value['params']) is dict,
          'REGISTRY_PRIVATE_READ_REQUEST_DENIED')
    op, params = value['operation'], value['params']
    if op == 'candidate.list_desired':
        _need(set(params) == {'limit', 'cursor'}
              and type(params['limit']) is int
              and 1 <= params['limit'] <= 100
              and (params['cursor'] is None or
                   type(params['cursor']) is str and
                   len(params['cursor']) <= 129),
              'REGISTRY_PRIVATE_READ_REQUEST_DENIED')
    elif op == 'candidate.original_operation':
        _need(set(params) == {'operationId'}
              and _uuid(params['operationId']),
              'REGISTRY_PRIVATE_READ_REQUEST_DENIED')
    else:
        _need(params == {},
              'REGISTRY_PRIVATE_READ_REQUEST_DENIED')
    return op, params


def _real_peer(connection, *, reader_uid, reader_gid):
    """Existing socket ACL + exact UID/GID, now require live kernel pidfd.

    A legitimate Gateway in another PID namespace has SO_PEERCRED pid=0.
    No caller-supplied process identifier or fallback to UID/GID alone is
    accepted. Registry does not owner-pin the future Gateway process at
    listener startup; its independent owner approval is still Core/Portal.
    """
    try:
        return kernel_live_peer(
            connection, expected_uid=reader_uid, expected_gid=reader_gid)
    except Denied as exc:
        if str(exc) == 'REGISTRY_PIDFD_CREDENTIALS_DENIED':
            # Preserve the accepted private Registry transport's exact
            # unauthorized UID/GID error contract.
            raise Denied('REGISTRY_PRIVATE_READ_PEER_DENIED') from None
        raise


class PrivateCandidateReadService:
    """Owner-host-composed Unix-only reader of *existing* local schema 3.

    A real Registry writer must run under its own process/UID with a private
    volume. This service has no in-process DB write path or tokens; its
    reader peer identity is checked by Linux SO_PEERCRED, not JSON fields.
    """

    def __init__(self, *, store, socket_path, reader_uid, reader_gid):
        _need(type(store) is FunctionalV1CandidateJournal
              and type(reader_uid) is int and 0 < reader_uid < 2**31
              and type(reader_gid) is int and 0 < reader_gid < 2**31
              and hasattr(socket, 'SO_PEERCRED')
              and os.geteuid() > 0 and os.getegid() > 0,
              'REGISTRY_PRIVATE_READ_CONFIG_DENIED')
        path = _absolute_path(socket_path, socket_name=True)
        # Do not put a shared reader socket under the private SQLite
        # directory or anywhere inside that writer-owned state tree.
        _need(not path.parent.is_relative_to(store.path.parent),
              'REGISTRY_PRIVATE_READ_SHARED_STATE_DIRECTORY')
        self._store = store
        self._path = path
        self._uid = reader_uid
        self._gid = reader_gid
        self._endpoint = None
        _private_socket_dir(path, self._gid)
        # Startup MUST read/replay existing schema 3; do not bootstrap.
        self._head()

    def _head(self):
        result = self._store.checkpoint()
        _need(result['result'] == 'LOCAL_SOURCE_CANDIDATE_HEAD'
              and result['integrityModel'] == 'LOCAL_EVENT_CHAIN_ONLY'
              and result['evidenceVerified'] is False
              and result['admissionAllowed'] is False
              and result['deploymentAllowed'] is False,
              'REGISTRY_PRIVATE_READ_STATE_DENIED')
        return result

    def _check_endpoint(self):
        _private_socket_dir(self._path, self._gid)
        try:
            row = self._path.lstat()
        except OSError:
            raise Denied('REGISTRY_PRIVATE_READ_SOCKET_MISSING') from None
        _need(stat.S_ISSOCK(row.st_mode) and row.st_nlink == 1
              and row.st_uid == os.geteuid() and row.st_gid == self._gid
              and stat.S_IMODE(row.st_mode) == 0o660,
              'REGISTRY_PRIVATE_READ_SOCKET_DENIED')
        endpoint = row.st_dev, row.st_ino
        _need(self._endpoint == endpoint,
              'REGISTRY_PRIVATE_READ_SOCKET_CHANGED')
        return endpoint

    def bind(self):
        """Bind one private path. Never unlink a preexisting socket/file."""
        _private_socket_dir(self._path, self._gid)
        _need(not self._path.exists() and not self._path.is_symlink(),
              'REGISTRY_PRIVATE_READ_SOCKET_EXISTS')
        self._head()
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            # Socket is never listening during ownership/mode adjustment.
            s.bind(str(self._path))
            row = self._path.lstat()
            self._endpoint = (row.st_dev, row.st_ino)
            # A non-root Registry must never need CAP_CHOWN or membership
            # in the Gateway reader's group. Linux setgid parent directory
            # (owner Registry UID, group reader GID, mode 2710) forces the
            # fresh socket to inherit reader GID before listening.
            _need(row.st_gid == self._gid,
                  'REGISTRY_PRIVATE_READ_SOCKET_GROUP_NOT_INHERITED')
            os.chmod(self._path, 0o660)
            self._check_endpoint()
            s.listen(8)
            return s
        except (OSError, Denied):
            s.close()
            # A failed bind cannot remove any socket replaced by another
            # actor. No opportunistic stale-socket deletion on startup.
            if self._endpoint is not None:
                try:
                    row = self._path.lstat()
                    if (row.st_dev, row.st_ino) == self._endpoint:
                        self._path.unlink()
                except OSError:
                    pass
            self._endpoint = None
            raise Denied('REGISTRY_PRIVATE_READ_SOCKET_SETUP_DENIED') from None

    def handle(self, connection):
        """Exactly one bound peer request and one candidate response."""
        before = self._check_endpoint()
        _need(connection.getsockname() == str(self._path),
              'REGISTRY_PRIVATE_READ_WRONG_SOCKET')
        peer = _real_peer(connection, reader_uid=self._uid,
                          reader_gid=self._gid)
        _need(peer[1:3] == (self._uid, self._gid),
              'REGISTRY_PRIVATE_READ_PEER_DENIED')
        request = _canonical_frame(connection)
        op, params = _request(request, self._store)
        head = self._head()
        if op == 'candidate.capabilities':
            data = {
                'result': 'INACTIVE_LOCAL_REGISTRY_CANDIDATE',
                'operations': list(_OPERATIONS),
                'storeAvailable': True,
                'authenticatedCollectorAvailable': False,
                'integrityModel': 'LOCAL_EVENT_CHAIN_ONLY',
                'writeEnabled': False, 'liveRegistryAvailable': False,
            }
        elif op == 'candidate.head':
            data = head
        elif op == 'candidate.list_desired':
            data = self._store.list_desired_candidates(**params)
        else:
            data = self._store.operation(
                actor=PLANNER, operation_id=params['operationId'])
        _need(self._head() == head,
              'REGISTRY_PRIVATE_READ_STATE_CHANGED')
        _need(self._check_endpoint() == before
              and _real_peer(connection, reader_uid=self._uid,
                             reader_gid=self._gid) == peer,
              'REGISTRY_PRIVATE_READ_BINDING_CHANGED')
        envelope = {
            'schemaVersion': 1, 'result': 'SOURCE_ONLY_CANDIDATE_READ',
            'requestId': request['requestId'], 'operation': op,
            'instanceId': self._store.instance_id,
            'scopeDigest': _hash(self._store.scope),
            'data': data,
            'authenticatedCollectorAvailable': False,
            'admissionAllowed': False, 'writeEnabled': False,
            'deploymentAllowed': False, 'runtimeActivationAllowed': False,
            'rollbackProtected': False,
        }
        wire = canonical(envelope).encode('utf-8') + b'\n'
        _need(len(wire) <= _MAX_REPLY + 1,
              'REGISTRY_PRIVATE_READ_RESPONSE_TOO_LARGE')
        try:
            previous = connection.gettimeout()
            connection.settimeout(_TIMEOUT)
            connection.sendall(wire)
            connection.shutdown(socket.SHUT_WR)
            connection.settimeout(previous)
        except (OSError, TimeoutError):
            raise Denied('REGISTRY_PRIVATE_READ_SEND_UNAVAILABLE') from None

    def serve(self, *, max_connections=None):
        """Foreground Unix listener. Tests cap requests; host owns lifecycle."""
        _need(max_connections is None or
              type(max_connections) is int and 1 <= max_connections <= 1000,
              'REGISTRY_PRIVATE_READ_SERVER_LIMIT')
        count = 0
        with self.bind() as listener:
            try:
                while max_connections is None or count < max_connections:
                    connection, _ = listener.accept()
                    count += 1
                    with connection:
                        try:
                            self.handle(connection)
                        except (Denied, Stale, OSError):
                            # No error payload that could be mistaken for a
                            # valid queue, negative receipt or owner decision.
                            pass
            finally:
                try:
                    row = self._path.lstat()
                    if (row.st_dev, row.st_ino) == self._endpoint:
                        self._path.unlink()
                except OSError:
                    pass
                self._endpoint = None
        return count


def _load_owner_config(path):
    """Single exact host-created file, not request-supplied credentials."""
    value = _absolute_path(path)
    try:
        parent = value.parent.lstat()
        fd = os.open(value, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        with os.fdopen(fd, 'rb') as f:
            row = os.fstat(f.fileno())
            _need(stat.S_ISREG(row.st_mode) and row.st_nlink == 1
                  and row.st_uid == os.geteuid()
                  and stat.S_IMODE(row.st_mode) == 0o600
                  and stat.S_ISDIR(parent.st_mode)
                  and parent.st_uid == os.geteuid()
                  and stat.S_IMODE(parent.st_mode) == 0o700,
                  'REGISTRY_PRIVATE_READ_CONFIG_PERMISSIONS')
            data = f.read(8193)
        _need(0 < len(data) <= 8192,
              'REGISTRY_PRIVATE_READ_CONFIG_INVALID')
        parsed = loads_strict(data)
        _need(canonical(parsed).encode('utf-8') == data
              and type(parsed) is dict and set(parsed) == {
                  'schemaVersion', 'instanceId', 'scope', 'registryStatePath',
                  'socketPath', 'readerUid', 'readerGid'}
              and type(parsed['schemaVersion']) is int
              and parsed['schemaVersion'] == 1
              and _uuid(parsed['instanceId']),
              'REGISTRY_PRIVATE_READ_CONFIG_INVALID')
        _scope(parsed['scope'])
        _absolute_path(parsed['registryStatePath'])
        _absolute_path(parsed['socketPath'], socket_name=True)
        return parsed
    except Denied:
        raise
    except (OSError, TypeError, ValueError, UnicodeError, RecursionError):
        raise Denied('REGISTRY_PRIVATE_READ_CONFIG_UNAVAILABLE') from None


def main(argv=None):
    """Manual *non-Production* candidate run. No install or enrollment."""
    parser = argparse.ArgumentParser(
        description='Inactive Registry candidate read-only private socket')
    parser.add_argument('--owner-config', required=True)
    args = parser.parse_args(argv)
    cfg = _load_owner_config(args.owner_config)
    def read_disabled(_):
        raise Denied('REGISTRY_PRIVATE_READ_WRITE_DISABLED')
    store = FunctionalV1CandidateJournal(
        cfg['registryStatePath'], instance_id=cfg['instanceId'],
        scope=cfg['scope'], plan_reader=read_disabled)
    service = PrivateCandidateReadService(
        store=store, socket_path=cfg['socketPath'],
        reader_uid=cfg['readerUid'], reader_gid=cfg['readerGid'])
    service.serve()
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (Denied, Stale) as exc:
        print('REGISTRY_PRIVATE_READ_STOP: ' + str(exc), file=sys.stderr)
        sys.exit(1)

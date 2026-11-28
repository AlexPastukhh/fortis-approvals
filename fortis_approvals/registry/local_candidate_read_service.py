"""Private Unix Registry candidate and owner-sealed semantic service entrypoint.

The protected host configuration binds state, socket and process identities.
The legacy planner and semantic writer each require explicit provisioning.
Startup uses already prepared state and leaves installation and migration
to the owner release controller.
"""
import argparse
from contextlib import contextmanager
import errno
import fcntl
import hashlib
import os
from pathlib import Path
import socket
import stat
import struct
import sys
import time

from ..core import Conflict, Denied, Stale, canonical, loads_strict
from ..integrations.registry.owner_pinned_pidfd import kernel_live_peer, peer_proof
from ..integrations.registry.read_contract import (PLANNER_OPERATION, PLANNER_FRAME_LIMIT,
    verify_planner_frame, private_planner_key)
from .functional_v1_journal import FunctionalV1CandidateJournal
from .state_journal import _hash, _hex, _need, _scope, _uuid, PLANNER

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


def _canonical_frame(connection, limit=_MAX_FRAME):
    previous = connection.gettimeout()
    try:
        deadline = time.monotonic() + _TIMEOUT
        connection.settimeout(_TIMEOUT)
        collected = bytearray()
        while True:
            remaining = deadline - time.monotonic()
            _need(remaining > 0, 'REGISTRY_PRIVATE_READ_FRAME_TIMEOUT')
            connection.settimeout(remaining)
            data = connection.recv(min(4096, limit + 2 - len(collected)))
            _need(bool(data) and len(collected) + len(data) <= limit + 1,
                  'REGISTRY_PRIVATE_READ_FRAME_DENIED')
            collected.extend(data)
            if b'\n' in data:
                _need(collected[-1:] == b'\n'
                      and collected.count(b'\n') == 1,
                      'REGISTRY_PRIVATE_READ_FRAME_DENIED')
                break
        # Client must half-close; no request pipelining or trailing junk.
        remaining = deadline - time.monotonic()
        _need(remaining > 0, 'REGISTRY_PRIVATE_READ_FRAME_TIMEOUT')
        connection.settimeout(remaining)
        _need(connection.recv(1) == b'',
              'REGISTRY_PRIVATE_READ_TRAILING_REQUEST')
        raw = bytes(collected[:-1])
        _need(0 < len(raw) <= limit,
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

    def __init__(self, *, store, socket_path, reader_uid, reader_gid, planner_key=None,
                 managed_startup=False):
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
        _need(type(managed_startup) is bool and
              (not managed_startup or type(planner_key) is bytes),
              'REGISTRY_MANAGED_STARTUP_CONFIG_DENIED')
        self._managed_startup = managed_startup
        self._store = store
        self._path = path
        self._uid = reader_uid
        self._gid = reader_gid
        _need(planner_key is None or type(planner_key) is bytes and len(planner_key) == 32,
              'REGISTRY_PLANNER_KEY_DENIED')
        self._planner_key = planner_key
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

    @contextmanager
    def _managed_socket(self):
        """Serialize managed listeners and remove only a verified dead socket."""
        if not self._managed_startup:
            with self.bind() as listener:
                yield listener
            return
        _private_socket_dir(self._path, self._gid)
        directory = os.open(self._path.parent,
                            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            try:
                fcntl.flock(directory, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError:
                raise Denied('REGISTRY_MANAGED_STARTUP_BUSY') from None
            # Verify the admitted Registry database before changing its endpoint.
            self._head()
            self._remove_dead_socket(directory)
            # bind() runs before any requests or worker threads are started.
            # An abrupt kill even before chmod leaves a socket with mode 0660.
            previous = os.umask(0o117)
            try:
                listener = self.bind()
            finally:
                os.umask(previous)
            with listener:
                yield listener
        finally:
            os.close(directory)

    def _remove_dead_socket(self, directory):
        name = self._path.name
        try:
            stale = os.stat(name, dir_fd=directory, follow_symlinks=False)
        except FileNotFoundError:
            return
        _need(stat.S_ISSOCK(stale.st_mode) and stale.st_nlink == 1
              and stale.st_uid == os.geteuid() and stale.st_gid == self._gid
              and stat.S_IMODE(stale.st_mode) == 0o660,
              'REGISTRY_MANAGED_STARTUP_SOCKET_DENIED')
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as probe:
            probe.settimeout(_TIMEOUT)
            try:
                probe.connect(str(self._path))
            except OSError as exc:
                _need(exc.errno == errno.ECONNREFUSED,
                      'REGISTRY_MANAGED_STARTUP_SOCKET_DENIED')
            else:
                raise Denied('REGISTRY_MANAGED_STARTUP_BUSY')
        current_dir = self._path.parent.lstat()
        locked_dir = os.fstat(directory)
        current = os.stat(name, dir_fd=directory, follow_symlinks=False)
        _need((current_dir.st_dev, current_dir.st_ino) == (locked_dir.st_dev, locked_dir.st_ino)
              and (current.st_dev, current.st_ino, current.st_ctime_ns) ==
                  (stale.st_dev, stale.st_ino, stale.st_ctime_ns),
              'REGISTRY_MANAGED_STARTUP_SOCKET_CHANGED')
        os.unlink(name, dir_fd=directory)

    def _prove_identity(self, connection):
        # Independent of the planner request MAC. No effect bytes have arrived.
        connection.settimeout(_TIMEOUT)
        challenge = bytearray()
        deadline = time.monotonic() + _TIMEOUT
        while len(challenge) < 64:
            remaining = deadline - time.monotonic()
            _need(remaining > 0, 'REGISTRY_FUNCTIONAL_PEER_CHALLENGE_DENIED')
            connection.settimeout(remaining)
            chunk = connection.recv(64 - len(challenge))
            _need(chunk, 'REGISTRY_FUNCTIONAL_PEER_CHALLENGE_DENIED')
            challenge.extend(chunk)
        try:
            proof = peer_proof(self._planner_key, challenge.decode('ascii'),
                               instance_id=self._store.instance_id,
                               scope_digest=_hash(self._store.scope))
        except UnicodeDecodeError:
            raise Denied('REGISTRY_FUNCTIONAL_PEER_CHALLENGE_DENIED') from None
        connection.sendall(proof)

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
        if self._managed_startup:
            connection.settimeout(_TIMEOUT)
            first = connection.recv(1, socket.MSG_PEEK)
            if first != b'{':
                self._prove_identity(connection)
        request = _canonical_frame(connection, PLANNER_FRAME_LIMIT if
                                   self._planner_key is not None else _MAX_FRAME)
        if type(request) is dict and request.get('operation') == PLANNER_OPERATION:
            return self._ingest(connection, request, before, peer)
        _need(len(canonical(request).encode('utf-8')) <= _MAX_FRAME,
              'REGISTRY_PRIVATE_READ_FRAME_DENIED')
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

    def _ingest(self, connection, request, endpoint, peer):
        # Same confined Registry process and SQLite, separate authenticated
        # planner capability. A READ peer or forged actor field is insufficient.
        _need(self._planner_key is not None, 'REGISTRY_PLANNER_WRITE_DISABLED')
        params, evidence = verify_planner_frame(self._planner_key, request,
            instance_id=self._store.instance_id, scope_digest=_hash(self._store.scope))
        _need(self._check_endpoint() == endpoint
              and _real_peer(connection, reader_uid=self._uid,
                             reader_gid=self._gid) == peer,
              'REGISTRY_PLANNER_PEER_CHANGED')
        def original(reference):
            _need(reference == params['evidenceId'], 'REGISTRY_PLANNER_EVIDENCE_ID_DENIED')
            return evidence
        writer = FunctionalV1CandidateJournal(self._store.path,
            instance_id=self._store.instance_id, scope=self._store.scope, plan_reader=original)
        result = writer.append_range(actor=PLANNER, operation_id=params['operationId'],
            evidence_id=params['evidenceId'], evidence_digest=_hash(evidence),
            expected_revision=params['expectedRevision'])
        # If peer/endpoint changes after commit, no success ACK. Recover by UUID.
        _need(self._check_endpoint() == endpoint
              and _real_peer(connection, reader_uid=self._uid,
                             reader_gid=self._gid) == peer,
              'REGISTRY_PLANNER_PEER_CHANGED')
        wire = canonical({'schemaVersion':1, 'operation':PLANNER_OPERATION,
            'instanceId':self._store.instance_id, 'scopeDigest':_hash(self._store.scope),
            'requestId':params['operationId'], 'data':result}).encode('utf-8')+b'\n'
        _need(len(wire) <= _MAX_REPLY+1, 'REGISTRY_PLANNER_REPLY_LIMIT')
        try:
            connection.settimeout(_TIMEOUT)
            connection.sendall(wire)
            connection.shutdown(socket.SHUT_WR)
        except OSError:
            raise Denied('REGISTRY_PLANNER_ACK_UNKNOWN') from None

    def serve(self, *, max_connections=None):
        """Foreground Unix listener. Tests cap requests; host owns lifecycle."""
        _need(max_connections is None or
              type(max_connections) is int and 1 <= max_connections <= 1000,
              'REGISTRY_PRIVATE_READ_SERVER_LIMIT')
        count = 0
        with self._managed_socket() as listener:
            try:
                while max_connections is None or count < max_connections:
                    connection, _ = listener.accept()
                    count += 1
                    with connection:
                        try:
                            self.handle(connection)
                        except (Conflict, Denied, Stale, OSError):
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


_OWNER_RUNTIME_CONFIG=Path('/run/fortis-registry-runtime/profile.json')


def _owner_runtime_bytes(path, maximum):
    location=_absolute_path(str(path))
    try:
        parent=location.parent.lstat()
        fd=os.open(location,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK)
        with os.fdopen(fd,'rb') as stream:
            row=os.fstat(stream.fileno())
            _need(stat.S_ISREG(row.st_mode) and row.st_nlink==1
                  and row.st_uid==os.geteuid() and stat.S_IMODE(row.st_mode)==0o600
                  and stat.S_ISDIR(parent.st_mode) and parent.st_uid==os.geteuid()
                  and stat.S_IMODE(parent.st_mode)==0o700,
                  'REGISTRY_PRIVATE_READ_CONFIG_PERMISSIONS')
            data=stream.read(maximum+1)
        _need(0<len(data)<=maximum,'REGISTRY_PRIVATE_READ_CONFIG_INVALID')
        return data
    except OSError:
        raise Denied('REGISTRY_PRIVATE_READ_CONFIG_UNAVAILABLE') from None


def _load_owner_config(path, *, allow_semantic=False):
    """Single exact host-created file, not request-supplied credentials."""
    try:
        data=_owner_runtime_bytes(path,65536 if allow_semantic else 8192)
        parsed=loads_strict(data)
        fields={'schemaVersion','instanceId','scope','registryStatePath','socketPath',
                'readerUid','readerGid'}
        _need(type(parsed) is dict and canonical(parsed).encode('utf-8')==data
              and type(parsed.get('schemaVersion')) is int
              and (parsed['schemaVersion']==1 or (allow_semantic and parsed['schemaVersion'] in (2,3)))
              and (parsed['schemaVersion']==3 or len(data)<=8192)
              and set(parsed)==(fields|{'semantic', 'sourceWrite'} if parsed['schemaVersion']==3
                               else fields|{'semantic'} if parsed['schemaVersion']==2 else fields)
              and _uuid(parsed['instanceId']),'REGISTRY_PRIVATE_READ_CONFIG_INVALID')
        _scope(parsed['scope'])
        _absolute_path(parsed['registryStatePath'])
        _absolute_path(parsed['socketPath'],socket_name=True)
        return parsed
    except Denied:
        raise
    except (OSError,TypeError,ValueError,UnicodeError,RecursionError):
        raise Denied('REGISTRY_PRIVATE_READ_CONFIG_UNAVAILABLE') from None


def _readonly_owner_runtime(path):
    config=_OWNER_RUNTIME_CONFIG
    _need(path==str(config) and config.parent.resolve()==config.parent
          and os.statvfs(config.parent).f_flag & os.ST_RDONLY,
          'REGISTRY_PLANNER_OWNER_CONFIG_REQUIRED')
    mountinfo=Path('/proc/self/mountinfo').read_bytes()
    mounts=[line.split(b' - ',1)[0].split() for line in mountinfo.splitlines()]
    matches=[f for f in mounts if len(f)>5 and f[4]==os.fsencode(config.parent)]
    _need(len(matches)==1 and b'ro' in matches[0][5].split(b','),
          'REGISTRY_PLANNER_OWNER_CONFIG_REQUIRED')
    return config.parent


def _check_successor_profile(cfg, expected_profile_sha256):
    _need(cfg['schemaVersion'] == 3 and
          hashlib.sha256(canonical(cfg).encode()).hexdigest() == expected_profile_sha256,
          'REGISTRY_SUCCESSOR_PROFILE_PIN_CHANGED')


def main(argv=None):
    """Manual *non-Production* candidate run. No install or enrollment."""
    parser = argparse.ArgumentParser(
        description='Owner-configured Registry candidate private Unix socket')
    parser.add_argument('--owner-config', required=True)
    parser.add_argument('--functional-planner-key-digest')
    parser.add_argument('--managed-startup', action='store_true')
    parser.add_argument('--expected-profile-sha256')
    parser.add_argument('--corrective-preview-sha')
    args = parser.parse_args(argv)
    cfg = _load_owner_config(args.owner_config,allow_semantic=True)
    if args.expected_profile_sha256 is not None:
        _check_successor_profile(cfg, args.expected_profile_sha256)
    if args.corrective_preview_sha is not None:
        _need(cfg['schemaVersion']==3 and args.expected_profile_sha256 is not None
              and _hex(args.corrective_preview_sha,40),
              'REGISTRY_CORRECTIVE_PREVIEW_PIN_REQUIRED')
    if cfg['schemaVersion'] in (2,3):
        _need(args.functional_planner_key_digest is None and not args.managed_startup,
              'REGISTRY_PRIVATE_READ_CONFIG_INVALID')
        root=_readonly_owner_runtime(args.owner_config)
        readonly = bool(os.statvfs(cfg['registryStatePath']).f_flag & os.ST_RDONLY)
        if cfg['schemaVersion'] == 2 or args.corrective_preview_sha is not None:
            _need(readonly, 'REGISTRY_SEMANTIC_READONLY_STATE_REQUIRED')
        else:
            _need(not readonly, 'REGISTRY_SEMANTIC_WRITE_STATE_REQUIRED')
        from .semantic_unix_service import owner_semantic_reader
        owner_semantic_reader(cfg,root,corrective_preview_sha=args.corrective_preview_sha).serve()
        return 0

    planner_key=None
    if args.functional_planner_key_digest is not None:
        # The owner chooses the exact pinned planner profile.
        root=_readonly_owner_runtime(args.owner_config)
        planner_key=private_planner_key(root/'planner.key',args.functional_planner_key_digest)
    def read_disabled(_):
        raise Denied('REGISTRY_PRIVATE_READ_WRITE_DISABLED')
    store = FunctionalV1CandidateJournal(
        cfg['registryStatePath'], instance_id=cfg['instanceId'],
        scope=cfg['scope'], plan_reader=read_disabled)
    service = PrivateCandidateReadService(
        store=store, socket_path=cfg['socketPath'],
        reader_uid=cfg['readerUid'], reader_gid=cfg['readerGid'], planner_key=planner_key,
        managed_startup=args.managed_startup)
    service.serve()
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (Denied, Stale) as exc:
        print('REGISTRY_PRIVATE_READ_STOP: ' + str(exc), file=sys.stderr)
        sys.exit(1)

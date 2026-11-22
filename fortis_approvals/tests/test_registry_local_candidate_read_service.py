"""Real local AF_UNIX transport, source-only. NOT cross-UID host acceptance."""
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import time
import uuid
import unittest
from unittest.mock import patch

from fortis_approvals.core import Denied, canonical, loads_strict
from fortis_approvals.registry import local_candidate_read_service as server
from fortis_approvals.tests import test_registry_functional_v1_journal as fixture


class LocalCandidateReadServiceTests(unittest.TestCase):
    setUp = fixture.FunctionalV1JournalTests.setUp
    read = fixture.FunctionalV1JournalTests.read
    args = fixture.FunctionalV1JournalTests.args
    append = fixture.FunctionalV1JournalTests.append
    accept = fixture.FunctionalV1JournalTests.accept
    suffix = fixture.FunctionalV1JournalTests.suffix

    def setup_service(self, *, reader_uid=None, reader_gid=None):
        sock_temp = tempfile.TemporaryDirectory(prefix='fortis-reg-read-')
        self.addCleanup(sock_temp.cleanup)
        self.socketdir = Path(sock_temp.name)
        self.socketdir.chmod(0o710)
        self.socketpath = self.socketdir / 'registry-read.sock'
        self.reader_uid = os.geteuid() if reader_uid is None else reader_uid
        self.reader_gid = os.getegid() if reader_gid is None else reader_gid
        self.service = server.PrivateCandidateReadService(
            store=self.state, socket_path=str(self.socketpath),
            reader_uid=self.reader_uid, reader_gid=self.reader_gid)

    def request(self, operation='candidate.capabilities', params=None, **over):
        return {
            'schemaVersion':1, 'operation':operation,
            'instanceId':self.instance,
            'scopeDigest':server._hash(self.scope),
            'requestId':str(uuid.uuid4()),
            'params':{} if params is None else params,
        } | over

    def client(self, *, request=None, raw=None, half_close=True,
               read_response=True):
        wire = raw if raw is not None else canonical(
            request or self.request()).encode('utf-8') + b'\n'
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as peer:
            peer.settimeout(4)
            peer.connect(str(self.socketpath))
            try:
                peer.sendall(wire)
                if half_close:
                    peer.shutdown(socket.SHUT_WR)
                if read_response:
                    response=bytearray()
                    while True:
                        data=peer.recv(4096)
                        if not data:
                            break
                        response.extend(data)
                        self.assertLessEqual(len(response),server._MAX_REPLY+1)
                    return bytes(response)
            except (ConnectionResetError, BrokenPipeError):
                # An OS-level early DENY may reset an unread stream. This
                # is an intentionally empty response, never an error DTO.
                return b''

    def roundtrip(self, *, request=None, raw=None, half_close=True,
                  service=None, before_handle=None):
        service = service or self.service
        listener=service.bind()
        failures=[]
        def worker():
            try:
                listener.settimeout(5)
                conn,_ = listener.accept()
                with conn:
                    if before_handle:
                        before_handle()
                    service.handle(conn)
            except Exception as exc:
                failures.append(exc)
        thread=threading.Thread(target=worker,daemon=True)
        thread.start()
        try:
            response=self.client(request=request,raw=raw,
                                 half_close=half_close)
        finally:
            thread.join(timeout=7)
            self.assertFalse(thread.is_alive(),'read service worker leaked')
            listener.close()
            # Test host owns this temporary socket directory. Never unlink
            # arbitrary host sockets in production.
            if self.socketpath.is_socket() or self.socketpath.is_symlink():
                self.socketpath.unlink()
            service._endpoint=None
        return response,failures

    def decode(self, raw, *, operation, request_id):
        self.assertTrue(raw.endswith(b'\n'),raw)
        self.assertEqual(raw.count(b'\n'),1)
        value=loads_strict(raw[:-1])
        self.assertEqual(raw[:-1],canonical(value).encode('utf-8'))
        self.assertEqual(value['schemaVersion'],1)
        self.assertEqual(value['result'],'SOURCE_ONLY_CANDIDATE_READ')
        self.assertEqual(value['requestId'],request_id)
        self.assertEqual(value['operation'],operation)
        self.assertEqual(value['instanceId'],self.instance)
        self.assertEqual(value['scopeDigest'],server._hash(self.scope))
        for key in ('authenticatedCollectorAvailable','admissionAllowed',
                    'writeEnabled','deploymentAllowed',
                    'runtimeActivationAllowed','rollbackProtected'):
            self.assertIs(value[key],False)
        return value['data']

    def test_real_unix_capabilities_explicitly_source_only(self):
        self.setup_service()
        req=self.request()
        raw,failures=self.roundtrip(request=req)
        self.assertEqual(failures,[])
        data=self.decode(raw,operation=req['operation'],
                         request_id=req['requestId'])
        self.assertEqual(data['result'],'INACTIVE_LOCAL_REGISTRY_CANDIDATE')
        self.assertEqual(data['integrityModel'],'LOCAL_EVENT_CHAIN_ONLY')
        self.assertIs(data['liveRegistryAvailable'],False)
        self.assertIs(data['authenticatedCollectorAvailable'],False)
        self.assertIs(data['writeEnabled'],False)
        self.assertEqual(self.socketdir.stat().st_mode & 0o777,0o710)
        self.assertEqual(self.state.checkpoint()['localCheckpoint']['revision'],0)

    def test_persisted_desired_head_and_original_uuid_over_unix(self):
        self.accept()
        operation_id=self.operations[0][0]['operation_id']
        self.setup_service()
        for operation,params,result in (
            ('candidate.head',{},'LOCAL_SOURCE_CANDIDATE_HEAD'),
            ('candidate.list_desired',{'limit':5,'cursor':None},
             'LOCAL_DESIRED_CANDIDATE_PAGE'),
            ('candidate.original_operation',{'operationId':operation_id},
             'LOCAL_DESIRED_CANDIDATE_COMMITTED')):
            with self.subTest(operation=operation):
                req=self.request(operation,params)
                raw,failures=self.roundtrip(request=req)
                self.assertEqual(failures,[])
                data=self.decode(raw,operation=operation,
                                 request_id=req['requestId'])
                self.assertEqual(data['result'],result)
                if operation=='candidate.list_desired':
                    self.assertEqual(len(data['records']),1)
                    self.assertIsNone(data['records'][0]['actual'])
                    self.assertFalse(data['deploymentVerified'])
                    self.assertFalse(data['admissionAllowed'])
                elif operation=='candidate.original_operation':
                    self.assertEqual(data['receipt']['operationId'],operation_id)
                    self.assertFalse(data['evidenceVerified'])

    def test_all_write_and_spoofed_actor_operations_rejected(self):
        self.setup_service()
        for request in (
            self.request('registry.ingest_merged'),
            self.request('registry.list_records'),
            self.request('registry.report_manual_complete'),
            self.request(actor='reader'),
            self.request(params={'actor':'planner'}),
            self.request('candidate.original_operation',{'operationId':'wrong'}),
            self.request('candidate.list_desired',{'limit':True,'cursor':None}),
            self.request('candidate.list_desired',{'limit':101,'cursor':None}),
            self.request(instanceId=str(uuid.uuid4())),
            self.request(scopeDigest='f'*64),
            self.request(schemaVersion=True),
        ):
            with self.subTest(request=request):
                wire,failures=self.roundtrip(request=request)
                self.assertEqual(wire,b'')
                self.assertEqual(len(failures),1)
                self.assertIsInstance(failures[0],Denied)
        self.assertEqual(self.state.checkpoint()['localCheckpoint']['revision'],0)

    def test_malformed_duplicate_noncanonical_and_pipelined_denied(self):
        self.setup_service()
        valid=canonical(self.request()).encode('utf-8')
        for raw in (
            b'{"schemaVersion":1,"schemaVersion":1,"operation":"candidate.head"}\n',
            b'{"schemaVersion":NaN}\n',
            b'{ "schemaVersion":1}\n',
            valid+b'\n'+valid+b'\n',
            valid+b'  \n',
            b'x'*4097+b'\n',
            valid+b'\n\x00',
        ):
            with self.subTest(raw=raw[:50]):
                wire,failures=self.roundtrip(raw=raw)
                self.assertEqual(wire,b'')
                self.assertEqual(len(failures),1)
                self.assertIsInstance(failures[0],Denied)

    def test_missing_half_close_fails_closed(self):
        self.setup_service()
        wire,failures=self.roundtrip(half_close=False)
        self.assertEqual(wire,b'')
        self.assertEqual(len(failures),1)
        self.assertIsInstance(failures[0],Denied)

    def test_actual_kernel_uid_mismatch_denies_before_read(self):
        self.setup_service(reader_uid=os.geteuid()+1)
        wire,failures=self.roundtrip()
        self.assertEqual(wire,b'')
        self.assertEqual(len(failures),1)
        self.assertRegex(str(failures[0]),'PEER_DENIED')

    def test_changed_source_during_read_never_yields_old_empty_queue(self):
        self.setup_service()
        original=self.state.list_desired_candidates
        def changed(**kwargs):
            result=original(**kwargs)
            self.accept()
            return result
        request=self.request('candidate.list_desired',
                             {'limit':5,'cursor':None})
        with patch.object(self.state,'list_desired_candidates',
                          side_effect=changed):
            wire,failures=self.roundtrip(request=request)
        self.assertEqual(wire,b'')
        self.assertEqual(len(failures),1)
        self.assertIsInstance(failures[0],Denied)
        self.assertIn('STATE_CHANGED',str(failures[0]))
        self.assertEqual(self.state.checkpoint()['localCheckpoint']['revision'],1)

    def test_cannot_expose_reader_socket_inside_private_db_tree(self):
        nested = self.path.parent / 'socket'
        nested.mkdir(mode=0o710)
        nested.chmod(0o710)
        with self.assertRaisesRegex(Denied,'SHARED_STATE_DIRECTORY'):
            server.PrivateCandidateReadService(
                store=self.state,socket_path=str(nested/'read.sock'),
                reader_uid=os.geteuid(),reader_gid=os.getegid())

    def test_existing_socket_never_unlinked_on_bind(self):
        self.setup_service()
        self.socketpath.write_text('do not replace',encoding='utf-8')
        with self.assertRaisesRegex(Denied,'SOCKET_EXISTS'):
            self.service.bind()
        self.assertEqual(self.socketpath.read_text(encoding='utf-8'),
                         'do not replace')

    def test_private_directory_required_and_missing_sqlite_fails(self):
        self.setup_service()
        self.socketdir.chmod(0o755)
        with self.assertRaisesRegex(Denied,'SOCKET_DIRECTORY_DENIED'):
            self.service.bind()
        self.socketdir.chmod(0o710)
        self.path.rename(self.path.with_name('removed.sqlite'))
        with self.assertRaises(Denied):
            server.PrivateCandidateReadService(
                store=self.state,socket_path=str(self.socketpath),
                reader_uid=os.geteuid(),reader_gid=os.getegid())

    def test_bounded_listener_multiple_real_socket_clients(self):
        self.setup_service()
        errors=[]
        def worker():
            try:
                count=self.service.serve(max_connections=2)
                self.assertEqual(count,2)
            except Exception as e:
                errors.append(e)
        thread=threading.Thread(target=worker,daemon=True)
        thread.start()
        for _ in range(2):
            deadline=time.monotonic()+3
            while not self.socketpath.is_socket():
                self.assertLess(time.monotonic(),deadline,
                                'bound listener not available')
                time.sleep(0.01)
            req=self.request('candidate.head')
            raw=self.client(request=req)
            self.assertEqual(
                self.decode(raw,operation=req['operation'],
                            request_id=req['requestId'])['result'],
                'LOCAL_SOURCE_CANDIDATE_HEAD')
        thread.join(timeout=5)
        self.assertFalse(thread.is_alive())
        self.assertEqual(errors,[])
        self.assertFalse(self.socketpath.exists())

    def test_reject_config_world_readable_and_extra_fields(self):
        self.setup_service()
        configdir=self.path.parent/'owner-config'
        configdir.mkdir(mode=0o700)
        cfg=configdir/'registry.json'
        data={
            'schemaVersion':1,'instanceId':self.instance,
            'scope':self.scope,'registryStatePath':str(self.path),
            'socketPath':str(self.socketpath),
            'readerUid':os.geteuid(),'readerGid':os.getegid(),
        }
        cfg.write_text(canonical(data),encoding='utf-8')
        cfg.chmod(0o644)
        with self.assertRaisesRegex(Denied,'CONFIG_PERMISSIONS'):
            server._load_owner_config(str(cfg))
        cfg.chmod(0o600)
        self.assertEqual(server._load_owner_config(str(cfg)),data)
        cfg.write_text(canonical(data|{'liveRegistry':True}),encoding='utf-8')
        with self.assertRaisesRegex(Denied,'CONFIG_INVALID'):
            server._load_owner_config(str(cfg))

    def test_separate_process_serves_existing_db_without_enrollment(self):
        self.setup_service()
        self.accept()
        configdir=self.path.parent/'owner-config'
        configdir.mkdir(mode=0o700)
        cfg=configdir/'registry.json'
        data={
            'schemaVersion':1,'instanceId':self.instance,
            'scope':self.scope,'registryStatePath':str(self.path),
            'socketPath':str(self.socketpath),
            'readerUid':os.geteuid(),'readerGid':os.getegid(),
        }
        cfg.write_text(canonical(data),encoding='utf-8')
        cfg.chmod(0o600)
        cmd=[sys.executable,'-B','-m',
             'fortis_approvals.registry.local_candidate_read_service',
             '--owner-config',str(cfg)]
        with subprocess.Popen(cmd,stdout=subprocess.DEVNULL,
                              stderr=subprocess.PIPE) as proc:
            try:
                deadline=time.monotonic()+4
                while not self.socketpath.is_socket():
                    if proc.poll() is not None:
                        self.fail('candidate process died: '+repr(
                            proc.stderr.read(500)))
                    self.assertLess(time.monotonic(),deadline)
                    time.sleep(0.02)
                req=self.request('candidate.list_desired',
                                 {'limit':10,'cursor':None})
                result=self.decode(self.client(request=req),
                                   operation=req['operation'],
                                   request_id=req['requestId'])
                self.assertEqual(result['localRevision'],1)
                self.assertEqual(len(result['records']),1)
                self.assertFalse(result['deploymentVerified'])
            finally:
                proc.terminate()
                proc.wait(timeout=4)
        self.assertEqual(self.state.checkpoint()['localCheckpoint']['revision'],1)


if __name__ == '__main__':
    unittest.main()

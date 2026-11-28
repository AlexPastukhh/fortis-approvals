"""Private frames and an optional kernel-checked separate Unix listener.

The process fixture uses the sandbox UID/GID on both ends. Host identity
separation and protected mount provisioning remain independent proofs.
"""
import copy
import socket
import unittest
from concurrent.futures import ThreadPoolExecutor

from fortis_approvals.core import Denied
from fortis_approvals.integrations.registry_contracts import semantic_contract as sc, semantic_wire as wire
from fortis_approvals.integrations.registry.candidate_gateway import GatewayRegistryUnixCandidateRead
from fortis_approvals.extensions.semantic_gateway import GatewayRegistrySemanticTransport
from fortis_approvals.registry.semantic_unix_service import SemanticFrameService
from fortis_approvals.registry.local_candidate_read_service import _canonical_frame
from fortis_approvals.tests import test_registry_source_lineage as fixture
from fortis_approvals.tests.test_registry_state_journal import uid


def start_kernel_semantic_peer(test, frames, root, *, peer_key):
    """Use the real listener and kernel peer proof in a same-UID sandbox."""
    from contextlib import contextmanager
    import multiprocessing
    import os
    from fortis_approvals.registry.semantic_unix_service import PrivateSemanticUnixService

    directory=root/'semantic-peer'
    directory.mkdir(exist_ok=True)
    directory.chmod(0o2710)
    path=directory/'registry.sock'
    context=multiprocessing.get_context('fork')
    ready=context.Event()
    reader_uid,reader_gid=os.geteuid(),os.getegid()

    def run():
        # The sandbox has a single UID/GID. Only the fixture supplies the
        # same-identity config. Serving, pidfds and all frame checks are real.
        service=object.__new__(PrivateSemanticUnixService)
        service.frames,service._store=frames,frames.store
        service._path,service._uid,service._gid=path,reader_uid,reader_gid
        service._planner_key,service._managed_startup=peer_key,True
        service._endpoint=None
        manage=service._managed_socket

        @contextmanager
        def announce():
            with manage() as listener:
                ready.set()
                yield listener

        service._managed_socket=announce
        service.serve()

    process=context.Process(target=run,daemon=True)
    process.start()

    def stop():
        if process.is_alive():
            process.terminate()
        process.join(5)

    test.addCleanup(stop)
    test.assertTrue(ready.wait(5),'private Registry process did not bind')
    peer=object.__new__(GatewayRegistryUnixCandidateRead)
    peer._path=path
    peer._instance,peer._scope=frames.pins['instance'],frames.pins['scope']
    peer._registry=(0,reader_uid,reader_gid)
    peer._reader=(reader_uid,reader_gid)
    peer._owner_pidfd = None
    peer._endpoint,peer._peer_key=None,peer_key
    peer._check_identity=lambda:None # Distinct reader UID/GID and caps are host acceptance.
    return peer,stop


def owner_read_configuration(lineage,root,*,operation,machine_actor='agent-1',source_write=None):
    """A protected test profile from the same Registry clone."""
    import hashlib
    import os

    config_root=root/('writer-config' if source_write is not None else 'runtime-config')
    config_root.mkdir(mode=0o700)
    peer_key,frame_key=b'p'*32,b'f'*32

    def write(name,data):
        path=config_root/name
        path.write_bytes(data)
        path.chmod(0o600)
        return path

    write('legacy-release-profile.json',sc.canonical(lineage.profile).encode())
    write('successor-release-profile.json',sc.canonical(lineage.successor).encode())
    write('semantic-peer.key',peer_key)
    write('semantic-frame.key',frame_key)
    operations = (operation,) if type(operation) is str else operation
    pins={'legacyWitness':lineage.witness,'transitionDigest':lineage.pin,
        'legacyProfileDigest':sc.digest(lineage.profile),
        'successorProfileDigest':sc.digest(lineage.successor),'generation':'a'*64,
        'internalActor':'internal','peerKeyDigest':hashlib.sha256(peer_key).hexdigest(),
        'frameKeyDigest':hashlib.sha256(frame_key).hexdigest(),
        'readGrants':[{'actor':actor,'operation':op,'subject':lineage.subjects[0]}
                      for actor in ('owner-actor',machine_actor) for op in operations]}
    config={'schemaVersion':2,'instanceId':lineage.instance,'scope':lineage.scope,
            'registryStatePath':str(lineage.store.path),
            'socketPath':str(root/'semantic-peer'/'registry.sock'),
            'readerUid':os.geteuid()+1,'readerGid':os.getegid()+1,'semantic':pins}
    if source_write is not None:
        config.update(schemaVersion=3, sourceWrite=source_write)
    return config,write('profile.json',sc.canonical(config).encode())


def read_service_via_entrypoint(path, *, readonly=True, expected_profile=None, corrective_preview_sha=None):
    """Capture what main would serve with isolated mount/UID prerequisites."""
    import os
    from contextlib import nullcontext
    from types import SimpleNamespace
    from unittest.mock import patch
    from fortis_approvals.registry import local_candidate_read_service as entrypoint
    from fortis_approvals.registry.semantic_unix_service import PrivateSemanticUnixService

    captured=[]
    mount = (patch('fortis_approvals.r7_registry_reader_mount._check_owner_readonly_mount')
             if corrective_preview_sha is not None else nullcontext())
    with mount, patch.object(entrypoint,'_readonly_owner_runtime',return_value=path.parent), \
         patch.object(entrypoint.os,'statvfs',return_value=SimpleNamespace(f_flag=os.ST_RDONLY if readonly else 0)), \
         patch('fortis_approvals.registry.semantic_unix_service._private_socket_dir'), \
         patch.object(PrivateSemanticUnixService,'serve',lambda service:captured.append(service)):
        args = ['--owner-config',str(path)]
        if expected_profile is not None:
            args.extend(['--expected-profile-sha256',expected_profile])
        if corrective_preview_sha is not None:
            args.extend(['--corrective-preview-sha',corrective_preview_sha])
        entrypoint.main(args)
    return captured[0]


class WireTests(fixture.LineageFixture,unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.domain.register_source(self.transition())
        self.allowed=True
        self.frames=SemanticFrameService(self.service,frame_key=b'f'*32,generation='a'*64,
                authorize=lambda a,act,b:self.allowed and a in ('agent-1','internal'),
                provenance=lambda a:'OWNER_TRANSCRIBED',internal_actor='internal')
        self.pins=self.frames.pins
        self.peer=object.__new__(GatewayRegistryUnixCandidateRead)
        self.peer._instance=self.pins['instance'];self.peer._scope=self.pins['scope']
        self.peer._peer_key=b'p'*32
        self.client=GatewayRegistrySemanticTransport(self.peer,frame_key=b'f'*32,
                   generation='a'*64,internal_actor='internal')
        self.client._exchange=self.exchange

    def exchange(self,frame,*,limit,timeout,reply_limit):
        # Actual socket framing only. No fake production peer proof.
        left,right=socket.socketpair()
        with left,right,ThreadPoolExecutor(max_workers=1) as pool:
            def server():
                try:
                    value=_canonical_frame(right,limit)
                    response=self.frames.dispatch(value)
                    right.sendall(sc.canonical(response).encode()+b'\n')
                finally:
                    right.shutdown(socket.SHUT_WR)
            future=pool.submit(server)
            left.settimeout(3)
            left.sendall(sc.canonical(frame).encode()+b'\n');left.shutdown(socket.SHUT_WR)
            data=bytearray()
            while True:
                chunk=left.recv(4096)
                if not chunk:break
                data.extend(chunk)
                self.assertLessEqual(len(data),reply_limit)
            future.result(timeout=3)
            return data

    def request(self,action,body,actor='agent-1'):
        return wire.request({'schemaVersion':2,'requestId':uid(),'instanceId':self.instance,
                'scopeDigest':self.pins['scope'],'generation':'a'*64,'actor':actor,
                'action':action,'body':body},**self.pins)

    def test_roundtrip_actual_registry_read_write_original_receipt(self):
        query={'subject':self.subjects[0]}
        self.assertEqual(self.client.read('agent-1','get_component',query)['data']['subject'],self.subjects[0])
        op=uid();p=self.report()
        result=self.client.owner_write('agent-1','report_release_result',p,operation_id=op,
                                       assertion_source='OWNER_TRANSCRIBED')
        self.assertEqual(result['operationId'],op)
        self.assertEqual(self.client.owner_write('agent-1','report_release_result',p,operation_id=op,
                                  assertion_source='OWNER_TRANSCRIBED'),result)
        self.assertEqual(self.client.read('agent-1','get_operation',{**query,'operationId':op})['data']['receipt'],result)
        self.assertEqual(self.client.maintenance_snapshot(),self.domain.maintenance_snapshot())
        self.assertEqual(self.client.profile_digest(),self.domain.snapshot()['profileDigest'])

    def test_profile_source_checkpoint_is_internal_and_uses_one_replay(self):
        from unittest.mock import patch

        self.domain.register_source(self.merge())
        view = self.domain.snapshot()
        self.assertNotIn('sourceCheckpoint', self.client.profile())
        with patch.object(self.domain, 'snapshot', wraps=self.domain.snapshot) as snapshot:
            profile = self.client.profile(source_checkpoint=True)
        snapshot.assert_called_once_with()
        self.assertEqual(profile, {
            'profileDigest': view['profileDigest'],
            'sourceRevision': view['sourceRevision'],
            'sourceCheckpoint': {
                'sourceCursor': view['sourceCursor'],
                'snapshotRevision': view['snapshotRevision'],
                'eventDigest': view['eventDigest'],
                'registryDigest': sc.digest(self.domain.maintenance_snapshot()),
            },
        })
        req = self.request('PROFILE', {'sourceCheckpoint': True})
        with self.assertRaisesRegex(Denied, 'SEMANTIC_WIRE_INTERNAL_ONLY'):
            self.frames.dispatch(wire.seal(self.frames.key, req))
        for body in ({'sourceCheckpoint': False}, {'sourceCheckpoint': 1},
                     {'sourceCheckpoint': True, 'extra': True}):
            with self.subTest(body=body), self.assertRaises(Denied):
                self.request('PROFILE', body, actor='internal')

    def test_frozen_delivery_accepts_accounted_cursor_ahead_of_desired(self):
        from types import SimpleNamespace
        from unittest.mock import patch
        from fortis_approvals.extensions.successor_runtime import ProtectedRegistrySuccessor

        deployment = self.merge()
        self.domain.register_source(deployment)
        desired_source = deployment['observation']['mergeSha']
        metadata_only = self.merge(number=289, targets=[])
        self.domain.register_source(metadata_only)
        self.assertEqual(self.component()['desired']['source']['sourceSha'], desired_source)
        profile = self.client.profile(source_checkpoint=True)
        checkpoint = profile['sourceCheckpoint']
        self.assertEqual(checkpoint['sourceCursor'], metadata_only['observation']['mergeSha'])
        self.assertNotEqual(checkpoint['sourceCursor'], desired_source)
        pin = 'b'*64
        handoff = {'registryDigest': checkpoint['registryDigest']}
        successor = object.__new__(ProtectedRegistrySuccessor)
        successor._raw = sc.canonical({
            'interlockDigest': pin, 'companionDigest': 'c'*64, 'frozenHandoff': handoff,
        })
        reader = SimpleNamespace(
            _successor_config=successor, _semantic_transport=self.client,
            _semantic_profile_digest=profile['profileDigest'],
        )
        # Isolate the check after startup admission and the evidence mount
        # check. The peer frame and journal replay are exercised as normal.
        gate = SimpleNamespace(verify_startup=lambda _: None)
        with patch.object(successor, '_maintenance_gate', return_value=gate), \
             patch.object(successor, '_delivery', return_value={'interlockDigest': pin}):
            receipt = successor.checked_delivery(reader, expected_interlock_digest=pin)
            self.assertEqual(receipt['registryCheckpoint'], {
                **checkpoint, 'sourceRevision': profile['sourceRevision'],
                'profileDigest': profile['profileDigest'],
            })
            reader._semantic_profile_digest = 'f'*64
            with self.assertRaisesRegex(Denied, 'R7_REGISTRY_SUCCESSOR_CHECKPOINT_CHANGED'):
                successor.checked_delivery(reader, expected_interlock_digest=pin)
            reader._semantic_profile_digest = profile['profileDigest']
            self.domain.owner_event('report_release_result', self.report(),
                actor='agent-1', assertion_source='OWNER_TRANSCRIBED',
                operation_id=uid(), recorded_at=100)
            with self.assertRaisesRegex(Denied, 'R7_REGISTRY_SUCCESSOR_CHECKPOINT_CHANGED'):
                successor.checked_delivery(reader, expected_interlock_digest=pin)

    def test_lost_reply_original_receipt_without_repeat(self):
        op=uid();p=self.report();calls=[]
        def lost(frame,**kw):
            calls.append(frame)
            self.exchange(frame,**kw)
            raise Denied('TEST_LOST_RESPONSE')
        self.client._exchange=lost
        with self.assertRaises(Denied):
            self.client.owner_write('agent-1','report_release_result',p,operation_id=op,
                                    assertion_source='OWNER_TRANSCRIBED')
        self.assertEqual(len(calls),1)
        self.client._exchange=self.exchange
        receipt=self.client.read('agent-1','get_operation',
              {'subject':self.subjects[0],'operationId':op})['data']['receipt']
        self.assertEqual(receipt['operationId'],op)

    def test_bad_mac_generation_and_provenance_no_write(self):
        req=self.request('WRITE',{'operation':'report_release_result','params':self.report(),
            'operationId':uid(),'assertionSource':'OWNER_TRANSCRIBED','parentRequestId':None})
        frame=wire.seal(b'f'*32,req)
        changed=copy.deepcopy(frame);changed['request']['body']['assertionSource']='OWNER_DIRECT'
        with self.assertRaises(Denied):self.frames.dispatch(changed)
        changed=copy.deepcopy(req);changed['generation']='b'*64
        with self.assertRaises(Denied):self.frames.dispatch(wire.seal(b'f'*32,changed))
        changed=copy.deepcopy(req);changed['body']['assertionSource']='OWNER_DIRECT'
        with self.assertRaises(Denied):self.frames.dispatch(wire.seal(b'f'*32,changed))
        self.assertIsNone(self.component()['ownerReported'])

    def test_unscoped_internal_read_and_response_replay_denied(self):
        req=self.request('HOLD_SNAPSHOT',{})
        with self.assertRaises(Denied):self.frames.dispatch(wire.seal(b'f'*32,req))
        req=self.request('PROFILE',{},actor='internal')
        response=self.frames.dispatch(wire.seal(b'f'*32,req))
        other={**req,'requestId':uid()}
        with self.assertRaises(Denied):wire.open_reply(b'f'*32,other,response)
        self.allowed=False
        with self.assertRaises(Denied):self.client.profile_digest()

    def test_same_peer_and_frame_key_refused(self):
        with self.assertRaises(Denied):
            GatewayRegistrySemanticTransport(self.peer,frame_key=b'p'*32,generation='a'*64,
                                               internal_actor='internal')


class OwnerSemanticStartupTests(fixture.LineageFixture,unittest.TestCase):
    def test_normal_registry_command_loads_the_mounted_admitted_read_profile(self):
        from pathlib import Path
        from tempfile import TemporaryDirectory
        from unittest.mock import patch
        from fortis_approvals.registry import local_candidate_read_service as entrypoint

        self.domain.register_source(self.transition())
        merge=self.merge()
        self.domain.register_source(merge)
        before=self.store.path.read_bytes()
        runtime=TemporaryDirectory()
        self.addCleanup(runtime.cleanup)
        config,path=owner_read_configuration(self,Path(runtime.name),operation='get_component')
        with self.assertRaisesRegex(Denied,'REGISTRY_PRIVATE_READ_CONFIG_INVALID'):
            entrypoint._load_owner_config(str(path))
        with self.assertRaisesRegex(Denied,'REGISTRY_PLANNER_OWNER_CONFIG_REQUIRED'):
            entrypoint.main(['--owner-config',str(path)])
        with patch.object(entrypoint,'_readonly_owner_runtime',return_value=path.parent):
            with self.assertRaisesRegex(Denied,'REGISTRY_SEMANTIC_READONLY_STATE_REQUIRED'):
                entrypoint.main(['--owner-config',str(path)])
        frames=read_service_via_entrypoint(path).frames

        def private(actor,action,body):
            req=wire.request({'schemaVersion':2,'requestId':uid(),'instanceId':self.instance,
                'scopeDigest':self.witness['scopeDigest'],'generation':'a'*64,
                'actor':actor,'action':action,'body':body},**frames.pins)
            return wire.open_reply(frames.key,req,frames.dispatch(wire.seal(frames.key,req)))

        query={'operation':'get_component','params':{'subject':self.subjects[0]}}
        owner=private('owner-actor','READ',query)
        self.assertEqual(owner,private('agent-1','READ',query))
        self.assertEqual(owner['data']['desired']['source']['sourceSha'],merge['observation']['mergeSha'])
        self.assertEqual(private('internal','PROFILE',{})['profileDigest'],sc.digest(self.successor))
        with self.assertRaisesRegex(Denied,'REGISTRY_SEMANTIC_SCOPE_DENIED'):
            private('agent-1','READ',{**query,'params':{'subject':self.subjects[1]}})
        with self.assertRaisesRegex(Denied,'SEMANTIC_WIRE_SCOPE_DENIED'):
            private('internal','READ',query)
        with self.assertRaisesRegex(Denied,'SEMANTIC_WIRE_SCOPE_DENIED'):
            private('owner-actor','WRITE',{'operation':'begin_release','params':self.params(),
                'operationId':uid(),'assertionSource':'OWNER_DIRECT','parentRequestId':None})
        config['semantic']['frameKeyDigest']='0'*64
        path.write_bytes(sc.canonical(config).encode())
        with self.assertRaisesRegex(Denied,'REGISTRY_PLANNER_KEY_DENIED'):
            read_service_via_entrypoint(path)
        self.assertEqual(self.store.path.read_bytes(),before)

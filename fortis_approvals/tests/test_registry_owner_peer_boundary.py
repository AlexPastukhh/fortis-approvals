"""Source-only closed UDS owner peer policy; never grants actual checkpoint CAS."""
import copy
import os
from pathlib import Path
import socket
import stat
import tempfile
import unittest
import uuid

from fortis_approvals.core import Denied, canonical
from fortis_approvals.registry import owner_peer_boundary as p


class OwnerPeerBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.folder=Path(self.tmp.name)/'owner-socket'
        self.folder.mkdir(mode=0o710)
        self.folder.chmod(0o710)
        self.path=self.folder/'checkpoint.sock'
        self.profile={'schemaVersion':1,
                      'transport':'linux-af-unix-stream-so-peercred-v1',
                      'socketPath':str(self.path),
                      'instanceId':str(uuid.uuid4()),
                      'scopeDigest':'a'*64,'enrollmentReceiptDigest':'b'*64,
                      'authorityUid':os.geteuid(),'authorityGid':os.getegid(),
                      'socketGid':os.getegid(),
                      'registryUid':os.geteuid()+1,'registryGid':os.getegid()+1,
                      'operatorUid':os.geteuid()+2,'operatorGid':os.getegid()+2}
        self.pin=p._hash(self.profile)
        self.listener=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
        self.addCleanup(self.listener.close)
        self.listener.bind(str(self.path))
        self.path.chmod(0o660)
        self.listener.listen(4)

    def read(self):return copy.deepcopy(self.profile)

    def get(self):
        return {'schemaVersion':1,'operation':'checkpoint.get',
                'instanceId':self.profile['instanceId'],
                'scopeDigest':self.profile['scopeDigest'],
                'requestId':str(uuid.uuid4())}

    def original(self):
        return {**self.get(),'operation':'checkpoint.original',
                'operationId':str(uuid.uuid4())}

    def classification(self,request=None,*,role='registry',pid=1234):
        if request is None:request=self.get()
        if role=='registry':uid=self.profile['registryUid'];gid=self.profile['registryGid']
        elif role=='operator':uid=self.profile['operatorUid'];gid=self.profile['operatorGid']
        elif role=='authority':uid=self.profile['authorityUid'];gid=self.profile['authorityGid']
        else:raise ValueError('bad test role')
        return p._classify(self.profile,pid=pid,uid=uid,gid=gid,request=request)

    def observe(self,raw=None,*,conn=None,expected_profile_digest=None):
        if raw is None:raw=canonical(self.get()).encode()+b'\n'
        client=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
        try:
            client.connect(str(self.path))
            accepted,_=self.listener.accept()
            try:
                client.sendall(raw)
                client.shutdown(socket.SHUT_WR)
                return p.observe_accepted_peer(connection=accepted,profile_reader=self.read,
                    expected_profile_digest=expected_profile_digest or self.pin)
            finally:accepted.close()
        finally:client.close()

    def test_live_kernel_peercred_denies_same_uid_as_owner_service(self):
        with self.assertRaisesRegex(Denied,'REGISTRY_PEER_UNAUTHORIZED'):
            self.observe()
        self.assertEqual(stat.S_IMODE(self.path.stat().st_mode),0o660)

    def test_synthetic_registry_read_only_capability(self):
        result=self.classification()
        self.assertEqual(result['role'],'registry-reader')
        self.assertEqual(result['operation'],'checkpoint.get')
        self.assertFalse(result['protectedAuthorityVerified'])
        self.assertFalse(result['dispatchAllowed'])
        self.assertFalse(result['admissionAllowed'])
        with self.assertRaisesRegex(Denied,'REGISTRY_PEER_ROLE_DENIED'):
            self.classification(self.original())

    def test_synthetic_operator_eligibility_no_advance(self):
        request=self.original()
        result=self.classification(request,role='operator')
        self.assertEqual(result['role'],'owner-operator')
        self.assertEqual(result['operationId'],request['operationId'])
        self.assertFalse(result['ownerAcceptanceVerified'])
        self.assertFalse(result['dispatchAllowed'])
        with self.assertRaisesRegex(Denied,'REGISTRY_PEER_OPERATION_CLOSED'):
            self.classification({**self.original(),'operation':'checkpoint.advance'},role='operator')

    def test_unknown_actor_spoofed_uid_extra_fields_rejected(self):
        for key,value in (('actor','owner-operator'),('uid',self.profile['operatorUid']),
                          ('grant','admin'),('admissionAllowed',True),
                          ('path','/tmp/forged.sqlite')):
            with self.subTest(key=key),self.assertRaisesRegex(Denied,'REGISTRY_PEER_REQUEST_INVALID'):
                self.classification({**self.get(),key:value})
        with self.assertRaisesRegex(Denied,'REGISTRY_PEER_UNAUTHORIZED'):
            self.classification(role='authority')
        with self.assertRaisesRegex(Denied,'REGISTRY_PEER_CREDENTIAL_INVALID'):
            p._classify(self.profile,pid=0,uid=1,gid=1,request=self.get())

    def test_profile_requires_pinned_distinct_nonroot_identities(self):
        self.assertEqual(p._profile(self.profile,self.pin),self.profile)
        for key,value in (('registryUid',self.profile['authorityUid']),
                          ('operatorUid',self.profile['registryUid']),
                          ('authorityUid',0),('registryGid',0),
                          ('schemaVersion',True),
                          ('transport','tcp'),
                          ('scopeDigest','f'*64)):
            modified={**self.profile,key:value}
            with self.subTest(key=key),self.assertRaises(Denied):
                p._profile(modified,self.pin)
        with self.assertRaisesRegex(Denied,'REGISTRY_PEER_PROFILE_INVALID'):
            p._profile(self.profile,'f'*64)

    def test_wrong_instance_scope_and_operation_id(self):
        for key,value in (('instanceId',str(uuid.uuid4())),
                          ('scopeDigest','c'*64),
                          ('requestId','not-uuid'),
                          ('schemaVersion',True)):
            with self.subTest(key=key),self.assertRaisesRegex(Denied,'REGISTRY_PEER_REQUEST_INVALID'):
                self.classification({**self.get(),key:value})
        with self.assertRaisesRegex(Denied,'REGISTRY_PEER_REQUEST_INVALID'):
            self.classification({**self.original(),'operationId':'not-uuid'},role='operator')

    def test_socket_permissions_symlink_and_parent_permissions(self):
        self.assertTrue(p._endpoint(self.profile))
        self.path.chmod(0o666)
        with self.assertRaisesRegex(Denied,'REGISTRY_PEER_SOCKET_PERMISSIONS'):self.observe()
        self.path.chmod(0o660)
        self.folder.chmod(0o777)
        with self.assertRaisesRegex(Denied,'REGISTRY_PEER_SOCKET_PERMISSIONS'):self.observe()
        self.folder.chmod(0o710)

    def test_missing_socket_and_nonunix_transport_denied(self):
        self.listener.close()
        self.path.unlink()
        with self.assertRaisesRegex(Denied,'REGISTRY_PEER_SOCKET_UNAVAILABLE'):
            p._endpoint(self.profile)
        a,b=socket.socketpair()
        try:
            with self.assertRaisesRegex(Denied,'REGISTRY_PEER_WRONG_SOCKET'):
                p.observe_accepted_peer(connection=a,profile_reader=self.read,
                                        expected_profile_digest=self.pin)
        finally:a.close();b.close()
        tcp=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        try:
            with self.assertRaisesRegex(Denied,'REGISTRY_PEER_UNIX_REQUIRED'):
                p.observe_accepted_peer(connection=tcp,profile_reader=self.read,
                                        expected_profile_digest=self.pin)
        finally:tcp.close()

    def test_payload_canonical_and_bounded_framing(self):
        for data in (b'{"x":1,"x":2}\n',b'{}\n{}\n',b'{} \n',
                     b'{"schemaVersion":1}\nextra',b' '*4097+b'\n',
                     b'\xff\n',b'{}'):
            with self.subTest(raw=data[:25]),self.assertRaises(Denied):
                self.observe(data)
        self.assertRaises(Denied,self.observe,b'')

    def test_noncanonical_profile_and_socket_path_rejected(self):
        bad={**self.profile,'socketPath':'checkpoint.sock'}
        with self.assertRaises(Denied):p._profile(bad,p._hash(bad))
        bad={**self.profile,'socketPath':'/x'*80}
        with self.assertRaises(Denied):p._profile(bad,p._hash(bad))
        self.folder.chmod(0o710)

    def test_socket_ownership_and_profile_change_rejected(self):
        self.profile['registryUid']+=1
        with self.assertRaisesRegex(Denied,'REGISTRY_PEER_PROFILE_INVALID'):
            self.observe()
        self.profile['registryUid']-=1
        self.path.chmod(0o600)
        with self.assertRaisesRegex(Denied,'REGISTRY_PEER_SOCKET_PERMISSIONS'):
            self.observe()

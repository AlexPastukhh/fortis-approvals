"""Source-only Linux AF_UNIX checkpoint READ client, no runtime/owner GO.

The positive end-to-end fixture must PATCH its registry EUID/GID because
both ends run under one test user. That is NOT evidence of host isolation.
"""
import copy
import os
import socket
import threading
import unittest
import uuid
from unittest.mock import patch

from fortis_approvals.core import Denied, canonical
from fortis_approvals.registry import owner_peer_boundary as p
from fortis_approvals.tests import test_registry_owner_peer_boundary as peer_fixture


class CheckpointReadTransportTests(unittest.TestCase):
    setUp = peer_fixture.OwnerPeerBoundaryTests.setUp
    read = peer_fixture.OwnerPeerBoundaryTests.read

    def checkpoint(self):
        return {'schemaVersion':1,
                'instanceId':self.profile['instanceId'],
                'scopeDigest':self.profile['scopeDigest'],
                'revision':0,'eventDigest':'e'*64}

    def envelope(self,request):
        return {'schemaVersion':1,
                'result':'OWNER_CHECKPOINT_READ_CANDIDATE',
                'requestId':request['requestId'],
                'operation':'checkpoint.get',
                'instanceId':self.profile['instanceId'],
                'scopeDigest':self.profile['scopeDigest'],
                'data':self.checkpoint(),
                'protectedAuthorityVerified':False,
                'ownerAcceptanceVerified':False,
                'dispatchAllowed':False,
                'admissionAllowed':False}

    def exchange(self,responder=None,*,fake_registry_identity=True):
        errors=[]
        requests=[]
        def serve():
            try:
                conn,_=self.listener.accept()
                with conn:
                    conn.settimeout(2)
                    req=p._one_frame(conn)
                    requests.append(req)
                    response=(responder(req) if responder is not None else
                              self.envelope(req))
                    if type(response) is bytes:
                        raw=response
                    else:
                        raw=canonical(response).encode('utf-8')+b'\n'
                    conn.sendall(raw)
                    conn.shutdown(socket.SHUT_WR)
            except Exception as exc:
                errors.append(exc)
        t=threading.Thread(target=serve,daemon=True)
        t.start()
        try:
            if fake_registry_identity:
                with patch.object(p.os,'geteuid',return_value=self.profile['registryUid']), \
                     patch.object(p.os,'getegid',return_value=self.profile['registryGid']):
                    result=p.read_pinned_checkpoint(profile_reader=self.read,
                                                   expected_profile_digest=self.pin)
            else:
                result=p.read_pinned_checkpoint(profile_reader=self.read,
                                               expected_profile_digest=self.pin)
            return result,requests
        finally:
            t.join(3)
            self.assertFalse(t.is_alive(),'test fixture listener blocked')
            self.assertEqual(errors,[])

    def test_one_shot_checkpoint_read_binds_kernel_peer_and_scope(self):
        response,requests=self.exchange()
        self.assertEqual(len(requests),1)
        self.assertEqual(set(requests[0]),{'schemaVersion','operation','instanceId',
                                           'scopeDigest','requestId'})
        self.assertEqual(requests[0]['operation'],'checkpoint.get')
        self.assertEqual(requests[0]['instanceId'],self.profile['instanceId'])
        self.assertEqual(requests[0]['scopeDigest'],self.profile['scopeDigest'])
        self.assertEqual(str(uuid.UUID(requests[0]['requestId'])),requests[0]['requestId'])
        self.assertEqual(response['data'],self.checkpoint())
        for f in ('protectedAuthorityVerified','ownerAcceptanceVerified',
                  'dispatchAllowed','admissionAllowed'):
            self.assertIs(response[f],False)

    def test_fake_euid_seam_is_not_live_host_principal_proof(self):
        # The real client is owned by this same-UID test process, not the
        # separately pinned registry identity. It MUST be denied on host.
        with self.assertRaisesRegex(Denied,'REGISTRY_OWNER_CLIENT_READER_IDENTITY_DENIED'):
            p.read_pinned_checkpoint(profile_reader=self.read,
                                     expected_profile_digest=self.pin)

    def test_wrong_pinned_profile_or_missing_profile_is_denied(self):
        with self.assertRaisesRegex(Denied,'REGISTRY_PEER_PROFILE_INVALID'):
            p.read_pinned_checkpoint(profile_reader=self.read,
                                     expected_profile_digest='f'*64)
        with self.assertRaisesRegex(Denied,'REGISTRY_OWNER_CLIENT_PROFILE_REQUIRED'):
            p.read_pinned_checkpoint(profile_reader=None,
                                     expected_profile_digest=self.pin)
        profile=copy.deepcopy(self.profile)
        profile['instanceId']=str(uuid.uuid4())
        with self.assertRaisesRegex(Denied,'REGISTRY_PEER_PROFILE_INVALID'):
            p.read_pinned_checkpoint(profile_reader=lambda:profile,
                                     expected_profile_digest=self.pin)

    def test_real_kernel_uid_mismatch_is_rejected(self):
        client=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
        try:
            client.connect(str(self.path))
            server,_=self.listener.accept()
            try:
                self.assertEqual(
                    p._server_peer_credentials(client,self.profile)[1:],
                    (os.geteuid(),os.getegid()))
                forged={**self.profile,'authorityUid':self.profile['operatorUid']}
                with self.assertRaisesRegex(Denied,'REGISTRY_OWNER_CLIENT_SERVER_IDENTITY_DENIED'):
                    p._server_peer_credentials(client,forged)
            finally:
                server.close()
        finally:
            client.close()

    def test_fake_approved_response_and_extra_actor_are_rejected(self):
        changes=(
            {'admissionAllowed':True},
            {'protectedAuthorityVerified':True},
            {'ownerAcceptanceVerified':True},
            {'dispatchAllowed':True},
            {'operation':'checkpoint.advance'},
            {'operation':'checkpoint.original'},
            {'result':'EXECUTED'},
            {'requestId':str(uuid.uuid4())},
            {'instanceId':str(uuid.uuid4())},
            {'scopeDigest':'f'*64},
            {'schemaVersion':True},
            {'role':'owner'},
            {'path':'/tmp/owner.sqlite'},
        )
        for changeset in changes:
            with self.subTest(changeset=changeset):
                with self.assertRaisesRegex(Denied,'REGISTRY_OWNER_CLIENT_RESPONSE_INVALID'):
                    self.exchange(lambda req:{**self.envelope(req),**changeset})

    def test_malformed_checkpoint_and_changed_revision_are_rejected(self):
        changes=(
            {'revision':True},
            {'revision':-1},
            {'revision':65},
            {'eventDigest':'F'*64},
            {'eventDigest':'f'*63},
            {'instanceId':str(uuid.uuid4())},
            {'scopeDigest':'f'*64},
            {'schemaVersion':False},
            {'ownerAccepted':True},
        )
        for value in changes:
            with self.subTest(value=value):
                def reply(req):
                    result=self.envelope(req)
                    result['data']={**result['data'],**value}
                    return result
                with self.assertRaisesRegex(Denied,'REGISTRY_OWNER_CLIENT_CHECKPOINT_INVALID'):
                    self.exchange(reply)

    def test_noncanonical_duplicate_and_oversized_responses_are_rejected(self):
        raws=(
            b'{"schemaVersion":1,"schemaVersion":1}\n',
            b'{"schemaVersion":1}\n{"second":true}\n',
            b'not-json\n',
            b'\xff\n',
            b'{}'+b' '*8300+b'\n',
            b'{}',
            b'\n',
        )
        for raw in raws:
            with self.subTest(raw=raw[:48]),self.assertRaises(Denied):
                self.exchange(lambda _:raw)

    def test_profile_and_socket_mutation_after_reply_are_denied(self):
        def mutate_socket(req):
            self.path.chmod(0o666)
            return self.envelope(req)
        try:
            with self.assertRaisesRegex(Denied,'REGISTRY_PEER_SOCKET_PERMISSIONS'):
                self.exchange(mutate_socket)
        finally:
            self.path.chmod(0o660)

    def test_no_advance_or_owner_original_is_sent(self):
        result,requests=self.exchange()
        self.assertEqual(requests[0]['operation'],'checkpoint.get')
        self.assertNotIn('operationId',requests[0])
        self.assertNotIn('actor',requests[0])
        self.assertNotIn('token',requests[0])
        self.assertNotIn('path',requests[0])
        self.assertNotIn('verified',result)
        self.assertFalse(result['admissionAllowed'])

    def test_pinned_socket_perms_not_optional(self):
        self.path.chmod(0o666)
        with patch.object(p.os,'geteuid',return_value=self.profile['registryUid']), \
             patch.object(p.os,'getegid',return_value=self.profile['registryGid']):
            with self.assertRaisesRegex(Denied,'REGISTRY_PEER_SOCKET_PERMISSIONS'):
                p.read_pinned_checkpoint(profile_reader=self.read,
                                         expected_profile_digest=self.pin)


if __name__=='__main__':
    unittest.main()

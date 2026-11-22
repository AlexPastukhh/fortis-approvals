"""P5 source-only accepted Unix checkpoint.get responder.

Positive tests synthetically change the classified peer UID (never the real
SO_PEERCRED bytes); this same-UID fixture is NOT protected host acceptance.
"""
import copy
import os
import socket
import threading
import unittest
import uuid
from unittest.mock import patch

from fortis_approvals.core import Denied, canonical
from fortis_approvals.registry import owner_peer_boundary as peer
from fortis_approvals.tests import test_registry_owner_read_boundary as fixture


class CheckpointReadResponderTests(unittest.TestCase):
    setUp=fixture.OwnerReadBoundaryTests.setUp
    witness=fixture.OwnerReadBoundaryTests.witness
    read=fixture.OwnerReadBoundaryTests.read
    args=fixture.OwnerReadBoundaryTests.args
    prepare_suffix=fixture.OwnerReadBoundaryTests.prepare_suffix
    read_profile=fixture.OwnerReadBoundaryTests.read_profile
    request=fixture.OwnerReadBoundaryTests.request

    def synthetic_peer(self,profile,*,pid,uid,gid,request,role='registry'):
        # Real SO_PEERCRED is still read by observe_accepted_peer. Only the
        # classification seam is synthetic, NOT a cross-UID host test.
        self.assertEqual((uid,gid),(os.geteuid(),os.getegid()))
        if role=='registry':
            fake=(profile['registryUid'],profile['registryGid'])
        else:
            fake=(profile['operatorUid'],profile['operatorGid'])
        return self.actual_classify(profile,pid=pid,uid=fake[0],
                                    gid=fake[1],request=request)

    def serve_once(self,*,request=None,raw=None,role=None):
        error=[]
        def worker():
            try:
                self.listener.settimeout(2)
                connection,_=self.listener.accept()
                with connection:
                    if role is not None:
                        with patch.object(peer,'_classify',
                            side_effect=lambda prof,*,pid,uid,gid,request:
                                self.synthetic_peer(prof,pid=pid,uid=uid,
                                                    gid=gid,request=request,
                                                    role=role)):
                            peer.respond_accepted_checkpoint_get(
                                connection=connection,profile_reader=self.read_profile,
                                expected_profile_digest=self.pin,ledger=self.authority)
                    else:
                        peer.respond_accepted_checkpoint_get(
                            connection=connection,profile_reader=self.read_profile,
                            expected_profile_digest=self.pin,ledger=self.authority)
            except Exception as e:
                error.append(e)
        self.actual_classify=peer._classify
        t=threading.Thread(target=worker,daemon=True)
        t.start()
        received=bytearray()
        try:
            with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as client:
                client.settimeout(3)
                client.connect(str(self.path))
                wire=raw if raw is not None else canonical(
                    request or self.request()).encode('utf-8')+b'\n'
                client.sendall(wire)
                client.shutdown(socket.SHUT_WR)
                while True:
                    data=client.recv(4096)
                    if not data:break
                    received.extend(data)
                    self.assertLess(len(received),8193)
        finally:
            t.join(4)
            self.assertFalse(t.is_alive(),'accepted-socket fixture leaked thread')
        return bytes(received),error

    def test_real_same_uid_cannot_read_ledger_or_get_network_response(self):
        with patch.object(self.authority,'read_checkpoint',
                          side_effect=AssertionError('ledger must not be read')):
            response,errors=self.serve_once()
        self.assertEqual(response,b'')
        self.assertEqual(len(errors),1)
        self.assertIsInstance(errors[0],Denied)
        self.assertEqual(str(errors[0]),'REGISTRY_PEER_UNAUTHORIZED')

    def test_one_shot_canonical_frame_matches_pinned_client_projection(self):
        wire,errors=self.serve_once(role='registry')
        self.assertEqual(errors,[])
        self.assertTrue(wire.endswith(b'\n'))
        body=peer.loads_strict(wire[:-1])
        self.assertEqual(wire[:-1],canonical(body).encode('utf-8'))
        peer._checkpoint_read_response(body,self.profile,body['requestId'])
        self.assertEqual(body['data'],self.anchor)
        self.assertEqual(body['operation'],'checkpoint.get')
        self.assertIsNone(peer.respond_accepted_checkpoint_get.__defaults__)
        for flag in ('protectedAuthorityVerified','ownerAcceptanceVerified',
                     'dispatchAllowed','admissionAllowed'):
            self.assertIs(body[flag],False)

    def test_pinned_client_to_real_responder_round_trip_source_only(self):
        self.actual_classify=peer._classify
        real_euid=os.geteuid
        real_egid=os.getegid
        caller=threading.current_thread()
        errors=[]
        def server():
            try:
                self.listener.settimeout(2)
                accepted,_=self.listener.accept()
                with accepted:
                    peer.respond_accepted_checkpoint_get(
                        connection=accepted,profile_reader=self.read_profile,
                        expected_profile_digest=self.pin,ledger=self.authority)
            except Exception as e:
                errors.append(e)
        def synthetic(prof,*,pid,uid,gid,request):
            # Simulate *only* remote role classification, not socket identity.
            self.assertEqual((uid,gid),(real_euid(),real_egid()))
            return self.actual_classify(
                prof,pid=pid,uid=prof['registryUid'],
                gid=prof['registryGid'],request=request)
        t=threading.Thread(target=server,daemon=True)
        t.start()
        try:
            with patch.object(peer,'_classify',side_effect=synthetic), \
                 patch.object(peer.os,'geteuid',side_effect=lambda:
                     self.profile['registryUid'] if threading.current_thread() is caller
                     else real_euid()), \
                 patch.object(peer.os,'getegid',side_effect=lambda:
                     self.profile['registryGid'] if threading.current_thread() is caller
                     else real_egid()):
                received=peer.read_pinned_checkpoint(
                    profile_reader=self.read_profile,
                    expected_profile_digest=self.pin)
        finally:
            t.join(4)
            self.assertFalse(t.is_alive())
        self.assertEqual(errors,[])
        self.assertEqual(received['data'],self.anchor)
        self.assertFalse(received['admissionAllowed'])

    def test_operator_original_cannot_be_served_by_this_route(self):
        r=self.request('checkpoint.original',str(uuid.uuid4()))
        with patch.object(self.authority,'original',
                          side_effect=AssertionError('original read forbidden')), \
             patch.object(self.authority,'read_checkpoint',
                          side_effect=AssertionError('ledger read forbidden')):
            response,errors=self.serve_once(request=r,role='operator')
        self.assertEqual(response,b'')
        self.assertEqual(len(errors),1)
        self.assertEqual(str(errors[0]),'REGISTRY_OWNER_GET_ONLY_OPERATION_DENIED')

    def test_advance_and_unknown_requests_have_no_response(self):
        for operation in ('checkpoint.advance','checkpoint.reset','raw.sql'):
            with self.subTest(operation=operation):
                with patch.object(self.authority,'read_checkpoint',
                                  side_effect=AssertionError('ledger touched')):
                    response,errors=self.serve_once(
                        request=self.request(operation),role='operator')
                self.assertEqual(response,b'')
                self.assertEqual(len(errors),1)
                self.assertEqual(str(errors[0]),'REGISTRY_PEER_OPERATION_CLOSED')

    def test_trailing_second_frame_is_rejected_before_ledger_read(self):
        request=canonical(self.request()).encode('utf-8')
        for tail in (b'bad',b'\n',b'{}\n'):
            with self.subTest(tail=tail):
                with patch.object(self.authority,'read_checkpoint',
                                  side_effect=AssertionError('ledger touched')):
                    response,errors=self.serve_once(
                        raw=request+b'\n'+tail,role='registry')
                self.assertEqual(response,b'')
                self.assertEqual(len(errors),1)
                self.assertIsInstance(errors[0],Denied)

    def test_client_without_half_close_is_refused_before_ledger(self):
        errors=[]
        def server():
            try:
                self.listener.settimeout(2)
                accepted,_=self.listener.accept()
                with accepted:
                    peer.respond_accepted_checkpoint_get(
                        connection=accepted,profile_reader=self.read_profile,
                        expected_profile_digest=self.pin,ledger=self.authority)
            except Exception as e:
                errors.append(e)
        t=threading.Thread(target=server,daemon=True)
        t.start()
        try:
            with patch.object(self.authority,'read_checkpoint',
                              side_effect=AssertionError('ledger touched')):
                with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as client:
                    client.settimeout(4)
                    client.connect(str(self.path))
                    client.sendall(canonical(self.request()).encode()+b'\n')
                    # No shutdown(SHUT_WR): a peer may be trying to pipeline.
                    self.assertEqual(client.recv(1),b'')
        finally:
            t.join(4)
            self.assertFalse(t.is_alive())
        self.assertEqual(len(errors),1)
        self.assertIsInstance(errors[0],Denied)
        # Same-UID peer is denied at classification even on valid EOF; without
        # EOF it is rejected before any classification or ledger access.
        self.assertEqual(str(errors[0]),'REGISTRY_PEER_REQUEST_EOF_UNAVAILABLE')

    def test_noncanonical_wrong_scope_and_unknown_fields_denied(self):
        for payload in (
            b'{"requestId":"duplicate","requestId":"duplicate"}\n',
            canonical({**self.request(),'scopeDigest':'f'*64}).encode()+b'\n',
            canonical({**self.request(),'owner':True}).encode()+b'\n',
            canonical({**self.request(),'admissionAllowed':True}).encode()+b'\n',
        ):
            with self.subTest(raw=payload[:50]):
                with patch.object(self.authority,'read_checkpoint',
                                  side_effect=AssertionError('ledger touched')):
                    response,errors=self.serve_once(raw=payload,role='registry')
                self.assertEqual(response,b'')
                self.assertEqual(len(errors),1)
                self.assertIsInstance(errors[0],Denied)

    def test_forged_checkpoint_authority_is_blocked_before_response(self):
        for change in (
            {'revision':True}, {'schemaVersion':True},
            {'eventDigest':'f'*63}, {'operatorApproved':True},
            {'scopeDigest':'f'*64},
        ):
            with self.subTest(change=change),patch.object(
                    self.authority,'read_checkpoint',return_value={
                        **self.anchor,**change}):
                response,errors=self.serve_once(role='registry')
                self.assertEqual(response,b'')
                self.assertEqual(len(errors),1)
                self.assertEqual(str(errors[0]),'REGISTRY_OWNER_CLIENT_CHECKPOINT_INVALID')

    def test_socket_mutation_during_ledger_read_sends_nothing(self):
        def changed():
            self.path.chmod(0o666)
            return copy.deepcopy(self.anchor)
        with patch.object(self.authority,'read_checkpoint',side_effect=changed):
            response,errors=self.serve_once(role='registry')
        self.assertEqual(response,b'')
        self.assertEqual(len(errors),1)
        self.assertIsInstance(errors[0],Denied)
        self.path.chmod(0o660)

    def test_not_a_listener_or_a_checkpoint_writer(self):
        self.assertFalse(hasattr(peer,'start_checkpoint_service'))
        self.assertFalse(hasattr(peer,'serve_forever'))
        self.assertEqual(peer.respond_accepted_checkpoint_get.__name__,
                         'respond_accepted_checkpoint_get')


if __name__=='__main__':
    unittest.main()

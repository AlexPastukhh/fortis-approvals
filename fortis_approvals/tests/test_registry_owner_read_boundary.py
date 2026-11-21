"""P5 closed owner-checkpoint read adapter tests (no live authority)."""
import copy
from pathlib import Path
import socket
import tempfile
import unittest
import uuid
from unittest.mock import patch

from fortis_approvals.core import Denied, canonical
from fortis_approvals.registry import owner_peer_boundary as peer
from fortis_approvals.registry import owner_read_boundary as read
from fortis_approvals.tests import test_registry_checkpoint_cas as fixture
from fortis_approvals.tests import test_registry_owner_peer_boundary as socket_fixture
from fortis_approvals.tests import test_registry_state_journal_v2 as journal_fixture


class OwnerReadBoundaryTests(unittest.TestCase):
    witness=journal_fixture.RegistryStateV2Tests.witness
    read=journal_fixture.RegistryStateV2Tests.read
    args=journal_fixture.RegistryStateV2Tests.args
    prepare_suffix=journal_fixture.RegistryStateV2Tests.prepare_suffix

    def setUp(self):
        journal_fixture.RegistryStateV2Tests.setUp(self)
        fixture.CheckpointCASTests.setup_anchor(self)
        socket_fixture.OwnerPeerBoundaryTests.setUp(self)
        self.profile['instanceId']=self.instance
        self.profile['scopeDigest']=peer._hash(self.scope)
        self.profile['enrollmentReceiptDigest']=self.enrollment
        self.pin=peer._hash(self.profile)

    def read_profile(self):
        return copy.deepcopy(self.profile)

    def request(self,operation='checkpoint.get',operation_id=None):
        r={'schemaVersion':1,'operation':operation,
           'instanceId':self.instance,'scopeDigest':peer._hash(self.scope),
           'requestId':str(uuid.uuid4())}
        if operation_id is not None:r['operationId']=operation_id
        return r

    def actual(self,request=None):
        client=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
        try:
            client.connect(str(self.path))
            accepted,_=self.listener.accept()
            try:
                client.sendall(canonical(request or self.request()).encode()+b'\n')
                client.shutdown(socket.SHUT_WR)
                return read.read_accepted_checkpoint(
                    connection=accepted,profile_reader=self.read_profile,
                    expected_profile_digest=self.pin,ledger=self.authority)
            finally:accepted.close()
        finally:client.close()

    def synthetic_observation(self,operation='checkpoint.get',operation_id=None,
                              role='registry-reader'):
        r=self.request(operation,operation_id)
        return {'result':'OWNER_PEER_BOUNDARY_CANDIDATE',
                'role':role,'operation':operation,
                'requestId':r['requestId'],
                'instanceId':self.instance,
                'scopeDigest':peer._hash(self.scope),
                'dispatchAllowed':False,
                'ownerAcceptanceVerified':False,
                'protectedAuthorityVerified':False,
                **({'operationId':operation_id} if operation_id else {})}

    def candidate_read(self,observation):
        with patch.object(read,'observe_accepted_peer',return_value=observation):
            return read.read_accepted_checkpoint(
                connection=None,profile_reader=self.read_profile,
                expected_profile_digest=self.pin,ledger=self.authority)

    def test_real_kernel_same_uid_denied_before_ledger_access(self):
        # Test host is intentionally same-UID. A real positive authorization
        # demands separately provisioned principals and independent owner GO.
        with patch.object(self.authority,'read_checkpoint',
                          side_effect=AssertionError('ledger was read')):
            with self.assertRaisesRegex(Denied,'REGISTRY_PEER_UNAUTHORIZED'):
                self.actual()

    def test_fixed_checkpoint_get_projection_is_not_accepted_authority(self):
        observation=self.synthetic_observation()
        result=self.candidate_read(observation)  # synthetic authorization seam
        self.assertEqual(result['data'],self.anchor)
        self.assertEqual(result['requestId'],observation['requestId'])
        for name in ('protectedAuthorityVerified','ownerAcceptanceVerified',
                     'dispatchAllowed','admissionAllowed'):
            self.assertIs(result[name],False)

    def test_original_operation_read_binds_exact_uuid(self):
        missing=str(uuid.uuid4())
        absent=self.candidate_read(self.synthetic_observation(
            'checkpoint.original',missing,'owner-operator'))
        self.assertEqual(absent['data'],{'result':'CHECKPOINT_OPERATION_NOT_FOUND'})
        args,pending=fixture.CheckpointCASTests.candidate(self)
        prior=self.authority.advance(operation_id=args['operation_id'],
                                    previous_checkpoint=pending['previousCheckpoint'],
                                    next_checkpoint=pending['pendingCheckpoint'],
                                    pending_reader=self.state.operation)
        result=self.candidate_read(self.synthetic_observation(
            'checkpoint.original',args['operation_id'],'owner-operator'))
        self.assertEqual(result['data'],prior)
        self.assertEqual(result['operationId'],args['operation_id'])
        self.assertFalse(result['admissionAllowed'])

    def test_registry_reader_cannot_read_original(self):
        with self.assertRaisesRegex(Denied,'REGISTRY_OWNER_READ_ROLE_DENIED'):
            self.candidate_read(self.synthetic_observation(
                'checkpoint.original',str(uuid.uuid4()),'registry-reader'))

    def test_advance_and_unknown_operation_are_closed_even_with_owner_claim(self):
        for op in ('checkpoint.advance','checkpoint.reset','raw.sql'):
            with self.subTest(operation=op),self.assertRaisesRegex(
                    Denied,'REGISTRY_OWNER_READ_OPERATION_CLOSED'):
                self.candidate_read(self.synthetic_observation(op,role='owner-operator'))
        with self.assertRaisesRegex(Denied,'REGISTRY_PEER_OPERATION_CLOSED'):
            self.actual(self.request('checkpoint.advance'))

    def test_pinned_scope_enrollment_instance_and_profile_must_match(self):
        for key,value in (('instanceId',str(uuid.uuid4())),
                          ('scopeDigest','e'*64),
                          ('enrollmentReceiptDigest','f'*64)):
            with self.subTest(key=key):
                original=self.profile[key]
                self.profile[key]=value
                self.pin=peer._hash(self.profile)
                with self.assertRaisesRegex(Denied,'REGISTRY_OWNER_READ_LEDGER_BINDING'):
                    self.candidate_read(self.synthetic_observation())
                self.profile[key]=original
                self.pin=peer._hash(self.profile)
        with self.assertRaisesRegex(Denied,'REGISTRY_PEER_PROFILE_INVALID'):
            read.read_accepted_checkpoint(
                connection=None,profile_reader=self.read_profile,
                expected_profile_digest='f'*64,ledger=self.authority)

    def test_rejects_observation_claiming_authority_or_dispatch(self):
        for k in ('dispatchAllowed','protectedAuthorityVerified',
                  'ownerAcceptanceVerified'):
            bad={**self.synthetic_observation(),k:True}
            with self.subTest(key=k),self.assertRaisesRegex(
                    Denied,'REGISTRY_OWNER_READ_PEER_INVALID'):
                self.candidate_read(bad)

    def test_rejects_missing_ledger_and_changed_socket_after_read(self):
        with self.assertRaisesRegex(Denied,'REGISTRY_OWNER_READ_LEDGER_REQUIRED'):
            read.read_accepted_checkpoint(
                connection=None,profile_reader=self.read_profile,
                expected_profile_digest=self.pin,ledger=object())
        with patch.object(read,'observe_accepted_peer',
                          return_value=self.synthetic_observation()):
            with patch.object(self.authority,'read_checkpoint',
                              side_effect=lambda: (self.path.chmod(0o666),self.anchor)[1]):
                with self.assertRaisesRegex(Denied,'REGISTRY_PEER_SOCKET_PERMISSIONS'):
                    read.read_accepted_checkpoint(
                        connection=None,profile_reader=self.read_profile,
                        expected_profile_digest=self.pin,ledger=self.authority)


if __name__=='__main__':unittest.main()

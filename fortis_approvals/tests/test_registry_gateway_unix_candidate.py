"""Real Unix/SQLite -> existing Core/Repo Broker candidate diagnostic path.

Gateway/Core and Registry service run under the SAME UID in this offline
fixture. Separate-UID checks are necessarily mocked for this integration
test and MUST NOT be interpreted as owner host acceptance or a live grant.
"""
import copy
import io
import json
import os
import socket
import tempfile
import threading
import time
import unittest
import uuid
from pathlib import Path
from unittest.mock import patch

from fortis_approvals.core import Authenticator, Core, Denied, canonical
from fortis_approvals.repo_action_contract import RepoIntentBroker
from fortis_approvals.repo_ingress import RepoIngress
from fortis_approvals.integrations.registry import candidate_gateway as gateway
from fortis_approvals.integrations.registry.read_contract import (
    REPOSITORY, validate_gateway_read_projection,
)
from fortis_approvals.registry import functional_v1_journal as local
from fortis_approvals.tests import test_registry_local_candidate_read_service as fixture

ACTOR = 'offline-registry-candidate-reader'
GRANT = 'offline-registry-candidate-test-grant-000001'
READ_OPS = ('candidate_head','candidate_list_desired',
            'candidate_original_operation')


class GatewayUnixCandidateTests(unittest.TestCase):
    setUp = fixture.LocalCandidateReadServiceTests.setUp
    read = fixture.LocalCandidateReadServiceTests.read
    args = fixture.LocalCandidateReadServiceTests.args
    accept = fixture.LocalCandidateReadServiceTests.accept
    suffix = fixture.LocalCandidateReadServiceTests.suffix
    setup_service = fixture.LocalCandidateReadServiceTests.setup_service

    def setup_broker(self):
        self.setup_service()
        self.listener=self.service.bind()
        self.listener.settimeout(0.1)
        self.stop=threading.Event()
        self.failures=[]
        def run():
            while not self.stop.is_set():
                try:
                    conn,_=self.listener.accept()
                except socket.timeout:
                    continue
                except OSError:
                    break
                with conn:
                    try:
                        self.service.handle(conn)
                    except Denied:
                        # Server closes without a success DTO on DENY.
                        pass
                    except Exception as e:
                        self.failures.append(e)
        self.worker=threading.Thread(target=run,daemon=True)
        self.worker.start()
        self.addCleanup(self.cleanup_server)
        row=self.socketpath.lstat()
        uid=os.getuid()
        gid=os.getgid()
        # Exact source socket owner/modes remain REAL. Synthetic future
        # reader UID/registry GID are checked in isolated unit tests; only
        # their cross-UID checks are mocked in this single-UID transport test.
        with patch.object(gateway.GatewayRegistryUnixCandidateRead,
                          '_check_identity', return_value=None):
            self.reader=gateway.GatewayRegistryUnixCandidateRead(
                socket_path=str(self.socketpath),
                instance_id=self.instance,
                scope_digest=local._hash(self.scope),
                registry_uid=uid,registry_gid=gid+100,
                registry_pid=os.getpid(),
                reader_uid=uid+100,reader_gid=gid,
                socket_device=row.st_dev,socket_inode=row.st_ino)
        self.auth=Authenticator({GRANT:ACTOR,'ungranted': 'not-reader'})
        self.policies={(ACTOR,'registry',op):'ALLOW' for op in READ_OPS}
        self.core=Core(self.path.parent/'gateway-core.sqlite',
                       adapters={'registry':object()},
                       authenticator=self.auth,policies=self.policies)
        self.broker=RepoIntentBroker(
            self.core,
            actor_operations={ACTOR:{('synthetic','set_ask')}},
            actor_read_operations={ACTOR:{('registry',op) for op in READ_OPS}},
            read_adapters={'registry':self.reader})

    def cleanup_server(self):
        self.stop.set()
        self.listener.close()
        self.worker.join(timeout=3)
        if self.socketpath.exists() or self.socketpath.is_symlink():
            self.socketpath.unlink()
        self.service._endpoint=None

    def query(self, op, **params):
        return {
            'requestId':str(uuid.uuid4()),'service':'registry',
            'operation':op,'target':'fortis-approvals',
            'params':{'repository':REPOSITORY,**params},
            'reason':'Offline source-only candidate diagnostics; no authority',
        }

    def broker_read(self, request, *, credential=GRANT):
        with patch.object(gateway.GatewayRegistryUnixCandidateRead,
                          '_check_identity',return_value=None), \
             patch.object(gateway.GatewayRegistryUnixCandidateRead,
                          '_peer',return_value=self.reader._registry):
            return self.broker.read(credential,request)

    def test_existing_broker_reads_source_candidate_head_and_page(self):
        self.accept()
        self.setup_broker()
        head=self.broker_read(self.query('candidate_head'))['data']
        self.assertEqual(head['result'],'SOURCE_ONLY_CANDIDATE_READ')
        self.assertEqual(head['candidateOperation'],'candidate_head')
        self.assertEqual(head['data']['localCheckpoint']['revision'],1)
        self.assertFalse(head['liveRegistryAvailable'])
        self.assertFalse(head['admissionAllowed'])
        self.assertFalse(head['rollbackProtected'])
        page=self.broker_read(self.query('candidate_list_desired',
                                        limit=5,cursor=None))['data']
        self.assertEqual(page['result'],'SOURCE_ONLY_CANDIDATE_READ')
        self.assertEqual(page['candidateOperation'],'candidate_list_desired')
        self.assertEqual(page['data']['localRevision'],1)
        self.assertEqual(len(page['data']['records']),1)
        row=page['data']['records'][0]
        self.assertEqual(row['planningState'],'PLANNED_UNVERIFIED')
        self.assertIsNone(row['actual'])
        self.assertEqual(row['identity']['repository'],REPOSITORY)
        self.assertFalse(page['deploymentAllowed'])
        self.assertFalse(page['authenticatedCollectorAvailable'])
        self.assertFalse(page['writeEnabled'])
        self.assertEqual(self.failures,[])

    def test_uuid_recovery_redacts_immutable_source_receipt(self):
        receipt=self.accept()
        self.setup_broker()
        outcome=self.broker_read(self.query(
            'candidate_original_operation',
            operationId=receipt['operationId']))['data']
        self.assertEqual(outcome['data']['operationId'],receipt['operationId'])
        self.assertEqual(outcome['data']['localCheckpoint'],receipt['checkpoint'])
        self.assertEqual(outcome['data']['recordIds'],receipt['recordIds'])
        self.assertNotIn('actor',outcome['data'])
        self.assertNotIn('ownerRequestId',outcome['data'])
        self.assertNotIn('evidenceId',outcome['data'])
        self.assertFalse(outcome['admissionAllowed'])
        self.assertFalse(outcome['deploymentAllowed'])
        self.assertEqual(self.failures,[])

    def test_missing_original_uuid_is_denied_not_authoritative_not_found(self):
        self.setup_broker()
        with self.assertRaisesRegex(Denied,
                                    'REGISTRY_CANDIDATE_OPERATION_DENIED'):
            self.broker_read(self.query('candidate_original_operation',
                                        operationId=str(uuid.uuid4())))
        self.assertEqual(self.failures,[])

    def test_wsgireads_over_real_unix_and_core_not_direct_source_queue(self):
        self.accept()
        self.setup_broker()
        app=RepoIngress(self.broker,host='localhost:19555',
                        allow_http_local_test=True)
        request=self.query('candidate_list_desired',limit=1,cursor=None)
        raw=canonical(request).encode('utf-8')
        statuses=[]
        environ={
            'REQUEST_METHOD':'POST', 'PATH_INFO':'/v1/reads',
            'HTTP_HOST':'localhost:19555','QUERY_STRING':'',
            'CONTENT_TYPE':'application/json','CONTENT_LENGTH':str(len(raw)),
            'HTTP_AUTHORIZATION':'Bearer '+GRANT,
            'wsgi.url_scheme':'http','REMOTE_ADDR':'127.0.0.1',
            'wsgi.input':io.BytesIO(raw),
        }
        with patch.object(gateway.GatewayRegistryUnixCandidateRead,
                          '_check_identity',return_value=None), \
             patch.object(gateway.GatewayRegistryUnixCandidateRead,
                          '_peer',return_value=self.reader._registry):
            answer=json.loads(b''.join(app(
                environ,lambda status,headers:statuses.append(status))))
        self.assertEqual(statuses,['200 OK'])
        self.assertEqual(answer['data']['candidateOperation'],
                         'candidate_list_desired')
        self.assertFalse(answer['data']['deploymentAllowed'])
        self.assertIsNone(answer['data']['data']['records'][0]['actual'])

    def test_not_granted_registry_list_records_write_or_unknown_methods(self):
        self.setup_broker()
        for op in ('list_records','get_operation','preview_merged',
                   'capabilities','ingest_merged','report_manual_complete'):
            with self.subTest(op=op),self.assertRaises(Denied):
                self.broker_read(self.query(op))
        with self.assertRaises(Denied):
            self.broker_read(self.query('candidate_head'),credential='ungranted')
        self.auth.revoke(GRANT)
        with self.assertRaises(Denied):
            self.broker_read(self.query('candidate_head'))
        self.assertEqual(self.failures,[])

    def test_deny_ask_and_revocation_block_before_socket(self):
        self.setup_broker()
        query=self.query('candidate_head')
        key=(ACTOR,'registry','candidate_head')
        with patch.object(self.reader,'_socket_read',
                          side_effect=AssertionError('must not read')):
            self.policies[key]='DENY'
            self.core.policies[key]='DENY'
            with self.assertRaises(Denied):
                self.broker_read(query)
            self.policies[key]='ASK'
            self.core.policies[key]='ASK'
            with self.assertRaises(Denied):
                self.broker_read(query)
        self.assertEqual(self.failures,[])

    def test_source_drift_or_missing_socket_never_returns_empty_queue(self):
        self.accept()
        self.setup_broker()
        self.listener.close()
        self.stop.set()
        self.worker.join(timeout=3)
        with self.assertRaises(Denied):
            self.broker_read(self.query('candidate_list_desired',
                                        limit=2,cursor=None))

    def test_wrong_actual_server_peer_is_denied_by_kernel_pin(self):
        self.setup_broker()
        # Real SO_PEERCRED reports the single-UID fixture's actual gid,
        # NOT the synthetic distinct Registry GID pinned by our test.
        with patch.object(gateway.GatewayRegistryUnixCandidateRead,
                          '_check_identity',return_value=None):
            with self.assertRaisesRegex(Denied,
                                        'REGISTRY_CANDIDATE_SERVER_IDENTITY_DENIED'):
                self.reader.read(self.query('candidate_head'))
        self.assertEqual(self.failures,[])

    def test_socket_inode_change_denied_before_read(self):
        self.setup_broker()
        self.reader._endpoint=(self.reader._endpoint[0],
                               self.reader._endpoint[1]+1)
        with self.assertRaisesRegex(Denied,'SOCKET_CHANGED'):
            self.broker_read(self.query('candidate_head'))
        self.assertEqual(self.failures,[])

    def test_gateway_rejects_forged_admission_and_installed_fields(self):
        self.accept()
        self.setup_broker()
        original=self.state.list_desired_candidates(limit=2)
        for fake in (
            original|{'admissionAllowed':True},
            original|{'deploymentVerified':True},
            original|{'records':[original['records'][0]|
                      {'actual':{'state':'DEPLOYED'}}]},
            original|{'records':[original['records'][0]|
                      {'recordId':'f'*64}]},
            original|{'records':[original['records'][0]|
                      {'requiredActions':['unauthorized-action']}]},
            original|{'records':[original['records'][0]|
                      {'requiredActions':[['invalid-unhashable']]}]},
            original|{'nextCursor':'../etc/passwd'},
            original|{'records':[original['records'][0]]*101},
        ):
            with self.subTest(fake=fake),self.assertRaises(Denied):
                self.reader._project('candidate_list_desired',fake,
                                     {'limit':100,'cursor':None})

    def test_core_revocation_mid_read_does_not_return_source_candidate(self):
        self.accept()
        self.setup_broker()
        request=self.query('candidate_head')
        original=self.reader.read
        def revoke(req):
            result=original(req)
            self.auth.revoke(GRANT)
            return result
        with patch.object(self.reader,'read',side_effect=revoke), \
             patch.object(gateway.GatewayRegistryUnixCandidateRead,
                          '_check_identity',return_value=None), \
             patch.object(gateway.GatewayRegistryUnixCandidateRead,
                          '_peer',return_value=self.reader._registry):
            with self.assertRaises(Denied):
                self.broker.read(GRANT,request)

    def test_wrong_scope_params_or_physical_path_never_reaches_socket(self):
        self.setup_broker()
        base=self.query('candidate_head')
        for altered in (
            {**base,'target':'fortis-container'},
            {**base,'params':{'repository':'bad/bad'}},
            {**base,'params':{**base['params'],'actor':'registry'}},
            {**base,'params':{**base['params'],'socketPath':'/tmp/foo'}},
            {**base,'params':{**base['params'],'auth':'owner'}},
        ):
            with self.subTest(altered=altered),self.assertRaises(Denied):
                self.broker_read(altered)
        with self.assertRaises(Denied):
            self.broker_read(self.query('candidate_list_desired',
                                        limit=True,cursor=None))
        with self.assertRaises(Denied):
            self.broker_read(self.query('candidate_list_desired',
                                        limit=4,cursor='../secret'))
        self.assertEqual(self.failures,[])

    def test_candidate_projection_cannot_be_recognized_as_live_registry(self):
        self.accept()
        self.setup_broker()
        value=self.broker_read(self.query('candidate_list_desired',
                                          limit=1,cursor=None))['data']
        with self.assertRaises(Denied):
            validate_gateway_read_projection('list_records',value)
        with self.assertRaises(Denied):
            validate_gateway_read_projection('get_operation',value)
        self.assertFalse(value['admissionAllowed'])
        self.assertFalse(value['liveRegistryAvailable'])

if __name__=='__main__':
    unittest.main()

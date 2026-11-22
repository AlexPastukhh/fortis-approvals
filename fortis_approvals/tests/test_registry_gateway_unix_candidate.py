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
from types import SimpleNamespace
from unittest.mock import patch

from fortis_approvals.core import Authenticator, Core, Denied, canonical
from fortis_approvals.repo_action_contract import RepoIntentBroker
from fortis_approvals.repo_ingress import RepoIngress
from fortis_approvals.r7_unified_candidate import ACTOR as R7_ACTOR, build_r7_unified_candidate
from fortis_approvals.integrations.registry.repo_client import RegistryCandidateClient
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

    def r7_candidate_app(self):
        """Real R7 factory, test-only fake owner and same-UID reader pins."""
        state = self.path.parent / 'r7-candidate'
        state.mkdir(mode=0o700)
        class SonarUnavailable:
            def call(self, *args):
                raise AssertionError('Registry GET must not query Sonar')
        with patch('fortis_approvals.r7_unified_candidate.IncidentOwnerWebAuthn',
                   return_value=SimpleNamespace(origin='http://localhost:19503')), \
             patch.object(gateway.GatewayRegistryUnixCandidateRead,
                          '_check_identity', return_value=None):
            core, _, _, app = build_r7_unified_candidate(
                state=state, owner_origin='http://localhost:19503',
                ingress_host='host.docker.internal:19504',
                ingress_grant=GRANT, sonar_transport=SonarUnavailable(),
                organizations=('fortis-test',),
                registry_candidate_reader=self.reader)
        return core, app

    def local_repo_client(self, app):
        """Exercise the real R7 machine WSGI ingress without host grants."""
        class TestGateway:
            def post(self, path, payload, *, accept_202=False):
                if path != '/v1/reads':
                    raise AssertionError('No other route is allowed')
                raw = canonical(payload).encode('utf-8')
                env = {
                    'REQUEST_METHOD': 'POST', 'PATH_INFO': path,
                    'HTTP_HOST': 'host.docker.internal:19504',
                    'QUERY_STRING': '', 'CONTENT_TYPE': 'application/json',
                    'CONTENT_LENGTH': str(len(raw)),
                    'HTTP_AUTHORIZATION': 'Bearer ' + GRANT,
                    'wsgi.url_scheme': 'https', 'wsgi.input': io.BytesIO(raw),
                }
                statuses = []
                reply = json.loads(b''.join(app(
                    env, lambda status, headers: statuses.append(status))))
                if statuses != ['200 OK']:
                    raise Denied('TEST_R7_REGISTRY_HTTP_DENIED')
                return reply
        return RegistryCandidateClient(TestGateway())

    def test_r7_candidate_adapter_opt_in_has_no_automatic_registry_grant(self):
        self.accept()
        self.setup_broker()
        core, app = self.r7_candidate_app()
        broker = app.broker
        self.assertIs(broker.read_adapters.get('registry'), self.reader)
        self.assertNotIn(('registry', 'candidate_head'),
                         broker.actor_read_operations[R7_ACTOR])
        self.assertNotIn((R7_ACTOR, 'registry', 'candidate_head'), core.policies)
        with patch.object(self.reader, '_socket_read',
                          side_effect=AssertionError('MUST NOT CONNECT')):
            with self.assertRaisesRegex(Denied, 'TEST_R7_REGISTRY_HTTP_DENIED'):
                self.local_repo_client(app).head()
        self.assertNotIn('registry', core.adapters)
        self.assertEqual(self.failures, [])

    def test_r7_repo_client_reads_real_socket_and_schema3_only_with_test_grants(self):
        receipt = self.accept()
        self.setup_broker()
        core, app = self.r7_candidate_app()
        broker = app.broker
        # In-memory *test-only* grant/policy; NOT installed or added to R7.
        broker.actor_read_operations[R7_ACTOR] |= frozenset(
            ('registry', op) for op in READ_OPS)
        for op in READ_OPS:
            core.policies[(R7_ACTOR, 'registry', op)] = 'ALLOW'
        client = self.local_repo_client(app)
        with patch.object(gateway.GatewayRegistryUnixCandidateRead,
                          '_check_identity', return_value=None), \
             patch.object(gateway.GatewayRegistryUnixCandidateRead,
                          '_peer', return_value=self.reader._registry):
            head = client.head()
            page = client.list_desired(limit=1)
            original = client.original_operation(receipt['operationId'])
        self.assertEqual(head['result'], 'SOURCE_ONLY_CANDIDATE_READ')
        self.assertEqual(head['data']['localCheckpoint']['revision'], 1)
        self.assertEqual(page['data']['records'][0]['identity']['repository'], REPOSITORY)
        self.assertEqual(page['data']['records'][0]['planningState'], 'PLANNED_UNVERIFIED')
        self.assertIsNone(page['data']['records'][0]['actual'])
        self.assertEqual(original['data']['operationId'], receipt['operationId'])
        self.assertFalse(original['admissionAllowed'])
        self.assertFalse(page['liveRegistryAvailable'])
        self.assertFalse(head['writeEnabled'])
        # Revoking an owner-controlled Core rule must DENY before any Unix IO.
        core.policies[(R7_ACTOR, 'registry', 'candidate_head')] = 'DENY'
        with patch.object(self.reader, '_socket_read',
                          side_effect=AssertionError('revoked must not connect')):
            with self.assertRaisesRegex(Denied, 'TEST_R7_REGISTRY_HTTP_DENIED'):
                client.head()
        self.assertEqual(self.failures, [])

    def test_r7_rejects_untrusted_reader_before_state_creation(self):
        root = self.path.parent / 'reject-untrusted-registry-reader'
        class UnusedSonar:
            def call(self, *args):
                raise AssertionError('Sonar call forbidden')
        with self.assertRaisesRegex(Denied, 'R7_REGISTRY_CANDIDATE_READER_INVALID'):
            build_r7_unified_candidate(
                state=root, owner_origin='http://localhost:19503',
                ingress_host='host.docker.internal:19504',
                ingress_grant=GRANT, sonar_transport=UnusedSonar(),
                organizations=('fortis-test',),
                registry_candidate_reader=object())
        self.assertFalse(root.exists())

    def test_repo_client_rejects_ask_spoofed_response_and_unsupported_calls(self):
        with self.assertRaisesRegex(Denied, 'REGISTRY_CLIENT_GATEWAY_REQUIRED'):
            RegistryCandidateClient(object())
        class PendingGateway:
            def post(self, path, request, *, accept_202=False):
                return {'requestId': request['requestId'],
                        'service': 'registry', 'operation': request['operation'],
                        'state': 'PENDING'}
        with self.assertRaisesRegex(Denied, 'REGISTRY_CLIENT_RESPONSE_DENIED'):
            RegistryCandidateClient(PendingGateway()).head()
        class SpoofGateway:
            def post(self, path, request, *, accept_202=False):
                return {'requestId': str(uuid.uuid4()),
                        'service': 'registry', 'operation': request['operation'],
                        'data': {}}
        with self.assertRaisesRegex(Denied, 'REGISTRY_CLIENT_RESPONSE_DENIED'):
            RegistryCandidateClient(SpoofGateway()).head()
        class ForbiddenGateway:
            def post(self, *a, **kw):
                raise AssertionError('Invalid query reached remote Gateway')
        client = RegistryCandidateClient(ForbiddenGateway())
        with self.assertRaises(Denied):
            client.original_operation('forged')
        with self.assertRaises(Denied):
            client.list_desired(limit=0)
        with self.assertRaises(Denied):
            client.list_desired(limit=101)
        with self.assertRaises(Denied):
            client.list_desired(cursor='/etc/passwd')

    def principal_status(self, *, capabilities='0', no_new_privs='1',
                         seccomp='2', trace='0', groups=None):
        """Synthetic /proc snapshot; never a distinct-UID host acceptance."""
        uid, gid = self.reader._reader
        groups = [] if groups is None else groups
        rows = {
            'Uid': f'{uid} {uid} {uid} {uid}',
            'Gid': f'{gid} {gid} {gid} {gid}',
            'Groups': ' '.join(map(str, groups)),
            'CapInh': capabilities, 'CapPrm': capabilities,
            'CapEff': capabilities, 'CapBnd': capabilities,
            'CapAmb': capabilities, 'NoNewPrivs': no_new_privs,
            'Seccomp': seccomp, 'TracerPid': trace,
        }
        return ''.join(f'{k}:\t{v}\n' for k,v in rows.items()).encode()

    def check_synthetic_process(self, raw, *, groups=None):
        uid, gid = self.reader._reader
        with patch.object(gateway.os, 'getresuid', return_value=(uid,)*3), \
             patch.object(gateway.os, 'getresgid', return_value=(gid,)*3), \
             patch.object(gateway.os, 'getuid', return_value=uid), \
             patch.object(gateway.os, 'geteuid', return_value=uid), \
             patch.object(gateway.os, 'getgid', return_value=gid), \
             patch.object(gateway.os, 'getegid', return_value=gid), \
             patch.object(gateway.os, 'getgroups', return_value=(
                 [] if groups is None else groups)), \
             patch.object(gateway.Path, 'read_bytes', return_value=raw):
            return self.reader._check_identity()

    def test_reader_process_security_guard_is_fail_closed(self):
        self.setup_broker()
        self.check_synthetic_process(self.principal_status())
        cases = [
            ('capability', {'capabilities':'1'}, None,
             'READER_PRIVILEGE_DENIED'),
            ('no_new_privs', {'no_new_privs':'0'}, None,
             'READER_PRIVILEGE_DENIED'),
            ('seccomp', {'seccomp':'0'}, None,
             'READER_PRIVILEGE_DENIED'),
            ('tracer', {'trace':'42'}, None,
             'READER_PRIVILEGE_DENIED'),
            ('registry_group', {}, [self.reader._registry[2]],
             'READER_GROUP_DENIED'),
            ('extra_proc_field_missing', {}, None, 'PROC_DENIED'),
        ]
        for label, options, groups, code in cases:
            with self.subTest(label=label), self.assertRaisesRegex(Denied,code):
                raw=self.principal_status(groups=groups,**options)
                if label=='extra_proc_field_missing':
                    raw=raw.replace(b'CapBnd:',b'Unknown:')
                self.check_synthetic_process(raw,groups=groups)
        with self.assertRaisesRegex(Denied,'READER_IDENTITY_DENIED'):
            self.check_synthetic_process(self.principal_status(
                groups=[123]),groups=[])

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

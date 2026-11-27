"""Existing Core composite across private source wire and Registry SQLite.

Only the GitHub/owner/independent authorization fixtures are synthetic;
socketpair framing is real, no host peer or live authority claim.
"""
import copy
import unittest
from unittest.mock import patch

from fortis_approvals.core import Denied
from fortis_approvals.extensions.merge_register import MergeRegisterAdapter,TransportMergeRegisterBinding
from fortis_approvals.extensions.composite_executor import Admission
from fortis_approvals.extensions.maintenance_gate import MaintenanceGate
from fortis_approvals.extensions.semantic_gateway import GatewayRegistrySemanticTransport
from fortis_approvals.integrations.registry.candidate_gateway import GatewayRegistryUnixCandidateRead
from fortis_approvals.integrations.registry_contracts import semantic_contract as sc, semantic_wire as wire
from fortis_approvals.registry.semantic_unix_service import SemanticFrameService
from fortis_approvals.tests import test_merge_register as fixture
from fortis_approvals.tests import test_maintenance_gate as maintenance
from fortis_approvals.tests import test_semantic_wire as wire_fixture
from fortis_approvals.tests.test_registry_source_lineage import LineageFixture


class SourceTransportTests(LineageFixture,unittest.TestCase):
    request=fixture.MergeRegisterTests.request
    submit=fixture.MergeRegisterTests.submit
    approve=fixture.MergeRegisterTests.approve
    steps=fixture.MergeRegisterTests.steps
    exchange=wire_fixture.WireTests.exchange

    # Explicit fixture setup rather than inheriting the old test suite.
    def setUp(self):
        # The original fixture uses super(); initialize via a separate
        # fixture instance and reuse its isolated resources.
        f=fixture.MergeRegisterTests('test_one_owner_ask_exact_merge_receipt_and_source_cursor')
        f.setUp()
        self.addCleanup(f.doCleanups)
        self.__dict__.update({k:v for k,v in vars(f).items() if not k.startswith('_')})
        self.source_allowed=True
        self.frames=SemanticFrameService(self.service,frame_key=b'f'*32,generation='a'*64,
                authorize=lambda a,act,b:a in ('agent-1','internal'),
                provenance=lambda a:'OWNER_TRANSCRIBED',internal_actor='internal',
                source_authorize=lambda a,act,b:self.source_allowed and
                    (a=='internal' if act=='SOURCE_PREFLIGHT' else a=='agent-1'))
        self.peer=object.__new__(GatewayRegistryUnixCandidateRead)
        self.peer._instance=self.instance;self.peer._scope=self.witness['scopeDigest']
        self.peer._peer_key=b'p'*32
        self.make_core()

    def make_core(self):
        self.transport=GatewayRegistrySemanticTransport(self.peer,frame_key=b'f'*32,
                   generation='a'*64,internal_actor='internal')
        self.transport._exchange=self.exchange
        self.ctrl=maintenance.Controller(self.instance,self.witness['scopeDigest'])
        self.gate=MaintenanceGate(instance_id=self.instance,scope_digest=self.witness['scopeDigest'],
                generation=maintenance.OLD,read_interlock=self.ctrl.read,
                read_holds=self.transport.maintenance_snapshot)
        self.binding=TransportMergeRegisterBinding(provider=self.provider,registry=self.transport,
                admission=lambda a,t,s:Admission('ASK',self.allowed and a=='agent-1' and t=='scope',
                    'ASK' if s['ordinal']==0 else 'ALLOW','a'*64),
                effect_guard=lambda ctx:self.allowed,gate=self.gate,policy_authority_digest='b'*64)
        self.adapter=MergeRegisterAdapter(binding=self.binding)
        self.core=fixture.TestCore(self.core_path,adapters={'release':self.adapter},
              policies=self.policy,authenticator=self.auth,owner_verifier=self.owner,clock=lambda:100)
        self.adapter.core=self.core;self.binding.adapter=self.adapter

    def test_owner_ask_both_steps_and_original_receipt_over_wire(self):
        parent=self.submit()
        self.assertEqual(parent['state'],'PENDING')
        self.assertEqual(self.provider.calls,0)
        self.assertEqual(self.approve(parent)['state'],'EXECUTED')
        self.assertEqual([s['state'] for s in self.steps(parent)],['CONFIRMED','CONFIRMED'])
        self.assertEqual(self.domain.snapshot()['sourceCursor'],self.proposed['observation']['mergeSha'])
        self.make_core()
        self.assertEqual(self.core.execute(parent['requestId'])['state'],'EXECUTED')
        self.assertEqual(self.provider.calls,1)

    def test_no_deployment_advances_only_source_cursor(self):
        p=self.proposed['proposal']
        p['classification']='no-deployment';p['targets']=[]
        self.provider.material['validatedProjectionDigest']=sc.digest({k:p[k] for k in
            ('classification','targets','dependencies','profileDigest')})
        previous=self.component()['desired']
        parent=self.submit()
        self.assertEqual(self.approve(parent)['state'],'EXECUTED')
        self.assertEqual(self.component()['desired'],previous)
        self.assertEqual(self.domain.snapshot()['sourceRevision'],2)

    def test_lost_register_response_reconcile_never_resends(self):
        parent=self.submit()
        writes=[]
        def lost(frame,**kw):
            result=self.exchange(frame,**kw)
            if frame['request']['action']=='SOURCE_REGISTER':
                writes.append(frame)
                raise Denied('FIXTURE_LOST_RESPONSE')
            return result
        self.transport._exchange=lost
        self.assertEqual(self.approve(parent)['state'],'UNCERTAIN')
        self.assertEqual([s['state'] for s in self.steps(parent)],['CONFIRMED','UNKNOWN'])
        self.assertEqual(self.domain.snapshot()['sourceRevision'],2)
        self.make_core()
        self.assertEqual(self.core.reconcile(parent['requestId'])['state'],'EXECUTED')
        self.assertEqual(len(writes),1)
        self.assertEqual(self.provider.calls,1)
        self.assertEqual(self.domain.snapshot()['sourceRevision'],2)

    def test_source_registration_requires_separate_admission_and_verification(self):
        parent=self.submit()
        self.verify=False
        # Even a valid MAC and exact approved Core step cannot substitute
        # for independent evidence verification in Registry.
        self.domain._source_verify=lambda _:False
        self.assertEqual(self.approve(parent)['state'],'UNCERTAIN')
        self.assertEqual(self.domain.snapshot()['sourceRevision'],1)
        self.assertEqual(self.provider.calls,1)

    def test_tampered_source_context_or_first_receipt_refused_before_write(self):
        parent=self.submit()
        def tamper(frame,**kw):
            if frame['request']['action']=='SOURCE_REGISTER':
                req=copy.deepcopy(frame['request'])
                req['body']['mergeReceipt']['captureDigest']='9'*64
                # A trusted frame MAC alone does not bind a changed receipt.
                frame=wire.seal(b'f'*32,req)
            return self.exchange(frame,**kw)
        self.transport._exchange=tamper
        self.assertEqual(self.approve(parent)['state'],'UNCERTAIN')
        self.assertEqual(self.domain.snapshot()['sourceRevision'],1)

    def test_source_grant_revocation_after_merge_blocks_register(self):
        parent=self.submit()
        real=self.provider.merge
        def changed(ctx,digest):
            result=real(ctx,digest);self.source_allowed=False;return result
        with patch.object(self.provider,'merge',side_effect=changed):
            self.assertEqual(self.approve(parent)['state'],'UNCERTAIN')
        self.assertEqual(self.domain.snapshot()['sourceRevision'],1)
        self.assertEqual(self.provider.calls,1)

    def test_source_methods_default_deny_and_no_transition_wire(self):
        self.frames.source_authorize=None
        with self.assertRaises(Denied):
            self.transport.source_preflight(self.proposed['proposal'])
        with self.assertRaises(Denied):
            self.transport._call('internal','SOURCE_REGISTER',{'request':self.transition()})
        self.assertEqual(self.domain.snapshot()['sourceRevision'],1)

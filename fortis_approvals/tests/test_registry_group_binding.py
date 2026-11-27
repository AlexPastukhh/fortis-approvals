"""Actual Core group lifecycle + actual local Registry domain/SQLite writer.

No production transport, credentials or owner admission: synthetic exact
scope, provenance and policy fixtures. No second Registry writer.
"""
from pathlib import Path
import unittest
from unittest.mock import patch

from fortis_approvals.core import Authenticator, Denied
from fortis_approvals.extensions.composite_executor import Admission, GroupAdapter
from fortis_approvals.extensions.registry_group_binding import RegistryGroupBinding
from fortis_approvals.extensions import composite_journal as journal
from fortis_approvals.tests import test_registry_release_domain as fixture
from fortis_approvals.tests.test_composite_executor import TestCore
from fortis_approvals.tests.test_core import SyntheticOwnerVerifier
from fortis_approvals.tests.test_registry_state_journal import uid


class RealRegistryGroupTests(unittest.TestCase):
    append=fixture.DomainTests.append
    clone=fixture.DomainTests.clone
    rebind=fixture.DomainTests.rebind
    component=fixture.DomainTests.component
    params=fixture.DomainTests.params
    report=fixture.DomainTests.report
    write=fixture.DomainTests.write

    def setUp(self):
        fixture.DomainTests.setUp(self)
        self.core_path=self.root/'core.sqlite'
        self.auth=Authenticator({'machine':'agent-1'})
        self.owner=SyntheticOwnerVerifier()
        self.make_core()
        with self.core._db() as db:
            db.execute('BEGIN IMMEDIATE')
            journal.install_schema(db)

    def make_core(self):
        def admission(actor,target,step):
            if (actor!='agent-1' or target!='scope'
                    or step['params']['subject'] not in self.subjects):
                raise Denied('FIXTURE_SCOPE')
            return Admission('ASK',True,'ALLOW','a'*64)
        self.binding=RegistryGroupBinding(transport=self.service,admission=admission,
                           provenance=lambda _: 'OWNER_TRANSCRIBED',
                           profile_digest=self.domain.profile_digest)
        self.adapter=GroupAdapter(binding=self.binding)
        self.core=TestCore(self.core_path,adapters={'registry':self.adapter},
              policies={('agent-1','registry','begin_release_group','scope'):'ASK',
                        ('agent-1','registry','report_release_results','scope'):'ASK'},
              authenticator=self.auth,owner_verifier=self.owner,clock=lambda:100)
        self.adapter.core=self.core
        self.binding.adapter=self.adapter

    def request(self,op,items):
        return {'requestId':uid(),'service':'registry','operation':op,'target':'scope',
                'params':{'items':items},'expectedVersion':0,'reason':'isolated registry integration'}

    def submit(self,op,items):
        return self.core.client('machine','submit',self.request(op,items))

    def approve(self,view):
        return self.core.owner_decide(view['requestId'],'approve',
                    self.owner.proof(view['requestId'],view['fingerprint'],'approve'))

    def steps(self,view):
        with self.core._db() as db:
            db.execute('BEGIN')
            return journal.inspect(db,view['requestId'])['steps']

    def test_atomic_group_single_call_all_markers_original_receipts(self):
        view=self.submit('begin_release_group',[self.params(0),self.params(1)])
        self.assertEqual(view['preview']['executionMode'],'ATOMIC_REGISTRY_LOCAL')
        self.assertEqual(self.domain.snapshot()['snapshotRevision'],0)
        real=self.service.begin_group
        def dispatch(*args,**kwargs):
            self.assertEqual([s['state'] for s in self.steps(view)],['DISPATCHED']*2)
            return real(*args,**kwargs)
        with patch.object(self.service,'begin_group',side_effect=dispatch) as called:
            self.assertEqual(self.approve(view)['state'],'EXECUTED')
            self.assertEqual(called.call_count,1)
        steps=self.steps(view)
        self.assertEqual([s['state'] for s in steps],['CONFIRMED']*2)
        for i,step in enumerate(steps):
            self.assertEqual(self.component(i)['activeAttempt']['attemptId'],step['stepId'])
        self.make_core()
        self.assertEqual(self.core.execute(view['requestId'])['state'],'EXECUTED')
        self.assertEqual(self.domain.snapshot()['snapshotRevision'],2)

    def test_atomic_lost_ack_recovers_as_unit_without_repeat(self):
        view=self.submit('begin_release_group',[self.params(0),self.params(1)])
        real=self.service.begin_group
        def lost(*a,**kw):
            real(*a,**kw)
            raise RuntimeError('lost test acknowledgement')
        with patch.object(self.service,'begin_group',side_effect=lost) as call:
            self.assertEqual(self.approve(view)['state'],'UNCERTAIN')
            self.assertEqual(call.call_count,1)
        self.assertEqual([s['state'] for s in self.steps(view)],['UNKNOWN']*2)
        self.make_core()
        orig=self.binding.lookup
        with patch.object(self.binding,'lookup',side_effect=lambda ctx: orig(ctx) if ctx.ordinal==0 else None):
            self.assertEqual(self.core.reconcile(view['requestId'])['state'],'UNCERTAIN')
        self.assertEqual([s['state'] for s in self.steps(view)],['UNKNOWN']*2)
        self.assertEqual(self.core.reconcile(view['requestId'])['state'],'EXECUTED')
        self.assertEqual(self.domain.snapshot()['snapshotRevision'],2)

    def test_group_conflict_does_not_commit_first_child(self):
        self.profile['subjects'][0]['maintenance']=fixture.maintenance(True,True)
        self.rebind()
        self.make_core()
        view=self.submit('begin_release_group',[self.params(0),self.params(1)])
        self.assertEqual(self.approve(view)['state'],'UNCERTAIN')
        self.assertEqual([s['state'] for s in self.steps(view)],['UNKNOWN']*2)
        self.assertEqual(self.domain.snapshot()['snapshotRevision'],0)
        self.assertEqual(self.core.reconcile(view['requestId'])['state'],'UNCERTAIN')

    def test_sequential_reports_same_writer_preserve_first_result(self):
        view=self.submit('begin_release_group',[self.params(0),self.params(1)])
        self.assertEqual(self.approve(view)['state'],'EXECUTED')
        ids=[s['stepId'] for s in self.steps(view)]
        p=[self.report(0,attemptId=ids[0]),self.report(1,attemptId=ids[1])]
        p[1]['attemptId']=uid()
        reports=self.submit('report_release_results',p)
        self.assertNotIn('executionMode',reports['preview'])
        self.assertEqual(self.approve(reports)['state'],'UNCERTAIN')
        self.assertEqual([s['state'] for s in self.steps(reports)],['CONFIRMED','UNKNOWN'])
        self.assertEqual(self.component(0)['ownerReported']['outcome'],'REPORTED_COMPLETE')
        self.assertIsNone(self.component(1)['ownerReported'])
        self.assertEqual(self.domain.snapshot()['snapshotRevision'],3)


if __name__=='__main__':
    unittest.main()

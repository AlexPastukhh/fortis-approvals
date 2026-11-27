"""Actual Core + actual Registry source writer, synthetic GitHub only."""
import copy
import hashlib
import unittest
from unittest.mock import patch

from fortis_approvals.core import Authenticator, Denied
from fortis_approvals.extensions.composite_executor import Admission
from fortis_approvals.extensions.merge_register import MergeRegisterAdapter,MergeRegisterBinding
from fortis_approvals.extensions import composite_journal as journal
from fortis_approvals.extensions.composite_preservation import inspect_companion
from fortis_approvals.integrations.registry_contracts import semantic_contract as sc
from fortis_approvals.tests import test_registry_source_lineage as fixture
from fortis_approvals.tests.test_composite_executor import TestCore
from fortis_approvals.tests.test_core import SyntheticOwnerVerifier
from fortis_approvals.tests.test_registry_state_journal import uid


class FakeProvider:
    """Synthetic original receipt store; no external effect or real CI."""
    def __init__(self):
        self.receipts={}
        self.calls=0
        self.mode='normal'
        self.changed=False

    def preview(self,actor,p):
        if actor not in ('agent-1','owner-actor'):raise Denied('FIXTURE_ACTOR_DENIED')
        return {**p,'bodyDigest':'f'*64} if self.changed else copy.deepcopy(p)

    def capture(self,ctx):
        return copy.deepcopy(self.material)

    def verify_capture(self,ctx,material):
        return material==self.material

    def merge(self,ctx,capture_digest):
        self.calls+=1
        p=ctx.params['proposal']
        o=copy.deepcopy(self.observation)
        if self.mode=='base-race':
            o['parents'][0]='f'*40
        result={'operationId':ctx.step_id,'parentRequestId':ctx.parent_id,
                'proposalDigest':sc.digest(p),'captureDigest':capture_digest,'observation':o}
        self.receipts[ctx.step_id]=result
        if self.mode=='lost':
            raise RuntimeError('fixture ack lost')
        return copy.deepcopy(result)

    def lookup(self,ctx):
        return copy.deepcopy(self.receipts.get(ctx.step_id))

    def verify(self,ctx,receipt):
        return receipt==self.receipts.get(ctx.step_id)


class MergeRegisterTests(fixture.LineageFixture,unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.domain.register_source(self.transition())
        self.proposed=self.merge()
        self.provider=FakeProvider()
        impact='schemaVersion: 1'
        body='<!-- fortis-release-impact:start -->\n```yaml\n'+impact+'\n```\n<!-- fortis-release-impact:end -->'
        paths=[{'status':'modified','path':'app.py','previousPath':None}]
        ci={'fixture':'exact head checks'}
        p=self.proposed['proposal']
        changes={'bodyDigest':hashlib.sha256(body.encode()).hexdigest(),
                 'impactDigest':hashlib.sha256(impact.encode()).hexdigest(),
                 'pathsDigest':sc.digest(paths),'ciDigest':sc.digest(ci)}
        p.update(changes)
        self.proposed['observation'].update(changes)
        self.provider.material={'body':body,'catalog':self.catalog_text,'paths':paths,'ci':ci,
            'validatedProjectionDigest':sc.digest({k:p[k] for k in ('classification','targets','dependencies','profileDigest')})}
        self.provider.observation=self.proposed['observation']
        self.auth=Authenticator({'machine':'agent-1'})
        self.owner=SyntheticOwnerVerifier()
        self.policy={('agent-1','release','merge_and_register','scope'):'ASK'}
        self.allowed=True
        self.core_path=self.root/'core.sqlite'
        self.make_core()
        with self.core._db() as db:
            db.execute('BEGIN IMMEDIATE')
            journal.install_schema(db)

    def make_core(self):
        self.binding=MergeRegisterBinding(provider=self.provider,registry=self.domain,
            admission=lambda actor,target,step:Admission('ASK',self.allowed and actor=='agent-1'
                and target=='scope','ASK' if step['ordinal']==0 else 'ALLOW','a'*64),
            effect_guard=lambda ctx:self.allowed)
        self.adapter=MergeRegisterAdapter(binding=self.binding)
        self.core=TestCore(self.core_path,adapters={'release':self.adapter},
              policies=self.policy,authenticator=self.auth,owner_verifier=self.owner,clock=lambda:100)
        self.adapter.core=self.core
        self.binding.adapter=self.adapter

    def request(self):
        return {'requestId':uid(),'service':'release','operation':'merge_and_register',
                'target':'scope','params':self.proposed['proposal'],'expectedVersion':0,
                'reason':'synthetic exact merge review'}

    def submit(self):
        return self.core.client('machine','submit',self.request())

    def approve(self,view):
        return self.core.owner_decide(view['requestId'],'approve',
                    self.owner.proof(view['requestId'],view['fingerprint'],'approve'))

    def steps(self,view):
        with self.core._db() as db:
            db.execute('BEGIN')
            return journal.inspect(db,view['requestId'])['steps']

    def test_one_owner_ask_exact_merge_receipt_and_source_cursor(self):
        view=self.submit()
        self.assertEqual(view['state'],'PENDING')
        self.assertEqual(self.provider.calls,0)
        self.assertEqual(self.approve(view)['state'],'EXECUTED')
        self.assertEqual(self.provider.calls,1)
        self.assertEqual([s['state'] for s in self.steps(view)],['CONFIRMED','CONFIRMED'])
        self.assertEqual(self.domain.snapshot()['sourceCursor'],self.proposed['observation']['mergeSha'])
        self.assertIsNone(self.component()['installed'])
        self.make_core()
        self.assertEqual(self.core.execute(view['requestId'])['state'],'EXECUTED')
        self.assertEqual(self.provider.calls,1)
        with self.core._db() as db:
            db.execute('PRAGMA query_only=ON');db.execute('BEGIN')
            self.assertEqual(inspect_companion(db)['parentStates'],{'EXECUTED':1})

    def test_merge_context_exact_repo_and_hard_ask_from_actual_policy_engine(self):
        from fortis_approvals.extensions.composite_authority import (
            MergeContextGrant,ContextAdmission,ProviderGuard)
        from fortis_approvals.extensions.composite_contract import definition,expand_composite
        from fortis_approvals.extensions.owner_policy_engine_v2 import UnifiedPolicyCore
        from fortis_approvals.tests.test_composite_authority import enrollment
        from fortis_approvals.synthetic import SyntheticAdapter
        definition_digest=definition('release','merge_and_register').definition_digest
        repo=self.proposed['proposal']['repository']
        grants=tuple(MergeContextGrant('agent-1','scope',svc,op,'exact-repo',repo,definition_digest)
                     for svc,op in (('github','merge_pull_request'),('registry','register_merge')))
        enrolled=enrollment(grants)
        coords={tuple(row[k]) for row in enrolled.metadata()['grants'] for k in ('parent','child')}
        dummy=SyntheticAdapter(self.root/'context-provider.sqlite')
        core=UnifiedPolicyCore(self.root/'context-core.sqlite',
                adapters={s:dummy for s in ('github','registry','release')},
                policies={c:'ASK' for c in coords},authenticator=self.auth,owner_verifier=self.owner)
        core.install_policy_authority({c:{'DENY','ASK','ALLOW'} for c in coords},
                scope_binding={'compositeContext':enrolled.sha})
        admission=ContextAdmission(core,enrolled,guard=lambda a,row,step:ProviderGuard(
                    True,True,'ASK' if step['ordinal']==0 else 'ALLOW','d'*64))
        steps=expand_composite('release','merge_and_register',uid(),self.proposed['proposal'])['steps']
        self.assertEqual(admission.admit('agent-1','scope',steps[0]).hard_floor,'ASK')
        self.assertEqual(admission.admit('agent-1','scope',steps[1]).hard_floor,'ALLOW')
        with self.assertRaises(Denied):
            admission.admit('agent-1','other-scope',steps[0])
        forged=copy.deepcopy(steps[0])
        forged['params']['proposal']['repository']='Other/repo'
        with self.assertRaises(Denied):
            admission.admit('agent-1','scope',forged)
        bad=ContextAdmission(core,enrolled,guard=lambda *_:ProviderGuard(True,True,'ALLOW','d'*64))
        with self.assertRaises(Denied):
            bad.admit('agent-1','scope',steps[0])

    def test_allow_parent_never_auto_merges(self):
        self.core.policies[('agent-1','release','merge_and_register','scope')]='ALLOW'
        with self.assertRaisesRegex(Denied,'OWNER_ASK_REQUIRED'):
            self.submit()
        self.assertEqual(self.provider.calls,0)
        self.assertEqual(self.domain.snapshot()['sourceRevision'],1)

    def test_external_preview_never_under_core_write_reservation(self):
        real=self.provider.preview
        actors=[]
        def checked(actor,p):
            actors.append(actor)
            # An independent SQLite connection must be able to acquire the
            # writer slot while a potentially slow provider read is in flight.
            import sqlite3
            with sqlite3.connect(self.core_path,timeout=0) as db:
                db.execute('BEGIN IMMEDIATE')
            return real(actor,p)
        with patch.object(self.provider,'preview',side_effect=checked):
            view=self.submit()
            self.assertEqual(self.approve(view)['state'],'EXECUTED')
        self.assertGreaterEqual(len(actors),3)
        self.assertEqual(set(actors),{'agent-1'})

    def test_policy_generation_drift_during_observation_prevents_parent_creation(self):
        real=self.provider.preview
        def changed(actor,p):
            result=real(actor,p)
            self.core.policy_version='changed'
            return result
        with patch.object(self.provider,'preview',side_effect=changed):
            with self.assertRaises(Denied):
                self.submit()
        self.assertEqual(self.core.owner_list(),[])
        self.assertEqual(self.provider.calls,0)

    def test_policy_generation_drift_before_dispatch_never_merges(self):
        view=self.submit()
        real=self.provider.preview
        def changed(actor,p):
            result=real(actor,p)
            self.core.policy_version='changed'
            return result
        with patch.object(self.provider,'preview',side_effect=changed):
            self.assertEqual(self.approve(view)['state'],'STALE')
        self.assertEqual(self.provider.calls,0)

    def test_original_uuid_replay_does_not_repeat_external_preview(self):
        q=self.request()
        view=self.core.submit('agent-1',q)
        with patch.object(self.provider,'preview',side_effect=AssertionError('unexpected preview')):
            self.assertEqual(self.core.submit('agent-1',q),view)

    def test_direct_prepare_without_actor_observation_fails_closed(self):
        view=self.submit()
        with self.assertRaises(Denied):
            self.adapter.prepare(view['request'])
        self.assertEqual(self.provider.calls,0)

    def test_changed_preview_blocks_before_merge(self):
        view=self.submit()
        self.provider.changed=True
        self.assertEqual(self.approve(view)['state'],'STALE')
        self.assertEqual(self.provider.calls,0)

    def test_source_cursor_change_blocks_even_if_provider_preview_stable(self):
        view=self.submit()
        self.domain.register_source(self.merge(289,targets=[]))
        self.assertEqual(self.approve(view)['state'],'STALE')
        self.assertEqual(self.provider.calls,0)
        self.assertEqual(self.domain.snapshot()['sourceRevision'],2)

    def test_unresolved_original_capture_reserves_source_revision(self):
        self.provider.mode='lost'
        first=self.submit()
        self.assertEqual(self.approve(first)['state'],'UNCERTAIN')
        second=self.submit()
        self.assertNotEqual(first['requestId'],second['requestId'])
        self.assertEqual(self.approve(second)['state'],'UNCERTAIN')
        self.assertEqual(self.provider.calls,1)
        self.assertEqual(self.domain.snapshot()['sourceRevision'],1)

    def test_source_capacity_fails_before_any_merge(self):
        from fortis_approvals.core import Stale
        from fortis_approvals.registry import source_event_journal
        for limit,value in (('MAX_SOURCE_EVENTS',1),('MAX_SOURCE_BYTES',
                self.domain.snapshot()['sourceEventBytes'])):
            with self.subTest(limit=limit),patch.object(source_event_journal,limit,value):
                with self.assertRaises(Stale):
                    self.submit()
                self.assertEqual(self.provider.calls,0)

    def test_base_race_after_effect_uncertain_no_registration(self):
        view=self.submit()
        self.provider.mode='base-race'
        self.assertEqual(self.approve(view)['state'],'UNCERTAIN')
        self.assertEqual([s['state'] for s in self.steps(view)],['UNKNOWN','PLANNED'])
        self.assertEqual(self.domain.snapshot()['sourceRevision'],1)
        self.assertEqual(self.provider.calls,1)

    def test_merge_ack_lost_recovery_never_starts_unexecuted_child(self):
        view=self.submit()
        self.provider.mode='lost'
        self.assertEqual(self.approve(view)['state'],'UNCERTAIN')
        self.make_core()
        self.assertEqual(self.core.reconcile(view['requestId'])['state'],'UNCERTAIN')
        self.assertEqual([s['state'] for s in self.steps(view)],['CONFIRMED','PLANNED'])
        self.assertEqual(self.provider.calls,1)
        self.assertEqual(self.domain.snapshot()['sourceRevision'],1)

    def test_registry_ack_lost_reconcile_original_both_receipts(self):
        view=self.submit()
        real=self.domain.register_source
        def lost(req):
            real(req)
            return {'result':'UNKNOWN_OUTCOME','operationId':req['operationId']}
        with patch.object(self.domain,'register_source',side_effect=lost):
            self.assertEqual(self.approve(view)['state'],'UNCERTAIN')
        self.assertEqual([s['state'] for s in self.steps(view)],['CONFIRMED','UNKNOWN'])
        self.assertEqual(self.domain.snapshot()['sourceRevision'],2)
        self.make_core()
        self.assertEqual(self.core.reconcile(view['requestId'])['state'],'EXECUTED')
        self.assertEqual(self.provider.calls,1)
        self.assertEqual(self.domain.snapshot()['sourceRevision'],2)

    def test_retained_capture_precedes_provider_and_tamper_detected(self):
        view=self.submit()
        real=self.provider.merge
        def checked(ctx,capture_digest):
            from fortis_approvals.extensions import merge_capture
            with self.core._db() as db:
                db.execute('BEGIN')
                self.assertEqual(merge_capture.lookup(db,ctx.parent_id)['materialDigest'],capture_digest)
            return real(ctx,capture_digest)
        with patch.object(self.provider,'merge',side_effect=checked):
            self.assertEqual(self.approve(view)['state'],'EXECUTED')
        with self.core._db() as db:
            db.execute("UPDATE composite_merge_captures SET material='{}'")
        with self.core._db() as db:
            db.execute('PRAGMA query_only=ON');db.execute('BEGIN')
            with self.assertRaises(Denied):inspect_companion(db)

    def test_capture_body_mismatch_never_calls_merge(self):
        view=self.submit()
        self.provider.material['body']+='changed'
        self.assertEqual(self.approve(view)['state'],'UNCERTAIN')
        self.assertEqual(self.provider.calls,0)
        self.assertEqual(self.domain.snapshot()['sourceRevision'],1)

    def test_revocation_after_merge_stops_register(self):
        view=self.submit()
        real=self.provider.merge
        def changed(ctx,capture_digest):
            result=real(ctx,capture_digest)
            self.allowed=False
            return result
        with patch.object(self.provider,'merge',side_effect=changed):
            self.assertEqual(self.approve(view)['state'],'UNCERTAIN')
        self.assertEqual(self.provider.calls,1)
        self.assertEqual(self.domain.snapshot()['sourceRevision'],1)


if __name__=='__main__':unittest.main()

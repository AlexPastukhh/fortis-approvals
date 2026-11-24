"""Original Core ASK and collector journals, real Git objects, offline provider.

No WebAuthn hardware, host isolation, real GitHub, enrollment or live grant is
claimed. Existing test verifier/provider are used only in this source suite.
"""
import copy
from datetime import datetime, timezone
from pathlib import Path
import time
import unittest
from unittest.mock import patch
import uuid

from fortis_approvals.core import Authenticator, Denied, canonical
from fortis_approvals.incidents import IncidentCore, IncidentOwnerPortal
from fortis_approvals.integrations.github.gateway import functional_review_runtime as rt
from fortis_approvals.integrations.github.gateway import collector_snapshot as cs
from fortis_approvals.integrations.github.gateway import registry_review_policy as rp
from fortis_approvals.integrations.github.tests import test_registry_review_policy as fixtures
from fortis_approvals.integrations.github.tests.test_review_attestation import TestVerifier
from fortis_approvals.tests import test_owner_portal_input as owner_input


class SessionVerifier(TestVerifier, owner_input.TestOwnerVerifier):
    pass
from fortis_approvals.workflow.common import secure_dir
from fortis_approvals.registry import functional_v1_journal as journal
from fortis_approvals.registry import state_journal as state
from fortis_approvals.integrations.github.gateway import admission_plan, forward_lineage, component_bindings
import hashlib


class FunctionalReviewRuntimeTests(unittest.TestCase):
    setUp=fixtures.RegistryReviewPolicyTests.setUp

    def runtime(self):
        self.enterContext(patch.object(rt,'REPOSITORY',self.fixture.api.head_repo))
        self.enterContext(patch.object(cs,'REPOSITORY',self.fixture.api.head_repo))
        root=secure_dir(self.fixture.root/'functional-review-runtime')
        self.cid=str(uuid.uuid4())
        def pin(name,value,instance=None):
            path=root/name
            path.write_bytes(canonical(value).encode());path.chmod(0o600)
            return rt.LocalPin(path,instance_id=instance)
        self.capture_pin=pin('capture.json',self.fixture.store.checkpoint())
        self.collector_pin=pin('collector.json',cs.genesis(self.cid),self.cid)
        self.collector=cs.CollectorSnapshotStore.initialize(root/'collector.sqlite',
            instance_id=self.cid,anchor_reader=self.collector_pin.read)
        self.verifier=SessionVerifier()
        self.core=IncidentCore(root/'core.sqlite',adapters={},policies={},
            authenticator=Authenticator({'fixture-internal-only':rt.ACTOR}),owner_verifier=self.verifier)
        self.portal=IncidentOwnerPortal(self.core,self.verifier)
        self.service=rt.FunctionalReviewRuntime(core=self.core,provider=self.fixture.adapter,
            capture=self.fixture.store,capture_pin=self.capture_pin,collector=self.collector,
            collector_pin=self.collector_pin,validator=self.fixture.validator,
            owner='test-owner',policy_reader=self.reader,policy_digest=self.pin)
        self.service.install(self.portal)
        self.rid=str(uuid.uuid4())
        return self.service

    def prepare(self, **kw):
        return self.service.prepare_review(**({'request_id':self.rid,'number':7,
            'expected_head_sha':self.fixture.source_head}|kw))

    def approve(self,decision='approve'):
        row=self.core._read(self.rid)
        return self.core.owner_decide(self.rid,decision,{'requestId':self.rid,
            'fingerprint':row['fingerprint'],'decision':decision})

    def test_original_review_retention_and_exact_replay(self):
        self.runtime()
        # Deliberately cross a second boundary between request insert and
        # audit insert. Later lifecycle uses strictly later deterministic time.
        t=int(time.time())+2
        ticks=iter(range(t,t+100))
        self.core.clock=lambda:next(ticks)
        row=self.prepare();self.assertEqual(row['state'],'PENDING')
        self.assertEqual(self.core._read(self.rid)['createdAt'],self.core.events(self.rid)[0]['at'])
        self.assertIn((rt.SERVICE,rt.BUNDLE_OPERATION),self.portal.strong_operations)
        with self.assertRaises(Denied):self.service.retain_merge(request_id=self.rid)
        with self.assertRaisesRegex(Denied,'IN_FLIGHT'):
            self.prepare(request_id=str(uuid.uuid4()))
        self.assertEqual(self.approve()['state'],'EXECUTED')
        decision=rt.read_bound_owner_decision(self.core,self.rid,owner='test-owner')
        self.fixture.merge()
        merged=decision['ownerExecutionAt']+1
        self.fixture.api.merged_at=datetime.fromtimestamp(merged,timezone.utc).isoformat()
        # Offline provider clock, not a runtime assertion about wall time.
        real=self.collector.retain
        with patch.object(self.collector,'retain',side_effect=lambda **k:real(**k,clock=lambda:merged+1)):
            receipt=self.service.retain_merge(request_id=self.rid)
        self.assertEqual(receipt['ownerRequestId'],self.rid)
        self.assertEqual(receipt['selectedMainSha'],self.fixture.selected)
        self.assertFalse(receipt['admissionAllowed'])
        self.assertEqual(self.collector_pin.read(),receipt['checkpoint'])
        with patch.object(self.fixture.adapter,'_api',side_effect=AssertionError('no recollection')):
            self.assertEqual(self.service.retain_merge(request_id=self.rid),receipt)
            self.assertEqual(self.prepare()['state'],'EXECUTED')
        self.assertEqual(self.capture_pin.read()['revision'],1)
        # Continue the newly orchestrated original evidence into the existing
        # exact source planner and schema-3 SQLite, never supply a plan DTO.
        for module in (state, journal, admission_plan, forward_lineage, component_bindings):
            self.enterContext(patch.object(module,'REPOSITORY',self.fixture.api.head_repo))
        baseline={'schemaVersion':1,'repository':self.fixture.api.head_repo,
            'enrollmentId':self.ref['enrollmentId'],'baselineSha':self.ref['baselineSha'],
            'catalogSha256':hashlib.sha256(self.fixture.api.sources['release/targets.yaml']).hexdigest(),
            'acceptanceReceiptDigest':self.ref['acceptanceReceiptDigest']}
        mapping={**{k:baseline[k] for k in ('schemaVersion','repository','enrollmentId','baselineSha','catalogSha256')},
            'bindings':[{'targetId':'app','environment':'production','componentId':'app-runtime'},
                        {'targetId':'dependency','environment':'production','componentId':'dep-runtime'}],
            'components':[{'id':'app-runtime','resources':['fixture-state'],'requires':['dep-runtime']},
                          {'id':'dep-runtime','resources':['fixture-state'],'requires':[]}]}
        baseline['bindingDigest']=rt._hash(mapping)
        scope={**{k:baseline[k] for k in ('repository','enrollmentId','baselineSha','catalogSha256','bindingDigest')},
               'baselineDigest':rt._hash(baseline),'policyReferenceDigest':self.pin}
        instance=str(uuid.uuid4());db=secure_dir(self.fixture.root/'registry-runtime')/'registry.sqlite'
        journal.FunctionalV1CandidateJournal.initialize(db,instance_id=instance,scope=scope,plan_reader=lambda _:None)
        comp=journal.OfflineSourceRangeComposition(path=db,instance_id=instance,scope=scope,
            adapter=self.fixture.adapter,journal=self.collector,validator=self.fixture.validator,
            baseline_reader=lambda:baseline,expected_baseline_digest=scope['baselineDigest'],
            policy_reader=self.reader,expected_policy_digest=self.pin,binding_reader=lambda:mapping,
            expected_collector_checkpoint=receipt['checkpoint'])
        operation=str(uuid.uuid4())
        result=comp.compose_and_append(operation_id=operation,expected_revision=0,
            selected_main_sha=receipt['selectedMainSha'],evidence_ids=[receipt['evidenceId']])
        self.assertEqual(result['storage']['result'],'LOCAL_DESIRED_CANDIDATE_COMMITTED')
        page=comp.candidate_page(limit=10)
        self.assertEqual(page['localRevision'],1)
        self.assertEqual(len(page['records']),1)
        self.assertIsNone(page['records'][0]['actual'])
        self.assertEqual(comp.operation(operation_id=operation),result['storage'])
        self.assertFalse(result['admissionAllowed'])

    def test_reject_and_pin_drift_do_not_retain(self):
        self.runtime();self.prepare();self.assertEqual(self.approve('reject')['state'],'REJECTED')
        with self.assertRaises(Denied):self.service.retain_merge(request_id=self.rid)
        self.assertEqual(self.collector_pin.read()['revision'],0)
        self.capture_pin.path.write_bytes(canonical({'revision':1,'eventDigest':'f'*64}).encode())
        with self.assertRaises(Denied):self.prepare(request_id=str(uuid.uuid4()))

    def test_pin_leftover_blocks_before_new_capture(self):
        self.runtime();self.capture_pin.path.with_name('capture.json.next').touch()
        with self.assertRaisesRegex(Denied,'OUTCOME_UNKNOWN'):self.prepare()
        self.assertEqual(self.fixture.store.checkpoint()['revision'],0)

    def test_owner_http_boundary(self):
        self.runtime()
        call=owner_input.OwnerPortalInputTests.call.__get__(self)
        body=canonical({'requestId':self.rid,'number':7,'headSha':self.fixture.source_head}).encode()
        path='/v1/owner/registry/review'
        for kwargs in ({'cookie':''},{'csrf':None},{'origin':'http://foreign.invalid'},{'host':'foreign.invalid'}):
            self.assertEqual(call(path,body,**kwargs)[0],403)
        self.portal.read_only_banner=True
        self.assertEqual(call(path,body)[0],403)
        self.portal.read_only_banner=False
        self.assertEqual(call(path,b'{}')[0],403)
        self.assertEqual(self.fixture.store.checkpoint()['revision'],0)
        code,row,_=call(path,body)
        self.assertEqual((code,row['state']),(200,'PENDING'))
        self.assertTrue(self.portal._owner_view(self.core._read(self.rid))['requiresStrongProof'])
        self.assertEqual(call('/v1/owner/registry/retain',canonical({'requestId':self.rid}).encode())[0],403)
        self.assertEqual(self.core._read(self.rid)['state'],'PENDING')

    def test_request_replay_changed_head_denied(self):
        self.runtime();self.prepare()
        with self.assertRaisesRegex(Denied,'ORIGINAL_REQUEST_CONFLICT'):
            self.prepare(expected_head_sha='f'*40)

if __name__=='__main__':unittest.main()

"""P5 integrated private capture -> Core ASK -> post-merge observation."""
import hashlib
from pathlib import Path
import tempfile
import unittest
import uuid

from fortis_approvals.core import Authenticator, Conflict, Core, Denied, Stale
from fortis_approvals.integrations.github.gateway.review_capture import ReviewCaptureStore
from fortis_approvals.integrations.github.gateway.review_attestation import (
    ACTOR, SERVICE, OPERATION, BUNDLE_OPERATION, ReviewAttestationAdapter,
    read_bound_owner_decision, review_policy,
)
from fortis_approvals.integrations.github.gateway.premerge_bundle import observe_reviewed_merge
from fortis_approvals.integrations.github.tests import test_path_ci_observation as path_fixture
from fortis_approvals.integrations.github.tests.test_review_attestation import TestVerifier
from fortis_approvals.integrations.github.tests.test_review_capture import BODY, DIGEST

HEAD, BASE, OWNER, REPO = (path_fixture.HEAD, path_fixture.BASE,
                          path_fixture.OWNER, path_fixture.REPOSITORY)
MERGE, TREE = 'c'*40, 'd'*40
CATALOG = b'schemaVersion: 1\nrepository: fortis-approvals\n'


class Provider(path_fixture.Provider):
    def __init__(self):
        super().__init__()
        self.body = BODY
        self.sources['release/targets.yaml'] = CATALOG
        self.merge_parent = BASE
        self.merged_at = '2099-01-01T00:00:00Z'

    def pr(self):
        result = super().pr()
        if self.merged:
            result.update(merged_at=self.merged_at, merge_commit_sha=MERGE)
        return result

    def request(self, method, path, **kw):
        suffix = path.split('/'+REPO,1)[1]
        if self.merged and suffix.startswith('/git/commits/'):
            sha = suffix.rsplit('/',1)[1]
            parents = [self.merge_parent, HEAD] if sha == MERGE else [BASE]
            self.calls.append((method,suffix,kw.get('params'),None))
            return {'sha':sha,'tree':{'sha':TREE},'parents':[{'sha':p} for p in parents]}
        if self.merged and suffix == '/branches/main':
            self.calls.append((method,suffix,kw.get('params'),None))
            return {'name':'main','commit':{'sha':MERGE},'protected':True}
        if self.merged and suffix == '/contents/release/targets.yaml':
            assert kw['params']=={'ref':MERGE}
            import base64
            data=self.sources['release/targets.yaml']
            self.calls.append((method,suffix,kw.get('params'),None))
            return {'path':'release/targets.yaml','type':'file','size':len(data),'encoding':'base64',
                    'content':base64.b64encode(data).decode(),
                    'sha':hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest()}
        return super().request(method,path,**kw)


class IntegratedCaptureTests(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory();self.addCleanup(tmp.cleanup);self.root=Path(tmp.name)
        self.api=Provider()
        self.adapter=path_fixture.AnalysisGitHubAdapter(self.api,owner=OWNER,repositories=[REPO],
            receipt_store=self.root/'receipts.sqlite',
            bindings={REPO:{'workflows':{str(w.ident):w.path for w in path_fixture.WORKFLOWS},
                            'projectKey':'fixture','allowCiControl':False}})
        self.store=ReviewCaptureStore.initialize(self.root/'capture.sqlite')
        self.kw=dict(operation_id=str(uuid.uuid4()),expected_revision=0,number=7,
                     expected_head_sha=HEAD,expected_base_sha=BASE,expected_body_sha256=DIGEST)

    def capture(self):
        return self.store.capture_bundle(self.adapter,**self.kw)

    def prepare(self, receipt, *, bundle=True):
        self.anchor=self.store.checkpoint()
        self.review=ReviewAttestationAdapter(store=self.store,provider=self.adapter,
                                           checkpoint_reader=lambda:self.anchor)
        self.core=Core(self.root/'core.sqlite',adapters={SERVICE:self.review},
                       policies={(SERVICE,OPERATION):review_policy,
                                 (SERVICE,BUNDLE_OPERATION):review_policy},
                       authenticator=Authenticator({'fixture':ACTOR}),owner_verifier=TestVerifier())
        params={'captureOperationId':receipt['operationId'],'captureEventDigest':receipt['eventDigest'],
                'number':7,'headSha':HEAD,'bodySha256':DIGEST,'checkpointDigest':self.anchor['eventDigest']}
        if bundle:
            params['bundleDigest']=receipt.get('bundleDigest','f'*64)
        self.payload={'requestId':str(uuid.uuid4()),'service':SERVICE,
                      'operation':BUNDLE_OPERATION if bundle else OPERATION,
                      'target':REPO,'params':params,'expectedVersion':self.anchor['revision'],
                      'reason':'Inspect retained pre-merge bundle'}
        return self.core.client('fixture','submit',self.payload)

    def decide(self,row):
        return self.core.owner_decide(row['requestId'],'approve',
              {'requestId':row['requestId'],'fingerprint':row['fingerprint'],'decision':'approve'})

    def merge(self):
        self.api.merged=True;self.api.state='closed'

    def read_merge(self):
        return observe_reviewed_merge(adapter=self.adapter,store=self.store,core=self.core,
              checkpoint_reader=lambda:self.anchor,owner='test-owner',
              owner_request_id=self.payload['requestId'],expected_merge_sha=MERGE,selected_main_sha=MERGE)

    def test_end_to_end_retained_bundle_and_merge(self):
        receipt=self.capture()
        self.assertEqual(receipt['result'],'PRE_MERGE_BUNDLE_RETAINED')
        self.assertNotIn(BODY,repr(receipt))
        material=self.store.retained_material(receipt['operationId'],expected_checkpoint=self.store.checkpoint())
        self.assertEqual(material['bundle']['catalog']['text'],CATALOG.decode())
        self.assertEqual(material['bundle']['pathCi']['paths']['count'],2)
        row=self.prepare(receipt)
        self.assertEqual(row['state'],'PENDING')
        self.assertEqual(row['preview']['purpose'],'ATTEST_RETAINED_PRE_MERGE_BUNDLE')
        self.assertNotIn(BODY,repr(row))
        self.assertEqual(self.decide(row)['state'],'EXECUTED')
        result=read_bound_owner_decision(self.core,row['requestId'],owner='test-owner')
        self.assertEqual(result['bundleDigest'],receipt['bundleDigest'])
        self.merge();self.api.body='mutable post-merge body'
        observed=self.read_merge()
        self.assertEqual(observed['result'],'REVIEWED_BUNDLE_MERGE_OBSERVED')
        for key in ('historicalMergeCutoffVerified','historicalPolicyVerified','requiredPolicySatisfied',
                    'evidenceVerified','admissionAllowed','deploymentAllowed'):
            self.assertIs(observed[key],False)
        self.assertNotIn(BODY,repr(observed))
        self.assertNotIn('mutable post-merge body',repr(observed))

    def test_bundle_replay_after_merge_and_body_only_collision(self):
        receipt=self.capture();calls=len(self.api.calls);self.merge()
        self.assertEqual(self.capture(),receipt)
        self.assertEqual(len(self.api.calls),calls)
        with self.assertRaises(Conflict):
            self.store.capture(self.adapter,**{k:v for k,v in self.kw.items() if k!='expected_base_sha'})

    def test_body_only_cannot_be_bundle(self):
        receipt=self.store.capture(self.adapter,**{k:v for k,v in self.kw.items() if k!='expected_base_sha'})
        with self.assertRaises(Denied):self.prepare(receipt)

    def test_bundle_cannot_use_body_review_operation(self):
        with self.assertRaises(Denied):self.prepare(self.capture(),bundle=False)

    def test_path_or_ci_drift_stops_owner_execution(self):
        row=self.prepare(self.capture())
        self.api.attempts[path_fixture.WORKFLOWS[0].ident]=2
        self.assertEqual(self.decide(row)['state'],'STALE')

    def test_bad_impact_or_catalog_leaves_no_record(self):
        self.api.body='missing markers'
        self.kw['expected_body_sha256']=hashlib.sha256(self.api.body.encode()).hexdigest()
        with self.assertRaisesRegex(Denied,'P5_BUNDLE_IMPACT_MARKERS_INVALID'):self.capture()
        self.api.body=BODY;self.kw['expected_body_sha256']=DIGEST
        self.api.sources['release/targets.yaml']=b'\xff'
        with self.assertRaisesRegex(Denied,'P5_BUNDLE_CATALOG_ENCODING'):self.capture()
        self.assertEqual(self.store.checkpoint()['revision'],0)

    def test_merge_base_or_catalog_drift_stops(self):
        self.assertEqual(self.decide(self.prepare(self.capture()))['state'],'EXECUTED')
        self.merge();self.api.merge_parent='f'*40
        with self.assertRaisesRegex(Denied,'P5_MERGE_BASE_OR_CATALOG_CHANGED'):self.read_merge()
        self.api.merge_parent=BASE;self.api.sources['release/targets.yaml']+=b'changed'
        with self.assertRaisesRegex(Denied,'P5_MERGE_BASE_OR_CATALOG_CHANGED'):self.read_merge()

    def test_merge_before_owner_execution_denied(self):
        self.assertEqual(self.decide(self.prepare(self.capture()))['state'],'EXECUTED')
        self.merge();self.api.merged_at='2000-01-01T00:00:00Z'
        with self.assertRaisesRegex(Denied,'P5_MERGE_REVIEW_ORDER_UNPROVEN'):self.read_merge()

"""Source contract tests; not live auth, storage or collector admission."""
import copy
import hashlib
import unittest
from unittest.mock import patch

from fortis_approvals.core import Authenticator, Denied, canonical
from fortis_approvals.registry import boundary as b

EVIDENCE='aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'
OPERATION='bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'


def digest(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def snapshot(*, classification='deployment', external=False, pr=False):
    impact={'repository':b.REPOSITORY,'number':7,'validatedImpact':{'classification':classification}}
    observation={'repository':b.REPOSITORY,'number':7,'selectedMainSha':'a'*40,
                 'retainedImpact':impact,'retainedImpactSha256':digest(impact),
                 'unresolvedExternalTargets':[{'repository':'external','target':'app'}] if external else [],
                 'unresolvedPullRequests':[{'repository':'fortis-approvals','number':6}] if pr else []}
    result={'result':'SELECTED_MAIN_LOCAL_SOURCE_BOUND','observation':observation,
            'observationDigest':digest(observation),'missingProofs':[],
            **{flag:False for flag in b.FLAGS}}
    return {'schemaVersion':1,'issuer':b.COLLECTOR,'repository':b.REPOSITORY,
            'evidenceId':EVIDENCE,'result':result}


class RegistryBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.auth=Authenticator({'planner':b.PLANNER,'reader':b.READER,'collector':b.COLLECTOR,
                                 'repo':'repo-sonar-read-proposal-actor','publisher':'publisher'})
        self.snapshot=snapshot()
        self.calls=[]
        def read(ident):
            self.calls.append(ident)
            return copy.deepcopy(self.snapshot)
        self.boundary=b.RegistryBoundary(authenticator=self.auth,evidence_reader=read)

    def raw(self, op, **params):
        return canonical({'operation':op,'params':{'repository':b.REPOSITORY,**params}}).encode()

    def preview(self, credential='reader', **params):
        payload={'evidenceId':EVIDENCE,'evidenceDigest':digest(self.snapshot),**params}
        return self.boundary.dispatch(credential,self.raw('registry.preview_merged',**payload))

    def test_capabilities_source_only(self):
        for credential in ('reader','planner'):
            r=self.boundary.dispatch(credential,self.raw('registry.capabilities'))
            self.assertEqual(r['activationState'],'SOURCE_ONLY')
            self.assertEqual(r['liveOperations'],[])
            self.assertFalse(r['writeEnabled'])
            self.assertFalse(r['storeAvailable'])
            self.assertFalse(r['authenticatedCollectorAvailable'])

    def test_default_deny_other_principals(self):
        for credential in ('collector','repo','publisher','unknown',None,[]):
            with self.subTest(credential=credential), self.assertRaisesRegex(Denied,'REGISTRY_ACTOR_DENIED'):
                self.preview(credential)
        self.assertEqual(self.calls,[])

    def test_scope_and_actor_injection(self):
        for params in ({'repository':'AlexPastukhh/fortis-container'}, {'repository':'fortis-approvals'},
                       {'actor':b.PLANNER},{'observation':{}},{'selectedMainSha':'f'*40},
                       {'complete':True},{'environment':'production'},{'path':'/state'}):
            with self.subTest(params=params),self.assertRaises(Denied):self.preview(**params)
        self.assertEqual(self.calls,[])

    def test_strict_json_rejects_duplicates_unknown_and_size(self):
        for raw in (b'{"operation":"registry.capabilities","operation":"registry.capabilities","params":{}}',
                    b'{"operation":"registry.capabilities","params":{"repository":"a","repository":"b"}}',
                    b'{"operation":"registry.capabilities","params":{},"actor":"reader"}',
                    b'{"operation": [],"params":{}}',b'\xff',b'['*4097,b'{"params":NaN}'):
            with self.subTest(raw=raw[:60]),self.assertRaises(Denied):
                self.boundary.dispatch('reader',raw)
        for op in ('registry.deploy','registry.report_manual_complete','registry.verify_actual',
                   'github.create_deployment','registry.query'):
            with self.assertRaisesRegex(Denied,'REGISTRY_OPERATION_UNSUPPORTED'):
                self.boundary.dispatch('reader',self.raw(op))

    def test_blocked_preview_and_no_deployment_not_admitted(self):
        for classification in ('deployment','no-deployment'):
            self.snapshot=snapshot(classification=classification)
            r=self.preview()
            self.assertEqual(r['result'],'BLOCKED_EVIDENCE_GAP')
            self.assertEqual(r['observedClassification'],classification)
            self.assertEqual(r['evidenceClass'],'SOURCE_CANDIDATE_ONLY')
            self.assertEqual(set(r['missingProofs']),set(b.MISSING))
            for key in ('evidenceVerified','admissionAllowed','deploymentAllowed'):
                self.assertIs(r[key],False)
            for key in ('records','recordCount','actual','noDeploymentOnly','receipt'):
                self.assertNotIn(key,r)
        self.assertEqual(self.calls,[EVIDENCE,EVIDENCE])

    def test_unresolved_external_and_pr(self):
        self.snapshot=snapshot(external=True,pr=True)
        r=self.preview()
        self.assertIn('EXTERNAL_TARGET_DEPENDENCY_UNRESOLVED',r['missingProofs'])
        self.assertIn('PR_DEPENDENCY_UNRESOLVED',r['missingProofs'])

    def test_identity_and_digest_mismatch(self):
        with self.assertRaisesRegex(Denied,'REGISTRY_EVIDENCE_DIGEST_MISMATCH'):
            self.preview(evidenceDigest='f'*64)
        for field,value in (('repository','other/repo'),('issuer',b.PLANNER),('evidenceId',OPERATION),('schemaVersion',True)):
            self.snapshot=snapshot();self.snapshot[field]=value
            with self.assertRaisesRegex(Denied,'REGISTRY_EVIDENCE_IDENTITY_MISMATCH'):
                self.preview()
        self.snapshot=snapshot();self.snapshot['result']['observation']['number']=8
        with self.assertRaisesRegex(Denied,'REGISTRY_EVIDENCE_INVALID'):self.preview()

    def test_forged_positive_flags_never_admitted(self):
        for flag in b.FLAGS:
            self.snapshot=snapshot();self.snapshot['result'][flag]=True
            with self.subTest(flag=flag),self.assertRaisesRegex(Denied,'REGISTRY_EVIDENCE_UNSUPPORTED'):
                self.preview()

    def test_no_reader_and_failure_are_unavailable_not_empty(self):
        def bad(_):
            raise RuntimeError('private error')
        for reader in (None,lambda _:None,bad):
            self.boundary=b.RegistryBoundary(authenticator=self.auth,evidence_reader=reader)
            with self.assertRaisesRegex(Denied,'^REGISTRY_EVIDENCE_UNAVAILABLE$'):self.preview()

    def test_revocation_during_read(self):
        def read(_):
            self.auth.revoke('reader')
            return self.snapshot
        self.boundary=b.RegistryBoundary(authenticator=self.auth,evidence_reader=read)
        with self.assertRaisesRegex(Denied,'REGISTRY_ACTOR_DENIED'):self.preview()

    def test_receipt_and_queue_reads_unavailable(self):
        for credential in ('reader','planner'):
            for op,params in (('registry.get_operation',{'operationId':OPERATION}),
                              ('registry.get_record',{'recordId':'a'*64}),
                              ('registry.list_records',{'limit':100,'cursor':None})):
                with self.subTest(op=op,credential=credential),self.assertRaisesRegex(Denied,'REGISTRY_STORAGE_UNAVAILABLE'):
                    self.boundary.dispatch(credential,self.raw(op,**params))
        self.assertEqual(self.calls,[])

    def test_closed_write_schema_and_no_effect(self):
        params=dict(operationId=OPERATION,evidenceId=EVIDENCE,evidenceDigest=digest(self.snapshot),expectedRevision=0)
        raw=self.raw(b.INGEST,**params)
        self.assertEqual(b.parse_request(raw)[0],b.INGEST)
        with self.assertRaisesRegex(Denied,'REGISTRY_WRITE_DISABLED'):
            self.boundary.dispatch('planner',raw)
        with self.assertRaisesRegex(Denied,'REGISTRY_ACTOR_DENIED'):
            self.boundary.dispatch('reader',raw)
        for changes in ({'expectedRevision':False},{'expectedRevision':-1},{'expectedRevision':2**63},
                        {'operationId':'bad'},{'evidenceDigest':'A'*64},{'preview':{}},{'actions':[]}):
            with self.subTest(changes=changes),self.assertRaises(Denied):
                self.boundary.dispatch('planner',self.raw(b.INGEST,**(params|changes)))
        self.assertEqual(self.calls,[])

    def test_cursor_and_record_bounds(self):
        for op,params in (('registry.list_records',{'limit':True,'cursor':None}),
                          ('registry.list_records',{'limit':101,'cursor':None}),
                          ('registry.list_records',{'limit':1,'cursor':'../secret'}),
                          ('registry.get_operation',{'operationId':'a'*40}),
                          ('registry.get_record',{'recordId':'g'*64})):
            with self.subTest(op=op,params=params),self.assertRaisesRegex(Denied,'REGISTRY_PARAMS_INVALID'):
                self.boundary.dispatch('reader',self.raw(op,**params))

    def test_actual_composed_selected_main_is_still_blocked(self):
        # Existing real Git/Core capture/merge fixture; its synthetic owner is
        # deliberately not the production canonical owner. Patch only fixture
        # scope so we test actual composition output, never a live source.
        from fortis_approvals.integrations.github.tests.test_selected_main_binding import SelectedMainTests
        fixture=SelectedMainTests()
        self.addCleanup(fixture.doCleanups)
        fixture.setup_case(external=True)
        fixture.approve()
        result=fixture.observe()
        with patch.object(b,'REPOSITORY',result['observation']['repository']):
            self.snapshot={'schemaVersion':1,'issuer':b.COLLECTOR,'repository':b.REPOSITORY,
                           'evidenceId':EVIDENCE,'result':result}
            r=self.preview()
            self.assertEqual(r['result'],'BLOCKED_EVIDENCE_GAP')
            self.assertIn('EXTERNAL_TARGET_DEPENDENCY_UNRESOLVED',r['missingProofs'])
            self.assertEqual(r['selectedMainSha'],fixture.selected)
            self.assertFalse(r['admissionAllowed'])

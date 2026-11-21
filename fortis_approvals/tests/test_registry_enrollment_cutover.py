"""First enrollment cutover offline candidate: no protected credentials or live state."""
import copy
from pathlib import Path
import tempfile
import unittest
import uuid

from fortis_approvals.core import Denied, Stale
from fortis_approvals.registry import enrollment_cutover as cut
from fortis_approvals.registry import owner_runtime_isolation as runtime
from fortis_approvals.registry import owner_storage_denial as denial
from fortis_approvals.registry import checkpoint_cas as owner_cas
from fortis_approvals.registry import state_journal_v2 as v2
from fortis_approvals.tests.test_registry_state_journal import sample


def uid():
    return str(uuid.uuid4())


class EnrollmentCutoverTests(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory();self.addCleanup(tmp.cleanup)
        self.root=Path(tmp.name)
        self.owner_dir=self.root/'owner'
        self.registry_dir=self.root/'registry'
        self.owner_dir.mkdir(mode=0o700);self.registry_dir.mkdir(mode=0o700)
        self.owner_path=self.owner_dir/'checkpoint.sqlite'
        self.registry_path=self.registry_dir/'state.sqlite'
        self.instance=uid()
        self.baseline={'schemaVersion':1,'repository':cut.REPOSITORY,
                       'enrollmentId':uid(),'baselineSha':'a'*40,
                       'catalogSha256':'b'*64,'acceptanceReceiptDigest':'e'*64,
                       'bindingDigest':'c'*64}
        self.baseline_digest=cut._hash(self.baseline)
        self.scope={'repository':cut.REPOSITORY,
                    'enrollmentId':self.baseline['enrollmentId'],
                    'baselineSha':self.baseline['baselineSha'],
                    'baselineDigest':self.baseline_digest,
                    'catalogSha256':self.baseline['catalogSha256'],
                    'bindingDigest':self.baseline['bindingDigest'],
                    'policyReferenceDigest':'d'*64}
        self.source_plan=sample(self.scope)
        self.owner=owner_cas.OfflineCheckpointCAS.initialize(
            self.owner_path,instance_id=self.instance,scope=self.scope,
            enrollment_receipt_digest=self.baseline['acceptanceReceiptDigest'],
            registered_registry_path=self.registry_path)
        self.store=v2.RegistryStateJournalV2.initialize(
            self.registry_path,instance_id=self.instance,scope=self.scope,
            anchor_reader=self.owner.read_checkpoint,plan_reader=self.read_plan)
        self.current_sha=self.baseline['baselineSha']
        self.peer={'schemaVersion':1,'transport':'linux-af-unix-stream-so-peercred-v1',
                   'socketPath':str(self.root/'socket'/'owner.sock'),
                   'instanceId':self.instance,'scopeDigest':cut._hash(self.scope),
                   'enrollmentReceiptDigest':self.baseline['acceptanceReceiptDigest'],
                   'authorityUid':11101,'authorityGid':11101,'socketGid':11104,
                   'registryUid':11102,'registryGid':11102,
                   'operatorUid':11105,'operatorGid':11105}
        self.profile_digest=cut._hash(self.peer)
        self.layout={'schemaVersion':1,
                     'format':'owner-registry-linux-layout-candidate-v1',
                     'peerProfileDigest':self.profile_digest,'instanceId':self.instance,
                     'scopeDigest':cut._hash(self.scope),'bootId':uid(),
                     'ownerPid':1011,'registryPid':1012,'repoPid':1013,
                     'ownerStatePath':str(self.owner_path),
                     'registryStatePath':str(self.registry_path),
                     'repoUid':11103,'repoGid':11103}
        self.layout_digest=cut._hash(self.layout)
        self.processes={}
        for i,role in enumerate(('owner','registry','repo')):
            label={'owner':'authority','registry':'registry','repo':'repo'}[role]
            pid=self.layout[role+'Pid']
            user=(self.layout['repoUid'] if role=='repo' else self.peer[label+'Uid'])
            group=(self.layout['repoGid'] if role=='repo' else self.peer[label+'Gid'])
            self.processes[role]={'pid':pid,'startTicks':100+i,
                 'uids':[user]*4,'gids':[group]*4,'groups':[group],
                 'capInh':0,'capPrm':0,'capEff':0,'capBnd':0,'capAmb':0,
                 'noNewPrivs':1,'seccomp':2,'tracerPid':0,
                 'mountNamespace':f'mnt:[{1000+i}]',
                 'cgroup':f'0::/independent/{role}'}
        self.files={}
        for role,dev in [('owner',1001),('registry',2002)]:
            label='authority' if role=='owner' else role
            self.files[role]={'path':self.layout[role+'StatePath'],
               'parentUid':self.peer[label+'Uid'],'parentGid':self.peer[label+'Gid'],
               'fileUid':self.peer[label+'Uid'],'fileGid':self.peer[label+'Gid'],
               'parentMode':0o700,'fileMode':0o600,
               'parentDev':dev,'fileDev':dev,'parentInode':dev+10,'fileInode':dev+20}
        self.isolation=runtime._assess(self.layout,self.peer,self.processes,
                                       self.files,(90,92))
        self.denials={}
        for role in ('registry','repo'):
            evidence={'schemaVersion':1,
                  'format':'registry-owner-storage-denial-v1',
                  'role':role,'instanceId':self.instance,
                  'scopeDigest':cut._hash(self.scope),
                  'enrollmentReceiptDigest':self.owner.enrollment_receipt_digest,
                  'peerProfileDigest':self.profile_digest,
                  'layoutDigest':self.layout_digest,
                  'bootId':self.layout['bootId'],
                  'ownerStatePath':str(self.owner.path),
                  'process':copy.deepcopy(self.processes[role]),
                  'attempts':{key:'EACCES' for key in denial._ATTEMPT_NAMES}}
            self.denials[role]={'result':'OWNER_STORAGE_DENIAL_OBSERVATION_CANDIDATE',
                 'evidence':evidence,'evidenceDigest':cut._hash(evidence),
                 **{key:False for key in denial._REQUIRED_FALSE}}

    def read_plan(self,eid):
        self.assertEqual(eid,self.source_plan['evidenceId'])
        return copy.deepcopy(self.source_plan)

    def payload(self):
        return dict(store=self.store,owner=self.owner,
                    baseline_reader=lambda:copy.deepcopy(self.baseline),
                    expected_baseline_digest=self.baseline_digest,
                    selected_main_reader=lambda:{'repository':cut.REPOSITORY,
                                                 'branch':'main','sha':self.current_sha},
                    peer_profile_reader=lambda:copy.deepcopy(self.peer),
                    expected_peer_profile_digest=self.profile_digest,
                    layout_reader=lambda:copy.deepcopy(self.layout),
                    expected_layout_digest=self.layout_digest,
                    isolation_observation=copy.deepcopy(self.isolation),
                    registry_denial_observation=copy.deepcopy(self.denials['registry']),
                    repo_denial_observation=copy.deepcopy(self.denials['repo']))

    def inspect(self,**updates):
        return cut.inspect_first_enrollment(**(self.payload()|updates))

    def test_candidate_genesis_stable_exact_source(self):
        result=self.inspect()
        self.assertEqual(result['result'],'FIRST_ENROLLMENT_CUTOVER_PREFLIGHT_CANDIDATE')
        self.assertEqual(result['observation']['baselineSha'],'a'*40)
        self.assertEqual(result['observation']['ownerCheckpoint'],self.store.initial)
        self.assertEqual(result['observation']['ownerOperationCount'],0)
        self.assertEqual(result['observation']['registryOperationCount'],0)
        self.assertEqual(result['observationDigest'],cut._hash(result['observation']))
        self.assertEqual(self.inspect(),result)
        for flag in ('originalHostEvidenceAuthenticated','ownerAcceptanceVerified',
                     'protectedCheckpointVerified','runtimeActivated',
                     'enrollmentAllowed','registryWriteAllowed','admissionAllowed'):
            self.assertIs(result[flag],False)

    def test_source_main_ahead_and_behind_never_rebaseline(self):
        for value in ('b'*40,'0'*40):
            self.current_sha=value
            with self.subTest(value=value),self.assertRaisesRegex(
                    Denied,'REGISTRY_ENROLLMENT_MAIN_CHANGED'):
                self.inspect()
        self.current_sha='a'*40
        self.assertEqual(self.inspect()['observation']['baselineSha'],'a'*40)

    def test_original_baseline_receipt_and_scope_exact(self):
        changed=copy.deepcopy(self.baseline);changed['acceptanceReceiptDigest']='f'*64
        with self.assertRaisesRegex(Denied,'REGISTRY_ENROLLMENT_BASELINE_MISMATCH'):
            self.inspect(baseline_reader=lambda:changed)
        changed={**self.baseline,'baselineSha':'b'*40}
        with self.assertRaisesRegex(Denied,'REGISTRY_ENROLLMENT_BASELINE_MISMATCH'):
            self.inspect(baseline_reader=lambda:changed)
        with self.assertRaisesRegex(Denied,'REGISTRY_ENROLLMENT_BASELINE_MISMATCH'):
            self.inspect(expected_baseline_digest='f'*64)

    def test_no_enrollment_against_locally_pending_registry_commit(self):
        request={'actor':v2.PLANNER,'operation_id':uid(),
                 'evidence_id':self.source_plan['evidenceId'],
                 'evidence_digest':cut._hash(self.source_plan),'expected_revision':0}
        self.assertEqual(self.store.append_range(**request)['result'],'UNKNOWN_OUTCOME')
        with self.assertRaisesRegex(Denied,'REGISTRY_ENROLLMENT_NONEMPTY_OR_UNANCHORED'):
            self.inspect()
        self.assertEqual(self.owner.read_checkpoint()['revision'],0)

    def test_not_allowed_on_advanced_anchored_owner_and_registry(self):
        request={'actor':v2.PLANNER,'operation_id':uid(),
                 'evidence_id':self.source_plan['evidenceId'],
                 'evidence_digest':cut._hash(self.source_plan),'expected_revision':0}
        pending=self.store.append_range(**request)
        self.owner.advance(operation_id=request['operation_id'],
            previous_checkpoint=pending['previousCheckpoint'],
            next_checkpoint=pending['pendingCheckpoint'],
            pending_reader=self.store.operation)
        with self.assertRaisesRegex(Denied,'REGISTRY_ENROLLMENT_NONEMPTY_OR_UNANCHORED'):
            self.inspect()
        self.assertEqual(self.owner.read_checkpoint()['revision'],1)

    def test_wrong_store_owner_path_and_original_reader_binding(self):
        wrong=self.payload()
        original=self.owner.registered_registry_path
        self.owner.registered_registry_path=self.root/'wrong.sqlite'
        with self.assertRaisesRegex(Denied,'REGISTRY_RECOVERY_SOURCE_BOUNDARY_REQUIRED'):
            cut.inspect_first_enrollment(**wrong)
        self.owner.registered_registry_path=original
        original_reader=self.store.anchor_reader
        self.store.anchor_reader=lambda:self.owner.read_checkpoint()
        with self.assertRaisesRegex(Denied,'REGISTRY_RECOVERY_SOURCE_BOUNDARY_REQUIRED'):
            self.inspect()
        self.store.anchor_reader=original_reader

    def test_isolation_result_cannot_claim_positive_authority(self):
        forged=copy.deepcopy(self.isolation)
        forged['protectedAnchorVerified']=True
        with self.assertRaisesRegex(Denied,'REGISTRY_ENROLLMENT_ISOLATION_INVALID'):
            self.inspect(isolation_observation=forged)
        forged=copy.deepcopy(self.isolation)
        forged['observation'].pop('socketDev')
        with self.assertRaisesRegex(Denied,'REGISTRY_ENROLLMENT_ISOLATION_INVALID'):
            self.inspect(isolation_observation=forged)
        forged=copy.deepcopy(self.isolation)
        forged['observation']['processes']['registry']['capEff']=1
        forged['observationDigest']=cut._hash(forged['observation'])
        with self.assertRaises(Denied):self.inspect(isolation_observation=forged)

    def test_owner_volume_path_was_not_verified_by_hardware_identity(self):
        layout={**self.layout,'ownerStatePath':'/invented/checkpoint.sqlite'}
        layout_digest=cut._hash(layout)
        with self.assertRaises(Denied):
            self.inspect(layout_reader=lambda:layout,
                         expected_layout_digest=layout_digest)
        self.assertFalse(self.inspect()['originalHostEvidenceAuthenticated'])

    def test_denial_missing_or_wrong_role_or_faked_permission(self):
        for role in ('registry','repo'):
            bad=copy.deepcopy(self.denials[role])
            bad['evidence']['attempts']['ownerDbReadWrite']='ENOENT'
            bad['evidenceDigest']=cut._hash(bad['evidence'])
            field=role+'_denial_observation'
            with self.subTest(role=role),self.assertRaisesRegex(
                    Denied,'REGISTRY_DENIAL_EVIDENCE_INVALID'):
                self.inspect(**{field:bad})
        with self.assertRaisesRegex(Denied,'REGISTRY_DENIAL_EVIDENCE_INVALID'):
            self.inspect(registry_denial_observation=self.denials['repo'])

    def test_denial_and_isolation_processes_must_match(self):
        bad=copy.deepcopy(self.denials['registry'])
        bad['evidence']['process']['startTicks']+=1
        bad['evidenceDigest']=cut._hash(bad['evidence'])
        with self.assertRaisesRegex(Denied,'REGISTRY_ENROLLMENT_DENIAL_PROCESS_MISMATCH'):
            self.inspect(registry_denial_observation=bad)

    def test_reader_changes_mid_preflight_blocked(self):
        calls=[0]
        def current():
            calls[0]+=1
            if calls[0]>1:return {'repository':cut.REPOSITORY,'branch':'main','sha':'b'*40}
            return {'repository':cut.REPOSITORY,'branch':'main','sha':'a'*40}
        with self.assertRaises(Denied):
            self.inspect(selected_main_reader=current)

    def test_baseline_or_layout_changed_mid_preflight_blocked(self):
        calls=[0]
        def changing_layout():
            calls[0]+=1
            if calls[0]>1:return {**self.layout,'repoPid':self.layout['repoPid']+1}
            return copy.deepcopy(self.layout)
        with self.assertRaises(Denied):
            self.inspect(layout_reader=changing_layout)

    def test_no_side_effect_any_success_or_error(self):
        before_owner=self.owner.read_checkpoint()
        before_registry=self.store.checkpoint()
        for _ in range(3):
            self.assertFalse(self.inspect()['registryWriteAllowed'])
        self.assertEqual(self.owner.read_checkpoint(),before_owner)
        self.assertEqual(self.store.checkpoint(),before_registry)

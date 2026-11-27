"""Actual isolated Core/Repo ingress freeze byte checks and record pins."""
import copy
import fcntl
import os
import stat
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from fortis_approvals.core import Denied, Core
from fortis_approvals.extensions.maintenance_core import MaintenanceCoreMixin
from fortis_approvals.extensions.maintenance_gate import MaintenanceGate, Coordinate
from fortis_approvals.extensions.maintenance_ingress import MaintenanceIngress, RouteAdmission, owner_passive_route
from fortis_approvals.deploy import github_pilot_helpers
from fortis_approvals.extensions import maintenance_interlock_reader as interlock
from fortis_approvals.extensions.maintenance_interlock_reader import read_owner_interlock
from fortis_approvals.integrations.registry_contracts import maintenance_contract as mc
from fortis_approvals.integrations.registry_contracts import maintenance_evidence as me
from fortis_approvals.integrations.registry_contracts import maintenance_seal as seal
from fortis_approvals.integrations.registry_contracts import semantic_contract as sc
from fortis_approvals.tests import test_maintenance_gate as fixture
from fortis_approvals.tests import test_core as core_fixture
from fortis_approvals.tests.test_registry_state_journal import uid
from fortis_approvals.tests.test_registry_semantic_contract import begin


def blocked_fixture():
    ctrl=fixture.Controller(uid(),'a'*64)
    b=begin()
    attempt={'attemptId':uid(),'subject':b['subject'],'source':b['source'],
             'restrictionDigest':'c'*64,'sourceGeneration':fixture.OLD,'targetGeneration':fixture.NEW}
    ctrl.advance('DRAINING',attempt=attempt)
    holds={'instanceId':ctrl.record['registryInstanceId'],'scopeDigest':ctrl.record['scopeDigest'],
           'snapshotRevision':1,'eventDigest':'a'*64,'holds':[
            {k:attempt[k] for k in ('attemptId','subject','source','restrictionDigest')} |
            {'stateFreeze':True,'blockedOperations':[]}]}
    return ctrl,holds


def gate_for(ctrl,holds,generation=fixture.OLD):
    return MaintenanceGate(instance_id=ctrl.record['registryInstanceId'],
        scope_digest=ctrl.record['scopeDigest'],generation=generation,
        read_interlock=ctrl.read,read_holds=lambda:copy.deepcopy(holds))


class BoundaryCore(MaintenanceCoreMixin,Core):
    pass


class CoreBoundaryTests(unittest.TestCase):
    setUp=core_fixture.G1Test.setUp
    new_core=core_fixture.G1Test.new_core
    request=core_fixture.G1Test.request

    def test_existing_core_direct_admission_fence_preserves_bytes(self):
        request=self.request()
        pending=self.core.client('client-1-secret','submit',request)
        core=BoundaryCore(self.core.path,adapters=self.core.adapters,policies=self.policies,
                  authenticator=self.auth,owner_verifier=self.owner,clock=lambda:self.now)
        ctrl,holds=blocked_fixture()
        core.bind_maintenance(gate_for(ctrl,holds))
        original={p.name:p.read_bytes() for p in self.path.glob('*.sqlite')}
        with self.assertRaisesRegex(Denied,'RELEASE_MAINTENANCE'):
            core.client('client-1-secret','submit',self.request(op='set_free'))
        with self.assertRaisesRegex(Denied,'RELEASE_MAINTENANCE'):
            core.owner_decide(pending['requestId'],'approve',
                 self.owner.proof(pending['requestId'],pending['fingerprint'],'approve'))
        with self.assertRaisesRegex(Denied,'RELEASE_MAINTENANCE'):
            core.execute(pending['requestId'])
        with self.assertRaisesRegex(Denied,'POLICY_DENIED'):
            core.client('client-1-secret','submit',self.request(op='set_deny'))
        self.assertEqual(core.client('client-1-secret','status',pending['requestId'])['state'],'PENDING')
        self.assertEqual(original,{p.name:p.read_bytes() for p in self.path.glob('*.sqlite')})

    def test_normal_core_retains_ask_and_allow(self):
        ctrl=fixture.Controller(uid(),'a'*64)
        holds={'instanceId':ctrl.record['registryInstanceId'],'scopeDigest':'a'*64,
               'snapshotRevision':0,'eventDigest':'b'*64,'holds':[]}
        core=BoundaryCore(self.core.path,adapters=self.core.adapters,policies=self.policies,
                  authenticator=self.auth,owner_verifier=self.owner,clock=lambda:self.now)
        core.bind_maintenance(gate_for(ctrl,holds))
        self.assertEqual(core.client('client-1-secret','submit',self.request(op='set_free'))['state'],
                         'EXECUTED')


class IngressBoundaryTests(unittest.TestCase):
    def test_unknown_routes_blocked_no_delegate_or_audit(self):
        ctrl,holds=blocked_fixture()
        calls=[]
        app=MaintenanceIngress(lambda env,start:calls.append(env) or [b'pass'],gate_for(ctrl,holds),
              classify=lambda env:RouteAdmission(owner_passive_route(env)))
        paths=['/v1/reads','/v1/integrations/call','/v1/integrations/result',
            '/v1/workspace/submit','/v1/workspace/claim','/v1/workspace/finish',
            '/v1/workspace/heartbeat','/v1/workspace/reconcile','/v1/git/artifact',
            '/v1/github/visual-review/stage','/v1/login/finish','/v1/enroll/finish',
            '/v1/owner/decision/finish','/v1/owner/policy/finish','/unclassified']
        for path in paths:
            response=[]
            raw=b''.join(app({'REQUEST_METHOD':'POST','PATH_INFO':path,
                'HTTP_X_FORTIS_REASON':'controller completion'},
                lambda status,headers:response.append(status)))
            self.assertTrue(response[0].startswith('403'))
            self.assertEqual(sc.loads_strict(raw),{'error':'RELEASE_MAINTENANCE'})
        self.assertFalse(calls)
        self.assertEqual(b''.join(app({'REQUEST_METHOD':'GET','PATH_INFO':'/'},lambda *_:None)),b'pass')
        self.assertEqual(len(calls),1)

    def test_auth_failure_precedes_hold_diagnostic(self):
        ctrl,holds=blocked_fixture()
        def deny(_):raise Denied('scope')
        app=MaintenanceIngress(lambda *_:self.fail('delegate'),gate_for(ctrl,holds),classify=deny)
        self.assertEqual(sc.loads_strict(b''.join(app({},lambda *_:None))),{'error':'POLICY_DENIED'})

    def test_close_before_iteration_releases_reservation(self):
        ctrl=fixture.Controller(uid(),'a'*64)
        holds={'instanceId':ctrl.record['registryInstanceId'],'scopeDigest':'a'*64,
               'snapshotRevision':0,'eventDigest':'a'*64,'holds':[]}
        gate=gate_for(ctrl,holds)
        app=MaintenanceIngress(lambda *_:[b'bytes'],gate,classify=lambda _:RouteAdmission(False))
        response=app({},lambda *_:None)
        self.assertEqual(gate.drain_status()['reservations'],1)
        response.close()
        self.assertEqual(gate.drain_status()['reservations'],0)


class RecordEvidenceTests(unittest.TestCase):
    def test_structural_transition_and_generation_pin(self):
        ctrl,holds=blocked_fixture()
        rec=ctrl.record
        with self.assertRaises(Denied):
            mc.validate_transition(rec,{**rec,'sequence':rec['sequence']+1,
                 'phase':'NORMAL','previousDigest':sc.digest(rec)})
        with self.assertRaises(Denied):
            mc.bind_record(rec,instance_id=rec['registryInstanceId'],scope_digest=rec['scopeDigest'],
                           generation=fixture.NEW,expected_digest=ctrl.pin)

    def test_readonly_record_reader_denies_missing_symlink_and_unreviewed_mount(self):
        ctrl,_=blocked_fixture()
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)/'interlock'
            root.mkdir()
            args=dict(instance_id=ctrl.record['registryInstanceId'],
                      scope_digest=ctrl.record['scopeDigest'],generation=fixture.OLD,
                      expected_digest=ctrl.pin,root=root)
            with self.assertRaises(Denied):read_owner_interlock(**args)
            # No real protected mount in this unit test.
            with patch('fortis_approvals.extensions.maintenance_interlock_reader._check_owner_readonly_mount'):
                root.chmod(0o555)
                with self.assertRaises(Denied):read_owner_interlock(**args)

    def test_freeze_binding_refuses_pending_and_unreviewed_composite_unknown(self):
        ctrl,holds=blocked_fixture()
        drain=gate_for(ctrl,holds).drain_status()
        state={'sha256':{'approvals.sqlite':'a'*64},'summary':{
            'requestStates':{'EXECUTED':1},'uncertainRequestIds':[],'approvedRequestIds':[],
            'native':{'jobStates':{'DONE':1},'preservedClaimedIds':[]}}}
        companion={'schemaVersion':1,'parentStates':{'EXECUTED':1}}
        args=dict(expected_registry_digest=sc.digest(holds),expected_state_digest=sc.digest(state),
                  expected_companion_digest=sc.digest(companion),worker_attestation_digest='f'*64,
                  preserved_uncertain_ids=[],preserved_claimed_ids=[])
        self.assertEqual(seal.freeze_binding(ctrl.record,drain,state,companion,**args)['result'],
                         'FREEZE_BINDINGS_MATCH_ONLY')
        changed=copy.deepcopy(state)
        changed['summary']['requestStates']['PENDING']=1
        with self.assertRaises(Denied):
            seal.freeze_binding(ctrl.record,drain,changed,companion,
                                **{**args,'expected_state_digest':sc.digest(changed)})
        unknown={'schemaVersion':1,'parentStates':{'UNCERTAIN':1}}
        with self.assertRaises(Denied):
            seal.freeze_binding(ctrl.record,drain,state,unknown,
                                **{**args,'expected_companion_digest':sc.digest(unknown)})
        self.assertEqual(seal.same_seal(state,state,expected_digest=sc.digest(state)),
                         'SEALED_STATE_MATCH_ONLY')
        with self.assertRaises(Denied):
            seal.same_seal(state,changed,expected_digest=sc.digest(state))

    def test_successor_inspector_seals_and_rechecks_under_exclusive_drain(self):
        ctrl,holds=blocked_fixture()
        drain=gate_for(ctrl,holds).drain_status()
        state={'sha256':{'approvals.sqlite':'a'*64},'summary':{
            'requestStates':{},'uncertainRequestIds':[],'approvedRequestIds':[],
            'native':{'jobStates':{},'preservedClaimedIds':[]}}}
        companion={'schemaVersion':1,'parentStates':{}}
        payload={'action':'successor_freeze_inspect','instanceId':ctrl.record['registryInstanceId'],
            'scopeDigest':ctrl.record['scopeDigest'],'generation':fixture.OLD,
            'interlockDigest':sc.digest(ctrl.record),'registryDigest':sc.digest(holds),
            'stateDigest':sc.digest(state),'companionDigest':sc.digest(companion),
            'coreSchemaDigest':'d'*64,'workerAttestationDigest':'f'*64,
            'preserveUncertainIds':[],'preserveClaimedIds':[],'drain':drain,
            'attemptId':ctrl.record['attempt']['attemptId'],'restrictionDigest':ctrl.record['attempt']['restrictionDigest'],
            'subject':ctrl.record['attempt']['subject'],'targetSourceSha':ctrl.record['attempt']['source']['sourceSha']}
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            root.chmod(0o555)
            lock=interlock.InterlockReservations(root)
            actual=root.stat()
            mode=SimpleNamespace(st_uid=0,st_mode=actual.st_mode,st_dev=actual.st_dev,st_ino=actual.st_ino)
            def while_sealed(*args,**kwargs):
                with self.assertRaisesRegex(Denied,'RELEASE_MAINTENANCE'),lock.reserve():
                    self.fail('shared reservation entered the frozen inspection')
            def inspect(*args,**kwargs):
                while_sealed()
                return state
            def companion_snapshot(*args,**kwargs):
                while_sealed()
                return companion
            with patch.object(interlock.os,'fstat',return_value=mode), \
                 patch.object(interlock,'_check_owner_readonly_mount'), \
                 patch('fortis_approvals.r7_registry_reader_mount._check_owner_readonly_mount'), \
                 patch.object(interlock,'InterlockReservations',return_value=lock), \
                 patch.object(interlock,'read_owner_interlock',return_value=ctrl.record) as read, \
                 patch.object(github_pilot_helpers,'inspect_state',side_effect=inspect) as walk, \
                 patch('fortis_approvals.extensions.composite_preservation.sealed_companion',
                       side_effect=companion_snapshot):
                with lock.reserve():
                    with self.assertRaisesRegex(RuntimeError,'PILOT_SUCCESSOR_DRAIN_UNCONFIRMED'):
                        github_pilot_helpers.successor_freeze_inspect(payload)
                walk.assert_not_called()
                result=github_pilot_helpers.successor_freeze_inspect(payload)
                self.assertEqual(result['seal']['result'],'FREEZE_BINDINGS_MATCH_ONLY')
                self.assertEqual(result['sourceReceipt'],state)
                self.assertEqual(result['seal']['stateReceiptDigest'],sc.digest(result['sourceReceipt']))
                self.assertEqual(read.call_count,2)
                read.side_effect=[ctrl.record,{**ctrl.record,'phase':'RECOVERY_HOLD'}]
                with self.assertRaisesRegex(RuntimeError,'PILOT_SUCCESSOR_DRAIN_UNCONFIRMED'):
                    github_pilot_helpers.successor_freeze_inspect(payload)
                self.assertTrue(lock.drained())

                draining=ctrl.record
                transition=result['transitions']
                frozen,checked=transition['frozen'],transition['checked']
                self.assertEqual((frozen['proofDigest'],checked['proofDigest']),
                                 (sc.digest(result['seal']),)*2)
                self.assertEqual(mc.validate_transition(draining,frozen),frozen)
                self.assertEqual(mc.validate_transition(frozen,checked),checked)
                apply={k:v for k,v in payload.items() if k!='drain'}
                apply.update(action='successor_freeze_apply_verify',interlockDigest=sc.digest(checked),
                             checkSeal=result['seal'],draining=draining,frozen=frozen)
                read.side_effect=None
                read.return_value=checked
                self.assertEqual(github_pilot_helpers.successor_freeze_inspect(apply),result)
                preparation={'sourceRecordDigest':'1'*64,'checkedRecordDigest':'2'*64,
                             'targetImageId':'sha256:'+'3'*64}
                stop=github_pilot_helpers.successor_freeze_inspect(
                    {**apply,'prepareStop':preparation})['stopIntent']
                self.assertEqual(mc.validate_transition(checked,stop['next']),stop['next'])
                self.assertEqual(stop['next']['phase'],'APPLY_STOP')
                self.assertEqual(stop['checkedPhaseDigest'],sc.digest(checked))
                self.assertEqual(stop['next']['proofDigest'],
                                 sc.digest({k:v for k,v in stop.items() if k!='next'}))
                self.assertEqual(stop['sourceReceiptDigest'],sc.digest(state))
                changed=seal.apply_stop_plan(checked,result['seal'],
                                             {**preparation,'checkedRecordDigest':'4'*64})
                self.assertNotEqual(changed['next']['proofDigest'],stop['next']['proofDigest'])
                with self.assertRaisesRegex(Denied,'MAINTENANCE_APPLY_STOP_BINDING_CHANGED'):
                    seal.apply_stop_plan(checked,result['seal'],
                                         {**preparation,'targetImageId':'latest'})
                with self.assertRaisesRegex(RuntimeError,'PILOT_SUCCESSOR_FREEZE_BINDING_INVALID'):
                    github_pilot_helpers.successor_freeze_inspect({**apply,'restrictionDigest':'0'*64})
                read.return_value=draining
                with self.assertRaisesRegex(RuntimeError,'PILOT_SUCCESSOR_DRAIN_UNCONFIRMED'):
                    github_pilot_helpers.successor_freeze_inspect(apply)
                read.return_value=checked
                with self.assertRaisesRegex(Denied,'MAINTENANCE_CHECK_BINDING_CHANGED'):
                    github_pilot_helpers.successor_freeze_inspect(
                        {**apply,'frozen':{**frozen,'proofDigest':'e'*64}})
                with self.assertRaisesRegex(Denied,'MAINTENANCE_CHECK_BINDING_CHANGED'):
                    github_pilot_helpers.successor_freeze_inspect(
                        {**apply,'checkSeal':{**result['seal'],'registryDigest':'e'*64}})
                walk.side_effect=None
                walk.return_value={**state,'sha256':{'approvals.sqlite':'b'*64}}
                with self.assertRaisesRegex(Denied,'MAINTENANCE_SEALED_STATE_CHANGED'):
                    github_pilot_helpers.successor_freeze_inspect(apply)
                self.assertTrue(lock.drained())

    def test_interlock_publisher_drains_and_recovers_exact_pending_transition(self):
        ctrl,_=blocked_fixture()
        draining=ctrl.record
        previous=fixture.Controller(draining['registryInstanceId'],draining['scopeDigest']).record
        ctrl.advance('FROZEN_BEFORE_CHECK')
        frozen=ctrl.record

        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            record=root/'record.json'
            record.write_text(sc.canonical(previous))
            record.chmod(0o444)
            actual_stat=os.fstat
            actual_fsync=os.fsync

            def mounted_owner(fd):
                info=actual_stat(fd)
                mode=(stat.S_IFDIR|0o555) if stat.S_ISDIR(info.st_mode) else info.st_mode
                return SimpleNamespace(st_uid=0,st_mode=mode,st_nlink=info.st_nlink,st_size=info.st_size)

            def stopped_after_rename(fd):
                if stat.S_ISDIR(actual_stat(fd).st_mode):
                    raise OSError('fixture lost acknowledgement after rename')
                actual_fsync(fd)

            def publish(before,after,mode='publish'):
                return github_pilot_helpers.successor_interlock_publish({
                    'action':'successor_interlock_publish','mode':mode,
                    'previous':before,'next':after},root=root)

            with patch.object(os,'geteuid',return_value=0), patch.object(os,'fstat',side_effect=mounted_owner), \
                 patch('fortis_approvals.r7_registry_reader_mount._exact_mountinfo',return_value=True):
                self.assertEqual(publish(previous,draining,'readback')['position'],'PREVIOUS')
                with (root/'publish.lock').open('rb') as publisher:
                    fcntl.flock(publisher.fileno(),fcntl.LOCK_EX|fcntl.LOCK_NB)
                    with self.assertRaises(BlockingIOError):
                        publish(previous,draining,'readback')
                worker=os.open(root,os.O_RDONLY|os.O_DIRECTORY)
                try:
                    fcntl.flock(worker,fcntl.LOCK_SH|fcntl.LOCK_NB)
                    self.assertEqual(publish(previous,draining),
                        {'position':'NEXT','phase':'DRAINING','digest':sc.digest(draining)})
                    with self.assertRaises(BlockingIOError):
                        publish(draining,frozen)
                    self.assertEqual(record.read_text(),sc.canonical(draining))
                finally:
                    os.close(worker)
                with patch.object(os,'fsync',side_effect=stopped_after_rename):
                    with self.assertRaisesRegex(OSError,'lost acknowledgement'):
                        publish(draining,frozen)
                replaced=record.stat().st_ino
                self.assertEqual(publish(draining,frozen,'readback'),
                    {'position':'NEXT','phase':'FROZEN_BEFORE_CHECK','digest':sc.digest(frozen)})
                self.assertEqual(publish(draining,frozen)['position'],'NEXT')
                self.assertEqual(record.stat().st_ino,replaced)
                self.assertEqual(stat.S_IMODE(record.stat().st_mode),0o444)
                with self.assertRaisesRegex(RuntimeError,'PILOT_INTERLOCK_PREDECESSOR_CHANGED'):
                    publish(draining,{**frozen,'proofDigest':'e'*64})
                self.assertEqual(record.read_text(),sc.canonical(frozen))
                ctrl.advance('CHECK_SEALED')
                checked=ctrl.record
                with patch.object(os,'fsync',side_effect=stopped_after_rename):
                    with self.assertRaisesRegex(OSError,'lost acknowledgement'):
                        publish(frozen,checked)
                replaced=record.stat().st_ino
                self.assertEqual(publish(frozen,checked,'readback'),
                    {'position':'NEXT','phase':'CHECK_SEALED','digest':sc.digest(checked)})
                self.assertEqual(record.stat().st_ino,replaced)
                self.assertEqual(record.read_text(),sc.canonical(checked))
                ctrl.advance('APPLY_STOP')
                stop=ctrl.record
                worker=os.open(root,os.O_RDONLY|os.O_DIRECTORY)
                try:
                    fcntl.flock(worker,fcntl.LOCK_SH|fcntl.LOCK_NB)
                    with self.assertRaises(BlockingIOError):
                        publish(checked,stop)
                    self.assertEqual(record.read_text(),sc.canonical(checked))
                finally:
                    os.close(worker)
                self.assertEqual(publish(checked,stop),
                    {'position':'NEXT','phase':'APPLY_STOP','digest':sc.digest(stop)})
                self.assertEqual(publish(checked,stop,'readback')['digest'],sc.digest(stop))
                self.assertEqual(list(root.glob('.record-*')),[])

    def test_exact_completion_receipt_binding_and_freshness(self):
        ctrl,_=blocked_fixture()
        for phase in ('FROZEN_BEFORE_CHECK','CHECK_SEALED','APPLY_STOP'):
            ctrl.advance(phase)
        ctrl.advance('STAGED_TARGET_FROZEN',generation=fixture.NEW)
        for phase in ('BACKUP_FROZEN','PROMOTE_FROZEN','COMPLETION_PENDING'):
            ctrl.advance(phase)
        record=copy.deepcopy(ctrl.record)
        record['attempt']['source']['artifactSha256']='a'*64
        a=record['attempt']
        identity={'schemaVersion':1,'attemptId':a['attemptId'],'subject':a['subject'],
                  'source':a['source'],'generation':fixture.NEW}
        controller={**identity,'applyRecordDigest':'a'*64,'backupRecordDigest':'b'*64,
                  'primaryRecordDigest':'c'*64,'finalSealDigest':'d'*64,'completionTime':100}
        observation={**identity,'primaryRecordDigest':'c'*64,'stateReceiptDigest':'d'*64,
                    'observedAt':101,'healthy':True}
        record['proofDigest']=sc.digest(controller)
        args=dict(expected_controller_digest=sc.digest(controller),expected_observation_digest=sc.digest(observation),
                  expected_target_revision=3,expected_desired_record='e'*64,now=102,max_age=30)
        self.assertEqual(me.completion_params(record,controller,observation,**args)['attemptId'],a['attemptId'])
        for changes in ({'healthy':False},{'generation':fixture.OLD},{'stateReceiptDigest':'f'*64}):
            modified={**observation,**changes}
            with self.assertRaises(Denied):
                me.completion_params(record,controller,modified,
                       **{**args,'expected_observation_digest':sc.digest(modified)})
        with self.assertRaises(Denied):
            me.completion_params(record,controller,observation,**{**args,'now':1000})


if __name__=='__main__':
    unittest.main()

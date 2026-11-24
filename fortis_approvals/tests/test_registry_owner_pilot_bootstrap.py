"""No Docker. Actual schema-3 genesis + separate inactive restored bytes."""
import copy
import hashlib
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import uuid

from fortis_approvals.core import Denied
from fortis_approvals.registry import recovery_snapshot
from fortis_approvals.registry.functional_v1_journal import FunctionalV1CandidateJournal
from fortis_approvals.integrations.github.gateway import component_bindings, registry_review_policy

ROOT = Path(__file__).resolve().parents[2]


def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT/'scripts'/(name+'.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


pilot = load('registry_owner_pilot_bootstrap')
helper = load('registry_owner_pilot_backup')


def proposal():
    return {'repository':pilot.REPOSITORY,'baselineSha':'a'*40,
            'catalogSha256':pilot.CATALOG_SHA,'instanceId':str(uuid.uuid4()),
            'enrollmentId':str(uuid.uuid4()),'maxReviewToMergeSeconds':3600,
            'clockToleranceSeconds':10,'profile':pilot.policy(),
            'mapping':{'bindings':[{'targetId':t,'environment':e,'componentId':f'owner-component-{i}'} for i,(t,e) in enumerate(pilot.TARGETS.items())],
                       'components':[{'id':f'owner-component-{i}','resources':['owner-fixture-engine'],'requires':[]} for i in range(4)]}}


class ScopeTests(unittest.TestCase):
    def test_scope_bytes_and_existing_validators(self):
        p=proposal(); records=pilot.compose(p,1700000000); scope=records['spec.json']['scope']
        self.assertFalse(records['pilot-acceptance.json']['enrollmentAccepted'])
        self.assertFalse(records['pilot-acceptance.json']['admissionAllowed'])
        self.assertEqual(scope['baselineDigest'],pilot.sha(pilot.raw(records['baseline.json'])))
        self.assertEqual(scope['bindingDigest'],pilot.sha(pilot.raw(records['binding.json'])))
        self.assertEqual(scope['policyReferenceDigest'],pilot.sha(pilot.raw(records['policy-reference.json'])))
        registry_review_policy.policy_reference(lambda:records['policy-reference.json'],scope['policyReferenceDigest'])
        catalog={'targets':[{'id':t,'deployment':{'environments':[e]},'verification':[]} for t,e in pilot.TARGETS.items()]}
        self.assertEqual(len(component_bindings._resolved(records['binding.json'],catalog)),4)
        self.assertEqual(pilot.raw(records['spec.json']),pilot.raw(pilot.compose(p,1700000000)['spec.json']))

    def test_bad_mapping_and_policy_fail_before_go(self):
        p=proposal();p['mapping']['components'][0]['requires']=['owner-component-0']
        with self.assertRaisesRegex(RuntimeError,'MAPPING_CYCLE'):pilot.compose(p,1700000000)
        p=proposal();p['mapping']['bindings'][0]['environment']='unknown'
        with self.assertRaisesRegex(RuntimeError,'MAPPING_TARGET'):pilot.compose(p,1700000000)
        p=proposal();p['maxReviewToMergeSeconds']=86401
        with self.assertRaisesRegex(RuntimeError,'POLICY_LIMITS'):pilot.compose(p,1700000000)
        p=proposal();p['catalogSha256']='0'*64
        with self.assertRaisesRegex(RuntimeError,'PILOT_BASELINE'):pilot.compose(p,1700000000)

    def test_native_context_and_restore_no_live_mounts(self):
        review={'registryImageId':'sha256:'+'a'*64}
        with patch.object(pilot,'preflight',return_value=('state','config','socket')), patch.object(pilot,'docker',return_value=b'{}') as run:
            pilot.backup_run('Restore',review,'a'*40,{},'b'*64,b'helper','c'*64)
            args=run.call_args.args
            self.assertNotIn('--mount',args); self.assertNotIn('--privileged',args)
            self.assertIn('--read-only',args); self.assertIn('20002:20002',args)
            pilot.backup_run('Backup',review,'a'*40,{},'b'*64,b'helper','c'*64)
            args=run.call_args.args
            self.assertEqual(args.count('--mount'),3)
            self.assertTrue(all(x.endswith(',readonly') for x in args if x.startswith('type=volume,')))


@unittest.skipIf(os.name=='nt','Linux filesystem source fixture')
class BackupRestoreTests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup); self.root=Path(temp.name)
        self.spec=pilot.compose(proposal(),1700000000)['spec.json']
        self.spec_bytes=pilot.raw(self.spec)
        self.state=self.root/'state';self.config=self.root/'config';self.socket=self.root/'socket'
        for p in (self.state,self.config,self.socket):p.mkdir(mode=0o700)
        self.db=self.state/'registry.sqlite'
        FunctionalV1CandidateJournal.initialize(self.db,instance_id=self.spec['instanceId'],scope=self.spec['scope'],plan_reader=helper.no_plan)
        self.profile=self.config/'profile.json';helper.put(self.profile,pilot.raw(helper.boot._config(self.spec)))
        self.source=(ROOT/'fortis_approvals'/'registry'/'recovery_snapshot.py').read_bytes()
        self.envelope={'recovery':pilot.b64(self.source),'spec':pilot.b64(self.spec_bytes),'backupId':str(uuid.uuid4())}
        # Source fixture: actual SQLite and filesystem, no fake claim of Docker
        # runtime identity, RO mount or host confinement. Test guards separately.
        for name,value in [('STATE',self.state),('CONFIG',self.config),('SOCKET',self.socket)]:
            p=patch.object(helper,name,value);p.start();self.addCleanup(p.stop)
        for name,value in [('_runtime_confinement',None),('_directories',None),('_private_directory',None),('_load_spec',(self.spec,pilot.sha(self.spec_bytes)))]:
            p=patch.object(helper.boot,name,return_value=value);p.start();self.addCleanup(p.stop)
        p=patch.object(helper,'expect_mount');p.start();self.addCleanup(p.stop)
        p=patch.object(helper.os,'statvfs',return_value=type('Stat',(),{'f_flag':os.ST_RDONLY})());p.start();self.addCleanup(p.stop)
        def actual_read(path,limit):
            return helper.boot._file(path,limit=limit,owner_uid=os.geteuid(),owner_gid=os.getegid(),parent_mode=0o700)
        p=patch.object(helper,'read_file',side_effect=actual_read);p.start();self.addCleanup(p.stop)
        # Loading the exact recovery source into its namespace must not leak
        # the replacement module into other source tests.
        import sys
        key='fortis_approvals.registry.recovery_snapshot'
        self.addCleanup(lambda:sys.modules.__setitem__(key,recovery_snapshot))

    def run_phase(self,action,envelope):
        scratch=Path(tempfile.mkdtemp(dir=self.root));
        with patch.object(helper,'ROOT',scratch):
            if action=='Restore':
                with patch.multiple(helper,STATE=self.root/'absent-state',CONFIG=self.root/'absent-config',SOCKET=self.root/'absent-socket'):
                    return helper.run(envelope,action,pilot.sha(self.source),pilot.sha(self.spec_bytes))
            return helper.run(envelope,action,pilot.sha(self.source),pilot.sha(self.spec_bytes))

    def test_real_backup_restore_genesis_and_source_unchanged(self):
        before=self.db.read_bytes()
        backup=self.run_phase('Backup',self.envelope)
        self.assertEqual(backup['result'],'PILOT_GENESIS_BACKUP_CREATED')
        self.assertEqual(self.db.read_bytes(),before)
        self.assertEqual(list(self.state.iterdir()),[self.db])
        restore=self.run_phase('Restore',{**self.envelope,'files':backup['files']})
        self.assertEqual(restore['result'],'PILOT_INDEPENDENT_INACTIVE_RESTORE_PASS')
        self.assertEqual(restore['receipt'],backup['receipt'])
        self.assertFalse(restore['receipt']['rollbackProtected'])
        bad=copy.deepcopy(backup['files']);bad['sqlite']=pilot.b64(b'not sqlite')
        with self.assertRaises(Denied):self.run_phase('Restore',{**self.envelope,'files':bad})

    def test_wal_or_unknown_extra_file_stops_before_copy(self):
        (self.state/'registry.sqlite-wal').write_bytes(b'pending')
        with self.assertRaisesRegex(Denied,'NOT_INACTIVE_GENESIS'):self.run_phase('Backup',self.envelope)

    def test_recovery_payload_tampering_stops(self):
        with self.assertRaisesRegex(Denied,'RECOVERY_PIN'):
            self.run_phase('Backup',{**self.envelope,'recovery':pilot.b64(b'bad')})

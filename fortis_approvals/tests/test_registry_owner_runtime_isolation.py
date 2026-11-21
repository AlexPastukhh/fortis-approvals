"""Offline Linux owner/Registry host placement guard; no protected authority."""
import copy
import os
from pathlib import Path
import socket
import tempfile
import unittest
import uuid
from unittest.mock import patch

from fortis_approvals.core import Denied, Stale
from fortis_approvals.registry import owner_runtime_isolation as iso
from fortis_approvals.registry import owner_peer_boundary as peer


class RuntimeIsolationTests(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory();self.addCleanup(tmp.cleanup)
        self.root=Path(tmp.name)
        uid=os.geteuid();gid=os.getegid()
        self.folder=self.root/'socket';self.folder.mkdir(mode=0o710)
        self.sockpath=self.folder/'owner.sock'
        self.peer={'schemaVersion':1,'transport':'linux-af-unix-stream-so-peercred-v1',
                   'socketPath':str(self.sockpath),'instanceId':str(uuid.uuid4()),
                   'scopeDigest':'a'*64,'enrollmentReceiptDigest':'b'*64,
                   'authorityUid':uid,'authorityGid':gid,'socketGid':gid,
                   'registryUid':uid+1,'registryGid':gid+1,
                   'operatorUid':uid+2,'operatorGid':gid+2}
        self.peer_digest=iso._hash(self.peer)
        self.layout={'schemaVersion':1,
                     'format':'owner-registry-linux-layout-candidate-v1',
                     'peerProfileDigest':self.peer_digest,
                     'instanceId':self.peer['instanceId'],
                     'scopeDigest':self.peer['scopeDigest'],
                     'bootId':str(uuid.uuid4()),
                     'ownerPid':1011,'registryPid':1012,'repoPid':1013,
                     'ownerStatePath':'/var/lib/fortis-owner-checkpoint/state.sqlite',
                     'registryStatePath':'/var/lib/fortis-registry/registry.sqlite',
                     'repoUid':uid+3,'repoGid':gid+3}
        self.layout_digest=iso._hash(self.layout)
        self.procs={}
        for idx,role in enumerate(('owner','registry','repo')):
            role_id='authority' if role=='owner' else role
            user=self.layout['repoUid'] if role=='repo' else self.peer[role_id+'Uid']
            group=self.layout['repoGid'] if role=='repo' else self.peer[role_id+'Gid']
            self.procs[role]={'pid':self.layout[role+'Pid'],'startTicks':100+idx,
                              'uids':[user]*4,'gids':[group]*4,'groups':[group],
                              'capInh':0,'capPrm':0,'capEff':0,'capBnd':0,'capAmb':0,
                              'noNewPrivs':1,'seccomp':2,'tracerPid':0,
                              'mountNamespace':f'mnt:[{1000+idx}]',
                              'cgroup':f'0::/isolated/{role}'}
        self.files={}
        for role in ('owner','registry'):
            user=self.peer[('authority' if role=='owner' else role)+'Uid']
            group=self.peer[('authority' if role=='owner' else role)+'Gid']
            device=50 if role=='owner' else 60
            self.files[role]={'path':self.layout[role+'StatePath'],
                              'parentUid':user,'parentGid':group,'parentMode':0o700,
                              'fileUid':user,'fileGid':group,'fileMode':0o600,
                              'parentDev':device,'fileDev':device,
                              'parentInode':80+device,'fileInode':81+device}
        self.socket_info=(71,72)

    def assess(self,*,procs=None,files=None,layout=None,endpoint=None):
        return iso._assess(layout or self.layout,self.peer,
                    procs if procs is not None else self.procs,
                    files if files is not None else self.files,
                    endpoint if endpoint is not None else self.socket_info)

    def observe_fake(self,**overrides):
        p=overrides.get('processes',copy.deepcopy(self.procs))
        f=overrides.get('files',copy.deepcopy(self.files))
        endpoint=overrides.get('endpoint',self.socket_info)
        with patch.object(iso,'_boot_id',return_value=self.layout['bootId']),             patch.object(iso,'_endpoint',return_value=endpoint),\
             patch.object(iso,'_read_process',side_effect=lambda pid:copy.deepcopy(next(
                 row for row in p.values() if row['pid']==pid))),\
             patch.object(iso,'_read_state_file',side_effect=lambda path:copy.deepcopy(next(
                 row for row in f.values() if row['path']==str(path)))):
            return iso.observe_host_isolation(
                layout_reader=lambda:copy.deepcopy(self.layout),
                expected_layout_digest=self.layout_digest,
                peer_profile_reader=lambda:copy.deepcopy(self.peer),
                expected_peer_profile_digest=self.peer_digest)

    def test_three_isolated_synthetic_processes_still_never_authorize(self):
        result=self.assess()
        self.assertEqual(result['result'],'OWNER_RUNTIME_ISOLATION_OBSERVATION_CANDIDATE')
        self.assertEqual(result['observationDigest'],iso._hash(result['observation']))
        for flag in ('protectedAnchorVerified','enrollmentVerified','hostStorageVerified',
                     'ownerAcceptanceVerified','runtimeActivationAllowed','admissionAllowed'):
            self.assertIs(result[flag],False)
        self.assertEqual(self.observe_fake(),result)

    def test_pinned_profile_and_layout_fail_for_any_change(self):
        self.assertEqual(iso._layout(self.layout,self.layout_digest,self.peer),self.layout)
        for key,value in (('registryPid',1011),('ownerPid',0),
                          ('repoUid',self.peer['registryUid']),
                          ('peerProfileDigest','f'*64),
                          ('instanceId',str(uuid.uuid4())),
                          ('ownerStatePath','/tmp/../path/state.sqlite'),
                          ('registryStatePath','/var/lib/fortis-owner-checkpoint/state.sqlite'),
                          ('bootId','not-uuid'),
                          ('schemaVersion',True)):
            with self.subTest(key=key),self.assertRaises(Denied):
                iso._layout({**self.layout,key:value},self.layout_digest,self.peer)
        with self.assertRaises(Denied):iso._layout(self.layout,'f'*64,self.peer)

    def test_identity_change_fails_for_every_role_including_owner(self):
        for role in ('owner','registry','repo'):
            for field,value in (('uids',[0]*4),('gids',[0]*4),
                                ('groups',[self.peer['authorityGid'],self.peer['authorityGid']]),
                                ('pid',9999)):
                bad=copy.deepcopy(self.procs);bad[role][field]=value
                with self.subTest(role=role,field=field),self.assertRaisesRegex(
                        Denied,'REGISTRY_ISOLATION_PROCESS_IDENTITY'):
                    self.assess(procs=bad)

    def test_registry_cannot_join_owner_private_group(self):
        for role in ('registry','repo'):
            bad=copy.deepcopy(self.procs)
            bad[role]['groups'].append(self.peer['authorityGid'])
            with self.subTest(role=role),self.assertRaisesRegex(
                    Denied,'REGISTRY_ISOLATION_PROCESS_IDENTITY'):
                self.assess(procs=bad)

    def test_caps_no_new_privs_and_seccomp_required(self):
        for role in ('owner','registry','repo'):
            for field,value in (('capEff',1),('capPrm',1),('capInh',1),
                                ('capBnd',1),('capAmb',1),('tracerPid',10),
                                ('noNewPrivs',0),('seccomp',0),('seccomp',1)):
                bad=copy.deepcopy(self.procs);bad[role][field]=value
                with self.subTest(role=role,field=field,value=value),self.assertRaisesRegex(
                        Denied,'REGISTRY_ISOLATION_PROCESS_PRIVILEGE'):
                    self.assess(procs=bad)

    def test_shared_mount_or_cgroup_fail_closed(self):
        for field in ('mountNamespace','cgroup'):
            bad=copy.deepcopy(self.procs)
            bad['registry'][field]=bad['owner'][field]
            with self.subTest(field=field),self.assertRaisesRegex(
                    Denied,'REGISTRY_ISOLATION_SHARED_RUNTIME'):
                self.assess(procs=bad)

    def test_private_state_paths_and_distinct_devices_required(self):
        for role in ('owner','registry'):
            for field,value in (('parentMode',0o755),('fileMode',0o644),
                                ('fileUid',self.peer['operatorUid']),
                                ('parentGid',self.peer['operatorGid']),
                                ('fileDev',999)):
                bad=copy.deepcopy(self.files);bad[role][field]=value
                with self.subTest(role=role,field=field),self.assertRaisesRegex(
                        Denied,'REGISTRY_ISOLATION_STATE_PERMISSIONS'):
                    self.assess(files=bad)
        bad=copy.deepcopy(self.files)
        bad['registry']['parentDev']=bad['owner']['parentDev']
        bad['registry']['fileDev']=bad['owner']['fileDev']
        with self.assertRaisesRegex(Denied,'REGISTRY_ISOLATION_SHARED_STATE_DEVICE'):
            self.assess(files=bad)

    def test_socket_observation_required(self):
        with self.assertRaisesRegex(Denied,'REGISTRY_ISOLATION_SOCKET_INVALID'):
            self.assess(endpoint=(0,5))
        with self.assertRaisesRegex(Denied,'REGISTRY_ISOLATION_SOCKET_INVALID'):
            iso._assess(self.layout,self.peer,self.procs,self.files,None)

    def test_proc_start_tick_parser_handles_parentheses_and_zombie(self):
        # field 22 is the 20th token starting with the process state.
        a='55 (worker (child)) S '+' '.join(['0']*18+['1234'])
        self.assertEqual(iso._start_ticks(a,55),1234)
        for row in ('55 (x) Z '+' '.join(['0']*18+['4']), '55 bad',
                    '55 (x) S 1 2 3', '56 (x) S '+' '.join(['0']*18+['4'])):
            with self.subTest(row=row),self.assertRaises(Denied):
                iso._start_ticks(row,55)

    def test_actual_proc_current_process_is_observed(self):
        pid=os.getpid()
        obs=iso._read_process(pid)
        self.assertEqual(obs['pid'],pid)
        self.assertEqual(obs['uids'][1],os.geteuid())
        self.assertGreater(obs['startTicks'],0)
        self.assertTrue(obs['mountNamespace'].startswith('mnt:['))
        self.assertIsInstance(obs['capEff'],int)

    def test_symlink_files_and_private_local_state_guard(self):
        path=self.root/'private';path.mkdir(mode=0o700)
        file=path/'state.sqlite';file.write_bytes(b'not a real database');file.chmod(0o600)
        observed=iso._read_state_file(file)
        self.assertEqual(observed['parentMode'],0o700)
        self.assertEqual(observed['fileMode'],0o600)
        linked=self.root/'linked';linked.symlink_to(path,target_is_directory=True)
        with self.assertRaisesRegex(Denied,'REGISTRY_ISOLATION_SYMLINK'):
            iso._read_state_file(linked/'state.sqlite')
        file.unlink()
        with self.assertRaisesRegex(Denied,'REGISTRY_ISOLATION_PATH_UNAVAILABLE'):
            iso._read_state_file(file)

    def test_process_and_file_drifts_block_after_first_check(self):
        def changed(pid):
            row=copy.deepcopy(next(x for x in self.procs.values() if x['pid']==pid))
            if pid==self.layout['ownerPid']:
                counter[0]+=1
                if counter[0]>1:row['startTicks']+=1
            return row
        counter=[0]
        with patch.object(iso,'_boot_id',return_value=self.layout['bootId']),             patch.object(iso,'_endpoint',return_value=self.socket_info),\
             patch.object(iso,'_read_process',side_effect=changed),\
             patch.object(iso,'_read_state_file',side_effect=lambda path:copy.deepcopy(
                 next(x for x in self.files.values() if x['path']==str(path)))):
            with self.assertRaisesRegex(Stale,'REGISTRY_ISOLATION_RUNTIME_CHANGED'):
                iso.observe_host_isolation(
                    layout_reader=lambda:copy.deepcopy(self.layout),
                    expected_layout_digest=self.layout_digest,
                    peer_profile_reader=lambda:copy.deepcopy(self.peer),
                    expected_peer_profile_digest=self.peer_digest)

    def test_real_host_preflight_cannot_self_attest_from_ai_uid(self):
        # The current source worker cannot masquerade as three distinct
        # host identities/volumes. Do not assert this is a live owner test.
        with self.assertRaises(Denied):
            iso.observe_host_isolation(
                layout_reader=lambda:copy.deepcopy(self.layout),
                expected_layout_digest=self.layout_digest,
                peer_profile_reader=lambda:copy.deepcopy(self.peer),
                expected_peer_profile_digest=self.peer_digest)

    def test_boot_id_changed_since_profile_is_denied(self):
        with patch.object(iso,'_boot_id',return_value=str(uuid.uuid4())):
            with self.assertRaisesRegex(Denied,'REGISTRY_ISOLATION_BOOT_ID_MISMATCH'):
                iso.observe_host_isolation(
                    layout_reader=lambda:copy.deepcopy(self.layout),
                    expected_layout_digest=self.layout_digest,
                    peer_profile_reader=lambda:copy.deepcopy(self.peer),
                    expected_peer_profile_digest=self.peer_digest)

    def test_boot_id_changed_mid_observation_is_stale(self):
        other=str(uuid.uuid4());calls=[0]
        def boot():
            calls[0]+=1
            return self.layout['bootId'] if calls[0]==1 else other
        with patch.object(iso,'_boot_id',side_effect=boot),             patch.object(iso,'_endpoint',return_value=self.socket_info),             patch.object(iso,'_read_process',side_effect=lambda pid:copy.deepcopy(next(
                 x for x in self.procs.values() if x['pid']==pid))),             patch.object(iso,'_read_state_file',side_effect=lambda path:copy.deepcopy(next(
                 x for x in self.files.values() if x['path']==str(path)))):
            with self.assertRaisesRegex(Stale,'REGISTRY_ISOLATION_RUNTIME_CHANGED'):
                iso.observe_host_isolation(
                    layout_reader=lambda:copy.deepcopy(self.layout),
                    expected_layout_digest=self.layout_digest,
                    peer_profile_reader=lambda:copy.deepcopy(self.peer),
                    expected_peer_profile_digest=self.peer_digest)

    def test_actual_linux_boot_id_is_uuid(self):
        self.assertTrue(iso._boot_id())

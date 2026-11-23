"""Offline checks for the owner-run cross-UID probe.

Local tests run under ONE real UID. They deliberately cannot yield a
cross-principal acceptance PASS: the positive transport subtest checks real
kernel socket/SQLite paths, not accepted owner host isolation.
"""
import importlib.util
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import uuid
import unittest
from unittest.mock import patch

from fortis_approvals.core import Denied, canonical, loads_strict
from fortis_approvals.integrations.registry.owner_pinned_pidfd import _boot_id
from fortis_approvals.registry.state_journal import _hash
from fortis_approvals.tests import test_registry_local_candidate_read_service as fixture


_ROOT=Path(__file__).resolve().parents[2]
_SCRIPT=_ROOT/'scripts'/'probe-functional-v1-registry-access.py'
spec=importlib.util.spec_from_file_location('functional_v1_access_probe',_SCRIPT)
probe=importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


class FunctionalV1CrossUidProbeTests(unittest.TestCase):
    setUp=fixture.LocalCandidateReadServiceTests.setUp
    read=fixture.LocalCandidateReadServiceTests.read
    args=fixture.LocalCandidateReadServiceTests.args
    append=fixture.LocalCandidateReadServiceTests.append
    accept=fixture.LocalCandidateReadServiceTests.accept
    suffix=fixture.LocalCandidateReadServiceTests.suffix
    setup_service=fixture.LocalCandidateReadServiceTests.setup_service

    def self_pidfd_inode(self):
        fd=os.pidfd_open(os.getpid())
        try:return os.fstat(fd).st_ino
        finally:os.close(fd)

    def profile(self):
        # Synthetic future host IDs. Tests do not impersonate these UIDs.
        uid=os.geteuid()
        return {
            'schemaVersion':2,
            'format':probe._FORMAT,
            'ownerUid':uid,
            'registryUid':uid+10,'registryGid':os.getegid()+10,
            'readerUid':uid+20,'readerGid':os.getegid()+20,
            'repoUid':uid+30,'repoGid':os.getegid()+30,
            'serverPidfdInode':self.self_pidfd_inode(),
            'kernelBootId':_boot_id(),
            'socketDev':1,'socketInode':2,
            'instanceId':self.instance,
            'scopeDigest':_hash(self.scope),
            'registryStatePath':str(self.path),
            'socketPath':'/srv/fortis-registry-read/reader.sock',
        }

    def profile_file(self):
        home=tempfile.TemporaryDirectory(prefix='fortis-access-profile-')
        self.addCleanup(home.cleanup)
        directory=Path(home.name)
        directory.chmod(0o755)
        value=self.profile()
        output=directory/'host-profile.json'
        output.write_text(canonical(value),encoding='utf-8')
        output.chmod(0o444)
        return value,output

    def test_owner_profile_is_canonical_readonly_and_pinned(self):
        value,output=self.profile_file()
        digest=_hash(value)
        self.assertEqual(probe.load_profile(str(output),digest),value)
        with self.assertRaisesRegex(Denied,'PROFILE_INVALID'):
            probe.load_profile(str(output),'f'*64)
        output.chmod(0o644)
        with self.assertRaisesRegex(Denied,'PROFILE_FILE_DENIED'):
            probe.load_profile(str(output),digest)
        output.chmod(0o444)
        output.parent.chmod(0o777)
        with self.assertRaisesRegex(Denied,'PROFILE_FILE_DENIED'):
            probe.load_profile(str(output),digest)
        output.parent.chmod(0o755)

    def test_profile_rejects_colliding_uids_groups_and_forged_fields(self):
        value=self.profile()
        for change in (
            {'readerUid':value['registryUid']},
            {'repoUid':value['readerUid']},
            {'repoGid':value['readerGid']},
            {'ownerUid':value['registryUid']},
            {'schemaVersion':True},
            {'serverPidfdInode':0},
            {'kernelBootId':'00000000-0000-0000-0000-000000000000'},
            {'socketInode':0},
            {'runtimeActivationAllowed':True},
            {'socketPath':str(self.path.parent/'read.sock')},
            {'registryStatePath':'/tmp/../forged.sqlite'},
            {'registryStatePath':'/tmp/bad\0sqlite'},
        ):
            with self.subTest(change=change),self.assertRaises(Denied):
                changed=value|change
                probe._profile(changed,_hash(changed))

    def test_same_uid_never_counts_as_cross_principal(self):
        value=self.profile()
        value['readerUid']=os.getuid()
        value['registryUid']=os.getuid()+10
        value['ownerUid']=os.getuid()+40
        # A fake digest/UID input cannot make the actual system principal
        # stop being the test runner.
        with self.assertRaisesRegex(Denied,'NOT_REAL_PRINCIPAL'):
            probe.observe('reader',value,_hash(value))
        with self.assertRaisesRegex(Denied,'NOT_REAL_PRINCIPAL'):
            probe.observe('repo',self.profile(),_hash(self.profile()))

    def test_real_kernel_denial_only_eacces_or_eperm_not_missing(self):
        with tempfile.TemporaryDirectory(prefix='fortis-access-deny-') as home:
            target=Path(home)/'db.sqlite'
            target.write_text('untouched',encoding='utf-8')
            with self.assertRaisesRegex(Denied,'UNEXPECTEDLY_ALLOWED'):
                probe._denied_open(target,os.O_RDONLY)
            target.parent.chmod(0o000)
            try:
                self.assertEqual(probe._denied_open(target,os.O_RDONLY),
                                 'EACCES')
                self.assertEqual(probe._denied_open(target,os.O_RDWR),
                                 'EACCES')
            finally:
                target.parent.chmod(0o700)
            with self.assertRaisesRegex(Denied,'NOT_PROVEN'):
                probe._denied_open(target.with_name('missing.sqlite'),
                                  os.O_RDONLY)

    def test_same_uid_able_to_read_private_db_never_passes(self):
        value=self.profile()
        with self.assertRaisesRegex(Denied,'UNEXPECTEDLY_ALLOWED'):
            probe._denied_state(value)

    def test_repo_socket_missing_or_accessible_not_a_valid_denial(self):
        value=self.profile()
        with self.assertRaisesRegex(Denied,'SOCKET_DENIAL_NOT_PROVEN'):
            probe._repo_socket_denied(value)
        self.setup_service()
        listener=self.service.bind()
        try:
            value['socketPath']=str(self.socketpath)
            with self.assertRaisesRegex(Denied,'SOCKET_UNEXPECTEDLY_ALLOWED'):
                probe._repo_socket_denied(value)
        finally:
            listener.close()
            self.socketpath.unlink()
            self.service._endpoint=None

    def test_real_socket_peer_and_source_only_head_are_validated(self):
        self.setup_service()
        self.accept()
        listener=self.service.bind()
        failures=[]
        def run():
            try:
                conn,_=listener.accept()
                with conn:
                    self.service.handle(conn)
            except Exception as err:
                failures.append(err)
        thread=threading.Thread(target=run,daemon=True)
        thread.start()
        try:
            row=self.socketpath.lstat()
            local=self.profile()
            local.update(
                registryUid=os.getuid(),registryGid=os.getgid(),
                readerGid=os.getgid(),readerUid=os.getuid(),
                socketDev=row.st_dev,socketInode=row.st_ino,
                socketPath=str(self.socketpath))
            # This is ONLY a real transport test. The deliberately same-UID
            # profile is invalid as cross-principal evidence.
            answer=probe._reader_socket(local)
            self.assertEqual(answer['localRevisionCandidate'],1)
            self.assertEqual(answer['serverUid'],os.getuid())
            self.assertEqual(answer['serverPidfdInode'],self.self_pidfd_inode())
            self.assertEqual(answer['stateAuthority'],
                             'LOCAL_EVENT_CHAIN_ONLY')
            with self.assertRaisesRegex(Denied,'IDENTITY_CONFLICT'):
                probe._profile(local,_hash(local))
        finally:
            thread.join(timeout=4)
            listener.close()
            self.socketpath.unlink()
            self.service._endpoint=None
        self.assertFalse(thread.is_alive())
        self.assertEqual(failures,[])

    def test_reader_socket_pin_rejects_stale_inode(self):
        self.setup_service()
        listener=self.service.bind()
        try:
            info=self.socketpath.lstat()
            local=self.profile()
            local.update(
                registryUid=os.getuid(),registryGid=os.getgid(),
                readerGid=os.getgid(),readerUid=os.getuid(),
                socketDev=info.st_dev,socketInode=info.st_ino+1,
                socketPath=str(self.socketpath))
            with self.assertRaisesRegex(Denied,'SOCKET_IDENTITY'):
                probe._reader_socket(local)
        finally:
            listener.close()
            self.socketpath.unlink()
            self.service._endpoint=None

    def test_kernel_server_peer_mismatch_is_denied(self):
        self.setup_service()
        listener=self.service.bind()
        try:
            info=self.socketpath.lstat()
            local=self.profile()
            local.update(
                registryUid=os.getuid(),registryGid=os.getgid(),
                readerGid=os.getgid(),readerUid=os.getuid(),
                serverPidfdInode=self.self_pidfd_inode()+123,
                socketDev=info.st_dev,socketInode=info.st_ino,
                socketPath=str(self.socketpath))
            with self.assertRaisesRegex(Denied,'SERVER_PRINCIPAL_MISMATCH'):
                probe._reader_socket(local)
        finally:
            listener.close()
            self.socketpath.unlink()
            self.service._endpoint=None

    def test_cli_cannot_claim_host_isolation_with_test_runner_uid(self):
        value,output=self.profile_file()
        proc=subprocess.run(
            [sys.executable,'-B',str(_SCRIPT),'--role','reader',
             '--profile',str(output),'--expected-sha256',_hash(value)],
            cwd=str(_ROOT),env={**os.environ,'PYTHONDONTWRITEBYTECODE':'1',
                                'PYTHONPATH':str(_ROOT)},
            capture_output=True,text=True,timeout=8,check=False)
        self.assertEqual(proc.returncode,1)
        self.assertEqual(proc.stdout,'')
        self.assertIn('REGISTRY_V1_ACCESS_STOP:',proc.stderr)
        self.assertIn('NOT_REAL_PRINCIPAL',proc.stderr)

    def test_missing_or_corrupt_profile_no_fake_positive(self):
        value,output=self.profile_file()
        digest=_hash(value)
        output.unlink()
        with self.assertRaises(Denied):
            probe.load_profile(str(output),digest)
        output.write_text('{"schemaVersion":1,"schemaVersion":1}',
                          encoding='utf-8')
        output.chmod(0o444)
        with self.assertRaises(Denied):
            probe.load_profile(str(output),digest)

    def test_structural_reader_observation_never_claims_owner_authority(self):
        # Mock-based observation formatting test ONLY; NOT a host proof.
        value=self.profile()
        principal={'pid':os.getpid(),'uid':value['readerUid'],
                   'gid':value['readerGid'],'groups':[],
                   'noNewPrivs':True,'seccompFilter':True,
                   'effectiveCapabilities':0}
        denials={'registryParentRead':'EACCES','registryDbRead':'EACCES',
                 'registryDbReadWrite':'EPERM'}
        endpoint={'serverPidfdInode':value['serverPidfdInode'],
                  'kernelBootId':value['kernelBootId'],
                  'serverUid':value['registryUid'],
                  'serverGid':value['registryGid'],
                  'socketDev':value['socketDev'],
                  'socketInode':value['socketInode'],
                  'localRevisionCandidate':1,
                  'stateAuthority':'LOCAL_EVENT_CHAIN_ONLY'}
        with patch.object(probe,'_identity',return_value=principal), \
             patch.object(probe,'_denied_state',return_value=denials), \
             patch.object(probe,'_reader_socket',return_value=endpoint), \
             patch.object(probe,'_socket_info',return_value=(
                 endpoint['socketDev'],endpoint['socketInode'])):
            result=probe.observe('reader',value,_hash(value))
        self.assertEqual(result['result'],probe._RESULT)
        self.assertEqual(result['evidenceDigest'],_hash(result['evidence']))
        self.assertEqual(result['evidence']['socketEvidence'],endpoint)
        for key in ('originalHostVerified','ownerAcceptanceVerified',
                    'collectorAuthenticated','liveRegistryAvailable',
                    'admissionAllowed','deploymentAllowed',
                    'runtimeActivationAllowed','rollbackProtected'):
            self.assertIs(result[key],False)

    def test_structural_repo_observation_does_not_claim_reader_access(self):
        value=self.profile()
        principal={'pid':os.getpid(),'uid':value['repoUid'],
                   'gid':value['repoGid'],'groups':[],
                   'noNewPrivs':True,'seccompFilter':True,
                   'effectiveCapabilities':0}
        denials={'registryParentRead':'EPERM','registryDbRead':'EACCES',
                 'registryDbReadWrite':'EACCES'}
        with patch.object(probe,'_identity',return_value=principal), \
             patch.object(probe,'_denied_state',return_value=denials), \
             patch.object(probe,'_repo_socket_denied',return_value='EACCES'):
            result=probe.observe('repo',value,_hash(value))
        self.assertEqual(
            result['evidence']['socketEvidence'],{'connectDenied':'EACCES'})
        self.assertEqual(result['evidence']['denials'],denials)
        self.assertIs(result['runtimeActivationAllowed'],False)
        self.assertIs(result['ownerAcceptanceVerified'],False)

    def test_no_automatic_authority_fields_exist_in_source_probe(self):
        self.assertNotIn('FUNCTIONAL_V1_GO',probe._RESULT)
        self.assertEqual(probe._RESULT,
                         'SOURCE_ONLY_CROSS_UID_ACCESS_OBSERVATION')
        self.assertFalse(probe._PROFILE_FIELDS & {
            'authenticatedOwner','actor','apiKey','password','witness',
            'liveRegistryGrant','allowWrite','install','deploy'})


if __name__=='__main__':
    unittest.main()

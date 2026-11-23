"""Source-only observation fixture; cannot attest owner Docker/image/host."""
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from fortis_approvals.core import Denied
from fortis_approvals.registry import owner_candidate_pidfd_observation as observer


class OwnerCandidatePidfdObservationTests(unittest.TestCase):
    def test_never_owner_go_and_rejects_self_or_wrong_identity(self):
        with self.assertRaisesRegex(Denied,'CALLER_OR_ARGUMENTS_DENIED'):
            observer.observe(pid=os.getpid(), registry_uid=os.geteuid(),
                             registry_gid=os.getegid(),reader_gid=os.getegid()+1)
        with self.assertRaisesRegex(Denied,'CALLER_OR_ARGUMENTS_DENIED'):
            observer.observe(pid=1234, registry_uid=os.geteuid(),
                             registry_gid=os.getegid(),reader_gid=os.getegid())
        for wrong in (None, True, 0, '1', -1):
            with self.subTest(wrong=wrong),self.assertRaises(Denied):
                observer.observe(pid=wrong,registry_uid=os.geteuid(),
                                 registry_gid=os.getegid(),
                                 reader_gid=os.getegid()+1)

    def test_wrong_config_command_never_claims_registry(self):
        with self.assertRaises(Denied):
            observer._process(os.getpid(),os.geteuid(),os.getegid(),
                              os.getegid()+1)

    def test_real_kernel_peer_pidfd_without_fake_host_acceptance(self):
        # Process and live Unix peer are real. Only the owner-visible Docker
        # source/mount/status seams are *mocked*; this is not a host test.
        with tempfile.TemporaryDirectory(prefix='fortis-registry-observer-') as temp:
            socket_path=Path(temp)/'reader.sock'
            source=(
                'import socket,sys,time;'
                's=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);'
                's.bind(sys.argv[1]);s.listen(1);'
                'conn,_=s.accept();conn.recv(1);conn.close();'
                'conn,_=s.accept();conn.recv(1);conn.close();s.close()'
            )
            child=subprocess.Popen([sys.executable,'-B','-c',source,str(socket_path)],
                     stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
            try:
                deadline=time.monotonic()+3
                while not socket_path.exists() and time.monotonic()<deadline:
                    time.sleep(0.01)
                self.assertTrue(socket_path.exists())
                def info(pid,uid,gid,reader_gid):
                    self.assertEqual(pid,child.pid)
                    return {'pid':pid,'startTicks':44,'uid':uid,'gid':gid,
                            'groups':[gid],'pidNamespace':'pid:[fixture]'}
                # The real observer would read stat/ACL directly. Fixture
                # patches are limited to inaccessible cross-GID host metadata.
                with patch.object(observer,'_process',side_effect=info), \
                     patch.object(observer,'_socket_stat',return_value=(11,22)), \
                     patch.object(observer,'_SOCKET',socket_path):
                    output=observer.observe(pid=child.pid,
                           registry_uid=os.geteuid(),registry_gid=os.getegid(),
                           reader_gid=os.getegid()+1)
                # A different live process with the *same UID* must NOT
                # authenticate as the actual Unix listener; owner-reported
                # process IDs are not trusted without kernel matching.
                other=subprocess.Popen([sys.executable,'-B','-c',
                                        'import time;time.sleep(2)'],
                         stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
                try:
                    with patch.object(observer,'_process',
                                      return_value={'pid':other.pid,
                                        'startTicks':44,'uid':os.geteuid(),
                                        'gid':os.getegid(),
                                        'groups':[os.getegid()],
                                        'pidNamespace':'pid:[fixture]'}), \
                         patch.object(observer,'_socket_stat',return_value=(11,22)), \
                         patch.object(observer,'_SOCKET',socket_path):
                        with self.assertRaisesRegex(Denied,'LISTENER_PROCESS_MISMATCH'):
                            observer.observe(pid=other.pid,
                                registry_uid=os.geteuid(),
                                registry_gid=os.getegid(),
                                reader_gid=os.getegid()+1)
                finally:
                    if other.poll() is None:other.kill()
                    other.wait(timeout=3)
                    other.stderr.close()
                self.assertEqual(output['result'],observer._RESULT)
                self.assertEqual(output['selectedPid'],child.pid)
                self.assertGreater(output['registryPidfdInode'],0)
                self.assertEqual(output['socketInode'],22)
                for field in ('containerImageVerified','ownerAcceptanceVerified',
                              'profileSealed','releaseAdmitted',
                              'runtimeActivationAllowed'):
                    self.assertIs(output[field],False)
            finally:
                if child.poll() is None:
                    child.kill()
                child.wait(timeout=3)
                child.stderr.close()

    def test_declared_image_and_source_only_contract(self):
        root=Path(__file__).resolve().parents[2]
        image=(root/'fortis_approvals/deploy/Dockerfile-Registry-Read-Candidate').read_text()
        catalog=(root/'release/targets.yaml').read_text()
        self.assertIn('owner_candidate_pidfd_observation.py',image)
        self.assertIn('owner_candidate_pidfd_observation.py',catalog)
        code=Path(observer.__file__).read_text()
        self.assertNotIn('Docker-Text',code)
        self.assertNotIn('FUNCTIONAL_V1_GO',code)
        self.assertIn('ownerAcceptanceVerified=False',code)
        self.assertIn('runtimeActivationAllowed=False',code)
        self.assertNotIn('docker.sock',code.replace('Docker socket',''))


if __name__=='__main__':unittest.main()

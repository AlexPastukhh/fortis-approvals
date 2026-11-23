"""Offline E1.3b helper tests; NOT real host identity or release admission."""
import errno
import os
import socket
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fortis_approvals.core import Denied
from fortis_approvals.integrations.registry import owner_pinned_pidfd as pidfd


class OwnerPinnedPidfdTests(unittest.TestCase):
    def setUp(self):
        self.left, self.right = socket.socketpair(socket.AF_UNIX,
                                                   socket.SOCK_STREAM)
        self.addCleanup(self.left.close)
        self.addCleanup(self.right.close)
        self.boot = pidfd._boot_id()
        me = os.pidfd_open(os.getpid())
        self.inode = os.fstat(me).st_ino
        os.close(me)
        self.opts = dict(expected_uid=os.geteuid(), expected_gid=os.getegid(),
                         expected_pidfd_inode=self.inode,
                         expected_boot_id=self.boot)

    def test_registry_server_can_verify_kernel_alive_with_pid_zero(self):
        peer=pidfd.kernel_live_peer(self.left,
                         expected_uid=os.geteuid(), expected_gid=os.getegid())
        self.assertEqual(peer[1:4], (os.geteuid(),os.getegid(),self.inode))
        self.assertEqual(peer[4],self.boot)
        with patch.object(pidfd, '_credentials',
                          return_value=(0,os.geteuid(),os.getegid())):
            peer=pidfd.kernel_live_peer(self.left,
                         expected_uid=os.geteuid(), expected_gid=os.getegid())
            self.assertEqual(peer[0],0)
            self.assertEqual(peer[3],self.inode)
        with self.assertRaisesRegex(Denied,'CREDENTIALS_DENIED'):
            pidfd.kernel_live_peer(self.left,
                         expected_uid=os.geteuid()+1, expected_gid=os.getegid())

    def test_real_kernel_credentials_and_owner_bound_inode(self):
        self.assertEqual(pidfd.owner_pinned_peer(self.left, **self.opts),
                         (os.geteuid(), os.getegid(), self.inode))
        self.assertEqual(pidfd.owner_pinned_peer(self.right, **self.opts),
                         (os.geteuid(), os.getegid(), self.inode))

    def test_wrong_inode_user_group_and_boot_fail_closed(self):
        for wrong in (dict(expected_pidfd_inode=self.inode + 1),
                      dict(expected_uid=os.geteuid() + 1),
                      dict(expected_gid=os.getegid() + 1),
                      dict(expected_boot_id='00000000-0000-0000-0000-000000000000'),
                      dict(expected_pidfd_inode=True),
                      dict(expected_boot_id='not-a-uuid')):
            with self.subTest(wrong=wrong), self.assertRaises(Denied):
                pidfd.owner_pinned_peer(self.left, **(self.opts|wrong))

    def test_unsupported_kernel_option_never_falls_back(self):
        # A subclass can simulate an unsupported option while real OS
        # credentials and the socket transport continue to work.
        class BlockingSocket(socket.socket):
            def getsockopt(self, level, optname, buflen=0):
                if optname == pidfd._SO_PEERPIDFD:
                    raise OSError(errno.ENOPROTOOPT, 'unsupported')
                return super().getsockopt(level, optname, buflen)
        one = BlockingSocket(fileno=os.dup(self.left.fileno()))
        try:
            with self.assertRaisesRegex(Denied,'REGISTRY_PIDFD_PROCESS_UNAVAILABLE'):
                pidfd.owner_pinned_peer(one, **self.opts)
        finally:
            one.close()

    def test_pid_zero_requires_real_pinned_pidfd_not_uid_gid_only(self):
        with patch.object(pidfd, '_credentials',
                          return_value=(0, os.geteuid(), os.getegid())):
            self.assertEqual(pidfd.owner_pinned_peer(self.left, **self.opts),
                             (os.geteuid(), os.getegid(), self.inode))
            with self.assertRaisesRegex(Denied,'PROCESS_NOT_PINNED'):
                pidfd.owner_pinned_peer(self.left,
                    **(self.opts|{'expected_pidfd_inode':self.inode + 1}))

    def test_old_kernel_pidfd_inode_is_not_accepted(self):
        with patch.object(pidfd.platform, 'release', return_value='6.8.12'):
            with self.assertRaisesRegex(Denied,'PIDFS_UNAVAILABLE'):
                pidfd.owner_pinned_peer(self.left, **self.opts)
        with patch.object(pidfd.platform, 'release', return_value='5.15.161'):
            with self.assertRaisesRegex(Denied,'PIDFS_UNAVAILABLE'):
                pidfd.owner_pinned_peer(self.left, **self.opts)
        with patch.object(pidfd.platform, 'release', return_value='invalid'):
            with self.assertRaisesRegex(Denied,'PIDFS_UNAVAILABLE'):
                pidfd.owner_pinned_peer(self.left, **self.opts)

    def test_no_host_default_authorization(self):
        with self.assertRaises(TypeError):
            pidfd.owner_pinned_peer(self.left)
        with self.assertRaisesRegex(Denied,'CONFIG_DENIED'):
            pidfd.owner_pinned_peer(self.left,
                **(self.opts|{'expected_uid':None}))

    def test_kernel_pidfd_exit_is_fail_closed(self):
        # Make a real child process establish the socket, then terminate.
        with tempfile.TemporaryDirectory(prefix='fortis-pidfd-exit-') as tmp:
            path=str(Path(tmp)/'peer.sock')
            listener=socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            listener.bind(path);listener.listen(1);listener.settimeout(3)
            self.addCleanup(listener.close)
            code=('import socket,sys; s=socket.socket(socket.AF_UNIX);'
                  's.connect(sys.argv[1]); s.recv(1); s.close()')
            child=subprocess.Popen([sys.executable,'-B','-c',code,path],
                                    env={'PYTHONDONTWRITEBYTECODE':'1'},
                                    stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
            try:
                connection,_=listener.accept()
                with connection:
                    expected=os.pidfd_open(child.pid)
                    inode=os.fstat(expected).st_ino
                    os.close(expected)
                    opts=self.opts|{'expected_pidfd_inode':inode}
                    self.assertEqual(pidfd.owner_pinned_peer(connection,**opts),
                                     (os.geteuid(),os.getegid(),inode))
                    connection.sendall(b'x')
                    child.wait(timeout=3)
                    self.assertEqual(child.returncode,0,child.stderr.read())
                    with self.assertRaisesRegex(Denied,'PROCESS_EXITED'):
                        pidfd.owner_pinned_peer(connection,**opts)
            finally:
                if child.poll() is None:
                    child.kill();child.wait(timeout=3)
                child.stderr.close()


if __name__ == '__main__':
    unittest.main()

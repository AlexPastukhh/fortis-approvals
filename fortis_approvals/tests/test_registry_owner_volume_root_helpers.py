"""Offline guard and effect-order tests: no Docker and no actual chown/chmod."""
import contextlib
import io
import json
import os
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, patch, mock_open

from scripts import registry_owner_volume_prepare_roots as prepare
from scripts import registry_owner_volume_inspect_roots as inspect
from scripts.registry_owner_volume_contract import plan_private_volume_roots

ROOT = Path(__file__).resolve().parents[2]


def row(uid=0, gid=0, mode=0o755, inode=1, device=42):
    return SimpleNamespace(st_uid=uid, st_gid=gid, st_mode=stat.S_IFDIR | mode,
                           st_dev=device, st_ino=inode)


class OwnerVolumeRootSourceTests(unittest.TestCase):
    def test_layout_matches_existing_contract(self):
        expected = tuple((x.mount, x.uid, x.gid, x.mode)
                         for x in plan_private_volume_roots('9c2a71ef'))
        self.assertEqual(prepare.ROOTS, expected)
        self.assertEqual(inspect.ROOTS, expected)
        text = (ROOT / 'scripts/registry_owner_volume_inspect_roots.py').read_text()
        for token in ('fchown(', 'fchmod(', 'chmod(', 'chown(', 'mkdir(', 'unlink(',
                      'subprocess', 'socket.connect', 'O_WRONLY', 'O_RDWR'):
            self.assertNotIn(token, text)

    def test_prepare_checks_all_three_before_any_effect(self):
        with patch.object(prepare, 'runtime') as runtime, \
             patch.object(prepare, 'mount_rows'), \
             patch.object(prepare, 'open_root', side_effect=[(10, row(inode=10)),
                        (11, row(inode=11)), (12, row(uid=123, inode=12))]), \
             patch.object(prepare.os, 'fchown') as chown, \
             patch.object(prepare.os, 'fchmod') as chmod:
            with self.assertRaisesRegex(RuntimeError, 'NOT_FRESH_DEFAULT_ROOT'):
                prepare.prepare()
            chown.assert_not_called()
            chmod.assert_not_called()
            runtime.assert_called_once_with(0, 10001, 9)

    def test_prepare_rejects_alias_before_first_effect(self):
        with patch.object(prepare, 'runtime'), patch.object(prepare, 'mount_rows'), \
             patch.object(prepare, 'open_root', side_effect=[(10, row()), (11, row())]), \
             patch.object(prepare.os, 'fchown') as chown:
            with self.assertRaisesRegex(RuntimeError, 'ROOT_ALIAS'):
                prepare.prepare()
            chown.assert_not_called()

    def test_prepare_stops_on_first_uncertain_mutation_no_compensation(self):
        roots = [(10 + i, row(inode=10 + i)) for i in range(3)]
        scanner = MagicMock()
        scanner.__enter__.return_value = iter(())
        with patch.object(prepare, 'runtime'), patch.object(prepare, 'mount_rows'), \
             patch.object(prepare, 'open_root', side_effect=roots), \
             patch.object(prepare.os, 'fstat', return_value=roots[0][1]), \
             patch.object(prepare.os, 'lseek'), patch.object(prepare.os, 'scandir', return_value=scanner), \
             patch.object(prepare.os, 'fchown', side_effect=OSError('uncertain')) as chown, \
             patch.object(prepare.os, 'fchmod') as chmod, \
             patch.object(prepare.os, 'fsync') as sync:
            with self.assertRaises(OSError):
                prepare.prepare()
            chown.assert_called_once_with(10, 20002, 20002)
            chmod.assert_not_called()
            sync.assert_not_called()

    def test_prepare_exact_effect_order_and_readback(self):
        roots = [(10 + i, row(inode=10 + i)) for i in range(3)]
        out = io.StringIO()
        trace = []
        def stat_for(fd):
            idx = fd - 10
            if ('chmod', fd, prepare.ROOTS[idx][3]) in trace:
                _, uid, gid, mode = prepare.ROOTS[idx]
                return row(uid, gid, mode, fd)
            return roots[idx][1]
        def scan(_fd):
            return contextlib.nullcontext(iter(()))
        with patch.object(prepare, 'runtime'), patch.object(prepare, 'mount_rows'), \
             patch.object(prepare, 'open_root', side_effect=roots), \
             patch.object(prepare.os, 'fstat', side_effect=stat_for), \
             patch.object(prepare.os, 'lseek'), patch.object(prepare.os, 'scandir', side_effect=scan), \
             patch.object(prepare.os, 'fchown', side_effect=lambda fd,u,g: trace.append(('chown',fd,u,g))), \
             patch.object(prepare.os, 'fchmod', side_effect=lambda fd,m: trace.append(('chmod',fd,m))), \
             patch.object(prepare.os, 'fsync', side_effect=lambda fd: trace.append(('sync',fd))), \
             contextlib.redirect_stdout(out):
            prepare.prepare()
        expected = []
        for i, (_, u, g, m) in enumerate(prepare.ROOTS):
            expected.extend([('chown',10+i,u,g), ('chmod',10+i,m), ('sync',10+i)])
        self.assertEqual(trace, expected)
        self.assertEqual(len(out.getvalue().splitlines()), 4)
        self.assertEqual(json.loads(out.getvalue().splitlines()[-1])['result'],
                         'E13B_VOLUME_ROOT_PREPARE_PASS')

    def test_inspector_is_nonroot_and_independent(self):
        roots = [(i, row(u,g,m,i+1)) for i,(_,u,g,m) in enumerate(inspect.ROOTS)]
        out = io.StringIO()
        with patch.object(inspect, 'runtime') as runtime, patch.object(inspect,'mount_rows') as mounts, \
             patch.object(inspect,'open_root',side_effect=roots), contextlib.redirect_stdout(out):
            inspect.inspect_roots()
        runtime.assert_called_once_with(20002, 20002, 0)
        mounts.assert_called_once_with(True)
        receipt=json.loads(out.getvalue())
        self.assertEqual(receipt['result'], 'E13B_VOLUME_ROOT_INSPECT_READONLY_PASS')
        self.assertEqual(receipt['roots'][2]['mode'], 0o2710)
        with patch.object(inspect,'runtime'), patch.object(inspect,'mount_rows'), \
             patch.object(inspect,'open_root',return_value=(1,row())):
            with self.assertRaisesRegex(RuntimeError,'OWNER_MODE_INVALID'):
                inspect.inspect_roots()

    def test_runtime_requires_exact_caps_and_vm_maps(self):
        for module, uid, gid, cap in ((prepare,0,10001,9),(inspect,20002,20002,0)):
            status = ('CapInh: 00000000\nCapAmb: 00000000\n'
                      f'CapPrm: {cap:08x}\nCapEff: {cap:08x}\nCapBnd: {cap:08x}\n'
                      'NoNewPrivs: 1\nSeccomp: 2\nTracerPid: 0\n')
            def run_with(status_text, map_text='0 0 4294967295\n'):
                def proc(path, **_):
                    return io.StringIO(status_text if path.endswith('/status') else map_text)
                with patch.object(module.os, 'getresuid', return_value=(uid,)*3), \
                     patch.object(module.os, 'getresgid', return_value=(gid,)*3), \
                     patch.object(module.os, 'getgroups', return_value=[gid]), \
                     patch.object(module.os, 'statvfs', return_value=SimpleNamespace(f_flag=os.ST_RDONLY)), \
                     patch('builtins.open', side_effect=proc):
                    module.runtime(uid, gid, cap)
            run_with(status)
            for bad in (status.replace(f'CapEff: {cap:08x}', 'CapEff: 00000002'),
                        status.replace('NoNewPrivs: 1','NoNewPrivs: 0'),
                        status.replace('Seccomp: 2','Seccomp: 0')):
                with self.assertRaisesRegex(RuntimeError, 'CONFINEMENT_INVALID'):
                    run_with(bad)
            with self.assertRaisesRegex(RuntimeError, 'MAP_NOT_IDENTITY'):
                run_with(status, '0 100000 65536\n')

    def test_mountinfo_denies_missing_nested_or_wrong_access(self):
        for module in (prepare, inspect):
            for ro in (False, True):
                flag='ro' if ro else 'rw'
                text=''.join(f'{i} 1 8:1 /volume{i} {p} {flag} - ext4 /dev/test rw\n'
                             for i,(p,*_) in enumerate(module.ROOTS, 2))
                with patch('builtins.open',mock_open(read_data=text)):
                    module.mount_rows(ro)
                for bad in (text.replace(flag, 'rw' if ro else 'ro', 1),
                            text.splitlines()[0]+'\n', text+f'9 1 8:1 /nested {module.ROOTS[0][0]}/child {flag} - ext4 /dev/test rw\n'):
                    with patch('builtins.open',mock_open(read_data=bad)):
                        with self.assertRaises(RuntimeError):
                            module.mount_rows(ro)

    def test_open_root_denies_nonempty_and_alias_without_mutation(self):
        with tempfile.TemporaryDirectory() as directory:
            p=Path(directory).resolve()/'root'
            p.mkdir()
            (p/'file').write_text('fixture')
            with contextlib.ExitStack() as stack:
                with self.assertRaisesRegex(RuntimeError,'ROOT_NOT_EMPTY'):
                    prepare.open_root(stack,str(p),False)
            alias=Path(directory)/'alias'
            alias.symlink_to(p,target_is_directory=True)
            with contextlib.ExitStack() as stack:
                with self.assertRaisesRegex(RuntimeError,'PATH_ALIAS'):
                    prepare.open_root(stack,str(alias),False)

    def test_controller_retains_exact_gate_and_no_cleanup(self):
        text=(ROOT/'scripts/registry_owner_volume_controller.ps1').read_text()
        for marker in ('SEPARATE_OWNER_HOST_GO_REQUIRED','OWNER_REVIEW_SCOPE_MISMATCH',
                       'OWNER_REVIEW_EVIDENCE_PIN_INVALID','VOLUME_ALREADY_EXISTS_NO_ADOPTION',
                       'HELPER_NOCOPY_OR_RO_INVALID','VOLUME_ATTACHMENT_CONFLICT',
                       'INDEPENDENT_ROOT_IDENTITY_CHANGED','HELPERS_RETAINED',
                       "'--cap-add','CHOWN','--cap-add','FOWNER'",'0:10001','20002:20002'):
            self.assertIn(marker,text)
        for token in ("'volume','rm'", "'container','rm'", "'--privileged'", "'--rm'", "'--cap-add','DAC_OVERRIDE'", "'--pid=host'", '/var/run/docker.sock'):
            self.assertNotIn(token,text)


if __name__ == '__main__':
    unittest.main()

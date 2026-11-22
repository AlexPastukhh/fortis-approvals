"""Source-worktree confinement, dry-run, fault recovery and DRY tests.

All writes are in disposable fixture directories. GitHub/Windows/Gateway
never receive these generated packages.
"""
from copy import deepcopy
from pathlib import Path
import os
import subprocess
import sys
from tempfile import TemporaryDirectory
from unittest import TestCase
from unittest.mock import patch

from fortis_approvals.core import Denied
from fortis_approvals.extensions import source_generator as generator
from fortis_approvals.extensions import source_workspace as workspace
from fortis_approvals.tests.test_source_generator import record_description


class SourceWorkspaceTests(TestCase):
    def setUp(self):
        self.temporary=TemporaryDirectory(prefix='fortis-workspace-qa-')
        self.addCleanup(self.temporary.cleanup)
        self.root=Path(self.temporary.name)
        self.base=self.root/'fortis_approvals'/'integrations'
        self.base.mkdir(parents=True)
        (self.root/'fortis_approvals'/'extensions').mkdir()
        (self.root/'fortis_approvals'/'extensions'/'model.py').write_text('# fixture')
        self.original=record_description()

    @staticmethod
    def files(root):
        return {str(p.relative_to(root)):p.read_bytes() for p in root.rglob('*')
                if p.is_file() and not p.is_symlink()}

    def apply(self,description):
        # Exercise real filesystem apply, but independent fixture paths cannot
        # pass the full registered task worktree check by design.
        with patch.object(generator,'_check_task_worktree',return_value=None):
            return generator.apply_source_package(self.root,description)

    def expanded(self):
        desc=deepcopy(self.original)
        extra=deepcopy(desc['methods'][0]);extra['name']='get_summary';extra['route']='summary'
        desc['routes'].append({'name':'summary',
              'path':'/v1/records/{action_id}/summary','queryKeys':[]})
        desc['methods'].append(extra)
        return desc

    def test_preview_is_byte_read_only_and_apply_reports_real_changes(self):
        before=self.files(self.root)
        plan=generator.source_plan(self.root,self.original)
        self.assertEqual(before,self.files(self.root))
        self.assertEqual(len(plan['changes']),5)
        created=self.apply(self.original)
        self.assertEqual(created['changes'],plan['changes'])
        self.assertEqual(len(created['appliedFiles']),5)
        self.assertEqual(generator.source_plan(self.root,self.original)['changes'],[])
        original_bytes=(self.base/'study_records'/'manual.py').read_bytes()
        changed=self.expanded()
        update_plan=generator.source_plan(self.root,changed)
        updated=self.apply(changed)
        self.assertEqual(updated['changes'],update_plan['changes'])
        self.assertEqual(updated['appliedFiles'],['definition.py','CONTRACT.generated.md'])
        self.assertEqual((self.base/'study_records'/'manual.py').read_bytes(),original_bytes)
        self.assertEqual(generator.source_plan(self.root,changed)['changes'],[])

    def test_unsafe_source_parent_symlink_refused_before_writes(self):
        outer=self.root/'external'
        outer.mkdir()
        source=self.root/'fortis_approvals'
        target=outer/'fortis_approvals'
        source.rename(target)
        source.symlink_to(target,target_is_directory=True)
        with self.assertRaisesRegex(Denied,'SOURCE_SYMLINK_DENIED'):
            self.apply(self.original)
        self.assertEqual(list((target/'integrations').iterdir()),[])

    def test_fake_root_without_git_refused_by_public_apply(self):
        with self.assertRaisesRegex(Denied,'SOURCE_TASK_WORKTREE_REQUIRED'):
            generator.apply_source_package(self.root,self.original)
        self.assertEqual(list(self.base.iterdir()),[])

    def test_fake_git_task_branch_is_not_a_registered_fortis_worktree(self):
        subprocess.run(['git','init','-q',str(self.root)],check=True,
                       capture_output=True,timeout=10)
        subprocess.run(['git','-C',str(self.root),'checkout','-q','-b',
                        'task/pretend'],check=True,capture_output=True,timeout=10)
        with self.assertRaisesRegex(Denied,'SOURCE_TASK_WORKTREE_REQUIRED'):
            generator.apply_source_package(self.root,self.original)
        self.assertEqual(list(self.base.iterdir()),[])

    def test_failed_second_rename_rolls_back_and_can_retry(self):
        self.apply(self.original)
        previous=self.files(self.base/'study_records')
        new=self.expanded()
        actual=os.replace;calls=[]
        def injected(source,target):
            calls.append(str(target))
            if len(calls)==2:raise OSError('offline second rename failure')
            return actual(source,target)
        with patch.object(workspace.os,'replace',side_effect=injected):
            with self.assertRaisesRegex(OSError,'offline second rename failure'):
                self.apply(new)
        self.assertEqual(self.files(self.base/'study_records'),previous)
        self.assertEqual(workspace._pending(self.base,'study_records'),[])
        final=self.apply(new)
        self.assertIn('definition.py',final['appliedFiles'])
        self.assertEqual(generator.source_plan(self.root,new)['changes'],[])

    def test_hard_exit_between_renames_is_recovered_on_retry(self):
        self.apply(self.original)
        prior_manual=(self.base/'study_records'/'manual.py').read_bytes()
        payload=self.expanded()
        # An isolated process ends without executing any Python finally block.
        code='''import os,sys,json
from pathlib import Path
from fortis_approvals.extensions import source_workspace as ws
from fortis_approvals.extensions import source_generator as sg
root=Path(sys.argv[1]);desc=json.loads(sys.argv[2]);source,files=sg._prepared(desc)
real=os.replace;state=[0]
def kill_after_backup(old,new):
 state[0]+=1
 if state[0]==2:os._exit(77)
 return real(old,new)
ws.os.replace=kill_after_backup
ws.apply(root,source['provider'],files,{'manual.py':sg._MANUAL,'tests/test_manual.py':sg._MANUAL_TEST})
'''
        from json import dumps
        env=dict(os.environ)
        env['PYTHONPATH']=str(Path(__file__).resolve().parents[2])
        run=subprocess.run([sys.executable,'-B','-c',code,str(self.root),dumps(payload)],
                           env=env,capture_output=True,timeout=20)
        self.assertEqual(run.returncode,77,run.stderr.decode(errors='replace'))
        self.assertFalse((self.base/'study_records').exists())
        self.assertEqual(len(workspace._pending(self.base,'study_records')),1)
        # A dry-run is never permitted to perform recovery writes.
        with self.assertRaisesRegex(Denied,'SOURCE_PENDING_TRANSACTION_REQUIRES_APPLY'):
            generator.source_plan(self.root,payload)
        outcome=self.apply(payload)
        self.assertEqual(outcome['recovery'],'rolled_back')
        self.assertEqual((self.base/'study_records'/'manual.py').read_bytes(),prior_manual)
        self.assertEqual(workspace._pending(self.base,'study_records'),[])
        self.assertEqual(generator.source_plan(self.root,payload)['changes'],[])

    def test_hard_exit_after_commit_is_reconciled_without_rewriting(self):
        self.apply(self.original)
        payload=self.expanded()
        code='''import os,sys,json
from pathlib import Path
from fortis_approvals.extensions import source_workspace as ws
from fortis_approvals.extensions import source_generator as sg
root=Path(sys.argv[1]);desc=json.loads(sys.argv[2]);source,files=sg._prepared(desc)
real=ws.shutil.rmtree

def kill_on_cleanup(path,*args,**kwargs):
 if Path(path).name.startswith('_study_records_source_txn_'):os._exit(78)
 return real(path,*args,**kwargs)
ws.shutil.rmtree=kill_on_cleanup
ws.apply(root,source['provider'],files,{'manual.py':sg._MANUAL,'tests/test_manual.py':sg._MANUAL_TEST})
'''
        from json import dumps
        env=dict(os.environ)
        env['PYTHONPATH']=str(Path(__file__).resolve().parents[2])
        run=subprocess.run([sys.executable,'-B','-c',code,str(self.root),dumps(payload)],
                           env=env,capture_output=True,timeout=20)
        self.assertEqual(run.returncode,78,run.stderr.decode(errors='replace'))
        self.assertEqual(len(workspace._pending(self.base,'study_records')),1)
        with self.assertRaisesRegex(Denied,'SOURCE_PENDING_TRANSACTION_REQUIRES_APPLY'):
            generator.source_plan(self.root,payload)
        outcome=self.apply(payload)
        self.assertEqual(outcome['recovery'],'committed')
        self.assertEqual(outcome['appliedFiles'],[])
        self.assertEqual(workspace._pending(self.base,'study_records'),[])

    def test_tampered_committed_source_preserves_recovery_backup(self):
        self.apply(self.original)
        payload=self.expanded()
        old_bytes=(self.base/'study_records'/'definition.py').read_bytes()
        real_remove=workspace.shutil.rmtree
        def fail_after_swap(path,*args,**kwargs):
            if Path(path).name.startswith('_study_records_source_txn_'):
                raise OSError('offline post-commit cleanup crash')
            return real_remove(path,*args,**kwargs)
        with patch.object(workspace.shutil,'rmtree',side_effect=fail_after_swap):
            with self.assertRaisesRegex(OSError,'offline post-commit cleanup crash'):
                self.apply(payload)
        package=self.base/'study_records'
        pending=workspace._pending(self.base,'study_records')
        self.assertEqual(len(pending),1)
        self.assertEqual((pending[0]/'previous'/'definition.py').read_bytes(),old_bytes)
        with (package/'definition.py').open('a') as stream:
            stream.write('# concurrent unexpected change\n')
        with self.assertRaisesRegex(Denied,'SOURCE_TRANSACTION_RECOVERY_REVIEW_REQUIRED'):
            self.apply(payload)
        self.assertEqual(workspace._pending(self.base,'study_records'),pending)
        self.assertEqual((pending[0]/'previous'/'definition.py').read_bytes(),old_bytes)

    def test_apply_normalizes_and_compiles_once_per_description(self):
        with patch.object(generator,'_source',wraps=generator._source) as source:
            with patch.object(generator,'_assert_compilable',
                              wraps=generator._assert_compilable) as compiler:
                self.apply(self.original)
                self.assertEqual(source.call_count,1)
                self.assertEqual(compiler.call_count,1)

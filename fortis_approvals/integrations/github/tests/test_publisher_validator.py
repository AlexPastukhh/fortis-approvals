"""Pin-loader isolation tests; real public-validator integration is explicitly supplied."""
from dataclasses import replace
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from fortis_approvals.core import Denied
from fortis_approvals.integrations.github.publisher_validator import PinnedValidator
from fortis_approvals.workflow.common import Git, secure_dir
from publisher_runner_fixture import RunnerFixture, BODY

PIN = '6627da85cab34dec75333676ec6215de8e0130ff'
# Protocol-only trusted fixtures. Classification semantics stay in the public action.
CHECKED_STUB = """import json,os,sys
from pathlib import Path
def run(event_file,**kwargs):
    assert sys.flags.isolated and sys.dont_write_bytecode
    assert os.environ.get('PUBLISHER_POISON') is None
    assert not Path(__file__).with_name('untracked.py').exists()
    event=json.loads(event_file.read_text())
    return dict(status='PASS',repository=kwargs['repository'],
                headSha=event['pull_request']['head']['sha'],
                pullRequest=event['pull_request']['number'],
                classification='no-deployment',affectedTargets=[])
"""
PLAN_STUB = """def plan_labels(admission,checked,pr,existing,available):
    return dict(status='PREVIEW_ONLY',repository=admission['repository'],
        headSha=admission['headSha'],pullRequest=admission['pullRequest'],
        suggestedLabels=['release:no-deployment'],add=[],remove=[],
        missingDefinitions=[],preservedHumanLabels=['bug'],preservedReviewFlag=True)
"""


class PinLoaderTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.code=secure_dir(self.root/'code')
        git=Git(self.root/'git-state');git.run(['init','--quiet','--template=',self.code])
        for args in [('user.name','Fixture'),('user.email','fixture@example.invalid')]:
            git.run(['config',*args],cwd=self.code)
        folder=self.code/'tools/release';folder.mkdir(mode=0o700,parents=True)
        (folder/'ci_entry.py').write_text(CHECKED_STUB)
        (folder/'label_admission_v1.py').write_text(PLAN_STUB)
        git.run(['add','--all'],cwd=self.code);git.run(['commit','--quiet','-m','Pinned protocol fixture'],cwd=self.code)
        self.pin=git.text(['rev-parse','HEAD'],cwd=self.code)
        self.f=RunnerFixture(self.root/'runner',revision=self.pin,validator_root=self.code,
                             validator_factory=PinnedValidator)

    def test_isolated_pin_never_imports_pr_code_or_inherited_python_path(self):
        with patch.dict(os.environ,{'PYTHONPATH':str(self.f.graph.repository),'PUBLISHER_POISON':'untrusted'}):
            result=self.f.runner.preview(7)
        self.assertEqual(result['status'],'NO_CHANGES')
        self.assertEqual(self.f.gateway.core.owner_list(),[])

    def test_dirty_or_untracked_validator_code_is_rejected_before_execution(self):
        original=(self.code/'tools/release/ci_entry.py').read_bytes()
        (self.code/'tools/release/ci_entry.py').write_text("raise RuntimeError('DIRTY CODE EXECUTED')\n")
        with self.assertRaisesRegex(Denied,'PUBLISHER_VALIDATOR_WORKTREE_CHANGED'):
            self.f.runner.request(7)
        (self.code/'tools/release/ci_entry.py').write_bytes(original)
        (self.code/'tools/release/untracked.py').write_text("raise RuntimeError('UNTRACKED CODE EXECUTED')\n")
        self.f.next_invocation()
        with self.assertRaisesRegex(Denied,'PUBLISHER_VALIDATOR_WORKTREE_CHANGED'):
            self.f.runner.request(7)
        self.assertEqual(self.f.gateway.core.owner_list(),[])

    def test_wrong_validator_checkout_pin_stops_before_ask(self):
        self.f.graph.git.run(['-C',self.code,'commit','--allow-empty','--quiet','-m','Wrong code revision'])
        with self.assertRaisesRegex(Denied,'PUBLISHER_VALIDATOR_PIN_CHANGED'):self.f.runner.request(7)
        self.assertEqual(self.f.gateway.core.owner_list(),[])

    def test_invalid_protocol_output_stops_before_ask(self):
        # The reviewed code fixture is intentionally made invalid under its own new pin.
        (self.code/'tools/release/label_admission_v1.py').write_text(
            "def plan_labels(*args): return {'status':'PREVIEW_ONLY'}\n")
        git=self.f.graph.git;git.run(['-C',self.code,'add','--all']);git.run(['-C',self.code,'commit','--quiet','-m','Invalid protocol fixture'])
        revision=git.text(['-C',self.code,'rev-parse','HEAD'])
        f=RunnerFixture(self.root/'other',revision=revision,validator_root=self.code,validator_factory=PinnedValidator)
        with self.assertRaises(Denied):f.runner.request(7)
        self.assertEqual(f.gateway.core.owner_list(),[])


@unittest.skipUnless(os.environ.get('FORTIS_TEST_VALIDATOR_ROOT'),
                     'Cross-repository integration requires an explicitly supplied pinned public validator')
class RealValidatorIntegration(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)
        self.f=RunnerFixture(self.root,revision=PIN,
            validator_root=Path(os.environ['FORTIS_TEST_VALIDATOR_ROOT']),validator_factory=PinnedValidator)

    def test_real_exact_head_no_deployment_preserves_human_and_sticky_labels(self):
        result=self.f.runner.preview(7)
        self.assertEqual(result['plan']['classification'],'no-deployment')
        self.assertEqual(result['plan']['suggestedLabels'],['release:no-deployment'])
        self.assertEqual(result['plan']['preservedHumanLabels'],['bug'])
        self.assertTrue(result['plan']['preservedReviewFlag'])
        self.assertEqual(self.f.gateway.core.owner_list(),[])

    def test_shared_build_unit_targets_one_bounded_remove_then_fresh_add(self):
        self.f.graph.write('runtime/app.py','CHANGED = 2\n')
        self.f.update_head('Runtime change')
        self.f.api.body=BODY.replace('classification: no-deployment','classification: deployment').replace(
            '  targets: []','  targets:\n    - id: api\n      actions: [image-rebuild]\n    - id: worker\n      actions: [image-rebuild]',1)
        self.f.api.labels=['bug','release:review-required','release:no-deployment']
        self.f.api.definitions+=['build:worker']
        result=self.f.runner.request(7)
        self.assertEqual(result['prepared']['plan']['suggestedLabels'],
                         ['build:api','build:worker','release:image-rebuild'])
        self.assertEqual(result['prepared']['operation'],'remove_pr_release_label')
        self.assertEqual(result['prepared']['params']['name'],'release:no-deployment')
        self.assertEqual(self.f.gateway.approve(result['intent']['requestId'])['state'],'EXECUTED')
        self.f.next_invocation()
        report=self.f.runner.inspect(result['intent']['intentId'])
        self.assertTrue(report['originalRequests'][0]['receiptVerified'])
        self.assertEqual(report['currentAdmission']['remainingRemove'],[])
        self.assertEqual(report['currentAdmission']['remainingAdd'],
                         ['build:api','build:worker','release:image-rebuild'])
        self.assertEqual(len(self.f.api.writes),1)

    def test_false_no_deployment_cannot_hide_runtime_change(self):
        self.f.graph.write('runtime/app.py','CHANGED = 3\n')
        self.f.update_head('Runtime source under false no-deployment')
        with self.assertRaises(Denied):self.f.runner.request(7)
        self.assertEqual(self.f.gateway.core.owner_list(),[])

    def test_unmatched_path_is_not_downgraded_to_no_deployment(self):
        self.f.graph.write('unclassified.bin',b'unknown data')
        self.f.update_head('Unknown source path')
        with self.assertRaises(Denied):self.f.runner.request(7)
        self.assertEqual(self.f.gateway.core.owner_list(),[])

    def test_yaml_code_constructor_does_not_execute(self):
        marker=self.root/'EXECUTED'
        self.f.api.body=BODY.replace('Only reviewed documentation data changes in this source fixture.',
            "!!python/object/apply:os.system ['touch "+str(marker)+"']")
        with self.assertRaises(Denied):self.f.runner.request(7)
        self.assertFalse(marker.exists());self.assertEqual(self.f.gateway.core.owner_list(),[])


if __name__=='__main__':
    unittest.main()

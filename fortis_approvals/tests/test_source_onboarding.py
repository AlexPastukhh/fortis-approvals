"""Single source onboarding workflow: auto, mixed, manual, pause and resume.

Executed in disposable folders with no registered provider, Git effects,
owner permissions, external network or installed Gateway.
"""
from copy import deepcopy
import importlib.util
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase
from unittest.mock import patch
import unittest

from fortis_approvals.core import Denied
from fortis_approvals.extensions import source_generator, source_onboarding
from fortis_approvals.extensions.source_generator import build_generated_provider
from fortis_approvals.tests.test_source_generator import (record_description,
                                                           service_description)
from fortis_approvals.tests.test_source_strategy import evidence
from fortis_approvals.tests.test_declarative_read import action_sample


POSTCHECK_SOURCE='''"""Reviewed narrow business constraint; source-owned."""
from fortis_approvals.core import Denied

def make_transport():raise Denied('UNUSED_TRANSPORT')
def result_postchecks():return {'read_action':_check}
def context_postchecks():return {}
def manual_operations():return ()
def _check(value):
    if not value['name'].startswith('Reviewed '):
        raise Denied('MANUAL_BUSINESS_REVIEW_REQUIRED')
'''

MANUAL_OP_SOURCE='''"""Source-reviewed hand-written read method."""
from fortis_approvals.extensions.model import Operation,check

def make_transport():raise NotImplementedError('standard API transport supplied')
def result_postchecks():return {}
def context_postchecks():return {}
def manual_operations():
    def params(value):check(type(value) is dict and value=={},'MANUAL_PARAMS')
    def result(value):check(value=={'manual':True},'MANUAL_RESULT')
    def execute(ctx):return {'manual':True}
    return (Operation('manual_health','Manual read via existing trusted transport',
                      'read',params,result,execute,routes=('health',)),)
'''


def reviewer_for(description):
    """Trusted test-owned verifier: real code import + provider contract checks.

    Production would require independently authorized source review; this
    callback is only supplied in offline tests AFTER inspecting manual source.
    """
    def verify(folder,requirements):
        source=folder/'manual.py'
        spec=importlib.util.spec_from_file_location('_fortis_offline_reviewed_manual',source)
        module=importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        provider=build_generated_provider(description,module)
        verified=[]
        for req in requirements:
            kind,name=req['kind'],req['method']
            if kind=='resultPostcheck':
                assert callable(module.result_postchecks().get(name))
                method=next(op for op in provider.operations if op.name==name)
                with __import__('unittest').TestCase().assertRaisesRegex(
                        Denied,'MANUAL_BUSINESS_REVIEW_REQUIRED'):
                    method.result(action_sample())
                good=action_sample();good['name']='Reviewed item'
                method.result(good)
            elif kind=='manualOperation':
                method=next(op for op in provider.operations if op.name==name)
                assert method.execute(None)=={'manual':True}
                method.result({'manual':True})
            elif kind=='trustedTransport':
                assert provider.api is not None
            else:
                raise AssertionError('unsupported offline manual requirement')
            verified.append(req)
        return {'passed':True,'verified':verified,
                'operations':sorted(op.name for op in provider.operations)}
    return verify


class OnboardingFlowTests(TestCase):
    def setUp(self):
        self.temp=TemporaryDirectory(prefix='fortis-onboarding-flow-')
        self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)
        self.session=self.root/'session'
        self.session.mkdir()
        self.source=self.root/'candidate'
        (self.source/'fortis_approvals'/'extensions').mkdir(parents=True)
        (self.source/'fortis_approvals'/'extensions'/'model.py').write_text('# fixture')
        (self.source/'fortis_approvals'/'integrations').mkdir()

    def stage(self):return source_onboarding.stage_path(self.session)

    def promote(self,description):
        # The only mock is external worktree authorization: generation and
        # filesystem validation execute normally against disposable source.
        with patch.object(source_generator,'_check_task_worktree',return_value=None):
            return source_onboarding.prepare_source(self.session,self.source,description)

    def _kill_source_process(self, snippet, args, expected):
        import os
        import subprocess
        import sys
        import json
        env=dict(os.environ)
        env['PYTHONPATH']=str(Path(__file__).resolve().parents[2])
        child=subprocess.run([sys.executable,'-B','-c',snippet,
                              str(self.session),json.dumps(args)],
                             capture_output=True,env=env,timeout=25)
        self.assertEqual(child.returncode,expected,
                         child.stderr.decode(errors='replace'))

    def test_begin_crash_before_atomic_replace_is_recoverable(self):
        src=record_description();facts=evidence()
        child='''import json,os,sys
from pathlib import Path
from fortis_approvals.extensions import source_onboarding as flow
real=flow.os.replace

def crash_before_file_rename(before,after):
    if Path(after).name=='definition.py':os._exit(91)
    return real(before,after)
flow.os.replace=crash_before_file_rename
flow.begin(sys.argv[1],json.loads(sys.argv[2])['facts'],
           json.loads(sys.argv[2])['source'])
'''
        self._kill_source_process(child,{'facts':facts,'source':src},91)
        # An abandoned private temp file may remain, but no active generated
        # file is corrupted and no manual source gets overwritten.
        self.assertEqual(source_onboarding.begin(self.session,facts,src)['phase'],
                         'SOURCE_READY')
        self.assertTrue((self.stage()/'definition.py').is_file())
        self.assertEqual(source_onboarding.inspect(self.session)['phase'],
                         'SOURCE_READY')

    def test_session_refuses_to_start_inside_provider_package(self):
        src=record_description();facts=evidence()
        nested=self.source/'fortis_approvals'/'integrations'/'sample_provider'/'session'
        nested.mkdir(parents=True)
        with self.assertRaisesRegex(Denied,'ONBOARDING_SESSION_WITHIN_PROVIDER'):
            source_onboarding.begin(nested,facts,src)
        self.assertEqual(list(nested.iterdir()),[])

    def test_begin_hard_crash_recovers_same_checkpoint(self):
        import json
        src=record_description();facts=evidence()
        child='''import json,os,sys
from pathlib import Path
from fortis_approvals.extensions import source_onboarding as flow
original=flow.os.replace
def stop_after_first_source_file(before,after):
    result=original(before,after)
    if Path(after).name=='__init__.py':os._exit(87)
    return result
flow.os.replace=stop_after_first_source_file
flow.begin(sys.argv[1],json.loads(sys.argv[2])['facts'],json.loads(sys.argv[2])['source'])
'''
        self._kill_source_process(child,{'facts':facts,'source':src},87)
        with self.assertRaisesRegex(Denied,'ONBOARDING_BEGIN_INCOMPLETE'):
            source_onboarding.inspect(self.session)
        state=source_onboarding.begin(self.session,facts,src)
        self.assertEqual(state['phase'],'SOURCE_READY')
        self.assertEqual(state['history'],[{'event':'ASSESS_AND_STAGE',
                                           'phase':'SOURCE_READY'}])
        self.assertEqual(source_onboarding.inspect(self.session)['phase'],'SOURCE_READY')

    def test_begin_hard_crash_after_file_completion_recovers(self):
        src=record_description();facts=evidence()
        child='''import json,os,sys
from fortis_approvals.extensions import source_onboarding as flow
real=flow._save;calls=[0]
def save_then_die(root,state):
    calls[0]+=1
    if calls[0]==2:os._exit(88)
    return real(root,state)
flow._save=save_then_die
flow.begin(sys.argv[1],json.loads(sys.argv[2])['facts'],json.loads(sys.argv[2])['source'])
'''
        self._kill_source_process(child,{'facts':facts,'source':src},88)
        result=source_onboarding.begin(self.session,facts,src)
        self.assertEqual(result['phase'],'SOURCE_READY')
        self.assertEqual(source_onboarding.inspect(self.session)['generatedHashes'],
                         result['generatedHashes'])

    def test_fallback_hard_crash_does_not_overwrite_active_stage(self):
        src=record_description();facts=evidence()
        initial=source_onboarding.begin(self.session,facts,src)
        old_stage=source_onboarding.stage_path(self.session)
        old_bytes=(old_stage/'definition.py').read_bytes()
        child='''import json,os,sys
from pathlib import Path
from fortis_approvals.extensions import source_onboarding as flow
real=flow.os.replace
def crash_during_new_draft(before,after):
    result=real(before,after)
    if Path(after).name=='definition.py' and '_onboarding_draft_' in str(after):
        os._exit(89)
    return result
flow.os.replace=crash_during_new_draft
flow.fallback(sys.argv[1],json.loads(sys.argv[2])['facts'],
              json.loads(sys.argv[2])['source'],'read_action','SOURCE_TEST_MISMATCH')
'''
        self._kill_source_process(child,{'facts':facts,'source':src},89)
        self.assertEqual(source_onboarding.inspect(self.session)['phase'],'SOURCE_READY')
        self.assertEqual((old_stage/'definition.py').read_bytes(),old_bytes)
        self.assertEqual(source_onboarding.stage_path(self.session),old_stage)
        result=source_onboarding.fallback(self.session,facts,src,'read_action',
                                          'SOURCE_TEST_MISMATCH')
        self.assertEqual(result['phase'],'MANUAL_REQUIRED')
        self.assertNotEqual(source_onboarding.stage_path(self.session),old_stage)
        self.assertEqual((old_stage/'definition.py').read_bytes(),old_bytes)
        self.assertEqual(len(result['history']),2)

    def test_fallback_after_checkpoint_crash_repeated_command_is_idempotent(self):
        src=record_description();facts=evidence()
        before=source_onboarding.begin(self.session,facts,src)
        child='''import json,os,sys
from fortis_approvals.extensions import source_onboarding as flow
real=flow._save

def save_then_crash(root,state):
    result=real(root,state)
    if state['activeStage'] != 'staged_provider':os._exit(90)
    return result
flow._save=save_then_crash
flow.fallback(sys.argv[1],json.loads(sys.argv[2])['facts'],
              json.loads(sys.argv[2])['source'],'read_action','SOURCE_TEST_MISMATCH')
'''
        self._kill_source_process(child,{'facts':facts,'source':src},90)
        checkpoint=source_onboarding.inspect(self.session)
        self.assertEqual(checkpoint['phase'],'MANUAL_REQUIRED')
        self.assertEqual(checkpoint['plan']['operations'][0]['selected'],
                         'handwrittenOperation')
        self.assertEqual(len(checkpoint['history']),2)
        # Recover a lost CLI reply: same input must NOT take another fallback.
        same=source_onboarding.fallback(self.session,facts,src,'read_action',
                                        'SOURCE_TEST_MISMATCH')
        self.assertEqual(same,checkpoint)
        self.assertEqual(len(same['history']),2)
        self.assertEqual(before['assessmentDigest'],same['assessmentDigest'])

    def test_review_receipt_records_source_snapshot_and_reviewer_source(self):
        src=record_description()
        source_onboarding.begin(self.session,evidence(),src)
        reviewed=source_onboarding.resume(self.session,reviewer=reviewer_for(src))
        record=reviewed['reviewEvidence']
        self.assertEqual(record['reviewer']['kind'],'source-test-only')
        self.assertEqual(record['reviewer']['file'],
                         'fortis_approvals/tests/test_source_onboarding.py')
        self.assertEqual(len(record['stageSha256']),64)
        self.assertEqual(len(record['reviewer']['fileSha256']),64)
        self.assertEqual(record['assessmentDigest'],reviewed['assessmentDigest'])
        self.promote(src)

    def test_review_record_rejects_wrong_source_digest(self):
        from fortis_approvals.core import loads_strict,canonical
        src=record_description()
        source_onboarding.begin(self.session,evidence(),src)
        source_onboarding.resume(self.session,reviewer=reviewer_for(src))
        file=self.session/'checkpoint.json'
        state=loads_strict(file.read_text())
        state['reviewEvidence']['sourceDigest']='0'*64
        file.write_text(canonical(state))
        with self.assertRaisesRegex(Denied,'ONBOARDING_REVIEW_SOURCE_MISMATCH'):
            self.promote(src)

    def test_review_record_rejects_unrecognized_reviewer_source_hash(self):
        from fortis_approvals.core import loads_strict,canonical
        src=record_description()
        source_onboarding.begin(self.session,evidence(),src)
        source_onboarding.resume(self.session,reviewer=reviewer_for(src))
        file=self.session/'checkpoint.json'
        state=loads_strict(file.read_text())
        state['reviewEvidence']['reviewer']['fileSha256']='0'*64
        file.write_text(canonical(state))
        with self.assertRaisesRegex(Denied,'ONBOARDING_REVIEWER_SOURCE_CHANGED'):
            self.promote(src)

    def test_outside_source_verifier_is_rejected_even_if_it_claims_pass(self):
        src=record_description()
        source_onboarding.begin(self.session,evidence(),src)
        other=self.root/'untrusted_verifier.py'
        other.write_text('def verify(*args):\n    return {\"passed\":True,\"verified\":[],\"operations\":[\"read_action\"]}\n')
        spec=importlib.util.spec_from_file_location('untrusted_verifier',other)
        module=importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with self.assertRaisesRegex(Denied,'ONBOARDING_REVIEWER_OUTSIDE_SOURCE'):
            source_onboarding.resume(self.session,reviewer=module.verify)
        self.assertEqual(source_onboarding.inspect(self.session)['phase'],'SOURCE_READY')

    def test_auto_flow_source_only_without_manual_edits(self):
        src=record_description();facts=evidence()
        created=source_onboarding.begin(self.session,facts,src)
        self.assertEqual(created['phase'],'SOURCE_READY')
        self.assertEqual(created['manualRequirements'],[])
        self.assertFalse((self.source/'fortis_approvals'/'integrations'/'study_records').exists())
        inspected=source_onboarding.inspect(self.session)
        self.assertEqual(inspected['assessmentDigest'],created['assessmentDigest'])
        verified=source_onboarding.resume(self.session,reviewer=reviewer_for(src))
        self.assertEqual(verified['phase'],'SOURCE_VERIFIED')
        created_files=self.promote(src)
        self.assertEqual(len(created_files['appliedFiles']),5)
        self.assertEqual(source_onboarding.inspect(self.session)['phase'],'SOURCE_PREPARED')
        self.assertEqual(self.promote(src)['appliedFiles'],[])

    def test_hybrid_pause_manual_check_resume_without_restarting(self):
        src=record_description();facts=evidence(custom='resultPostcheck')
        created=source_onboarding.begin(self.session,facts,src)
        self.assertEqual(created['phase'],'MANUAL_REQUIRED')
        self.assertEqual(created['manualRequirements'],[{
            'kind':'resultPostcheck','method':'read_action'}])
        self.assertEqual(len(created['history']),1)
        with self.assertRaisesRegex(Denied,'ONBOARDING_MANUAL_REVIEW_REQUIRED'):
            source_onboarding.resume(self.session)
        (self.stage()/'manual.py').write_text(POSTCHECK_SOURCE)
        done=source_onboarding.resume(self.session,reviewer=reviewer_for(src))
        self.assertEqual(done['phase'],'SOURCE_VERIFIED')
        self.assertEqual([x['event'] for x in done['history']],
                         ['ASSESS_AND_STAGE','SOURCE_TESTS_ACCEPTED'])
        created_files=self.promote(src)
        package=self.source/'fortis_approvals'/'integrations'/'study_records'
        self.assertEqual(created_files['action'],'create')
        self.assertEqual((package/'manual.py').read_text(),POSTCHECK_SOURCE)
        self.assertEqual(len(source_onboarding.inspect(self.session)['history']),3)

    def test_fully_manual_method_pause_finish_in_same_task(self):
        src=service_description();src['provider']='study_custom';src['methods']=[]
        facts=evidence(method='manual_health',custom='manualOperation',descriptor=False)
        facts['provider']='study_custom'
        data=source_onboarding.begin(self.session,facts,src)
        self.assertEqual(data['phase'],'MANUAL_REQUIRED')
        self.assertEqual(data['manualRequirements'],[{
            'kind':'manualOperation','method':'manual_health'}])
        (self.stage()/'manual.py').write_text(MANUAL_OP_SOURCE)
        state=source_onboarding.resume(self.session,reviewer=reviewer_for(src))
        self.assertEqual(state['phase'],'SOURCE_VERIFIED')
        applied=self.promote(src)
        self.assertEqual(applied['action'],'create')
        self.assertEqual((self.source/'fortis_approvals'/'integrations'/'study_custom'/
                          'manual.py').read_text(),MANUAL_OP_SOURCE)

    def test_review_stop_never_creates_discoverable_provider(self):
        src=record_description();facts=evidence(effect='UNKNOWN',verb='UNKNOWN')
        state=source_onboarding.begin(self.session,facts,src)
        self.assertEqual(state['phase'],'REVIEW_REQUIRED')
        with self.assertRaisesRegex(Denied,'ONBOARDING_REVIEW_STOP'):
            source_onboarding.resume(self.session,reviewer=reviewer_for(src))
        with self.assertRaisesRegex(Denied,'ONBOARDING_NOT_VERIFIED'):
            self.promote(src)
        self.assertFalse((self.source/'fortis_approvals'/'integrations'/'study_records').exists())

    def test_generated_file_change_before_review_fails_closed(self):
        src=record_description();source_onboarding.begin(self.session,evidence(),src)
        (self.stage()/'definition.py').write_text('TAMPERED')
        with self.assertRaisesRegex(Denied,'ONBOARDING_GENERATED_SOURCE_CHANGED'):
            source_onboarding.resume(self.session,reviewer=reviewer_for(src))

    def test_manual_change_after_review_revokes_source_preparation(self):
        src=record_description();source_onboarding.begin(self.session,evidence(),src)
        source_onboarding.resume(self.session,reviewer=reviewer_for(src))
        (self.stage()/'manual.py').write_text('changed after approval')
        with self.assertRaisesRegex(Denied,'ONBOARDING_REVIEWED_SOURCE_CHANGED'):
            self.promote(src)
        self.assertFalse((self.source/'fortis_approvals'/'integrations'/'study_records').exists())

    def test_descriptor_change_after_checkpoint_never_applies(self):
        src=record_description();source_onboarding.begin(self.session,evidence(),src)
        source_onboarding.resume(self.session,reviewer=reviewer_for(src))
        modified=deepcopy(src)
        modified['methods'][0]['description']='Different source description'
        with self.assertRaisesRegex(Denied,'ONBOARDING_SOURCE_BINDING_MISMATCH'):
            self.promote(modified)

    def test_manual_unreviewed_missing_or_unassessed_operation_refused(self):
        src=record_description();source_onboarding.begin(
             self.session,evidence(custom='resultPostcheck'),src)
        with self.assertRaisesRegex(Denied,'ONBOARDING_MANUAL_UNVERIFIED'):
            source_onboarding.resume(self.session,reviewer=lambda *_:{
                'passed':False,'verified':[],'operations':['read_action']})
        with self.assertRaisesRegex(Denied,'ONBOARDING_UNASSESSED_MANUAL_OPERATION'):
            source_onboarding.resume(self.session,reviewer=lambda folder,req:{
                'passed':True,'verified':req,'operations':['read_action','hidden_write']})
        self.assertEqual(source_onboarding.inspect(self.session)['phase'],'MANUAL_REQUIRED')

    def test_fallback_in_same_task_compiled_to_hook_to_handwritten(self):
        src=record_description();facts=evidence()
        initial=source_onboarding.begin(self.session,facts,src)
        self.assertEqual(initial['phase'],'SOURCE_READY')
        changed=source_onboarding.fallback(self.session,facts,src,'read_action',
                                           'ADDITIVE_VALIDATION_GAP')
        self.assertEqual(changed['phase'],'MANUAL_REQUIRED')
        self.assertEqual(changed['manualRequirements'],[{
            'kind':'resultPostcheck','method':'read_action'}])
        self.assertEqual(changed['assessmentDigest'],initial['assessmentDigest'])
        # The reviewed description remains available; human source is preserved
        # across another source-only fallback into a complete manual Operation.
        (self.stage()/'manual.py').write_text(POSTCHECK_SOURCE)
        complete=source_onboarding.fallback(self.session,facts,src,'read_action',
                                            'SOURCE_TEST_MISMATCH')
        self.assertEqual(complete['phase'],'MANUAL_REQUIRED')
        self.assertEqual(complete['manualRequirements'],[{
            'kind':'manualOperation','method':'read_action'}])
        self.assertEqual((self.stage()/'manual.py').read_text(),POSTCHECK_SOURCE)
        self.assertEqual(complete['plan']['operations'][0]['selected'],'handwrittenOperation')
        self.assertNotIn('read_action',
                         {x['name'] for x in self._staged_description()['methods']})
        self.assertEqual(len(complete['plan']['operations'][0]['attemptHistory']),2)
        with self.assertRaisesRegex(Denied,'ONBOARDING_NOT_VERIFIED'):
            self.promote(src)

    def _staged_description(self):
        # The session's reviewed package source lives only in the stage.
        from ast import literal_eval
        import ast
        value=ast.parse((self.stage()/'definition.py').read_text())
        assignment=next(n for n in value.body if isinstance(n,ast.Assign))
        return literal_eval(assignment.value)

    def test_additive_fallback_can_finish_as_reviewed_postcheck(self):
        src=record_description();facts=evidence()
        source_onboarding.begin(self.session,facts,src)
        source_onboarding.fallback(self.session,facts,src,'read_action',
                                   'ADDITIVE_VALIDATION_GAP')
        (self.stage()/'manual.py').write_text(POSTCHECK_SOURCE)
        finished=source_onboarding.resume(self.session,reviewer=reviewer_for(src))
        self.assertEqual(finished['phase'],'SOURCE_VERIFIED')
        receipt=self.promote(src)
        self.assertEqual(receipt['action'],'create')
        self.assertEqual((self.source/'fortis_approvals'/'integrations'/'study_records'/
                          'manual.py').read_text(),POSTCHECK_SOURCE)

    def test_source_test_mismatch_can_finish_as_handwritten_in_same_session(self):
        src=record_description();facts=evidence()
        source_onboarding.begin(self.session,facts,src)
        state=source_onboarding.fallback(self.session,facts,src,'read_action',
                                         'SOURCE_TEST_MISMATCH')
        self.assertEqual(state['phase'],'MANUAL_REQUIRED')
        self.assertEqual(state['expectedOperations'],['read_action'])
        # This is a source-reviewed full replacement of the original compiled
        # method, not an extra method with the same name.
        code=MANUAL_OP_SOURCE.replace("'manual_health'", "'read_action'").replace(
            "routes=('health',)", "routes=('get_record',)")
        (self.stage()/'manual.py').write_text(code)
        effective=source_onboarding._effective_description(src,state['plan'])
        done=source_onboarding.resume(self.session,reviewer=reviewer_for(effective))
        self.assertEqual(done['phase'],'SOURCE_VERIFIED')
        self.promote(src)
        self.assertEqual((self.source/'fortis_approvals'/'integrations'/'study_records'/
                          'manual.py').read_text(),code)
        self.assertEqual(source_onboarding.inspect(self.session)['phase'],'SOURCE_PREPARED')

    def test_pinned_plan_uses_chronological_fallback_across_methods(self):
        src=record_description()
        second=deepcopy(src['methods'][0]);second['name']='read_summary'
        second['route']='get_summary'
        src['methods'].append(second)
        src['routes'].append({'name':'get_summary',
             'path':'/v1/records/{action_id}/summary','queryKeys':[]})
        facts=evidence()
        second_fact=deepcopy(facts['operations'][0]);second_fact['name']='read_summary'
        facts['operations'].append(second_fact)
        source_onboarding.begin(self.session,facts,src)
        source_onboarding.fallback(self.session,facts,src,'read_summary',
                                   'SOURCE_TEST_MISMATCH')
        source_onboarding.fallback(self.session,facts,src,'read_action',
                                   'ADDITIVE_VALIDATION_GAP')
        # No state reinitialization and no failed plan fingerprint check.
        plan=source_onboarding.inspect(self.session)['plan']
        self.assertEqual({p['operation']:p['selected'] for p in plan['operations']},
                         {'read_action':'compiledWithTrustedCheck',
                          'read_summary':'handwrittenOperation'})

    def test_broad_source_mismatch_goes_directly_to_manual(self):
        src=record_description();facts=evidence()
        source_onboarding.begin(self.session,facts,src)
        row=source_onboarding.fallback(self.session,facts,src,'read_action',
                                      'SOURCE_TEST_MISMATCH')
        self.assertEqual(row['phase'],'MANUAL_REQUIRED')
        self.assertEqual(row['manualRequirements'],[{
            'kind':'manualOperation','method':'read_action'}])
        self.assertFalse(self._staged_description()['methods'])

    def test_unknown_effect_fallback_stops_without_any_source_promotion(self):
        src=record_description();facts=evidence()
        source_onboarding.begin(self.session,facts,src)
        stopped=source_onboarding.fallback(self.session,facts,src,'read_action',
                                          'SECURITY_OR_UNKNOWN_EFFECT')
        self.assertEqual(stopped['phase'],'REVIEW_REQUIRED')
        with self.assertRaisesRegex(Denied,'ONBOARDING_REVIEW_STOP'):
            source_onboarding.resume(self.session,reviewer=reviewer_for(src))
        self.assertFalse((self.source/'fortis_approvals'/'integrations'/'study_records').exists())

    def test_changed_evidence_for_fallback_cannot_rewrite_original_plan(self):
        src=record_description();facts=evidence()
        source_onboarding.begin(self.session,facts,src)
        tampered=deepcopy(facts);tampered['transport']='trustedManual'
        with self.assertRaises(Denied):
            source_onboarding.fallback(self.session,tampered,src,'read_action',
                                       'CAPABILITY_UNSUPPORTED')
        self.assertEqual(source_onboarding.inspect(self.session)['phase'],'SOURCE_READY')

    def test_rejected_manual_operations_cannot_sneak_through_same_task(self):
        src=record_description();facts=evidence()
        source_onboarding.begin(self.session,facts,src)
        source_onboarding.fallback(self.session,facts,src,'read_action',
                                   'SOURCE_TEST_MISMATCH')
        # This implementation contains an unrelated manual method and a
        # result hook for the removed compiled method, not a replacement.
        from fortis_approvals.tests.test_source_generator import MANUAL_CODE
        (self.stage()/'manual.py').write_text(MANUAL_CODE)
        with self.assertRaisesRegex(Denied,'SOURCE_MANUAL_HOOK_WITHOUT_METHOD'):
            source_onboarding.resume(self.session,reviewer=reviewer_for(
                source_onboarding._effective_description(src,
                    source_onboarding.inspect(self.session)['plan'])))

    def test_source_methods_cannot_be_silently_changed_by_verifier(self):
        src=record_description();source_onboarding.begin(self.session,evidence(),src)
        with self.assertRaisesRegex(Denied,'ONBOARDING_SOURCE_TEST_FAILED'):
            source_onboarding.resume(self.session,reviewer=lambda *_:{
                'passed':True,'verified':[],'operations':['hidden']})

    def test_promotion_cannot_drop_newly_reviewed_manual_file_on_update(self):
        src=record_description();source_onboarding.begin(self.session,evidence(),src)
        source_onboarding.resume(self.session,reviewer=reviewer_for(src))
        self.promote(src)
        # A later human edit in source is not overwritten by the generator;
        # instead, the workflow requires review of the divergence.
        target=self.source/'fortis_approvals'/'integrations'/'study_records'/'manual.py'
        target.write_text(target.read_text()+'\n# new author edit')
        with self.assertRaisesRegex(Denied,'ONBOARDING_EXISTING_MANUAL_DIFF_REVIEW_REQUIRED'):
            self.promote(src)

if __name__=='__main__':unittest.main(verbosity=2)

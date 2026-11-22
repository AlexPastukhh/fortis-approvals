"""Reasonable source-onboarding selection and fail-closed fallback; offline."""
from copy import deepcopy
import unittest

from fortis_approvals.core import Denied
from fortis_approvals.extensions.source_strategy import (
    advise_onboarding, next_source_attempt)
from fortis_approvals.tests.test_source_generator import (
    record_description, service_description)


def evidence(*,custom='none',descriptor=True,reviewed=True,
             transport='standardJsonapi', effect='READ',verb='GET',
             response='json',method='read_action'):
    return {'schemaVersion':1,'provider':'study_records','reviewed':reviewed,
            'transport':transport,'operations':[
      {'name':method,'reviewed':True,'effect':effect,'verb':verb,
       'response':response,'customization':custom,
       'descriptionReady':descriptor}]}


class SourceStrategyTests(unittest.TestCase):
    def test_standard_reviewed_json_get_prefers_compiled(self):
        case=record_description()
        assessment=advise_onboarding(evidence(),case)
        self.assertEqual(assessment['status'],'SOURCE_PREFLIGHT_READY')
        self.assertEqual(assessment['operations'][0]['selected'],'compiledRead')
        self.assertEqual(assessment['operations'][0]['estimatedEffort'],1)
        self.assertEqual(assessment['operations'][0]['manualTasks'],[])
        self.assertEqual(assessment['workflow'],[
            'DISCOVER','ASSESS','REVIEW','SOURCE_PREPARE','TEST',
            'OWNER_RELEASE','LIVE_VERIFY'])

    def test_custom_business_check_prefers_hybrid_when_cheaper(self):
        row=advise_onboarding(evidence(custom='resultPostcheck'),record_description())
        op=row['operations'][0]
        self.assertEqual(op['selected'],'compiledWithTrustedCheck')
        self.assertEqual(row['status'],'MANUAL_REQUIRED')
        self.assertIn('resultPostcheck',op['manualTasks'][0])
        self.assertEqual([a['technique'] for a in op['attempts']],
                         ['compiledWithTrustedCheck','handwrittenOperation'])

    def test_ranking_can_choose_manual_when_combination_more_expensive(self):
        cost={'compiled':2,'draftDescriptor':2,'resultPostcheck':10,
              'contextCheck':9,'manualOperation':5,'trustedTransport':7}
        row=advise_onboarding(evidence(custom='resultPostcheck'),
                              record_description(),effort=cost)['operations'][0]
        self.assertEqual(row['selected'],'handwrittenOperation')
        self.assertEqual(row['estimatedEffort'],5)
        self.assertFalse(any('resultPostcheck' in x for x in row['manualTasks']))

    def test_no_descriptor_try_reviewed_description_before_manual_code(self):
        row=advise_onboarding(evidence(descriptor=False))['operations'][0]
        self.assertEqual(row['selected'],'prepareDescriptorThenCompile')
        self.assertEqual(row['status'],'MANUAL_REQUIRED')
        self.assertTrue(any('Draft and review' in t for t in row['manualTasks']))
        self.assertEqual(row['estimatedEffort'],3)

    def test_bad_route_requires_source_fix_not_expensive_manual_fallback(self):
        bad=record_description()
        bad['methods'][0]['route']='unregistered_route'
        row=advise_onboarding(evidence(),bad)['operations'][0]
        self.assertIsNone(row['selected'])
        self.assertEqual(row['status'],'REVIEW_REQUIRED')
        self.assertIn('DECLARATIVE_ROUTE_NOT_REGISTERED',row['stopReasons'])

    def test_actual_unsupported_schema_type_can_choose_custom_implementation(self):
        bad=record_description()
        bad['methods'][0]['resultSchema']['fields']['name']={'type':'decimal'}
        row=advise_onboarding(evidence(),bad)['operations'][0]
        self.assertEqual(row['selected'],'handwrittenOperation')
        self.assertEqual(row['status'],'MANUAL_REQUIRED')
        self.assertEqual(next(a['reason'] for a in row['attempts'] if
                              a['preflight']=='UNSUPPORTED'),
                         'DECLARATIVE_SCHEMA_TYPE_UNSUPPORTED')

    def test_security_denial_never_becomes_handwritten_fallback(self):
        bad=record_description();bad['origin']='http://unsafe.example.invalid'
        plan=advise_onboarding(evidence(),bad)
        self.assertEqual(plan['status'],'REVIEW_REQUIRED')
        self.assertIsNone(plan['operations'][0]['selected'])
        self.assertIn('SOURCE_PREFLIGHT_SECURITY_OR_CONTRACT_DENIED',
                      plan['operations'][0]['stopReasons'])

    def test_mismatched_transport_fails_preflight_before_selection(self):
        bad=record_description()
        with self.assertRaisesRegex(Denied,'ASSESSMENT_SOURCE_TRANSPORT_MISMATCH'):
            advise_onboarding(evidence(transport='trustedManual'),bad)

    def test_evidence_provider_mismatch_fails_closed(self):
        bad=service_description()
        with self.assertRaisesRegex(Denied,'ASSESSMENT_SOURCE_PROVIDER_MISMATCH'):
            advise_onboarding(evidence(),bad)

    def test_unknown_effect_requires_discovery_not_generated_methods(self):
        plan=advise_onboarding(evidence(effect='UNKNOWN'),record_description())
        self.assertEqual(plan['status'],'REVIEW_REQUIRED')
        self.assertIsNone(plan['operations'][0]['selected'])

    def test_unreviewed_method_or_provider_requires_review(self):
        provider=advise_onboarding(evidence(reviewed=False),record_description())
        self.assertEqual(provider['status'],'REVIEW_REQUIRED')
        fact=evidence();fact['operations'][0]['reviewed']=False
        self.assertEqual(advise_onboarding(fact,record_description())['status'],
                         'REVIEW_REQUIRED')

    def test_write_post_and_unknown_response_are_not_automatically_fallbacked(self):
        for changed in ({'effect':'WRITE','verb':'POST'},
                        {'effect':'READ','verb':'POST'},
                        {'response':'unknown'}):
            facts=evidence()
            facts['operations'][0].update(changed)
            with self.subTest(facts=changed):
                item=advise_onboarding(facts,record_description())['operations'][0]
                self.assertEqual(item['status'],'REVIEW_REQUIRED')
                self.assertIsNone(item['selected'])

    def test_manual_transport_is_a_reviewed_source_task_not_permission_mode(self):
        src=record_description();src['transport']='manual';src['origin']=None
        item=advise_onboarding(evidence(transport='trustedManual'),src)['operations'][0]
        self.assertEqual(item['selected'],'compiledRead')
        self.assertEqual(item['status'],'MANUAL_REQUIRED')
        self.assertTrue(any('trusted transport' in task for task in item['manualTasks']))

    def test_manually_written_operation_coexists_with_compiled_in_one_plan(self):
        facts=evidence()
        facts['operations'].append({'name':'manual_read','reviewed':True,
            'effect':'READ','verb':'GET','response':'json',
            'customization':'manualOperation','descriptionReady':False})
        plan=advise_onboarding(facts,record_description())
        self.assertEqual(plan['status'],'MANUAL_REQUIRED')
        self.assertEqual([x['selected'] for x in plan['operations']],
                         ['compiledRead','handwrittenOperation'])
        self.assertEqual(len(plan['workflow']),7)

    def test_failed_source_test_falls_back_once_without_replaying_effects(self):
        original=advise_onboarding(evidence(),record_description())
        fallback=next_source_attempt(original,'read_action','SOURCE_TEST_MISMATCH')
        self.assertEqual(fallback['operations'][0]['selected'],'handwrittenOperation')
        self.assertEqual(fallback['operations'][0]['status'],'MANUAL_REQUIRED')
        self.assertEqual(len(fallback['operations'][0]['attemptHistory']),1)
        self.assertEqual(original['operations'][0]['selected'],'compiledRead')
        final=next_source_attempt(fallback,'read_action','CAPABILITY_UNSUPPORTED')
        self.assertEqual(final['status'],'REVIEW_REQUIRED')
        self.assertIn('NO_SAFE_SOURCE_FALLBACK',final['operations'][0]['stopReasons'])

    def test_verified_additive_gap_try_hook_then_manual_in_same_workflow(self):
        original=advise_onboarding(evidence(),record_description())
        self.assertEqual(original['operations'][0]['selected'],'compiledRead')
        narrow=next_source_attempt(original,'read_action','ADDITIVE_VALIDATION_GAP')
        self.assertEqual(narrow['operations'][0]['selected'],'compiledWithTrustedCheck')
        self.assertEqual(narrow['operations'][0]['status'],'MANUAL_REQUIRED')
        manual=next_source_attempt(narrow,'read_action','SOURCE_TEST_MISMATCH')
        self.assertEqual(manual['operations'][0]['selected'],'handwrittenOperation')
        self.assertEqual(len(manual['operations'][0]['attemptHistory']),2)
        self.assertEqual(manual['assessmentDigest'],original['assessmentDigest'])
        self.assertEqual(manual['workflow'],original['workflow'])

    def test_security_error_does_not_retry_less_economical_technique(self):
        plan=advise_onboarding(evidence(),record_description())
        stop=next_source_attempt(plan,'read_action','SECURITY_OR_UNKNOWN_EFFECT')
        self.assertEqual(stop['status'],'REVIEW_REQUIRED')
        self.assertIsNone(stop['operations'][0]['selected'])

    def test_untrusted_unknown_effect_cannot_be_advanced(self):
        plan=advise_onboarding(evidence(effect='WRITE',verb='POST'))
        with self.assertRaisesRegex(Denied,'ASSESSMENT_NOT_ATTEMPTABLE'):
            next_source_attempt(plan,'read_action','SOURCE_TEST_MISMATCH')

    def test_deterministic_and_does_not_mutate_research_inputs(self):
        facts=evidence();spec=record_description()
        facts_before=deepcopy(facts);spec_before=deepcopy(spec)
        one=advise_onboarding(facts,spec)
        two=advise_onboarding(deepcopy(facts),deepcopy(spec))
        self.assertEqual(one,two)
        self.assertEqual(facts,facts_before)
        self.assertEqual(spec,spec_before)
        self.assertEqual(len(one['assessmentDigest']),64)

    def test_cli_on_local_reviewed_evidence_is_read_only(self):
        from pathlib import Path
        from tempfile import TemporaryDirectory
        from subprocess import run
        import json
        import sys
        with TemporaryDirectory(prefix='fortis-assessment-cli-') as root:
            facts=Path(root)/'facts.json';definition=Path(root)/'source.json'
            facts.write_text(json.dumps(evidence()),encoding='utf-8')
            definition.write_text(json.dumps(record_description()),encoding='utf-8')
            result=run([sys.executable,'-B','-m',
                 'fortis_approvals.extensions.source_strategy',
                 '--evidence',str(facts),'--source-description',str(definition)],
                 capture_output=True,text=True,check=False,timeout=15)
            self.assertEqual(result.returncode,0,result.stderr)
            report=json.loads(result.stdout)
            self.assertEqual(report['status'],'SOURCE_PREFLIGHT_READY')
            self.assertEqual(set(Path(root).iterdir()),{facts,definition})

    def test_source_cli_apply_requires_preflight_assessment(self):
        from pathlib import Path
        from tempfile import TemporaryDirectory
        from subprocess import run
        import json
        import sys
        with TemporaryDirectory(prefix='fortis-advisory-apply-') as root:
            folder=Path(root)
            (folder/'fortis_approvals'/'extensions').mkdir(parents=True)
            (folder/'fortis_approvals'/'extensions'/'model.py').write_text('# fixture')
            providers=folder/'fortis_approvals'/'integrations'
            providers.mkdir()
            facts=folder/'facts.json';description=folder/'source.json'
            facts.write_text(json.dumps(evidence()),encoding='utf-8')
            description.write_text(json.dumps(record_description()),encoding='utf-8')
            command=[sys.executable,'-B','-m',
               'fortis_approvals.extensions.source_generator',
               '--source-root',str(folder),'--descriptor',str(description),'--apply']
            denied=run(command,capture_output=True,text=True,timeout=15)
            self.assertNotEqual(denied.returncode,0)
            self.assertIn('SOURCE_ASSESSMENT_REQUIRED',denied.stderr)
            self.assertEqual(list(providers.iterdir()),[])
            approved=run(command+['--evidence',str(facts)],
                         capture_output=True,text=True,timeout=15)
            # A fake source tree must never be modified by the CLI, even
            # when its evidence JSON is marked "reviewed" by the caller.
            self.assertNotEqual(approved.returncode,0)
            self.assertIn('SOURCE_TASK_WORKTREE_REQUIRED',approved.stderr)
            self.assertEqual(list(providers.iterdir()),[])

    def test_source_cli_refuses_incomplete_manual_postcheck_before_writes(self):
        from pathlib import Path
        from tempfile import TemporaryDirectory
        from subprocess import run
        import json
        import sys
        with TemporaryDirectory(prefix='fortis-manual-source-stop-') as root:
            folder=Path(root)
            (folder/'fortis_approvals'/'extensions').mkdir(parents=True)
            (folder/'fortis_approvals'/'extensions'/'model.py').write_text('# fixture')
            providers=folder/'fortis_approvals'/'integrations'
            providers.mkdir()
            facts=folder/'facts.json';description=folder/'source.json'
            facts.write_text(json.dumps(evidence(custom='resultPostcheck')),encoding='utf-8')
            description.write_text(json.dumps(record_description()),encoding='utf-8')
            request=run([sys.executable,'-B','-m',
                    'fortis_approvals.extensions.source_generator',
                    '--source-root',str(folder),
                    '--descriptor',str(description),
                    '--evidence',str(facts),'--apply'],
                    capture_output=True,text=True,timeout=15)
            self.assertNotEqual(request.returncode,0)
            self.assertIn('SOURCE_ASSESSMENT_MANUAL_REQUIRED',request.stderr)
            self.assertEqual(list(providers.iterdir()),[])

    def test_malformed_customization_cannot_raise_raw_type_error(self):
        bad=evidence();bad['operations'][0]['customization']=[]
        with self.assertRaises(Denied):advise_onboarding(bad,record_description())

    def test_invalid_effort_and_unsupported_evidence_fields_rejected(self):
        with self.assertRaises(Denied):
            advise_onboarding(evidence(),record_description(),effort={'compiled':1})
        bad=evidence();bad['operations'][0]['grant']='ALLOW'
        with self.assertRaises(Denied):advise_onboarding(bad,record_description())


if __name__=='__main__':unittest.main(verbosity=2)

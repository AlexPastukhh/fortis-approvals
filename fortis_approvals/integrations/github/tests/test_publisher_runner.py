"""P3.3 offline authority, real Git data acquisition and one-shot scheduling."""
from dataclasses import asdict, replace
import copy
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from fortis_approvals.core import Denied
from fortis_approvals.integrations.github.publisher_profile import ACTOR, REPOSITORY
from fortis_approvals.integrations.github.publisher_source import source_view
from fortis_approvals.integrations.github.publisher_validator import PinnedValidator
from fortis_approvals.integrations.github.release_label_publisher import (
    PublisherRunner, RunnerConfig, TypedCIReader, _owner_client, main)
from fortis_approvals.integrations.github.release_label_ci import WORKFLOWS
from publisher_runner_fixture import RunnerFixture


class RunnerTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.f=RunnerFixture(self.root)

    def runner(self, config=None):
        return PublisherRunner(config or self.f.config,self.f.client,
                               validator_factory=self.f.plan.factory)

    def test_preview_is_read_only_with_exact_data_and_older_pr_base(self):
        plan=self.f.runner.preview(7)
        self.assertEqual(plan['status'],'PREPARED_OWNER_ASK')
        self.assertEqual(plan['sourceReadback']['baseSha'],self.f.graph.base)
        self.assertEqual(plan['sourceReadback']['mainSha'],self.f.graph.main)
        self.assertNotEqual(self.f.graph.base,self.f.graph.main)
        self.assertEqual(plan['sourceReadback']['mergeBaseSha'],self.f.graph.base)
        self.assertEqual(plan['operation'],'remove_pr_release_label')
        self.assertEqual(plan['params']['name'],'build:legacy')
        self.assertFalse(plan['writeEnabled']);self.assertEqual(self.f.api.writes,[])
        self.assertEqual(self.f.gateway.core.owner_list(),[])
        self.assertEqual(list(self.f.config.cache_root.iterdir()),[])

    def test_one_request_uses_existing_journal_and_original_ids(self):
        first=self.f.runner.request(7);self.f.next_invocation();second=self.f.runner.request(7)
        self.assertEqual(first['intent']['state'],'PENDING')
        self.assertEqual(second['intent']['intentId'],first['intent']['intentId'])
        self.assertEqual(second['intent']['attemptIds'],first['intent']['attemptIds'])
        self.assertEqual(len(self.f.gateway.core.owner_list()),1)
        record=self.f.client.intents.journal.load(first['intent']['intentId'])
        self.assertEqual(record['callerEvidence']['admissionSha256'],first['prepared']['admissionSha256'])
        self.assertEqual(record['attempts'][0]['requestId'],first['intent']['requestId'])
        self.assertEqual(self.f.api.writes,[])

    def test_lost_ask_ack_restart_reads_original_request_without_replacement(self):
        self.f.gateway.publisher.lose_ask_ack=True
        first=self.f.runner.request(7);self.f.next_invocation();again=self.runner().request(7)
        self.assertEqual(first['intent']['attemptIds'],again['intent']['attemptIds'])
        self.assertEqual(again['intent']['state'],'PENDING')
        self.assertEqual(len(self.f.gateway.core.owner_list()),1)

    def test_owner_decision_and_original_receipt_remain_distinct_from_current_admission(self):
        result=self.f.runner.request(7);ident=result['intent']['requestId']
        self.assertEqual(self.f.gateway.approve(ident)['state'],'EXECUTED')
        self.f.plan.value['remove']=[]
        self.f.next_invocation()
        report=self.f.runner.inspect(result['intent']['intentId'])
        self.assertEqual(report['effect']['state'],'EXECUTED',report)
        self.assertTrue(report['originalRequests'][0]['receiptVerified'],report)
        self.assertTrue(report['originalRequests'][0]['targetReadback']['desiredStateObserved'])
        self.assertTrue(report['originalRequests'][0]['targetReadback']['receiptLabelsMatch'])
        self.assertEqual(report['currentAdmission']['status'],'VERIFIED')
        self.assertIn('bug',self.f.api.labels);self.assertIn('release:review-required',self.f.api.labels)
        self.assertEqual(len(self.f.api.writes),1)

    def test_post_effect_read_failure_preserves_known_execution_without_write(self):
        result=self.f.runner.request(7);ident=result['intent']['requestId']
        self.assertEqual(self.f.gateway.approve(ident)['state'],'EXECUTED')
        self.f.api.fail_context=True
        report=self.f.runner.inspect(result['intent']['intentId'])
        self.assertEqual(report['effect']['state'],'EXECUTED',report)
        self.assertEqual(report['currentAdmission']['status'],'UNCONFIRMED')
        self.assertFalse(report['automaticRetryAllowed']);self.assertEqual(len(self.f.api.writes),1)

    def test_disabling_new_admission_keeps_own_receipt_inspection_available(self):
        result=self.f.runner.request(7)
        self.assertEqual(self.f.gateway.approve(result['intent']['requestId'])['state'],'EXECUTED')
        runner=self.runner(replace(self.f.config,enabled=False))
        report=runner.inspect(result['intent']['intentId'])
        self.assertEqual(report['effect']['state'],'EXECUTED')
        self.assertTrue(report['originalRequests'][0]['receiptVerified'])
        self.assertEqual(report['currentAdmission']['status'],'UNCONFIRMED')
        self.assertEqual(len(self.f.api.writes),1)

    def test_unknown_effect_inspection_never_reconciles_from_matching_labels(self):
        result=self.f.runner.request(7);self.f.api.lose_response=True
        ident=result['intent']['requestId']
        self.assertEqual(self.f.gateway.approve(ident)['state'],'UNCERTAIN')
        self.f.plan.value['remove']=[]
        self.f.next_invocation()
        report=self.f.runner.inspect(result['intent']['intentId'])
        self.assertEqual(report['effect']['state'],'UNCONFIRMED')
        self.assertFalse(report['originalRequests'][0]['receiptVerified'])
        self.assertEqual(self.f.gateway.core._read(ident)['state'],'UNCERTAIN')
        self.assertFalse(any(path.endswith('/reconcile') for path,_,_ in self.f.gateway.publisher.calls))

    def test_rejection_stops_same_admitted_intent(self):
        result=self.f.runner.request(7)
        self.f.gateway.approve(result['intent']['requestId'],decision='reject')
        self.f.next_invocation()
        again=self.f.runner.request(7)
        self.assertEqual(again['intent']['status'],'STOP')
        self.assertEqual(again['intent']['attemptIds'],result['intent']['attemptIds'])
        self.assertEqual(self.f.gateway.core._read(result['intent']['requestId'])['state'],'REJECTED')
        self.assertEqual(sum(path=='/v1/actions' for path,_,_ in self.f.gateway.publisher.calls),1)

    def test_no_delta_creates_no_ask(self):
        self.f.plan.value.update(add=[],remove=[])
        self.assertEqual(self.f.runner.request(7)['status'],'NO_CHANGES')
        self.assertEqual(self.f.gateway.core.owner_list(),[])

    def test_missing_definition_creates_no_ask(self):
        # Independent source graph/journal: a separate input must not depend
        # on a previous NO_CHANGES run or its cached Git bundle objects.
        self.f.plan.value.update(status='BLOCKED_MISSING_LABELS',add=['build:missing'],
                                 missingDefinitions=['build:missing'])
        self.assertEqual(self.f.runner.request(7)['status'],'BLOCKED_MISSING_LABELS')
        self.assertEqual(self.f.gateway.core.owner_list(),[])

    def test_remove_before_add_and_bounded_sorted_additions(self):
        self.f.plan.value.update(remove=['build:z','build:a'],add=['build:new'])
        self.assertEqual(self.f.runner.preview(7)['params']['name'],'build:a')
        self.f.next_invocation()
        self.f.plan.value.update(remove=[],add=['build:z','build:b','build:c','build:d','build:e','build:a'])
        prepared=self.f.runner.preview(7)
        self.assertEqual(prepared['params']['labels'],['build:a','build:b','build:c','build:d','build:e'])

    def test_sticky_review_is_addable_but_cannot_be_removed(self):
        self.f.plan.value.update(remove=[],add=['release:review-required'])
        self.assertEqual(self.f.runner.preview(7)['params']['labels'],['release:review-required'])
        self.f.next_invocation()
        self.f.plan.value.update(remove=['release:review-required'],add=[])
        with self.assertRaises(Denied):self.f.runner.request(7)
        self.assertEqual(self.f.gateway.core.owner_list(),[])

    def test_ci_changes_during_validation_stop_before_ask(self):
        self.f.plan.after_plan=lambda:self.f.api.attempts.__setitem__(WORKFLOWS[0].ident,2)
        with self.assertRaisesRegex(Denied,'PUBLISHER_CI_CHANGED_DURING_PLAN'):
            self.f.runner.request(7)
        self.assertEqual(self.f.gateway.core.owner_list(),[]);self.assertEqual(self.f.api.writes,[])

    def test_body_or_labels_race_during_validation_stop_before_ask(self):
        for field,value in [('body','Changed metadata'),('labels',['bug'])]:
            with self.subTest(field=field):
                old=copy.deepcopy(getattr(self.f.api,field))
                self.f.plan.after_plan=lambda:setattr(self.f.api,field,value)
                try:
                    with self.assertRaises(Denied):self.f.runner.request(7)
                finally:setattr(self.f.api,field,old)
                self.f.next_invocation()
        self.assertEqual(self.f.gateway.core.owner_list(),[])

    def test_wrong_profile_or_disabled_local_config_denies_before_provider(self):
        for config in (replace(self.f.config,enabled=False),
                       replace(self.f.config,profile_sha256='f'*64)):
            with self.assertRaises(Denied):self.runner(config).request(7)
        self.assertEqual(self.f.api.calls,[]);self.assertEqual(self.f.backend.fetches,[])

    def test_overlapping_paths_and_untrusted_endpoint_are_rejected(self):
        for values in [dict(intent_root=self.f.config.cache_root/'intents'),
                       dict(validator_root=self.f.config.cache_root),
                       dict(endpoint='http://untrusted.invalid'),
                       dict(endpoint='https://user:secret@untrusted.invalid')]:
            with self.subTest(values=values),self.assertRaises(Denied):
                replace(self.f.config,**values)

    def test_wrong_ready_pr_and_registration_are_rejected(self):
        for field,value in [('draft',True),('state','closed'),('head_repo','Other/fork')]:
            with self.subTest(field=field):
                old=getattr(self.f.api,field);setattr(self.f.api,field,value)
                try:
                    with self.assertRaises(Denied):self.f.runner.request(7)
                finally:setattr(self.f.api,field,old)
        self.f.gateway.store.close_task('repo-fixture-actor',REPOSITORY,'release-pilot')
        with self.assertRaises(Denied):self.f.runner.request(7)
        self.assertEqual(self.f.backend.fetches,[])

    def test_bundle_metadata_or_digest_poisoning_stops_before_validation(self):
        for change in [dict(sha='e'*40),dict(ref='task/other'),dict(repository='other-repo'),
                       dict(bundleSha256='f'*64),dict(bundle='bad!')]:
            with self.subTest(change=change):
                self.f.backend.transform=lambda reply:{**reply,**change}
                with self.assertRaises(Denied):self.f.runner.request(7)
        self.assertEqual(self.f.plan.calls,0);self.assertEqual(self.f.gateway.core.owner_list(),[])

    def test_pr_base_not_reachable_from_verified_main_is_denied(self):
        self.f.api.base=self.f.graph.head
        with self.assertRaisesRegex(Denied,'PUBLISHER_BASE_NOT_IN_MAIN'):self.f.runner.request(7)
        self.assertEqual(self.f.plan.calls,0);self.assertEqual(self.f.gateway.core.owner_list(),[])

    def test_symlink_pr_tree_is_rejected_before_any_code_or_ask(self):
        (self.f.graph.repository/'docs/escape').symlink_to('/etc/passwd')
        self.f.update_head('Unsafe PR symlink')
        with self.assertRaises(Denied):self.f.runner.request(7)
        self.assertEqual(self.f.plan.calls,0);self.assertEqual(self.f.gateway.core.owner_list(),[])

    def test_raw_blob_view_ignores_attributes_and_inherited_filters(self):
        marker=self.root/'EXECUTED'
        global_config=self.root/'poison.config'
        global_config.write_text('[filter "evil"]\n smudge = touch '+str(marker)+'\n required = true\n')
        with patch.dict(os.environ,{'GIT_CONFIG_GLOBAL':str(global_config),'GIT_CONFIG_COUNT':'1',
                'GIT_CONFIG_KEY_0':'core.hooksPath','GIT_CONFIG_VALUE_0':str(self.root)}):
            with source_view(self.f.client.gateway,self.f.config.cache_root,
                    main_sha=self.f.graph.main,head_sha=self.f.graph.head,base_sha=self.f.graph.base,
                    task_branch='task/release-pilot') as (view,evidence):
                self.assertEqual((view.data/'docs/pr.txt').read_bytes(),b'PR data\n')
                self.assertFalse(os.access(view.data/'tools/release/ci_entry.py',os.X_OK))
                self.assertEqual(view.git.text(['rev-parse','HEAD'],cwd=view.data),self.f.graph.head)
        self.assertFalse(marker.exists())

    def test_inspect_recovers_private_journal_ids_without_cli_reply(self):
        result=self.f.runner.request(7)
        self.f.next_invocation()
        reports=self.runner().inspect_pr(7)['intents']
        self.assertEqual(len(reports),1)
        self.assertEqual(reports[0]['intentId'],result['intent']['intentId'])
        self.assertEqual(reports[0]['attemptIds'],result['intent']['attemptIds'])
        self.assertEqual(len(self.f.gateway.core.owner_list()),1)

    def test_changed_private_evidence_is_not_adopted(self):
        result=self.f.runner.request(7);ident=result['intent']['intentId']
        record=self.f.client.intents.journal.load(ident)
        record['callerEvidence']['admission']['params']['name']='build:other'
        self.f.client.intents.journal.save(record)
        with self.assertRaises(Denied):self.f.runner.inspect(ident)
        self.assertEqual(self.f.api.writes,[])

    def test_disabled_cli_never_constructs_transport_or_reads_default_credentials(self):
        path=self.root/'config.json'
        values={k:str(v) if isinstance(v,Path) else v for k,v in asdict(self.f.config).items()}
        values['enabled']=False;path.write_text(json.dumps(values));path.chmod(0o600)
        with patch('fortis_approvals.integrations.github.release_label_publisher._owner_client',
                   side_effect=AssertionError('Credential constructor must not run')):
            self.assertEqual(main(['--config',str(path),'request','--pr','7']),2)

    def test_real_rate_limit_does_not_create_a_replacement_ask(self):
        first=self.f.runner.request(7)
        with self.assertRaisesRegex(Denied,'FORTIS_HTTP_429'):self.f.runner.request(7)
        self.assertEqual(len(self.f.gateway.core.owner_list()),1)
        self.f.next_invocation()
        again=self.f.runner.request(7)
        self.assertEqual(again['intent']['attemptIds'],first['intent']['attemptIds'])

    def test_poll_timestamps_do_not_change_admission_or_intent(self):
        first=self.f.runner.request(7)
        original=self.f.api.runs
        def timestamps():
            rows=original()
            for row in rows:row['updated_at']='2026-11-17T01:02:03Z'
            return rows
        self.f.api.runs=timestamps
        self.f.next_invocation()
        second=self.f.runner.request(7)
        self.assertEqual(first['prepared']['admissionSha256'],second['prepared']['admissionSha256'])
        self.assertEqual(first['intent']['intentId'],second['intent']['intentId'])

    def test_different_valid_bundle_encoding_does_not_create_a_new_intent(self):
        first=self.f.runner.request(7)
        original=first['prepared']['sourceReadback']['headBundleSha256']
        for revision in (self.f.graph.main,self.f.graph.head):
            path=self.f.graph.root/(revision+'.bundle');path.unlink()
            self.f.graph.git.run(['update-ref','refs/heads/transfer',revision],cwd=self.f.graph.repository)
            self.f.graph.git.run(['-c','pack.compression=0','bundle','create',path,'refs/heads/transfer'],
                                 cwd=self.f.graph.repository)
        self.f.next_invocation()
        second=self.f.runner.request(7)
        self.assertNotEqual(original,second['prepared']['sourceReadback']['headBundleSha256'])
        self.assertEqual(first['prepared']['admissionSha256'],second['prepared']['admissionSha256'])
        self.assertEqual(first['intent']['attemptIds'],second['intent']['attemptIds'])

    def test_foreign_receipt_cannot_verify_original_effect(self):
        result=self.f.runner.request(7)
        self.f.gateway.approve(result['intent']['requestId'])
        receipt=self.f.gateway.adapter.receipt
        self.f.gateway.adapter.receipt=lambda ident:{**receipt(ident),'requestId':'11111111-1111-4111-8111-111111111111'}
        self.f.next_invocation()
        report=self.f.runner.inspect(result['intent']['intentId'])
        self.assertFalse(report['originalRequests'][0]['receiptVerified'])
        self.assertFalse(report['automaticRetryAllowed'])
        self.assertEqual(len(self.f.api.writes),1)

    def test_missing_job_or_workflow_blob_change_is_not_admitted(self):
        self.f.api.job_changes['offline-tests']={'name':'unrelated'}
        with self.assertRaises(Denied):self.f.runner.request(7)
        self.assertEqual(self.f.gateway.core.owner_list(),[])
        self.f.api.job_changes.clear()
        self.f.graph.write(WORKFLOWS[0].path,self.f.api.sources[WORKFLOWS[0].path]+b'\n# Changed PR workflow\n')
        self.f.update_head('Changed workflow data')
        self.f.next_invocation()
        with self.assertRaises(Denied):self.f.runner.request(7)
        self.assertEqual(self.f.gateway.core.owner_list(),[])

    def test_unexpected_current_read_timeout_keeps_original_execution(self):
        result=self.f.runner.request(7)
        self.f.gateway.approve(result['intent']['requestId'])
        with patch.object(self.f.runner,'preview',side_effect=RuntimeError('unit read timeout')):
            report=self.f.runner.inspect(result['intent']['intentId'])
        self.assertEqual(report['effect']['state'],'EXECUTED')
        self.assertEqual(report['currentAdmission']['status'],'UNCONFIRMED')
        self.assertEqual(len(self.f.api.writes),1)

    def test_owner_transport_has_all_explicit_paths_and_no_fallback(self):
        with patch('fortis_approvals.workflow.client.WorkflowTransport',
                   return_value=self.f.gateway.publisher) as transport:
            client=_owner_client(self.f.config)
        transport.assert_called_once_with(endpoint=self.f.config.endpoint,
            grant_path=str(self.f.config.grant_path),certificate_path=str(self.f.config.certificate_path))
        self.assertIsNone(client.worker)

    def test_broader_capability_cannot_be_borrowed(self):
        original=self.f.client.capabilities
        def broader(**kwargs):
            return {**original(**kwargs),'workspaceOperations':['commit']}
        with patch.object(self.f.client,'capabilities',side_effect=broader):
            with self.assertRaises(Denied):self.f.runner.request(7)
        self.assertEqual(self.f.api.calls,[])

    def test_journal_evidence_cannot_rebind_an_existing_intent(self):
        result=self.f.runner.request(7);record=self.f.client.intents.journal.load(result['intent']['intentId'])
        evidence=copy.deepcopy(record['callerEvidence']);evidence['admission']['source']['mainSha']='f'*40
        with self.assertRaisesRegex(Denied,'INTENT_PAYLOAD_CHANGED'):
            self.f.client.intents.github_action(record['intent']['operation'],REPOSITORY,
                record['intent']['params'],reason=record['intent']['reason'],journal_evidence=evidence)
        self.assertEqual(len(self.f.gateway.core.owner_list()),1)

    def test_post_effect_failed_ci_does_not_undo_known_label_effect(self):
        result=self.f.runner.request(7);ident=result['intent']['requestId']
        self.f.gateway.approve(ident);self.f.next_invocation()
        self.f.api.conclusion[WORKFLOWS[0].ident]='failure'
        report=self.f.runner.inspect(result['intent']['intentId'])
        self.assertEqual(report['effect']['state'],'EXECUTED')
        self.assertTrue(report['originalRequests'][0]['receiptVerified'])
        self.assertTrue(report['originalRequests'][0]['targetReadback']['desiredStateObserved'])
        self.assertEqual(report['currentAdmission']['status'],'UNCONFIRMED')
        self.assertEqual(len(self.f.api.writes),1)

    def test_ci_rpc_budget_stops_after_one_slow_read(self):
        clock=iter([0,0,61]);reader=TypedCIReader(self.f.client.github,None,clock=lambda:next(clock))
        with self.assertRaisesRegex(Denied,'PUBLISHER_CI_READ_BUDGET'):reader._read(lambda:None)
        self.assertEqual(reader.reads,1)


if __name__=='__main__':
    unittest.main()

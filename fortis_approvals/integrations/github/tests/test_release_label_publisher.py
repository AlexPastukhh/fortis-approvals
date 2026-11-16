"""P3.2 source-only authority, approval binding, concurrency and recovery tests."""
import copy
from contextlib import contextmanager
from pathlib import Path
import tempfile
from types import SimpleNamespace
from threading import Event, Thread
import unittest
from unittest.mock import patch
import uuid

from fortis_approvals.core import Denied, Stale
from fortis_approvals.integrations.github.contract import validate_github_read
from fortis_approvals.integrations.github.publisher_profile import (
    ACTOR, REPOSITORY, READS, WRITES, PublisherProfile)
from fortis_approvals.integrations.github.release_label_ci import WORKFLOWS, ServerCIReader, collect_ci
from fortis_approvals.workflow.client import WorkflowClient
from fortis_approvals.workflow.ingress import NativeIngress
from fortis_approvals.integrations.github.publisher_evidence import own_label_evidence
from publisher_fixture import Fixture, HEAD, BASE, REGISTRY_ACTOR, OWNER


class PublisherTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.f=Fixture(self.root)

    def query(self, op, params, target=REPOSITORY):
        return dict(requestId=str(uuid.uuid4()),service='github',operation=op,target=target,params=params)

    def ask(self, *, fixture=None):
        f=fixture or self.f;intent=f.intent();code,row=f.publisher.call('/v1/actions',intent)
        self.assertEqual(code,202,row);self.assertEqual(row['state'],'PENDING')
        return intent['requestId']

    def client(self, fixture=None):
        f=fixture or self.f
        return WorkflowClient.for_release_label_publisher(gateway=f.publisher,intent_root=self.root/'journal')

    def test_disabled_profile_creates_no_grants_and_no_provider_effect(self):
        f=Fixture(self.root/'disabled',enabled=False)
        self.assertNotIn(ACTOR,f.broker.actor_operations)
        self.assertNotIn(ACTOR,f.broker.actor_read_operations)
        self.assertFalse(any(key[0]==ACTOR for key in f.core.policies))
        cap=f.publisher.post('/v1/workspace/capabilities',{})
        self.assertFalse(cap['publisherProfile']['enabled'])
        self.assertEqual(cap['githubReleaseLabelWrites']['policy'],'DENY')
        self.assertNotIn('globalRequestInventory',cap)
        self.assertEqual(f.publisher.call('/v1/actions',f.intent())[0],403)
        self.assertEqual(f.publisher.call('/v1/reads',self.query('get_pull_request',{'number':7}))[0],403)
        self.assertEqual(f.api.calls,[])
        self.assertEqual(f.core.owner_list(),[])

    def test_incident_only_ingress_requires_adapter_only_for_enabled_publisher(self):
        base=SimpleNamespace(broker=SimpleNamespace(core=self.f.core))
        for github in (None, SimpleNamespace(config=SimpleNamespace())):
            with self.subTest(github=github):
                native=NativeIngress(base,github=github,workspace=None,store=None,actor=REGISTRY_ACTOR)
                self.assertFalse(native.publisher.enabled)
                with self.assertRaisesRegex(ValueError,'GITHUB_PUBLISHER_EXPLICIT_OWNER_GRANTS_REQUIRED'):
                    NativeIngress(base,github=github,workspace=None,store=None,actor=REGISTRY_ACTOR,
                                  publisher_profile=self.f.profile)
        base.broker.actor_operations={ACTOR:frozenset(('github',x) for x in WRITES)}
        with self.assertRaisesRegex(ValueError,'GITHUB_PUBLISHER_BROKER_GUARDS_REQUIRED'):
            NativeIngress(base,github=SimpleNamespace(config=SimpleNamespace()),
                          workspace=None,store=None,actor=REGISTRY_ACTOR)

    def test_capabilities_are_own_label_only_and_legacy_ai_reads_unchanged(self):
        cap=self.f.publisher.post('/v1/workspace/capabilities',{})
        self.assertEqual(own_label_evidence(cap)['actor'],ACTOR)
        self.assertNotIn('globalRequestInventory',cap)
        self.assertEqual(cap['workspaceOperations'],[])
        self.assertEqual(set(cap['githubReleaseLabelWrites']['commands']),WRITES)
        self.assertEqual(cap['githubReleaseLabelWrites']['policy'],'ASK')
        self.assertTrue(self.f.repo.post('/v1/workspace/capabilities',{})[
            'globalRequestInventory']['crossActorDetails'])
        altered={**cap,'globalRequestInventory':{'crossActorDetails':True}}
        with self.assertRaises(Denied):own_label_evidence(altered)

    def test_new_head_read_is_default_deny_for_existing_repo_actor(self):
        code,_=self.f.repo.call('/v1/reads',self.query('list_head_workflow_runs',
            dict(headSha=HEAD,page=1,perPage=20)))
        self.assertEqual(code,403);self.assertEqual(self.f.api.calls,[])

    def test_head_read_is_typed_bounded_and_uses_only_exact_head(self):
        client=self.client();page=client.github.list_head_workflow_runs(REPOSITORY,HEAD)
        self.assertEqual(page['headSha'],HEAD);self.assertEqual(page['totalCount'],2)
        self.assertTrue(page['complete']);self.assertEqual(page['perPage'],20)
        self.assertTrue(all(x['headSha']==HEAD and x['event']=='pull_request' for x in page['items']))
        for values in [dict(headSha=HEAD,page=6,perPage=20),dict(headSha=HEAD,page=1,perPage=100),
                       dict(headSha=HEAD,page=True,perPage=20),dict(headSha='main',page=1,perPage=20),
                       dict(headSha=HEAD,page=1,perPage=20,url='https://example.invalid')]:
            with self.subTest(values=values):
                before=len(self.f.api.calls)
                with self.assertRaises(Denied):validate_github_read('list_head_workflow_runs',REPOSITORY,values)
                self.assertEqual(len(self.f.api.calls),before)

    def test_wrong_repo_and_unlisted_read_denied_before_provider(self):
        queries=[self.query('get_pull_request',{'number':7},'another-repo'),
                 self.query('get_repository',{}),self.query('list_repositories',{},OWNER),
                 self.query('get_branch',{'branch':'feature/unregistered'})]
        for query in queries:
            with self.subTest(query=query):
                self.assertEqual(self.f.publisher.call('/v1/reads',query)[0],403)
        self.assertEqual(self.f.api.calls,[])

    def test_workspace_owner_and_global_routes_are_not_publisher_authority(self):
        for path in ['/v1/workspace/submit','/v1/workspace/claim','/v1/workspace/finish',
                     '/v1/workspace/list_requests','/v1/workspace/list_uncertain',
                     '/v1/workspace/activity','/v1/git/artifact','/v1/github/visual-review/stage',
                     '/v1/owner/decision/finish']:
            with self.subTest(path=path):self.assertGreaterEqual(self.f.publisher.call(path,{})[0],400)
        intent=self.f.intent();intent['actor']=REGISTRY_ACTOR
        self.assertEqual(self.f.publisher.call('/v1/actions',intent)[0],403)
        self.assertEqual(self.f.publisher.call('/v1/actions',self.f.intent(
            operation='create_release_label',params=dict(name='build:new')))[0],403)
        self.assertEqual(self.f.api.calls,[])

    def test_fetch_delegates_existing_registration_without_own_task_or_claim(self):
        for ref,sha in [('main',BASE),('task/release-pilot',HEAD)]:
            response=self.f.publisher.post('/v1/git/fetch',dict(repository=REPOSITORY,ref=ref,expectedSha=sha))
            self.assertEqual(response['sha'],sha)
        self.assertEqual(self.f.backend.fetches,[(REPOSITORY,'main',BASE),
                                               (REPOSITORY,'task/release-pilot',HEAD)])
        with self.assertRaises(Denied):self.f.store.task(ACTOR,REPOSITORY,'release-pilot')
        self.assertFalse(self.f.store.task(REGISTRY_ACTOR,REPOSITORY,'release-pilot').get('closed',False))

    def test_fetch_missing_sha_registration_or_wrong_repo_has_no_provider_read(self):
        for updates in [dict(expectedSha=None),dict(ref='task/unregistered'),
                        dict(repository='other-repo'),dict(ref='refs/heads/main'),
                        dict(registryOwner=REGISTRY_ACTOR)]:
            with self.subTest(updates=updates):
                body=dict(repository=REPOSITORY,ref='main',expectedSha=BASE);body.update(updates)
                before=len(self.f.api.calls)
                self.assertGreaterEqual(self.f.publisher.call('/v1/git/fetch',body)[0],400)
                self.assertEqual(len(self.f.api.calls),before)
        self.assertEqual(self.f.backend.fetches,[])

    def test_fetch_rejects_closed_draft_fork_and_sha_drift(self):
        for attribute,value in [('state','closed'),('draft',True),('head_repo','Other/fork'),('head','c'*40)]:
            with self.subTest(attribute=attribute):
                old=getattr(self.f.api,attribute);setattr(self.f.api,attribute,value)
                try:self.assertGreaterEqual(self.f.publisher.call('/v1/git/fetch',dict(
                    repository=REPOSITORY,ref='task/release-pilot',expectedSha=HEAD))[0],400)
                finally:setattr(self.f.api,attribute,old)
        self.assertEqual(self.f.backend.fetches,[])
        self.f.store.close_task(REGISTRY_ACTOR,REPOSITORY,'release-pilot')
        before=len(self.f.api.calls)
        self.assertEqual(self.f.publisher.call('/v1/git/fetch',dict(
            repository=REPOSITORY,ref='task/release-pilot',expectedSha=HEAD))[0],403)
        self.assertEqual(len(self.f.api.calls),before)

    def test_one_owner_ask_binds_ci_and_preserves_human_labels(self):
        ident=self.ask();record=self.f.core._read(ident)
        self.assertEqual(record['actor'],ACTOR)
        admission=record['preview']['releaseLabelAdmission']
        self.assertEqual(admission['profileSha256'],self.f.profile.fingerprint(REGISTRY_ACTOR))
        self.assertEqual([x['name'] for x in admission['requiredCI']],['Source CI','Fortis Release Impact'])
        self.assertEqual(self.f.api.writes,[])
        self.assertTrue(all(('github',op) in self.f.portal.strong_operations for op in WRITES))
        executed=self.f.approve(ident);self.assertEqual(executed['state'],'EXECUTED',executed)
        self.assertEqual(executed['result']['headSha'],HEAD)
        self.assertEqual(set(executed['result']['labels']),
                         {'bug','build:legacy','build:api','release:review-required'})
        self.assertEqual(len(self.f.api.writes),1)

    def test_remove_is_one_bounded_owner_operation(self):
        intent=self.f.intent(operation='remove_pr_release_label')
        self.assertEqual(self.f.publisher.call('/v1/actions',intent)[0],202)
        result=self.f.approve(intent['requestId']);self.assertEqual(result['state'],'EXECUTED',result)
        self.assertEqual(set(result['result']['labels']),{'bug','release:review-required'})
        self.assertEqual(len(self.f.api.writes),1)

    def test_allows_no_publisher_allow_downgrade(self):
        self.f.core.policies[(ACTOR,'github','add_pr_release_labels')]='ALLOW'
        self.assertEqual(self.f.publisher.call('/v1/actions',self.f.intent())[0],403)
        self.assertEqual(self.f.api.calls,[]);self.assertEqual(self.f.core.owner_list(),[])

    def test_active_guard_blocks_legacy_and_definition_aliases_before_provider(self):
        ident=self.ask();before=len(self.f.api.calls)
        for intent in [self.f.intent(),self.f.intent(operation='create_release_label',
                target=REPOSITORY.upper(),params=dict(name='build:new'))]:
            self.assertEqual(self.f.repo.call('/v1/actions',intent)[0],409)
        self.assertEqual(len(self.f.api.calls),before)
        self.assertEqual([r['requestId'] for r in self.f.core.owner_list()],[ident])
        self.assertEqual(self.f.api.writes,[])

    def test_guard_is_durable_and_atomic_across_actors_and_core_instances(self):
        second=Fixture(self.root,api=self.f.api)
        entered,release,began=Event(),Event(),Event();blocked=[]
        def hold(method,suffix,params,body):
            if method=='GET' and suffix=='' and not blocked:
                blocked.append(True);entered.set()
                if not release.wait(3):raise AssertionError('fixture release timeout')
        self.f.api.on_request=hold
        original_db=second.core._db
        @contextmanager
        def observed_db():
            with original_db() as db:
                class Connection:
                    def execute(self,sql,*args):
                        if sql=='BEGIN IMMEDIATE':began.set()
                        return db.execute(sql,*args)
                    def __getattr__(self,name):return getattr(db,name)
                yield Connection()
        second.core._db=observed_db
        results=[];errors=[]
        def submit(bridge,fixture):
            try:results.append(bridge.call('/v1/actions',fixture.intent())[0])
            except Exception as exc:errors.append(exc)
        one=Thread(target=submit,args=(self.f.publisher,self.f));two=Thread(target=submit,args=(second.repo,second))
        one.start();self.assertTrue(entered.wait(2));two.start()
        try:self.assertTrue(began.wait(2))
        finally:release.set()
        one.join(5);two.join(5)
        self.assertFalse(one.is_alive() or two.is_alive());self.assertEqual(errors,[])
        self.assertEqual(sorted(results),[202,409]);self.assertEqual(len(self.f.core.owner_list()),1)
        restarted=Fixture(self.root,api=self.f.api);before=len(self.f.api.calls)
        self.assertEqual(restarted.publisher.call('/v1/actions',restarted.intent())[0],409)
        self.assertEqual(len(self.f.api.calls),before)

    def test_current_ci_changes_while_pending_prevent_effect(self):
        for change in ['attempt','failure','queued','workflow','disabled-workflow','skipped-job','partial-jobs']:
            with self.subTest(change=change),tempfile.TemporaryDirectory() as directory:
                f=Fixture(directory);ident=self.ask(fixture=f);workflow=WORKFLOWS[0]
                if change=='attempt':f.api.attempts[workflow.ident]=2
                elif change=='failure':f.api.conclusion[workflow.ident]='failure'
                elif change=='queued':f.api.status[workflow.ident]='in_progress';f.api.conclusion[workflow.ident]=None
                elif change=='workflow':f.api.sources[workflow.path]+=b'\n# modified PR workflow\n'
                elif change=='disabled-workflow':f.api.workflow_state[workflow.ident]='disabled_manually'
                elif change=='skipped-job':f.api.job_changes['offline-tests']={'conclusion':'skipped'}
                else:f.api.jobs_total_override=100
                result=f.approve(ident);self.assertEqual(result['state'],'STALE',result)
                self.assertEqual(f.api.writes,[])

    def test_newer_failed_run_never_substitutes_old_green(self):
        row=copy.deepcopy(self.f.api.runs()[0]);row.update(id=201,run_number=2,conclusion='failure')
        self.f.api.extra_runs=[row]
        self.assertEqual(self.f.publisher.call('/v1/actions',self.f.intent())[0],403)
        self.assertEqual(self.f.core.owner_list(),[]);self.assertEqual(self.f.api.writes,[])

    def test_ci_race_after_core_dispatch_compares_original_approved_preview(self):
        ident=self.ask();apply=self.f.adapter.apply
        def race(request):
            self.f.api.attempts[WORKFLOWS[0].ident]=2
            return apply(request)
        self.f.adapter.apply=race
        result=self.f.approve(ident);self.assertEqual(result['state'],'STALE',result)
        self.assertEqual(self.f.api.writes,[])

    def test_forged_fresh_preview_cannot_replace_actual_core_approval(self):
        ident=self.ask()
        def forged(request):
            self.f.api.attempts[WORKFLOWS[0].ident]=2
            return self.f.adapter.apply_approved(request,self.f.adapter.prepare(request))
        self.f.adapter.apply=forged
        result=self.f.approve(ident);self.assertEqual(result['state'],'STALE',result)
        self.assertEqual(self.f.api.writes,[])

    def test_revocation_policy_and_profile_races_at_effect_edge(self):
        for change in ['credential','policy','profile','expiry']:
            with self.subTest(change=change),tempfile.TemporaryDirectory() as directory:
                f=Fixture(directory);ident=self.ask(fixture=f);before=f.adapter._before_release_label_write
                def race(request,snapshot,approved):
                    if change=='credential':f.core.auth.revoke('publisher-fixture-credential')
                    elif change=='policy':f.core.policy_version='changed-after-dispatch'
                    elif change=='expiry':f.core.clock=lambda:f.core._read(ident)['expiresAt']
                    else:f.adapter.publisher=PublisherProfile(enabled=True,revision='f'*64,
                        validator_revision='d'*40,registry_delegation=True)
                    return before(request,snapshot,approved)
                f.adapter._before_release_label_write=race
                result=f.approve(ident);self.assertEqual(result['state'],'STALE',result)
                self.assertEqual(f.api.writes,[])

    def test_workflow_jobs_and_head_inventory_fail_closed(self):
        for change in ['foreign-head','duplicate-run','duplicate-job','foreign-job','missing-job','partial-runs']:
            with self.subTest(change=change),tempfile.TemporaryDirectory() as directory:
                f=Fixture(directory)
                if change=='foreign-head':f.api.ci_head='c'*40
                elif change=='duplicate-run':f.api.extra_runs=[copy.deepcopy(f.api.runs()[0])]
                elif change=='duplicate-job':f.api.job_changes['audit-projections']={'id':2010,'name':'offline-tests'}
                elif change=='foreign-job':f.api.job_changes['offline-tests']={'run_id':999}
                elif change=='missing-job':f.api.job_changes['offline-tests']={'name':'unrelated'}
                else:f.api.total_override=3
                self.assertEqual(f.publisher.call('/v1/actions',f.intent())[0],403)
                self.assertEqual(f.core.owner_list(),[]);self.assertEqual(f.api.writes,[])

    def test_ci_collection_has_finite_read_and_time_budgets(self):
        source=self.f.api.runs()[0]
        self.f.api.extra_runs=[{**source,'id':200+i,'workflow_id':999,'name':'Other',
            'path':'.github/workflows/other.yml'} for i in range(90)]
        reader=ServerCIReader(self.f.adapter)
        evidence=collect_ci(reader,profile=self.f.profile,registry_actor=REGISTRY_ACTOR,
            owner=OWNER,head=HEAD,number=7,branch=self.f.api.branch)
        self.assertEqual(reader.reads,18);self.assertEqual(len(evidence['requiredCI']),2)
        before=len(self.f.api.calls)
        with self.assertRaises(Denied):reader.get('actions/runs')
        self.assertEqual(len(self.f.api.calls),before)
        clock=iter([0,0,21]);reader=ServerCIReader(self.f.adapter,clock=lambda:next(clock))
        with self.assertRaises(Denied):reader.get('')
        self.assertEqual(reader.reads,1)

    def test_latest_attempt_drift_during_ci_collection_stops_admission(self):
        head_reads=[]
        def change(method,suffix,params,body):
            if suffix=='/actions/runs':
                head_reads.append(True)
                if len(head_reads)==2:self.f.api.attempts[WORKFLOWS[0].ident]=2
        self.f.api.on_request=change
        self.assertEqual(self.f.publisher.call('/v1/actions',self.f.intent())[0],403)
        self.assertEqual(self.f.core.owner_list(),[]);self.assertEqual(self.f.api.writes,[])

    def test_scope_factory_uses_explicit_private_journal_without_repo_fallback(self):
        client=self.client();self.assertIsNone(client.worker)
        self.assertEqual(client.intents.journal.root,self.root/'journal')
        with self.assertRaises(Denied):WorkflowClient.for_release_label_publisher(
            gateway=self.f.repo,intent_root=self.root/'not-publisher')
        with self.assertRaises(Denied):WorkflowClient.for_release_label_publisher(
            gateway=self.f.publisher,intent_root='relative-journal')
        self.assertFalse((self.root/'not-publisher').exists())
        with patch('fortis_approvals.integrations.github.repo_client.client.GatewayTransport',
                   side_effect=AssertionError('Repo credential fallback is forbidden')):
            for gateway in (None, object()):
                with self.subTest(gateway=gateway), self.assertRaisesRegex(
                        Denied, 'PUBLISHER_EXPLICIT_GATEWAY_REQUIRED'):
                    WorkflowClient.for_release_label_publisher(
                        gateway=gateway, intent_root=self.root/'missing-transport')
        self.assertFalse((self.root/'missing-transport').exists())

    def test_lost_ask_ack_and_restart_resume_same_uuid_then_original_receipt(self):
        client=self.client();ident=str(uuid.uuid4());self.f.publisher.lose_ask_ack=True
        first=client.github.add_pr_release_labels(REPOSITORY,**self.call_params(),request_id=ident,
            reason='One reviewed private publisher intent')
        self.assertEqual(first['attemptIds'],[ident]);self.assertEqual(len(self.f.core.owner_list()),1)
        restarted=self.client();pending=restarted.intents.retry(first['intentId'])
        self.assertEqual(pending['attemptIds'],[ident]);self.assertEqual(len(self.f.core.owner_list()),1)
        self.assertEqual(self.f.approve(ident)['state'],'EXECUTED')
        self.f.api.fail_context=True
        final=restarted.intents.retry(first['intentId'])
        self.assertEqual(final['status'],'DONE',final)
        self.assertEqual(final['effect'],dict(state='EXECUTED',requestId=ident))
        self.assertEqual(final['attemptIds'],[ident]);self.assertEqual(len(self.f.api.writes),1)

    def call_params(self):
        p=self.f.params()
        return dict(number=p['number'],expected_head_sha=p['expectedHeadSha'],
            expected_base_sha=p['expectedBaseSha'],expected_body_sha256=p['expectedBodySha256'],
            expected_labels_sha256=p['expectedLabelsSha256'],labels=p['labels'])

    def test_unknown_provider_ack_is_not_reconciled_from_matching_labels(self):
        ident=self.ask();self.f.api.lose_response=True
        result=self.f.approve(ident);self.assertEqual(result['state'],'UNCERTAIN')
        self.assertIn('build:api',self.f.api.labels)
        code,_=self.f.publisher.call('/v1/workspace/reconcile',dict(requestId=ident))
        self.assertEqual(code,403);self.assertEqual(self.f.core._read(ident)['state'],'UNCERTAIN')
        self.assertIsNone(self.f.adapter.receipt(ident));self.assertEqual(len(self.f.api.writes),1)


    def foreign_request(self):
        class Unrelated:
            def prepare(self,payload):return {'fixture':'unrelated provider'}
        self.f.core.adapters['unrelated']=Unrelated()
        self.f.core.policies[('other-ai','unrelated','fixture')]='ASK'
        ident=str(uuid.uuid4())
        self.f.core.submit('other-ai',dict(requestId=ident,service='unrelated',operation='fixture',
            target='unit',params={},expectedVersion=0,reason='Unrelated actor request remains untouched'))
        return ident

    def test_foreign_requests_are_hidden_without_reducing_ai_global_investigation(self):
        foreign=self.foreign_request();own=self.ask();before=len(self.f.api.calls)
        result=self.f.publisher.post('/v1/workspace/result',dict(requestId=foreign))
        self.assertEqual(result['state'],'NOT_FOUND');self.assertIsNone(result['result'])
        self.assertEqual(self.f.publisher.call('/v1/workspace/details',dict(
            requestId=foreign,eventOffset=0,eventLimit=100))[0],403)
        with self.assertRaises(Denied):self.client().incidents.inspect(foreign,github_reads=False)
        self.assertEqual(self.f.core._read(foreign)['state'],'PENDING')
        inventory=self.f.other.post('/v1/workspace/list_requests',dict(offset=0,limit=100,unresolvedOnly=True))
        self.assertFalse(inventory['actorScoped'])
        self.assertEqual({r['requestId'] for r in inventory['items']},{foreign,own})
        detail=self.f.other.post('/v1/workspace/details',dict(requestId=own,eventOffset=0,eventLimit=100))
        self.assertEqual(detail['request']['actor'],ACTOR)
        self.assertEqual(len(self.f.api.calls),before)

    def test_inspector_supports_own_evidence_and_preserves_known_execution_on_read_failure(self):
        own=self.ask();self.assertEqual(self.f.approve(own)['state'],'EXECUTED')
        self.f.api.fail_context=True
        report=self.client().incidents.inspect(own)
        self.assertEqual(report['coreState'],'EXECUTED')
        self.assertEqual(report['releaseLabelReconciliation']['state'],'UNKNOWN_STOP')
        self.assertEqual(report['releaseLabelReconciliation']['retryAuthorization'],'NONE')
        self.assertEqual(self.f.core._read(own)['state'],'EXECUTED')
        self.assertEqual(len(self.f.api.writes),1)

    def test_positive_original_receipt_is_the_only_machine_reconciliation(self):
        own=self.ask();confirm=self.f.adapter.confirm
        def lost_local_ack(*args):raise RuntimeError('unit failure after persisted receipt')
        self.f.adapter.confirm=lost_local_ack
        try:self.assertEqual(self.f.approve(own)['state'],'UNCERTAIN')
        finally:self.f.adapter.confirm=confirm
        receipt=self.f.adapter.receipt(own);self.assertEqual(receipt['requestId'],own)
        read=self.f.adapter.receipt
        self.f.adapter.receipt=lambda ident:{**receipt,'requestId':str(uuid.uuid4())}
        try:self.assertEqual(self.f.publisher.call('/v1/workspace/reconcile',dict(requestId=own))[0],403)
        finally:self.f.adapter.receipt=read
        before=len(self.f.api.calls)
        result=self.f.publisher.post('/v1/workspace/reconcile',dict(requestId=own))
        self.assertEqual(result['state'],'EXECUTED');self.assertEqual(result['result']['requestId'],own)
        self.assertEqual(len(self.f.api.calls),before);self.assertEqual(len(self.f.api.writes),1)

    def test_disabling_future_admission_keeps_original_own_receipt_readable(self):
        own=self.ask();self.assertEqual(self.f.approve(own)['state'],'EXECUTED')
        disabled=Fixture(self.root,api=self.f.api,enabled=False)
        self.assertFalse(disabled.publisher.post('/v1/workspace/capabilities',{})['publisherProfile']['enabled'])
        result=disabled.publisher.post('/v1/workspace/result',dict(requestId=own))
        self.assertEqual(result['state'],'EXECUTED');self.assertEqual(result['result']['requestId'],own)
        details=disabled.publisher.post('/v1/workspace/details',dict(requestId=own,eventOffset=0,eventLimit=100))
        self.assertEqual(details['request']['actor'],ACTOR);self.assertIsNotNone(details['receipt'])
        before=len(self.f.api.calls)
        self.assertEqual(disabled.publisher.call('/v1/actions',disabled.intent())[0],403)
        self.assertEqual(len(self.f.api.calls),before)

    def test_profile_missing_cannot_borrow_accidental_broad_grants(self):
        disabled=Fixture(self.root/'missing',enabled=False)
        disabled.broker.actor_operations[ACTOR]=frozenset(('github',x) for x in WRITES)
        disabled.broker.actor_read_operations[ACTOR]=frozenset({('github','get_repository')})
        disabled.core.policies[(ACTOR,'github','add_pr_release_labels')]='ALLOW'
        disabled.core.policies[(ACTOR,'github','get_repository')]='ALLOW'
        self.assertEqual(disabled.publisher.call('/v1/actions',disabled.intent())[0],403)
        self.assertEqual(disabled.publisher.call('/v1/reads',self.query('get_repository',{}))[0],403)
        self.assertEqual(disabled.api.calls,[])

    def test_logs_artifacts_and_token_inventory_are_outside_scoped_read_grant(self):
        queries=[self.query('get_job_log',dict(runId=101,attempt=1,jobId=2010,offsetLines=0,maxLines=10)),
                 self.query('list_run_artifacts',dict(runId=101,attempt=1,page=1,perPage=100)),
                 self.query('list_workflow_runs',dict(page=1,perPage=20))]
        for query in queries:self.assertEqual(self.f.publisher.call('/v1/reads',query)[0],403)
        self.assertEqual(self.f.api.calls,[])

    def test_real_owner_rejection_is_stop_for_the_same_journal_intent(self):
        client=self.client();ident=str(uuid.uuid4())
        first=client.github.add_pr_release_labels(REPOSITORY,**self.call_params(),request_id=ident,
            reason='One scoped proposal with preserved owner decision')
        self.assertEqual(first['attemptIds'],[ident]);self.f.approve(ident,'reject')
        result=client.intents.retry(first['intentId'])
        self.assertEqual(result['status'],'STOP');self.assertEqual(result['attemptIds'],[ident])
        self.assertEqual(self.f.core._read(ident)['state'],'REJECTED')
        self.assertEqual(self.f.api.writes,[])

    def test_legacy_allow_does_not_bypass_required_owner_approval_at_write(self):
        self.f.core.policies[(REGISTRY_ACTOR,'github','add_pr_release_labels')]='ALLOW'
        code,result=self.f.repo.call('/v1/actions',self.f.intent())
        self.assertEqual(code,200);self.assertEqual(result['state'],'STALE',result)
        self.assertEqual(self.f.api.writes,[])

    def test_over_limit_inventory_and_missing_review_pins_fail_closed(self):
        self.f.api.total_override=101
        self.assertEqual(self.f.publisher.call('/v1/actions',self.f.intent())[0],403)
        self.assertEqual(self.f.core.owner_list(),[]);self.assertEqual(self.f.api.writes,[])
        for values in [dict(enabled=True),dict(enabled='true'),
                       dict(enabled=True,revision='a'*64,validator_revision='b'*40),
                       dict(enabled=True,revision='a'*64,validator_revision='main',registry_delegation=True)]:
            with self.subTest(values=values),self.assertRaises(ValueError):PublisherProfile(**values)


if __name__=='__main__':unittest.main()

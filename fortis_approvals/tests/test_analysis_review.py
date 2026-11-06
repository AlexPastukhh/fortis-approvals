"""Offline domain/security tests. No real provider credentials or live mutations."""
from copy import deepcopy
from io import BytesIO
import json
from pathlib import Path
import tempfile
import unittest
import uuid
import zipfile
from urllib.error import HTTPError

from fortis_approvals.core import Authenticator, Core, Denied, Stale
from fortis_approvals.repo_action_contract import RepoIntentBroker, validate_intent, validate_read_query
from fortis_approvals.integrations.analysis_review import AnalysisReviewConfig, install
from fortis_approvals.integrations.sonarcloud.analysis_contract import READS as SONAR_READS, ACTIONS as SONAR_ACTIONS
from fortis_approvals.integrations.sonarcloud.gateway.read_adapter import SonarReadAdapter, SonarReadOnlyTransport
from fortis_approvals.integrations.sonarcloud.gateway.analysis_reader import AnalysisReader, validate_result
from fortis_approvals.integrations.sonarcloud.gateway.review_actions import SonarReviewAdapter
from fortis_approvals.integrations.sonarcloud.gateway.sonar import SonarIssueAdapter, SonarHTTPTransport, SonarTransportError
from fortis_approvals.integrations.github.analysis_contract import READS as GITHUB_READS, ACTIONS as GITHUB_ACTIONS
from fortis_approvals.integrations.github.gateway.analysis_adapter import AnalysisGitHubAdapter, GitHubReviewRouter
from fortis_approvals.integrations.github.gateway.transport import GitHubHTTPTransport, GitHubTransportError
from fortis_approvals.clients.analysis_review import AnalysisReviewClient
from test_sonar import TestOnlyVerifier

PROJECT = 'org_project'
SHA = 'a' * 40
BINDINGS = {'repo': {'projectKey': PROJECT, 'workflows': {'17': '.github/workflows/sonar.yml'}, 'allowCiControl': True}}


def envelope(op, params, *, service='sonarcloud', target=PROJECT, request_id=None):
    return dict(requestId=request_id or str(uuid.uuid4()), service=service, operation=op,
                target=target, params=params, reason='Explain this exact finding')


class Sonar:
    def __init__(self):
        self.posts = 0; self.calls = []; self.fail_post = False; self.foreign = False
        self.row = dict(key='I1', project=PROJECT, component=PROJECT+':src.py', rule='python:S100',
            message='Review input', issueStatus='OPEN', severity='MAJOR', type='VULNERABILITY',
            line=3, textRange=dict(startLine=3, endLine=3, startOffset=0, endOffset=4),
            flows=[{'locations': [{'component': PROJECT+':src.py', 'msg': 'source', 'textRange': None}]}],
            impacts=[{'softwareQuality': 'SECURITY', 'severity': 'HIGH'}], effort='5min',
            tags=['security'], assignee=None, updateDate='2026-11-06T00:00:00Z', comments=[],
            transitions=['accept', 'falsepositive', 'reopen', 'confirm'], credential='DO_NOT_PROJECT')
        self.task = dict(id='T1', componentKey=PROJECT, analysisId='A1', status='SUCCESS',
                         executedAt='2026-11-06T00:00:00Z', warnings=['test warning'])
        self.analysis = dict(key='A1', date='2026-11-06T00:00:00Z', revision=SHA, buildString='run-9-2')

    @staticmethod
    def paged(field, rows, p):
        pg = int(p.get('p', '1')); size = int(p.get('ps', '100'))
        return {field: rows[(pg-1)*size:pg*size], 'paging': {'pageIndex': pg, 'pageSize': size, 'total': len(rows)}}

    def call(self, method, path, p):
        self.calls.append((method, path, deepcopy(p)))
        if method == 'POST':
            self.posts += 1
            if path == '/api/issues/do_transition':
                self.row['issueStatus'] = {'accept':'ACCEPTED', 'falsepositive':'FALSE_POSITIVE',
                    'reopen':'OPEN', 'confirm':'CONFIRMED'}[p['transition']]
            elif path == '/api/issues/add_comment':
                self.row['comments'].append(dict(key='C'+str(self.posts), htmlText=p['text'], createdAt='now'))
            elif path == '/api/issues/assign': self.row['assignee'] = p['assignee'] or None
            elif path == '/api/issues/set_tags': self.row['tags'] = p['tags'].split(',') if p['tags'] else []
            else: raise AssertionError(path)
            self.row['updateDate'] = 'changed-' + str(self.posts)
            if self.fail_post: raise SonarTransportError('AMBIGUOUS_POST')
            return {'issue': deepcopy(self.row)}
        if path == '/api/components/search':
            return self.paged('components', [dict(key=PROJECT, qualifier='TRK', organization='org')], p)
        if path == '/api/issues/search':
            row = deepcopy(self.row)
            if self.foreign: row['project'] = 'foreign'
            if p.get('additionalFields') == 'transitions': row['transitions'] = ['accept']
            return self.paged('issues', [row], p)
        if path == '/api/ce/task': return {'task': deepcopy(self.task)}
        if path == '/api/project_analyses/search': return self.paged('analyses', [self.analysis], p)
        if path == '/api/project_branches/list':
            return {'branches': [dict(name='main', isMain=True, type='LONG', analysisDate='now')]}
        if path == '/api/project_pull_requests/list':
            return {'pullRequests': [dict(key='3', branch='task/x', base='main', analysisDate='now')]}
        if path == '/api/qualitygates/project_status':
            return {'projectStatus': {'status':'ERROR', 'ignoredConditions':True,
                'conditions':[{'status':'ERROR','metricKey':'new_coverage','comparator':'LT','errorThreshold':'80'}]}}
        if path == '/api/issues/changelog':
            return {'changelog':[{'creationDate':'now','diffs':[{'key':'status','oldValue':'OPEN','newValue':'ACCEPTED'}],
                                  'email':'PRIVATE'}]}
        if path == '/api/rules/show':
            return {'rule': {'key':'python:S100','name':'Rule', 'htmlDesc':'<p>Fix input</p><script>bad()</script>',
                             'lang':'py','severity':'MAJOR','type':'VULNERABILITY','status':'READY','tags':[]}}
        if path in ('/api/measures/component','/api/measures/component_tree'):
            component = dict(key=PROJECT, name='Project', measures=[dict(metric='new_coverage',period={'value':'22'})])
            if path.endswith('component'): return {'component':component}
            component.update(key=PROJECT+':src.py',path='src.py')
            return self.paged('components',[component],p)
        if path == '/api/duplications/show':
            return {'files':{'f':{'key':PROJECT+':src.py'}},'duplications':[{'blocks':[{'_ref':'f','from':1,'size':3}]}]}
        if path == '/api/hotspots/search':
            return self.paged('hotspots',[dict(key='H1',project=PROJECT,component=PROJECT+':src.py',
                line=1,message='Inspect',status='TO_REVIEW',resolution=None,
                securityCategory='auth',vulnerabilityProbability='HIGH')],p)
        if path == '/api/hotspots/show':
            return dict(key='H1',project={'key':PROJECT},component={'key':PROJECT+':src.py'},
                message='Inspect',status='TO_REVIEW',resolution=None,textRange=None,
                rule=dict(key='python:S200',riskDescription='Risk',fixRecommendations='Review'))
        raise AssertionError((method,path,p))


class GitHub:
    def __init__(self):
        self.posts = 0; self.calls = []; self.bad_job = False; self.fail_post = False; self.latest_attempt = 2
        self.run = dict(id=9,run_attempt=2,workflow_id=17,path='.github/workflows/sonar.yml',
            event='push',status='completed',conclusion='failure',head_sha=SHA,head_branch='main',
            repository={'full_name':'owner/repo'},head_repository={'full_name':'owner/repo'},
            created_at='now',updated_at='now')
        self.job = dict(id=5,run_id=9,run_attempt=2,head_sha=SHA,name='scan',status='completed',conclusion='failure',
            steps=[dict(number=1,name='Scan',status='completed',conclusion='failure')])
        self.artifact = dict(id=4,name='fortis-sonar-analysis-9-2',size_in_bytes=500,expired=False,
            created_at='now',digest=None,workflow_run={'id':9,'head_sha':SHA})
        self.manifest = dict(schemaVersion=1,repository='owner/repo',workflowId=17,
            workflowPath='.github/workflows/sonar.yml',runId=9,attempt=2,projectKey=PROJECT,
            context={'branch':'main'},prHeadSha=None,checkoutSha=SHA,scannerRevision=SHA,ceTaskId='T1')

    def request(self, method, path, *, params=None, body=None, **kw):
        self.calls.append((method,path,deepcopy(params),deepcopy(body)))
        if method == 'POST':
            self.posts += 1
            if self.fail_post: raise GitHubTransportError('AMBIGUOUS_POST')
            return {'_httpStatus':201}
        if path.endswith('/attempts/2'): return deepcopy(self.run)
        if path.endswith('/actions/runs/9'): return dict(self.run,run_attempt=self.latest_attempt)
        if path.endswith('/jobs'):
            return {'total_count':1,'jobs':[dict(self.job,run_attempt=1) if self.bad_job else deepcopy(self.job)]}
        if path.endswith('/actions/jobs/5'): return dict(self.job,run_attempt=1) if self.bad_job else deepcopy(self.job)
        if path.endswith('/artifacts'): return {'total_count':1,'artifacts':[deepcopy(self.artifact)]}
        if path.endswith('/actions/artifacts/4'): return deepcopy(self.artifact)
        if path.endswith('/annotations'):
            return [dict(path='src.py',start_line=3,end_line=3,annotation_level='failure',message='Finding',title=None,secret='HIDE')]
        if path.endswith('/check-runs/6'):
            return dict(id=6,name='Sonar',head_sha=SHA,status='completed',conclusion='failure',
                app={'id':1,'slug':'sonar'},output={'title':'Scan','summary':'Failed','text':None,'annotations_count':1})
        if path.endswith('/actions/workflows/17'):
            return dict(id=17,path='.github/workflows/sonar.yml',state='active')
        if '/git/ref/' in path: return {'object':{'sha':SHA}}
        if '/contents/' in path: return dict(path='.github/workflows/sonar.yml',type='file',sha='b'*40)
        raise AssertionError(path)

    def download(self, path, *, maximum):
        if path.endswith('/logs'): return b'test log\nscanner failed\n'
        out=BytesIO()
        with zipfile.ZipFile(out,'w') as z: z.writestr('analysis-manifest.json',json.dumps(self.manifest))
        return out.getvalue()

    def redact(self, value): return value


class Fixture(unittest.TestCase):
    def setUp(self):
        t=tempfile.TemporaryDirectory();self.addCleanup(t.cleanup);self.root=Path(t.name)
        self.sonar=Sonar();self.github=GitHub()
        self.reader=SonarReadAdapter(self.sonar,organization_keys=('org',),allowed_project_keys=(PROJECT,))
        self.reader._reader=SonarReadOnlyTransport(self.sonar,analysis_review=True)
        self.writer=SonarReviewAdapter(self.sonar,project_keys=(PROJECT,),receipt_store=self.root/'sonar.sqlite')
        self.verifier=TestOnlyVerifier()
        self.core=Core(self.root/'core.sqlite',adapters={'sonarcloud':self.writer},
            policies={('sonarcloud',op):'ASK' for _,op in SONAR_ACTIONS | {('sonarcloud','accept_issue')}},
            authenticator=Authenticator({'grant':'actor','second':'other'}),owner_verifier=self.verifier)
        self.broker=RepoIntentBroker(self.core,actor_operations={'actor':SONAR_ACTIONS | {('sonarcloud','accept_issue')}},
            actor_read_operations={'actor':SONAR_READS},read_adapter=self.reader)
        for service,op in SONAR_READS:self.core.policies[('actor',service,op)]='ALLOW'
        self.ci=AnalysisGitHubAdapter(self.github,owner='owner',repositories=('repo',),
            receipt_store=self.root/'ci.sqlite',bindings=deepcopy(BINDINGS))

    def read(self,op,p):
        return self.broker.read('grant',envelope(op,p))['data']['data']

    def decide(self,ident,decision='approve'):
        row=self.core._read(ident)
        return self.core.owner_decide(ident,decision,self.verifier.proof(ident,row['fingerprint'],decision))


class ReadTests(Fixture):
    def test_all_sonar_reads_and_public_projection(self):
        ctx={'branch':'main'}
        cases={
          'list_project_branches':{},'list_project_pull_requests':{},
          'list_analyses':dict(context=ctx,page=1,pageSize=10),
          'get_analysis_task':{'taskId':'T1'},
          'get_quality_gate_details':dict(context={},analysisId='A1',taskId='T1'),
          'search_issues':dict(context=ctx,page=1,pageSize=10,filters={'issueStatuses':['OPEN']}),
          'get_issue_details':dict(context=ctx,issueKey='I1'),
          'get_issue_history':dict(context=ctx,issueKey='I1'),
          'get_rule':dict(ruleKey='python:S100'),
          'get_measures':dict(context=ctx,metricKeys=['new_coverage','coverage']),
          'list_file_measures':dict(context=ctx,metricKeys=['new_coverage'],page=1,pageSize=10),
          'get_duplications':dict(context=ctx,componentKey=PROJECT+':src.py'),
          'list_security_hotspots':dict(page=1,pageSize=10),'get_security_hotspot':dict(hotspotKey='H1')}
        self.assertEqual({op for _,op in SONAR_READS},set(cases))
        for op,p in cases.items():
            with self.subTest(op=op):
                data=self.read(op,p);self.assertNotIn('DO_NOT_PROJECT',json.dumps(data));self.assertNotIn('PRIVATE',json.dumps(data))
        self.assertEqual(self.sonar.posts,0)
        details=self.read('get_issue_details',dict(context=ctx,issueKey='I1'))
        self.assertEqual(details['issue']['flows'][0][0]['msg'],'source')
        gate=self.read('get_quality_gate_details',dict(context={},analysisId='A1',taskId='T1'))
        self.assertEqual(gate['conditions'][0]['dataState'],'NO_VALUE')
        self.assertTrue(gate['ignoredConditions'])
        rule=self.read('get_rule',dict(ruleKey='python:S100'))
        self.assertEqual(rule['description'],'Fix input')
        measures=self.read('get_measures',dict(context=ctx,metricKeys=['new_coverage','coverage']))
        self.assertEqual(measures['missingMetrics'],['coverage'])

    def test_scope_schema_pagination_and_task_binding_fail_closed(self):
        bad=[
          envelope('list_analyses',dict(context={'pullRequest':'3'},page=1,pageSize=10)),
          envelope('get_analysis_task',dict(taskId='T1',url='https://bad')),
          envelope('get_issue_details',dict(context={'branch':'x','pullRequest':'3'},issueKey='I1')),
          envelope('get_measures',dict(context={},metricKeys=['arbitrary_secret'])),
          envelope('set_issue_tags',dict(projectKey=PROJECT,tags=[{}]),target='I1')]
        for q in bad:
            with self.subTest(q=q),self.assertRaises(Denied):
                (validate_intent if q['operation']=='set_issue_tags' else validate_read_query)(q)
        q=envelope('get_analysis_task',{'taskId':'T1'},target='foreign')
        with self.assertRaises(Denied):self.broker.read('grant',q)
        self.sonar.task['componentKey']='foreign'
        with self.assertRaises(Denied):self.read('get_quality_gate_details',dict(context={},analysisId='A1',taskId='T1'))
        self.assertFalse(any(p=='/api/qualitygates/project_status' for _,p,_ in self.sonar.calls))
        self.sonar.foreign=True
        with self.assertRaises(Denied):self.read('get_issue_details',dict(context={},issueKey='I1'))

    def test_low_level_legacy_transport_remains_closed(self):
        ro=SonarReadOnlyTransport(self.sonar)
        with self.assertRaises(Denied):ro.call('GET','/api/ce/task',{'id':'T1'})
        transport=SonarHTTPTransport(region='eu',bearer_token='FAKE-TEST-ONLY')
        with self.assertRaises(Denied):transport.call('GET','/api/qualitygates/project_status',{'projectKey':PROJECT,'pullRequest':'3'})
        with self.assertRaises(Denied):transport.call('GET','/api/ce/task',{'id':'T1'})

    def test_new_operations_remain_denied_without_grants(self):
        self.broker.actor_read_operations={}
        before=len(self.sonar.calls)
        with self.assertRaises(Denied):self.read('get_analysis_task',{'taskId':'T1'})
        self.assertEqual(before,len(self.sonar.calls))

    def test_every_github_ci_read_validates_attempt_and_manifest(self):
        cases={
          'get_workflow_run':dict(runId=9,attempt=2),
          'list_workflow_jobs':dict(runId=9,attempt=2,page=1,perPage=10),
          'get_job_log':dict(runId=9,attempt=2,jobId=5,offsetLines=0,maxLines=10),
          'get_check_run':dict(checkRunId=6,expectedHeadSha=SHA),
          'list_check_annotations':dict(checkRunId=6,expectedHeadSha=SHA,page=1,perPage=10),
          'list_run_artifacts':dict(runId=9,attempt=2,page=1,perPage=10),
          'get_analysis_manifest':dict(runId=9,attempt=2,artifactId=4)}
        self.assertEqual(set(cases),{x for _,x in GITHUB_READS})
        for op,p in cases.items():
            with self.subTest(op=op):
                result=self.ci.read(envelope(op,p,service='github',target='repo'))
                self.assertNotIn('HIDE',json.dumps(result))
        self.assertEqual(self.github.posts,0)
        self.github.bad_job=True
        with self.assertRaises(Denied):
            self.ci.read(envelope('get_job_log',cases['get_job_log'],service='github',target='repo'))
        self.github.manifest['attempt']=1
        with self.assertRaises(Denied):
            self.ci.read(envelope('get_analysis_manifest',cases['get_analysis_manifest'],service='github',target='repo'))

    def test_report_distinguishes_binding_stale_and_pending(self):
        self.broker.read_adapters['github']=self.ci
        self.broker.actor_read_operations['actor'] |= GITHUB_READS
        for service,op in GITHUB_READS:self.core.policies[('actor',service,op)]='ALLOW'
        broker=self.broker
        class Transport:
            def post(self,path,body,**kw):
                self.path=path
                return broker.read('grant',body)
        client=AnalysisReviewClient(Transport())
        report=client.get_ci_analysis_report('repo',run_id=9,attempt=2,artifact_id=4,expected_head_sha=SHA)
        self.assertEqual(report['binding'],'SONAR_REVISION_MATCH_CI_RECORDED')
        self.assertEqual(report['contextFreshness'],'LATEST_AT_READ')
        self.sonar.analysis['key']='A2'
        report=client.get_ci_analysis_report('repo',run_id=9,attempt=2,artifact_id=4,expected_head_sha=SHA)
        self.assertEqual(report['binding'],'CI_METADATA_ONLY')
        self.assertEqual(report['contextFreshness'],'STALE_OR_UNVERIFIED')
        self.sonar.task['status']='PENDING';self.sonar.task['analysisId']=None
        report=client.get_ci_analysis_report('repo',run_id=9,attempt=2,artifact_id=4,expected_head_sha=SHA)
        self.assertIsNone(report['gate'])
        with self.assertRaises(Denied):
            client.get_ci_analysis_report('repo',run_id=9,attempt=2,artifact_id=4,expected_head_sha='b'*40)


class ActionTests(Fixture):
    def proposal(self, op, **params):
        q=envelope(op,dict(projectKey=PROJECT,**params),target='I1')
        out=self.broker.submit('grant',q)
        self.assertEqual(out['state'],'PENDING');self.assertEqual(self.sonar.posts,0)
        return q,out

    def test_each_sonar_action_reject_approve_and_replay(self):
        cases={'mark_false_positive':{},'reopen_issue':{},'confirm_issue':{},
            'add_issue_comment':{'comment':'Investigated exact flow'},
            'assign_issue':{'assignee':'owner'},'set_issue_tags':{'tags':['reviewed']},
            'accept_issue':{'comment':'Fix later, tracked'}}
        for op,params in cases.items():
            with self.subTest(op=op):
                self.sonar.posts=0
                q,out=self.proposal(op,**params)
                self.assertEqual(self.decide(out['requestId'],'reject')['state'],'REJECTED')
                self.assertEqual(self.sonar.posts,0)
                q['requestId']=str(uuid.uuid4())
                out=self.broker.submit('grant',q)
                end=self.decide(out['requestId'])
                self.assertEqual(end['state'],'EXECUTED',end)
                self.assertEqual(self.sonar.posts,1)
                self.assertEqual(self.broker.submit('grant',q)['state'],'EXECUTED')
                self.assertEqual(self.sonar.posts,1)
                q['reason']='Changed reason'
                with self.assertRaises(Denied):self.broker.submit('grant',q)

    def test_stale_transition_and_ambiguous_post_never_repeat(self):
        q,out=self.proposal('mark_false_positive')
        self.sonar.row['message']='changed'
        self.assertEqual(self.decide(out['requestId'])['state'],'STALE')
        self.assertEqual(self.sonar.posts,0)
        q,out=self.proposal('add_issue_comment',comment='Review')
        self.sonar.fail_post=True
        self.assertEqual(self.decide(out['requestId'])['state'],'UNCERTAIN')
        self.assertEqual(self.sonar.posts,1)
        self.assertEqual(self.core.execute(out['requestId'])['state'],'UNCERTAIN')
        self.assertEqual(self.sonar.posts,1)

    def test_ask_downgrade_and_foreign_actor_denied_before_read(self):
        self.core.policies[('sonarcloud','mark_false_positive')]='ALLOW'
        before=len(self.sonar.calls)
        with self.assertRaises(Denied):self.broker.submit('grant',envelope('mark_false_positive',dict(projectKey=PROJECT),target='I1'))
        self.assertEqual(before,len(self.sonar.calls))
        with self.assertRaises(Denied):self.broker.submit('second',envelope('confirm_issue',dict(projectKey=PROJECT),target='I1'))

    def test_ci_controls_exact_attempt_fork_and_uncertain_no_retry(self):
        self.core.adapters['github']=self.ci
        self.broker.actor_operations['actor'] |= GITHUB_ACTIONS
        for _,op in GITHUB_ACTIONS:self.core.policies[('actor','github',op)]='ASK'
        for op,params in {
          'rerun_failed_jobs':dict(runId=9,attempt=2,expectedHeadSha=SHA),
          'rerun_job':dict(runId=9,attempt=2,expectedHeadSha=SHA,jobId=5),
          'cancel_analysis_run':dict(runId=9,attempt=2,expectedHeadSha=SHA),
          'dispatch_analysis_workflow':dict(workflowId=17,ref='main',expectedHeadSha=SHA)}.items():
            self.github.run['status']='in_progress' if op=='cancel_analysis_run' else 'completed'
            q=envelope(op,params,service='github',target='repo')
            out=self.broker.submit('grant',q)
            self.assertEqual(out['state'],'PENDING')
            end=self.decide(out['requestId'])
            self.assertEqual(end['state'],'EXECUTED',end)
            self.assertEqual(end['result']['effect'],'PROVIDER_ACCEPTED_NOT_COMPLETED')
            prior=self.github.posts
            self.assertEqual(self.broker.submit('grant',q)['state'],'EXECUTED')
            self.assertEqual(self.github.posts,prior)
        self.github.latest_attempt=3
        with self.assertRaises(Stale):
            self.ci.prepare(envelope('rerun_failed_jobs',dict(runId=9,attempt=2,expectedHeadSha=SHA),service='github',target='repo'))


class ProfileTests(Fixture):
    def test_explicit_config_install_and_extra_repo_git_is_denied(self):
        portal=type('Portal',(),{'core':self.core,'strong_operations':frozenset()})()
        config=AnalysisReviewConfig(owner='owner',bindings=BINDINGS,sonar_mutations=True)
        install(core=self.core,portal=portal,broker=self.broker,config=config,root=self.root,
                actor='actor',github_transport=self.github)
        result=self.broker.read('grant',envelope('get_workflow_run',dict(runId=9,attempt=2),service='github',target='repo'))
        self.assertEqual(result['data']['data']['run']['id'],9)
        router=self.core.adapters['github']
        with self.assertRaises(Denied):
            router.prepare(envelope('create_branch',dict(branch='task/x',sourceSha=SHA),service='github',target='repo'))
        self.assertIn(('github','rerun_job'),portal.strong_operations)
        self.assertIsNone(AnalysisReviewConfig.from_environment({}))
        for raw in ('{}','{"owner":"x","owner":"y"}','{"x":NaN}'):
            with self.assertRaises(Denied):
                AnalysisReviewConfig.from_environment({'FORTIS_ANALYSIS_REVIEW_CONFIG':raw})

class DownloadTests(unittest.TestCase):
    class Response:
        def __init__(self, content=b'data', status=200, headers=None):
            self.content=BytesIO(content);self.status=status;self.headers=headers or {}
        def __enter__(self):return self
        def __exit__(self,*args):return False
        def read(self,n=-1):return self.content.read(n)

    class Opener:
        def __init__(self, response, location='https://productionresultssa0.blob.core.windows.net/data?sig=private'):
            self.calls=[];self.response=response;self.location=location
        def open(self,request,timeout=None):
            self.calls.append(request)
            if len(self.calls)==1:
                raise HTTPError(request.full_url,302,'redirect',{'Location':self.location},BytesIO())
            return self.response

    def test_download_strips_bearer_and_bounds_content(self):
        opener=self.Opener(self.Response())
        transport=GitHubHTTPTransport('github_pat_'+'x'*40,opener=opener)
        self.assertEqual(transport.download('/repos/owner/repo/actions/jobs/5/logs',maximum=10),b'data')
        self.assertIsNotNone(opener.calls[0].get_header('Authorization'))
        self.assertIsNone(opener.calls[1].get_header('Authorization'))
        self.assertIsNone(opener.calls[1].get_header('Cookie'))
        self.assertEqual(transport.redact('Authorization: Bearer secret\ngithub_pat_'+'x'*40),
                         'Authorization: [REDACTED]\n[REDACTED]')
        opener=self.Opener(self.Response(b'x'*11))
        with self.assertRaises(GitHubTransportError):
            GitHubHTTPTransport('x'*40,opener=opener).download('/repos/owner/repo/actions/artifacts/4/zip',maximum=10)

    def test_download_rejects_untrusted_hosts_credentials_and_second_redirect(self):
        for location in ('http://productionresultssa0.blob.core.windows.net/x',
                         'https://attacker.invalid/x',
                         'https://productionresultssa0.blob.core.windows.net.attacker.invalid/x',
                         'https://user@productionresultssa0.blob.core.windows.net/x',
                         'https://productionresultssa0.blob.core.windows.net:444/x'):
            opener=self.Opener(self.Response(),location)
            with self.subTest(location=location),self.assertRaises(GitHubTransportError):
                GitHubHTTPTransport('x'*40,opener=opener).download('/repos/owner/repo/actions/jobs/5/logs',maximum=10)
            self.assertEqual(len(opener.calls),1)
        opener=self.Opener(self.Response(status=302,headers={'Location':'https://attacker.invalid'}))
        with self.assertRaises(GitHubTransportError):
            GitHubHTTPTransport('x'*40,opener=opener).download('/repos/owner/repo/actions/jobs/5/logs',maximum=10)
        self.assertEqual(len(opener.calls),2)

    def test_download_never_accepts_caller_urls(self):
        transport=GitHubHTTPTransport('x'*40)
        with self.assertRaises(Denied):transport.download('https://attacker.invalid',maximum=10)

class TLSReviewTests(unittest.TestCase):
    from test_r6_repo_sonar_read_to_approvals_tls_offline import R6CompleteOfflineChainTests as Base
    cleanup_services=staticmethod(Base.cleanup_services)
    machine_call=Base.machine_call
    owner_call=Base.owner_call
    owner_login=Base.owner_login

    def setUp(self):
        self.Base.setUp(self)
        self.fake=Sonar();self.github=GitHub()
        self.core.adapters['sonarcloud']=SonarIssueAdapter(self.fake,project_keys=(PROJECT,),
            receipt_store=self.folder/'review-sonar.sqlite')
        reader=SonarReadAdapter(self.fake,organization_keys=('org',),allowed_project_keys=(PROJECT,))
        self.broker.read_adapters['sonarcloud']=reader
        install(core=self.core,portal=self.portal,broker=self.broker,
            config=AnalysisReviewConfig(owner='owner',bindings=BINDINGS,sonar_mutations=True),
            root=self.folder,actor='trusted-ai-actor',github_transport=self.github)

    def test_real_tls_new_reads_web_authn_reject_approve_and_no_machine_bypass(self):
        q=envelope('get_issue_details',dict(context={'pullRequest':'3'},issueKey='I1'))
        code,data=self.machine_call('/v1/reads',q)
        self.assertEqual(code,200,data)
        self.assertEqual(data['data']['data']['issue']['flows'][0][0]['msg'],'source')
        q=envelope('get_workflow_run',dict(runId=9,attempt=2),service='github',target='repo')
        code,data=self.machine_call('/v1/reads',q)
        self.assertEqual(code,200,data)
        self.assertEqual(data['data']['data']['run']['attempt'],2)
        for op,params,service,target in (
            ('mark_false_positive',dict(projectKey=PROJECT,comment='Reviewed source flow'),'sonarcloud','I1'),
            ('rerun_failed_jobs',dict(runId=9,attempt=2,expectedHeadSha=SHA),'github','repo')):
            q=envelope(op,params,service=service,target=target)
            code,out=self.machine_call('/v1/actions',q)
            self.assertEqual((code,out['state']),(202,'PENDING'))
            self.assertEqual(self.fake.posts,0)
            self.assertEqual(self.github.posts,0)
            self.assertEqual(self.machine_call('/v1/owner/decision/finish',{})[0],404)
            if self.cookie is None:self.owner_login()
            # Session-only execution cannot approve a newly registered strong operation.
            code,_,_=self.owner_call('/v1/owner/decision',{'requestId':q['requestId'],'decision':'approve'})
            self.assertIn(code,(403,404))
            code,begin,_=self.owner_call('/v1/owner/decision/begin',{'requestId':q['requestId'],'decision':'reject'})
            self.assertEqual(code,200)
            code,out,_=self.owner_call('/v1/owner/decision/finish',{'requestId':q['requestId'],'decision':'reject',
                'ceremonyId':begin['ceremonyId'],'response':self.key.assert_(begin)})
            self.assertEqual((code,out['state']),(200,'REJECTED'))
        q=envelope('mark_false_positive',dict(projectKey=PROJECT,comment='Reviewed exact input flow'),target='I1')
        self.assertEqual(self.machine_call('/v1/actions',q)[0],202)
        code,begin,_=self.owner_call('/v1/owner/decision/begin',{'requestId':q['requestId'],'decision':'approve'})
        self.assertEqual(code,200)
        code,out,_=self.owner_call('/v1/owner/decision/finish',{'requestId':q['requestId'],'decision':'approve',
            'ceremonyId':begin['ceremonyId'],'response':self.key.assert_(begin)})
        self.assertEqual((code,out['state']),(200,'EXECUTED'),out)
        self.assertEqual(self.fake.posts,1)
        self.assertEqual(self.machine_call('/v1/actions',q)[1]['state'],'EXECUTED')
        self.assertEqual(self.fake.posts,1)

class AdditionalBindingTests(Fixture):
    def test_pr_metadata_never_becomes_verified_branch_binding(self):
        self.github.run['event']='pull_request'
        self.github.run['pull_requests']=[dict(number=3,head={'sha':SHA},base={'sha':'b'*40})]
        self.github.manifest.update(context={'pullRequest':'3'},prHeadSha=SHA,checkoutSha='c'*40)
        self.broker.read_adapters['github']=self.ci
        self.broker.actor_read_operations['actor'] |= GITHUB_READS
        for service,op in GITHUB_READS:self.core.policies[('actor',service,op)]='ALLOW'
        broker=self.broker
        class Transport:
            def post(self,path,body,**kw):return broker.read('grant',body)
        result=AnalysisReviewClient(Transport()).get_ci_analysis_report('repo',run_id=9,attempt=2,
            artifact_id=4,expected_head_sha=SHA)
        self.assertEqual(result['binding'],'CI_METADATA_ONLY')
        self.assertEqual(result['contextFreshness'],'UNKNOWN')
        self.assertEqual(result['manifest']['checkoutSha'],'c'*40)
        self.github.manifest['context']={'pullRequest':'4'}
        with self.assertRaises(Denied):
            AnalysisReviewClient(Transport()).get_ci_analysis_report('repo',run_id=9,attempt=2,
                artifact_id=4,expected_head_sha=SHA)

    def test_artifact_digest_zip_traversal_duplicate_json_and_oversize_denied(self):
        q=envelope('get_analysis_manifest',dict(runId=9,attempt=2,artifactId=4),service='github',target='repo')
        self.github.artifact['digest']='sha256:'+'0'*64
        with self.assertRaises(Denied):self.ci.read(q)
        self.github.artifact['digest']=None
        for filename,content in (('../analysis-manifest.json','{}'),
                                 ('analysis-manifest.json','{"runId":9,"runId":10}'),
                                 ('analysis-manifest.json','x'*16385)):
            archive=BytesIO()
            with zipfile.ZipFile(archive,'w') as z:z.writestr(filename,content)
            self.github.download=lambda *a,**k:archive.getvalue()
            with self.subTest(filename=filename,size=len(content)),self.assertRaises(Denied):
                self.ci.read(q)

    def test_ci_stale_approval_fork_scope_and_uncertain_receipt(self):
        self.core.adapters['github']=self.ci;self.broker.actor_operations['actor'] |= GITHUB_ACTIONS
        for _,op in GITHUB_ACTIONS:self.core.policies[('actor','github',op)]='ASK'
        p=dict(runId=9,attempt=2,expectedHeadSha=SHA)
        q=envelope('rerun_failed_jobs',p,service='github',target='repo')
        self.broker.submit('grant',q)
        self.github.latest_attempt=3
        self.assertEqual(self.decide(q['requestId'])['state'],'STALE')
        self.assertEqual(self.github.posts,0)
        self.github.latest_attempt=2
        self.github.run['head_repository']={'full_name':'attacker/fork'}
        with self.assertRaises(Denied):self.ci.prepare(q)
        self.github.run['head_repository']={'full_name':'owner/repo'}
        q['requestId']=str(uuid.uuid4());self.broker.submit('grant',q);self.github.fail_post=True
        self.assertEqual(self.decide(q['requestId'])['state'],'UNCERTAIN')
        self.assertEqual(self.core.execute(q['requestId'])['state'],'UNCERTAIN')
        self.assertEqual(self.github.posts,1)
        self.assertIsNone(self.ci.receipt(q['requestId']))

    def test_default_candidate_retains_old_grants_and_review_refuses_production(self):
        from fortis_approvals.r7_unified_candidate import build_r7_unified_candidate, ACTOR
        base=dict(state=self.root/'candidate',owner_origin='http://localhost:19203',
            ingress_host='host.docker.internal:19204',ingress_grant='test-grant-'+'x'*32,
            sonar_transport=self.sonar,organizations=('org',),project_keys=(PROJECT,))
        base['state'].mkdir(mode=0o700)
        core,owner,portal,ingress=build_r7_unified_candidate(**base)
        self.assertEqual(len(ingress.broker.actor_read_operations[ACTOR]),4)
        from fortis_approvals.r5_read_candidate import build_r5_read_candidate, _ACTOR
        (self.root/'r5-candidate').mkdir(mode=0o700)
        _,_,_,r5_ingress=build_r5_read_candidate(**{k:v for k,v in dict(base,state=self.root/'r5-candidate').items() if k != 'project_keys'})
        self.assertEqual(len(r5_ingress.broker.actor_read_operations[_ACTOR]),4)
        before=len(self.sonar.calls)
        with self.assertRaises(Denied):
            ingress.broker.read(base['ingress_grant'],envelope('get_analysis_task',{'taskId':'T1'}))
        self.assertEqual(len(self.sonar.calls),before)
        config=AnalysisReviewConfig(owner='owner',bindings=BINDINGS)
        with self.assertRaises(Denied):
            config.check_endpoints('http://localhost:19103','host.docker.internal:19104')
        (self.root/'candidate-enabled').mkdir(mode=0o700)
        core,owner,portal,ingress=build_r7_unified_candidate(**dict(base,state=self.root/'candidate-enabled'),
            analysis_review=config,github_transport=self.github)
        self.assertIn(('github','get_workflow_run'),ingress.broker.actor_read_operations[ACTOR])
        self.assertNotIn(('sonarcloud','mark_false_positive'),ingress.broker.actor_operations[ACTOR])


class ManifestTests(unittest.TestCase):
    def test_writer_uses_only_public_fields_and_rejects_ambiguous_metadata(self):
        from fortis_approvals.integrations.sonarcloud.repo_client.manifest import build_manifest
        args=dict(environment={'GITHUB_REPOSITORY':'owner/repo',
                'GITHUB_WORKFLOW_REF':'owner/repo/.github/workflows/sonar.yml@refs/heads/main',
                'GITHUB_RUN_ID':'9','GITHUB_RUN_ATTEMPT':'2','SONAR_TOKEN':'NEVER_READ'},
            workflow_id=17,project_key=PROJECT,context={'branch':'main'},pr_head_sha=None,
            checkout_sha=SHA,scanner_revision=SHA,report_text='ceTaskId=T1\nserverUrl=https://ignored.invalid\n')
        result=build_manifest(**args)
        self.assertEqual(result['ceTaskId'],'T1')
        self.assertNotIn('NEVER_READ',json.dumps(result))
        self.assertNotIn('ignored.invalid',json.dumps(result))
        with self.assertRaises(Denied):
            build_manifest(**dict(args,report_text='ceTaskId=T1\nceTaskId=T2'))

class SonarTransportTests(unittest.TestCase):
    def transport(self, content):
        from fortis_approvals.integrations.sonarcloud.gateway.analysis_transport import SonarAnalysisTransport
        original=SonarHTTPTransport(region='eu',bearer_token='TEST_TOKEN_NEVER_REAL')
        class Opener:
            def __init__(self):self.calls=[]
            def open(self,req,timeout=None):
                self.calls.append(req)
                return DownloadTests.Response(content)
        original._opener=Opener()
        return SonarAnalysisTransport(original)

    def test_extended_transport_fixed_origin_allowed_params_and_no_secret_response(self):
        transport=self.transport(b'{"task":{"id":"T1"}}')
        result=transport.call('GET','/api/ce/task',{'id':'T1','additionalFields':'warnings'})
        self.assertEqual(result,{'task':{'id':'T1'}})
        req=transport._opener.calls[0]
        self.assertTrue(req.full_url.startswith('https://sonarcloud.io/api/ce/task?'))
        for method,path,params in (
            ('GET','/api/ce/task',{'id':'T1','additionalFields':'scannerContext'}),
            ('POST','/api/projects/delete',{'project':PROJECT}),
            ('GET','https://attacker.invalid',{})):
            with self.assertRaises(Denied):transport.call(method,path,params)
        self.assertEqual(len(transport._opener.calls),1)
        reflected=self.transport(b'{"warnings":["TEST_TOKEN_NEVER_REAL"]}').call('GET','/api/ce/task',{'id':'T1'})
        self.assertEqual(reflected['warnings'],['[REDACTED]'])

    def test_extended_transport_rejects_duplicate_nonfinite_and_large_provider_json(self):
        for raw in (b'{"task":1,"task":2}',b'{"task":NaN}',b'x'*262145):
            with self.subTest(raw=raw[:40]),self.assertRaises((Denied,SonarTransportError)):
                self.transport(raw).call('GET','/api/ce/task',{'id':'T1'})

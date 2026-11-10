"""Offline safety tests: typed categories, actor-scoped heartbeat, old claim.

No real provider operation, claim replay or protected production state mutation.
"""
import json
from pathlib import Path
from io import BytesIO
import sqlite3
import subprocess
import tempfile
import unittest
import uuid
from types import SimpleNamespace
from unittest.mock import Mock, patch

from fortis_approvals.core import Authenticator, Conflict, Core, Denied
from fortis_approvals.incidents import IncidentCore
from fortis_approvals.workflow.error_diagnostics import category, evidence, observe_adapter
from fortis_approvals.workflow.client import WorkflowClient
from fortis_approvals.workflow.incident_read import diagnose
from fortis_approvals.workflow.ingress import NativeIngress, NATIVE_PATHS
from fortis_approvals.workflow.store import Store
from fortis_approvals.workflow.worker import Worker


class ActivityStoreTests(unittest.TestCase):
    def setUp(self):
        t=tempfile.TemporaryDirectory(prefix='worker-observability-')
        self.addCleanup(t.cleanup)
        self.root=Path(t.name)/'state'
        self.store=Store(self.root)
        self.actor='actor-a'
        self.ids=[]

    def enqueue(self,actor='actor-a'):
        ident=str(uuid.uuid4())
        self.store.enqueue(actor,dict(requestId=ident,service='workspace',
            operation='inspect',target='sandbox',params={'task':None},approvedPreview={}))
        self.ids.append(ident)
        return ident

    def test_legacy_claim_remains_unchanged_and_has_no_observation(self):
        old=str(uuid.uuid4())
        token=str(uuid.uuid4())
        with self.store.db() as db:
            db.execute('INSERT INTO jobs(id,actor,payload,state,claim,result,error) VALUES (?,?,?,?,?,?,?)',
                       (old,self.actor,'{}','CLAIMED',token,None,None))
        store=Store(self.root)  # idempotent additive migration, no rewriting of old job
        r=store.job(old)
        self.assertEqual((r['state'],r['claim'],r['result'],r['error']),
                         ('CLAIMED',token,None,None))
        item=store.activity(self.actor)['items'][0]
        self.assertEqual(item['signal'],'NO_HEARTBEAT_UNCONFIRMED')
        self.assertIsNone(item['claimedAt'])
        self.assertIsNone(item['lastHeartbeatAt'])
        self.assertFalse(store.activity(self.actor)['quiescenceProven'])
        self.assertNotIn(token,json.dumps(store.activity(self.actor)))

    def test_true_legacy_seven_column_schema_migrates_without_rewriting_claim(self):
        # Construct a pre-observability database *before* Store initialization.
        temp=tempfile.TemporaryDirectory(prefix='legacy-worker-schema-')
        self.addCleanup(temp.cleanup)
        root=Path(temp.name)/'state'
        root.mkdir(mode=0o700)
        ident=str(uuid.uuid4());claim=str(uuid.uuid4())
        with sqlite3.connect(root/'workflow.sqlite') as db:
            db.execute('CREATE TABLE jobs(id TEXT PRIMARY KEY,actor TEXT,payload TEXT,'
                       'state TEXT,claim TEXT,result TEXT,error TEXT)')
            db.execute('INSERT INTO jobs VALUES (?,?,?,?,?,?,?)',
                       (ident,self.actor,'{}','CLAIMED',claim,None,None))
        (root/'workflow.sqlite').chmod(0o600)
        store=Store(root)
        self.assertEqual((store.job(ident)['claim'],store.job(ident)['state']),
                         (claim,'CLAIMED'))
        self.assertEqual(store.activity(self.actor)['items'][0]['signal'],
                         'NO_HEARTBEAT_UNCONFIRMED')
        # New columns are nullable, no synthetic liveness or outcome is inferred.
        self.assertEqual(len(store.job(ident)),10)

    def test_heartbeat_is_bound_to_original_claim_and_cannot_restart_job(self):
        ident=self.enqueue()
        token=self.store.claim(self.actor,ident)['claim']
        self.assertIsNone(self.store.job(ident)['heartbeat_at'])
        with self.assertRaises(Denied):self.store.heartbeat('actor-b',ident,token)
        with self.assertRaises(Denied):self.store.heartbeat(self.actor,ident,str(uuid.uuid4()))
        with patch('fortis_approvals.workflow.store.time.time',return_value=1000):
            self.store.heartbeat(self.actor,ident,token)
            a=self.store.activity(self.actor)
        self.assertEqual(a['items'][0]['signal'],'RECENT_HEARTBEAT_UNCONFIRMED')
        self.assertEqual(a['claimed'],1)
        with patch('fortis_approvals.workflow.store.time.time',return_value=1050):
            a=self.store.activity(self.actor)
        self.assertEqual(a['items'][0]['signal'],'STALE_HEARTBEAT_UNCONFIRMED')
        self.assertFalse(a['quiescenceProven'])
        self.assertEqual(self.store.claim(self.actor,ident),{'state':'CLAIMED'})
        result={'requestId':ident,'operation':'inspect','repository':'sandbox'}
        self.store.finish(self.actor,ident,token,result,None)
        with self.assertRaises(Denied):self.store.heartbeat(self.actor,ident,token)
        self.assertEqual(self.store.activity(self.actor)['total'],0)
        self.assertEqual(self.store.job(ident)['state'],'DONE')

    def test_other_actor_cannot_see_or_modify_claim_and_pagination_is_bounded(self):
        ids=[self.enqueue() for _ in range(105)]
        own=self.store.activity(self.actor,limit=100)
        self.assertEqual((own['total'],own['queued'],own['claimed']), (105,105,0))
        self.assertEqual(len(own['items']),100)
        self.assertEqual(len(self.store.activity(self.actor,offset=100)['items']),5)
        self.assertEqual(self.store.activity('actor-b')['items'],[])
        self.assertEqual({x['requestId'] for x in own['items']+self.store.activity(self.actor,offset=100)['items']},set(ids))
        for data in ({'limit':0},{'limit':101},{'limit':False},
                     {'offset':-1},{'offset':True},{'offset':1000001}):
            with self.subTest(data=data),self.assertRaises(Denied):
                self.store.activity(self.actor,**data)

    def test_diagnostic_allowlist_and_immutable_finish(self):
        ident=self.enqueue();token=self.store.claim(self.actor,ident)['claim']
        bad={'stage':'WORKER_EXECUTE','code':'SECRET-private-token'}
        with self.assertRaises((Denied,ValueError)):
            self.store.finish(self.actor,ident,token,None,'UNCERTAIN',bad)
        self.assertEqual(self.store.job(ident)['state'],'CLAIMED')
        good=evidence('WORKER_EXECUTE','TIMEOUT')
        self.store.finish(self.actor,ident,token,None,'UNCERTAIN',good)
        self.store.finish(self.actor,ident,token,None,'UNCERTAIN',good)  # same receipt idempotent
        self.assertEqual(json.loads(self.store.job(ident)['diagnostic']),good)
        with self.assertRaises(Conflict):
            self.store.finish(self.actor,ident,token,None,'UNCERTAIN',evidence('WORKER_EXECUTE','UNKNOWN'))
        self.assertNotIn('SECRET-private-token',self.store.path.read_bytes().decode('latin-1'))


class CoreAndIngressTests(unittest.TestCase):
    def setUp(self):
        t=tempfile.TemporaryDirectory(prefix='worker-typed-core-')
        self.addCleanup(t.cleanup)
        root=Path(t.name)
        self.store=Store(root/'store')
        self_outer_store=self.store
        class InstrumentedAdapter:
            def __init__(self):
                self.store=self_outer_store
                self.core=None
                self.fail=None
                self.confirm_result=True
            def prepare(self,payload):return {'snapshot':'locked'}
            @observe_adapter('WORKSPACE_ADAPTER')
            def apply(self,payload):
                if self.fail is not None:raise self.fail
                return {'requestId':payload['requestId']}
            def confirm(self, ident, result):return self.confirm_result
        self.adapter=InstrumentedAdapter()
        self.core=IncidentCore(root/'core.sqlite',adapters={'workspace':self.adapter},
            policies={('workspace','inspect'):'ALLOW'},
            authenticator=Authenticator({'secret-a':'actor-a','secret-b':'actor-b'}))
        self.adapter.core=self.core
        self.native=NativeIngress(SimpleNamespace(broker=SimpleNamespace(core=self.core)),
            github=None,workspace=None,store=self.store,actor='actor-a')

    def submit(self):
        return self.core.submit('actor-a',dict(requestId=str(uuid.uuid4()),
            service='workspace',operation='inspect',target='sandbox',params={'task':None},
            expectedVersion=0,reason='offline sensitive'))

    def test_core_durable_stage_exception_class_no_raw_text(self):
        secret='PRIVATE-API-KEY-7890'
        self.adapter.fail=TimeoutError('timeout '+secret)
        record=self.submit()
        self.assertEqual(record['state'],'UNCERTAIN')
        event=self.core.events(record['requestId'])[-1]
        self.assertEqual(json.loads(self.core.events(record['requestId'])[-2]['detail']),
                         evidence('WORKSPACE_ADAPTER','TIMEOUT'))
        self.assertEqual(event['state'],'UNCERTAIN')
        details=self.native._dispatch('/v1/workspace/details',
            {'requestId':record['requestId'],'eventOffset':0,'eventLimit':100},'secret-a','actor-a')
        self.assertEqual(details['diagnostic']['coreError'],
                         evidence('WORKSPACE_ADAPTER','TIMEOUT'))
        self.assertNotIn(secret,self.core.path.read_bytes().decode('latin-1'))
        self.assertEqual(record['failure'],'REMOTE_OUTCOME_UNCONFIRMED')
        self.adapter.fail=None
        self.adapter.confirm_result=False
        second=self.submit()
        self.assertEqual(self.core.events(second['requestId'])[-1]['state'],'UNCERTAIN')
        self.assertEqual(second['state'],'UNCERTAIN')

    def test_activity_route_is_actor_scoped_and_heartbeat_claim_bound(self):
        ident=self.submit()['requestId']
        self.store.enqueue('actor-a',dict(requestId=ident,service='workspace',
            operation='inspect',target='sandbox',params={'task':None},approvedPreview={}))
        # This is only a local authorization fixture; no worker is executed.
        with self.core._db() as db:
            db.execute("UPDATE requests SET state='DISPATCHED' WHERE id=?",(ident,))
        assert '/v1/workspace/activity' in NATIVE_PATHS
        assert '/v1/workspace/heartbeat' in NATIVE_PATHS
        a=self.native._dispatch('/v1/workspace/activity',{'offset':0,'limit':100},'secret-a','actor-a')
        self.assertEqual(a['items'][0]['signal'],'NOT_CLAIMED')
        claim=self.store.claim('actor-a',ident)['claim']
        with self.assertRaises(Denied):
            self.native._dispatch('/v1/workspace/activity',{'offset':0,'limit':100},'secret-b','actor-a')
        with self.assertRaises(Denied):
            self.native._dispatch('/v1/workspace/heartbeat',{'requestId':ident,'claim':claim},'secret-b','actor-a')
        self.native._dispatch('/v1/workspace/heartbeat',{'requestId':ident,'claim':claim},'secret-a','actor-a')
        a=self.native._dispatch('/v1/workspace/activity',{'offset':0,'limit':100},'secret-a','actor-a')
        self.assertEqual(a['items'][0]['signal'],'RECENT_HEARTBEAT_UNCONFIRMED')
        self.assertNotIn(claim,json.dumps(a))
        for bad in ({'offset':0,'limit':100,'actor':'actor-b'},{'offset':0}):
            with self.assertRaises(Denied):
                self.native._dispatch('/v1/workspace/activity',bad,'secret-a','actor-a')

    def test_machine_http_activity_accepts_only_post_authenticated_actor(self):
        ident=str(uuid.uuid4())
        self.store.enqueue('actor-a',dict(requestId=ident,service='workspace',
            operation='inspect',target='sandbox',params={'task':None},approvedPreview={}))
        class Base:
            def __init__(self,core):self.broker=SimpleNamespace(core=core)
            @staticmethod
            def _environment(env):return True
            @staticmethod
            def _credential(env):return (env['testCredential'],env['testActor'])
        ingress=NativeIngress(Base(self.core),github=None,workspace=None,
                              store=self.store,actor='actor-a')
        body=json.dumps({'offset':0,'limit':100}).encode()
        def attempt(method='POST',credential='secret-a',actor='actor-a',path='/v1/workspace/activity'):
            env={'PATH_INFO':path,'REQUEST_METHOD':method,
                 'CONTENT_TYPE':'application/json','CONTENT_LENGTH':str(len(body)),
                 'wsgi.input':BytesIO(body),'testCredential':credential,'testActor':actor}
            statuses=[]
            reply=b''.join(ingress(env,lambda status,headers:statuses.append(status)))
            return statuses[0][:3],json.loads(reply)
        self.assertEqual(attempt()[0],'200')
        self.assertEqual(attempt()[1]['items'][0]['requestId'],ident)
        self.assertEqual(attempt(method='GET')[0],'403')
        self.assertEqual(attempt(actor='actor-b')[0],'403')
        self.assertEqual(attempt(credential='secret-b')[0],'403')
        self.assertEqual(attempt(path='/v1/workspace/heartbeat')[0],'403')

    def test_worker_diagnostic_survives_details_without_raw_exception(self):
        ident=self.submit()['requestId']
        self.store.enqueue('actor-a',dict(requestId=ident,service='workspace',
            operation='inspect',target='sandbox',params={'task':None},approvedPreview={}))
        with self.core._db() as db:
            db.execute("UPDATE requests SET state='UNCERTAIN' WHERE id=?",(ident,))
        token=self.store.claim('actor-a',ident)['claim']
        legacy=self.native._dispatch('/v1/workspace/details',
            {'requestId':ident,'eventOffset':0,'eventLimit':100},'secret-a','actor-a')
        self.assertNotIn('diagnostic',legacy['worker'])
        d=evidence('WORKER_EXECUTE','OPERATING_SYSTEM')
        self.native._dispatch('/v1/workspace/finish',
            {'requestId':ident,'claim':token,'result':None,'error':'UNCERTAIN','diagnostic':d},
            'secret-a','actor-a')
        self.assertEqual(json.loads(self.store.job(ident)['diagnostic']),d)
        # Full details is tested separately through IncidentCore; diagnose only
        # consumes safe fields and does not consult or mutate provider state.
        details=self.native._dispatch('/v1/workspace/details',
            {'requestId':ident,'eventOffset':0,'eventLimit':100},'secret-a','actor-a')
        self.assertEqual(details['worker']['diagnostic'],d)
        self.assertEqual(details['diagnostic']['workerError'],d)
        self.assertEqual(details['diagnostic']['rootCause'],'UNDETERMINED')
        self.assertNotIn(token,json.dumps(details))
        with self.assertRaises(Denied):
            self.native._dispatch('/v1/workspace/details',
                {'requestId':ident,'eventOffset':0,'eventLimit':100},'secret-b','actor-a')

    def test_exception_code_clamps_unknown_and_never_calls_str(self):
        class Hostile(Exception):
            def __str__(self):raise AssertionError('exception text may be secret')
        self.assertEqual(category(Hostile()),'INTERNAL_ERROR')
        self.assertEqual(category(ConnectionError('secret')),'CONNECTION')
        self.assertEqual(category(PermissionError('secret')),'PERMISSION')
        with self.assertRaises(ValueError):evidence('WORKER_EXECUTE','secret')


class DurableWorkerJournalTests(unittest.TestCase):
    def test_local_worker_journal_stores_only_bounded_code_after_dispatch(self):
        tmp=tempfile.TemporaryDirectory(prefix='journal-typed-code-')
        self.addCleanup(tmp.cleanup)
        root=Path(tmp.name)/'Repos'/'sandbox'
        root.mkdir(parents=True)
        def git(*args):
            result=subprocess.run(['git',*args],cwd=root,capture_output=True,
                                  text=True,check=False)
            if result.returncode:raise AssertionError(result.stderr)
        git('init','-b','main')
        git('remote','add','origin','https://github.com/PilotOwner/sandbox.git')
        (root/'README.md').write_text('snapshot\n')
        git('add','README.md')
        git('-c','user.name=Offline', '-c','user.email=offline@example.invalid',
            'commit','-m','baseline')
        worktrees=Path(tmp.name)/'Worktrees'/'sandbox'
        worktrees.mkdir(parents=True)
        worker=Worker(owner='PilotOwner',repositories={'sandbox':root},
                      worktrees={'sandbox':worktrees},gateway=Mock())
        ident=str(uuid.uuid4())
        payload=dict(requestId=ident,operation='inspect',target='sandbox',
                     service='workspace',params={'task':None})
        job={'payload':payload,'approvedPreview':{}}
        with patch.object(worker,'_prepare',return_value={}), \
             patch.object(worker,'_execute',side_effect=TimeoutError('SECRET-DO-NOT-STORE')) as effect:
            result,error=worker.execute(job)
            self.assertEqual((result,error),(None,'UNCERTAIN'))
            self.assertEqual(worker.failure_code(job),'TIMEOUT')
            # Re-entering a previously dispatched UUID cannot repeat a worktree effect.
            self.assertEqual(worker.execute(job),(None,'UNCERTAIN'))
            effect.assert_called_once()
        journal=root/'.git'/'fortis-workflow-worker'/'receipts.sqlite'
        with sqlite3.connect(journal) as db:
            row=db.execute('SELECT state,error,result FROM journal WHERE id=?',(ident,)).fetchone()
        self.assertEqual(row,('FAILED','UNCERTAIN:TIMEOUT',None))
        self.assertNotIn('SECRET-DO-NOT-STORE',journal.read_bytes().decode('latin-1'))


class ClientTelemetryTests(unittest.TestCase):
    def test_worker_exception_sends_bounded_code_but_no_private_text(self):
        ident=str(uuid.uuid4());claim=str(uuid.uuid4())
        calls=[]
        class Gateway:
            def post(self,path,body,**kwargs):
                calls.append((path,body.copy()))
                return {'observed':True}
        worker=Mock()
        worker.execute.side_effect=OSError('PRIVATE-ERROR-DO-NOT-STORE')
        c=WorkflowClient(gateway=Gateway(),worker=worker,worker_observability=True)
        c._finish_claim(ident,{'claim':claim,'payload':{'requestId':ident}})
        finishes=[data for path,data in calls if path.endswith('/finish')]
        self.assertEqual(len(finishes),1)
        self.assertEqual(finishes[0]['diagnostic'],evidence('WORKER_CLIENT','OPERATING_SYSTEM'))
        self.assertEqual(finishes[0]['error'],'UNCERTAIN')
        self.assertNotIn('PRIVATE-ERROR-DO-NOT-STORE',json.dumps(finishes))
        self.assertTrue(any(p.endswith('/heartbeat') for p,_ in calls))

    def test_older_gateway_does_not_receive_new_heartbeat_or_finish_fields(self):
        ident=str(uuid.uuid4());claim=str(uuid.uuid4())
        sent=[]
        class OldGateway:
            def post(self,path,body,**kwargs):
                sent.append((path,body.copy()))
                if path=='/v1/workspace/finish':
                    assert set(body)=={'requestId','claim','result','error'}
                    return {'recorded':True}
                raise AssertionError('UNSUPPORTED_OLD_ENDPOINT:'+path)
        worker=Mock();worker.execute.side_effect=RuntimeError('PRIVATE_OLD_GATEWAY_ERROR')
        flow=WorkflowClient(gateway=OldGateway(),worker=worker)
        with self.assertRaises(Denied):flow.activity()
        flow._finish_claim(ident,{'claim':claim,'payload':{'requestId':ident}})
        self.assertEqual([path for path,body in sent],['/v1/workspace/finish'])
        self.assertEqual(sent[0][1]['error'],'UNCERTAIN')

    def test_client_activity_calls_only_read_route(self):
        ident=[]
        class G:
            def post(self,path,body):
                ident.append((path,body));return {'total':0}
        result=WorkflowClient(gateway=G(),worker=Mock(),worker_observability=True).activity(offset=4,limit=9)
        self.assertEqual(result,{'total':0})
        self.assertEqual(ident,[('/v1/workspace/activity',{'offset':4,'limit':9})])


if __name__=='__main__':unittest.main()

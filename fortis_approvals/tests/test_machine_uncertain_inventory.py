"""Authenticated UNCERTAIN inventory and non-invasive incident phase triage."""
from io import BytesIO
import json
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
import uuid

from fortis_approvals.core import Authenticator, Denied
from fortis_approvals.incidents import IncidentCore
from fortis_approvals.synthetic import SyntheticAdapter
from fortis_approvals.workflow.client import WorkflowClient
from fortis_approvals.workflow.ingress import NativeIngress, NATIVE_PATHS
from fortis_approvals.workflow.incident_read import diagnose, list_uncertain, list_requests


class InventoryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        base = Path(self.tmp.name)
        self.adapter = SyntheticAdapter(base/'synthetic.sqlite')
        self.adapter.seed('R3','before')
        self.core = IncidentCore(
            base/'approvals.sqlite', adapters={'synthetic':self.adapter},
            policies={('synthetic','set_ask'):'ASK'},
            authenticator=Authenticator({'secret-a':'agent-a','secret-b':'agent-b'}))
        self.native = NativeIngress(
            SimpleNamespace(broker=SimpleNamespace(core=self.core)),
            github=None, workspace=None, store=None, actor='agent-a')

    def submit(self, actor='agent-a'):
        return self.core.submit(actor,{
            'requestId':str(uuid.uuid4()),'service':'synthetic',
            'operation':'set_ask','target':'R3','params':{'value':'private'},
            'expectedVersion':0,'reason':'sensitive-reason-not-in-list'})

    def uncertain(self, actor='agent-a'):
        row = self.submit(actor)
        with self.core._db() as db:
            db.execute("UPDATE requests SET state='UNCERTAIN',failure=? WHERE id=?",
                       ('REMOTE_OUTCOME_UNCONFIRMED',row['requestId']))
            self.core._event(db,row['requestId'],'DISPATCHED')
            self.core._event(db,row['requestId'],'UNCERTAIN')
        return row['requestId']

    def test_actor_scoped_inventory_is_paginated_minimal_and_read_only(self):
        own = [self.uncertain() for _ in range(3)]
        other = self.uncertain('agent-b')
        pending = self.submit()['requestId']
        closed = self.uncertain()
        with self.core._db() as db:
            db.execute("UPDATE requests SET state='CLOSED_UNCONFIRMED' WHERE id=?",
                       (closed,))
        self.assertIn('/v1/workspace/list_uncertain',NATIVE_PATHS)
        first = self.native._dispatch('/v1/workspace/list_uncertain',
                                      {'offset':0,'limit':2},'secret-a','agent-a')
        second = self.native._dispatch('/v1/workspace/list_uncertain',
                                       {'offset':2,'limit':2},'secret-a','agent-a')
        ids = [r['requestId'] for r in first['items']+second['items']]
        self.assertEqual(set(ids),set(own))
        self.assertEqual(first['total'],3)
        self.assertTrue(first['truncated'])
        self.assertEqual(first['nextOffset'],2)
        self.assertEqual(second['nextOffset'],None)
        self.assertFalse(second['truncated'])
        self.assertEqual(len(ids),len(set(ids)))
        self.assertNotIn(other,ids)
        self.assertNotIn(pending,ids)
        self.assertNotIn(closed,ids)
        self.assertEqual(first['items'][0]['state'],'UNCERTAIN')
        text = json.dumps(first)
        self.assertNotIn('sensitive-reason-not-in-list',text)
        self.assertNotIn('private',text)
        self.assertNotIn('fingerprint',text)
        self.assertEqual(self.core._read(own[0])['state'],'UNCERTAIN')
        self.assertEqual(self.core._read(other)['state'],'UNCERTAIN')
        self.assertEqual(self.core._read(closed)['state'],'CLOSED_UNCONFIRMED')

    def test_foreign_full_details_excludes_worker_claim_token(self):
        foreign=self.submit('agent-b')['requestId']
        claim='SENSITIVE-WORKER-CLAIM-NEVER-TO-EXPOSE'
        self.adapter.store=SimpleNamespace(job=lambda request_id: {
            'actor':'agent-b', 'state':'CLAIMED', 'claim':claim,
            'result':None, 'error':None, 'diagnostic':None,
            'claimed_at':1700000000,'heartbeat_at':1700000010})
        before=self.core._read(foreign)
        full=self.core.machine_request_details('secret-a',foreign)
        self.assertTrue(full['worker']['hasClaim'])
        self.assertEqual(full['worker']['state'],'CLAIMED')
        self.assertEqual(full['worker']['claimedAt'],1700000000)
        self.assertEqual(full['worker']['lastHeartbeatAt'],1700000010)
        self.assertNotIn('claim',full['worker'])
        self.assertNotIn(claim,json.dumps(full))
        self.assertIsNone(full['receipt'])
        self.assertEqual(self.core._read(foreign),before)

    def test_global_readonly_inventory_sees_every_actor_and_archived_history(self):
        a=self.submit('agent-a')['requestId']
        b=self.submit('agent-b')['requestId']
        closed=self.uncertain('agent-b')
        with self.core._db() as db:
            db.execute("UPDATE requests SET state='APPROVED' WHERE id=?",(b,))
            db.execute("UPDATE requests SET state='CLOSED_UNCONFIRMED' WHERE id=?",
                       (closed,))
        self.assertIn('/v1/workspace/list_requests',NATIVE_PATHS)
        first=self.native._dispatch('/v1/workspace/list_requests',
            {'offset':0,'limit':1,'unresolvedOnly':True},'secret-a','agent-a')
        second=self.native._dispatch('/v1/workspace/list_requests',
            {'offset':1,'limit':1,'unresolvedOnly':True},'secret-a','agent-a')
        self.assertEqual(first['total'],2)
        self.assertTrue(first['readOnly'])
        self.assertFalse(first['actorScoped'])
        self.assertEqual(first['stateCounts'],{'PENDING':1,'APPROVED':1})
        self.assertEqual({x['requestId'] for x in first['items']+second['items']},
                         {a,b})
        self.assertEqual({x['actor'] for x in first['items']+second['items']},
                         {'agent-a','agent-b'})
        from_other=list_requests(self.core,'secret-b',limit=100,unresolved_only=False)
        self.assertEqual(from_other['total'],3)
        self.assertIn(closed,[x['requestId'] for x in from_other['items']])
        exposed=json.dumps(from_other)
        for secret in ('private','sensitive-reason-not-in-list','fingerprint',
                       'snapshot','params','preview','claim','decision','owner'):
            self.assertNotIn('"'+secret+'"',exposed)
        self.assertEqual(self.core._read(b)['state'],'APPROVED')
        self.assertEqual(self.core._read(closed)['state'],'CLOSED_UNCONFIRMED')
        self.assertEqual(self.core._read(a)['state'],'PENDING')

    def test_global_details_reads_foreign_request_without_action_or_claim(self):
        foreign=self.submit('agent-b')['requestId']
        self.assertIn(foreign,[i['requestId'] for i in
                      list_requests(self.core,'secret-a')['items']])
        original=self.core._read(foreign)
        original_events=len(self.core.events(foreign))
        full=self.native._dispatch('/v1/workspace/details',
            {'requestId':foreign,'eventOffset':0,'eventLimit':100},
            'secret-a','agent-a')
        self.assertEqual(full['request'],original)
        self.assertEqual(full['request']['actor'],'agent-b')
        self.assertEqual(full['request']['request']['params']['value'],'private')
        self.assertEqual(full['request']['preview'],original['preview'])
        self.assertEqual(full['eventTotal'],original_events)
        self.assertIsNone(full['worker'])
        self.assertIsNone(full['receipt'])
        self.assertEqual(len(self.core.events(foreign)),original_events)
        self.assertEqual(self.core._read(foreign),original)
        # Old status/decision/effect policy still limits the caller.
        with self.assertRaises(Denied):
            self.core.client('secret-a','status',foreign)
        response=self.native._dispatch('/v1/workspace/result',
            {'requestId':foreign},'secret-a','agent-a')
        self.assertEqual(response['state'],'NOT_FOUND')
        with self.assertRaises(Denied):
            list_requests(self.core,'invalid')
        for opts in ({'offset':-1},{'offset':True},{'limit':101},
                     {'limit':0},{'unresolved_only':'yes'},
                     {'unresolved_only':0}):
            with self.subTest(opts=opts),self.assertRaises(Denied):
                list_requests(self.core,'secret-a',**opts)
        for wrong in ({'offset':0,'limit':5},
                      {'offset':0,'limit':5,'unresolvedOnly':True,'actor':'agent-b'},
                      {'offset':0,'limit':5,'unresolvedOnly':True,'includePayload':True}):
            with self.assertRaises(Denied):
                self.native._dispatch('/v1/workspace/list_requests',
                                       wrong,'secret-a','agent-a')
        with self.assertRaises(Denied):
            self.native._dispatch('/v1/workspace/list_requests',
                {'offset':0,'limit':5,'unresolvedOnly':True},'secret-b','agent-a')

    def test_page_beyond_100_and_complete_quiescent_inventory(self):
        own=[self.uncertain() for _ in range(104)]
        first=list_uncertain(self.core,'secret-a',limit=100)
        second=list_uncertain(self.core,'secret-a',offset=100,limit=100)
        self.assertEqual((len(first['items']),len(second['items'])),(100,4))
        self.assertEqual(first['total'],second['total'])
        self.assertTrue(first['truncated'])
        self.assertEqual(first['nextOffset'],100)
        self.assertIsNone(second['nextOffset'])
        self.assertEqual(
            set(x['requestId'] for x in first['items']+second['items']),
            set(own))

    def test_bad_auth_actor_isolation_and_invalid_pagination(self):
        uid=self.uncertain()
        self.assertEqual(
            list_uncertain(self.core,'secret-b')['items'],[])
        with self.assertRaises(Denied):
            list_uncertain(self.core,'wrong-token')
        self.assertEqual(
            self.core.machine_request_details('secret-b',uid)['request']['requestId'],
            uid)
        with self.assertRaises(Denied):
            self.core.machine_request_details('wrong-token',uid)
        with self.assertRaises(Denied):
            self.core.machine_request_details('secret-a','not-a-uuid')
        for opts in ({'offset':-1},{'offset':True},{'offset':1000001},
                     {'limit':0},{'limit':False},{'limit':101},
                     {'limit':'1'}):
            with self.subTest(opts=opts),self.assertRaises(Denied):
                list_uncertain(self.core,'secret-a',**opts)
        for wrong in ({'offset':0}, {'offset':0,'limit':5,'actor':'agent-b'},
                      {'offset':0,'limit':5,'state':'EXECUTED'}):
            with self.assertRaises(Denied):
                self.native._dispatch('/v1/workspace/list_uncertain',
                                      wrong,'secret-a','agent-a')

    def test_machine_http_post_and_existing_actor_guard(self):
        self.uncertain()
        class Base:
            def __init__(self,core): self.broker=SimpleNamespace(core=core)
            @staticmethod
            def _environment(env): return True
            @staticmethod
            def _credential(env): return ('secret-a',env.get('testActor','agent-a'))
        native=NativeIngress(Base(self.core),github=None,workspace=None,store=None,actor='agent-a')
        body=json.dumps({'offset':0,'limit':5}).encode()
        def run(method='POST',actor='agent-a'):
            env={'PATH_INFO':'/v1/workspace/list_uncertain',
                 'REQUEST_METHOD':method,'CONTENT_TYPE':'application/json',
                 'CONTENT_LENGTH':str(len(body)),'wsgi.input':BytesIO(body),
                 'testActor':actor}
            reported=[]
            raw=b''.join(native(env,lambda status,headers:reported.append(status)))
            return reported[0],json.loads(raw)
        code,result=run()
        self.assertEqual(code[:3],'200')
        self.assertEqual(result['total'],1)
        self.assertEqual(run(actor='agent-b')[0][:3],'403')
        self.assertEqual(run(method='GET')[0][:3],'403')

    def test_other_ai_machine_actor_can_read_but_not_mutate(self):
        uid=self.uncertain('agent-b')
        class Base:
            def __init__(self,core): self.broker=SimpleNamespace(core=core)
            @staticmethod
            def _environment(env): return True
            @staticmethod
            def _credential(env): return ('secret-b','agent-b')
        native=NativeIngress(Base(self.core),github=None,workspace=None,
                             store=None,actor='agent-a')
        def run(path,body):
            encoded=json.dumps(body).encode()
            env={'PATH_INFO':path,'REQUEST_METHOD':'POST',
                 'CONTENT_TYPE':'application/json','CONTENT_LENGTH':str(len(encoded)),
                 'wsgi.input':BytesIO(encoded)}
            statuses=[]
            raw=b''.join(native(env,lambda status,headers:statuses.append(status)))
            return statuses[0][:3],json.loads(raw)
        status,inventory=run('/v1/workspace/list_requests',
            {'offset':0,'limit':100,'unresolvedOnly':True})
        self.assertEqual(status,'200')
        self.assertIn(uid,[r['requestId'] for r in inventory['items']])
        status,full=run('/v1/workspace/details',
            {'requestId':uid,'eventOffset':0,'eventLimit':100})
        self.assertEqual(status,'200')
        self.assertEqual(full['request']['requestId'],uid)
        self.assertIsNotNone(full['diagnostic'])
        status,_=run('/v1/workspace/activity',{'offset':0,'limit':5})
        self.assertEqual(status,'403')
        status,_=run('/v1/workspace/result',{'requestId':uid})
        self.assertEqual(status,'403')

    def test_safe_phase_diagnosis_from_existing_evidence(self):
        uid=self.uncertain()
        details=self.core.machine_request_details('secret-a',uid)
        details['request']['request']['service']='workspace'
        self.assertEqual(diagnose(details)['phase'],'WORKSPACE_JOB_NOT_FOUND')
        self.assertEqual(diagnose(details)['originalEffect'],'UNCONFIRMED')
        self.assertEqual(diagnose(details)['rootCause'],'UNDETERMINED')
        self.assertEqual(diagnose(details)['dispatchToUncertainSeconds'],0)
        details['worker']={'state':'FAILED','actor':'agent-a',
                           'error':'UNCERTAIN','hasClaim':True,'result':None}
        self.assertEqual(diagnose(details)['phase'],'WORKER_FAILED_NO_RECEIPT')
        details['worker']['state']='CLAIMED'
        self.assertEqual(diagnose(details)['phase'],'WORKER_CLAIMED_NO_FINISH')
        details['worker']=None
        details['request']['request']['service']='github'
        self.assertEqual(diagnose(details)['phase'],'GITHUB_RECEIPT_NOT_FOUND')
        details['receipt']={'source':'signed','result':{'requestId':uid}}
        self.assertEqual(diagnose(details)['phase'],'RECEIPT_PRESENT_REVIEW_CORE_STATE')
        self.assertNotIn('claim',json.dumps(diagnose(details)).lower())
        self.assertEqual(self.core._read(uid)['state'],'UNCERTAIN')
        details['request']['state']='EXECUTED'
        self.assertIsNone(diagnose(details))

    def test_capabilities_advertise_exact_support(self):
        gh=SimpleNamespace(config=SimpleNamespace(
            owner='example',repository='sandbox',dynamic_repositories=False,
            ci_control_repositories=()))
        native=NativeIngress(
            SimpleNamespace(broker=SimpleNamespace(core=self.core)),
            github=gh,workspace=None,store=None,actor='agent-a')
        capabilities=native._dispatch('/v1/workspace/capabilities',{},
                                      'secret-a','agent-a')
        self.assertEqual(capabilities['incidentInventory'],{
            'readOnly':True,'actorScoped':True,'maxPageSize':100,
            'diagnostic':'evidence-stage-v1'})
        self.assertEqual(capabilities['globalRequestInventory'],{
            'readOnly':True,'actorScoped':False,'maxPageSize':100,
            'metadataOnly':True,'supportsHistory':True,
            'crossActorDetails':True})

    def test_native_details_adds_read_only_diagnostic(self):
        uid=self.uncertain()
        before=len(self.core.events(uid))
        d=self.native._dispatch('/v1/workspace/details',
                               {'requestId':uid,'eventOffset':0,'eventLimit':100},
                               'secret-a','agent-a')
        self.assertIn('diagnostic',d)
        self.assertEqual(d['diagnostic']['rootCause'],'UNDETERMINED')
        self.assertEqual(len(self.core.events(uid)),before)

    def test_client_calls_only_closed_machine_route(self):
        class Capture:
            def post(self,path,body):
                self.called=(path,body)
                return {'schemaVersion':1,'items':[], 'total':0}
        fake=Capture()
        client=WorkflowClient.__new__(WorkflowClient)
        client.gateway=fake
        result=client.list_uncertain(offset=2,limit=7)
        self.assertEqual(fake.called,('/v1/workspace/list_uncertain',
                                      {'offset':2,'limit':7}))
        self.assertEqual(result['total'],0)
        global_result=client.list_requests(offset=1,limit=4,unresolved_only=False)
        self.assertEqual(fake.called,('/v1/workspace/list_requests',
            {'offset':1,'limit':4,'unresolvedOnly':False}))
        self.assertEqual(global_result['total'],0)


if __name__=='__main__':
    unittest.main()

"""Actual local Core/Registry and existing WSGI boundaries; no live grants."""
import copy
import unittest
from io import BytesIO
from unittest.mock import patch
from fortis_approvals.core import Authenticator, Denied
from fortis_approvals.extensions.semantic_access import SemanticAccess,SemanticRepoBroker,READ,WRITE
from fortis_approvals.extensions.semantic_owner_portal import SemanticOwnerPortal,PREFIX
from fortis_approvals.extensions.registry_single_binding import RegistrySingleAdapter
from fortis_approvals.extensions.maintenance_transport import MaintenanceRegistryTransport
from fortis_approvals.extensions.maintenance_gate import MaintenanceGate
from fortis_approvals.extensions.maintenance_core import MaintenanceCoreMixin
from fortis_approvals.extensions.composite_executor import CompositeCoreMixin,GroupAdapter,Admission
from fortis_approvals.extensions.registry_group_binding import RegistryGroupBinding
from fortis_approvals.extensions.merge_register import MergeRegisterAdapter,MergeRegisterBinding
from fortis_approvals.extensions import composite_journal as journal
from fortis_approvals.extensions.owner_policy_engine_v2 import UnifiedPolicyCore
from fortis_approvals.read_approval import install_owner_read_approval
from fortis_approvals.repo_action_contract import RepoIntentBroker
from fortis_approvals.repo_ingress import RepoIngress
from fortis_approvals.owner_portal import OwnerPortal
from fortis_approvals.synthetic import SyntheticAdapter
from fortis_approvals.integrations.registry_contracts import semantic_contract as sc
from fortis_approvals.tests import test_registry_source_lineage as fixture
from fortis_approvals.tests import test_maintenance_gate as maintenance
from fortis_approvals.tests.test_core import SyntheticOwnerVerifier
from fortis_approvals.tests.test_merge_register import FakeProvider
from fortis_approvals.tests.test_registry_state_journal import uid


class Owner(SyntheticOwnerVerifier):
    origin='http://localhost:18990'
    def session(self,token,csrf=None):
        if token!='owner-session' or csrf not in (None,'csrf'):
            raise Denied('OWNER_SESSION_REQUIRED')
        return {'owner':'owner','csrf':'csrf'}


class LocalCore(MaintenanceCoreMixin,CompositeCoreMixin,UnifiedPolicyCore):
    pass


class SemanticAccessTests(fixture.LineageFixture,unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.domain.register_source(self.transition())
        self.service.authorize=lambda a,op,s:a in ('agent-1','owner-actor') and s.get('targetId')!='hidden'
        self.ctrl=maintenance.Controller(self.instance,self.witness['scopeDigest'])
        self.gate=MaintenanceGate(instance_id=self.instance,scope_digest=self.witness['scopeDigest'],
                generation=maintenance.OLD,read_interlock=self.ctrl.read,read_holds=self.domain.maintenance_snapshot)
        self.ready=True
        self.hidden=set()
        self.auth=Authenticator({'machine-secret':'agent-1','owner-fixture-secret':'owner-actor',
                                 'other-secret':'other'})
        self.owner=Owner()
        self.transport=MaintenanceRegistryTransport(self.service,self.gate,preflight=lambda *_:True)
        self.single=RegistrySingleAdapter(self.transport,authorize=lambda a,p:a in ('agent-1','owner-actor'),
                provenance=lambda a:'OWNER_DIRECT' if a=='owner-actor' else 'OWNER_TRANSCRIBED',
                profile_reader=lambda:self.domain.snapshot()['profileDigest'])
        self.group=RegistryGroupBinding(transport=self.transport,admission=lambda *_:Admission('ASK',True,'ALLOW','a'*64),
                 provenance=lambda a:'OWNER_DIRECT' if a=='owner-actor' else 'OWNER_TRANSCRIBED',
                 profile_digest=sc.digest(self.successor))
        self.adapter=GroupAdapter(binding=self.group,ordinary=self.single)
        self.provider=FakeProvider()
        self.mergebinding=MergeRegisterBinding(provider=self.provider,registry=self.domain,
             admission=lambda a,t,s:Admission('ASK',True,'ASK' if s['ordinal']==0 else 'ALLOW','a'*64),
             effect_guard=lambda _:True)
        self.mergeadapter=MergeRegisterAdapter(binding=self.mergebinding)
        policies={(a,s,o,'scope'):('ASK' if (s,o) in WRITE else 'ALLOW')
                  for a in ('agent-1','owner-actor') for s,o in READ|WRITE}
        for a in ('agent-1','owner-actor'):
            policies[(a,'registry','report_release_result','scope')]='ALLOW'
            policies[(a,'registry','get_component','scope')]='ASK'
            policies[(a,'github','list_pull_requests','fortis-approvals')]='ALLOW'
        self.core=LocalCore(self.root/'core.sqlite',adapters={'registry':self.adapter,'release':self.mergeadapter,
              'github':SyntheticAdapter(self.root/'github-fixture.sqlite')},policies=policies,authenticator=self.auth,owner_verifier=self.owner,clock=lambda:100)
        self.core.bind_maintenance(self.gate)
        self.adapter.core=self.single.core=self.mergeadapter.core=self.core
        self.group.adapter=self.adapter;self.mergebinding.adapter=self.mergeadapter
        with self.core._db() as db:
            db.execute('BEGIN IMMEDIATE');journal.install_schema(db)
        self.core.install_policy_authority({k:{'ALLOW','ASK','DENY'} for k in policies})
        self.base=RepoIntentBroker(self.core,actor_operations={})
        self.portal=OwnerPortal(self.core,self.owner)
        self.approval=install_owner_read_approval(self.core,self.base,self.portal)
        self.access=SemanticAccess(self.core,self.transport,self.gate,grant=self.grant,
                  owner_actor=lambda name:'owner-actor' if name=='owner' else None,ready=lambda *_:self.ready)
        self.access.bind_existing_read_approval(self.approval)
        self.broker=SemanticRepoBroker(self.base,self.access)
        self.ingress=RepoIngress(self.broker,host='localhost:18992',allow_http_local_test=True,max_bytes=32768)
        self.pr=self.merge()['proposal']
        self.ownerportal=SemanticOwnerPortal(self.portal,self.access,repository=self.scope['repository'],
                        target='scope',discovery=lambda *_:[copy.deepcopy(self.pr)])

    def grant(self,a,s,o,t,subject):
        return a in ('agent-1','owner-actor') and t==('fortis-approvals' if s=='github' else 'scope') and subject['repository']==self.scope['repository'] and subject.get('targetId') not in self.hidden

    def query(self,op='list_components',params=None,service='registry'):
        return {'requestId':uid(),'service':service,'operation':op,'target':'scope','reason':'fixture',
                'params':params if params is not None else {'repository':self.scope['repository'],'page':{'limit':10,'cursor':None}}}

    def http(self,path,data,*,owner=False,extra=None):
        raw=sc.canonical(data).encode()
        env={'HTTP_HOST':'localhost:18990' if owner else 'localhost:18992',
             'REQUEST_METHOD':'POST','PATH_INFO':path,'QUERY_STRING':'','REMOTE_ADDR':'127.0.0.1',
             'wsgi.url_scheme':'http','wsgi.input':BytesIO(raw),'CONTENT_TYPE':'application/json',
             'CONTENT_LENGTH':str(len(raw))}
        if owner:env.update(HTTP_ORIGIN=self.owner.origin,HTTP_COOKIE='fortis_owner=owner-session',HTTP_X_FORTIS_CSRF='csrf')
        else:env['HTTP_AUTHORIZATION']='Bearer machine-secret'
        env.update(extra or {})
        codes=[]
        result=b''.join((self.ownerportal if owner else self.ingress)(env,lambda status,h:codes.append(int(status[:3]))))
        return codes[0],sc.loads_strict(result)

    def test_passive_read_machine_owner_same_registry_no_core_rows(self):
        q=self.query()
        before=self.core.owner_list()
        a=self.http('/v1/reads',q)
        b=self.http(PREFIX+'/read',q,owner=True)
        self.assertEqual(a[0],200);self.assertEqual(b[0],200)
        self.assertEqual(a[1]['data'],b[1]['data'])
        self.assertEqual(before,self.core.owner_list())
        self.assertEqual(self.core.owner_list(pending=False),[])

    def test_wrong_scope_wrong_route_and_csrf(self):
        q=self.query()
        self.assertEqual(self.http('/v1/actions',q)[0],403)
        self.assertEqual(self.http(PREFIX+'/read',q,owner=True,extra={'HTTP_X_FORTIS_CSRF':'bad'})[0],403)
        self.assertEqual(self.http('/v1/reads',{**q,'target':'other'})[0],403)
        self.assertEqual(self.http('/v1/reads',q,extra={'HTTP_AUTHORIZATION':'Bearer other-secret'})[0],403)
        self.assertEqual(self.http('/v1/reads',{**q,'actor':'owner-actor'})[0],403)
        self.assertEqual(self.core.owner_list(),[])

    def test_one_shot_read_ask_both_actor_types_and_original_uuid(self):
        for owner in (False,True):
            q=self.query('get_component',{'subject':self.subjects[0]})
            path=PREFIX+'/read' if owner else '/v1/reads'
            status,out=self.http(path,q,owner=owner)
            self.assertEqual(out['state'],'PENDING')
            self.assertNotIn('data',out)
            row=self.core._read(q['requestId'])
            self.assertEqual(row['actor'],'owner-actor' if owner else 'agent-1')
            self.core.owner_decide(q['requestId'],'approve',self.owner.proof(q['requestId'],row['fingerprint'],'approve'))
            status,out=self.http(path,q,owner=owner)
            self.assertEqual(status,200)
            self.assertEqual(out['data']['data']['subject'],self.subjects[0])
            self.assertEqual(self.http(path,q,owner=owner)[0],403)

    def test_owner_and_machine_write_provenance(self):
        q=self.query('report_release_result',self.report())
        status,result=self.http(PREFIX+'/submit',q,owner=True)
        self.assertEqual((status,result['state']),(200,'EXECUTED'))
        self.assertEqual(self.component()['ownerReported']['assertionSource'],'OWNER_DIRECT')
        q=self.query('report_release_result',self.report())
        status,result=self.http('/v1/actions',q)
        self.assertEqual((status,result['state']),(200,'EXECUTED'))
        self.assertEqual(self.component()['ownerReported']['assertionSource'],'OWNER_TRANSCRIBED')

    def test_begin_ask_same_core_no_effect_before_owner(self):
        q=self.query('begin_release',self.params())
        status,result=self.http('/v1/actions',q)
        self.assertEqual((status,result['state']),(202,'PENDING'))
        self.assertIsNone(self.component()['activeAttempt'])
        row=self.core._read(q['requestId'])
        out=self.core.owner_decide(q['requestId'],'approve',self.owner.proof(q['requestId'],row['fingerprint'],'approve'))
        self.assertEqual(out['state'],'EXECUTED')
        self.assertEqual(self.component()['activeAttempt']['attemptId'],q['requestId'])

    def test_discovery_dedup_terminal_rejection_no_auto_reproposal(self):
        status,first=self.http(PREFIX+'/discover',{},owner=True)
        self.assertEqual(status,200)
        self.assertEqual(first[0]['state'],'PENDING')
        status,second=self.http(PREFIX+'/discover',{},owner=True)
        self.assertEqual(first,second)
        row=self.core._read(first[0]['requestId'])
        self.core.owner_decide(row['requestId'],'reject',self.owner.proof(row['requestId'],row['fingerprint'],'reject'))
        status,third=self.http(PREFIX+'/discover',{},owner=True)
        self.assertEqual(third[0]['state'],'REJECTED')
        self.assertEqual(self.provider.calls,0)
        self.assertEqual(len(self.core.owner_list(pending=False)),1)

    def test_refresh_settles_changed_head_pending_without_touching_approval(self):
        status,first=self.http(PREFIX+'/discover',{},owner=True)
        self.assertEqual((status,first[0]['state']),(200,'PENDING'))
        original=first[0]['requestId']
        self.pr={**self.pr,'headSha':'d'*40}
        status,second=self.http(PREFIX+'/discover',{},owner=True)
        self.assertEqual((status,second[0]['state']),(200,'PENDING'))
        self.assertNotEqual(second[0]['requestId'],original)
        self.assertEqual(self.core._read(original)['state'],'STALE')
        self.assertEqual(self.provider.calls,0)

    def test_pending_duplicate_and_unknown_incident_overlay(self):
        q=self.query('begin_release',self.params())
        status,first=self.http('/v1/actions',q)
        self.assertEqual(status,202)
        status,second=self.http('/v1/actions',{**q,'requestId':uid(),'reason':'another refresh'})
        self.assertEqual(first,second)
        self.assertEqual(len(self.core.owner_list()),1)
        # Simulated lost acknowledgement after Core's actual dispatch;
        # no synthetic Registry hold/receipt is created.
        with patch.object(self.transport,'owner_write',side_effect=RuntimeError('lost ack')):
            row=self.core._read(q['requestId'])
            self.assertEqual(self.core.owner_decide(q['requestId'],'approve',
                self.owner.proof(q['requestId'],row['fingerprint'],'approve'))['state'],'UNCERTAIN')
        status,result=self.http('/v1/reads',self.query())
        self.assertEqual(status,200)
        row=next(r for r in result['data']['data']['items'] if r['subject']==self.subjects[0])
        self.assertEqual(row['planningState'],'UNKNOWN')
        self.assertEqual(row['incidentStatus'],'UNRESOLVED_RESULT')
        self.assertEqual(self.http('/v1/actions',self.query('report_release_result',self.report()))[0],403)
        self.assertIsNone(self.component()['activeAttempt'])

    def test_unavailable_or_scope_revoked_during_read_no_data(self):
        q=self.query()
        self.ready=False
        self.assertEqual(self.http('/v1/reads',q)[0],403)
        self.ready=True
        real=self.transport.read
        def changed(*args):
            out=real(*args);self.ready=False;return out
        with patch.object(self.transport,'read',side_effect=changed):
            status,out=self.http('/v1/reads',q)
        self.assertEqual(status,403);self.assertNotIn('data',out)

    def test_freeze_blocks_mutation_preserves_passive_read(self):
        self.ctrl.available=False
        self.assertEqual(self.http('/v1/reads',self.query())[0],403)
        self.assertEqual(self.http('/v1/actions',self.query('begin_release',self.params()))[0],403)
        self.assertEqual(self.core.owner_list(),[])


if __name__=='__main__':unittest.main()

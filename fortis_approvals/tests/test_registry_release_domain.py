"""Registry-local semantic and planner acceptance on isolated v3->v4 copies."""
import copy
import unittest
from unittest.mock import patch

from fortis_approvals.core import Denied, Stale
from fortis_approvals.integrations.registry_contracts import semantic_contract as sc
from fortis_approvals.registry.release_domain import ReleaseDomain, key
from fortis_approvals.registry.release_event_journal import ReleaseEventJournal
from fortis_approvals.registry.semantic_service import SemanticRegistry
from fortis_approvals.registry.release_planner import plan
from fortis_approvals.registry import state_journal as old
from fortis_approvals.tests import test_registry_transition_contract as fixture
from fortis_approvals.tests.test_registry_state_journal import uid


def maintenance(required=False, freeze=False):
    return {'beginRequired':required,'stateFreeze':freeze,
            'blockedOperations':[{'service':'registry','operation':'begin_release'}] if required else [],
            'notes':['review']}


class DomainTests(unittest.TestCase):
    append=fixture.LegacyPrefixTests.append
    clone=fixture.LegacyPrefixTests.clone

    def setUp(self):
        fixture.LegacyPrefixTests.setUp(self)
        obs=self.evidence['plan']['observation']
        row=obs['recordCandidates'][0]
        row['requiredActions']=['config-deploy','migration-required']
        other=copy.deepcopy(row)
        other['identity']['targetId']='other'
        other['subjectId']=old._hash({k:other['identity'][k] for k in ('repository','targetId','environment')})
        other['recordId']=old._hash(other['identity'])
        other['resourceIds']=['other-state']
        other['componentId']='other-runtime'
        obs['recordCandidates'].append(other)
        self.evidence['plan']['observationDigest']=old._hash(obs)
        self.append()
        self.witness=fixture.legacy_prefix_witness(self.state)
        self.copy=self.clone()
        self.store=ReleaseEventJournal.migrate_clone(self.copy,expected_legacy=self.witness,
                                                    transition_digest='e'*64)
        self.subjects=[{k:r['identity'][k] for k in ('repository','targetId','environment')}
                       for r in obs['recordCandidates']]
        self.profile={'schemaVersion':1,'repository':self.scope['repository'],
                      'catalogSha256':self.scope['catalogSha256'],'subjects':[
            {'subject':s,'componentId':r['componentId'],'resources':r['resourceIds'],'dependencies':[],
             'unresolvedDependencies':[],'deployable':True,
             'maintenance':maintenance(i==0),'procedure':r['deploymentProcedure'],
             'verification':sorted(r['verification']),'build':None}
            for i,(s,r) in enumerate(zip(self.subjects,obs['recordCandidates']))]}
        self.verify=False
        self.hidden=set()
        self.rebind()

    def rebind(self):
        self.domain=ReleaseDomain(self.store,self.profile,expected_profile_digest=sc.digest(self.profile),
                                  protected_verify=lambda r:self.verify)
        self.service=SemanticRegistry(self.domain,authorize=lambda a,op,s:
            a=='agent-1' and s['repository']==self.scope['repository']
            and s.get('targetId') not in self.hidden,clock=lambda:100)

    def component(self,i=0):
        return self.domain.snapshot()['states'][key(self.subjects[i])]

    def params(self,i=0):
        s=self.component(i)
        return {'subject':s['subject'],'source':s['desired']['source'],
                'expected':{'targetRevision':s['targetRevision'],
                            'desiredRecordId':s['desired']['recordId'],
                            'catalogSha256':self.scope['catalogSha256']}}

    def write(self,op,p,ident=None):
        return self.service.owner_write('agent-1',op,p,operation_id=ident or uid(),
                                        assertion_source='OWNER_TRANSCRIBED')

    def report(self,i=0,**changes):
        return {**self.params(i),'attemptId':None,'context':'release','outcome':'REPORTED_COMPLETE',
                'assertion':'reported by owner','observedAt':100,'evidenceDigests':[],**changes}

    def protected(self,kind,attempt=None,i=0):
        return self.domain.protected_event(kind,{**self.params(i),'attemptId':attempt,
             'controllerReceiptDigest':'a'*64,'readbackDigest':'b'*64,'observedAt':100},
             actor='controller',operation_id=uid(),recorded_at=101)

    def test_owner_report_never_creates_installed_and_historical_no_downgrade(self):
        self.assertIsNone(self.component(1)['installed'])
        self.write('report_release_result',self.report(1))
        reported=copy.deepcopy(self.component(1)['ownerReported'])
        self.assertEqual(self.component(1)['outstandingActions'],['migration-required'])
        historical=self.report(1,context='historical',outcome='REPORTED_FAILED',observedAt=10)
        self.write('report_release_result',historical)
        self.assertEqual(self.component(1)['ownerReported'],reported)
        self.assertIsNone(self.component(1)['installed'])
        rollback=self.report(1,context='rollback')
        rollback['source']['sourceSha']='f'*40
        self.write('report_release_result',rollback)
        self.assertEqual(self.component(1)['ownerReported']['source']['sourceSha'],'f'*40)
        self.assertEqual(self.component(1)['outstandingActions'],['config-deploy','migration-required'])
        self.assertNotEqual(self.component(1)['desired']['source']['sourceSha'],'f'*40)

    def test_profile_preview_matches_restrictions_recorded_by_begin(self):
        operations=[{'service':'github','operation':'merge_pull_request'},
                    {'service':'registry','operation':'register_merge'}]
        profile=self.profile['subjects'][0]['maintenance']
        profile['blockedOperations']=operations
        self.rebind()
        p=self.params()
        rows=self.service.read('agent-1','list_components',{'repository':p['subject']['repository'],
                               'page':{'limit':10,'cursor':None}})['data']['items']
        board=next(row for row in rows if row['subject']==p['subject'])
        planned=self.service.read('agent-1','plan_batch',{'items':[
            {'subject':p['subject'],'source':p['source']}]})['data']['targets'][0]
        self.assertEqual(board['maintenanceProfile'],planned['maintenance'])
        self.assertEqual(board['maintenanceProfile']['blockedOperations'],operations)
        self.assertEqual(board['restrictionDigest'],planned['restrictionDigest'])
        sc.hex_id(board['restrictionDigest'],64)
        self.assertEqual(self.domain.maintenance_snapshot()['holds'],[])
        attempt=self.write('begin_release',p)
        hold=self.domain.maintenance_snapshot()['holds'][0]
        self.assertEqual((hold['attemptId'],hold['restrictionDigest'],hold['blockedOperations']),
                         (attempt['operationId'],board['restrictionDigest'],operations))

    def test_required_begin_matching_attempt_and_independent_close(self):
        with self.assertRaises(Denied):
            self.write('report_release_result',self.report())
        r=self.write('begin_release',self.params())
        attempt=r['operationId']
        with self.assertRaises(Denied):
            self.write('begin_release',self.params())
        with self.assertRaises(Denied):
            self.write('report_release_result',self.report(attemptId=uid()))
        self.write('report_release_result',self.report(attemptId=attempt))
        self.assertEqual(self.component()['activeAttempt']['attemptId'],attempt)
        self.assertIsNone(self.component()['installed'])
        with self.assertRaises(Denied):
            self.protected('RELEASE_HOLD_CLOSED',attempt)
        self.verify=True
        self.protected('TECHNICAL_OBSERVATION_ACCEPTED',attempt)
        self.assertEqual(self.component()['installed']['validity'],'LAST_ACCEPTED_TECHNICAL_OBSERVATION')
        self.assertIsNotNone(self.component()['activeAttempt'])
        self.protected('RELEASE_HOLD_CLOSED',attempt)
        self.assertIsNone(self.component()['activeAttempt'])

    def test_unknown_or_failure_keeps_hold(self):
        attempt=self.write('begin_release',self.params())['operationId']
        for outcome in ('UNKNOWN','REPORTED_FAILED'):
            self.write('report_release_result',self.report(attemptId=attempt,outcome=outcome))
            self.assertEqual(self.component()['activeAttempt']['result'],outcome)

    def test_atomic_group_and_exact_replay(self):
        items=[self.params(0),self.params(1)]
        ids=[uid(),uid()]
        parent=uid()
        result=self.service.begin_group('agent-1',{'items':items},operation_ids=ids,parent_id=parent,
                                        assertion_source='OWNER_TRANSCRIBED')
        self.assertEqual([r['operationId'] for r in result],ids)
        self.assertEqual(self.service.begin_group('agent-1',{'items':items},operation_ids=ids,
                         parent_id=parent,assertion_source='OWNER_TRANSCRIBED'),result)
        self.assertTrue(all(self.component(i)['activeAttempt'] for i in (0,1)))

    def test_atomic_group_conflict_rolls_back_first(self):
        self.profile['subjects'][0]['maintenance']=maintenance(True,True)
        self.rebind()
        with self.assertRaises(Denied):
            self.service.begin_group('agent-1',{'items':[self.params(0),self.params(1)]},
                   operation_ids=[uid(),uid()],parent_id=uid(),assertion_source='OWNER_TRANSCRIBED')
        self.assertEqual(self.domain.snapshot()['snapshotRevision'],0)
        self.assertIsNone(self.component()['activeAttempt'])

    def test_report_optional_window_closes_only_own_attempt(self):
        first=self.write('begin_release',self.params())['operationId']
        second=self.write('begin_release',self.params(1))['operationId']
        self.write('report_release_result',self.report(1,attemptId=second))
        self.assertIsNone(self.component(1)['activeAttempt'])
        self.assertEqual(self.component()['activeAttempt']['attemptId'],first)

    def test_stale_causal_guard_and_duplicate_receipt(self):
        p=self.report(1)
        ident=uid()
        first=self.write('report_release_result',p,ident)
        self.assertEqual(self.write('report_release_result',p,ident),first)
        with self.assertRaises(Stale):
            self.write('report_release_result',p)
        with self.assertRaises(Denied):
            self.write('report_release_result',self.report(1,observedAt=1))

    def test_scope_and_scoped_history_cursor(self):
        self.write('report_release_result',self.report(1))
        self.write('report_release_result',self.report(1))
        repo=self.scope['repository']
        query={'subject':self.subjects[1],'page':{'limit':1,'cursor':None}}
        first=self.service.read('agent-1','list_history',query)['data']
        self.assertIsNotNone(first['nextCursor'])
        query['page']['cursor']=first['nextCursor']
        self.assertTrue(self.service.read('agent-1','list_history',query)['data']['complete'])
        self.write('report_release_result',self.report(1))
        with self.assertRaises(Stale):
            self.service.read('agent-1','list_history',query)
        self.hidden.add('other')
        with self.assertRaises(Denied):
            self.service.read('agent-1','get_component',{'subject':self.subjects[1]})
        data=self.service.read('agent-1','list_components',{'repository':repo,
                    'page':{'limit':10,'cursor':None}})['data']
        self.assertEqual(len(data['items']),1)
        self.assertIsNone(self.service.read('agent-1','get_maintenance_status',
                                           {'repository':repo})['data']['holds'])

    def test_reads_all_seven_and_stateless_plan(self):
        r=self.write('begin_release',self.params())
        repo=self.scope['repository']
        subject=self.subjects[0]
        page={'limit':10,'cursor':None}
        inputs={'list_components':{'repository':repo,'page':page},
                'list_active_releases':{'repository':repo,'page':page},
                'get_component':{'subject':subject},'list_history':{'subject':subject,'page':page},
                'get_operation':{'subject':subject,'operationId':r['operationId']},
                'get_maintenance_status':{'repository':repo},
                'plan_batch':{'items':[{'subject':subject,'source':self.params()['source']}]}}
        for op,params in inputs.items():
            first=self.service.read('agent-1',op,params)
            self.assertEqual(first,self.service.read('agent-1',op,params))
            self.assertFalse(first['runtimeAdmissionAllowed'])
        self.assertEqual(self.service.read('agent-1','plan_batch',inputs['plan_batch'])['data']['status'],'BLOCKED')
        self.assertEqual(self.domain.snapshot()['snapshotRevision'],1)

    def test_plan_missing_dependency_unknown_cycle_blocked(self):
        items=[{'subject':self.subjects[0],'source':self.params()['source']}]
        self.profile['subjects'][0]['dependencies']=[{**self.subjects[1],'targetId':'missing'}]
        self.rebind()
        self.assertEqual(self.service.read('agent-1','plan_batch',{'items':items})['data']['status'],'UNKNOWN')
        self.profile['subjects'][0]['dependencies']=[self.subjects[1]]
        self.profile['subjects'][1]['dependencies']=[self.subjects[0]]
        self.rebind()
        self.assertEqual(self.service.read('agent-1','plan_batch',{'items':items})['data']['status'],'BLOCKED')

    def test_unknown_maintenance_not_optional(self):
        self.profile['subjects'][1]['maintenance']=None
        self.rebind()
        for op,params in [('begin_release',self.params(1)),('report_release_result',self.report(1))]:
            with self.assertRaises(Denied):
                self.write(op,params)

    def test_profile_change_after_event_fails_closed(self):
        self.write('report_release_result',self.report(1))
        self.profile['subjects'][1]['maintenance']=maintenance(True)
        self.rebind()
        with self.assertRaises(Denied):
            self.domain.snapshot()

    def test_protected_raw_event_not_public_writer(self):
        p={**self.params(),'attemptId':None,'controllerReceiptDigest':'a'*64,
           'readbackDigest':'b'*64,'observedAt':100}
        req={'operationId':uid(),'actor':'controller','kind':'TECHNICAL_OBSERVATION_ACCEPTED',
             'assertionSource':'PROTECTED_CONTROLLER','parentRequestId':None,
             'profileDigest':self.domain.profile_digest,'params':p}
        with self.assertRaises(Denied):
            self.store.append_event(req,recorded_at=100)


if __name__=='__main__':
    unittest.main()

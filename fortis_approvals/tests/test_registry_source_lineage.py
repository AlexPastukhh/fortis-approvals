"""Isolated exact #286 transition contract and successor source accounting.

Historical gap constants are source facts, all current witness/owner/CI
observations are synthetic fixtures, never a live readback or owner GO.
"""
import copy
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from fortis_approvals.core import Denied, Conflict, Stale
from fortis_approvals.integrations.registry_contracts import source_lineage_contract as lc
from fortis_approvals.integrations.registry_contracts import transition_contract as tc
from fortis_approvals.integrations.registry_contracts import semantic_contract as sc
from fortis_approvals.integrations.github.gateway import forward_lineage as gap_source
from fortis_approvals.registry import functional_v1_journal as legacy
from fortis_approvals.registry.transition_preservation import legacy_prefix_witness
from fortis_approvals.registry.release_event_journal import ReleaseEventJournal
from fortis_approvals.registry.release_domain import ReleaseDomain,key
from fortis_approvals.registry.semantic_service import SemanticRegistry
from fortis_approvals.tests import test_registry_transition_contract as fixture
from fortis_approvals.tests.test_registry_state_journal import uid
from fortis_approvals.tests.test_registry_release_domain import maintenance


def exact_gap():
    return {'disposition':'OWNER_REVIEWED_POST_285_CAPTURE_GAP',
            'merges':[copy.deepcopy(getattr(gap_source,'_CUTOVER_'+str(n)))
                for n in range(253,272)]+copy.deepcopy(list(gap_source._POST_285_SUFFIX))+
                [copy.deepcopy(lc.FINAL_GAP)]}


class LineageFixture:
    def setUp(self, *, successor=None, owner_scope=None, instance_id=None):
        tmp=tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root=Path(tmp.name)
        self.scope={'repository':tc.REPOSITORY,'enrollmentId':uid(),'baselineSha':lc.BASELINE,
                    'baselineDigest':'a'*64,'catalogSha256':tc.BASE_CATALOG,
                    'bindingDigest':'b'*64,'policyReferenceDigest':'c'*64}
        if owner_scope is not None:
            self.scope=copy.deepcopy(owner_scope)
        self.instance=uid() if instance_id is None else instance_id
        self.path=self.root/'old.sqlite'
        self.state=legacy.FunctionalV1CandidateJournal.initialize(self.path,
              instance_id=self.instance,scope=self.scope,plan_reader=lambda _:self.fail('legacy lookup'))
        self.witness=legacy_prefix_witness(self.state)
        self.subjects=[{'repository':tc.REPOSITORY,'targetId':n,'environment':'test'}
                       for n in ('app','other')]
        self.profile={'schemaVersion':1,'repository':tc.REPOSITORY,'catalogSha256':tc.BASE_CATALOG,
                      'subjects':[{'subject':s,'componentId':s['targetId']+'-runtime',
                           'resources':[s['targetId']+'-state'],'dependencies':[],
                           'unresolvedDependencies':[],'maintenance':None,'procedure':'UC.md',
                           'verification':['source-ci'],'build':None,'deployable':True}
                           for s in self.subjects]}
        self.successor=copy.deepcopy(self.profile)
        self.catalog_text='schemaVersion: 2\nrepository: fortis-approvals\n'
        import hashlib
        self.successor['catalogSha256']=hashlib.sha256(self.catalog_text.encode()).hexdigest()
        for row in self.successor['subjects']:row['maintenance']=maintenance(False)
        if successor is not None:
            self.successor,self.catalog_text=copy.deepcopy(successor)
            self.subjects=[row['subject'] for row in self.successor['subjects']]
            self.profile=copy.deepcopy(self.successor)
            self.profile['catalogSha256']=tc.BASE_CATALOG
            for row in self.profile['subjects']:
                row['maintenance']=None
        m=fixture.manifest()
        m['old']['registry']=self.witness
        self.gap=exact_gap()
        m['old']['historicalGapDigest']=sc.digest(self.gap)
        m['successor']['catalogSha256']=self.successor['catalogSha256']
        self.manifest=m
        self.pin=sc.digest(m)
        self.clone=fixture.LegacyPrefixTests.clone(self)
        self.store=ReleaseEventJournal.migrate_clone(self.clone,expected_legacy=self.witness,
                                                      transition_digest=self.pin)
        self.verify=True
        self.domain=self.reopen()
        self.service=SemanticRegistry(self.domain,authorize=lambda a,op,s:a=='agent-1',
                                      clock=lambda:100)

    def reopen(self):
        return ReleaseDomain(self.store,self.profile,expected_profile_digest=sc.digest(self.profile),
                  successor_profile=self.successor,expected_successor_profile_digest=sc.digest(self.successor),
                  source_verify=lambda req:self.verify)

    def transition(self):
        m=self.manifest
        p={k:m['pr'][k] for k in ('number','baseSha','headSha','treeSha','bodyDigest','impactDigest',
                                   'pathsDigest','ciDigest')}
        p.update(repository=tc.REPOSITORY,catalogSha256=self.successor['catalogSha256'],
                 profileDigest=sc.digest(self.successor),expectedSourceRevision=0,
                 classification='deployment',targets=[{'subject':self.subjects[0],
                   'actions':['config-deploy','migration-required']}],dependencies=[],
                 dependencyDigest=sc.digest([]))
        return {'operationId':uid(),'kind':'TRANSITION','parentRequestId':None,'proposal':p,
                'observation':fixture.observation(m),'evidenceDigest':'f'*64,
                'transition':{'manifest':copy.deepcopy(m),'gap':copy.deepcopy(self.gap),
                       'oldStateDigest':sc.digest(m['old']),'gapObservationDigest':'e'*64}}

    def merge(self,number=288,targets=None):
        view=self.domain.snapshot()
        if targets is None:targets=[{'subject':self.subjects[0],'actions':['image-rebuild']}]
        import hashlib
        def h(label):return hashlib.sha1((str(number)+label).encode()).hexdigest()
        p={'repository':tc.REPOSITORY,'number':number,'baseSha':view['sourceCursor'],
           'headSha':h('head'),'treeSha':h('tree'),'catalogSha256':self.successor['catalogSha256'],
           'profileDigest':sc.digest(self.successor),'bodyDigest':'1'*64,'impactDigest':'2'*64,
           'pathsDigest':'3'*64,'ciDigest':'4'*64,'expectedSourceRevision':view['sourceRevision'],
           'classification':'deployment' if targets else 'no-deployment','targets':targets,
           'dependencies':[],'dependencyDigest':sc.digest([])}
        o={k:p[k] for k in ('repository','number','headSha','treeSha','catalogSha256',
                              'bodyDigest','impactDigest','pathsDigest','ciDigest')}
        o.update(mergeSha=h('merge'),mainSha=h('merge'),parents=[p['baseSha'],p['headSha']])
        return {'operationId':uid(),'kind':'MERGE','parentRequestId':uid(),'proposal':p,
                'observation':o,'evidenceDigest':'5'*64,'transition':None}

    def component(self,i=0):
        return self.domain.snapshot()['states'][key(self.subjects[i])]

    def params(self,i=0):
        view=self.domain.snapshot()
        state=view['states'][key(self.subjects[i])]
        return {'subject':state['subject'],'source':state['desired']['source'],
                'expected':{'targetRevision':state['targetRevision'],
                            'desiredRecordId':state['desired']['recordId'],
                            'catalogSha256':view['catalogSha256']}}

    def report(self,**changes):
        return {**self.params(),'attemptId':None,'context':'release','outcome':'REPORTED_COMPLETE',
                'assertion':'fixture owner report','observedAt':100,'evidenceDigests':[],**changes}

    def write(self,op,params):
        return self.service.owner_write('agent-1',op,params,operation_id=uid(),
                                        assertion_source='OWNER_TRANSCRIBED')


class SourceLineageTests(LineageFixture,unittest.TestCase):
    def test_exact_transition_preserves_legacy_genesis_and_only_actual_impact(self):
        self.assertTrue(self.domain.snapshot()['sourceTransitionPending'])
        req=self.transition()
        r=self.domain.register_source(req)
        self.assertEqual(r['kind'],'TRANSITION')
        self.assertEqual(self.domain.snapshot()['sourceCursor'],req['observation']['mergeSha'])
        self.assertFalse(self.domain.snapshot()['sourceTransitionPending'])
        self.assertEqual(self.component()['desired']['provenance'],'REVIEWED_TRANSITION')
        self.assertIsNone(self.component(1)['desired'])
        self.assertIsNone(self.component()['installed'])
        self.assertEqual(legacy_prefix_witness(self.state),self.witness)
        self.assertEqual(self.store.release_checkpoint()['legacy'],self.witness)
        self.assertEqual(self.reopen().source_operation(req['operationId']),r)

    def test_bad_gap_or_unverified_old_state_blocks_cursor(self):
        req=self.transition()
        bad=copy.deepcopy(req)
        bad['transition']['gap']['merges'][0]['number']=1
        with self.assertRaises(Denied):self.domain.register_source(bad)
        self.verify=False
        with self.assertRaises(Denied):self.domain.register_source(req)
        self.assertEqual(self.domain.snapshot()['sourceRevision'],0)
        self.assertEqual(self.domain.snapshot()['sourceCursor'],lc.BASELINE)

    def test_no_deployment_advances_only_source_cursor(self):
        self.domain.register_source(self.transition())
        before=self.component()
        req=self.merge(targets=[])
        self.domain.register_source(req)
        self.assertEqual(self.component(),before)
        self.assertEqual(self.domain.snapshot()['sourceRevision'],2)
        self.assertEqual(self.domain.snapshot()['sourceCursor'],req['observation']['mergeSha'])

    def test_cumulative_actions_and_old_attempt_report_does_not_clear_newer(self):
        self.domain.register_source(self.transition())
        start=self.params()
        attempt=self.write('begin_release',start)['operationId']
        req=self.merge(targets=[{'subject':self.subjects[0],'actions':['config-deploy','image-rebuild']}])
        self.domain.register_source(req)
        self.assertEqual(self.component()['outstandingActions'],
                         ['config-deploy','image-rebuild','migration-required'])
        report=self.report(attemptId=attempt,source=start['source'])
        self.write('report_release_result',report)
        self.assertIsNone(self.component()['activeAttempt'])
        self.assertEqual(self.component()['desired']['source']['sourceSha'],req['observation']['mergeSha'])
        self.assertEqual(self.component()['outstandingActions'],
                         ['config-deploy','image-rebuild','migration-required'])
        self.assertEqual(sum(a['ownerReported'] for a in self.component()['actionCoverage']),1)
        self.write('report_release_result',self.report())
        self.assertEqual(self.component()['outstandingActions'],['migration-required'])
        self.assertIsNone(self.component()['installed'])
        self.assertEqual(self.reopen().snapshot(),self.domain.snapshot())

    def test_new_merge_does_not_resurrect_old_reported_action(self):
        self.domain.register_source(self.transition())
        self.write('report_release_result',self.report())
        self.domain.register_source(self.merge())
        self.assertEqual(self.component()['outstandingActions'],['image-rebuild','migration-required'])

    def test_dependency_plan_begin_and_verified_artifact_coverage(self):
        consumer,dependency=self.successor['subjects']
        consumer['dependencies']=[dependency['subject']]
        dependency['build']={'buildUnitId':'dependency-build','recipeDigest':'a'*64,
                            'configDigest':'b'*64}
        self.domain=self.reopen()
        self.service.domain=self.domain
        self.domain.register_source(self.transition())
        req=self.merge(targets=[{'subject':s,'actions':['image-rebuild']} for s in self.subjects])
        self.domain.register_source(req)

        def plan(indices):
            return self.service.read('agent-1','plan_batch',{'items':[
                {'subject':self.subjects[i],'source':self.params(i)['source']} for i in indices]})['data']

        self.assertEqual(plan([0])['status'],'UNKNOWN')
        joint=plan([0,1])
        self.assertEqual(joint['status'],'PLAN_READY')
        self.assertEqual(joint['order'],[self.subjects[1],self.subjects[0]])
        self.assertEqual(joint['buildGroups'][0]['artifactState'],'BUILD_REQUIRED')
        self.assertFalse(joint['deploymentAuthorized'])
        with self.assertRaisesRegex(Denied,'REGISTRY_DOMAIN_DEPENDENCY_UNVERIFIED'):
            self.write('begin_release',self.params(0))

        attempt=self.write('begin_release',self.params(1))['operationId']
        params=copy.deepcopy(self.params(1))
        params['source']['artifactSha256']='e'*64
        observation={**params,'attemptId':attempt,'controllerReceiptDigest':'a'*64,
                     'readbackDigest':'b'*64,'observedAt':100,
                     'coveredRecordIds':[params['expected']['desiredRecordId']]}
        with self.assertRaisesRegex(Denied,'REGISTRY_PROTECTED_PROOF_REQUIRED'):
            self.domain.protected_event('TECHNICAL_OBSERVATION_ACCEPTED',observation,
                                        actor='controller',operation_id=uid(),recorded_at=101)
        self.assertIsNone(self.component(1)['installed'])
        self.domain._protected_verify=lambda event:event['params']==observation
        self.domain.protected_event('TECHNICAL_OBSERVATION_ACCEPTED',observation,
                                    actor='controller',operation_id=uid(),recorded_at=101)
        self.assertEqual(self.component(1)['desired']['source']['artifactSha256'],'e'*64)
        self.assertEqual(self.component(1)['outstandingActions'],[])
        self.assertIsNone(self.domain.maintenance_snapshot()['holds'][0]['source']['artifactSha256'])
        self.assertEqual(self.component(1)['activeAttempt']['verifiedSource']['artifactSha256'],'e'*64)
        self.write('report_release_result',{**self.report(attemptId=attempt),**self.params(1)})
        self.assertEqual(self.component(1)['planningState'],'DEPLOYED')
        self.assertEqual(plan([0])['status'],'PLAN_READY')
        self.assertEqual(self.write('begin_release',self.params(0))['eventKind'],
                         'RELEASE_ATTEMPT_STARTED')
        self.assertEqual(self.component()['planningState'],'IN_PROGRESS')
        self.assertEqual(self.reopen().snapshot(),self.domain.snapshot())

    def test_stale_merge_revision_and_bad_parent_tree(self):
        self.domain.register_source(self.transition())
        first=self.merge()
        second=self.merge(289)
        self.domain.register_source(first)
        with self.assertRaises(Stale):self.domain.register_source(second)
        bad=self.merge(290)
        bad['observation']['parents'][0]='f'*40
        with self.assertRaises(Denied):self.domain.register_source(bad)
        bad=self.merge(291)
        bad['observation']['treeSha']='e'*40
        with self.assertRaises(Denied):self.domain.register_source(bad)
        self.assertEqual(self.domain.snapshot()['sourceRevision'],2)

    def test_original_operation_recovery_and_conflict(self):
        req=self.transition()
        with patch.object(self.domain,'source_operation',side_effect=Denied('lost acknowledgement')):
            self.assertEqual(self.domain.register_source(req)['result'],'UNKNOWN_OUTCOME')
        r=self.reopen().source_operation(req['operationId'])
        self.verify=False
        self.assertEqual(self.domain.register_source(req),r)
        changed={**req,'evidenceDigest':'a'*64}
        with self.assertRaises(Conflict):self.domain.register_source(changed)

    def test_source_history_and_receipt_lookup_are_subject_scoped(self):
        req=self.transition()
        result=self.domain.register_source(req)
        p={'subject':self.subjects[0],'operationId':req['operationId']}
        self.assertEqual(self.service.read('agent-1','get_operation',p)['data']['receipt'],result)
        p['subject']=self.subjects[1]
        self.assertFalse(self.service.read('agent-1','get_operation',p)['data']['found'])

    def test_corrupt_source_row_fails_readback(self):
        import sqlite3
        self.domain.register_source(self.transition())
        with sqlite3.connect(self.store.path) as db:
            db.execute("UPDATE source_events SET request='not json'")
        with self.assertRaises(Denied):
            self.reopen().snapshot()

    def test_stale_catalog_and_unreviewed_target_refused(self):
        self.domain.register_source(self.transition())
        wrong=self.merge()
        wrong['proposal']['profileDigest']='a'*64
        with self.assertRaises(Denied):self.domain.register_source(wrong)
        wrong=self.merge(targets=[{'subject':{**self.subjects[0],'targetId':'missing'},
                                  'actions':['image-rebuild']}])
        with self.assertRaises(Denied):self.domain.register_source(wrong)
        self.assertEqual(self.domain.snapshot()['sourceRevision'],1)


if __name__=='__main__':unittest.main()

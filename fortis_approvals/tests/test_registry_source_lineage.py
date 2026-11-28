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
from fortis_approvals.integrations.registry_contracts import maintenance_evidence
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

    def reopen(self,store=None):
        return ReleaseDomain(self.store if store is None else store,self.profile,expected_profile_digest=sc.digest(self.profile),
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
        dependency['maintenance']=maintenance(required=True,freeze=True)
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
        params=self.params(1)
        hold=self.domain.maintenance_snapshot()['holds'][0]
        artifact_source={**hold['source'],'artifactSha256':'e'*64}
        generation='a'*64
        identity={'schemaVersion':1,'attemptId':attempt,'subject':hold['subject'],
                  'source':artifact_source,'generation':generation}
        controller={**identity,'applyRecordDigest':'b'*64,'backupRecordDigest':'c'*64,
                    'primaryRecordDigest':'d'*64,'finalSealDigest':'e'*64,'completionTime':99}
        readback={**identity,'primaryRecordDigest':controller['primaryRecordDigest'],
                  'stateReceiptDigest':controller['finalSealDigest'],'observedAt':100,'healthy':True}
        current=self.domain.maintenance_snapshot()
        interlock={'schemaVersion':1,'registryInstanceId':current['instanceId'],
                   'scopeDigest':current['scopeDigest'],'sequence':8,'previousDigest':'f'*64,
                   'phase':'COMPLETION_PENDING','generation':generation,
                   'attempt':{**{k:hold[k] for k in ('attemptId','subject','source','restrictionDigest')},
                              'sourceGeneration':'f'*64,'targetGeneration':generation},
                   'proofDigest':sc.digest(controller)}
        expected=params['expected']
        completion=maintenance_evidence.completion_params(interlock,controller,readback,
                   expected_controller_digest=sc.digest(controller),
                   expected_observation_digest=sc.digest(readback),
                   expected_target_revision=expected['targetRevision'],
                   expected_desired_record=expected['desiredRecordId'],now=101,max_age=30)
        observation={**completion,'coveredRecordIds':[expected['desiredRecordId']]}
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
        with self.assertRaisesRegex(Denied,'REGISTRY_DOMAIN_DEPENDENCY_UNVERIFIED'):
            self.write('begin_release',self.params(0))
        self.assertEqual(self.component(1)['planningState'],'IN_PROGRESS')
        close={**completion,'expected':self.params(1)['expected']}
        self.domain._protected_verify=lambda event:event['params']==close
        operation_id=uid()
        receipt=self.domain.protected_event('RELEASE_HOLD_CLOSED',close,actor='controller',
                                           operation_id=operation_id,recorded_at=101)
        self.assertEqual(self.domain.protected_event('RELEASE_HOLD_CLOSED',close,actor='controller',
                         operation_id=operation_id,recorded_at=102),receipt)
        self.assertEqual(self.domain.maintenance_snapshot()['holds'],[])
        self.assertEqual(self.component(1)['planningState'],'DEPLOYED')
        self.assertEqual(plan([0])['status'],'PLAN_READY')
        self.assertEqual(self.write('begin_release',self.params(0))['eventKind'],
                         'RELEASE_ATTEMPT_STARTED')
        self.assertEqual(self.component()['planningState'],'IN_PROGRESS')
        self.assertEqual(self.reopen().snapshot(),self.domain.snapshot())

    def test_bootstrap_backup_readback_rejects_changed_bytes(self):
        import hashlib
        from fortis_approvals.registry import owner_functional_v1_bootstrap as boot
        root=self.root/'retained-backup'
        root.mkdir(mode=0o700)
        for name in ('state','config'):(root/name).mkdir(mode=0o700)
        def write(name,data):
            path=root/name
            path.write_bytes(data);path.chmod(0o600)
            return hashlib.sha256(data).hexdigest()
        data=self.store.path.read_bytes()
        manifest={'schema':'fortis-registry-v4-local-backup-v1',
            'checkpoint':{'sourceRevision':3,'sourceCursor':'073d6f8701595e499eac5a1fa0cbe90accb05819'},
            'databaseSha256':write('state/registry.sqlite',data),'databaseBytes':len(data),
            'configHashes':{'profile.json':write('config/profile.json',b'fixture')}}
        pin=write('manifest.json',sc.canonical(manifest).encode())
        with patch('fortis_approvals.r7_registry_reader_mount._check_owner_readonly_mount'):
            self.assertEqual(boot.verify_bootstrap_backup(pin,root=root),pin)
            with self.assertRaisesRegex(Denied,'SOURCE_BOOTSTRAP_EVIDENCE_PIN_CHANGED'):
                boot.verify_bootstrap_backup('0'*64,root=root)
            write('config/profile.json',b'changed')
            with self.assertRaisesRegex(Denied,'SOURCE_BOOTSTRAP_BACKUP_CHANGED'):
                boot.verify_bootstrap_backup(pin,root=root)

    def test_bootstrap_offline_pair_exact_check_and_lost_ack(self):
        import hashlib
        import os
        from contextlib import ExitStack, nullcontext
        from types import SimpleNamespace
        from fortis_approvals.registry import source_event_journal as src, protected_transition as pt
        from fortis_approvals.registry import owner_functional_v1_bootstrap as boot
        from fortis_approvals.integrations.registry_contracts import maintenance_contract as mc
        from fortis_approvals.extensions import maintenance_interlock_reader as ir
        subjects=mc.paired_subjects(tc.REPOSITORY)
        self.subjects=[subjects['gateway'],subjects['registry']]
        for profile in (self.profile,self.successor):
            for i,row in enumerate(profile['subjects']):
                row['subject']=self.subjects[i]
                row['resources']=['registry-read']
                row['dependencies']=[self.subjects[1]] if i==0 else []
                if profile is self.successor:row['maintenance']=maintenance(True,True)
        self.domain=self.reopen()
        config_root=self.root/'bootstrap-runtime'
        config_root.mkdir(mode=0o700)
        def write(name,data):
            path=config_root/name
            path.write_bytes(data);path.chmod(0o600)
            return hashlib.sha256(data).hexdigest()
        def retain(prefix,req):
            ci={'fixture':prefix}
            # The historical transition's manifest pins its synthetic CI.
            # Repair fixtures can use actual canonical CI digests directly.
            if prefix!='transition':
                req['proposal']['ciDigest']=req['observation']['ciDigest']=sc.digest(ci)
            evidence={'proposal':req['proposal'],'observation':req['observation'],'ci':ci,
                'bundleSha256':write(prefix+'-main.bundle',prefix.encode())}
            req['evidenceDigest']=write(prefix+'-evidence.json',sc.canonical(evidence).encode())
            return req
        first=self.domain.register_source(retain('transition',self.transition()))
        targets=[{'subject':x,'actions':['image-rebuild']} for x in self.subjects]
        with ExitStack() as stack:
            def pin(name,value):
                stack.enter_context(patch.object(src,name,value))
            def append(req):
                with self.store._db() as db:
                    return src.append(self.store,db,src.request(req,self.store),{})
            pin('_DELIVERY_287',first['sourceCursor'])
            prev=first
            for n in (288,289):
                req=self.merge(number=n,targets=targets)
                req.update(kind=src.DELIVERY_REPAIR,parentRequestId=None,
                    operationId=src.delivery_repair_id(prev['operationId'],req['observation']['mergeSha']),
                    transition={'predecessorOperationId':prev['operationId'],'predecessorEventDigest':prev['eventDigest']})
                prev=append(retain('delivery-repair' if n==288 else 'delivery-repair-2',req))
                if n==288:
                    pin('_DELIVERY_288',prev['sourceCursor']);pin('_DELIVERY_288_EVENT',prev['eventDigest'])
            pin('_BOOTSTRAP_BASE',prev['sourceCursor']);pin('_BOOTSTRAP_EVENT',prev['eventDigest'])
            req=self.merge(number=291,targets=targets)
            review={'schemaVersion':1,'prefix':pt.bootstrap_prefix(self.domain.snapshot(),self.store),
                'proposal':req['proposal'],'authorityDigest':'a'*64,'authorityWitnessDigest':'b'*64,
                'primaryRecordDigest':'c'*64,'gatewayBackupDigest':'d'*64,
                'registryBackupDigest':'e'*64,'ownerReviewProofDigest':'f'*64}
            review_pin=write('bootstrap-review.json',sc.canonical(review).encode())
            evidence={'reviewDigest':review_pin,'observation':req['observation'],'ci':{},'body':'fixture','bundleSha256':write('bootstrap-main.bundle',b'fixture-bootstrap')}
            evidence_pin=write('bootstrap-evidence.json',sc.canonical(evidence).encode())
            req.update(kind=src.BOOTSTRAP_MIGRATION,parentRequestId=None,evidenceDigest=evidence_pin,
                operationId=src.bootstrap_migration_id(prev['operationId'],req['observation']['mergeSha']),
                transition={'schemaVersion':1,'predecessorOperationId':prev['operationId'],
                    'predecessorEventDigest':prev['eventDigest'],'reviewDigest':review_pin})
            receipt=append(req)
            write('legacy-release-profile.json',sc.canonical(self.profile).encode())
            write('successor-release-profile.json',sc.canonical(self.successor).encode())
            pins={'legacyWitness':self.witness,'transitionDigest':self.pin,
                  'legacyProfileDigest':sc.digest(self.profile),'successorProfileDigest':sc.digest(self.successor),
                  'generation':'1'*64,'internalActor':'controller',
                  'peerKeyDigest':write('semantic-peer.key',b'p'*32),
                  'frameKeyDigest':write('semantic-frame.key',b'f'*32)}
            from fortis_approvals.tests.test_maintenance_gate import Controller
            controller=Controller(self.instance,sc.digest(self.scope),pins['generation'])
            cfg={'schemaVersion':3,'instanceId':self.instance,'scope':self.scope,
                 'registryStatePath':str(self.store.path),'socketPath':'/run/fortis-registry/socket',
                 'readerUid':10001,'readerGid':10001,'semantic':pins,
                 'sourceWrite':{'policyAuthorityDigest':'a'*64,'interlockDigest':controller.pin}}
            profile_pin=write('profile.json',sc.canonical(cfg).encode())
            stack.enter_context(patch.object(boot,'STATE_PATH',self.store.path))
            stack.enter_context(patch.object(boot,'_successor_inputs',return_value=(cfg,config_root,pins)))
            stack.enter_context(patch('fortis_approvals.r7_registry_reader_mount._exact_mountinfo',return_value=True))
            stack.enter_context(patch('fortis_approvals.r7_registry_reader_mount._check_owner_readonly_mount'))
            args={'expected_profile_sha256':profile_pin,'review_sha256':review_pin,
                  'evidence_sha256':evidence_pin,'source_sha':receipt['sourceCursor']}
            with patch.object(boot.os,'statvfs',return_value=SimpleNamespace(f_flag=os.ST_RDONLY)):
                registry=boot.inspect_bootstrap_pair(**args)
            self.assertEqual(registry['sourceMigrationReceipt'],receipt)
            self.assertEqual(registry['review']['reviewContentDigest'],
                sc.digest({k:v for k,v in review.items() if k!='ownerReviewProofDigest'}))
            gateway={'result':'BOOTSTRAP_GATEWAY_MATERIAL_ONLY','profileDigest':'4'*64,'sourceDigest':'5'*64,
                     'releaseNonce':uid(),'incumbentProfileDigest':'6'*64,
                     'companion':{'authorityWitnessDigest':'b'*64},'binding':registry['binding']}
            checked={'gateway':gateway,'registry':registry,'artifacts':{'gateway':'7'*64,'registry':'8'*64}}
            go={'schemaVersion':1,'attemptId':uid(),'checkDigest':'9'*64,
                'compatibilityDigest':boot.bootstrap_compatibility_digest(checked),'sourceRecordDigest':'a'*64,
                'reviewDigest':review_pin,'evidenceDigest':evidence_pin,
                'reviewProofDigest':review['ownerReviewProofDigest'],'targetGeneration':'2'*64,'recordedAt':100}
            frozen={'sha256':{'fixture':'b'*64},'summary':{}}
            def bind(owner_go=go,source_receipt=frozen):
                return boot.bootstrap_pair_authorization(checked,owner_go,source_receipt,
                    review_sha256=review_pin,evidence_sha256=evidence_pin,seed_digest=controller.pin)
            authorization=bind()
            self.assertEqual(authorization['frozenSourceReceiptDigest'],sc.digest(frozen))
            self.assertEqual(authorization['ownerGoDigest'],sc.digest(go))
            for bad in ({'reviewDigest':'0'*64},{'reviewProofDigest':'0'*64},
                        {'targetGeneration':pins['generation']},{'evidenceDigest':'0'*64}):
                with self.assertRaisesRegex(Denied,'SOURCE_BOOTSTRAP_OWNER_GO_CHANGED'):
                    bind({**go,**bad})
            stack.enter_context(patch.object(ir.InterlockReservations,'exclusive',return_value=nullcontext(True)))
            seed=stack.enter_context(patch.object(ir,'read_latest_interlock',return_value=(
                controller.record,{'interlockDigest':controller.pin})))
            def begin(auth=authorization,value=checked):
                return boot.begin_bootstrap_pair(**args,checked=value,authorization=auth)
            with self.assertRaisesRegex(Denied,'SOURCE_BOOTSTRAP_PAIR_CHECK_CHANGED'):
                begin({**authorization,'compatibilityDigest':'0'*64})
            seed.return_value=(controller.record,{'interlockDigest':'0'*64})
            with self.assertRaisesRegex(Denied,'SOURCE_BOOTSTRAP_PAIR_SEED_CHANGED'):begin()
            seed.return_value=(controller.record,{'interlockDigest':controller.pin})
            self.assertFalse(self.domain.snapshot()['operations'])
            def readback(auth=authorization):
                with patch.object(boot.os,'statvfs',return_value=SimpleNamespace(f_flag=os.ST_RDONLY)):
                    return boot.read_bootstrap_pair(**args,checked=checked,authorization=auth,seed=controller.record)
            with self.assertRaisesRegex(Denied,'SOURCE_BOOTSTRAP_PAIR_CHECK_CHANGED'):readback()
            original=ReleaseDomain.protected_begin_pair
            def lose_ack(domain,*a,**kw):
                original(domain,*a,**kw)
                raise OSError('fixture lost ACK')
            with patch.object(ReleaseDomain,'protected_begin_pair',lose_ack):
                with self.assertRaisesRegex(OSError,'lost ACK'):begin()
            # The first response was lost. Independently read the actual
            # journal, without calling the writable method again.
            with patch.object(ReleaseDomain,'protected_begin_pair',side_effect=AssertionError('readback wrote')):
                recovered=readback()
            self.assertEqual(begin(),recovered)
            self.assertEqual(readback(),recovered)
            # Real surviving WAL/SHM from an open SQLite connection. The
            # readback uses the existing stable snapshot copy, not immutable
            # SQLite on uncheckpointed bytes and not a writer.
            import sqlite3
            with sqlite3.connect(self.store.path) as conn:
                conn.execute('PRAGMA wal_autocheckpoint=0')
                conn.execute('BEGIN IMMEDIATE')
                conn.commit()
                with patch('fortis_approvals.registry.protected_transition._check_owner_readonly_mount'):
                    self.assertEqual(readback(),recovered)
            conn.close()
            with self.assertRaisesRegex(Denied,'SOURCE_BOOTSTRAP_PAIR_CHECK_CHANGED'):
                readback({**authorization,'attemptId':uid()})
            self.assertEqual(len(recovered['holdSnapshot']['holds']),2)
            plan=recovered['phasePlan']
            self.assertEqual(plan['proofKind'],'BOOTSTRAP_PHYSICAL_FREEZE')
            self.assertEqual([r['phase'] for r in plan['records']],
                ['DRAINING','FROZEN_BEFORE_CHECK','CHECK_SEALED','APPLY_STOP','STAGED_TARGET_FROZEN'])
            previous=controller.record
            for record in plan['records']:
                self.assertEqual(mc.validate_transition(previous,record),record)
                self.assertEqual(record['proofDigest'],plan['proofDigest'])
                previous=record
            self.assertEqual(mc.bind_startup_handoff(plan['handoff'],previous),previous)
            self.assertEqual(plan['registryDigest'],recovered['registryDigest'])
            self.assertEqual(previous['generation'],go['targetGeneration'])
            publication={'schema':'fortis-successor-maintenance-publication-v2','state':'Committed',
                'sourceRecordHash':authorization['sourceRecordDigest'].upper(),
                'record':plan['records'][-2],'digest':sc.digest(plan['records'][-2]),
                'previous':plan['records'][-3],'registryDigest':plan['registryDigest'],
                'previousRegistryDigest':plan['registryDigest']}
            final=mc.bootstrap_final_handoff(checked,authorization,controller.record,readback(),publication)
            self.assertEqual(final,{'record':plan['records'][-1],'handoff':plan['handoff']})
            # Actual inactive journal and exact per-file pins, with the
            # historical CI comparison stubbed only for the synthetic
            # transition manifest. No live owner/host/mount proof.
            from fortis_approvals import r7_registry_reader_mount as mount
            target=self.root/'final-runtime';target.mkdir(mode=0o700)
            before_files={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in config_root.iterdir()}
            original_retained=pt._retained_source_evidence
            def fixture_retained(root,name,request):
                if name!='transition-evidence.json':return original_retained(root,name,request)
                raw=(root/name).read_bytes()
                self.assertEqual(hashlib.sha256(raw).hexdigest(),request['evidenceDigest'])
                envelope=sc.loads_strict(raw)
                self.assertEqual(envelope['proposal'],request['proposal'])
                self.assertEqual(envelope['observation'],request['observation'])
                return envelope
            seed.return_value=(publication['record'],{'interlockDigest':publication['digest'],
                                                        'registryDigest':publication['registryDigest']})
            pin_target={'device':target.stat().st_dev,'inode':target.stat().st_ino}
            def seal(verify):
                def flags(path):
                    return SimpleNamespace(f_flag=os.ST_RDONLY if Path(path)!=target or verify else 0)
                with patch.object(boot.os,'statvfs',side_effect=flags),patch.object(pt,'_retained_source_evidence',side_effect=fixture_retained):
                    return boot.seal_bootstrap_registry_material(**args,checked=checked,authorization=authorization,
                        seed=controller.record,begin=recovered,publication=publication,
                        verify_only=verify,expected_target=pin_target,target=target)
            with patch.object(ReleaseDomain,'protected_begin_pair',side_effect=AssertionError('seal wrote journal')):
                sealed=seal(False)
                self.assertEqual(seal(True),sealed)
            self.assertEqual(sealed['profileDigest'],sc.digest(mc.staged_registry_profile(cfg,
                handoff=final['handoff'],staged_record=final['record'])))
            self.assertEqual(before_files,{p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in config_root.iterdir()})
            self.assertEqual(self.domain.snapshot()['snapshotRevision'],6)
            seed.return_value=(controller.record,{'interlockDigest':controller.pin})
            with self.assertRaisesRegex(Denied,'SOURCE_BOOTSTRAP_FINAL_PUBLICATION_CHANGED'):seal(True)
            for bad in ({'state':'Pending'},{'sourceRecordHash':'0'*64},{'registryDigest':'0'*64},
                        {'record':plan['records'][-1]},{'previous':plan['records'][0]}):
                with self.assertRaisesRegex(Denied,'SOURCE_BOOTSTRAP_FINAL_PUBLICATION_CHANGED'):
                    mc.bootstrap_final_handoff(checked,authorization,controller.record,recovered,{**publication,**bad})
            changed_plan=copy.deepcopy(recovered)
            changed_plan['phasePlan']['handoff']['registryDigest']='0'*64
            with self.assertRaisesRegex(Denied,'SOURCE_BOOTSTRAP_FINAL_PROOF_CHANGED'):
                mc.bootstrap_final_handoff(checked,authorization,controller.record,changed_plan,publication)
            changed=copy.deepcopy(recovered['holdSnapshot'])
            changed['holds'].pop()
            with self.assertRaisesRegex(Denied,'SOURCE_BOOTSTRAP_PHASE_PROOF_CHANGED'):
                boot.bootstrap_phase_plan(controller.record,authorization,recovered['pair'],recovered['receipts'],changed)
            self.assertFalse(recovered['admissionAllowed'])
            self.assertFalse(recovered['hostAccepted'])
            self.assertEqual(len(self.domain.snapshot()['operations']),2)
            self.assertTrue(all(x['installed'] is None for x in self.domain.snapshot()['states'].values()))
            with self.assertRaisesRegex(Denied,'SOURCE_BOOTSTRAP_PAIR_CHECK_CHANGED'):
                begin({**authorization,'attemptId':uid()})
            # Exact post-activation proof fixture on the original accounted
            # clone. Controller observations are synthetic, NOT host evidence.
            pair=recovered['pair'];holds=recovered['holdSnapshot']
            record=final['record']
            for phase in ('BACKUP_FROZEN','PROMOTE_FROZEN'):
                record=mc.validate_transition(record,{**record,'phase':phase,
                    'previousDigest':sc.digest(record),'sequence':record['sequence']+1,'proofDigest':'1'*64})
            reserve=self.root/'reserve';reserve.mkdir(mode=0o700)
            final_config=mc.staged_registry_profile(cfg,handoff=final['handoff'],staged_record=final['record'])
            seed.return_value=(record,mc.latest_projection(record,committed=True,registry_digest=sc.digest(holds)))
            def backup(verify):
                def flags(path):
                    return SimpleNamespace(f_flag=os.ST_RDONLY if Path(path)!=reserve or verify else 0)
                with (patch.object(boot,'_successor_inputs',return_value=(final_config,target,final_config['semantic'])),
                      patch.object(boot.os,'statvfs',side_effect=flags),
                      patch.object(pt,'_check_owner_readonly_mount')):
                    return boot.frozen_pair_backup(sealed['profileDigest'],pair=pair,holds=holds,
                        phase_record=record,verify_only=verify,target=reserve,
                        expected_target={'device':reserve.stat().st_dev,'inode':reserve.stat().st_ino})
            self.assertFalse(list(reserve.iterdir()))
            backup_result=backup(False)
            self.assertEqual(backup(True),backup_result)
            self.assertEqual(backup(False),backup_result)
            self.assertEqual(backup_result['holdSnapshot'],holds)
            self.assertEqual(backup_result['databaseSha256'],hashlib.sha256((reserve/self.store.path.name).read_bytes()).hexdigest())
            live={'gatewayId':'a'*64,'registryId':'b'*64,
                'gatewayImage':'sha256:'+pair['artifacts']['gateway'],
                'registryImage':'sha256:'+pair['artifacts']['registry'],
                'gatewayHealth':'healthy','registryStatus':'running','observedAt':101,
                'delivery':{'latestPin':True,'maintenancePhase':record['phase'],'generation':record['generation'],
                    'sourceDelivery':{'interlockDigest':sc.digest(record)},
                    'registryCheckpoint':{**backup_result['checkpoint'],'registryDigest':sc.digest(holds)}}}
            gateway_receipt={'sha256':{'fixture':'a'*64}}
            def project(**changes):
                kwargs=dict(apply_digest='3'*64,backup_digest='4'*64,primary_digest='2'*64,
                    backup_gateway=gateway_receipt,actual_gateway=gateway_receipt,
                    backup_registry=backup_result,actual_registry=backup_result,live=live,now=102)
                return maintenance_evidence.project_paired_completion(record,pair,holds,**{**kwargs,**changes})
            proof=project()
            evidence,pending=proof['evidence'],proof['pending']
            self.assertEqual(proof['recordedAt'],102)
            for changed in ({'actual_gateway':{}},{'now':1000},{'live':{**live,'registryImage':'sha256:'+'0'*64}}):
                with self.assertRaises(Denied):project(**changed)
            wrong_live=copy.deepcopy(live);wrong_live['delivery']['registryCheckpoint']['eventDigest']='0'*64
            with self.assertRaises(Denied):project(live=wrong_live)
            params=maintenance_evidence.paired_completion_params(pending,pair,holds,evidence,now=102)
            wrong=copy.deepcopy(evidence);wrong['observations']['registry']['healthy']=False
            with self.assertRaises(Denied):
                maintenance_evidence.paired_completion_params({**pending,'proofDigest':sc.digest(wrong)},pair,holds,wrong,now=102)
            with self.assertRaises(Denied):
                maintenance_evidence.paired_completion_params(pending,pair,holds,evidence,now=1000)
            before=self.domain.snapshot()
            self.domain._protected_verify=lambda req:True
            append_real=self.store._append_in_transaction
            def fail_final(db,req,recorded_at):
                if req['operationId']==mc.paired_operation_id(pair['attemptId'],'gateway',closing=True):
                    raise Denied('FIXTURE_FINAL_APPEND_FAILED')
                return append_real(db,req,recorded_at)
            with patch.object(self.store,'_append_in_transaction',side_effect=fail_final):
                with self.assertRaisesRegex(Denied,'FIXTURE_FINAL_APPEND_FAILED'):
                    self.domain.protected_complete_pair(pair,params,actor='owner-release-controller',recorded_at=102)
            self.assertEqual(self.domain.snapshot(),before)
            def complete(readback,now=102,recorded_at=102):
                with (patch.object(boot,'_successor_inputs',return_value=(final_config,target,final_config['semantic'])),
                      patch.object(boot.os,'statvfs',return_value=SimpleNamespace(f_flag=os.ST_RDONLY if readback else 0)),
                      patch('time.time',return_value=now)):
                    return boot.complete_frozen_pair(sealed['profileDigest'],pair=pair,holds=holds,
                        pending=pending,evidence=evidence,recorded_at=recorded_at,readback=readback)
            seed.return_value=(pending,mc.latest_projection(pending,committed=True,registry_digest=sc.digest(holds)))
            absent=complete(True)
            self.assertEqual(absent['notApplied']['result'],'PROTECTED_PAIR_COMPLETION_NOT_APPLIED')
            self.assertIsNone(absent['recovery'])
            with self.assertRaisesRegex(Denied,'MAINTENANCE_COMPLETION_OBSERVATION_UNVERIFIED'):
                complete(False,now=1000)
            expired=complete(True,now=1000)
            recovery=expired['recovery']
            self.assertEqual(recovery['phase'],'RECOVERY_HOLD')
            self.assertEqual(recovery['generation'],pending['generation'])
            self.assertEqual(recovery['proofDigest'],sc.digest(expired['notApplied']))
            self.assertEqual(self.domain.snapshot(),before)
            recovery_pin=mc.latest_projection(recovery,committed=True,registry_digest=sc.digest(holds))
            mc.latest_startup(recovery,recovery_pin,holds)
            with self.assertRaises(Denied):
                mc.latest_startup(recovery,recovery_pin,{**holds,'holds':holds['holds'][:1]})
            wrong=copy.deepcopy(expired['notApplied']);wrong['checkpoint']['eventDigest']='0'*64
            with self.assertRaises(Denied):
                maintenance_evidence.paired_recovery_record(pending,pair,holds,evidence,wrong,now=1000)
            with self.assertRaises(Denied):
                maintenance_evidence.paired_recovery_record(pending,pair,holds,evidence,expired['notApplied'],now=102)
            seed.return_value=(pending,mc.latest_projection(pending,committed=True,registry_digest='0'*64))
            with self.assertRaisesRegex(Denied,'SOURCE_PAIRED_COMPLETION_PHASE_CHANGED'):complete(False)
            self.assertEqual(self.domain.snapshot(),before)
            record=recovery
            seed.return_value=(record,recovery_pin)
            self.assertEqual(backup(True),backup_result)
            with self.assertRaises(Denied):backup(False)
            live['observedAt']=1001
            live['delivery']['maintenancePhase']=record['phase']
            live['delivery']['sourceDelivery']['interlockDigest']=sc.digest(record)
            proof=project(now=1002)
            evidence,pending=proof['evidence'],proof['pending']
            params=maintenance_evidence.paired_completion_params(pending,pair,holds,evidence,now=1002)
            seed.return_value=(pending,mc.latest_projection(pending,committed=True,registry_digest=sc.digest(holds)))
            original_complete=ReleaseDomain.protected_complete_pair
            def lose_close_ack(domain,*a,**kw):
                original_complete(domain,*a,**kw)
                raise OSError('fixture completion ACK lost')
            with patch.object(ReleaseDomain,'protected_complete_pair',lose_close_ack):
                with self.assertRaisesRegex(OSError,'completion ACK lost'):complete(False,now=1002,recorded_at=1002)
            with patch.object(ReleaseDomain,'protected_complete_pair',side_effect=AssertionError('replayed completion')):
                output=complete(True,now=2000,recorded_at=1002)
                self.assertEqual(complete(True,now=2000,recorded_at=1002),output)
            result=output['readback']
            self.domain._protected_verify=None
            self.assertEqual(self.domain.protected_complete_pair_readback(pair,params,actor='owner-release-controller'),result)
            self.assertEqual(self.domain.protected_complete_pair(pair,params,actor='owner-release-controller',recorded_at=1002),result)
            normal=maintenance_evidence.paired_normal_record(pending,pair,evidence,result)
            self.assertEqual(normal,output['normal'])
            self.assertEqual(normal['phase'],'NORMAL')
            self.assertEqual(normal['proofDigest'],sc.digest(result))
            self.assertEqual(self.domain.maintenance_snapshot()['holds'],[])
            self.assertEqual(self.reopen().snapshot(),self.domain.snapshot())
            wrong=copy.deepcopy(result);wrong['closeReceipts'][0]['operationId']=uid()
            with self.assertRaises(Denied):
                maintenance_evidence.paired_normal_record(pending,pair,evidence,wrong)

            # Second release on the completed bootstrap journal: retain
            # historical evidence and reseal without a second migration.
            import shutil
            from fortis_approvals.integrations.registry_contracts import maintenance_seal as seal_contract
            req=self.merge(number=292,targets=targets)
            self.domain.register_source(req)
            prepared=self.root/'next-prepared';shutil.copytree(target,prepared)
            cfg2=copy.deepcopy(final_config)
            for k,name,data in (('peerKeyDigest','semantic-peer.key',b'g'*32),
                                ('frameKeyDigest','semantic-frame.key',b'h'*32)):
                (prepared/name).write_bytes(data)
                cfg2['semantic'][k]=hashlib.sha256(data).hexdigest()
            (prepared/'profile.json').write_bytes(sc.canonical(cfg2).encode())
            next_pin=sc.digest(cfg2)
            dest=self.root/'next-final'
            stage_dir=self.root/'next-state'
            reserve_dir=self.root/'next-reserve'
            roots={'registry':dest,'gateway':self.root/'next-gateway','state':stage_dir,'backup':reserve_dir}
            for path in roots.values():path.mkdir(mode=0o700)
            nonce=uid()
            seed.return_value=(normal,mc.latest_projection(normal,committed=True,registry_digest=None))
            with patch.object(boot,'_successor_inputs',return_value=(cfg2,prepared,cfg2['semantic'])), \
                 patch.object(boot,'_BOOTSTRAP_INCUMBENT_CONFIG',target/'profile.json'), \
                 patch.object(pt,'_check_owner_readonly_mount'):
                material=boot.inspect_ordinary_pair(next_pin,incumbent_profile_sha256=sealed['profileDigest'],
                    source_sha=req['observation']['mergeSha'],normal=normal)
                witness={'schemaDigest':'1'*64,'companionDigest':'2'*64,'authorityWitnessDigest':'3'*64}
                checked2={'gateway':{**gateway,'result':'ORDINARY_GATEWAY_MATERIAL_ONLY',
                    'releaseNonce':nonce,'companion':witness,'binding':material['binding']},
                    'registry':material,'artifacts':{'gateway':'4'*64,'registry':'5'*64},
                    'roots':{k:{'device':path.stat().st_dev,'inode':path.stat().st_ino}
                             for k,path in roots.items()}}
                auth={'attemptId':uid(),'recordedAt':2001,'sourceRecordDigest':'6'*64,
                    'targetGeneration':'7'*64,'targetNonce':nonce,'normalDigest':sc.digest(normal),
                    'compatibilityDigest':sc.digest(checked2)}
                intent={'schemaVersion':1,'normal':normal,'authorization':auth,'compatibility':checked2}
                pair2=mc.ordinary_pair_intent(intent)
                self.domain._protected_verify=lambda req:True
                self.domain.protected_begin_pair(pair2,actor='owner-release-controller',recorded_at=2001)
                rb=self.domain.protected_pair_begin_readback(pair2,actor='owner-release-controller')
                drain=mc.paired_draining_record(normal,pair2,rb['receipts'],rb['holdSnapshot'],
                    target_generation=auth['targetGeneration'],recorded_at=2001)
                begin2={'result':'PROTECTED_PAIR_BEGIN_READBACK_ONLY','intentDigest':sc.digest(intent),
                    'pair':pair2,**rb,'draining':drain,'registryDigest':sc.digest(rb['holdSnapshot'])}
                check={'result':'FREEZE_BINDINGS_MATCH_ONLY','interlockDigest':sc.digest(drain),
                    'registryDigest':begin2['registryDigest'],'stateReceiptDigest':sc.digest(frozen),
                    'companionDigest':witness['companionDigest'],'workerAttestationDigest':'8'*64,
                    'attemptId':auth['attemptId'],'restrictionDigest':drain['attempt']['restrictionDigest']}
                check_record=seal_contract.checked_transitions(check,drain)['checked']
                stop=seal_contract.apply_stop_plan(check_record,check,{'sourceRecordDigest':auth['sourceRecordDigest'],
                    'checkedRecordDigest':'9'*64,'targetImageId':'sha256:'+pair2['artifacts']['gateway']})
                pub={'schema':'fortis-successor-maintenance-publication-v2','state':'Committed',
                    'sourceRecordHash':auth['sourceRecordDigest'],'record':stop['next'],'digest':sc.digest(stop['next']),
                    'previous':check_record,'registryDigest':begin2['registryDigest'],
                    'previousRegistryDigest':begin2['registryDigest']}
                seed.return_value=(pub['record'],mc.latest_projection(pub['record'],committed=True,registry_digest=pub['registryDigest']))
                ordinary={'intent':intent,'check':check,'sourceReceipt':frozen,'stop':stop}
                held_source=self.domain.snapshot()
                def stage_copy(verify):
                    def flags(path):
                        return SimpleNamespace(f_flag=os.ST_RDONLY if Path(path)!=stage_dir or verify else 0)
                    with patch.object(boot.os,'statvfs',side_effect=flags), \
                         patch.object(ir,'read_controller_begin',return_value={'intent':intent,'revoked':False}):
                        return boot.frozen_pair_backup(next_pin,pair=pair2,holds=rb['holdSnapshot'],
                            phase_record=stop['next'],verify_only=verify,target=stage_dir,
                            expected_target=checked2['roots']['state'],ordinary={**ordinary,'begin':begin2,'publication':pub})
                staged=stage_copy(False)
                self.assertEqual(stage_copy(True),staged)
                self.assertEqual(stage_copy(False),staged)
                stage_path=stage_dir/self.store.path.name
                def next_seal(verify):
                    def flags(path):
                        return SimpleNamespace(f_flag=os.ST_RDONLY if Path(path)!=dest or verify else 0)
                    with patch.object(boot.os,'statvfs',side_effect=flags), \
                         patch.object(boot,'STATE_PATH',stage_path), \
                         patch.object(pt,'_retained_source_evidence',side_effect=fixture_retained), \
                         patch.object(ir,'read_controller_begin',return_value={'intent':intent,'revoked':False}):
                        return boot.seal_bootstrap_registry_material(next_pin,review_sha256=None,evidence_sha256=None,
                            source_sha=req['observation']['mergeSha'],checked=checked2,authorization=auth,
                            seed=normal,begin=begin2,publication=pub,verify_only=verify,
                            expected_target=checked2['roots']['registry'],target=dest,
                            ordinary={'intent':intent,'check':check,'sourceReceipt':frozen,'stop':stop})
                actual_next=next_seal(False)
                self.assertEqual(next_seal(True),actual_next)
                self.assertEqual(actual_next['generation'],auth['targetGeneration'])
                self.assertEqual(actual_next['fileHashes']['bootstrap-evidence.json'],evidence_pin)
            # Continue the same ordinary staged DB through the existing
            # backup/promote/completion path. The old held source is retained.
            pair,holds=pair2,rb['holdSnapshot']
            record=staged['final']['record']
            self.assertEqual(actual_next['handoff'],staged['final']['handoff'])
            final_config=mc.staged_registry_profile(cfg2,handoff=actual_next['handoff'],staged_record=record)
            target,sealed,reserve=dest,actual_next,reserve_dir
            with patch.object(boot,'STATE_PATH',stage_path):
                record=mc.validate_transition(record,{**record,'phase':'BACKUP_FROZEN',
                    'previousDigest':sc.digest(record),'sequence':record['sequence']+1,'proofDigest':'1'*64})
                seed.return_value=(record,mc.latest_projection(record,committed=True,registry_digest=sc.digest(holds)))
                backup_result=backup(False)
                self.assertEqual(backup(True),backup_result)
                record=mc.validate_transition(record,{**record,'phase':'PROMOTE_FROZEN',
                    'previousDigest':sc.digest(record),'sequence':record['sequence']+1,'proofDigest':'2'*64})
                seed.return_value=(record,mc.latest_projection(record,committed=True,registry_digest=sc.digest(holds)))
                self.assertEqual(backup(True),backup_result)
                live={**live,'gatewayImage':'sha256:'+pair['artifacts']['gateway'],
                    'registryImage':'sha256:'+pair['artifacts']['registry'],'observedAt':2002,
                    'delivery':{'latestPin':True,'maintenancePhase':record['phase'],'generation':record['generation'],
                        'sourceDelivery':{'interlockDigest':sc.digest(record)},
                        'registryCheckpoint':{**backup_result['checkpoint'],'registryDigest':sc.digest(holds)}}}
                proof=project(now=2003)
                evidence,pending=proof['evidence'],proof['pending']
                seed.return_value=(pending,mc.latest_projection(pending,committed=True,registry_digest=sc.digest(holds)))
                self.assertEqual(complete(True,now=2003,recorded_at=2003)['notApplied']['result'],
                                 'PROTECTED_PAIR_COMPLETION_NOT_APPLIED')
                with patch.object(ReleaseDomain,'protected_complete_pair',lose_close_ack):
                    with self.assertRaisesRegex(OSError,'completion ACK lost'):
                        complete(False,now=2003,recorded_at=2003)
                with patch.object(ReleaseDomain,'protected_complete_pair',side_effect=AssertionError('replayed ordinary completion')):
                    output=complete(True,now=2400,recorded_at=2003)
                    self.assertEqual(complete(True,now=2400,recorded_at=2003),output)
                normal2=output['normal']
                self.assertEqual(normal2,maintenance_evidence.paired_normal_record(pending,pair,evidence,output['readback']))
                self.assertEqual(normal2['phase'],'NORMAL')
                self.assertEqual(normal2['generation'],auth['targetGeneration'])
                from fortis_approvals.registry.release_event_journal import ReleaseEventJournal
                staged_journal=ReleaseEventJournal(stage_path,instance_id=self.instance,scope=self.scope,
                    expected_legacy=pins['legacyWitness'],transition_digest=pins['transitionDigest'])
                staged_domain=pt.staged_domain(staged_journal,dest,final_config['semantic'])
                self.assertEqual(staged_domain.maintenance_snapshot()['holds'],[])
                mc.latest_startup(normal2,mc.latest_projection(normal2,committed=True,registry_digest=None),
                                  staged_domain.maintenance_snapshot())
            self.assertEqual(self.domain.snapshot(),held_source)
            self.assertEqual(len(self.domain.maintenance_snapshot()['holds']),2)


    def test_ordinary_controller_begin_mount_and_wire_readback(self):
        import os
        import stat
        from types import SimpleNamespace
        from fortis_approvals.deploy import github_pilot_helpers as host
        from fortis_approvals.extensions import maintenance_interlock_reader as ir
        from fortis_approvals.integrations.registry_contracts import maintenance_contract as mc, semantic_wire as wire
        from fortis_approvals.registry.protected_source_write import ProtectedSourceWrite,SOURCE_MOUNT
        from fortis_approvals.registry.semantic_unix_service import SemanticFrameService
        from fortis_approvals.tests.test_maintenance_gate import Controller,OLD,NEW
        subjects=mc.paired_subjects(tc.REPOSITORY)
        self.subjects=[subjects['gateway'],subjects['registry']]
        for profile in (self.profile,self.successor):
            for i,row in enumerate(profile['subjects']):
                row.update(subject=self.subjects[i],resources=['registry-read'],
                           dependencies=[self.subjects[1]] if i==0 else [])
                if profile is self.successor:row['maintenance']=maintenance(True,True)
        self.domain=self.reopen();self.service.domain=self.domain
        self.domain.register_source(self.transition())
        self.domain.register_source(self.merge(targets=[{'subject':s,'actions':['image-rebuild']} for s in self.subjects]))
        self.domain.register_source(self.merge(number=289,targets=[]))
        view=self.domain.snapshot()
        normal=Controller(self.instance,self.witness['scopeDigest']).record
        binding=dict(instanceId=self.instance,scopeDigest=self.witness['scopeDigest'],
            profileDigest=view['profileDigest'],generation=OLD,internalActor='controller-internal',
            peerKeyDigest='1'*64,frameKeyDigest='2'*64,socketPath='/run/registry/socket',
            readerUid=10001,readerGid=10001,authorityDigest='3'*64,interlockDigest=sc.digest(normal))
        nonce=uid()
        checked=dict(gateway=dict(result='ORDINARY_GATEWAY_MATERIAL_ONLY',profileDigest='4'*64,
            sourceDigest='5'*64,releaseNonce=nonce,incumbentProfileDigest='6'*64,
            companion=dict(schemaDigest='7'*64,companionDigest=sc.digest({'schemaVersion':1,'parentStates':{}}),authorityWitnessDigest='9'*64),
            binding=binding),registry=dict(result='ORDINARY_REGISTRY_MATERIAL_ONLY',
            profileDigest='a'*64,incumbentProfileDigest='b'*64,binding=binding,
            checkpoint={k:view[k] for k in ('sourceRevision','sourceCursor','snapshotRevision','eventDigest','profileDigest')},
            items={'gateway':self.params(0),'registry':self.params(1)},holdSnapshot=self.domain.maintenance_snapshot()),
            artifacts={'gateway':'c'*64,'registry':'d'*64})
        intent=dict(schemaVersion=1,normal=normal,compatibility=checked,authorization=dict(
            attemptId=uid(),sourceRecordDigest='e'*64,targetGeneration=NEW,targetNonce=nonce,
            recordedAt=100,normalDigest=sc.digest(normal),compatibilityDigest=sc.digest(checked)))
        # Actual candidate Registry package replay on a disposable copy.
        # Only host mount identity and installed source phase are fixtures.
        import hashlib
        from fortis_approvals.registry import owner_functional_v1_bootstrap as boot
        from fortis_approvals.registry import protected_transition as pt
        from contextlib import nullcontext
        prepared=self.root/'prepared';prepared.mkdir(mode=0o700)
        incumbent=self.root/'incumbent';incumbent.mkdir(mode=0o700)
        pins=dict(generation=OLD,successorProfileDigest=view['profileDigest'],
            legacyProfileDigest=sc.digest(self.profile),legacyWitness=self.witness,
            transitionDigest=self.pin,internalActor=binding['internalActor'])
        configs=[]
        for i,base in enumerate((incumbent,prepared)):
            keys={name:bytes([10+i*2+j])*32 for j,name in enumerate(('semantic-peer.key','semantic-frame.key'))}
            for name,data in keys.items():
                (base/name).write_bytes(data);(base/name).chmod(0o600)
            conf=dict(schemaVersion=3,instanceId=self.instance,scope=self.scope,
                registryStatePath=str(self.store.path),socketPath='/run/registry/socket',readerUid=10001,readerGid=10001,
                semantic={**pins,'peerKeyDigest':hashlib.sha256(keys['semantic-peer.key']).hexdigest(),
                    'frameKeyDigest':hashlib.sha256(keys['semantic-frame.key']).hexdigest()},
                sourceWrite={'latestPin':True,'interlockDigest':sc.digest(normal),'policyAuthorityDigest':binding['authorityDigest']})
            (base/'profile.json').write_text(sc.canonical(conf));(base/'profile.json').chmod(0o600)
            configs.append(conf)
        for name,value in (('legacy-release-profile.json',self.profile),('successor-release-profile.json',self.successor)):
            (prepared/name).write_text(sc.canonical(value));(prepared/name).chmod(0o600)
        old,new=configs
        with patch.object(boot,'STATE_PATH',self.store.path),patch.object(boot,'_BOOTSTRAP_INCUMBENT_CONFIG',incumbent/'profile.json'), \
             patch.object(boot,'_successor_inputs',return_value=(new,prepared,new['semantic'])), \
             patch('fortis_approvals.r7_registry_reader_mount._check_owner_readonly_mount'), \
             patch.object(pt,'_check_owner_readonly_mount'), \
             patch.object(ir,'read_latest_interlock',return_value=(normal,{'registryDigest':None})), \
             patch.object(ir.InterlockReservations,'exclusive',return_value=nullcontext(True)):
            material=boot.inspect_ordinary_pair(sc.digest(new),incumbent_profile_sha256=sc.digest(old),
                source_sha=self.params(0)['source']['sourceSha'],normal=normal)
            self.assertEqual(material['checkpoint'],checked['registry']['checkpoint'])
            self.assertEqual(material['items'],checked['registry']['items'])
            self.assertEqual(material['holdSnapshot'],checked['registry']['holdSnapshot'])
            with self.assertRaisesRegex(Denied,'SOURCE_ORDINARY_PAIR_DESIRED_CHANGED'):
                boot.inspect_ordinary_pair(sc.digest(new),incumbent_profile_sha256=sc.digest(old),
                    source_sha='0'*40,normal=normal)
        self.assertEqual(self.domain.snapshot(),view)
        checked['registry']=material
        checked['gateway']['binding']=material['binding']
        binding=material['binding']
        stage=self.root/'ordinary-stage';stage.mkdir(mode=0o700)
        checked['roots']={k:{'device':stage.stat().st_dev,'inode':stage.stat().st_ino+i}
                          for i,k in enumerate(('state','gateway','registry','backup'))}
        intent['authorization']['compatibilityDigest']=sc.digest(checked)
        pair=mc.ordinary_pair_intent(intent)
        root=self.root/'interlock';root.mkdir()
        latest=self.root/'anchor';latest.mkdir()
        for path,value in ((root/'record.json',normal),(latest/'record.json',
                mc.latest_projection(normal,committed=True,registry_digest=None))):
            path.write_text(sc.canonical(value));path.chmod(0o444)
        writer=object.__new__(ProtectedSourceWrite)
        writer._root=SOURCE_MOUNT;writer._dynamic=True
        writer._pins=dict(instance_id=self.instance,scope_digest=binding['scopeDigest'],generation=OLD)
        writer._profile_digest=binding['profileDigest'];writer._config={'policyAuthorityDigest':binding['authorityDigest']}
        writer._internal=binding['internalActor'];writer.reservations=ir.InterlockReservations(root)
        service=SemanticFrameService(self.service,frame_key=b'f'*32,generation=OLD,
            authorize=lambda *_:True,provenance=lambda *_:None,internal_actor=writer._internal,
            controller_begin=writer.controller_begin)
        def call(readback,actor=writer._internal,digest=sc.digest(intent)):
            req=wire.request(dict(schemaVersion=2,requestId=uid(),instanceId=self.instance,
                scopeDigest=binding['scopeDigest'],generation=OLD,actor=actor,action='CONTROLLER_PAIRED_BEGIN',
                body=dict(intentDigest=digest,readback=readback)),**service.pins)
            return wire.open_reply(service.key,req,service.dispatch(wire.seal(service.key,req)))
        actual_stat=os.fstat
        def owner_stat(fd):
            info=actual_stat(fd)
            path=Path(os.readlink('/proc/self/fd/'+str(fd)))
            if path not in (root,latest) and path.parent not in (root,latest):
                return info
            return SimpleNamespace(st_uid=0,st_mode=(stat.S_IFDIR|0o555) if stat.S_ISDIR(info.st_mode) else info.st_mode,
                st_nlink=info.st_nlink,st_size=info.st_size,st_dev=info.st_dev,st_ino=info.st_ino)
        read_intent=ir.read_controller_begin
        with patch.object(os,'fstat',side_effect=owner_stat), \
             patch('fortis_approvals.r7_registry_reader_mount._exact_mountinfo',return_value=True), \
             patch.object(ir,'_check_owner_readonly_mount'), \
             patch.object(ir,'read_controller_begin',side_effect=lambda **kw:read_intent(root=latest,**kw)), \
             patch.object(writer,'_phase',return_value=normal):
            with patch.object(os,'geteuid',return_value=0):
                result=host.successor_begin_intent({'action':'successor_begin_intent','intent':intent},root=root,latest_root=latest)
                self.assertEqual(result,{'intentDigest':sc.digest(intent),'pairDigest':sc.digest(pair),'revoked':False})
                self.assertEqual(host.successor_begin_intent({'action':'successor_begin_intent','intent':intent},
                    root=root,latest_root=latest),result)
                changed=copy.deepcopy(intent);changed['authorization']['attemptId']=uid()
                with self.assertRaisesRegex(RuntimeError,'PILOT_CONTROLLER_BEGIN_INTENT_EXISTS'):
                    host.successor_begin_intent({'action':'successor_begin_intent','intent':changed},root=root,latest_root=latest)
            with self.assertRaisesRegex(Denied,'MAINTENANCE_CONTROLLER_BEGIN_DENIED'):call(False,actor='agent-1')
            with self.assertRaisesRegex(Denied,'MAINTENANCE_CONTROLLER_BEGIN_CHANGED'):call(False,digest='0'*64)
            self.assertTrue(call(True)['exactPredecessor'])
            with patch('time.time',return_value=401):
                with self.assertRaisesRegex(Denied,'MAINTENANCE_CONTROLLER_BEGIN_STALE'):call(False)
            self.assertEqual(self.domain.snapshot(),view)
            with patch.object(os,'geteuid',return_value=0),patch('time.time',return_value=401):
                revoked=host.successor_begin_intent({'action':'successor_begin_intent','mode':'revoke','intent':intent},
                    root=root,latest_root=latest)
                self.assertTrue(revoked['revoked'])
                self.assertTrue(host.successor_begin_intent({'action':'successor_begin_intent','intent':intent},
                    root=root,latest_root=latest)['revoked'])
            absence=call(True)
            self.assertTrue(absence['revoked'])
            old_digest=sc.digest(intent)
            # Even a clock rollback cannot reopen revoked authorization.
            with patch('time.time',return_value=100):
                with self.assertRaisesRegex(Denied,'MAINTENANCE_CONTROLLER_BEGIN_STALE'):call(False)
            next_intent=copy.deepcopy(intent)
            next_intent['authorization'].update(attemptId=uid(),recordedAt=401)
            with patch.object(os,'geteuid',return_value=0):
                changed=copy.deepcopy(absence);changed['checkpoint']['sourceRevision']+=1
                with self.assertRaisesRegex(Denied,'MAINTENANCE_CONTROLLER_BEGIN_REPLACEMENT_CHANGED'):
                    host.successor_begin_intent({'action':'successor_begin_intent','mode':'replace','intent':next_intent,'absence':changed},
                        root=root,latest_root=latest)
                replacement={'action':'successor_begin_intent','mode':'replace','intent':next_intent,'absence':absence}
                projected=host.successor_begin_intent(replacement,root=root,latest_root=latest)
                self.assertFalse(projected['revoked'])
                self.assertEqual(host.successor_begin_intent(replacement,root=root,latest_root=latest),projected)
            with self.assertRaisesRegex(Denied,'MAINTENANCE_CONTROLLER_BEGIN_CHANGED'):call(False,digest=old_digest)
            intent=next_intent
            def next_call(readback):
                return call(readback,digest=sc.digest(intent))
            original=self.domain.protected_begin_pair
            def lose_ack(*args,**kwargs):
                original(*args,**kwargs)
                raise OSError('fixture lost acknowledgement')
            with patch('time.time',return_value=401),patch.object(self.domain,'protected_begin_pair',side_effect=lose_ack):
                with self.assertRaisesRegex(OSError,'lost acknowledgement'):next_call(False)
            actual=next_call(True)
            self.assertEqual(actual['result'],'PROTECTED_PAIR_BEGIN_READBACK_ONLY')
            self.assertEqual(actual['draining']['previousDigest'],sc.digest(normal))
            self.assertEqual(actual['registryDigest'],sc.digest(self.domain.maintenance_snapshot()))
            self.assertEqual(next_call(False),actual)
            # Revocation cannot erase a previously committed begin.
            with patch.object(os,'geteuid',return_value=0),patch('time.time',return_value=702):
                self.assertTrue(host.successor_begin_intent({'action':'successor_begin_intent','mode':'revoke','intent':intent},
                    root=root,latest_root=latest)['revoked'])
            self.assertEqual(next_call(True),actual)
            # A fresh Registry process recovers the original readback; the
            # normal Gateway admission still refuses this unpaired phase.
            restarted=self.reopen()
            projection=mc.latest_projection(normal,committed=True,registry_digest=None)
            with patch('fortis_approvals.registry.protected_source_write.read_latest_interlock',
                       return_value=(normal,projection)):
                writer.verify_startup(restarted,restarted.snapshot())
                with self.assertRaisesRegex(Denied,'MAINTENANCE_STARTUP_HANDOFF_REQUIRED'):
                    mc.latest_startup(normal,projection,restarted.maintenance_snapshot())
                with patch.object(ir,'read_controller_begin',side_effect=Denied('FIXTURE_MISSING_INTENT')):
                    with self.assertRaisesRegex(Denied,'FIXTURE_MISSING_INTENT'):
                        writer.verify_startup(restarted,restarted.snapshot())
                with patch.object(writer,'_begin_result',side_effect=Denied('FIXTURE_BAD_RECEIPTS')):
                    with self.assertRaisesRegex(Denied,'FIXTURE_BAD_RECEIPTS'):
                        writer.verify_startup(restarted,restarted.snapshot())
            with self.assertRaisesRegex(Denied,'SOURCE_MAINTENANCE_BLOCKED'):
                restarted.source_preflight(self.merge(number=290)['proposal'])
            # Actual durable phase projection, passive restart, and same
            # freeze inspector under the same reservation inode.
            draining=actual['draining'];pin=actual['registryDigest']
            phase_request={'action':'successor_interlock_publish','mode':'publish','previous':normal,'next':draining,
                           'latest':{'previousRegistryDigest':None,'nextRegistryDigest':pin}}
            with patch.object(os,'geteuid',return_value=0):
                host.successor_interlock_publish(phase_request,root=root,latest_root=latest)
                host.successor_interlock_publish({**phase_request,'mode':'commit'},root=root,latest_root=latest)
            read_phase=ir.read_latest_interlock
            def phase(**_):
                return read_phase(instance_id=self.instance,scope_digest=binding['scopeDigest'],
                                               generation=OLD,root=root,latest_root=latest)
            with patch('fortis_approvals.registry.protected_source_write.read_latest_interlock',side_effect=phase):
                writer.verify_startup(restarted,restarted.snapshot())
                with self.assertRaisesRegex(Denied,'MAINTENANCE_STARTUP_HANDOFF_REQUIRED'):
                    mc.latest_startup(*phase(),restarted.maintenance_snapshot())
            from fortis_approvals.extensions.maintenance_gate import MaintenanceGate
            gate=MaintenanceGate(instance_id=self.instance,scope_digest=binding['scopeDigest'],generation=OLD,
                read_interlock=lambda:(phase()[0],phase()[1]['interlockDigest']),
                read_holds=restarted.maintenance_snapshot,shared_reservations=writer.reservations,read_latest=phase)
            drain=gate.drain_status()
            self.assertTrue(drain['ready'])
            state={'sha256':{'approvals.sqlite':'a'*64},'summary':{
                'requestStates':{},'uncertainRequestIds':[],'approvedRequestIds':[],
                'native':{'jobStates':{},'preservedClaimedIds':[]}}}
            companion={'schemaVersion':1,'parentStates':{}}
            # This synthetic Gateway state receipt is independently pinned
            # by the fixture; the Registry replay and phase files are real.
            payload={'action':'successor_freeze_inspect','latestPin':True,
                'instanceId':self.instance,'scopeDigest':binding['scopeDigest'],'generation':OLD,
                'interlockDigest':sc.digest(draining),'registryDigest':pin,
                'coreSchemaDigest':checked['gateway']['companion']['schemaDigest'],
                'companionDigest':checked['gateway']['companion']['companionDigest'],
                'attemptId':draining['attempt']['attemptId'],'restrictionDigest':draining['attempt']['restrictionDigest'],
                'subject':draining['attempt']['subject'],'targetSourceSha':draining['attempt']['source']['sourceSha'],
                'preserveUncertainIds':[],'preserveClaimedIds':[],'drain':drain,
                'prepare':{'intentDigest':sc.digest(intent),'sourceRecordDigest':intent['authorization']['sourceRecordDigest'],
                           'ownerConfirmed':True,'begin':actual}}
            with patch.object(ir,'InterlockReservations',return_value=writer.reservations), \
                 patch.object(ir,'read_latest_interlock',side_effect=phase), \
                 patch.object(host,'inspect_state',return_value=state), \
                 patch('fortis_approvals.extensions.composite_preservation.sealed_companion',return_value=companion), \
                 patch('fortis_approvals.r7_registry_reader_mount._check_owner_readonly_mount'):
                with self.assertRaisesRegex(Denied,'PILOT_SUCCESSOR_WORKER_ATTESTATION_REQUIRED'):
                    host.successor_freeze_inspect({**payload,'prepare':{**payload['prepare'],'ownerConfirmed':False}})
                with self.assertRaisesRegex(Denied,'PILOT_SUCCESSOR_FREEZE_BEGIN_CHANGED'):
                    host.successor_freeze_inspect({**payload,'prepare':{**payload['prepare'],'sourceRecordDigest':'0'*64}})
                result=host.successor_freeze_inspect(payload)
                self.assertEqual(result['payload']['stateDigest'],sc.digest(state))
                self.assertEqual(result['seal']['stateReceiptDigest'],sc.digest(state))
                self.assertEqual(result['transitions']['draining'],draining)
                self.assertNotIn('prepare',result['payload'])
                self.assertEqual(host.successor_freeze_inspect(result['payload'])['seal'],result['seal'])
                def publish(previous,next_record):
                    req={'action':'successor_interlock_publish','mode':'publish','previous':previous,'next':next_record,
                        'latest':{'previousRegistryDigest':pin,'nextRegistryDigest':pin}}
                    with patch.object(os,'geteuid',return_value=0):
                        host.successor_interlock_publish(req,root=root,latest_root=latest)
                        host.successor_interlock_publish({**req,'mode':'commit'},root=root,latest_root=latest)
                frozen,checked_phase=(result['transitions'][k] for k in ('frozen','checked'))
                publish(draining,frozen);publish(frozen,checked_phase)
                verify={k:v for k,v in result['payload'].items() if k!='drain'}
                verify.update(action='successor_freeze_apply_verify',interlockDigest=sc.digest(checked_phase),
                    checkSeal=result['seal'],draining=draining,frozen=frozen)
                stop=host.successor_freeze_inspect({**verify,'prepareStop':{
                    'sourceRecordDigest':intent['authorization']['sourceRecordDigest'],
                    'checkedRecordDigest':'0'*64,'targetImageId':'sha256:'+intent['compatibility']['artifacts']['gateway']}})['stopIntent']
                publish(checked_phase,stop['next'])
                stopped={**verify,'interlockDigest':sc.digest(stop['next']),'stoppedIntent':stop}
                self.assertEqual(host.successor_freeze_inspect(stopped)['sourceReceipt'],state)
                wrong=copy.deepcopy(stop);wrong['checkedRecordDigest']='1'*64
                with self.assertRaisesRegex(RuntimeError,'PILOT_SUCCESSOR_FREEZE_BINDING_INVALID'):
                    host.successor_freeze_inspect({**stopped,'stoppedIntent':wrong})
                publication={'schema':'fortis-successor-maintenance-publication-v2','state':'Committed',
                    'sourceRecordHash':intent['authorization']['sourceRecordDigest'],'record':stop['next'],
                    'digest':sc.digest(stop['next']),'registryDigest':pin,'previous':checked_phase,'previousRegistryDigest':pin}
                proof={'intent':intent,'begin':actual,'check':result['seal'],'sourceReceipt':state,'stop':stop,'publication':publication}
                # Reuse actual confined copy and independently replay the
                # same SQLite journal and paired receipts in the target.
                from fortis_approvals.integrations.registry_contracts.maintenance_seal import ordinary_handover
                final=ordinary_handover(**{k:v for k,v in proof.items() if k!='sourceReceipt'},source_receipt=state)
                self.assertEqual(final['record']['phase'],'STAGED_TARGET_FROZEN')
                with self.assertRaises(Denied):
                    ordinary_handover(intent,actual,result['seal'],state,stop,{**publication,'registryDigest':'0'*64})
                with patch.object(boot,'STATE_PATH',self.store.path), \
                     patch.object(boot,'_successor_inputs',return_value=(new,prepared,new['semantic'])), \
                     patch.object(pt,'_check_owner_readonly_mount'):
                    def clone(readback):
                        with patch.object(boot.os,'statvfs',return_value=SimpleNamespace(f_flag=os.ST_RDONLY if readback else 0)):
                            return boot.frozen_pair_backup(sc.digest(new),pair=actual['pair'],holds=actual['holdSnapshot'],
                                phase_record=stop['next'],verify_only=readback,expected_target=checked['roots']['state'],
                                target=stage,ordinary=proof)
                    # Use exact profile pin from independently inspected material
                    # (not the synthetic Gateway profile used by this fixture).
                    self.assertEqual(sc.digest(new),material['profileDigest'])
                    copied=clone(False)
                    self.assertEqual(copied['result'],'PAIRED_STAGED_STATE_COPY_ONLY')
                    self.assertEqual(copied['final'],final)
                    self.assertEqual(clone(True),copied)
                    self.assertEqual(clone(False),copied)
                publish(stop['next'],final['record'])
                self.assertEqual(mc.latest_startup(final['record'],mc.latest_projection(final['record'],
                    committed=True,registry_digest=pin),actual['holdSnapshot']),final['record'])
                # Return uses the ORIGINAL journal, not the staged copy.
                # Actual phase files and original paired replay are exercised.
                before=self.domain.snapshot()
                source_bytes=self.store.path.read_bytes()
                staged_bytes=(stage/self.store.path.name).read_bytes()
                staged_publication={**publication,'record':final['record'],'digest':sc.digest(final['record']),
                    'previous':stop['next']}
                for name in ('legacy-release-profile.json','successor-release-profile.json'):
                    (incumbent/name).write_bytes((prepared/name).read_bytes())
                    (incumbent/name).chmod(0o600)
                def mounted(**kw):
                    return read_phase(**kw,root=root,latest_root=latest)
                def restore(pub,**overrides):
                    args={'intent':intent,'begin':actual,'check':result['seal'],'source_receipt':state,
                          'stop':stop,'publication':pub,**overrides}
                    with patch.object(boot,'STATE_PATH',self.store.path), \
                         patch.object(boot,'_successor_inputs',return_value=(old,incumbent,old['semantic'])), \
                         patch.object(pt,'_check_owner_readonly_mount'), \
                         patch.object(ir,'read_latest_interlock',side_effect=mounted):
                        return boot.read_ordinary_return(sc.digest(old),**args)
                with self.assertRaises(Denied):
                    restore(staged_publication,source_receipt={**state,'sha256':{}})
                with self.assertRaises(Denied):
                    restore({**staged_publication,'registryDigest':'0'*64})
                recovery=restore(staged_publication)
                self.assertEqual(recovery['record']['phase'],'RECOVERY_HOLD')
                self.assertEqual(recovery['record']['generation'],OLD)
                self.assertEqual(recovery['checkpoint'],actual['checkpoint'])
                publish(final['record'],recovery['record'])
                recovered_pub={**staged_publication,'record':recovery['record'],
                    'digest':sc.digest(recovery['record']),'previous':final['record']}
                self.assertEqual(restore(recovered_pub),recovery)
                self.assertEqual(self.store.path.read_bytes(),source_bytes)
                self.assertEqual((stage/self.store.path.name).read_bytes(),staged_bytes)
                self.assertEqual(self.domain.snapshot(),before)
                self.assertEqual(mc.latest_startup(*phase(),self.domain.maintenance_snapshot()),recovery['record'])
                with patch('fortis_approvals.registry.protected_source_write.read_latest_interlock',side_effect=phase):
                    writer.verify_startup(self.domain,self.domain.snapshot())
                self.assertEqual(gate.verify_startup(release_active=True)[0],recovery['record'])
                with self.assertRaises(Denied):
                    gate.verify_startup(release_active=False)
                with self.assertRaisesRegex(Denied,'SOURCE_MAINTENANCE_BLOCKED'):
                    self.domain.source_preflight(self.merge(number=290)['proposal'])
            self.assertEqual(self.reopen().snapshot(),self.domain.snapshot())
            self.assertEqual(len(actual['receipts']),2)
            self.assertIsNone(self.component(0)['installed']);self.assertIsNone(self.component(1)['installed'])

    def test_protected_pair_atomic_begin_and_exact_frozen_admission(self):
        from contextlib import nullcontext
        from fortis_approvals.integrations.registry_contracts import maintenance_contract as mc
        from fortis_approvals.extensions.maintenance_gate import MaintenanceGate,Coordinate,matching_holds
        from fortis_approvals.extensions.maintenance_interlock_reader import InterlockReservations
        from fortis_approvals.tests.test_maintenance_gate import Controller,OLD,NEW

        subjects=mc.paired_subjects(tc.REPOSITORY)
        self.subjects=[subjects['gateway'],subjects['registry']]
        for profile in (self.profile,self.successor):
            for i,row in enumerate(profile['subjects']):
                row['subject']=self.subjects[i]
                row['resources']=['registry-read']
                row['dependencies']=[self.subjects[1]] if i==0 else []
                if profile is self.successor:row['maintenance']=maintenance(True,True)
        self.domain=self.reopen();self.service.domain=self.domain
        self.domain.register_source(self.transition())
        self.domain.register_source(self.merge(targets=[{'subject':s,'actions':['image-rebuild']} for s in self.subjects]))
        # An independently accounted no-deploy edge may advance cursor without
        # altering either Desired. The paired intent must pin both facts.
        self.domain.register_source(self.merge(number=289,targets=[]))
        view=self.domain.snapshot()
        pair={'schemaVersion':1,'attemptId':uid(),
              'checkpoint':{k:view[k] for k in ('sourceRevision','sourceCursor','snapshotRevision','eventDigest','profileDigest')},
              'items':{'gateway':self.params(0),'registry':self.params(1)},
              'artifacts':{'gateway':'a'*64,'registry':'b'*64},
              'controllerReceiptDigest':'c'*64,'compatibilityReadbackDigest':'d'*64}
        self.assertNotEqual(pair['checkpoint']['sourceCursor'],pair['items']['gateway']['source']['sourceSha'])
        with self.assertRaisesRegex(Denied,'REGISTRY_DOMAIN_DEPENDENCY_UNVERIFIED'):
            self.write('begin_release',self.params(0))
        def begin(value=pair):
            return self.domain.protected_begin_pair(value,actor='controller',recorded_at=100)
        with self.assertRaisesRegex(Denied,'REGISTRY_PROTECTED_PROOF_REQUIRED'):begin()
        self.domain._protected_verify=lambda req:req['pair']==pair
        wrong=copy.deepcopy(pair);wrong['items']['registry']['subject']['environment']='production'
        with self.assertRaisesRegex(Denied,'MAINTENANCE_PAIRED_SCOPE'):begin(wrong)
        self.domain._protected_verify=lambda _:True
        stale=copy.deepcopy(pair);stale['checkpoint']['eventDigest']='0'*64
        with self.assertRaisesRegex(Denied,'REGISTRY_PROTECTED_PAIR_CHANGED'):begin(stale)
        stale=copy.deepcopy(pair);stale['items']['gateway']['expected']['targetRevision']+=1
        with self.assertRaisesRegex(Stale,'REGISTRY_DOMAIN_STATE_STALE'):begin(stale)
        # Failure after first append must roll back both rows, not expose a
        # one-sided hold or fabricate a successful group result.
        append=self.store._append_in_transaction
        def fail_second(db,req,recorded_at):
            if req['operationId']==pair['attemptId']:raise Denied('FIXTURE_SECOND_APPEND_FAILED')
            return append(db,req,recorded_at)
        with patch.object(self.store,'_append_in_transaction',side_effect=fail_second):
            with self.assertRaisesRegex(Denied,'FIXTURE_SECOND_APPEND_FAILED'):begin()
        self.assertEqual(self.domain.snapshot(),view)
        # Unrelated pre-existing active hold cannot be absorbed into the pair.
        attempt=self.write('begin_release',self.params(1))['operationId']
        active=self.domain.snapshot()
        busy={**pair,'checkpoint':{k:active[k] for k in pair['checkpoint']},
              'items':{'gateway':self.params(0),'registry':self.params(1)}}
        with self.assertRaisesRegex(Denied,'REGISTRY_PROTECTED_PAIR_SCOPE_OR_HOLD'):begin(busy)
        close={**self.params(1),'attemptId':attempt,'controllerReceiptDigest':'e'*64,
               'readbackDigest':'f'*64,'observedAt':100}
        self.domain.protected_event('RELEASE_HOLD_CLOSED',close,actor='controller',operation_id=uid(),recorded_at=100)
        fresh=self.domain.snapshot()
        pair.update(checkpoint={k:fresh[k] for k in pair['checkpoint']},
                    items={'gateway':self.params(0),'registry':self.params(1)})
        receipts=begin()
        self.assertEqual([r['operationId'] for r in receipts],
                         [mc.paired_operation_id(pair['attemptId'],'registry'),pair['attemptId']])
        self.assertTrue(all(r['eventKind']=='PROTECTED_PAIRED_BEGIN' and not r['technicalInstallationVerified']
                            for r in receipts))
        self.domain._protected_verify=None
        self.assertEqual(begin(),receipts)
        self.assertIsNone(self.component(0)['installed']);self.assertIsNone(self.component(1)['installed'])
        self.assertEqual(self.reopen().snapshot(),self.domain.snapshot())
        holds=self.domain.maintenance_snapshot()
        gateway=next(h for h in holds['holds'] if h['subject']==subjects['gateway'])
        registry=next(h for h in holds['holds'] if h['subject']==subjects['registry'])
        self.assertEqual(gateway['pairDigest'],sc.digest(pair));self.assertEqual(registry['pairDigest'],sc.digest(pair))
        self.assertEqual(gateway['pairId'],registry['pairId'])
        ctrl=Controller(self.store.instance_id,self.witness['scopeDigest'])
        ctrl.advance('DRAINING',attempt={**{k:gateway[k] for k in ('attemptId','subject','source','restrictionDigest')},
            'sourceGeneration':OLD,'targetGeneration':NEW})
        lock=InterlockReservations(self.root)
        def gate(generation=OLD,snapshot=None):
            return MaintenanceGate(instance_id=self.store.instance_id,scope_digest=self.witness['scopeDigest'],
                generation=generation,read_interlock=ctrl.read,read_holds=(lambda:snapshot) if snapshot is not None
                else self.domain.maintenance_snapshot,shared_reservations=lock)
        with patch.object(lock,'drained',return_value=True):
            self.assertTrue(gate().drain_status()['ready'])
            for changed in ([gateway],[registry], [gateway,{**registry,'pairDigest':'0'*64}],
                            [gateway,{**registry,'source':{**registry['source'],'sourceSha':'0'*40}}]):
                self.assertFalse(gate(snapshot={**holds,'holds':changed}).drain_status()['ready'])
            self.assertFalse(matching_holds([gateway,registry,{**registry,'attemptId':uid()}],ctrl.record['attempt']))
        with patch.object(lock,'reserve',side_effect=nullcontext):
            source=gate()
            source._latest=lambda:(ctrl.record,mc.latest_projection(ctrl.record,committed=True,
                                                  registry_digest=sc.digest(holds)))
            for phase in ('DRAINING','FROZEN_BEFORE_CHECK','CHECK_SEALED','APPLY_STOP'):
                if phase!='DRAINING':ctrl.advance(phase)
                record,snapshot,projection=source.verify_running_source_delivery()
                self.assertEqual((record,snapshot,projection['interlockDigest']),(ctrl.record,holds,ctrl.pin))
                with self.assertRaisesRegex(Denied,'MAINTENANCE_STARTUP_HANDOFF_REQUIRED'):
                    source.verify_startup()
        ctrl.advance('STAGED_TARGET_FROZEN',generation=NEW)
        handoff={'role':'staged_target','attemptId':pair['attemptId'],
            'restrictionDigest':gateway['restrictionDigest'],'interlockDigest':ctrl.pin,'registryDigest':sc.digest(holds)}
        with patch.object(lock,'reserve',side_effect=nullcontext):
            gate(NEW).verify_startup(handoff)
            with self.assertRaisesRegex(Denied,'RELEASE_MAINTENANCE'):
                with gate(NEW).reserve(Coordinate('github','merge_pull_request')):pass
            for changed in ([gateway],[gateway,{**registry,'pairDigest':'0'*64}]):
                snapshot={**holds,'holds':changed}
                with self.assertRaisesRegex(Denied,'MAINTENANCE_STARTUP_HOLD_CHANGED'):
                    gate(NEW,snapshot).verify_startup({**handoff,'registryDigest':sc.digest(snapshot)})
            # Real Gateway and Registry composition both read the current
            # independently supplied pin, not the original profile digest.
            from types import SimpleNamespace
            from fortis_approvals.extensions import successor_runtime as runtime
            from fortis_approvals.registry import protected_source_write as writer
            from fortis_approvals.integrations.registry_contracts import merge_evidence
            def latest(**pins):
                record=ctrl.read()[0]
                sc.need(record['generation']==pins['generation'],'MAINTENANCE_STATE_UNKNOWN')
                return record,mc.latest_projection(record,committed=True,
                    registry_digest=None if record['phase']=='NORMAL' else sc.digest(holds))
            from fortis_approvals.registry.semantic_unix_service import SemanticFrameService
            from fortis_approvals.extensions.semantic_gateway import GatewayRegistrySemanticTransport
            from fortis_approvals.integrations.registry.candidate_gateway import GatewayRegistryUnixCandidateRead
            from fortis_approvals.tests.test_semantic_wire import WireTests
            peer=object.__new__(GatewayRegistryUnixCandidateRead)
            peer._instance,peer._scope=self.store.instance_id,self.witness['scopeDigest']
            peer._peer_key=b'p'*32
            peer._reader=(10001,10001);peer._registry=(0,20002,20002)
            transport=GatewayRegistrySemanticTransport(peer,frame_key=b'f'*32,
                generation=NEW,internal_actor='internal')
            self.frames=SemanticFrameService(self.service,frame_key=transport.key,generation=NEW,
                authorize=lambda actor,action,body:actor=='internal',
                provenance=lambda _:None,internal_actor='internal',
                source_delivery=lambda:registered.delivery_binding())
            transport._exchange=lambda *args,**kw:WireTests.exchange(self,*args,**kw)
            peer._semantic_transport=transport
            peer._semantic_profile_digest=fresh['profileDigest']
            receiver=object.__new__(runtime.ProtectedRegistrySuccessor)
            config={'latestPin':True,'interlockDigest':handoff['interlockDigest'],'successorDigest':'a'*64,
                    'frozenHandoff':handoff,'companionDigest':'b'*64}
            receiver._raw=sc.canonical(config);peer._successor_config=receiver
            writer_config={'ownerActor':'owner','ownerName':'owner','target':'fortis-approvals',
                           'policyAuthorityDigest':'a'*64,'interlockDigest':handoff['interlockDigest'],
                           'validatorRevision':'a'*40,'impactBinding':{},'buildPins':{},'latestPin':True}
            with (patch.object(runtime,'read_latest_interlock',side_effect=latest),
                  patch.object(runtime,'InterlockReservations',return_value=lock),
                  patch.object(writer,'read_latest_interlock',side_effect=latest),
                  patch.object(writer.ProtectedSourceWrite,'_check_source'),
                  patch.object(merge_evidence,'mount_binding',return_value={'device':1,'inode':2})):
                registered=writer.ProtectedSourceWrite(writer_config,journal=self.store,generation=NEW,
                    internal='internal',profile_digest=fresh['profileDigest'],producer_uid=10001)
                candidate=receiver._maintenance_gate(peer,config)
                def check_current():
                    registered.verify_startup(self.domain,self.domain.snapshot())
                    delivery=registered.delivery_binding()
                    self.assertEqual(delivery['interlockDigest'],ctrl.pin)
                    self.assertEqual(receiver._delivery(peer,config,readonly=False,
                        profile={'sourceDelivery':delivery}),delivery)
                    checked=receiver.checked_delivery(peer,expected_interlock_digest=ctrl.pin)
                    self.assertEqual(checked['sourceDelivery'],delivery)
                    self.assertEqual(checked['registryCheckpoint']['registryDigest'],sc.digest(self.domain.maintenance_snapshot()))
                    self.assertEqual(checked['maintenancePhase'],ctrl.record['phase'])
                    self.assertIs(checked['latestPin'],True)
                    if ctrl.pin!=handoff['interlockDigest']:
                        with self.assertRaisesRegex(Denied,'R7_REGISTRY_SUCCESSOR_CONTROLLER_PIN_CHANGED'):
                            receiver.checked_delivery(peer,expected_interlock_digest=handoff['interlockDigest'])
                candidate.verify_startup(handoff,release_active=False)
                check_current()
                for phase in ('BACKUP_FROZEN','PROMOTE_FROZEN','COMPLETION_PENDING'):
                    ctrl.advance(phase)
                    with self.assertRaisesRegex(Denied,'MAINTENANCE_STARTUP_HANDOFF_REQUIRED'):
                        candidate.verify_startup(handoff,release_active=False)
                    candidate.verify_startup(handoff,release_active=True)
                    check_current()
                completion_record=copy.deepcopy(ctrl.record)
                # Neither runtime may admit ordinary new effects during the
                # later phases, even if its original sealed pin differs.
                self.assertFalse(registered.authorize('internal','SOURCE_PREFLIGHT',{}))
                with self.assertRaisesRegex(Denied,'RELEASE_MAINTENANCE'):
                    with candidate.reserve(Coordinate('github','merge_pull_request')):pass
            ctrl.advance('RECOVERY_HOLD',generation=OLD)
            gate().verify_startup({**handoff,'role':'return_source','interlockDigest':ctrl.pin})
        self.domain._protected_verify=lambda _:True
        wrong_artifact={**self.params(1),'source':{**registry['source'],'artifactSha256':'0'*64},
             'attemptId':registry['attemptId'],'controllerReceiptDigest':'e'*64,'readbackDigest':'f'*64,
             'observedAt':100,'coveredRecordIds':[self.params(1)['expected']['desiredRecordId']]}
        with self.assertRaisesRegex(Denied,'REGISTRY_PROTECTED_PAIR_ARTIFACT_CHANGED'):
            self.domain.protected_event('TECHNICAL_OBSERVATION_ACCEPTED',wrong_artifact,
                                        actor='controller',operation_id=uid(),recorded_at=100)
        self.assertEqual(self.domain.maintenance_snapshot(),holds)

        # Successful paired completion must not expose a half-closed pair.
        # The real verifier is deliberately not supplied by this fixture.
        def observation(i,role):
            return {**self.params(i),'source':{**self.params(i)['source'],'artifactSha256':pair['artifacts'][role]},
                'attemptId':mc.paired_operation_id(pair['attemptId'],role),
                'controllerReceiptDigest':('1' if i==0 else '2')*64,
                'readbackDigest':('3' if i==0 else '4')*64,'observedAt':100,
                'coveredRecordIds':sorted({a['recordId'] for a in self.component(i)['actionCoverage']})}
        def close_items():
            return {role:{k:v for k,v in observation(i,role).items() if k!='coveredRecordIds'}
                    for i,role in enumerate(('gateway','registry'))}
        def close_pair(items=None):
            return self.domain.protected_close_pair(pair,close_items() if items is None else items,
                                                    actor='controller',recorded_at=100)
        with self.assertRaises(Denied):close_pair()
        for i,role in enumerate(('gateway','registry')):
            self.domain.protected_event('TECHNICAL_OBSERVATION_ACCEPTED',observation(i,role),
                actor='controller',operation_id=uid(),recorded_at=100)
            if i==0:
                with self.assertRaises(Denied):close_pair()
        items=close_items()
        observed=self.domain.snapshot()
        with self.assertRaisesRegex(Denied,'REGISTRY_PROTECTED_PAIR_CLOSE_REQUIRED'):
            self.domain.protected_event('RELEASE_HOLD_CLOSED',items['registry'],
                actor='controller',operation_id=uid(),recorded_at=100)
        wrong=copy.deepcopy(items);wrong['gateway']['readbackDigest']='0'*64
        with self.assertRaisesRegex(Denied,'REGISTRY_PROTECTED_PAIR_COMPLETION_UNVERIFIED'):close_pair(wrong)
        self.domain._protected_verify=None
        with self.assertRaisesRegex(Denied,'REGISTRY_PROTECTED_PROOF_REQUIRED'):close_pair(items)
        self.domain._protected_verify=lambda _:True
        def fail_close(db,req,recorded_at):
            if req['operationId']==mc.paired_operation_id(pair['attemptId'],'gateway',closing=True):
                raise Denied('FIXTURE_SECOND_CLOSE_FAILED')
            return append(db,req,recorded_at)
        with patch.object(self.store,'_append_in_transaction',side_effect=fail_close):
            with self.assertRaisesRegex(Denied,'FIXTURE_SECOND_CLOSE_FAILED'):close_pair(items)
        self.assertEqual(self.domain.snapshot(),observed)
        self.assertEqual(len(self.domain.maintenance_snapshot()['holds']),2)
        with self.assertRaisesRegex(Denied,'REGISTRY_PROTECTED_COMPLETION_RECEIPTS_MISSING'):
            self.domain.protected_pair_completion_readback(pair,items,actor='controller')
        closed=close_pair(items)
        self.assertEqual([r['operationId'] for r in closed],
            [mc.paired_operation_id(pair['attemptId'],r,closing=True) for r in ('registry','gateway')])
        self.assertTrue(all(r['eventKind']=='PROTECTED_PAIRED_CLOSE' for r in closed))
        self.domain._protected_verify=None
        self.assertEqual(close_pair(items),closed)
        self.assertEqual(self.domain.maintenance_snapshot()['holds'],[])
        self.assertTrue(all(self.component(i)['planningState']=='DEPLOYED' for i in (0,1)))
        self.assertEqual(self.reopen().snapshot(),self.domain.snapshot())
        original=self.store.path.read_bytes()
        from fortis_approvals.registry import protected_transition as protected
        with (patch.object(protected,'_check_owner_readonly_mount'),
              patch.object(protected,'staged_domain',side_effect=lambda store,*_:self.reopen(store=store))):
            # Real read-only SQLite scratch replay; no live writer or proof
            # callback, source bytes remain unchanged.
            recovered=protected.frozen_paired_completion_readback(self.store,self.store.path.parent,{},
                pair=pair,items=items,actor='controller')
        self.assertEqual(recovered['closeReceipts'],closed)
        self.assertEqual(recovered['holdSnapshot'],self.domain.maintenance_snapshot())
        self.assertEqual(recovered['result'],'PROTECTED_PAIR_COMPLETION_READBACK_ONLY')
        self.assertEqual(self.store.path.read_bytes(),original)
        with self.assertRaises(Denied):
            self.domain.protected_pair_completion_readback(pair,wrong,actor='controller')
        with self.assertRaises(Denied):
            self.domain.protected_pair_completion_readback(pair,items,actor='other')
        self.domain.register_source(self.merge(number=290,targets=[]))
        with self.assertRaisesRegex(Denied,'REGISTRY_PROTECTED_COMPLETION_CHECKPOINT_CHANGED'):
            self.domain.protected_pair_completion_readback(pair,items,actor='controller')
        # The same immutable staged profile admits a lawful NORMAL after
        # completion and a later no-deploy source event, not stale hold pins.
        ctrl.record=completion_record;ctrl.pin=sc.digest(completion_record)
        ctrl.advance('NORMAL')
        with (patch.object(lock,'reserve',side_effect=nullcontext),
              patch.object(runtime,'read_latest_interlock',side_effect=latest),
              patch.object(runtime,'InterlockReservations',return_value=lock),
              patch.object(writer,'read_latest_interlock',side_effect=latest),
              patch.object(merge_evidence,'mount_binding',return_value={'device':1,'inode':2})):
            check_current()
            current=self.domain.snapshot()
            receipt=receiver.checked_delivery(peer,expected_interlock_digest=ctrl.pin)
            self.assertEqual(receipt['registryCheckpoint']['sourceCursor'],current['sourceCursor'])
            self.assertNotEqual(receipt['registryCheckpoint']['registryDigest'],handoff['registryDigest'])
            original=transport.profile
            def wrong_profile(**kw):
                result=original(**kw)
                result['sourceCheckpoint']['registryDigest']=handoff['registryDigest']
                return result
            with patch.object(transport,'profile',side_effect=wrong_profile):
                with self.assertRaisesRegex(Denied,'R7_REGISTRY_SUCCESSOR_CHECKPOINT_CHANGED'):
                    receiver.checked_delivery(peer,expected_interlock_digest=ctrl.pin)

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

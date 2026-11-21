"""Registry transaction mechanics with synthetic independent witness and plan."""
import copy
from concurrent.futures import ThreadPoolExecutor
import os
from pathlib import Path
import sqlite3
import tempfile
import threading
import unittest
import uuid

from fortis_approvals.core import Conflict, Denied, Stale
from fortis_approvals.registry import state_journal as s


def uid():return str(uuid.uuid4())


def sample(scope,*,deployment=True):
    eid=uid()
    cp={'schemaVersion':1,'instanceId':uid(),'revision':1,'eventDigest':'e'*64}
    audit={'mergeSha':'b'*40,'baseSha':scope['baselineSha'],'headSha':'c'*40,'number':7,
           'treeSha':'d'*40,'evidenceId':eid,'evidenceDigest':'e'*64,'ownerRequestId':uid(),
           'collectorCheckpoint':cp,'registryReviewDigest':'a'*64,
           'policyReferenceDigest':scope['policyReferenceDigest'],'impactDigest':'f'*64,
           'classification':'deployment' if deployment else 'no-deployment','sourceDependencyTargets':[]}
    subject={'repository':s.REPOSITORY,'targetId':'app','environment':'production'}
    identity={**subject,'desiredSourceSha':'b'*40,'catalogCommitSha':scope['baselineSha'],
              'catalogSha256':scope['catalogSha256']}
    row={'subjectId':s._hash(subject),'recordId':s._hash(identity),'identity':identity,
         'componentId':'app-runtime','resourceIds':['state'],'requiresComponentIds':[],
         'buildUnitId':None,'deploymentProcedure':'procedure.md','verification':['source-ci'],
         'requiredActions':['config-deploy'],'evidenceIds':[eid],'artifact':{'state':'NOT_BUILT','digest':None},
         'actual':None,'planningState':'PLANNED_UNVERIFIED','evidenceVerified':False}
    o={**scope,'selectedMainSha':'b'*40,'collectorCheckpoint':cp,'lineageDigest':'d'*64,
       'componentObservationDigest':'c'*64,'rangeClassification':'DEPLOYMENT_CANDIDATE' if deployment else 'NO_DEPLOYMENT_CANDIDATE',
       'mergeAudit':[audit],'recordCandidates':[row] if deployment else [],'sourceDependencyRequirements':[]}
    plan={'result':'INITIAL_RANGE_PLAN_CANDIDATE','observation':o,'observationDigest':s._hash(o),
          'evidenceVerified':False,'admissionAllowed':False,'deploymentAllowed':False,
          'missingProofs':['PROTECTED_ENROLLMENT_AND_RESOURCE_ATTESTATION',
                          'AUTHENTICATED_COLLECTOR_AND_TRUSTED_CLOCK','PROTECTED_REGISTRY_STATE_AND_RECOVERY']}
    return {'schemaVersion':1,'issuer':s.COLLECTOR,'repository':s.REPOSITORY,'evidenceId':uid(),'plan':plan}


class RegistryStateTests(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory();self.addCleanup(tmp.cleanup)
        self.root=Path(tmp.name);self.path=self.root/'registry.sqlite'
        self.instance=uid()
        self.scope={'repository':s.REPOSITORY,'enrollmentId':uid(),'baselineSha':'a'*40,
                    'baselineDigest':'a'*64,'catalogSha256':'b'*64,'bindingDigest':'c'*64,
                    'policyReferenceDigest':'d'*64}
        self.anchor=s.genesis(self.instance,self.scope);self.evidence=sample(self.scope)
        self.calls=0;self.op=uid()
        self.store=s.RegistryStateJournal.initialize(self.path,**self.options())

    def read(self,eid):
        self.calls+=1
        self.assertEqual(eid,self.evidence['evidenceId'])
        return copy.deepcopy(self.evidence)

    def options(self):
        return dict(instance_id=self.instance,scope=self.scope,
                    anchor_reader=lambda:copy.deepcopy(self.anchor),plan_reader=self.read)

    def args(self):
        return dict(actor=s.PLANNER,operation_id=self.op,evidence_id=self.evidence['evidenceId'],
                    evidence_digest=s._hash(self.evidence),expected_revision=0)

    def append(self,**kw):return self.store.append_initial(**(self.args()|kw))

    def confirm(self,pending):
        self.assertEqual(pending['result'],'UNKNOWN_OUTCOME')
        self.assertEqual(pending['previousCheckpoint'],self.anchor)
        self.anchor=copy.deepcopy(pending['pendingCheckpoint'])

    def counts(self):
        with sqlite3.connect(self.path) as db:
            return tuple(db.execute('SELECT COUNT(*) FROM '+t).fetchone()[0] for t in ('operations','records'))

    def test_original_recovery_and_candidate_cursor(self):
        self.assertEqual(self.store.checkpoint()['candidateCursor'],self.scope['baselineSha'])
        args=self.args();pending=self.append()
        self.assertNotIn('receipt',pending)
        self.assertEqual(self.counts(),(1,1))
        with self.assertRaisesRegex(Denied,'ANCHOR_MISMATCH'):self.store.checkpoint()
        self.store=s.RegistryStateJournal(self.path,**self.options())
        self.evidence['plan']={}
        self.assertEqual(self.store.append_initial(**args),pending)
        self.confirm(pending)
        r=self.store.operation(actor=s.PLANNER,operation_id=self.op)
        self.assertEqual(r['result'],'ANCHORED_CANDIDATE_TRANSACTION')
        self.assertEqual(r,self.store.append_initial(**args))
        self.assertEqual(self.calls,1)
        self.assertEqual(self.store.checkpoint()['candidateCursor'],'b'*40)
        self.assertFalse(r['receipt']['admissionAllowed'])
        self.assertEqual(self.counts(),(1,1))

    def test_no_deploy_only_records_original_audit(self):
        self.evidence=sample(self.scope,deployment=False)
        self.confirm(self.append())
        self.assertEqual(self.counts(),(1,0))
        r=self.store.operation(actor=s.PLANNER,operation_id=self.op)
        self.assertEqual(r['receipt']['recordIds'],[])
        self.assertEqual(r['receipt']['rangeClassification'],'NO_DEPLOYMENT_CANDIDATE')
        self.assertFalse(r['receipt']['evidenceVerified'])

    def test_cas_replay_conflict_and_suffix_stop(self):
        with self.assertRaises(Stale):self.append(expected_revision=1)
        self.assertEqual(self.calls,0)
        pending=self.append()
        with self.assertRaises(Conflict):self.append(evidence_digest='f'*64)
        with self.assertRaisesRegex(Denied,'ANCHOR_MISMATCH'):self.append(operation_id=uid())
        self.confirm(pending)
        with self.assertRaises(Stale):self.append(operation_id=uid())
        with self.assertRaisesRegex(Denied,'SUFFIX_UNSUPPORTED'):
            self.append(operation_id=uid(),expected_revision=1)
        self.assertEqual(self.counts(),(1,1))

    def test_bad_actor_and_evidence_digest(self):
        with self.assertRaises(Denied):self.append(actor='reader')
        self.assertEqual(self.calls,0)
        with self.assertRaisesRegex(Denied,'EVIDENCE_MISMATCH'):self.append(evidence_digest='f'*64)
        self.assertEqual(self.counts(),(0,0))

    def test_invalid_plan_and_no_fake_installed_state(self):
        original=copy.deepcopy(self.evidence)
        for field in ('actual','recordId','evidenceIds','requiredActions'):
            self.evidence=copy.deepcopy(original);plan=self.evidence['plan'];o=plan['observation']
            row=o['recordCandidates'][0];row[field]='forged'
            plan['observationDigest']=s._hash(o)
            with self.subTest(field=field),self.assertRaises(Denied):self.append()
        self.assertEqual(self.counts(),(0,0))

    def test_anchor_rollback_wrong_scope_and_unknown_operation(self):
        initial=copy.deepcopy(self.anchor);self.confirm(self.append())
        good=copy.deepcopy(self.anchor)
        self.anchor=initial
        with self.assertRaisesRegex(Denied,'ANCHOR_MISMATCH'):self.store.checkpoint()
        with self.assertRaisesRegex(Denied,'ANCHOR_MISMATCH'):
            self.store.operation(actor=s.PLANNER,operation_id=uid())
        self.anchor={**good,'scopeDigest':'f'*64}
        with self.assertRaisesRegex(Denied,'ANCHOR_INVALID'):self.store.checkpoint()
        self.anchor=good
        self.assertEqual(self.store.operation(actor=s.PLANNER,operation_id=uid()),
                         {'result':'CANDIDATE_OPERATION_NOT_FOUND'})

    def test_tampering_and_schema_drift(self):
        self.confirm(self.append())
        with sqlite3.connect(self.path) as db:
            db.execute("UPDATE records SET payload='{}'")
        with self.assertRaisesRegex(Denied,'CORRUPT'):self.store.checkpoint()
        with sqlite3.connect(self.path) as db:
            db.execute('CREATE TABLE extra(value TEXT)')
        with self.assertRaisesRegex(Denied,'SCHEMA_MISMATCH'):self.store.checkpoint()

    def test_schema_and_missing_file_not_auto_created(self):
        missing=self.root/'missing.sqlite'
        with self.assertRaises(Denied):s.RegistryStateJournal(missing,**self.options())
        self.assertFalse(missing.exists())
        with self.assertRaises(FileExistsError):s.RegistryStateJournal.initialize(self.path,**self.options())
        os.chmod(self.path,0o644)
        with self.assertRaisesRegex(Denied,'PERMISSIONS'):self.store.checkpoint()
        os.chmod(self.path,0o600)

    def test_atomic_rollback_if_record_insert_fails(self):
        # Inject failure inside the write transaction; no partial row persists.
        original=self.store._checked
        def fail(db):
            if db.execute('SELECT COUNT(*) FROM operations').fetchone()[0]:
                raise Denied('TEST_AFTER_RECORD_INSERT')
            return original(db)
        self.store._checked=fail
        with self.assertRaisesRegex(Denied,'TEST_AFTER_RECORD_INSERT'):self.append()
        self.assertEqual(self.counts(),(0,0))
        self.store._checked=original
        self.confirm(self.append())

    def test_two_concurrent_writers_only_one_local_commit(self):
        barrier=threading.Barrier(2)
        def read(eid):
            result=self.read(eid);barrier.wait(timeout=5);return result
        self.store.plan_reader=read
        def submit(operation):
            try:return self.append(operation_id=operation)['result']
            except (Denied,Stale) as e:return str(e)
        with ThreadPoolExecutor(max_workers=2) as pool:
            results=list(pool.map(submit,[self.op,uid()]))
        self.assertEqual(results.count('UNKNOWN_OUTCOME'),1)
        self.assertEqual(results.count('REGISTRY_STATE_CHECKPOINT_CHANGED'),1)
        self.assertEqual(self.counts(),(1,1))

    def test_lost_witness_after_commit_resolves_original(self):
        original=self.store._checked
        def fail(db):
            result=original(db)
            if result[1] is not None:
                self.committed=result[2]['checkpoint']
                self.store.anchor_reader=lambda:(_ for _ in ()).throw(OSError('offline'))
            return result
        self.store._checked=fail
        self.assertEqual(self.append(),{'result':'UNKNOWN_OUTCOME','operationId':self.op})
        self.assertEqual(self.counts(),(1,1))
        self.store=s.RegistryStateJournal(self.path,**self.options())
        self.anchor=self.committed
        self.assertEqual(self.append()['result'],'ANCHORED_CANDIDATE_TRANSACTION')
        self.assertEqual(self.calls,1)

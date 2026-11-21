"""Isolated Registry schema v2 suffix CAS/supersession mechanics.

Uses synthetic host plans and independent in-memory witness; not admission.
"""
import copy
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import os
import sqlite3
import tempfile
import threading
import unittest

from fortis_approvals.core import Conflict, Denied, Stale
from fortis_approvals.registry import state_journal as old
from fortis_approvals.registry import state_journal_v2 as s
from fortis_approvals.tests.test_registry_state_journal import sample,uid


def next_evidence(scope,previous,checkpoint,collector_cp,*,target='app',deploy=True):
    """Create next-range protocol with separate evidence, owner and revision."""
    snapshot=sample(scope,deployment=deploy)
    o=snapshot['plan']['observation']
    previous_sha=previous['candidateCursor']
    new_sha=('c' if previous_sha=='b'*40 else 'd')*40
    o.update(selectedMainSha=new_sha,startCursorSha=previous_sha,
             registryCursorCheckpoint=copy.deepcopy(checkpoint))
    o['collectorCheckpoint']={**collector_cp,'revision':collector_cp['revision']+1,
                              'eventDigest':('f' if collector_cp['eventDigest']!='f'*64 else '1')*64}
    m=o['mergeAudit'][0]
    m.update(baseSha=previous_sha,mergeSha=new_sha,headSha='e'*40,
             number=8 if previous_sha=='b'*40 else 9,
             collectorCheckpoint=copy.deepcopy(o['collectorCheckpoint']))
    if deploy:
        row=o['recordCandidates'][0];identity=row['identity']
        identity.update(desiredSourceSha=new_sha,targetId=target)
        subject={'repository':s.REPOSITORY,'targetId':target,'environment':identity['environment']}
        row['subjectId']=s._hash(subject);row['recordId']=s._hash(identity)
        row['evidenceIds']=[m['evidenceId']]
    snapshot['plan']['result']='SUFFIX_RANGE_PLAN_CANDIDATE'
    snapshot['plan']['observationDigest']=s._hash(o)
    return snapshot


class RegistryStateV2Tests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup)
        self.root=Path(temp.name);self.path=self.root/'v2.sqlite'
        self.scope={'repository':s.REPOSITORY,'enrollmentId':uid(),'baselineSha':'a'*40,
                    'baselineDigest':'a'*64,'catalogSha256':'b'*64,'bindingDigest':'c'*64,
                    'policyReferenceDigest':'d'*64}
        self.instance=uid();self.anchor=s.genesis_v2(self.instance,self.scope)
        self.first=sample(self.scope)
        self.current=self.first
        self.reads=0
        self.state=s.RegistryStateJournalV2.initialize(
            self.path,instance_id=self.instance,scope=self.scope,
            anchor_reader=self.witness,plan_reader=self.read)
        self.operations=[]

    def witness(self):return copy.deepcopy(self.anchor)

    def read(self,eid):
        self.reads+=1
        self.assertEqual(eid,self.current['evidenceId'])
        return copy.deepcopy(self.current)

    def args(self,*,eid=None,op=None,rev=None):
        return dict(actor=s.PLANNER,operation_id=op or uid(),evidence_id=eid or self.current['evidenceId'],
                    evidence_digest=s._hash(self.current),
                    expected_revision=self.anchor['revision'] if rev is None else rev)

    def append(self,**kwargs):
        return self.state.append_range(**(self.args()|kwargs))

    def accept(self,**kwargs):
        args=self.args()|kwargs
        result=self.state.append_range(**args)
        self.assertEqual(result['result'],'UNKNOWN_OUTCOME')
        self.assertEqual(result['previousCheckpoint'],self.anchor)
        self.anchor=copy.deepcopy(result['pendingCheckpoint'])
        receipt=self.state.operation(actor=s.PLANNER,operation_id=args['operation_id'])['receipt']
        self.assertEqual(receipt['checkpoint'],self.anchor)
        self.operations.append((args,receipt))
        return receipt

    def prepare_suffix(self,*,target='app',deploy=True):
        previous=self.operations[-1][1]
        self.current=next_evidence(self.scope,previous,self.anchor,
                      self.current['plan']['observation']['collectorCheckpoint'],
                      target=target,deploy=deploy)

    def query(self,table,columns='*'):
        with sqlite3.connect(self.path) as db:
            return db.execute('SELECT '+columns+' FROM '+table).fetchall()

    def test_initial_then_suffix_immutable_supersession(self):
        one=self.accept()
        self.assertEqual(one['checkpoint']['revision'],1)
        self.assertEqual(self.state.checkpoint()['candidateCursor'],'b'*40)
        self.prepare_suffix()
        two=self.accept()
        self.assertEqual(two['checkpoint']['revision'],2)
        self.assertEqual(two['previousCheckpoint'],one['checkpoint'])
        self.assertEqual(two['startCursorSha'],one['candidateCursor'])
        self.assertEqual(two['candidateCursor'],'c'*40)
        self.assertNotEqual(two['recordIds'],one['recordIds'])
        self.assertEqual(two['supersessions'],[{'fromRecordId':one['recordIds'][0],
                                               'toRecordId':two['recordIds'][0]}])
        self.assertEqual(len(self.query('operations')),2)
        self.assertEqual(len(self.query('records')),2)
        self.assertEqual(self.query('supersessions','from_record_id,to_record_id'),
                         [(one['recordIds'][0],two['recordIds'][0])])
        self.assertEqual(self.state.checkpoint()['candidateCursor'],'c'*40)
        self.assertEqual(self.state.operation(actor=s.PLANNER,operation_id=self.operations[0][0]['operation_id'])
                         ['receipt'],one)
        self.state=s.RegistryStateJournalV2(self.path,instance_id=self.instance,scope=self.scope,
                                             anchor_reader=self.witness,plan_reader=self.read)
        self.assertEqual(self.state.operation(actor=s.PLANNER,operation_id=self.operations[1][0]['operation_id'])
                         ['receipt'],two)
        self.assertFalse(two['admissionAllowed'])
        self.assertFalse(two['deploymentAllowed'])

    def test_no_deploy_moves_cursor_without_superseding(self):
        first=self.accept()
        self.prepare_suffix(deploy=False)
        no=self.accept()
        self.assertEqual(no['recordIds'],[])
        self.assertEqual(no['supersessions'],[])
        self.assertEqual(no['rangeClassification'],'NO_DEPLOYMENT_CANDIDATE')
        self.assertEqual(self.state.checkpoint()['candidateCursor'],'c'*40)
        self.prepare_suffix()
        third=self.accept()
        self.assertEqual(third['supersessions'],[{'fromRecordId':first['recordIds'][0],
                                                 'toRecordId':third['recordIds'][0]}])
        self.assertEqual(len(self.query('records')),2)
        self.assertEqual(len(self.query('operations')),3)

    def test_new_target_has_no_supersession(self):
        self.accept()
        self.prepare_suffix(target='dependency')
        second=self.accept()
        self.assertEqual(second['supersessions'],[])
        self.assertEqual(len(self.query('records')),2)
        self.assertEqual(len(self.query('supersessions')),0)

    def test_original_receipt_and_pending_immutable(self):
        first_op=uid();args=self.args(op=first_op)
        pending=self.state.append_range(**args)
        self.assertEqual(pending['result'],'UNKNOWN_OUTCOME')
        with self.assertRaisesRegex(Denied,'ANCHOR_MISMATCH'):self.state.checkpoint()
        self.assertEqual(self.state.append_range(**args),pending)
        with self.assertRaises(Conflict):self.state.append_range(**(args|{'evidence_digest':'f'*64}))
        self.anchor=copy.deepcopy(pending['pendingCheckpoint'])
        self.current['plan']={}
        reread=self.state.append_range(**args)
        self.assertEqual(reread['result'],'ANCHORED_CANDIDATE_TRANSACTION')
        self.assertEqual(self.reads,1)

    def test_suffix_requires_exact_previous_cursor_and_checkpoint(self):
        self.accept();self.prepare_suffix()
        original=copy.deepcopy(self.current)
        for kind in ('cursor','checkpoint','source','audit'):
            self.current=copy.deepcopy(original);o=self.current['plan']['observation']
            if kind=='cursor':o['startCursorSha']='a'*40
            if kind=='checkpoint':o['registryCursorCheckpoint']['eventDigest']='f'*64
            if kind=='source':o['selectedMainSha']='a'*40
            if kind=='audit':o['mergeAudit'][0]['baseSha']='a'*40
            self.current['plan']['observationDigest']=s._hash(o)
            with self.subTest(kind=kind),self.assertRaises(Denied):self.append()
        self.assertEqual(len(self.query('operations')),1)

    def test_previous_source_merges_not_replayed(self):
        self.accept();self.prepare_suffix()
        o=self.current['plan']['observation'];o['mergeAudit'][0]['evidenceId']=self.first['plan']['observation']['mergeAudit'][0]['evidenceId']
        o['recordCandidates'][0]['evidenceIds']=[o['mergeAudit'][0]['evidenceId']]
        self.current['plan']['observationDigest']=s._hash(o)
        with self.assertRaisesRegex(Denied,'REGISTRY_STATE_REPLAYED_MERGE'):
            self.append()
        self.assertEqual(len(self.query('operations')),1)

    def test_concurrent_suffix_cas_single_winner(self):
        self.accept();self.prepare_suffix()
        ready=threading.Barrier(2)
        def read(eid):
            result=self.read(eid);ready.wait(timeout=5);return result
        self.state.plan_reader=read
        args=self.args()
        def write(oid):
            try:return self.state.append_range(**(args|{'operation_id':oid}))['result']
            except (Denied,Stale,Conflict) as exc:return str(exc)
        with ThreadPoolExecutor(max_workers=2) as pool:
            values=list(pool.map(write,[uid(),uid()]))
        self.assertEqual(values.count('UNKNOWN_OUTCOME'),1)
        self.assertEqual(values.count('REGISTRY_STATE_CHECKPOINT_CHANGED'),1)
        self.assertEqual(len(self.query('operations')),2)
        self.assertEqual(len(self.query('supersessions')),1)

    def test_failed_suffix_insert_rolls_back_all_tables(self):
        self.accept();self.prepare_suffix()
        before=tuple(len(self.query(t)) for t in ('operations','records','supersessions'))
        previous=self.state._checked
        def fail(db):
            result=previous(db)
            if len(result[2])==2:raise Denied('INJECTED_FAILURE')
            return result
        self.state._checked=fail
        with self.assertRaisesRegex(Denied,'INJECTED_FAILURE'):self.append()
        self.state._checked=previous
        self.assertEqual(tuple(len(self.query(t)) for t in ('operations','records','supersessions')),before)
        self.accept()

    def test_corrupted_record_link_or_event_is_detected(self):
        self.accept();self.prepare_suffix();self.accept()
        for query,restore in (
            ("UPDATE supersessions SET to_record_id='faked'",
             "UPDATE supersessions SET to_record_id=(SELECT record_id FROM records WHERE revision=2)"),
            ("UPDATE operations SET event_digest='faked' WHERE revision=2",
             "UPDATE operations SET event_digest='"+self.anchor['eventDigest']+"' WHERE revision=2"),
            ("UPDATE records SET payload='{}' WHERE revision=1",None)):
            if restore is None:
                with sqlite3.connect(self.path) as db:
                    old_payload=db.execute('SELECT payload FROM records WHERE revision=1').fetchone()[0]
            with sqlite3.connect(self.path) as db:db.execute(query)
            with self.assertRaisesRegex(Denied,'REGISTRY_STATE_CORRUPT'):self.state.checkpoint()
            with sqlite3.connect(self.path) as db:
                if restore is not None:db.execute(restore)
                else:db.execute('UPDATE records SET payload=? WHERE revision=1',(old_payload,))
        self.assertEqual(self.state.checkpoint()['checkpoint'],self.anchor)

    def test_v1_append_method_cannot_run_on_v2_store(self):
        with self.assertRaisesRegex(Denied,'REGISTRY_STATE_USE_V2_APPEND_RANGE'):
            self.state.append_initial(**self.args())

    def test_cross_schema_no_auto_migration_or_witness_reuse(self):
        first=old.RegistryStateJournal
        v1root=self.root/'v1';v1root.mkdir(mode=0o700)
        p=v1root/'v1.sqlite';old_anchor=old.genesis(self.instance,self.scope)
        legacy=first.initialize(p,instance_id=self.instance,scope=self.scope,
                                anchor_reader=lambda:old_anchor,plan_reader=self.read)
        with self.assertRaises(Denied):
            s.RegistryStateJournalV2(p,instance_id=self.instance,scope=self.scope,
                                     anchor_reader=self.witness,plan_reader=self.read).checkpoint()
        self.assertTrue(p.exists())
        self.assertEqual(legacy.checkpoint()['candidateCursor'],self.scope['baselineSha'])
        with self.assertRaises(FileExistsError):
            s.RegistryStateJournalV2.initialize(p,instance_id=self.instance,scope=self.scope,
                                                 anchor_reader=self.witness,plan_reader=self.read)

    def test_anchor_rollback_and_forged_revision(self):
        first=self.accept()
        initial=copy.deepcopy(self.anchor)
        self.prepare_suffix();self.accept()
        self.anchor=initial
        with self.assertRaisesRegex(Denied,'ANCHOR_MISMATCH'):self.state.checkpoint()
        self.anchor={**self.anchor,'revision':99}
        with self.assertRaisesRegex(Denied,'ANCHOR_INVALID'):self.state.checkpoint()
        self.anchor=self.operations[-1][1]['checkpoint']
        self.assertEqual(self.state.checkpoint()['candidateCursor'],'c'*40)

    def test_schema_drift_and_private_files(self):
        with sqlite3.connect(self.path) as db:
            db.execute('CREATE TABLE extra(value TEXT)')
        with self.assertRaisesRegex(Denied,'SCHEMA_MISMATCH'):self.state.checkpoint()
        with sqlite3.connect(self.path) as db:db.execute('DROP TABLE extra')
        os.chmod(self.path,0o644)
        with self.assertRaisesRegex(Denied,'PERMISSIONS'):self.state.checkpoint()

    def test_three_versions_form_chain_without_rewriting_prior_rows(self):
        first=self.accept()
        self.prepare_suffix();second=self.accept()
        self.prepare_suffix();third=self.accept()
        self.assertEqual(len(self.query('operations')),3)
        self.assertEqual(len(self.query('records')),3)
        self.assertEqual(self.query('supersessions','from_record_id,to_record_id'),
            sorted([(first['recordIds'][0],second['recordIds'][0]),
                    (second['recordIds'][0],third['recordIds'][0])]))
        self.assertEqual(third['supersessions'],[
            {'fromRecordId':second['recordIds'][0],'toRecordId':third['recordIds'][0]}])
        self.assertEqual(self.state.checkpoint()['candidateCursor'],'d'*40)
        self.assertFalse(third['evidenceVerified'])

    def test_unknown_or_stale_anchor_cannot_admit_next_range(self):
        first=self.accept()
        self.prepare_suffix()
        operation=self.args()
        pending=self.state.append_range(**operation)
        self.assertEqual(pending['result'],'UNKNOWN_OUTCOME')
        self.assertNotIn('receipt',pending)
        with self.assertRaisesRegex(Denied,'ANCHOR_MISMATCH'):
            self.state.append_range(**(self.args()|{'operation_id':uid()}))
        with self.assertRaisesRegex(Denied,'ANCHOR_MISMATCH'):self.state.checkpoint()
        self.assertEqual(self.state.append_range(**operation),pending)
        self.anchor=copy.deepcopy(pending['pendingCheckpoint'])
        self.assertEqual(self.state.operation(actor=s.PLANNER,operation_id=operation['operation_id'])
                         ['result'],'ANCHORED_CANDIDATE_TRANSACTION')

    def test_bad_collector_revision_and_duplicate_old_approval(self):
        first=self.accept();self.prepare_suffix()
        base=copy.deepcopy(self.current)
        for kind,code in (('revision','REGISTRY_STATE_COLLECTOR_ORDER'),
                          ('instance','REGISTRY_STATE_COLLECTOR_ORDER'),
                          ('owner','REGISTRY_STATE_REPLAYED_MERGE')):
            self.current=copy.deepcopy(base);o=self.current['plan']['observation']
            if kind=='revision':o['collectorCheckpoint']['revision']=1
            if kind=='instance':o['collectorCheckpoint']['instanceId']=uid()
            if kind=='owner':
                o['mergeAudit'][0]['ownerRequestId']=self.first['plan']['observation']['mergeAudit'][0]['ownerRequestId']
            if kind in ('revision','instance'):
                o['mergeAudit'][0]['collectorCheckpoint']=copy.deepcopy(o['collectorCheckpoint'])
            self.current['plan']['observationDigest']=s._hash(o)
            with self.subTest(kind=kind),self.assertRaisesRegex(Denied,code):self.append()
        self.assertEqual(len(self.query('operations')),1)

"""Offline byte-exact orphaned worker claim carryover; never a replay or terminalization."""
import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[2]
SPEC=importlib.util.spec_from_file_location(
    'claim_state_helper',ROOT/'fortis_approvals/deploy/github_pilot_helpers.py')
H=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(H)
IDENT='2df32a24-efb1-4dac-97f6-3b66147d8944'
ACTOR='repo-sonar-read-proposal-actor'
CLAIM='55555555-5555-4555-8555-555555555555'
TARGET='offline-repository'
PARAMS={'task':'offline-task','baseSha':'a'*40,'adoptHeadSha':None}
REQUEST=dict(service='workspace',operation='create_task',target=TARGET,params=PARAMS,
             reason='Offline checked create-task fixture')
PAYLOAD={**REQUEST,'requestId':IDENT,'approvedPreview':{}}


class OrphanedClaimStateTests(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory(prefix='claim-release-offline-')
        self.addCleanup(tmp.cleanup)
        self.root=Path(tmp.name)
        self.source=self.root/'source'
        self.target=self.root/'target'
        self.source.mkdir()
        self.target.mkdir()
        private=self.source/'private'
        private.mkdir(mode=0o700)
        (private/H.MARKER).write_bytes(b'fortis-r7-unified-v1\n')
        with sqlite3.connect(private/'approvals.sqlite') as db:
            db.executescript(
                'CREATE TABLE requests(id TEXT PRIMARY KEY,actor TEXT,state TEXT,payload TEXT);'
                'CREATE TABLE events(value TEXT);')
            db.execute('INSERT INTO requests VALUES(?,?,?,?)',
                       (IDENT,ACTOR,'UNCERTAIN',json.dumps(REQUEST)))
        with sqlite3.connect(private/'owner.sqlite') as db:
            db.executescript('CREATE TABLE config(setting TEXT,value TEXT);'
                'CREATE TABLE credentials(active INTEGER,data BLOB);'
                'CREATE TABLE invitations(data BLOB);')
            db.executemany('INSERT INTO config VALUES (?,?)',[
                ('origin','http://localhost:19203'),('rpId','localhost'),('owner','owner')])
            db.execute('INSERT INTO credentials VALUES(?,?)',(1,b'offline-owner'))
        with sqlite3.connect(private/'sonar-receipts.sqlite') as db:
            db.execute('CREATE TABLE receipts(value TEXT)')
        with sqlite3.connect(private/'github-receipts.sqlite') as db:
            db.execute('CREATE TABLE receipts(request_id TEXT,result TEXT)')
        for name in H.NATIVE_DIRS:
            (private/name).mkdir(mode=0o700)
        (private/'native-git/git/runner/empty.config').write_bytes(b'')
        with sqlite3.connect(private/'native-git/workflow.sqlite') as db:
            db.executescript(
                'CREATE TABLE artifacts(actor TEXT,digest TEXT,metadata TEXT);'
                'CREATE TABLE tasks(actor TEXT,repo TEXT,task TEXT,data TEXT);'
                'CREATE TABLE jobs(id TEXT PRIMARY KEY,actor TEXT,payload TEXT,state TEXT,'
                'claim TEXT,result TEXT,error TEXT);')
            db.execute('INSERT INTO jobs VALUES(?,?,?,?,?,?,?)',(
                IDENT,ACTOR,json.dumps(PAYLOAD),'CLAIMED',CLAIM,None,None))
        for name in [*H.FILES,'github-receipts.sqlite',
                     'native-git/workflow.sqlite','native-git/git/runner/empty.config']:
            (private/name).chmod(0o600)
        self.kw=dict(github=True,native=True,uid=os.geteuid(),gid=os.getegid())
        self.good=dict(preserve_uncertain_ids=[IDENT],preserve_claimed_ids=[IDENT])

    def inspect(self,**override):
        return H.inspect_state(self.source,**(self.kw|self.good|override))

    def update(self,query,params=(),table='native-git/workflow.sqlite'):
        with sqlite3.connect(self.source/'private'/table) as db:
            db.execute(query,params)

    def test_explicit_claimed_id_preserves_all_bytes_and_unknown_state(self):
        result=self.inspect(require_exact_uncertain=True,require_exact_claimed=True)
        self.assertEqual(result['summary']['native']['preservedClaimedIds'],[IDENT])
        self.assertEqual(result['summary']['native']['jobStates'],{'CLAIMED':1})
        with self.assertRaisesRegex(RuntimeError,'UNREVIEWED_CLAIMED_JOBS'):
            H.inspect_state(self.source,**self.kw,preserve_uncertain_ids=[IDENT])
        before=(self.source/'private/native-git/workflow.sqlite').read_bytes()
        copied=H.clone_state(self.source,self.target,**self.kw,**self.good)
        self.assertEqual(copied,result)
        self.assertEqual(before,(self.target/'private/native-git/workflow.sqlite').read_bytes())
        with sqlite3.connect(self.target/'private/native-git/workflow.sqlite') as db:
            self.assertEqual(db.execute('SELECT state,error,result FROM jobs WHERE id=?',
                                        (IDENT,)).fetchone(),('CLAIMED',None,None))

    def test_collector_state_clones_with_existing_worker_history(self):
        from fortis_approvals.integrations.github.gateway.functional_review_runtime import initialize_functional_state
        import uuid
        initialize_functional_state(self.source/'private',str(uuid.uuid4()))
        before=self.inspect()
        self.assertGreater(before['summary']['registryCollector']['entries'],0)
        copied=H.clone_state(self.source,self.target,**self.kw,**self.good)
        self.assertEqual(copied,before)
        self.assertEqual(H.inspect_state(self.target,**self.kw,**self.good),before)
        directory=self.source/'private/registry-functional-v1'
        (directory/'capture.sqlite-wal').write_bytes(b'pending')
        with self.assertRaises(RuntimeError):
            self.inspect()

    def test_collector_clone_sets_modes_before_giving_up_ownership(self):
        from uuid import uuid4
        from fortis_approvals.integrations.github.gateway.functional_review_runtime import (
            initialize_functional_state,
        )

        initialize_functional_state(self.source/'private', str(uuid4()))
        before = self.inspect()
        transferred = set()
        chmod, fchmod = os.chmod, os.fchmod
        chown, fchown = os.chown, os.fchown

        def path_identity(path):
            row = os.stat(path)
            return row.st_dev, row.st_ino

        def fd_identity(fd):
            row = os.fstat(fd)
            return row.st_dev, row.st_ino

        def chmod_as_owner(path, mode):
            if path_identity(path) in transferred:
                raise PermissionError('chmod after chown without CAP_FOWNER')
            return chmod(path, mode)

        def fchmod_as_owner(fd, mode):
            if fd_identity(fd) in transferred:
                raise PermissionError('fchmod after fchown without CAP_FOWNER')
            return fchmod(fd, mode)

        def transfer_path(path, uid, gid):
            chown(path, uid, gid)
            if Path(path).is_relative_to(self.target/'private'/H.REGISTRY_STATE_DIR):
                transferred.add(path_identity(path))

        def transfer_file(fd, uid, gid):
            fchown(fd, uid, gid)
            transferred.add(fd_identity(fd))

        with patch.object(os, 'chmod', chmod_as_owner), patch.object(os, 'fchmod', fchmod_as_owner),              patch.object(os, 'chown', transfer_path), patch.object(os, 'fchown', transfer_file):
            self.assertEqual(H.clone_state(self.source, self.target, **self.kw, **self.good), before)
        self.assertEqual(len(transferred), before['summary']['registryCollector']['entries'])

    def test_no_implicit_claimed_allowlist_and_bad_scope_denied(self):
        with self.assertRaisesRegex(RuntimeError,'UNREVIEWED_UNCERTAIN'):
            self.inspect(preserve_uncertain_ids=[])
        with self.assertRaisesRegex(RuntimeError,'UNREVIEWED_CLAIMED_JOBS'):
            self.inspect(preserve_claimed_ids=['11111111-1111-4111-8111-111111111111'])
        with self.assertRaisesRegex(RuntimeError,'UNCERTAIN_SCOPE_INVALID'):
            self.inspect(preserve_claimed_ids=[IDENT,IDENT])
        with self.assertRaisesRegex(RuntimeError,'UNREVIEWED_CLAIMED_JOBS'):
            self.inspect(preserve_claimed_ids=[])
        self.update("UPDATE jobs SET state='FAILED',error='UNCERTAIN' WHERE id=?",(IDENT,))
        with self.assertRaisesRegex(RuntimeError,'CLAIMED_JOB_SET_CHANGED'):
            self.inspect(require_exact_claimed=True)
        self.assertEqual(self.inspect()['summary']['native']['preservedClaimedIds'],[])

    def test_closed_claimed_job_survives_future_backups_without_reopening_request(self):
        with sqlite3.connect(self.source/'private/approvals.sqlite') as db:
            db.execute('DROP TABLE events')
            db.execute('CREATE TABLE events(seq INTEGER PRIMARY KEY AUTOINCREMENT,request_id TEXT,state TEXT,detail TEXT)')
            db.execute("UPDATE requests SET state='CLOSED_UNCONFIRMED' WHERE id=?",(IDENT,))
            db.execute('INSERT INTO events(request_id,state,detail) VALUES(?,?,?)',(IDENT,'CLOSED_UNCONFIRMED',
                json.dumps({'owner':'owner','remoteEffectVerified':False,
                            'closeMethod':'authenticated_owner_session'})))
        # After closure the exact active UNCERTAIN set is empty, while the
        # previously approved worker claim is still present and byte-preserved.
        args={**self.kw,'preserve_uncertain_ids':[],
              'preserve_claimed_ids':[IDENT],'require_exact_uncertain':True,
              'require_exact_claimed':True}
        state=H.inspect_state(self.source,**args)
        self.assertEqual(state['summary']['uncertainRequestIds'],[])
        self.assertEqual(state['summary']['native']['preservedClaimedIds'],[IDENT])
        before=(self.source/'private/native-git/workflow.sqlite').read_bytes()
        result=H.clone_state(self.source,self.target,**{
            k:v for k,v in args.items() if not k.startswith('require_exact_')})
        self.assertEqual(result['sha256'],state['sha256'])
        self.assertEqual(before,(self.target/'private/native-git/workflow.sqlite').read_bytes())
        with sqlite3.connect(self.target/'private/approvals.sqlite') as db:
            self.assertEqual(db.execute('SELECT state FROM requests WHERE id=?',
                                        (IDENT,)).fetchone(),('CLOSED_UNCONFIRMED',))
        self.update('DELETE FROM events WHERE request_id=?',(IDENT,),table='approvals.sqlite')
        with self.assertRaisesRegex(RuntimeError,'CLAIMED_CLOSURE_AUDIT_MISSING'):
            H.inspect_state(self.source,**args)

    def test_worker_queued_and_wrong_operation_never_allowed(self):
        self.update("UPDATE jobs SET state='QUEUED' WHERE id=?",(IDENT,))
        with self.assertRaisesRegex(RuntimeError,'NATIVE_HAS_UNFINISHED_JOBS'):
            self.inspect()
        self.update("UPDATE jobs SET state='CLAIMED' WHERE id=?",(IDENT,))
        req={**REQUEST,'operation':'commit'}
        job={**PAYLOAD,'operation':'commit'}
        self.update("UPDATE requests SET payload=? WHERE id=?",
                    (json.dumps(req),IDENT),table='approvals.sqlite')
        self.update("UPDATE jobs SET payload=? WHERE id=?",(json.dumps(job),IDENT))
        with self.assertRaisesRegex(RuntimeError,'CLAIMED_JOB_RECORD_INVALID'):
            self.inspect()

    def test_uncertain_core_binding_actor_claim_receipt_are_strict(self):
        self.update("UPDATE requests SET state='EXECUTED' WHERE id=?",
                    (IDENT,),table='approvals.sqlite')
        with self.assertRaisesRegex(RuntimeError,'CLAIMED_APPROVAL_NOT_UNCERTAIN'):
            self.inspect()
        self.update("UPDATE requests SET state='UNCERTAIN' WHERE id=?",
                    (IDENT,),table='approvals.sqlite')
        cases=[
            ("actor='other'","actor=?",(ACTOR,)),
            ("claim=NULL","claim=?",(CLAIM,)),
            ("result='{}'","result=NULL",()),
            ("error='UNCERTAIN'","error=NULL",())]
        for change,undo,values in cases:
            self.update('UPDATE jobs SET '+change+' WHERE id=?',(IDENT,))
            with self.assertRaisesRegex(RuntimeError,'CLAIMED_JOB_RECORD_INVALID'):
                self.inspect()
            self.update('UPDATE jobs SET '+undo+' WHERE id=?',(*values,IDENT))

    def test_repeated_source_reads_are_unchanged_and_no_database_mutation(self):
        db_path=self.source/'private/native-git/workflow.sqlite'
        core_path=self.source/'private/approvals.sqlite'
        before=(db_path.read_bytes(),core_path.read_bytes())
        for _ in range(3):
            self.inspect(require_exact_claimed=True)
        self.assertEqual(before,(db_path.read_bytes(),core_path.read_bytes()))


if __name__=='__main__':
    unittest.main()

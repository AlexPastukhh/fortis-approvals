"""Phase 6C.7 offline independent process / shared SQLite safety evidence.

Synthetic owner assertion is NOT real WebAuthn. No host, network or release
access; this intentionally proves rollback and split-DB bypasses still exist.
"""
import multiprocessing
import os
from pathlib import Path
import shutil
import threading
import tempfile
import time
import unittest
import uuid

from fortis_approvals.core import Authenticator, Core, Denied
from fortis_approvals.synthetic import SyntheticAdapter
from fortis_approvals.extensions.owner_policy_local_core_phase6c import LocalDenyCore
from fortis_approvals.extensions.owner_policy_local_deny_apply_phase6c1 import OwnerLocalDenyApply
from fortis_approvals.tests.test_owner_policy_local_deny_apply_phase6c1 import (
    SyntheticWebAuthn, SOURCE, CREDS)

_ACTOR='agent-1'
_POLICIES={(_ACTOR,'synthetic','set_ask'):'ASK'}
_VERSION='phase6c7-test-v1'


def _process(path, adapter_path, channel):
    """Independent interpreter/process reconstructs Core from same DB path."""
    try:
        core=LocalDenyCore(Path(path),adapters={
            'synthetic':SyntheticAdapter(Path(adapter_path))},
            policies=_POLICIES,authenticator=Authenticator({'machine':_ACTOR}),
            owner_verifier=object(),policy_version=_VERSION)
        channel.send(('READY',os.getpid(),core.policy_version))
        while True:
            operation,data=channel.recv()
            if operation=='stop':
                break
            try:
                if operation=='policy':
                    result=(core._policy(_ACTOR,data),core.policy_version)
                elif operation=='submit':
                    view=core.submit(_ACTOR,data)
                    result=(view['state'],view['policyVersion'])
                elif operation=='approve':
                    result=core.owner_decide(data,'approve',{})
                elif operation=='execute':
                    view=core.execute(data)
                    result=(view['state'],view['failure'])
                elif operation=='hold_uncommitted_deny':
                    with core._db() as db:
                        db.execute('BEGIN IMMEDIATE')
                        db.execute("INSERT INTO owner_local_denials VALUES(?,?,?,?,'DENY')",
                                   (_ACTOR,'synthetic','set_ask','record'))
                        db.execute('UPDATE owner_local_policy_meta SET revision=revision+1')
                        channel.send(('UNCOMMITTED',os.getpid()))
                        channel.recv()  # Parent terminates process before commit.
                    result='UNREACHABLE'
                elif operation=='hold_immediate':
                    with core._db() as db:
                        db.execute('BEGIN IMMEDIATE')
                        channel.send(('LOCKED',os.getpid()))
                        instruction,_=channel.recv()
                        if instruction!='unlock':
                            raise AssertionError('UNEXPECTED_TEST_COMMAND')
                    result='RELEASED'
                else:
                    raise AssertionError('UNKNOWN_TEST_COMMAND')
                channel.send(('PASS',result))
            except Exception as exc:
                channel.send(('ERROR',type(exc).__name__,str(exc)))
    except Exception as exc:
        channel.send(('SETUP_ERROR',type(exc).__name__,str(exc)))
    finally:
        channel.close()


class Child:
    def __init__(self,case,path,adapter_path):
        ctx=multiprocessing.get_context('spawn')
        self.parent,child=ctx.Pipe(duplex=True)
        self.process=ctx.Process(target=_process,args=(str(path),str(adapter_path),child))
        self.process.start()
        child.close()
        case.addCleanup(self.close)
        if not self.parent.poll(12):
            raise AssertionError('CHILD_START_TIMEOUT')
        ready=self.parent.recv()
        if ready[0]!='READY':
            raise AssertionError('CHILD_START_FAILED: '+repr(ready))
        self.pid,self.initial_version=ready[1:]

    def ask(self,operation,data=None):
        self.parent.send((operation,data))
        if not self.parent.poll(12):
            raise AssertionError('CHILD_RESPONSE_TIMEOUT')
        return self.parent.recv()

    def close(self):
        if self.process.is_alive():
            try:
                self.parent.send(('stop',None))
                self.process.join(3)
            except (OSError,EOFError,BrokenPipeError):
                pass
        if self.process.is_alive():
            self.process.terminate()
            self.process.join(3)
        self.parent.close()


class CrossProcessLocalPolicyTests(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory(prefix='fortis-policy-process-')
        self.addCleanup(tmp.cleanup)
        self.root=Path(tmp.name)
        self.path=self.root/'core.sqlite'
        self.adapter_path=self.root/'data.sqlite'
        adapter=SyntheticAdapter(self.adapter_path)
        adapter.seed('record','before')
        adapter.seed('other','untouched')
        self.owner=SyntheticWebAuthn()
        self.core=LocalDenyCore(self.path,
            adapters={'synthetic':adapter},policies=_POLICIES,
            authenticator=Authenticator({'machine':_ACTOR}),
            owner_verifier=self.owner,policy_version=_VERSION)
        self.apply=OwnerLocalDenyApply(self.core,self.owner,
            source_digest=SOURCE,credential_generation_digest=CREDS)

    def request(self,target='record'):
        return dict(requestId=str(uuid.uuid4()),service='synthetic',
            operation='set_ask',target=target,params={'value':'after'},
            expectedVersion=0,reason='isolated-process-test')

    def candidate(self):
        return dict(actor=_ACTOR,provider='synthetic',operation='set_ask',
            target='record',expectedConfiguredPolicy='ASK',
            expectedConfiguredScope='actor',
            expectedPolicyVersion=self.core.policy_version,
            expectedRevision=0,reasonCode='OWNER_DENY_ONE_TARGET')

    def deny(self):
        started=self.apply.begin_deny(self.owner._session,self.owner._csrf,
                                     self.candidate())
        return self.apply.finish_deny(self.owner._session,self.owner._csrf,
            started['ceremonyId'],{'syntheticTestOnlyUv':True},started['change'])

    def worker(self,path=None):
        return Child(self,path or self.path,self.adapter_path)

    def test_two_existing_independent_processes_observe_shared_revision(self):
        first=self.worker()
        second=self.worker()
        self.assertNotEqual(first.pid,second.pid)
        self.assertEqual(_VERSION+'|owner-local-deny:0',first.initial_version)
        self.deny()
        for worker in (first,second):
            self.assertEqual(('PASS',('DENY',_VERSION+'|owner-local-deny:1')),
                worker.ask('policy',self.request('record')))
            self.assertEqual(('PASS',('ASK',_VERSION+'|owner-local-deny:1')),
                worker.ask('policy',self.request('other')))
            answer=worker.ask('submit',self.request())
            self.assertEqual(('ERROR','Denied','OPERATION_DENIED'),answer)
        self.assertEqual('before',SyntheticAdapter(self.adapter_path).get('record')['value'])

    def test_old_pending_and_approved_states_are_fenced_across_processes(self):
        worker=self.worker()
        payload=self.request()
        answer=worker.ask('submit',payload)
        self.assertEqual('PASS',answer[0])
        self.assertEqual('PENDING',answer[1][0])
        self.deny()
        self.assertEqual(('ERROR','Denied','OWNER_POLICY_CHANGED'),
            worker.ask('approve',payload['requestId']))
        with self.core._db() as db:
            db.execute("UPDATE requests SET state='APPROVED',decision='approve' WHERE id=?",
                       (payload['requestId'],))
        self.assertEqual(('PASS',('STALE','POLICY_CHANGED')),
            worker.ask('execute',payload['requestId']))
        with self.core._db() as db:
            self.assertFalse(db.execute(
                "SELECT 1 FROM events WHERE request_id=? AND state='DISPATCHED'",
                (payload['requestId'],)).fetchone())

    def test_cross_process_sqlite_immediate_lock_serializes_owner_apply(self):
        worker=self.worker()
        begun=self.apply.begin_deny(self.owner._session,self.owner._csrf,
                                    self.candidate())
        worker.parent.send(('hold_immediate',None))
        self.assertTrue(worker.parent.poll(12))
        self.assertEqual('LOCKED',worker.parent.recv()[0])
        done=threading.Event()
        receipt=[]
        def commit():
            try:
                receipt.append(self.apply.finish_deny(
                    self.owner._session,self.owner._csrf,begun['ceremonyId'],
                    {'syntheticTestOnlyUv':True},begun['change']))
            finally:
                done.set()
        thread=threading.Thread(target=commit,daemon=True)
        thread.start()
        self.assertFalse(done.wait(0.15))
        worker.parent.send(('unlock',None))
        self.assertEqual(('PASS','RELEASED'),worker.parent.recv() if worker.parent.poll(12) else None)
        self.assertTrue(done.wait(12))
        thread.join(2)
        self.assertEqual(1,receipt[0]['appliedRevision'])
        self.assertEqual(('PASS',('DENY',_VERSION+'|owner-local-deny:1')),
            worker.ask('policy',self.request()))

    def test_prepared_gate_denies_already_running_other_process(self):
        worker=self.worker()
        with self.core._db() as db:
            db.execute("UPDATE owner_local_policy_meta SET gate='PREPARED'")
        self.assertEqual(('ERROR','Denied','OWNER_LOCAL_POLICY_NOT_READY'),
            worker.ask('policy',self.request()))
        self.assertEqual(('ERROR','Denied','OWNER_LOCAL_POLICY_NOT_READY'),
            worker.ask('submit',self.request()))
        with self.core._db() as db:
            db.execute("UPDATE owner_local_policy_meta SET gate='READY'")
        self.assertEqual('ASK',worker.ask('policy',self.request())[1][0])

    def test_crashed_worker_uncommitted_deny_does_not_partial_commit(self):
        worker=self.worker()
        worker.parent.send(('hold_uncommitted_deny',None))
        self.assertTrue(worker.parent.poll(12))
        self.assertEqual('UNCOMMITTED',worker.parent.recv()[0])
        worker.process.terminate()
        worker.process.join(5)
        self.assertFalse(worker.process.is_alive())
        self.assertEqual('ASK',self.core._policy(_ACTOR,self.request()))
        with self.core._db() as db:
            self.assertEqual(0,self.core._local_revision(db))
            self.assertEqual(0,db.execute('SELECT COUNT(*) FROM owner_local_denials').fetchone()[0])
            self.assertEqual(0,db.execute('SELECT COUNT(*) FROM owner_local_policy_events').fetchone()[0])

    def test_separate_sqlite_paths_are_not_multi_worker_protection(self):
        worker=self.worker(self.root/'separate.sqlite')
        self.deny()
        self.assertEqual(('PASS',('ASK',_VERSION+'|owner-local-deny:0')),
            worker.ask('policy',self.request()))
        self.assertEqual('PENDING',worker.ask('submit',self.request())[1][0])
        # A split DB is a RELEASE STOP, not a successful revoke.
        self.assertEqual('DENY',self.core._policy(_ACTOR,self.request()))

    def test_old_backup_rollback_resurrects_ask_without_external_witness(self):
        snapshot=self.root/'pre-deny-backup.sqlite'
        shutil.copyfile(self.path,snapshot)
        self.deny()
        self.assertEqual('DENY',self.core._policy(_ACTOR,self.request()))
        shutil.copyfile(snapshot,self.path)  # offline fixture, NEVER production recovery
        worker=self.worker()
        self.assertEqual(('PASS',('ASK',_VERSION+'|owner-local-deny:0')),
            worker.ask('policy',self.request()))
        with self.core._db() as db:
            self.assertEqual(0,db.execute('SELECT COUNT(*) FROM owner_local_policy_events').fetchone()[0])
        # No immutable off-DB head was consulted. This is a known STOP.
        self.assertEqual('PENDING',worker.ask('submit',self.request())[1][0])

    def test_plain_legacy_core_remains_a_bypass_outside_r7_builder(self):
        self.deny()
        legacy=Core(self.path,adapters={
            'synthetic':SyntheticAdapter(self.adapter_path)},
            policies=_POLICIES,authenticator=Authenticator({'machine':_ACTOR}),
            policy_version=_VERSION)
        self.assertEqual('ASK',legacy._policy(_ACTOR,self.request()))
        # The Phase6C5 startup guard protects only the new R7 builder path.


if __name__=='__main__':
    unittest.main()

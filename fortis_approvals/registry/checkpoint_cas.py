"""Offline owner-side checkpoint CAS candidate, not a protected live anchor.

This intentionally has no transport, external credential, owner WebAuthn
authority, service principal, or link to Registry admission. Production MUST
put the checkpoint outside the writer's trust boundary under owner control.
A separate SQLite file under the same UID is NOT a protected witness.
"""
from contextlib import contextmanager
import os
from pathlib import Path
import sqlite3

from ..core import Conflict, Denied, Stale
from .state_journal import (_private, _scope, _need, _uuid, _hex, _raw,
                             _decode, _hash, _CommitUncertain, PLANNER)
from .state_journal_v2 import RegistryStateJournalV2, genesis_v2, MAX_REVISIONS

_SCHEMA=(
    'CREATE TABLE meta(instance_id TEXT PRIMARY KEY NOT NULL, scope TEXT NOT NULL, enrollment_receipt_digest TEXT NOT NULL, registered_registry_path TEXT NOT NULL)',
    '''CREATE TABLE advances(revision INTEGER PRIMARY KEY CHECK(revision>=1),
        operation_id TEXT UNIQUE NOT NULL, previous_checkpoint TEXT NOT NULL,
        next_checkpoint TEXT NOT NULL, pending_digest TEXT NOT NULL,
        receipt TEXT NOT NULL, event_digest TEXT UNIQUE NOT NULL)''',
    'PRAGMA user_version=1',
)


def _cp(cp,initial):
    _need(type(cp) is dict and set(cp)==set(initial)
          and type(cp['schemaVersion']) is int and cp['schemaVersion']==1
          and cp['instanceId']==initial['instanceId']
          and cp['scopeDigest']==initial['scopeDigest']
          and type(cp['revision']) is int and 0<=cp['revision']<=MAX_REVISIONS
          and _hex(cp['eventDigest'],64),
          'REGISTRY_CHECKPOINT_INVALID')
    return _decode(_raw(cp))


def _pending(operation_id,previous,proposed):
    return {'result':'UNKNOWN_OUTCOME','previousCheckpoint':previous,
            'pendingCheckpoint':proposed,'operationId':operation_id}


class OfflineCheckpointCAS:
    """Explicitly provisioned CAS ledger for owner-side contract tests.

    This object is NOT authorized to impersonate a protected owner service.
    Host composition must keep the writer and this object in different
    principals/volumes in a later separately reviewed runtime proposal.
    """

    def __init__(self,path,*,instance_id,scope,enrollment_receipt_digest,
                 registered_registry_path):
        self.path=Path(path);self.instance_id=instance_id;self.scope=_scope(scope)
        _need(_hex(enrollment_receipt_digest,64),'REGISTRY_CHECKPOINT_ENROLLMENT_REQUIRED')
        self.enrollment_receipt_digest=enrollment_receipt_digest
        self.registered_registry_path=Path(registered_registry_path)
        _need(self.registered_registry_path.is_absolute()
              and self.registered_registry_path.parent.resolve()==self.registered_registry_path.parent
              and self.registered_registry_path.parent!=self.path.parent,
              'REGISTRY_CHECKPOINT_SOURCE_PATH_INVALID')
        self.initial=genesis_v2(instance_id,self.scope)
        self._paths()

    @classmethod
    def initialize(cls,path,*,instance_id,scope,enrollment_receipt_digest,
                   registered_registry_path):
        path=Path(path);scope=_scope(scope)
        _need(path.is_absolute() and path.parent.resolve()==path.parent,
              'REGISTRY_CHECKPOINT_PATH_INVALID')
        _private(path.parent,True)
        _need(_hex(enrollment_receipt_digest,64),
              'REGISTRY_CHECKPOINT_ENROLLMENT_REQUIRED')
        registered_registry_path=Path(registered_registry_path)
        _need(registered_registry_path.is_absolute()
              and registered_registry_path.parent.resolve()==registered_registry_path.parent
              and registered_registry_path.parent!=path.parent,
              'REGISTRY_CHECKPOINT_SOURCE_PATH_INVALID')
        fd=os.open(path,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o600)
        os.close(fd)
        instance=cls(path,instance_id=instance_id,scope=scope,
                     enrollment_receipt_digest=enrollment_receipt_digest,
                     registered_registry_path=registered_registry_path)
        with instance._db(initialize=True) as db:
            for statement in _SCHEMA:db.execute(statement)
            db.execute('INSERT INTO meta VALUES(?,?,?,?)',
                       (instance_id,_raw(scope),enrollment_receipt_digest,
                        str(registered_registry_path)))
        return instance

    def _paths(self):
        try:
            _need(self.path.is_absolute() and self.path.parent.resolve()==self.path.parent,
                  'REGISTRY_CHECKPOINT_PATH_INVALID')
            _private(self.path.parent,True);_private(self.path)
            for suffix in ('-wal','-shm','-journal'):
                side=Path(str(self.path)+suffix)
                if side.exists() or side.is_symlink():
                    try:
                        _private(side)
                    except FileNotFoundError:
                        # SQLite may unlink its transient -wal/-shm files
                        # between the existence check and lstat. A newly
                        # appearing sidecar must still pass the full guard.
                        if side.exists() or side.is_symlink():
                            _private(side)
        except OSError:
            raise Denied('REGISTRY_CHECKPOINT_UNAVAILABLE') from None

    @contextmanager
    def _db(self,initialize=False):
        self._paths();db=None
        try:
            db=sqlite3.connect(self.path.as_uri()+'?mode=rw',uri=True,
                               timeout=3,isolation_level=None)
            db.execute('PRAGMA trusted_schema=OFF');db.execute('PRAGMA foreign_keys=ON')
            db.execute('PRAGMA busy_timeout=3000');db.execute('PRAGMA synchronous=FULL')
            _need(db.execute('PRAGMA journal_mode'+('=WAL' if initialize else '')).fetchone()==('wal',),
                  'REGISTRY_CHECKPOINT_WAL_REQUIRED')
            db.execute('BEGIN IMMEDIATE')
            if not initialize:
                _need(db.execute(
                    "SELECT sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_autoindex_%' ORDER BY name"
                ).fetchall()==sorted((sql,) for sql in _SCHEMA[:-1])
                and db.execute('PRAGMA user_version').fetchone()==(1,)
                and db.execute('SELECT * FROM meta LIMIT 2').fetchall()==
                    [(self.instance_id,_raw(self.scope),self.enrollment_receipt_digest,
                      str(self.registered_registry_path))],
                    'REGISTRY_CHECKPOINT_SCHEMA_MISMATCH')
            yield db
            try:db.commit()
            except sqlite3.Error:
                raise _CommitUncertain('REGISTRY_CHECKPOINT_COMMIT_UNCERTAIN') from None
        except sqlite3.Error:
            raise Denied('REGISTRY_CHECKPOINT_UNAVAILABLE') from None
        finally:
            if db is not None:db.close()

    def _event(self,revision,operation_id,previous,proposed,pending_digest):
        return _hash(['owner-checkpoint-v1',self.instance_id,self.enrollment_receipt_digest,
                      revision,operation_id,previous,proposed,pending_digest])

    def _receipt(self,operation_id,previous,proposed,pending_digest,event):
        return {'schemaVersion':1,'result':'CHECKPOINT_CAS_CANDIDATE',
                'operationId':operation_id,'enrollmentReceiptDigest':self.enrollment_receipt_digest,
                'previousCheckpoint':previous,'checkpoint':proposed,
                'pendingDigest':pending_digest,'authorityEventDigest':event,
                'protectedAnchorVerified':False,'admissionAllowed':False}

    def _checked(self,db):
        _need(db.execute('PRAGMA quick_check').fetchall()==[('ok',)]
              and db.execute('PRAGMA foreign_key_check').fetchone() is None,
              'REGISTRY_CHECKPOINT_CORRUPT')
        rows=db.execute('SELECT * FROM advances ORDER BY revision').fetchall()
        _need(len(rows)<=MAX_REVISIONS
              and db.execute('SELECT COALESCE(SUM(length(CAST(previous_checkpoint AS BLOB))+'
                             'length(CAST(next_checkpoint AS BLOB))+length(CAST(receipt AS BLOB))),0)'
                             ' FROM advances').fetchone()[0]<=1_000_000,
              'REGISTRY_CHECKPOINT_LIMIT')
        prev=self.initial;seen={}
        for rev,operation_id,previous_raw,proposed_raw,pending_digest,receipt_raw,event in rows:
            _need(rev==len(seen)+1 and _uuid(operation_id) and operation_id not in seen,
                  'REGISTRY_CHECKPOINT_CORRUPT')
            previous=_cp(_decode(previous_raw),self.initial)
            proposed=_cp(_decode(proposed_raw),self.initial)
            _need(previous==prev and proposed['revision']==rev
                  and previous['revision']==rev-1 and proposed['eventDigest']!=previous['eventDigest']
                  and _hex(pending_digest,64),
                  'REGISTRY_CHECKPOINT_CORRUPT')
            expected_pending=_hash(_pending(operation_id,previous,proposed))
            _need(pending_digest==expected_pending,'REGISTRY_CHECKPOINT_CORRUPT')
            computed=self._event(rev,operation_id,previous,proposed,pending_digest)
            expected=self._receipt(operation_id,previous,proposed,pending_digest,computed)
            _need(computed==event and _decode(receipt_raw)==expected,
                  'REGISTRY_CHECKPOINT_CORRUPT')
            seen[operation_id]=(previous,proposed,expected)
            prev=proposed
        return prev,seen

    def read_checkpoint(self):
        """Owner-side candidate read; never an authority attestation."""
        with self._db() as db:
            checkpoint,_=self._checked(db)
            return _decode(_raw(checkpoint))

    def _source(self,pending_reader):
        owner=getattr(pending_reader,'__self__',None)
        _need(type(owner) is RegistryStateJournalV2 and
              getattr(pending_reader,'__func__',None) is RegistryStateJournalV2.operation
              and getattr(owner.anchor_reader,'__self__',None) is self
              and getattr(owner.anchor_reader,'__func__',None) is OfflineCheckpointCAS.read_checkpoint
              and owner.instance_id==self.instance_id
              and owner.scope==self.scope
              and owner.path==self.registered_registry_path
              and owner.path.parent.resolve()!=self.path.parent.resolve(),
              'REGISTRY_CHECKPOINT_SOURCE_BOUNDARY_REQUIRED')
        return owner

    def advance(self,*,operation_id,previous_checkpoint,next_checkpoint,pending_reader):
        """Check the original unanchored Registry operation then CAS only.

        This method is an offline owner-side protocol candidate, NOT a
        machine API callable by Registry, Gateway or an assistant.
        """
        _need(_uuid(operation_id),'REGISTRY_CHECKPOINT_OPERATION_INVALID')
        previous=_cp(previous_checkpoint,self.initial)
        proposed=_cp(next_checkpoint,self.initial)
        _need(proposed['revision']==previous['revision']+1
              and proposed['eventDigest']!=previous['eventDigest'],
              'REGISTRY_CHECKPOINT_TRANSITION_INVALID')
        self._source(pending_reader)
        # Never call Registry under this ledger's SQLite lock: Registry
        # itself reads the owner ledger and would invert the lock order.
        try:
            status=pending_reader(actor=PLANNER,operation_id=operation_id)
        except Stale:
            # Read-only recheck: the other owner CAS may have advanced
            # between Registry's independent anchor readbacks.
            status=pending_reader(actor=PLANNER,operation_id=operation_id)
        expected=_pending(operation_id,previous,proposed)
        _need(status==expected or
              (type(status) is dict and status.get('result')=='ANCHORED_CANDIDATE_TRANSACTION'
               and status.get('receipt',{}).get('previousCheckpoint')==previous
               and status['receipt'].get('checkpoint')==proposed
               and status['receipt'].get('operationId')==operation_id),
              'REGISTRY_CHECKPOINT_ORIGINAL_OPERATION_REQUIRED')
        anchor=self.read_checkpoint()
        pending_digest=_hash(expected)
        with self._db() as db:
            fresh,seen=self._checked(db)
            if operation_id in seen:
                old_prev,old_next,receipt=seen[operation_id]
                if (old_prev,old_next)!=(previous,proposed):
                    raise Conflict('REGISTRY_CHECKPOINT_OPERATION_CONFLICT')
                # A competing same-ID CAS can commit after our earlier
                # read, and later legitimate operations may have advanced.
                # Full chain replay and the original operation still bind
                # this immutable receipt; do not require stale pre-READ.
                _need(fresh['revision']>=proposed['revision'],
                      'REGISTRY_CHECKPOINT_ANCHOR_DRIFT')
                result=receipt
            else:
                _need(fresh==anchor==previous,
                      'REGISTRY_CHECKPOINT_CAS_STALE')
                _need(len(seen)<MAX_REVISIONS,'REGISTRY_CHECKPOINT_LIMIT')
                event=self._event(proposed['revision'],operation_id,previous,proposed,pending_digest)
                result=self._receipt(operation_id,previous,proposed,pending_digest,event)
                db.execute('INSERT INTO advances VALUES(?,?,?,?,?,?,?)',
                           (proposed['revision'],operation_id,_raw(previous),
                            _raw(proposed),pending_digest,_raw(result),event))
                self._checked(db)
        # Reconcile by original ID on a lost result. Do not advance twice.
        after=self.read_checkpoint()
        if after['revision']<proposed['revision']:
            raise Stale('REGISTRY_CHECKPOINT_READBACK_CHANGED')
        done=pending_reader(actor=PLANNER,operation_id=operation_id)
        _need(type(done) is dict and done.get('result')=='ANCHORED_CANDIDATE_TRANSACTION'
              and done['receipt']['previousCheckpoint']==previous
              and done['receipt']['checkpoint']==proposed
              and done['receipt']['operationId']==operation_id,
              'REGISTRY_CHECKPOINT_ORIGINAL_READBACK_REQUIRED')
        return {'result':'CHECKPOINT_CAS_CANDIDATE','receipt':result,
                'protectedAnchorVerified':False,'admissionAllowed':False}

    def original(self,operation_id):
        _need(_uuid(operation_id),'REGISTRY_CHECKPOINT_OPERATION_INVALID')
        with self._db() as db:
            _,seen=self._checked(db)
            return {'result':'CHECKPOINT_CAS_CANDIDATE','receipt':seen[operation_id][2],
                    'protectedAnchorVerified':False,'admissionAllowed':False} if operation_id in seen else {
                    'result':'CHECKPOINT_OPERATION_NOT_FOUND'}

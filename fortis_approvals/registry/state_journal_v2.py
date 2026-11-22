"""Explicit Registry state schema v2: bounded suffix transactions and supersession.

Source-only isolated store. No automatic v1 migration, protected witness,
admission, live API, deployment or actual-state authority.
"""
from contextlib import contextmanager
import os
from pathlib import Path
import re
import sqlite3

from ..core import Conflict, Denied, Stale
from .state_journal import (RegistryStateJournal, _checkpoint, _private, _scope,
                            _request, _plan, _hash, _raw, _decode, _hex, _uuid,
                            _need, REPOSITORY, PLANNER, _CommitUncertain)

MAX_REVISIONS=64
MAX_RECORDS=512
MAX_JOURNAL_BYTES=16_000_000
_SCHEMA=(
    'CREATE TABLE meta(instance_id TEXT PRIMARY KEY NOT NULL, scope TEXT NOT NULL)',
    '''CREATE TABLE operations(revision INTEGER PRIMARY KEY CHECK(revision>=1),
        operation_id TEXT UNIQUE NOT NULL, request TEXT NOT NULL, fingerprint TEXT NOT NULL,
        evidence TEXT NOT NULL, evidence_digest TEXT NOT NULL, receipt TEXT NOT NULL,
        previous_digest TEXT NOT NULL, event_digest TEXT UNIQUE NOT NULL)''',
    '''CREATE TABLE records(record_id TEXT PRIMARY KEY NOT NULL,
        subject_id TEXT NOT NULL, revision INTEGER NOT NULL REFERENCES operations(revision),
        payload TEXT NOT NULL, UNIQUE(subject_id,revision))''',
    '''CREATE TABLE supersessions(from_record_id TEXT PRIMARY KEY NOT NULL REFERENCES records(record_id),
        to_record_id TEXT UNIQUE NOT NULL REFERENCES records(record_id),
        revision INTEGER NOT NULL REFERENCES operations(revision))''',
    'PRAGMA user_version=2',
)


def genesis_v2(instance_id,scope):
    _need(_uuid(instance_id),'REGISTRY_STATE_INSTANCE_INVALID')
    scope=_scope(scope)
    return _checkpoint(instance_id,scope,0,_hash(['registry-state-v2',instance_id,scope]))


class RegistryStateJournalV2(RegistryStateJournal):
    """Dedicated v2 store; never opens or migrates a schema-v1 database.

    The original v1 class and its immutable transaction remain unchanged.
    A separate reviewed owner migration/restore process is required if an
    already-existing v1 database must be carried forward.
    """
    def __init__(self,path,*,instance_id,scope,anchor_reader,plan_reader):
        self.path=Path(path);self.instance_id=instance_id;self.scope=_scope(scope)
        self.anchor_reader=anchor_reader;self.plan_reader=plan_reader
        self.initial=genesis_v2(instance_id,self.scope)
        _need(callable(anchor_reader) and callable(plan_reader),'REGISTRY_STATE_READER_REQUIRED')
        self._paths()

    @classmethod
    def initialize(cls,path,*,instance_id,scope,anchor_reader,plan_reader):
        path=Path(path);scope=_scope(scope);initial=genesis_v2(instance_id,scope)
        _need(path.is_absolute() and path.parent.resolve()==path.parent,'REGISTRY_STATE_PATH')
        _private(path.parent,True)
        _need(callable(anchor_reader) and callable(plan_reader),'REGISTRY_STATE_READER_REQUIRED')
        _need(_raw(anchor_reader())==_raw(initial),'REGISTRY_STATE_ANCHOR_MISMATCH')
        fd=os.open(path,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o600)
        os.close(fd)
        obj=cls(path,instance_id=instance_id,scope=scope,
                anchor_reader=anchor_reader,plan_reader=plan_reader)
        with obj._db(initialize=True) as db:
            for statement in _SCHEMA:db.execute(statement)
            _need(obj._anchor()==initial,'REGISTRY_STATE_ANCHOR_MISMATCH')
            db.execute('INSERT INTO meta VALUES(?,?)',(instance_id,_raw(scope)))
        return obj

    def _verify_schema(self,db):
        """One exact schema/scope check shared by write and read-only opens."""
        actual=db.execute(
            "SELECT sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_autoindex_%' ORDER BY name"
        ).fetchall()
        _need(actual==sorted((sql,) for sql in _SCHEMA[:-1])
              and db.execute('PRAGMA user_version').fetchone()==(2,)
              and db.execute('SELECT * FROM meta LIMIT 2').fetchall()==
                  [(self.instance_id,_raw(self.scope))],
              'REGISTRY_STATE_SCHEMA_MISMATCH')

    @contextmanager
    def _db(self,initialize=False):
        self._paths();db=None
        try:
            db=sqlite3.connect(self.path.as_uri()+'?mode=rw',uri=True,
                               timeout=3,isolation_level=None)
            db.execute('PRAGMA trusted_schema=OFF');db.execute('PRAGMA foreign_keys=ON')
            db.execute('PRAGMA busy_timeout=3000');db.execute('PRAGMA synchronous=FULL')
            if initialize:
                _need(db.execute('PRAGMA journal_mode=WAL').fetchone()==('wal',),
                      'REGISTRY_STATE_WAL_REQUIRED')
            else:
                _need(db.execute('PRAGMA journal_mode').fetchone()==('wal',),
                      'REGISTRY_STATE_WAL_REQUIRED')
            db.execute('BEGIN IMMEDIATE')
            if not initialize:
                self._verify_schema(db)
            yield db
            try:db.commit()
            except sqlite3.Error:
                raise _CommitUncertain('REGISTRY_STATE_COMMIT_UNCERTAIN') from None
        except sqlite3.Error:
            raise Denied('REGISTRY_STATE_UNAVAILABLE') from None
        finally:
            if db is not None:db.close()

    @contextmanager
    def _read_only_db(self):
        """Inspect existing v2 state without opening it for writes.

        A live writer/owner may change the WAL concurrently. This method is
        strictly an *inactive source preflight*, not a stable live snapshot,
        authoritative checkpoint, admission or recovery authorization.
        """
        self._paths()
        db=None
        try:
            db=sqlite3.connect(self.path.as_uri()+'?mode=ro',uri=True,
                               timeout=3,isolation_level=None)
            db.execute('PRAGMA query_only=ON')
            db.execute('PRAGMA trusted_schema=OFF')
            db.execute('PRAGMA foreign_keys=ON')
            db.execute('PRAGMA busy_timeout=3000')
            _need(db.execute('PRAGMA journal_mode').fetchone()==('wal',),
                  'REGISTRY_STATE_WAL_REQUIRED')
            db.execute('BEGIN')  # Deferred read transaction, never IMMEDIATE.
            self._verify_schema(db)
            yield db
            db.rollback()
        except sqlite3.Error:
            raise Denied('REGISTRY_STATE_UNAVAILABLE') from None
        finally:
            if db is not None:db.close()
            self._paths()

    def _anchor(self):
        try:
            value=self.anchor_reader()
            _need(type(value) is dict and set(value)==set(self.initial)
                  and type(value['schemaVersion']) is int and value['schemaVersion']==1
                  and value['instanceId']==self.instance_id
                  and value['scopeDigest']==self.initial['scopeDigest']
                  and type(value['revision']) is int
                  and 0<=value['revision']<=MAX_REVISIONS
                  and _hex(value['eventDigest'],64),
                  'REGISTRY_STATE_ANCHOR_INVALID')
            return _decode(_raw(value))
        except Denied:raise
        except Exception:
            raise Denied('REGISTRY_STATE_ANCHOR_UNAVAILABLE') from None

    def _event(self,revision,fp,evidence_digest,previous):
        return _hash(['registry-state-v2',self.instance_id,self.initial['scopeDigest'],
                      revision,fp,evidence_digest,previous['eventDigest']])

    def _receipt_v2(self,request,plan,prev,revision,event,links):
        o=plan['observation']
        return {'schemaVersion':2,'operationId':request['operationId'],'actor':PLANNER,
                'repository':REPOSITORY,'evidenceId':request['evidenceId'],
                'evidenceDigest':request['evidenceDigest'],'fingerprint':_hash(request),
                'previousCheckpoint':prev,
                'checkpoint':_checkpoint(self.instance_id,self.scope,revision,event),
                'startCursorSha':self.scope['baselineSha'] if revision==1 else o['startCursorSha'],
                'candidateCursor':o['selectedMainSha'],
                'recordIds':sorted(r['recordId'] for r in o['recordCandidates']),
                'supersessions':links,
                'rangeClassification':o['rangeClassification'],
                'evidenceVerified':False,'admissionAllowed':False,'deploymentAllowed':False}

    def _checked(self,db):
        _need(db.execute('PRAGMA quick_check').fetchall()==[('ok',)]
              and db.execute('PRAGMA foreign_key_check').fetchone() is None,
              'REGISTRY_STATE_CORRUPT')
        ops=db.execute('SELECT * FROM operations ORDER BY revision').fetchall()
        records=db.execute('SELECT record_id,subject_id,revision,payload FROM records ORDER BY record_id').fetchall()
        links=db.execute('SELECT from_record_id,to_record_id,revision FROM supersessions ORDER BY from_record_id').fetchall()
        _need(len(ops)<=MAX_REVISIONS and len(records)<=MAX_RECORDS
              and len(links)<=MAX_RECORDS
              and db.execute('SELECT COALESCE(SUM(length(CAST(evidence AS BLOB))+'
                             'length(CAST(request AS BLOB))+length(CAST(receipt AS BLOB))),0)'
                             ' FROM operations').fetchone()[0]<=MAX_JOURNAL_BYTES
              and db.execute('SELECT COALESCE(SUM(length(CAST(payload AS BLOB))),0)'
                             ' FROM records').fetchone()[0]<=MAX_JOURNAL_BYTES,
              'REGISTRY_STATE_LIMIT')
        prev=self.initial;cursor=self.scope['baselineSha'];seen_ops={}
        used_evidence=set();used_merges=set();used_owner=set();used_numbers=set()
        active={};used_record_ids=set()
        expected_records=[];expected_links=[]
        previous_collector=None
        for rev,op,raw,fp,evidence,ed,receipt,prev_hash,event in ops:
            _need(rev==len(seen_ops)+1 and rev<=MAX_REVISIONS,
                  'REGISTRY_STATE_CORRUPT')
            req=_decode(raw);ev=_decode(evidence)
            try:
                _need(req==_request(req['actor'],req['operationId'],req['evidenceId'],
                                   req['evidenceDigest'],req['expectedRevision'])
                      and req['expectedRevision']==rev-1 and req['operationId']==op
                      and op not in seen_ops and _hash(req)==fp
                      and ed==req['evidenceDigest'] and prev_hash==prev['eventDigest'],
                      'REGISTRY_STATE_CORRUPT')
                o=_plan(ev,req,self.scope,start_sha=cursor if rev>1 else None,
                        previous_checkpoint=prev if rev>1 else None)
                cp=o['collectorCheckpoint']
                _need(previous_collector is None or
                      (cp['instanceId']==previous_collector['instanceId']
                       and cp['revision']>previous_collector['revision']),
                      'REGISTRY_STATE_COLLECTOR_ORDER')
                next_evidence={m['evidenceId'] for m in o['mergeAudit']}
                next_merges={m['mergeSha'] for m in o['mergeAudit']}
                next_owners={m['ownerRequestId'] for m in o['mergeAudit']}
                next_numbers={m['number'] for m in o['mergeAudit']}
                _need(not (used_evidence&next_evidence or used_merges&next_merges
                           or used_owner&next_owners or used_numbers&next_numbers),
                      'REGISTRY_STATE_REPLAYED_MERGE')
                used_evidence.update(next_evidence);used_merges.update(next_merges)
                used_owner.update(next_owners);used_numbers.update(next_numbers)
                change=[]
                for r in o['recordCandidates']:
                    ident=r['recordId'];subject=r['subjectId']
                    _need(ident not in used_record_ids and len(used_record_ids)<MAX_RECORDS,
                          'REGISTRY_STATE_REPEATED_RECORD')
                    used_record_ids.add(ident)
                    if subject in active:
                        change.append({'fromRecordId':active[subject],'toRecordId':ident})
                        expected_links.append((active[subject],ident,rev))
                    active[subject]=ident
                    expected_records.append((ident,subject,rev,_raw(r)))
                change.sort(key=lambda item:item['fromRecordId'])
                computed=self._event(rev,fp,ed,prev)
                expected=self._receipt_v2(req,ev['plan'],prev,rev,computed,change)
                _need(event==computed and _decode(receipt)==expected,
                      'REGISTRY_STATE_CORRUPT')
                prev=expected['checkpoint'];cursor=o['selectedMainSha']
                previous_collector=cp;seen_ops[op]=(req,expected)
            except (KeyError,ValueError,TypeError,AttributeError,RecursionError):
                raise Denied('REGISTRY_STATE_CORRUPT') from None
        _need(records==sorted(expected_records)
              and links==sorted(expected_links),
              'REGISTRY_STATE_CORRUPT')
        return prev,cursor,seen_ops,active,previous_collector

    def _outcome_v2(self,anchor,head,receipt):
        if anchor==head:
            result={'result':'ANCHORED_CANDIDATE_TRANSACTION','receipt':receipt}
        elif anchor==receipt['previousCheckpoint'] and head==receipt['checkpoint']:
            result={'result':'UNKNOWN_OUTCOME',
                    'previousCheckpoint':receipt['previousCheckpoint'],
                    'pendingCheckpoint':receipt['checkpoint'],
                    'operationId':receipt['operationId']}
        else:
            raise Denied('REGISTRY_STATE_ANCHOR_MISMATCH')
        if self._anchor()!=anchor:raise Stale('REGISTRY_STATE_ANCHOR_CHANGED')
        return result

    def append_initial(self,**_kwargs):
        # Never inherit the incompatible schema-v1 append implementation.
        raise Denied('REGISTRY_STATE_USE_V2_APPEND_RANGE')

    def append_range(self,*,actor,operation_id,evidence_id,evidence_digest,expected_revision):
        """Atomic candidate initial/suffix, no witness mutation or admission."""
        req=_request(actor,operation_id,evidence_id,evidence_digest,expected_revision)
        anchor=self._anchor()
        with self._db() as db:
            head,cursor,seen,active,previous_collector=self._checked(db)
            if operation_id in seen:
                old,receipt=seen[operation_id]
                if old!=req:raise Conflict('REGISTRY_STATE_OPERATION_CONFLICT')
                return self._outcome_v2(anchor,head,receipt)
            _need(anchor==head,'REGISTRY_STATE_ANCHOR_MISMATCH')
            if head['revision']!=expected_revision:
                raise Stale('REGISTRY_STATE_REVISION_STALE')
            _need(expected_revision<MAX_REVISIONS,'REGISTRY_STATE_LIMIT')
        evidence=_decode(_raw(self.plan_reader(evidence_id)))
        o=_plan(evidence,req,self.scope,start_sha=cursor if expected_revision else None,
                previous_checkpoint=head if expected_revision else None)
        if previous_collector is not None:
            cp=o['collectorCheckpoint']
            _need(cp['instanceId']==previous_collector['instanceId'] and
                  cp['revision']>previous_collector['revision'],
                  'REGISTRY_STATE_COLLECTOR_ORDER')
        added={m['evidenceId'] for m in o['mergeAudit']}
        merged={m['mergeSha'] for m in o['mergeAudit']}
        owners={m['ownerRequestId'] for m in o['mergeAudit']}
        numbers={m['number'] for m in o['mergeAudit']}
        # The second locked read is authoritative for all preconditions.
        try:
            with self._db() as db:
                fresh,actual_cursor,seen,active,previous_collector=self._checked(db)
                _need(fresh==head==anchor and self._anchor()==anchor
                      and actual_cursor==cursor and operation_id not in seen,
                      'REGISTRY_STATE_CHECKPOINT_CHANGED')
                _need(not any(
                    (added&{m['evidenceId'] for m in e['plan']['observation']['mergeAudit']}
                     or merged&{m['mergeSha'] for m in e['plan']['observation']['mergeAudit']}
                     or owners&{m['ownerRequestId'] for m in e['plan']['observation']['mergeAudit']}
                     or numbers&{m['number'] for m in e['plan']['observation']['mergeAudit']})
                    for (raw_e,) in db.execute('SELECT evidence FROM operations')
                    for e in [_decode(raw_e)]),
                    'REGISTRY_STATE_REPLAYED_MERGE')
                new_revision=expected_revision+1
                links=[]
                for r in o['recordCandidates']:
                    if r['subjectId'] in active:
                        links.append({'fromRecordId':active[r['subjectId']],
                                      'toRecordId':r['recordId']})
                links.sort(key=lambda item:item['fromRecordId'])
                fp=_hash(req);event=self._event(new_revision,fp,evidence_digest,head)
                receipt=self._receipt_v2(req,evidence['plan'],head,new_revision,event,links)
                try:
                    db.execute('INSERT INTO operations VALUES(?,?,?,?,?,?,?,?,?)',
                               (new_revision,operation_id,_raw(req),fp,_raw(evidence),
                                evidence_digest,_raw(receipt),head['eventDigest'],event))
                    db.executemany('INSERT INTO records VALUES(?,?,?,?)',
                        [(r['recordId'],r['subjectId'],new_revision,_raw(r)) for r in o['recordCandidates']])
                    db.executemany('INSERT INTO supersessions VALUES(?,?,?)',
                        [(r['fromRecordId'],r['toRecordId'],new_revision) for r in links])
                    self._checked(db)
                except sqlite3.IntegrityError:
                    raise Denied('REGISTRY_STATE_DUPLICATE_OR_CORRUPT') from None
        except _CommitUncertain:
            return {'result':'UNKNOWN_OUTCOME','operationId':operation_id}
        try:
            outcome=self.operation(actor=actor,operation_id=operation_id)
            _need(outcome.get('result')!='CANDIDATE_OPERATION_NOT_FOUND',
                  'REGISTRY_STATE_LOST_COMMIT')
            return outcome
        except (Denied,Stale):
            return {'result':'UNKNOWN_OUTCOME','operationId':operation_id}

    def operation(self,*,actor,operation_id):
        _need(actor==PLANNER and _uuid(operation_id),'REGISTRY_STATE_REQUEST_INVALID')
        anchor=self._anchor()
        with self._db() as db:
            head,_,seen,_,_=self._checked(db)
            if operation_id in seen:
                return self._outcome_v2(anchor,head,seen[operation_id][1])
            _need(anchor==head,'REGISTRY_STATE_ANCHOR_MISMATCH')
            if self._anchor()!=anchor:raise Stale('REGISTRY_STATE_ANCHOR_CHANGED')
            return {'result':'CANDIDATE_OPERATION_NOT_FOUND'}

    def checkpoint(self):
        anchor=self._anchor()
        with self._db() as db:
            head,cursor,_,_,_=self._checked(db)
            _need(anchor==head,'REGISTRY_STATE_ANCHOR_MISMATCH')
            if self._anchor()!=anchor:raise Stale('REGISTRY_STATE_ANCHOR_CHANGED')
            return {'checkpoint':head,'candidateCursor':cursor,
                    'evidenceVerified':False,'admissionAllowed':False}

    def list_desired_candidates(self, *, limit, cursor=None):
        """Offline, read-only v2 desired projection, NOT a live Registry queue.

        Cursor is bound to one local checkpoint and record ID, but is not
        authenticated or an admission proof. It cannot authorize any effect.
        This reads existing records only; no new event or installed state.
        """
        _need(type(limit) is int and 1<=limit<=100
              and (cursor is None or
                   (type(cursor) is str and re.fullmatch(
                       r'[0-9a-f]{64}_[0-9a-f]{64}',cursor) is not None)),
              'REGISTRY_STATE_PAGE_REQUEST_INVALID')
        anchor=self._anchor()
        with self._read_only_db() as db:
            head,selected_sha,_,active,_=self._checked(db)
            _need(head==anchor,'REGISTRY_STATE_ANCHOR_MISMATCH')
            ids=sorted(active.values())
            start=0
            if cursor is not None:
                last,proof=cursor.split('_',1)
                _need(last in ids,'REGISTRY_STATE_PAGE_CURSOR_STALE')
                expected=_hash(['registry-v2-candidate-page',self.instance_id,
                                head['revision'],head['eventDigest'],last])
                _need(proof==expected,'REGISTRY_STATE_PAGE_CURSOR_STALE')
                start=ids.index(last)+1
            selected=ids[start:start+limit]
            rows=[]
            for record_id in selected:
                payload=db.execute(
                    'SELECT revision,payload FROM records WHERE record_id=?',
                    (record_id,)).fetchone()
                _need(payload is not None,'REGISTRY_STATE_CORRUPT')
                revision,raw=payload
                record=_decode(raw)
                _need(record['recordId']==record_id
                      and record['subjectId'] in active
                      and active[record['subjectId']]==record_id
                      and record['actual'] is None
                      and record['evidenceVerified'] is False
                      and record['planningState']=='PLANNED_UNVERIFIED',
                      'REGISTRY_STATE_CORRUPT')
                rows.append({
                    'recordId':record_id,'subjectId':record['subjectId'],
                    'recordRevision':revision,'identity':record['identity'],
                    'componentId':record['componentId'],
                    'buildUnitId':record['buildUnitId'],
                    'requiredActions':record['requiredActions'],
                    'deploymentProcedure':record['deploymentProcedure'],
                    'planningState':'PLANNED_UNVERIFIED',
                    'actual':None,'evidenceVerified':False,
                })
            has_more=start+len(selected)<len(ids)
            last=selected[-1] if has_more else None
            next_cursor=(last+'_'+_hash([
                'registry-v2-candidate-page',self.instance_id,
                head['revision'],head['eventDigest'],last
            ])) if last is not None else None
            result={
                'result':'INACTIVE_DESIRED_CANDIDATE_PAGE',
                'repository':REPOSITORY,
                'snapshotRevision':head['revision'],
                'snapshotDigest':head['eventDigest'],
                'candidateSourceSha':selected_sha,
                'records':rows,'nextCursor':next_cursor,
                'evidenceVerified':False,'admissionAllowed':False,
                'deploymentVerified':False,'writeEnabled':False,
            }
            _need(len(_raw(result).encode('utf-8'))<=8192,
                  'REGISTRY_STATE_PAGE_TOO_LARGE')
        if self._anchor()!=anchor:
            raise Stale('REGISTRY_STATE_ANCHOR_CHANGED')
        return result

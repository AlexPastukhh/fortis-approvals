"""Registry-owned transaction mechanics, offline source candidates only.

The separate candidate plan reader and independent checkpoint reader are host
dependencies, not a public API or proof of authority. No provisioned runtime,
anchor mutation, admitted records, actual state or deployment authorization.
The initial enrollment range is the only supported append in schema 1.
"""
from contextlib import contextmanager
import hashlib
import os
from pathlib import Path
import sqlite3
import re
import stat

from ..core import Conflict, Denied, Stale, canonical, loads_strict
from .boundary import REPOSITORY, COLLECTOR, PLANNER, _need, _hex, _uuid

MAX_BYTES=2_000_000
SCOPE_FIELDS={'repository','enrollmentId','baselineSha','baselineDigest',
              'catalogSha256','bindingDigest','policyReferenceDigest'}
ACTIONS={'image-rebuild','config-deploy','windows-update','package-build','migration-required'}
_SCHEMA=(
    'CREATE TABLE meta(instance_id TEXT PRIMARY KEY NOT NULL, scope TEXT NOT NULL)',
    '''CREATE TABLE operations(revision INTEGER PRIMARY KEY CHECK(revision=1),
        operation_id TEXT UNIQUE NOT NULL, request TEXT NOT NULL, fingerprint TEXT NOT NULL,
        evidence TEXT NOT NULL, evidence_digest TEXT NOT NULL, receipt TEXT NOT NULL,
        previous_digest TEXT NOT NULL, event_digest TEXT UNIQUE NOT NULL)''',
    '''CREATE TABLE records(record_id TEXT PRIMARY KEY NOT NULL,
        subject_id TEXT UNIQUE NOT NULL, revision INTEGER NOT NULL REFERENCES operations(revision),
        payload TEXT NOT NULL)''',
    'PRAGMA user_version=1',
)


def _raw(value):
    raw=canonical(value)
    _need(len(raw.encode('utf-8'))<=MAX_BYTES,'REGISTRY_STATE_LIMIT')
    return raw


def _hash(value):
    return hashlib.sha256(_raw(value).encode('utf-8')).hexdigest()


def _decode(raw):
    try:
        value=loads_strict(raw)
        _need(_raw(value)==raw,'REGISTRY_STATE_NONCANONICAL')
        return value
    except (ValueError,TypeError,UnicodeError,RecursionError):
        raise Denied('REGISTRY_STATE_CORRUPT') from None


def _name(value):
    return type(value) is str and re.fullmatch(r'[a-z0-9][a-z0-9._/-]{0,127}',value) is not None and '//' not in value and '..' not in value


def _names(values,*,empty=True):
    return type(values) is list and (empty or bool(values)) and len(values)<=256 and all(_name(v) for v in values) and values==sorted(set(values))


def _scope(scope):
    _need(type(scope) is dict and set(scope)==SCOPE_FIELDS
          and scope['repository']==REPOSITORY and _uuid(scope['enrollmentId'])
          and _hex(scope['baselineSha'],40)
          and all(_hex(scope[k],64) for k in SCOPE_FIELDS-{'repository','enrollmentId','baselineSha'}),
          'REGISTRY_STATE_SCOPE_INVALID')
    return _decode(_raw(scope))


def _checkpoint(instance_id,scope,revision,event):
    return {'schemaVersion':1,'instanceId':instance_id,'scopeDigest':_hash(scope),
            'revision':revision,'eventDigest':event}


def genesis(instance_id,scope):
    _need(_uuid(instance_id),'REGISTRY_STATE_INSTANCE_INVALID')
    scope=_scope(scope)
    return _checkpoint(instance_id,scope,0,_hash(['registry-state-v1',instance_id,scope]))


def _private(path,directory=False):
    info=path.stat(follow_symlinks=False)
    _need((stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode))
          and info.st_uid==os.geteuid() and stat.S_IMODE(info.st_mode)==(0o700 if directory else 0o600)
          and (directory or info.st_nlink==1),'REGISTRY_STATE_PERMISSIONS')


def _request(actor,operation_id,evidence_id,evidence_digest,expected_revision):
    _need(actor==PLANNER and _uuid(operation_id) and _uuid(evidence_id)
          and _hex(evidence_digest,64) and type(expected_revision) is int
          and 0<=expected_revision<=2**63-1,'REGISTRY_STATE_REQUEST_INVALID')
    return {'operation':'registry.ingest_merged','actor':actor,'repository':REPOSITORY,
            'operationId':operation_id,'evidenceId':evidence_id,'evidenceDigest':evidence_digest,
            'expectedRevision':expected_revision}


def _plan(evidence,request,scope,*,start_sha=None,previous_checkpoint=None,
          allow_cutover_gap=False):
    """Structural invariant checks, not a substitute for trusted collector.

    Explicit suffix parameters are derived from Registry's previous local
    operation and checkpoint, NEVER from caller-selected candidate fields.
    """
    try:
        _need(type(evidence) is dict and set(evidence)=={'schemaVersion','issuer','repository','evidenceId','plan'}
              and type(evidence['schemaVersion']) is int and evidence['schemaVersion']==1
              and evidence['issuer']==COLLECTOR and evidence['repository']==REPOSITORY
              and evidence['evidenceId']==request['evidenceId'] and _hash(evidence)==request['evidenceDigest'],
              'REGISTRY_STATE_EVIDENCE_MISMATCH')
        plan=evidence['plan'];o=plan['observation']
        _need(set(plan)=={'result','observation','observationDigest','evidenceVerified',
                          'admissionAllowed','deploymentAllowed','missingProofs'}
              and plan['result']==('SUFFIX_RANGE_PLAN_CANDIDATE' if start_sha is not None else
                                    'INITIAL_RANGE_PLAN_CANDIDATE')
              and all(plan[k] is False for k in ('evidenceVerified','admissionAllowed','deploymentAllowed'))
              and plan['missingProofs']==['PROTECTED_ENROLLMENT_AND_RESOURCE_ATTESTATION',
                  'AUTHENTICATED_COLLECTOR_AND_TRUSTED_CLOCK','PROTECTED_REGISTRY_STATE_AND_RECOVERY']
              and _hash(o)==plan['observationDigest'] and all(o[k]==scope[k] for k in SCOPE_FIELDS),
              'REGISTRY_STATE_PLAN_INVALID')
        expected_fields=SCOPE_FIELDS|{'selectedMainSha','collectorCheckpoint','lineageDigest',
              'componentObservationDigest','rangeClassification','mergeAudit','recordCandidates',
              'sourceDependencyRequirements'}
        if start_sha is not None:
            expected_fields |= {'startCursorSha','registryCursorCheckpoint'}
        if 'cutoverGap' in o:
            gap = o['cutoverGap']
            _need(allow_cutover_gap and start_sha is None
                  and type(gap) is dict and set(gap) == {'disposition', 'merges'}
                  and type(gap['merges']) is list
                  and (gap['disposition'], len(gap['merges'])) in (
                      ('OWNER_REVIEWED_PRE_CAPTURE_GAP', 2),
                      ('OWNER_REVIEWED_POST_255_CAPTURE_GAP', 4),
                      ('OWNER_REVIEWED_POST_255_CAPTURE_GAP', 5),
                      ('OWNER_REVIEWED_POST_255_CAPTURE_GAP', 6),
                      ('OWNER_REVIEWED_POST_255_CAPTURE_GAP', 7),
                      ('OWNER_REVIEWED_POST_255_CAPTURE_GAP', 9),
                      ('OWNER_REVIEWED_POST_255_CAPTURE_GAP', 10),
                      ('OWNER_REVIEWED_POST_255_CAPTURE_GAP', 12),
                      ('OWNER_REVIEWED_POST_255_CAPTURE_GAP', 13),
                      ('OWNER_REVIEWED_POST_255_CAPTURE_GAP', 15),
                      ('OWNER_REVIEWED_POST_255_CAPTURE_GAP', 16),
                      ('OWNER_REVIEWED_POST_255_CAPTURE_GAP', 18),
                      ('OWNER_REVIEWED_POST_255_CAPTURE_GAP', 19),
                      ('OWNER_REVIEWED_POST_255_CAPTURE_GAP', 20),
                      ('OWNER_REVIEWED_POST_285_CAPTURE_GAP', 31),
                  ),
                  'REGISTRY_STATE_CUTOVER_GAP')
            expected_fields.add('cutoverGap')
        _need(set(o)==expected_fields
              and _hex(o['selectedMainSha'],40)
              and (start_sha is None or (
                  _hex(start_sha,40) and o['startCursorSha']==start_sha
                  and o['registryCursorCheckpoint']==previous_checkpoint))

              and all(_hex(o[k],64) for k in ('lineageDigest','componentObservationDigest')),
              'REGISTRY_STATE_PLAN_INVALID')
        cp=o['collectorCheckpoint']
        _need(type(cp) is dict and set(cp)=={'schemaVersion','instanceId','revision','eventDigest'}
              and type(cp['schemaVersion']) is int and cp['schemaVersion']==1
              and _uuid(cp['instanceId']) and type(cp['revision']) is int and cp['revision']>0
              and _hex(cp['eventDigest'],64),'REGISTRY_STATE_PLAN_INVALID')
        audit=o['mergeAudit'];rows=o['recordCandidates'];src=o['selectedMainSha']
        _need(type(audit) is list and 0<len(audit)<=64 and type(rows) is list and len(rows)<=200
              and o['rangeClassification']==('DEPLOYMENT_CANDIDATE' if rows else 'NO_DEPLOYMENT_CANDIDATE'),
              'REGISTRY_STATE_EMPTY_OR_INVALID_RANGE')
        cursor=start_sha if start_sha is not None else scope['baselineSha']
        seen={cursor};eids=set();numbers=set();owners=set();rev=0
        if 'cutoverGap' in o:
            post285 = gap['disposition'] == 'OWNER_REVIEWED_POST_285_CAPTURE_GAP'
            if post285:
                # Independently pin the full known prefix, including two CI-only rows.
                _need(_hash(gap['merges'][:-1]) == '91e1de5b02af9e2eaa0cf33b251f2e2db16edf13baab70e49b06a1ffc4dd9c36',
                      'REGISTRY_STATE_CUTOVER_GAP')
            for merge in gap['merges']:
                _need(type(merge) is dict and set(merge) == {'number', 'mergeSha', 'headSha', 'impact'}
                      and type(merge['number']) is int and merge['number'] > 0
                      and merge['number'] not in numbers
                      and _hex(merge['mergeSha'], 40) and merge['mergeSha'] not in seen
                      and _hex(merge['headSha'], 40)
                      and type(merge['impact']) is dict
                      and (bool(merge['impact']) or (post285 and merge['number'] in (274, 275)))
                      and all(_name(target) and _names(actions, empty=False)
                              and set(actions) <= ACTIONS for target, actions in merge['impact'].items()),
                      'REGISTRY_STATE_CUTOVER_GAP')
                cursor = merge['mergeSha']
                seen.add(cursor)
                numbers.add(merge['number'])
            if post285:
                _need(gap['merges'][-1]['number'] > 285 and gap['merges'][-1]['impact'] == {
                    'fortis-gateway': ['image-rebuild'], 'fortis-registry-pilot': ['image-rebuild'],
                    'release-label-publisher': ['image-rebuild']}, 'REGISTRY_STATE_CUTOVER_GAP')
            elif gap['disposition'] == 'OWNER_REVIEWED_POST_255_CAPTURE_GAP':
                prefix = list(range(253, 253 + len(gap['merges']) - 1))
                _need([merge['number'] for merge in gap['merges'][:-1]] == prefix
                      and gap['merges'][-1]['number'] > prefix[-1], 'REGISTRY_STATE_CUTOVER_GAP')
        for m in audit:
            p=m['collectorCheckpoint']
            _need(set(m)=={'mergeSha','baseSha','headSha','number','treeSha','evidenceId','evidenceDigest',
                       'ownerRequestId','collectorCheckpoint','registryReviewDigest','policyReferenceDigest',
                       'impactDigest','classification','sourceDependencyTargets'}
                  and m['baseSha']==cursor and all(_hex(m[k],40) for k in ('mergeSha','headSha','treeSha'))
                  and m['mergeSha'] not in seen and _uuid(m['evidenceId']) and m['evidenceId'] not in eids
                  and _uuid(m['ownerRequestId']) and m['ownerRequestId'] not in owners
                  and type(m['number']) is int and m['number']>0 and m['number'] not in numbers
                  and all(_hex(m[k],64) for k in ('evidenceDigest','registryReviewDigest','impactDigest'))
                  and m['policyReferenceDigest']==scope['policyReferenceDigest']
                  and m['classification'] in ('deployment','no-deployment')
                  and _names(m['sourceDependencyTargets'])
                  and type(p['revision']) is int and rev<p['revision']<=cp['revision']
                  and set(p)==set(cp) and p['schemaVersion']==cp['schemaVersion']
                  and p['instanceId']==cp['instanceId'] and _hex(p['eventDigest'],64)
                  and (p['revision']!=cp['revision'] or p==cp),'REGISTRY_STATE_RANGE_INVALID')
            cursor=m['mergeSha'];seen.add(cursor);eids.add(m['evidenceId']);numbers.add(m['number'])
            owners.add(m['ownerRequestId']);rev=p['revision']
        _need(cursor==src,'REGISTRY_STATE_RANGE_INVALID')
        deployment_ids={m['evidenceId'] for m in audit if m['classification']=='deployment'}
        used=set();subjects=set();records=set()
        for row in rows:
            ident=row['identity'];subject={k:ident[k] for k in ('repository','targetId','environment')}
            _need(set(row)=={'subjectId','recordId','identity','componentId','resourceIds',
                  'requiresComponentIds','buildUnitId','deploymentProcedure','verification','requiredActions',
                  'evidenceIds','artifact','actual','planningState','evidenceVerified'}
                  and set(ident)==set(subject)|{'desiredSourceSha','catalogCommitSha','catalogSha256'}
                  and subject['repository']==REPOSITORY
                  and all(_name(subject[k]) for k in ('targetId','environment'))
                  and _name(row['componentId']) and _names(row['resourceIds'],empty=False)
                  and _names(row['requiresComponentIds'])
                  and (row['buildUnitId'] is None or _name(row['buildUnitId']))
                  and type(row['deploymentProcedure']) is str and 0<len(row['deploymentProcedure'])<=240
                  and type(row['verification']) is list and 0<len(row['verification'])<=40
                  and all(type(v) is str and 0<len(v)<=500 for v in row['verification'])
                  and len(set(row['verification']))==len(row['verification'])
                  and ident['desiredSourceSha']==src and ident['catalogCommitSha']==scope['baselineSha']
                  and ident['catalogSha256']==scope['catalogSha256']
                  and row['recordId']==_hash(ident) and row['subjectId']==_hash(subject)
                  and row['recordId'] not in records and row['subjectId'] not in subjects
                  and row['actual'] is None and row['planningState']=='PLANNED_UNVERIFIED'
                  and row['evidenceVerified'] is False and row['artifact']=={'state':'NOT_BUILT','digest':None}
                  and type(row['requiredActions']) is list and bool(row['requiredActions'])
                  and row['requiredActions']==sorted(set(row['requiredActions']))
                  and set(row['requiredActions'])<=ACTIONS
                  and type(row['evidenceIds']) is list and bool(row['evidenceIds'])
                  and row['evidenceIds']==[m['evidenceId'] for m in audit if m['evidenceId'] in row['evidenceIds']]
                  and set(row['evidenceIds'])<=deployment_ids,'REGISTRY_STATE_RECORD_INVALID')
            records.add(row['recordId']);subjects.add(row['subjectId']);used.update(row['evidenceIds'])
        _need(used==deployment_ids,'REGISTRY_STATE_RANGE_INVALID')
        _need(type(o['sourceDependencyRequirements']) is list and len(o['sourceDependencyRequirements'])<=200
              and all(type(d) is dict and set(d)=={'repository','targetId','environment','sourceSha','actual'}
                      and d['repository']==REPOSITORY and d['sourceSha']==src and d['actual'] is None
                      and _name(d['targetId']) and _name(d['environment'])
                      for d in o['sourceDependencyRequirements']),'REGISTRY_STATE_DEPENDENCY_INVALID')
        _need([d['targetId'] for d in o['sourceDependencyRequirements']]==
              sorted({t for m in audit for t in m['sourceDependencyTargets']}),
              'REGISTRY_STATE_DEPENDENCY_INVALID')
        return o
    except Denied:
        raise
    except (KeyError,TypeError,ValueError,UnicodeError,AttributeError,RecursionError):
        raise Denied('REGISTRY_STATE_PLAN_INVALID') from None


class _CommitUncertain(Denied):
    pass


class RegistryStateJournal:
    """One initial candidate transaction and original-receipt recovery.

    There is deliberately no API dispatch or public record/queue reader.
    Future suffix/supersession and authenticated admission must extend the
    same owning schema; do not interpret these rows as admitted releases.
    """
    def __init__(self,path,*,instance_id,scope,anchor_reader,plan_reader):
        self.path=Path(path);self.instance_id=instance_id;self.scope=_scope(scope)
        self.anchor_reader=anchor_reader;self.plan_reader=plan_reader
        self.initial=genesis(instance_id,self.scope)
        _need(callable(anchor_reader) and callable(plan_reader),'REGISTRY_STATE_READER_REQUIRED')
        self._paths()

    @classmethod
    def initialize(cls,path,*,instance_id,scope,anchor_reader,plan_reader):
        path=Path(path);scope=_scope(scope);initial=genesis(instance_id,scope)
        _need(path.is_absolute() and path.parent.resolve()==path.parent,'REGISTRY_STATE_PATH')
        _private(path.parent,True)
        _need(callable(anchor_reader) and callable(plan_reader),'REGISTRY_STATE_READER_REQUIRED')
        _need(_raw(anchor_reader())==_raw(initial),'REGISTRY_STATE_ANCHOR_MISMATCH')
        fd=os.open(path,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o600)
        os.close(fd)
        obj=cls(path,instance_id=instance_id,scope=scope,anchor_reader=anchor_reader,plan_reader=plan_reader)
        with obj._db(initialize=True) as db:
            for statement in _SCHEMA:db.execute(statement)
            db.execute('INSERT INTO meta VALUES(?,?)',(instance_id,_raw(scope)))
            _need(obj._anchor()==initial,'REGISTRY_STATE_ANCHOR_MISMATCH')
        return obj

    def _paths(self):
        try:
            _need(self.path.is_absolute() and self.path.parent.resolve()==self.path.parent,'REGISTRY_STATE_PATH')
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
            raise Denied('REGISTRY_STATE_UNAVAILABLE') from None

    @contextmanager
    def _db(self,initialize=False):
        self._paths();db=None
        try:
            db=sqlite3.connect(self.path.as_uri()+'?mode=rw',uri=True,timeout=3,isolation_level=None)
            db.execute('PRAGMA trusted_schema=OFF');db.execute('PRAGMA foreign_keys=ON')
            db.execute('PRAGMA busy_timeout=3000');db.execute('PRAGMA synchronous=FULL')
            if initialize:
                _need(db.execute('PRAGMA journal_mode=WAL').fetchone()==('wal',),'REGISTRY_STATE_WAL_REQUIRED')
            else:
                _need(db.execute('PRAGMA journal_mode').fetchone()==('wal',),'REGISTRY_STATE_WAL_REQUIRED')
            db.execute('BEGIN IMMEDIATE')
            if not initialize:
                _need(db.execute("SELECT sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_autoindex_%' ORDER BY name").fetchall()==
                      [(x,) for x in (_SCHEMA[0],_SCHEMA[1],_SCHEMA[2])],
                      'REGISTRY_STATE_SCHEMA_MISMATCH')
                _need(db.execute('PRAGMA user_version').fetchone()==(1,)
                      and db.execute('SELECT * FROM meta LIMIT 2').fetchall()==[(self.instance_id,_raw(self.scope))],
                      'REGISTRY_STATE_SCHEMA_MISMATCH')
            yield db
            try:
                db.commit()
            except sqlite3.Error:
                raise _CommitUncertain('REGISTRY_STATE_COMMIT_UNCERTAIN') from None
        except sqlite3.Error:
            raise Denied('REGISTRY_STATE_UNAVAILABLE') from None
        finally:
            if db is not None:db.close()

    def _anchor(self):
        try:
            a=self.anchor_reader()
            _need(type(a) is dict and set(a)==set(self.initial)
                  and type(a['schemaVersion']) is int and a['schemaVersion']==1
                  and a['instanceId']==self.instance_id and a['scopeDigest']==self.initial['scopeDigest']
                  and type(a['revision']) is int and 0<=a['revision']<=1
                  and _hex(a['eventDigest'],64),'REGISTRY_STATE_ANCHOR_INVALID')
            return _decode(_raw(a))
        except Denied:
            raise
        except Exception:
            raise Denied('REGISTRY_STATE_ANCHOR_UNAVAILABLE') from None

    def _receipt(self,request,o,event):
        return {'schemaVersion':1,'operationId':request['operationId'],'actor':request['actor'],
                'repository':REPOSITORY,'evidenceId':request['evidenceId'],'evidenceDigest':request['evidenceDigest'],
                'fingerprint':_hash(request),'previousCheckpoint':self.initial,
                'checkpoint':_checkpoint(self.instance_id,self.scope,1,event),
                'candidateCursor':o['selectedMainSha'],'recordIds':sorted(r['recordId'] for r in o['recordCandidates']),
                'rangeClassification':o['rangeClassification'],'evidenceVerified':False,
                'admissionAllowed':False,'deploymentAllowed':False}

    def _checked(self,db):
        _need(db.execute('PRAGMA quick_check').fetchall()==[('ok',)]
              and db.execute('PRAGMA foreign_key_check').fetchone() is None,'REGISTRY_STATE_CORRUPT')
        _need(db.execute('SELECT COUNT(*) FROM operations').fetchone()[0]<=1
              and db.execute('SELECT COALESCE(SUM(length(CAST(evidence AS BLOB))),0) FROM operations').fetchone()[0]<=MAX_BYTES
              and db.execute('SELECT COALESCE(SUM(length(CAST(request AS BLOB))+length(CAST(receipt AS BLOB))),0) FROM operations').fetchone()[0]<=MAX_BYTES
              and db.execute('SELECT COUNT(*) FROM records').fetchone()[0]<=200
              and db.execute('SELECT COALESCE(SUM(length(CAST(payload AS BLOB))),0) FROM records').fetchone()[0]<=MAX_BYTES,
              'REGISTRY_STATE_LIMIT')
        rows=db.execute('SELECT * FROM operations').fetchall()
        records=db.execute('SELECT record_id,subject_id,revision,payload FROM records ORDER BY record_id').fetchall()
        if not rows:
            _need(not records,'REGISTRY_STATE_CORRUPT')
            return self.initial,None,None
        rev,op,raw,fp,evidence,ed,receipt,prev,event=rows[0]
        req=_decode(raw);ev=_decode(evidence)
        _need(rev==1 and req==_request(req['actor'],req['operationId'],req['evidenceId'],
                     req['evidenceDigest'],req['expectedRevision']) and req['expectedRevision']==0
              and req['operationId']==op and _hash(req)==fp and ed==req['evidenceDigest']
              and prev==self.initial['eventDigest'],'REGISTRY_STATE_CORRUPT')
        o=_plan(ev,req,self.scope)
        computed=_hash([self.instance_id,self.initial['scopeDigest'],rev,fp,ed,prev])
        expected=self._receipt(req,o,computed)
        _need(event==computed and _decode(receipt)==expected
              and records==sorted((r['recordId'],r['subjectId'],1,_raw(r)) for r in o['recordCandidates']),
              'REGISTRY_STATE_CORRUPT')
        return expected['checkpoint'],req,expected

    def _outcome(self,anchor,head,receipt):
        if anchor==head:
            outcome={'result':'ANCHORED_CANDIDATE_TRANSACTION','receipt':receipt}
        elif anchor==self.initial and head==receipt['checkpoint']:
            outcome={'result':'UNKNOWN_OUTCOME','pendingCheckpoint':head,
                     'previousCheckpoint':self.initial,'operationId':receipt['operationId']}
        else:
            raise Denied('REGISTRY_STATE_ANCHOR_MISMATCH')
        if self._anchor()!=anchor:raise Stale('REGISTRY_STATE_ANCHOR_CHANGED')
        return outcome

    def append_initial(self,*,actor,operation_id,evidence_id,evidence_digest,expected_revision):
        req=_request(actor,operation_id,evidence_id,evidence_digest,expected_revision)
        anchor=self._anchor()
        with self._db() as db:
            head,old,receipt=self._checked(db)
            if old is not None and old['operationId']==operation_id:
                if old!=req:raise Conflict('REGISTRY_STATE_OPERATION_CONFLICT')
                return self._outcome(anchor,head,receipt)
            _need(anchor==head,'REGISTRY_STATE_ANCHOR_MISMATCH')
            if head['revision']!=expected_revision:raise Stale('REGISTRY_STATE_REVISION_STALE')
            _need(old is None,'REGISTRY_STATE_SUFFIX_UNSUPPORTED')
        # Read candidate by identity, never accept an inline caller plan.
        evidence=self.plan_reader(evidence_id)
        evidence=_decode(_raw(evidence));o=_plan(evidence,req,self.scope)
        event=_hash([self.instance_id,self.initial['scopeDigest'],1,_hash(req),evidence_digest,anchor['eventDigest']])
        receipt=self._receipt(req,o,event)
        try:
            with self._db() as db:
                fresh,old,_=self._checked(db)
                _need(fresh==anchor==self.initial and old is None and self._anchor()==anchor,
                      'REGISTRY_STATE_CHECKPOINT_CHANGED')
                db.execute('INSERT INTO operations VALUES(?,?,?,?,?,?,?,?,?)',
                           (1,operation_id,_raw(req),_hash(req),_raw(evidence),evidence_digest,
                            _raw(receipt),anchor['eventDigest'],event))
                db.executemany('INSERT INTO records VALUES(?,?,?,?)',
                               [(r['recordId'],r['subjectId'],1,_raw(r)) for r in o['recordCandidates']])
                self._checked(db)
        except _CommitUncertain:
            return {'result':'UNKNOWN_OUTCOME','operationId':operation_id}
        # A fault after local commit is resolved by querying the original
        # operation, never by assuming success or re-deriving the plan.
        try:
            outcome=self.operation(actor=actor,operation_id=operation_id)
            _need(outcome.get('result')!='CANDIDATE_OPERATION_NOT_FOUND','REGISTRY_STATE_LOST_COMMIT')
            return outcome
        except (Denied,Stale):
            return {'result':'UNKNOWN_OUTCOME','operationId':operation_id}

    def operation(self,*,actor,operation_id):
        _need(actor==PLANNER and _uuid(operation_id),'REGISTRY_STATE_REQUEST_INVALID')
        anchor=self._anchor()
        with self._db() as db:
            head,req,receipt=self._checked(db)
            if req is not None and req['operationId']==operation_id:
                return self._outcome(anchor,head,receipt)
            _need(anchor==head,'REGISTRY_STATE_ANCHOR_MISMATCH')
            if self._anchor()!=anchor:raise Stale('REGISTRY_STATE_ANCHOR_CHANGED')
            return {'result':'CANDIDATE_OPERATION_NOT_FOUND'}

    def checkpoint(self):
        """Candidate cursor only; no authoritative state while pending."""
        anchor=self._anchor()
        with self._db() as db:
            head,_,receipt=self._checked(db)
            _need(anchor==head,'REGISTRY_STATE_ANCHOR_MISMATCH')
            if self._anchor()!=anchor:raise Stale('REGISTRY_STATE_ANCHOR_CHANGED')
            return {'checkpoint':head,'candidateCursor':self.scope['baselineSha'] if receipt is None else
                    receipt['candidateCursor'],'evidenceVerified':False,'admissionAllowed':False}

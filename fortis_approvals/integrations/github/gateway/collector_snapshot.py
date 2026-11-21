"""Private P5 collector candidate receipt journal, not Registry state.

An independently provisioned anchor is required for reads. This module has
no anchor writer, live authentication/transport, ingress or admission grant.
Owner composition supplies actual dependencies, never a raw evidence DTO.
"""
from contextlib import contextmanager
import os
from pathlib import Path
import sqlite3
import time

from ....core import Conflict, Denied, Stale, canonical, loads_strict
from .review_capture import _hash, _hex, _need, _private, _uuid
from .selected_main_binding import observe_selected_main

REPOSITORY = 'AlexPastukhh/fortis-approvals'
ISSUER = 'release-registry-collector-v1'
MAX_ROWS = 128
MAX_BYTES = 32_000_000
MAX_SNAPSHOT = 2_000_000
GENESIS = '0'*64
_FLAGS = ('historicalPolicyVerified','historicalMergeCutoffVerified',
          'dependencyClosureVerified','componentBindingsVerified',
          'evidenceVerified','admissionAllowed','deploymentAllowed')
_SCHEMA = """
CREATE TABLE meta(instance_id TEXT PRIMARY KEY NOT NULL);
CREATE TABLE snapshots(
    revision INTEGER PRIMARY KEY,
    evidence_id TEXT UNIQUE NOT NULL,
    request TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    snapshot TEXT NOT NULL,
    snapshot_digest TEXT NOT NULL,
    previous_digest TEXT NOT NULL,
    event_digest TEXT NOT NULL UNIQUE
);
PRAGMA user_version=1;
"""


def genesis(instance_id):
    _need(_uuid(instance_id),'P5_SNAPSHOT_INSTANCE_INVALID')
    return {'schemaVersion':1,'instanceId':instance_id,'revision':0,'eventDigest':GENESIS}


def _source(snapshot, request):
    bound='policyReferenceDigest' in request
    fields={'schemaVersion','issuer','repository','evidenceId','result'}
    if bound: fields|={'registryPolicy','registryReview'}
    _need(type(snapshot) is dict and set(snapshot)==fields
          and type(snapshot['schemaVersion']) is int and snapshot['schemaVersion']==(2 if bound else 1)
          and snapshot['issuer']==ISSUER and snapshot['repository']==REPOSITORY
          and snapshot['evidenceId']==request['evidenceId'],'P5_SNAPSHOT_SOURCE_INVALID')
    result=snapshot['result']
    _need(type(result) is dict and result.get('result')=='SELECTED_MAIN_LOCAL_SOURCE_BOUND'
          and all(result.get(k) is False for k in _FLAGS),'P5_SNAPSHOT_SOURCE_INVALID')
    o=result['observation']
    review=o['reviewedMerge'];decision=review['ownerDecision'];impact=o['retainedImpact']
    _need(o['repository']==REPOSITORY and o['selectedMainSha']==request['selectedMainSha']
          and _hash(o)==result['observationDigest']
          and _hash(review)==o['reviewedMergeSha256']
          and _hash(impact)==o['retainedImpactSha256']
          and decision['result']=='OWNER_BUNDLE_DECISION_BOUND'
          and decision['ownerDecisionBound'] is True
          and decision['requestId']==request['ownerRequestId']
          and decision['repository']==impact['repository']==REPOSITORY
          and decision['number']==impact['number']==o['number']
          and decision['bundleDigest']==impact['bundleDigest']==review['bundleDigest']
          and decision['captureEventDigest']==impact['captureEventDigest']
          and review['mergeObservation']['selectedMainSha']==request['selectedMainSha']
          and review['mergeObservation']['pullRequest']['mergeSha']==request['selectedMainSha'],
          'P5_SNAPSHOT_SOURCE_INVALID')
    if bound:
        from .registry_review_policy import policy_reference, _binding, _epoch
        pin=request['policyReferenceDigest']
        ref=policy_reference(lambda:snapshot['registryPolicy'],pin)
        rr=snapshot['registryReview']
        flags={'registryReviewPolicyVerified','registryReviewCutoffVerified',
               'historicalPolicyVerified','historicalMergeCutoffVerified',
               'evidenceVerified','admissionAllowed','deploymentAllowed'}
        _need(type(rr) is dict and set(rr)=={'result','observation','observationDigest',*flags}
              and rr['result']=='REGISTRY_REVIEW_POLICY_MATCH_CANDIDATE'
              and all(rr[k] is False for k in flags),'P5_SNAPSHOT_POLICY_INVALID')
        r=rr['observation']
        _need(type(r) is dict and set(r)=={
            'repository','policyBinding','selectedMainSha','ownerRequestId',
            'ownerRequestFingerprint','captureEventDigest','bundleDigest','captureCheckpoint',
            'capturedAt','ownerDecisionAt','ownerExecutionAt','mergedAt',
            'selectedMainObservationDigest','ciBindingDigest'}
            and _hash(r)==rr['observationDigest']
            and r['repository']==REPOSITORY and r['policyBinding']==_binding(ref,pin)
            and r['selectedMainSha']==request['selectedMainSha']
            and r['ownerRequestId']==decision['requestId']
            and r['ownerRequestFingerprint']==decision['requestFingerprint']
            and r['captureEventDigest']==decision['captureEventDigest']
            and r['bundleDigest']==decision['bundleDigest']
            and r['captureCheckpoint']==review['checkpoint']
            and r['ownerDecisionAt']==decision['ownerDecisionAt']
            and r['ownerExecutionAt']==decision['ownerExecutionAt']
            and r['mergedAt']==review['mergeObservation']['pullRequest']['mergedAt']
            and r['selectedMainObservationDigest']==result['observationDigest']
            and r['ciBindingDigest']==review['retainedCiBindingSha256']
            and ref['effectiveAt']<=_epoch(r['capturedAt'])<r['ownerDecisionAt']<=r['ownerExecutionAt']<_epoch(r['mergedAt'])
            and _epoch(r['mergedAt'])-r['ownerDecisionAt']<=ref['maxReviewToMergeSeconds'],
            'P5_SNAPSHOT_POLICY_BINDING_MISMATCH')


class CollectorSnapshotStore:
    """Bounded immutable candidate snapshots with externally witnessed head.

    The anchor_reader is a host-composed dependency. It MUST NOT simply read
    this SQLite store. Tests inject an independent in-memory witness, not
    production durable anchor authority. There is no self-anchoring path.
    """
    def __init__(self,path,*,instance_id,anchor_reader):
        self.path=Path(path)
        self.instance_id=instance_id
        self.anchor_reader=anchor_reader
        genesis(instance_id)
        _need(callable(anchor_reader),'P5_SNAPSHOT_ANCHOR_UNAVAILABLE')
        self._check_path()

    @classmethod
    def initialize(cls,path,*,instance_id,anchor_reader):
        path=Path(path)
        _need(path.is_absolute() and path.parent.resolve()==path.parent,
              'P5_SNAPSHOT_STORAGE_PATH')
        _private(path.parent,directory=True)
        _need(callable(anchor_reader),'P5_SNAPSHOT_ANCHOR_UNAVAILABLE')
        try:
            initial=anchor_reader()
        except Exception:
            raise Denied('P5_SNAPSHOT_ANCHOR_UNAVAILABLE') from None
        _need(type(initial) is dict and type(initial.get('revision')) is int
              and type(initial.get('schemaVersion')) is int
              and initial==genesis(instance_id),'P5_SNAPSHOT_ANCHOR_MISMATCH')
        fd=os.open(path,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o600)
        os.close(fd)
        store=cls(path,instance_id=instance_id,anchor_reader=anchor_reader)
        with store._db(initialize=True) as db:
            db.executescript(_SCHEMA)
            db.execute('INSERT INTO meta VALUES(?)',(instance_id,))
        return store

    def _check_path(self):
        try:
            _need(self.path.is_absolute() and self.path.parent.resolve()==self.path.parent,
                  'P5_SNAPSHOT_STORAGE_PATH')
            _private(self.path.parent,directory=True)
            _private(self.path,directory=False)
            for suffix in ('-journal','-wal','-shm'):
                sidecar=Path(str(self.path)+suffix)
                if sidecar.exists() or sidecar.is_symlink():
                    _private(sidecar,directory=False)
        except OSError:
            raise Denied('P5_SNAPSHOT_STORAGE_UNAVAILABLE') from None

    @contextmanager
    def _db(self,*,initialize=False):
        self._check_path()
        db=None
        try:
            db=sqlite3.connect(self.path.as_uri()+'?mode=rw',uri=True,timeout=5)
            db.execute('PRAGMA trusted_schema=OFF')
            db.execute('PRAGMA synchronous=FULL')
            db.execute('BEGIN IMMEDIATE')
            if not initialize:
                _need(db.execute('PRAGMA user_version').fetchone()==(1,)
                      and db.execute('SELECT instance_id FROM meta LIMIT 2').fetchall()==[(self.instance_id,)],
                      'P5_SNAPSHOT_SCHEMA_INVALID')
            yield db
            db.commit()
        except sqlite3.Error:
            if db is not None: db.rollback()
            raise Denied('P5_SNAPSHOT_STORAGE_UNAVAILABLE') from None
        finally:
            if db is not None: db.close()

    def _anchor(self):
        try:
            value=self.anchor_reader()
        except Exception:
            raise Denied('P5_SNAPSHOT_ANCHOR_UNAVAILABLE') from None
        _need(type(value) is dict and set(value)==set(genesis(self.instance_id))
              and value['instanceId']==self.instance_id
              and type(value['schemaVersion']) is int and value['schemaVersion']==1
              and type(value['revision']) is int and 0<=value['revision']<=MAX_ROWS
              and _hex(value['eventDigest'],64),'P5_SNAPSHOT_ANCHOR_INVALID')
        return dict(value)

    def _checked(self,db):
        _need(db.execute('PRAGMA quick_check').fetchall()==[('ok',)],
              'P5_SNAPSHOT_INTEGRITY_INVALID')
        _need(db.execute('SELECT COALESCE(SUM(length(CAST(snapshot AS BLOB))),0) FROM snapshots').fetchone()[0]
              <=MAX_BYTES,'P5_SNAPSHOT_STORAGE_LIMIT')
        rows=db.execute('SELECT revision,evidence_id,request,fingerprint,snapshot,snapshot_digest,'
                        'previous_digest,event_digest FROM snapshots ORDER BY revision LIMIT ?',
                        (MAX_ROWS+1,)).fetchall()
        _need(len(rows)<=MAX_ROWS,'P5_SNAPSHOT_STORAGE_LIMIT')
        previous=GENESIS
        for rev,row in enumerate(rows,1):
            r,eid,raw_request,fp,raw,sd,prev,event=row
            try:
                req=loads_strict(raw_request);snapshot=loads_strict(raw)
                fields={'evidenceId','ownerRequestId','selectedMainSha','expectedRevision'}
                _need(type(req) is dict and set(req) in (fields,fields|{'policyReferenceDigest'})
                      and ('policyReferenceDigest' not in req or _hex(req['policyReferenceDigest'],64))
                      and type(req['expectedRevision']) is int and req['expectedRevision']==rev-1
                      and _uuid(eid) and req['evidenceId']==eid and _uuid(req['ownerRequestId'])
                      and _hex(req['selectedMainSha'],40)
                      and canonical(req)==raw_request and _hash(req)==fp
                      and len(raw.encode('utf-8'))<=MAX_SNAPSHOT
                      and canonical(snapshot)==raw and _hash(snapshot)==sd,
                      'P5_SNAPSHOT_INTEGRITY_INVALID')
                _source(snapshot,req)
                _need(r==rev and prev==previous and event==_hash(
                    [self.instance_id,rev,eid,fp,sd,prev]),'P5_SNAPSHOT_INTEGRITY_INVALID')
            except (ValueError,TypeError,KeyError,UnicodeError,RecursionError,AttributeError):
                raise Denied('P5_SNAPSHOT_INTEGRITY_INVALID') from None
            previous=event
        return rows,{**genesis(self.instance_id),'revision':len(rows),'eventDigest':previous}

    def _receipt(self,row,*,anchored):
        rev,eid,req,fp,raw,sd,prev,event=row
        request=loads_strict(req)
        receipt={'result':'ANCHORED_CANDIDATE_EVIDENCE_RETAINED' if anchored else 'LOCAL_EVIDENCE_PENDING_ANCHOR',
                'evidenceClass':'SOURCE_CANDIDATE_ONLY','repository':REPOSITORY,
                'evidenceId':eid,'evidenceDigest':sd,'requestDigest':fp,
                'ownerRequestId':request['ownerRequestId'],'selectedMainSha':request['selectedMainSha'],
                'previousCheckpoint':{**genesis(self.instance_id),'revision':rev-1,'eventDigest':prev},
                'checkpoint':{**genesis(self.instance_id),'revision':rev,'eventDigest':event},
                'evidenceVerified':False,'admissionAllowed':False,'deploymentAllowed':False}

        if 'policyReferenceDigest' in request:
            receipt['policyReferenceDigest']=request['policyReferenceDigest']
            receipt['registryReviewDigest']=loads_strict(raw)['registryReview']['observationDigest']
        return receipt

    def retain(self,*,evidence_id,expected_revision,owner_request_id,selected_main_sha,
               adapter,store,core,checkpoint_reader,owner,validator,
               policy_reader=None,expected_policy_digest=None,clock=time.time):
        """One internal capture request; replay never recollects a merged PR.

        expected_revision is the append CAS, bound to evidence ID in the
        resulting event position. A pending result is only a local proposal
        for separate owner-controlled anchor advancement.
        """
        _need(_uuid(evidence_id) and _uuid(owner_request_id) and _hex(selected_main_sha,40)
              and type(expected_revision) is int and 0<=expected_revision<MAX_ROWS,
              'P5_SNAPSHOT_REQUEST_INVALID')
        request={'evidenceId':evidence_id,'ownerRequestId':owner_request_id,
                 'selectedMainSha':selected_main_sha,'expectedRevision':expected_revision}
        bound=policy_reader is not None or expected_policy_digest is not None
        if bound:
            _need(callable(policy_reader) and _hex(expected_policy_digest,64),'P5_SNAPSHOT_POLICY_REQUEST_INVALID')
            request['policyReferenceDigest']=expected_policy_digest
        fp=_hash(request)
        anchor=self._anchor()
        with self._db() as db:
            rows,actual=self._checked(db)
            old=next((row for row in rows if row[1]==evidence_id),None)
            if old is not None:
                if old[3]!=fp or old[0]!=expected_revision+1:
                    raise Conflict('P5_SNAPSHOT_OPERATION_CONFLICT')
                receipt=self._receipt(old,anchored=anchor==actual)
                _need(anchor==actual or (old[0]==actual['revision'] and
                      anchor==receipt['previousCheckpoint']),'P5_SNAPSHOT_ANCHOR_MISMATCH')
                if self._anchor()!=anchor:raise Stale('P5_SNAPSHOT_ANCHOR_CHANGED')
                return receipt
            _need(anchor==actual,'P5_SNAPSHOT_ANCHOR_MISMATCH')
            if actual['revision']!=expected_revision:raise Stale('P5_SNAPSHOT_REVISION_STALE')
        # No transaction held across provider/Git reads. Recheck both CAS and
        # independent witness before writing the exact observed source bytes.
        common=dict(adapter=adapter,store=store,core=core,checkpoint_reader=checkpoint_reader,
                    owner=owner,owner_request_id=owner_request_id,validator=validator,
                    selected_main_sha=selected_main_sha)
        if bound:
            from .registry_review_policy import policy_reference, _observe_registry_review_pair
            ref=policy_reference(policy_reader,expected_policy_digest)
            result,review=_observe_registry_review_pair(**common,policy_reader=policy_reader,
                         expected_policy_digest=expected_policy_digest,clock=clock)
            snapshot={'schemaVersion':2,'issuer':ISSUER,'repository':REPOSITORY,
                      'evidenceId':evidence_id,'result':result,'registryPolicy':ref,'registryReview':review}
            if policy_reference(policy_reader,expected_policy_digest)!=ref:
                raise Stale('P5_SNAPSHOT_POLICY_CHANGED')
        else:
            result=observe_selected_main(**common,expected_merge_sha=selected_main_sha)
            snapshot={'schemaVersion':1,'issuer':ISSUER,'repository':REPOSITORY,
                      'evidenceId':evidence_id,'result':result}
        _source(snapshot,request)
        raw=canonical(snapshot);size=len(raw.encode('utf-8'))
        _need(size<=MAX_SNAPSHOT,'P5_SNAPSHOT_STORAGE_LIMIT')
        sd=_hash(snapshot);rev=expected_revision+1
        event=_hash([self.instance_id,rev,evidence_id,fp,sd,anchor['eventDigest']])
        row=(rev,evidence_id,canonical(request),fp,raw,sd,anchor['eventDigest'],event)
        with self._db() as db:
            rows,fresh=self._checked(db)
            if bound and policy_reference(policy_reader,expected_policy_digest)!=ref:
                raise Stale('P5_SNAPSHOT_POLICY_CHANGED')
            _need(fresh==anchor and self._anchor()==anchor,'P5_SNAPSHOT_ANCHOR_CHANGED')
            _need(len(rows)<MAX_ROWS and sum(len(r[4].encode('utf-8')) for r in rows)+size<=MAX_BYTES,
                  'P5_SNAPSHOT_STORAGE_LIMIT')
            db.execute('INSERT INTO snapshots VALUES(?,?,?,?,?,?,?,?)',row)
        # No external mutation or implied ACK. A crash after commit is
        # recovered by exact retain replay; the pending receipt is not readable.
        return self._receipt(row,anchored=False)

    def _read(self,evidence_id,*,snapshot):
        _need(_uuid(evidence_id),'P5_SNAPSHOT_REQUEST_INVALID')
        anchor=self._anchor()
        with self._db() as db:
            rows,actual=self._checked(db)
            _need(anchor==actual,'P5_SNAPSHOT_ANCHOR_MISMATCH')
            row=next((row for row in rows if row[1]==evidence_id),None)
            _need(row is not None,'P5_SNAPSHOT_NOT_FOUND')
            value=loads_strict(row[4]) if snapshot else self._receipt(row,anchored=True)
            if self._anchor()!=anchor:
                raise Stale('P5_SNAPSHOT_ANCHOR_CHANGED')
            return value

    def anchored_batch(self,evidence_ids):
        """Internal bounded consistent snapshot/receipt read, not admission."""
        _need(type(evidence_ids) is list and len(evidence_ids)<=64
              and all(_uuid(e) for e in evidence_ids)
              and len(set(evidence_ids))==len(evidence_ids),
              'P5_SNAPSHOT_BATCH_INVALID')
        anchor=self._anchor()
        with self._db() as db:
            rows,actual=self._checked(db)
            _need(anchor==actual,'P5_SNAPSHOT_ANCHOR_MISMATCH')
            by_id={row[1]:row for row in rows}
            _need(all(e in by_id for e in evidence_ids),'P5_SNAPSHOT_NOT_FOUND')
            result={'checkpoint':actual,'entries':[
                {'snapshot':loads_strict(by_id[e][4]),
                 'receipt':self._receipt(by_id[e],anchored=True)} for e in evidence_ids]}
            if self._anchor()!=anchor:
                raise Stale('P5_SNAPSHOT_ANCHOR_CHANGED')
            return result

    def read(self,evidence_id):
        """Source-only reader for RegistryBoundary; refuses unanchored bytes."""
        return self._read(evidence_id,snapshot=True)

    def receipt(self,evidence_id):
        return self._read(evidence_id,snapshot=False)

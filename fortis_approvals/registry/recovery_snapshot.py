"""Registry v2 inactive SQLite backup/readback, source-only.

Host-selected private destination and independent owner anchor are inputs.
Does not write, provision, rotate or impersonate the independent anchor;
does not restore an active database or authorize Registry admission.
"""
import hashlib
import os
from pathlib import Path
import sqlite3
import time

from ..core import Denied, Stale
from .state_journal import _private, _need, _uuid, _hex, _raw, _decode, _hash
from .state_journal_v2 import RegistryStateJournalV2

MAX_SQLITE_BYTES=40_000_000
MANIFEST_FIELDS={'schemaVersion','format','backupId','instanceId','scopeDigest',
                 'checkpoint','candidateCursor','sqliteBytes','sqliteSha256',
                 'operationCount','recordCount','supersessionCount'}
_COUNTS=('operations','records','supersessions')


def _paths(directory,backup_id):
    _need(_uuid(backup_id),'REGISTRY_BACKUP_ID_INVALID')
    directory=Path(directory)
    _need(directory.is_absolute() and directory.parent.resolve()==directory.parent,
          'REGISTRY_BACKUP_PATH_INVALID')
    try:
        _private(directory,True)
    except OSError:
        raise Denied('REGISTRY_BACKUP_PATH_UNAVAILABLE') from None
    return directory/('registry-'+backup_id+'.sqlite'),directory/('registry-'+backup_id+'.manifest.json')


def _digest_file(path):
    try:
        _private(path)
        size=path.stat().st_size
        _need(0<size<=MAX_SQLITE_BYTES,'REGISTRY_BACKUP_SIZE')
        digest=hashlib.sha256()
        with path.open('rb') as source:
            for chunk in iter(lambda: source.read(65536),b''):
                digest.update(chunk)
        _need(path.stat().st_size==size,'REGISTRY_BACKUP_CHANGED')
        return size,digest.hexdigest()
    except OSError:
        raise Denied('REGISTRY_BACKUP_UNAVAILABLE') from None


def _counts(store):
    with store._db() as db:
        _,_,_,_,_=store._checked(db)
        return {name:db.execute('SELECT COUNT(*) FROM '+name).fetchone()[0] for name in _COUNTS}


def _checkpoint(store):
    # A digest/hash chain stored in SQLite is not its own independent anchor.
    # This calls the existing independently composed owner witness reader.
    ref=store.checkpoint()
    _need(type(ref) is dict and set(ref)=={'checkpoint','candidateCursor',
          'evidenceVerified','admissionAllowed'} and ref['evidenceVerified'] is False
          and ref['admissionAllowed'] is False,'REGISTRY_BACKUP_STATE_INVALID')
    return ref


def _verify_snapshot(directory,backup_id,*,instance_id,scope,anchor_reader,plan_reader,
                     manifest=None):
    dbpath,mpath=_paths(directory,backup_id)
    _need(callable(anchor_reader) and callable(plan_reader),'REGISTRY_BACKUP_READER_REQUIRED')
    _private(dbpath)
    if manifest is None:
        _private(mpath)
        _need(mpath.stat().st_size<=12000,'REGISTRY_BACKUP_MANIFEST_INVALID')
        try:manifest=_decode(mpath.read_text('utf-8'))
        except (UnicodeError,OSError):
            raise Denied('REGISTRY_BACKUP_MANIFEST_INVALID') from None
    _need(type(manifest) is dict and set(manifest)==MANIFEST_FIELDS
          and type(manifest['schemaVersion']) is int and manifest['schemaVersion']==1
          and manifest['format']=='registry-state-v2-inactive-sqlite'
          and manifest['backupId']==backup_id and manifest['instanceId']==instance_id
          and manifest['scopeDigest']==_hash(scope)
          and type(manifest['sqliteBytes']) is int and 0<manifest['sqliteBytes']<=MAX_SQLITE_BYTES
          and _hex(manifest['sqliteSha256'],64)
          and _hex(manifest['candidateCursor'],40)
          and all(type(manifest[k]) is int and 0<=manifest[k]<=1024 for k in
                  ('operationCount','recordCount','supersessionCount')),
          'REGISTRY_BACKUP_MANIFEST_INVALID')
    size,digest=_digest_file(dbpath)
    _need((size,digest)==(manifest['sqliteBytes'],manifest['sqliteSha256']),
          'REGISTRY_BACKUP_DIGEST_MISMATCH')
    # Open only a separate private snapshot, never reconstruct active state.
    store=RegistryStateJournalV2(dbpath,instance_id=instance_id,scope=scope,
                                 anchor_reader=anchor_reader,plan_reader=plan_reader)
    state=_checkpoint(store);counts=_counts(store)
    _need(state['checkpoint']==manifest['checkpoint']
          and state['candidateCursor']==manifest['candidateCursor']
          and counts=={name:manifest[prefix+'Count'] for name,prefix in
                      (('operations','operation'),('records','record'),('supersessions','supersession'))},
          'REGISTRY_BACKUP_CONTENT_MISMATCH')
    if _checkpoint(store)!=state:
        raise Stale('REGISTRY_BACKUP_ANCHOR_CHANGED')
    # Snapshot SQLite may create ephemeral WAL/SHM metadata when opened.
    # Original durable main DB bytes MUST remain unchanged.
    _need(_digest_file(dbpath)==(size,digest),'REGISTRY_BACKUP_CHANGED')
    return manifest


def verify_inactive_backup(*,directory,backup_id,instance_id,scope,
                           anchor_reader,plan_reader):
    """Compare backup bytes, full journal and external checkpoint; NO restore."""
    try:
        manifest=_verify_snapshot(directory,backup_id,instance_id=instance_id,
              scope=scope,anchor_reader=anchor_reader,plan_reader=plan_reader)
        return {'result':'INACTIVE_BACKUP_MATCH_CANDIDATE','backupId':backup_id,
                'manifestDigest':_hash(manifest),'checkpoint':manifest['checkpoint'],
                'candidateCursor':manifest['candidateCursor'],
                'restoreAllowed':False,'admissionAllowed':False}
    except OSError:
        raise Denied('REGISTRY_BACKUP_UNAVAILABLE') from None


def create_verified_backup(*,store,directory,backup_id):
    """Snapshot via SQLite backup API, never copy WAL/DB files with shutil."""
    _need(type(store) is RegistryStateJournalV2,'REGISTRY_BACKUP_STORE_REQUIRED')
    dbpath,mpath=_paths(directory,backup_id)
    _need(dbpath.parent!=store.path.parent and
          dbpath.parent.resolve()!=store.path.parent.resolve(),
          'REGISTRY_BACKUP_NOT_SEPARATE')
    _need(not dbpath.exists() and not dbpath.is_symlink()
          and not mpath.exists() and not mpath.is_symlink(),
          'REGISTRY_BACKUP_ALREADY_EXISTS')
    original=_checkpoint(store)
    # Refuse to copy an unanchored local pending operation.
    try:
        fd=os.open(dbpath,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o600)
        os.close(fd)
        try:
            with sqlite3.connect(store.path.as_uri()+'?mode=ro',uri=True,timeout=3) as source:
                with sqlite3.connect(dbpath.as_uri()+'?mode=rw',uri=True,timeout=3) as target:
                    deadline=time.monotonic()+20
                    def bounded(*_args):
                        _need(time.monotonic()<=deadline,'REGISTRY_BACKUP_TIMEOUT')
                    source.backup(target,pages=128,progress=bounded,sleep=0.05)
        except sqlite3.Error:
            raise Denied('REGISTRY_BACKUP_SQLITE_FAILED') from None
        _private(dbpath)
        _need(_checkpoint(store)==original,'REGISTRY_BACKUP_SOURCE_CHANGED')
        # Validate copy using the SAME external witness, not its own hash.
        copy=RegistryStateJournalV2(dbpath,instance_id=store.instance_id,
                scope=store.scope,anchor_reader=store.anchor_reader,plan_reader=store.plan_reader)
        state=_checkpoint(copy)
        _need(state==original,'REGISTRY_BACKUP_SOURCE_CHANGED')
        counts=_counts(copy);size,digest=_digest_file(dbpath)
        _need(_checkpoint(store)==original and _checkpoint(copy)==original,
              'REGISTRY_BACKUP_SOURCE_CHANGED')
        # Read-only metadata digest identifies the exact verified SQLite bytes.
        manifest={'schemaVersion':1,'format':'registry-state-v2-inactive-sqlite',
                  'backupId':backup_id,'instanceId':store.instance_id,
                  'scopeDigest':_hash(store.scope),'checkpoint':state['checkpoint'],
                  'candidateCursor':state['candidateCursor'],
                  'sqliteBytes':size,'sqliteSha256':digest,
                  'operationCount':counts['operations'],'recordCount':counts['records'],
                  'supersessionCount':counts['supersessions']}
        _need(_verify_snapshot(directory,backup_id,instance_id=store.instance_id,
              scope=store.scope,anchor_reader=store.anchor_reader,
              plan_reader=store.plan_reader,manifest=manifest)==manifest,
              'REGISTRY_BACKUP_VERIFY_FAILED')
        with dbpath.open('rb') as destination:
            os.fsync(destination.fileno())
        fd=os.open(mpath,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        try:
            with os.fdopen(fd,'wb') as output:
                output.write(_raw(manifest).encode('utf-8'))
                output.flush();os.fsync(output.fileno())
        except Exception:
            raise
        directory_fd=os.open(dbpath.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:os.fsync(directory_fd)
        finally:os.close(directory_fd)
        _need(_checkpoint(store)==original,'REGISTRY_BACKUP_SOURCE_CHANGED')
        return verify_inactive_backup(directory=directory,backup_id=backup_id,
                instance_id=store.instance_id,scope=store.scope,
                anchor_reader=store.anchor_reader,plan_reader=store.plan_reader)
    except (OSError,sqlite3.Error):
        raise Denied('REGISTRY_BACKUP_UNAVAILABLE') from None


# Functional V1 uses a *different on-disk schema* and a deliberately weaker
# local-chain threat model. Never reuse v2's owner checkpoint validation by
# passing a synthetic anchor or "verified=True" witness.
LOCAL_MANIFEST_FIELDS={
    'schemaVersion','format','backupId','instanceId','scopeDigest',
    'localCheckpoint','candidateCursor','integrityModel','sqliteBytes',
    'sqliteSha256','operationCount','recordCount','supersessionCount',
}
LOCAL_FORMAT='registry-functional-v1-local-inactive-sqlite'


def _local_state(store):
    """Verify full local history in a read-only transaction."""
    with store._read_only_db() as db:
        head,cursor,_,_,_=store._state(db)
        counts={name:db.execute('SELECT COUNT(*) FROM '+name).fetchone()[0]
                for name in _COUNTS}
    return head,cursor,counts


def _local_backup_manifest(directory,backup_id,*,instance_id,scope,
                           plan_reader,manifest=None):
    from .functional_v1_journal import FunctionalV1CandidateJournal
    dbpath,mpath=_paths(directory,backup_id)
    _need(callable(plan_reader),'REGISTRY_LOCAL_BACKUP_READER_REQUIRED')
    _private(dbpath)
    if manifest is None:
        _private(mpath)
        _need(0<mpath.stat().st_size<=12000,
              'REGISTRY_LOCAL_BACKUP_MANIFEST_INVALID')
        try:manifest=_decode(mpath.read_text('utf-8'))
        except (UnicodeError,OSError):
            raise Denied('REGISTRY_LOCAL_BACKUP_MANIFEST_INVALID') from None
    _need(type(manifest) is dict and set(manifest)==LOCAL_MANIFEST_FIELDS
          and type(manifest['schemaVersion']) is int and
          manifest['schemaVersion']==1
          and manifest['format']==LOCAL_FORMAT
          and manifest['backupId']==backup_id
          and manifest['instanceId']==instance_id
          and manifest['scopeDigest']==_hash(scope)
          and manifest['integrityModel']=='LOCAL_EVENT_CHAIN_ONLY'
          and type(manifest['sqliteBytes']) is int
          and 0<manifest['sqliteBytes']<=MAX_SQLITE_BYTES
          and _hex(manifest['sqliteSha256'],64)
          and _hex(manifest['candidateCursor'],40)
          and all(type(manifest[key]) is int and 0<=manifest[key]<=1024
                  for key in ('operationCount','recordCount','supersessionCount')),
          'REGISTRY_LOCAL_BACKUP_MANIFEST_INVALID')
    size,digest=_digest_file(dbpath)
    _need((size,digest)==(manifest['sqliteBytes'],manifest['sqliteSha256']),
          'REGISTRY_LOCAL_BACKUP_DIGEST_MISMATCH')
    copy=FunctionalV1CandidateJournal(
        dbpath,instance_id=instance_id,scope=scope,plan_reader=plan_reader)
    head,cursor,counts=_local_state(copy)
    _need(head==manifest['localCheckpoint']
          and cursor==manifest['candidateCursor']
          and counts=={name:manifest[prefix+'Count'] for name,prefix in
                      (('operations','operation'),('records','record'),
                       ('supersessions','supersession'))},
          'REGISTRY_LOCAL_BACKUP_CONTENT_MISMATCH')
    # Readonly snapshot read must never alter the captured database bytes.
    _need(_digest_file(dbpath)==(size,digest),'REGISTRY_LOCAL_BACKUP_CHANGED')
    return manifest


def verify_inactive_local_backup(*,directory,backup_id,instance_id,scope,
                                 plan_reader):
    """Check exact private SQLite snapshot and local event-chain continuity.

    A full database + manifest rollback can still pass. This is NOT a
    protected witness or a restore/activation procedure.
    """
    try:
        manifest=_local_backup_manifest(
            directory,backup_id,instance_id=instance_id,
            scope=scope,plan_reader=plan_reader)
        return {
            'result':'INACTIVE_LOCAL_BACKUP_MATCH_CANDIDATE',
            'backupId':backup_id,'manifestDigest':_hash(manifest),
            'localCheckpoint':manifest['localCheckpoint'],
            'candidateCursor':manifest['candidateCursor'],
            'integrityModel':'LOCAL_EVENT_CHAIN_ONLY',
            'admissionAllowed':False,'restoreAllowed':False,
            'deploymentAllowed':False,'rollbackProtected':False,
        }
    except OSError:
        raise Denied('REGISTRY_LOCAL_BACKUP_UNAVAILABLE') from None


def create_inactive_local_backup(*,store,directory,backup_id):
    """Produce a WAL-consistent *inactive* copy; never install/restore it."""
    from .functional_v1_journal import FunctionalV1CandidateJournal
    _need(type(store) is FunctionalV1CandidateJournal,
          'REGISTRY_LOCAL_BACKUP_STORE_REQUIRED')
    dbpath,mpath=_paths(directory,backup_id)
    _need(dbpath.parent!=store.path.parent and
          dbpath.parent.resolve()!=store.path.parent.resolve(),
          'REGISTRY_LOCAL_BACKUP_NOT_SEPARATE')
    _need(not dbpath.exists() and not dbpath.is_symlink()
          and not mpath.exists() and not mpath.is_symlink(),
          'REGISTRY_LOCAL_BACKUP_ALREADY_EXISTS')
    head,cursor,counts=_local_state(store)
    try:
        fd=os.open(dbpath,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o600)
        os.close(fd)
        try:
            with sqlite3.connect(store.path.as_uri()+'?mode=ro',
                                 uri=True,timeout=3) as source:
                with sqlite3.connect(dbpath.as_uri()+'?mode=rw',
                                     uri=True,timeout=3) as target:
                    deadline=time.monotonic()+20
                    def bounded(*_args):
                        _need(time.monotonic()<=deadline,
                              'REGISTRY_LOCAL_BACKUP_TIMEOUT')
                    source.backup(target,pages=128,progress=bounded,sleep=0.05)
        except sqlite3.Error:
            raise Denied('REGISTRY_LOCAL_BACKUP_SQLITE_FAILED') from None
        _private(dbpath)
        _need(_local_state(store)==(head,cursor,counts),
              'REGISTRY_LOCAL_BACKUP_SOURCE_CHANGED')
        copied=FunctionalV1CandidateJournal(
            dbpath,instance_id=store.instance_id,scope=store.scope,
            plan_reader=store.plan_reader)
        copy_head,copy_cursor,copy_counts=_local_state(copied)
        _need((copy_head,copy_cursor,copy_counts)==(head,cursor,counts),
              'REGISTRY_LOCAL_BACKUP_SOURCE_CHANGED')
        size,digest=_digest_file(dbpath)
        manifest={
            'schemaVersion':1,'format':LOCAL_FORMAT,
            'backupId':backup_id,'instanceId':store.instance_id,
            'scopeDigest':_hash(store.scope),
            'localCheckpoint':head,'candidateCursor':cursor,
            'integrityModel':'LOCAL_EVENT_CHAIN_ONLY',
            'sqliteBytes':size,'sqliteSha256':digest,
            'operationCount':counts['operations'],
            'recordCount':counts['records'],
            'supersessionCount':counts['supersessions'],
        }
        _need(_local_backup_manifest(
            directory,backup_id,instance_id=store.instance_id,
            scope=store.scope,plan_reader=store.plan_reader,
            manifest=manifest)==manifest
            and _local_state(store)==(head,cursor,counts),
            'REGISTRY_LOCAL_BACKUP_SOURCE_CHANGED')
        with dbpath.open('rb') as source_file:
            os.fsync(source_file.fileno())
        fd=os.open(mpath,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'wb') as output:
            output.write(_raw(manifest).encode('utf-8'))
            output.flush()
            os.fsync(output.fileno())
        parent_fd=os.open(dbpath.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:os.fsync(parent_fd)
        finally:os.close(parent_fd)
        _need(_local_state(store)==(head,cursor,counts),
              'REGISTRY_LOCAL_BACKUP_SOURCE_CHANGED')
        return verify_inactive_local_backup(
            directory=directory,backup_id=backup_id,
            instance_id=store.instance_id,scope=store.scope,
            plan_reader=store.plan_reader)
    except (OSError,sqlite3.Error):
        raise Denied('REGISTRY_LOCAL_BACKUP_UNAVAILABLE') from None

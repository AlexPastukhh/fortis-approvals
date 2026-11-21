"""P5 read-only Registry/owner-checkpoint/backup recovery preflight.

Source-only composition with concrete local journal types. It never changes
the owner checkpoint, repairs the Registry, chooses a backup, or promotes
a source candidate to protected/admitted evidence. A locally rolled-back
owner ledger can look like a pending commit: an independent protected
operator must resolve this ambiguity.
"""
from ..core import Denied, Stale
from . import recovery_snapshot
from .checkpoint_cas import OfflineCheckpointCAS, _pending
from .state_journal import _need, _hash
from .state_journal_v2 import RegistryStateJournalV2


def _bind(store,owner):
    _need(type(store) is RegistryStateJournalV2
          and type(owner) is OfflineCheckpointCAS
          and getattr(store.anchor_reader,'__self__',None) is owner
          and getattr(store.anchor_reader,'__func__',None)
                is OfflineCheckpointCAS.read_checkpoint
          and store.instance_id==owner.instance_id
          and store.scope==owner.scope
          and store.initial==owner.initial
          and store.path==owner.registered_registry_path
          and store.path.parent.resolve()!=owner.path.parent.resolve(),
          'REGISTRY_RECOVERY_SOURCE_BOUNDARY_REQUIRED')


def _read_owner(owner):
    with owner._db() as db:
        cp,operations=owner._checked(db)
        return cp,operations


def _read_registry(store):
    with store._db() as db:
        cp,cursor,operations,_,_=store._checked(db)
        return cp,cursor,operations


def _compare(owner_view,store_view):
    owner_cp,owner_ops=owner_view
    state_cp,cursor,state_ops=store_view
    _need(state_cp['revision']>=owner_cp['revision'],
          'REGISTRY_RECOVERY_OWNER_AHEAD')
    _need(state_cp['revision']<=owner_cp['revision']+1,
          'REGISTRY_RECOVERY_GAP_UNSUPPORTED')
    _need(len(owner_ops)==owner_cp['revision']
          and len(state_ops)==state_cp['revision'],
          'REGISTRY_RECOVERY_CHAIN_INVALID')
    for op,(previous,proposed,receipt) in owner_ops.items():
        _need(op in state_ops,'REGISTRY_RECOVERY_OWNER_OPERATION_MISSING')
        req,registry_receipt=state_ops[op]
        _need(req['operationId']==op
              and registry_receipt['operationId']==op
              and registry_receipt['previousCheckpoint']==previous
              and registry_receipt['checkpoint']==proposed
              and receipt['operationId']==op
              and receipt['previousCheckpoint']==previous
              and receipt['checkpoint']==proposed
              and receipt['pendingDigest']==_hash(_pending(op,previous,proposed)),
              'REGISTRY_RECOVERY_CROSS_CHAIN_MISMATCH')
    if state_cp==owner_cp:
        _need(set(state_ops)==set(owner_ops),
              'REGISTRY_RECOVERY_CROSS_CHAIN_MISMATCH')
        return {'status':'MATCHED_LOCAL_CANDIDATES',
                'candidateCursor':cursor,'checkpoint':state_cp,
                'pendingOperation':None}
    # The mismatch may be a legitimate crash after a Registry commit,
    # OR owner-side rollback of a formerly acknowledged CAS.
    # No automatic CAS, restore, or status promotion is permitted.
    _need(state_cp['revision']==owner_cp['revision']+1,
          'REGISTRY_RECOVERY_CHECKPOINT_DIVERGENCE')
    extra=set(state_ops)-set(owner_ops)
    _need(len(extra)==1,'REGISTRY_RECOVERY_CROSS_CHAIN_MISMATCH')
    op=extra.pop()
    req,receipt=state_ops[op]
    _need(req['operationId']==op
          and receipt['previousCheckpoint']==owner_cp
          and receipt['checkpoint']==state_cp,
          'REGISTRY_RECOVERY_CHECKPOINT_DIVERGENCE')
    return {'status':'UNRESOLVED_LOCAL_COMMIT_OR_OWNER_ROLLBACK',
            'checkpoint':owner_cp,
            'candidateCursor':None,
            'pendingOperation':_pending(op,owner_cp,state_cp)}


def reconcile_inactive(*,store,owner,backup_directory=None,backup_id=None):
    """Read-only source candidate reconciliation with optional exact backup.

    The only positive-looking status is a local match, not proof of an
    independently protected checkpoint. In an unresolved case the next
    checkpoint is informational only, never a token to authorize CAS.
    """
    _bind(store,owner)
    _need((backup_directory is None)==(backup_id is None),
          'REGISTRY_RECOVERY_BACKUP_ARGUMENTS_INVALID')
    before_owner=_read_owner(owner)
    before_registry=_read_registry(store)
    projection=_compare(before_owner,before_registry)
    result_backup=None
    if backup_id is not None:
        _need(projection['status']=='MATCHED_LOCAL_CANDIDATES',
              'REGISTRY_RECOVERY_PENDING_BACKUP_BLOCKED')
        result_backup=recovery_snapshot.verify_inactive_backup(
            directory=backup_directory,backup_id=backup_id,
            instance_id=store.instance_id,scope=store.scope,
            anchor_reader=owner.read_checkpoint,plan_reader=store.plan_reader)
        _need(result_backup['checkpoint']==projection['checkpoint']
              and result_backup['candidateCursor']==projection['candidateCursor'],
              'REGISTRY_RECOVERY_BACKUP_NOT_CURRENT')
    after_owner=_read_owner(owner)
    after_registry=_read_registry(store)
    if (before_owner!=after_owner or before_registry!=after_registry):
        raise Stale('REGISTRY_RECOVERY_CHANGED_DURING_READ')
    if result_backup is not None:
        # After all local views are stable, a caller still must not
        # interpret a matching copy as an approved restore target.
        backup_result={'backupId':result_backup['backupId'],
                       'manifestDigest':result_backup['manifestDigest']}
    else:
        backup_result=None
    observation={'repository':store.scope['repository'],
                 'enrollmentId':store.scope['enrollmentId'],
                 'enrollmentReceiptDigest':owner.enrollment_receipt_digest,
                 'instanceId':store.instance_id,
                 'scopeDigest':store.initial['scopeDigest'],
                 'ownerCheckpoint':before_owner[0],
                 'registryCheckpoint':before_registry[0],
                 'registryOperationCount':len(before_registry[2]),
                 'ownerAdvanceCount':len(before_owner[1]),
                 'backup':backup_result,**projection}
    return {'result':'REGISTRY_RECOVERY_READBACK_CANDIDATE',
            'observation':observation,'observationDigest':_hash(observation),
            'protectedCheckpointVerified':False,'enrollmentVerified':False,
            'backupRestorable':False,'restoreAllowed':False,
            'admissionAllowed':False,'deploymentAllowed':False}

"""Pure controller interlock contract. No host writer or live admission.

Pins and evidence must come from the independently protected controller;
this module validates structure, identity and transitions, not provenance.
"""
from . import semantic_contract as sc

PHASES = ('NORMAL','DRAINING','FROZEN_BEFORE_CHECK','CHECK_SEALED',
          'APPLY_STOP','STAGED_TARGET_FROZEN','BACKUP_FROZEN','PROMOTE_FROZEN',
          'COMPLETION_PENDING','RECOVERY_HOLD')
_NEXT = {
    'NORMAL': {'DRAINING'},
    'DRAINING': {'FROZEN_BEFORE_CHECK','RECOVERY_HOLD'},
    'FROZEN_BEFORE_CHECK': {'CHECK_SEALED','RECOVERY_HOLD'},
    'CHECK_SEALED': {'APPLY_STOP','RECOVERY_HOLD'},
    'APPLY_STOP': {'STAGED_TARGET_FROZEN','RECOVERY_HOLD'},
    'STAGED_TARGET_FROZEN': {'BACKUP_FROZEN','RECOVERY_HOLD'},
    'BACKUP_FROZEN': {'PROMOTE_FROZEN','RECOVERY_HOLD'},
    'PROMOTE_FROZEN': {'COMPLETION_PENDING','RECOVERY_HOLD'},
    'COMPLETION_PENDING': {'NORMAL','RECOVERY_HOLD'},
    'RECOVERY_HOLD': {'COMPLETION_PENDING'},
}


def validate_record(value):
    sc.fields(value, ('schemaVersion','registryInstanceId','scopeDigest','sequence',
                      'previousDigest','phase','generation','attempt','proofDigest'))
    sc.need(type(value['schemaVersion']) is int and value['schemaVersion']==1)
    sc.uuid_id(value['registryInstanceId'])
    sc.hex_id(value['scopeDigest'],64)
    sc.revision(value['sequence'])
    sc.hex_id(value['generation'],64)
    sc.need(type(value['phase']) is str and value['phase'] in PHASES)
    if value['sequence']==0:
        sc.need(value['phase']=='NORMAL' and value['previousDigest'] is None
                and value['attempt'] is None and value['proofDigest'] is None)
    else:
        sc.hex_id(value['previousDigest'],64)
        sc.hex_id(value['proofDigest'],64)
        attempt=value['attempt']
        sc.fields(attempt,('attemptId','subject','source','restrictionDigest',
                           'sourceGeneration','targetGeneration'))
        sc.uuid_id(attempt['attemptId'])
        sc.subject(attempt['subject'])
        sc.source(attempt['source'])
        for k in ('restrictionDigest','sourceGeneration','targetGeneration'):
            sc.hex_id(attempt[k],64)
        sc.need(value['generation'] in (attempt['sourceGeneration'],attempt['targetGeneration']))
        if value['phase'] in ('DRAINING','FROZEN_BEFORE_CHECK','CHECK_SEALED','APPLY_STOP'):
            sc.need(value['generation']==attempt['sourceGeneration'])
        if value['phase'] in ('STAGED_TARGET_FROZEN','BACKUP_FROZEN','PROMOTE_FROZEN'):
            sc.need(value['generation']==attempt['targetGeneration'])
    return sc.loads_strict(sc.canonical(value))


def validate_transition(before, after):
    a,b=validate_record(before),validate_record(after)
    sc.need(b['sequence']==a['sequence']+1 and b['previousDigest']==sc.digest(a)
            and b['registryInstanceId']==a['registryInstanceId']
            and b['scopeDigest']==a['scopeDigest'] and b['phase'] in _NEXT[a['phase']],
            'MAINTENANCE_TRANSITION_INVALID')
    if a['phase']=='NORMAL':
        sc.need(b['attempt']['sourceGeneration']==a['generation']
                and (a['attempt'] is None or b['attempt']['attemptId']!=a['attempt']['attemptId']),
                'MAINTENANCE_ATTEMPT_CHANGED')
    else:
        sc.need(a['attempt']==b['attempt'],'MAINTENANCE_ATTEMPT_CHANGED')
        if b['phase'] not in ('STAGED_TARGET_FROZEN','RECOVERY_HOLD','COMPLETION_PENDING'):
            sc.need(a['generation']==b['generation'],'MAINTENANCE_GENERATION_CHANGED')
        if b['phase']=='COMPLETION_PENDING' and a['phase']=='PROMOTE_FROZEN':
            sc.need(b['generation']==a['generation'],'MAINTENANCE_GENERATION_CHANGED')
    return b


def startup_handoff(value):
    sc.fields(value,('role','attemptId','restrictionDigest','interlockDigest','registryDigest'))
    sc.need(value['role'] in ('staged_target','return_source'),'MAINTENANCE_STARTUP_HANDOFF_INVALID')
    sc.uuid_id(value['attemptId'])
    for field in ('restrictionDigest','interlockDigest','registryDigest'):
        sc.hex_id(value[field],64)
    return sc.loads_strict(sc.canonical(value))


def bind_startup_handoff(value,record):
    handoff=startup_handoff(value)
    current=validate_record(record)
    phase,generation=(('STAGED_TARGET_FROZEN','targetGeneration') if handoff['role']=='staged_target'
                      else ('RECOVERY_HOLD','sourceGeneration'))
    attempt=current['attempt']
    sc.need(current['phase']==phase and current['generation']==attempt[generation]
            and attempt['sourceGeneration']!=attempt['targetGeneration']
            and attempt['attemptId']==handoff['attemptId']
            and attempt['restrictionDigest']==handoff['restrictionDigest']
            and sc.digest(current)==handoff['interlockDigest'],
            'MAINTENANCE_STARTUP_HANDOFF_CHANGED')
    return current


def bind_record(value, *, instance_id, scope_digest, generation, expected_digest):
    record=validate_record(value)
    sc.hex_id(expected_digest,64)
    sc.need(record['registryInstanceId']==instance_id and record['scopeDigest']==scope_digest
            and record['generation']==generation and sc.digest(record)==expected_digest,
            'MAINTENANCE_INTERLOCK_MISMATCH')
    return record

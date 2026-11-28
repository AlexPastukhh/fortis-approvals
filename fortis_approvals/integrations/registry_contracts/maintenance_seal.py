"""Supplemental exact freeze proof contract, not the existing state inspector.

Controller must obtain authenticated, independently pinned drain evidence,
original protected inspect_state receipt, validated companion witness and
worker quiescence attestation. This checks their binding only. No path,
host operation, state normalization, auto-GO or growth exception.
"""
from . import semantic_contract as sc
from .maintenance_contract import validate_record, validate_transition


def require_quiescent_companion(companion):
    sc.need(companion['schemaVersion']==1 and type(companion['parentStates']) is dict
            and not any(companion['parentStates'].get(k,0) for k in
                        ('PENDING','APPROVED','DISPATCHED','UNCERTAIN','CLOSED_UNCONFIRMED')),
            'MAINTENANCE_COMPOSITE_NOT_QUIESCENT')


def freeze_binding(record, drain, state_receipt, companion, *, expected_registry_digest,
                   expected_state_digest, expected_companion_digest,
                   worker_attestation_digest, preserved_uncertain_ids,
                   preserved_claimed_ids):
    rec=validate_record(record)
    sc.need(rec['phase']=='DRAINING')
    sc.fields(drain,('status','reservations','interlockDigest','registryDigest',
                     'attemptId','generation','ready'))
    for pin in (expected_registry_digest,expected_state_digest,expected_companion_digest,
                worker_attestation_digest):
        sc.hex_id(pin,64)
    sc.need(drain['status']=='DRAINING' and type(drain['reservations']) is int
            and drain['reservations']==0 and drain['ready'] is True
            and drain['interlockDigest']==sc.digest(rec)
            and drain['registryDigest']==expected_registry_digest
            and drain['generation']==rec['generation']
            and drain['attemptId']==rec['attempt']['attemptId'],
            'MAINTENANCE_DRAIN_UNCONFIRMED')
    sc.fields(state_receipt,('sha256','summary'))
    sc.need(sc.digest(state_receipt)==expected_state_digest and
            sc.digest(companion)==expected_companion_digest,
            'MAINTENANCE_SEAL_WITNESS_CHANGED')
    for ids,limit in ((preserved_uncertain_ids,20),(preserved_claimed_ids,3)):
        sc.need(type(ids) is list and len(ids)<=limit and ids==sorted(set(ids)))
        for ident in ids:sc.uuid_id(ident)
    s=state_receipt['summary']
    states=s['requestStates']
    sc.need(type(states) is dict and all(type(n) is int and n>=0 for n in states.values())
            and not any(states.get(k,0) for k in ('PENDING','APPROVED','DISPATCHED'))
            and s['uncertainRequestIds']==preserved_uncertain_ids
            and states.get('UNCERTAIN',0)==len(preserved_uncertain_ids)
            and s['approvedRequestIds']==[], 'MAINTENANCE_CORE_NOT_QUIESCENT')
    native=s['native']
    jobs=native['jobStates']
    sc.need(type(jobs) is dict and set(jobs)<={'DONE','FAILED','CLAIMED'}
            and all(type(n) is int and n>=0 for n in jobs.values())
            and native['preservedClaimedIds']==preserved_claimed_ids
            and jobs.get('CLAIMED',0)==len(preserved_claimed_ids),
            'MAINTENANCE_WORKER_NOT_QUIESCENT')
    require_quiescent_companion(companion)
    return {'result':'FREEZE_BINDINGS_MATCH_ONLY','interlockDigest':sc.digest(rec),
            'registryDigest':expected_registry_digest,'stateReceiptDigest':expected_state_digest,
            'companionDigest':expected_companion_digest,'workerAttestationDigest':worker_attestation_digest,
            'attemptId':rec['attempt']['attemptId'],'restrictionDigest':rec['attempt']['restrictionDigest']}


def checked_transitions(check, draining):
    """Prepare the exact transitions justified by the saved source Check."""
    start=validate_record(draining)
    sc.need(start['phase']=='DRAINING' and check['result']=='FREEZE_BINDINGS_MATCH_ONLY'
            and check['interlockDigest']==sc.digest(start)
            and check['attemptId']==start['attempt']['attemptId']
            and check['restrictionDigest']==start['attempt']['restrictionDigest'],
            'MAINTENANCE_CHECK_BINDING_CHANGED')
    proof=sc.digest(check)
    frozen=validate_transition(start,{**start,'phase':'FROZEN_BEFORE_CHECK',
                    'sequence':start['sequence']+1,'previousDigest':sc.digest(start),'proofDigest':proof})
    checked=validate_transition(frozen,{**frozen,'phase':'CHECK_SEALED',
                    'sequence':frozen['sequence']+1,'previousDigest':sc.digest(frozen),'proofDigest':proof})
    return {'draining':start,'frozen':frozen,'checked':checked}


def verify_apply_binding(check, draining, frozen, current, state_receipt, companion, *,
                         expected_registry_digest, worker_attestation_digest):
    """Verify the original Check seal against the current protected phase."""
    sc.fields(check, ('result','interlockDigest','registryDigest','stateReceiptDigest',
                      'companionDigest','workerAttestationDigest','attemptId','restrictionDigest'))
    expected=checked_transitions(check,draining)
    sc.need(validate_record(frozen)==expected['frozen'] and validate_record(current)==expected['checked']
            and check['registryDigest']==expected_registry_digest
            and check['workerAttestationDigest']==worker_attestation_digest,
            'MAINTENANCE_CHECK_BINDING_CHANGED')
    for value in (expected_registry_digest,worker_attestation_digest):
        sc.hex_id(value,64)
    sc.fields(state_receipt,('sha256','summary'))
    sc.need(sc.digest(state_receipt)==check['stateReceiptDigest']
            and sc.digest(companion)==check['companionDigest'],
            'MAINTENANCE_SEALED_STATE_CHANGED')
    return check


def apply_stop_plan(checked, check, prepared):
    """Bind a proposed stop to the protected image Check and source records."""
    current=validate_record(checked)
    sc.fields(prepared,('sourceRecordDigest','checkedRecordDigest','targetImageId'))
    for field in ('sourceRecordDigest','checkedRecordDigest'):
        sc.hex_id(prepared[field],64)
    image=prepared['targetImageId']
    sc.need(type(image) is str and image.startswith('sha256:'),'MAINTENANCE_APPLY_STOP_BINDING_CHANGED')
    sc.hex_id(image[7:],64)
    sc.need(current['phase']=='CHECK_SEALED'
            and current['proofDigest']==sc.digest(check)
            and current['attempt']['attemptId']==check['attemptId']
            and current['attempt']['restrictionDigest']==check['restrictionDigest'],
            'MAINTENANCE_APPLY_STOP_BINDING_CHANGED')
    previous=sc.digest(current)
    body={'schemaVersion':1,'attemptId':check['attemptId'],'restrictionDigest':check['restrictionDigest'],
          'checkedPhaseDigest':previous,'sourceReceiptDigest':check['stateReceiptDigest'],**prepared}
    next_record=validate_transition(current,{**current,'phase':'APPLY_STOP',
                          'sequence':current['sequence']+1,'previousDigest':previous,
                          'proofDigest':sc.digest(body)})
    return {**body,'next':next_record}


def same_seal(before,after,*,expected_digest):
    """No new permitted growth; compare original full protected receipts."""
    sc.hex_id(expected_digest,64)
    sc.need(sc.digest(before)==expected_digest and sc.digest(after)==expected_digest,
            'MAINTENANCE_SEALED_STATE_CHANGED')
    return 'SEALED_STATE_MATCH_ONLY'

def _ordinary_chain(intent, begin, check, source_receipt, stop):
    """Reuse the actual checked phase chain, not bootstrap physical proof.

    The host independently verifies container exclusion and the original
    Check/Apply record hashes. This projection does not authorize either.
    """
    from .maintenance_contract import ordinary_pair_intent, paired_draining_record, matching_holds
    pair=ordinary_pair_intent(intent)
    auth=intent['authorization']
    sc.fields(begin,('result','intentDigest','pair','receipts','checkpoint','holdSnapshot','draining','registryDigest'))
    sc.need(begin['result']=='PROTECTED_PAIR_BEGIN_READBACK_ONLY'
            and begin['intentDigest']==sc.digest(intent) and begin['pair']==pair
            and begin['registryDigest']==sc.digest(begin['holdSnapshot'])
            and begin['draining']==paired_draining_record(intent['normal'],pair,begin['receipts'],
                begin['holdSnapshot'],target_generation=auth['targetGeneration'],recorded_at=auth['recordedAt'])
            and begin['checkpoint']['snapshotRevision']==begin['holdSnapshot']['snapshotRevision']
            and begin['checkpoint']['eventDigest']==begin['holdSnapshot']['eventDigest']
            and all(begin['checkpoint'][k]==pair['checkpoint'][k] for k in ('sourceCursor','sourceRevision','profileDigest')),
            'MAINTENANCE_ORDINARY_HANDOVER_CHANGED')
    transitions=checked_transitions(check,begin['draining'])
    checked=transitions['checked']
    prepared={k:stop[k] for k in ('sourceRecordDigest','checkedRecordDigest','targetImageId')}
    sc.need(stop==apply_stop_plan(checked,check,prepared)
            and prepared['sourceRecordDigest']==auth['sourceRecordDigest']
            and prepared['targetImageId']=='sha256:'+pair['artifacts']['gateway']
            and check['stateReceiptDigest']==sc.digest(source_receipt)
            and check['registryDigest']==begin['registryDigest']
            and check['companionDigest']==intent['compatibility']['gateway']['companion']['companionDigest'],
            'MAINTENANCE_ORDINARY_HANDOVER_CHANGED')
    current=stop['next']
    sc.need(matching_holds(begin['holdSnapshot']['holds'],current['attempt']),
            'MAINTENANCE_ORDINARY_HANDOVER_CHANGED')
    staged=validate_transition(current,{**current,'phase':'STAGED_TARGET_FROZEN',
        'generation':auth['targetGeneration'],'sequence':current['sequence']+1,
        'previousDigest':sc.digest(current),'proofDigest':sc.digest({'stop':stop,'begin':begin,'check':check})})
    return checked, staged, {'record':staged,'handoff':{'role':'staged_target','attemptId':pair['attemptId'],
        'restrictionDigest':current['attempt']['restrictionDigest'],'interlockDigest':sc.digest(staged),
        'registryDigest':begin['registryDigest']}}

def ordinary_handover(intent, begin, check, source_receipt, stop, publication):
    checked,_,final=_ordinary_chain(intent,begin,check,source_receipt,stop)
    auth=intent['authorization']
    sc.fields(publication,('schema','state','sourceRecordHash','record','digest',
                           'registryDigest','previous','previousRegistryDigest'))
    current=stop['next']
    sc.need(publication['schema']=='fortis-successor-maintenance-publication-v2'
            and publication['state']=='Committed'
            and publication['sourceRecordHash'].lower()==auth['sourceRecordDigest']
            and publication['record']==current and publication['digest']==sc.digest(current)
            and publication['previous']==checked
            and publication['previousRegistryDigest']==publication['registryDigest']==begin['registryDigest'],
            'MAINTENANCE_ORDINARY_HANDOVER_CHANGED')
    return final


def ordinary_return_record(intent,begin,check,source_receipt,stop,publication,actual):
    """Project a source-generation hold, never a successful closure.

    Caller proves both pairs are excluded, target activation absent, and
    original Gateway receipt exact. Actual Registry replay is independent.
    """
    checked,staged,_=_ordinary_chain(intent,begin,check,source_receipt,stop)
    sc.fields(actual,('receipts','checkpoint','holdSnapshot'))
    sc.need(all(actual[k]==begin[k] for k in actual),
            'MAINTENANCE_ORDINARY_RETURN_CHANGED')
    sc.fields(publication,('schema','state','sourceRecordHash','record','digest',
                          'registryDigest','previous','previousRegistryDigest'))
    rec=validate_record(publication['record'])
    sc.need(publication['schema']=='fortis-successor-maintenance-publication-v2'
            and publication['state']=='Committed'
            and publication['sourceRecordHash'].lower()==intent['authorization']['sourceRecordDigest']
            and publication['digest']==sc.digest(rec)
            and publication['previousRegistryDigest']==publication['registryDigest']==begin['registryDigest'],
            'MAINTENANCE_ORDINARY_RETURN_CHANGED')
    prior=publication['previous'] if rec['phase']=='RECOVERY_HOLD' else rec
    chain=(checked_transitions(check,begin['draining'])['frozen'],checked,stop['next'],staged)
    sc.need(prior in chain[1:] and (rec['phase']=='RECOVERY_HOLD'
            or publication['previous']==chain[chain.index(prior)-1]),
            'MAINTENANCE_ORDINARY_RETURN_CHANGED')
    recovery=validate_transition(prior,{**prior,'phase':'RECOVERY_HOLD',
        'generation':intent['normal']['generation'],'sequence':prior['sequence']+1,
        'previousDigest':sc.digest(prior),'proofDigest':sc.digest({'kind':'ORDINARY_RETURN',
            'stop':stop,'begin':actual,'sourceReceiptDigest':check['stateReceiptDigest']})})
    sc.need(rec['phase']!='RECOVERY_HOLD' or rec==recovery,'MAINTENANCE_ORDINARY_RETURN_CHANGED')
    return recovery

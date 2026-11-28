"""Closed controller completion and independently observed target binding.

These are projections from trusted protected controller and independent
target-specific readers, not new evidence minting or an admission API.
The actual readers for existing Windows records and live target must be
reviewed separately. Failure/Return is not success and cannot use this
successful completion contract.
"""
from . import semantic_contract as sc
from .maintenance_contract import validate_record


def completion_params(record, controller, observation, *, expected_controller_digest,
                      expected_observation_digest, expected_target_revision,
                      expected_desired_record, now, max_age):
    record=validate_record(record)
    sc.need(record['phase']=='COMPLETION_PENDING'
            and record['proofDigest']==expected_controller_digest,
            'MAINTENANCE_COMPLETION_PROOF_CHANGED')
    return _completion_params(record['attempt'],record['generation'],controller,observation,
        expected_controller_digest=expected_controller_digest,
        expected_observation_digest=expected_observation_digest,
        expected_target_revision=expected_target_revision,expected_desired_record=expected_desired_record,
        now=now,max_age=max_age)


def _completion_params(attempt, generation, controller, observation, *,
                       expected_controller_digest, expected_observation_digest,
                       expected_target_revision, expected_desired_record, now, max_age):
    sc.fields(controller,('schemaVersion','attemptId','subject','source','generation',
                          'applyRecordDigest','backupRecordDigest','primaryRecordDigest',
                          'finalSealDigest','completionTime'))
    sc.fields(observation,('schemaVersion','attemptId','subject','source','generation',
                           'primaryRecordDigest','observedAt','stateReceiptDigest','healthy'))
    # Desired may not yet have an artifact when the hold is opened. Keep
    # the sealed attempt intact and require both proofs to name one exact image.
    source=controller['source']
    sc.source(source)
    expected_artifact=attempt['source']['artifactSha256']
    sc.need(all(source[k]==attempt['source'][k] for k in
                ('sourceSha','catalogCommitSha','catalogSha256'))
            and source['artifactSha256'] is not None
            and expected_artifact in (None,source['artifactSha256']),
            'MAINTENANCE_COMPLETION_IDENTITY')
    for data in (controller,observation):
        sc.need(type(data['schemaVersion']) is int and data['schemaVersion']==1)
        sc.need(data['attemptId']==attempt['attemptId'] and data['subject']==attempt['subject']
                and data['source']==source and data['generation']==generation,
                'MAINTENANCE_COMPLETION_IDENTITY')
    for k in ('applyRecordDigest','backupRecordDigest','primaryRecordDigest','finalSealDigest'):
        sc.hex_id(controller[k],64)
    sc.hex_id(observation['stateReceiptDigest'],64)
    for pin in (expected_controller_digest,expected_observation_digest):
        sc.hex_id(pin,64)
    sc.need(sc.digest(controller)==expected_controller_digest and
            sc.digest(observation)==expected_observation_digest and
            expected_controller_digest!=expected_observation_digest,
            'MAINTENANCE_COMPLETION_PROOF_CHANGED')
    sc.revision(now)
    sc.revision(controller['completionTime'])
    sc.revision(observation['observedAt'])
    sc.need(type(max_age) is int and 1<=max_age<=300)
    sc.need(controller['completionTime']<=observation['observedAt']<=now and
            now-observation['observedAt']<=max_age and observation['healthy'] is True
            and observation['primaryRecordDigest']==controller['primaryRecordDigest']
            and observation['stateReceiptDigest']==controller['finalSealDigest']
            and generation==attempt['targetGeneration'],
            'MAINTENANCE_COMPLETION_OBSERVATION_UNVERIFIED')
    sc.revision(expected_target_revision)
    sc.hex_id(expected_desired_record,64)
    return {'subject':attempt['subject'],'source':dict(source),
            'expected':{'targetRevision':expected_target_revision,
                        'desiredRecordId':expected_desired_record,
                        'catalogSha256':attempt['source']['catalogSha256']},
            'attemptId':attempt['attemptId'],'controllerReceiptDigest':expected_controller_digest,
            'readbackDigest':expected_observation_digest,'observedAt':observation['observedAt']}

def paired_completion_params(record, pair, holds, evidence, *, now, max_age=300):
    """Project one protected two-target intent; not a host evidence issuer.

    The host must independently observe both real receivers and their
    controller records before stopping them. The journal writer verifies
    exact frozen hold/checkpoint and uses only this committed proof.
    """
    from .maintenance_contract import paired_begin, paired_operation_id, matching_holds, hold_snapshot
    record=validate_record(record)
    pair=paired_begin(pair,pair['items']['gateway']['subject']['repository'])
    holds=hold_snapshot(holds)
    sc.fields(evidence,('schemaVersion','pairDigest','controllers','observations','coverage'))
    sc.need(type(evidence['schemaVersion']) is int and evidence['schemaVersion']==1
            and evidence['pairDigest']==sc.digest(pair)
            and record['phase']=='COMPLETION_PENDING'
            and record['proofDigest']==sc.digest(evidence)
            and record['attempt']['attemptId']==pair['attemptId']
            and record['attempt']['subject']==pair['items']['gateway']['subject']
            and record['attempt']['source']==pair['items']['gateway']['source']
            and record['registryInstanceId']==holds['instanceId']
            and record['scopeDigest']==holds['scopeDigest']
            and holds['snapshotRevision']==pair['checkpoint']['snapshotRevision']+2
            and matching_holds(holds['holds'],record['attempt'])
            and all(h.get('pairDigest')==sc.digest(pair) for h in holds['holds']),
            'MAINTENANCE_PAIRED_COMPLETION_CHANGED')
    for field in ('controllers','observations','coverage'):sc.fields(evidence[field],('registry','gateway'))
    result={}
    for role in ('registry','gateway'):
        item=pair['items'][role]
        controller=evidence['controllers'][role];observation=evidence['observations'][role]
        attempt={'attemptId':paired_operation_id(pair['attemptId'],role),'subject':item['subject'],
                 'source':item['source'],'targetGeneration':record['attempt']['targetGeneration']}
        params=_completion_params(attempt,record['generation'],controller,observation,
            expected_controller_digest=sc.digest(controller),expected_observation_digest=sc.digest(observation),
            expected_target_revision=item['expected']['targetRevision']+1,
            expected_desired_record=item['expected']['desiredRecordId'],now=now,max_age=max_age)
        sc.need(params['source']['artifactSha256']==pair['artifacts'][role],
                'MAINTENANCE_PAIRED_COMPLETION_ARTIFACT_CHANGED')
        ids=evidence['coverage'][role]
        sc.need(type(ids) is list and 0<len(ids)<=64 and ids==sorted(set(ids)))
        for ident in ids:sc.hex_id(ident,64)
        result[role]={**params,'coveredRecordIds':ids}
    return result


def paired_recovery_record(record, pair, holds, evidence, readback, *, now):
    """Only expired, independently proven absent completion can renew proof.

    Keep the SAME held, already activated target generation. No journal
    write, hold removal or source rollback is authorized by this projection.
    """
    from .maintenance_contract import validate_transition, hold_snapshot
    # Validate original intent at its original observation time, never
    # reinterpret expired proof as authorization for a new journal write.
    observed=max(row['observedAt'] for row in evidence['observations'].values())
    paired_completion_params(record,pair,holds,evidence,now=observed)
    sc.revision(now)
    sc.need(any(now-row['observedAt']>300 for row in evidence['observations'].values()),
            'MAINTENANCE_PAIRED_COMPLETION_NOT_EXPIRED')
    sc.fields(readback,('result','pairDigest','pendingDigest','holdSnapshot','checkpoint'))
    actual=hold_snapshot(readback['holdSnapshot']);checkpoint=readback['checkpoint']
    sc.fields(checkpoint,pair['checkpoint'])
    sc.need(readback['result']=='PROTECTED_PAIR_COMPLETION_NOT_APPLIED'
            and readback['pairDigest']==sc.digest(pair)
            and readback['pendingDigest']==sc.digest(record)
            and actual==holds and checkpoint['snapshotRevision']==actual['snapshotRevision']
            and checkpoint['eventDigest']==actual['eventDigest']
            and all(checkpoint[k]==pair['checkpoint'][k] for k in ('sourceCursor','sourceRevision','profileDigest')),
            'MAINTENANCE_PAIRED_COMPLETION_READBACK_CHANGED')
    return validate_transition(record,{**record,'phase':'RECOVERY_HOLD',
        'sequence':record['sequence']+1,'previousDigest':sc.digest(record),'proofDigest':sc.digest(readback)})


def paired_normal_record(record, pair, evidence, readback):
    """Next NORMAL requires exact independently replayed close receipts."""
    from .maintenance_contract import paired_begin, paired_operation_id, validate_transition, hold_snapshot
    record=validate_record(record)
    pair=paired_begin(pair,pair['items']['gateway']['subject']['repository'])
    sc.fields(readback,('result','attemptId','pairDigest','checkpoint','holdSnapshot',
                        'closeReceipts','observationReceipts'))
    holds=hold_snapshot(readback['holdSnapshot']);checkpoint=readback['checkpoint']
    sc.fields(checkpoint,pair['checkpoint'])
    sc.need(record['phase']=='COMPLETION_PENDING' and record['proofDigest']==sc.digest(evidence)
            and record['generation']==record['attempt']['targetGeneration']
            and record['attempt']['attemptId']==pair['attemptId']
            and readback['result']=='PROTECTED_PAIR_COMPLETION_READBACK_ONLY'
            and readback['attemptId']==pair['attemptId'] and readback['pairDigest']==sc.digest(pair)
            and holds['instanceId']==record['registryInstanceId'] and holds['scopeDigest']==record['scopeDigest']
            and not holds['holds'] and holds['snapshotRevision']==checkpoint['snapshotRevision']==pair['checkpoint']['snapshotRevision']+6
            and holds['eventDigest']==checkpoint['eventDigest']
            and all(checkpoint[k]==pair['checkpoint'][k] for k in ('sourceCursor','sourceRevision','profileDigest')),
            'MAINTENANCE_PAIRED_COMPLETION_READBACK_CHANGED')
    sc.hex_id(checkpoint['eventDigest'],64)
    sc.fields(readback['observationReceipts'],('registry','gateway'))
    sc.need(type(readback['closeReceipts']) is list and len(readback['closeReceipts'])==2)
    for role,receipt in zip(('registry','gateway'),readback['closeReceipts']):
        item=pair['items'][role]
        observation=readback['observationReceipts'][role]
        for row,kind,ident,offset in (
            (receipt,'PROTECTED_PAIRED_CLOSE',paired_operation_id(pair['attemptId'],role,closing=True),3),
            (observation,'TECHNICAL_OBSERVATION_ACCEPTED',paired_observation_id(pair['attemptId'],role),2)):
            sc.need(row['eventKind']==kind and row['operationId']==ident and row['subject']==item['subject']
                    and row['instanceId']==holds['instanceId']
                    and row['targetRevision']==item['expected']['targetRevision']+offset,
                    'MAINTENANCE_PAIRED_COMPLETION_READBACK_CHANGED')
    return validate_transition(record,{**record,'phase':'NORMAL','sequence':record['sequence']+1,
        'previousDigest':sc.digest(record),'proofDigest':sc.digest(readback)})


def paired_observation_id(attempt_id,role):
    import uuid
    sc.uuid_id(attempt_id);sc.need(role in ('registry','gateway'))
    return str(uuid.uuid5(uuid.UUID(attempt_id),role+'-paired-observation-v1'))


def project_paired_completion(record, pair, holds, *, apply_digest, backup_digest,
                              primary_digest, backup_gateway, actual_gateway,
                              backup_registry, actual_registry, live, now):
    """Controller projection of actual protected record and frozen readbacks.

    The caller owns the host lock, validates the real Docker identity and
    health, and independently reads both state reserves. No host effect or
    authority is granted here.
    """
    from .maintenance_contract import paired_operation_id, validate_transition
    record=validate_record(record)
    sc.fields(live,('gatewayId','registryId','gatewayImage','registryImage',
                    'gatewayHealth','registryStatus','delivery','observedAt'))
    for pin in (apply_digest,backup_digest,primary_digest,live['gatewayId'],live['registryId']):
        sc.hex_id(pin,64)
    sc.need(len({apply_digest,backup_digest,primary_digest})==3
            and live['gatewayId']!=live['registryId']
            and record['phase'] in ('PROMOTE_FROZEN','RECOVERY_HOLD')
            and record['generation']==record['attempt']['targetGeneration']
            and live['gatewayImage']=='sha256:'+pair['artifacts']['gateway']
            and live['registryImage']=='sha256:'+pair['artifacts']['registry']
            and live['gatewayHealth']=='healthy' and live['registryStatus']=='running'
            and actual_gateway==backup_gateway and actual_registry==backup_registry,
            'MAINTENANCE_PAIRED_COMPLETION_OBSERVATION_CHANGED')
    delivery=live['delivery']
    checkpoint=delivery['registryCheckpoint']
    sc.need(delivery['latestPin'] is True and delivery['maintenancePhase']==record['phase']
            and delivery['generation']==record['generation']
            and delivery['sourceDelivery']['interlockDigest']==sc.digest(record)
            and checkpoint['registryDigest']==sc.digest(holds)
            and {k:checkpoint[k] for k in pair['checkpoint']}==backup_registry['checkpoint']
            and backup_registry['holdSnapshot']==holds
            and backup_registry['result']=='PAIRED_FROZEN_LOCAL_STATE_RESERVE_ONLY',
            'MAINTENANCE_PAIRED_COMPLETION_OBSERVATION_CHANGED')
    evidence={'schemaVersion':1,'pairDigest':sc.digest(pair),'controllers':{},'observations':{},
              'coverage':backup_registry['coverage']}
    for role,expected,actual in (('gateway',backup_gateway,actual_gateway),
                                 ('registry',backup_registry,actual_registry)):
        item=pair['items'][role]
        common={'schemaVersion':1,'attemptId':paired_operation_id(pair['attemptId'],role),
                'subject':item['subject'],'source':{**item['source'],'artifactSha256':pair['artifacts'][role]},
                'generation':record['generation'],'primaryRecordDigest':primary_digest}
        evidence['controllers'][role]={**common,'applyRecordDigest':apply_digest,'backupRecordDigest':backup_digest,
            'finalSealDigest':sc.digest(expected),'completionTime':live['observedAt']}
        evidence['observations'][role]={**common,'observedAt':live['observedAt'],
            'stateReceiptDigest':sc.digest(actual),'healthy':True}
    pending=validate_transition(record,{**record,'phase':'COMPLETION_PENDING',
        'sequence':record['sequence']+1,'previousDigest':sc.digest(record),'proofDigest':sc.digest(evidence)})
    paired_completion_params(pending,pair,holds,evidence,now=now)
    return {'evidence':evidence,'pending':pending,'recordedAt':now}

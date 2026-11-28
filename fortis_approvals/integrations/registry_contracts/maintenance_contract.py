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


def paired_subjects(repository):
    from .transition_contract import REPOSITORY
    sc.need(repository==REPOSITORY,'MAINTENANCE_PAIRED_SCOPE')
    return {role:{'repository':repository,'targetId':target,'environment':env}
            for role,target,env in (('gateway','fortis-gateway','production'),
                                    ('registry','fortis-registry-pilot','non-production'))}


def paired_operation_id(attempt_id, role, *, closing=False):
    import uuid
    sc.uuid_id(attempt_id)
    sc.need(role in ('gateway','registry') and type(closing) is bool,'MAINTENANCE_PAIRED_SCOPE')
    if closing:
        return str(uuid.uuid5(uuid.UUID(attempt_id),role+'-paired-close-v1'))
    return attempt_id if role=='gateway' else str(uuid.uuid5(uuid.UUID(attempt_id),'registry-paired-begin-v1'))


def paired_begin(value, repository):
    """Exact two-target controller intent, not a public group or proof issuer."""
    sc.fields(value,('schemaVersion','attemptId','checkpoint','items','artifacts',
                     'controllerReceiptDigest','compatibilityReadbackDigest'))
    sc.need(type(value['schemaVersion']) is int and value['schemaVersion']==1)
    sc.uuid_id(value['attemptId'])
    checkpoint=value['checkpoint']
    sc.fields(checkpoint,('sourceRevision','sourceCursor','snapshotRevision','eventDigest','profileDigest'))
    sc.revision(checkpoint['sourceRevision']);sc.revision(checkpoint['snapshotRevision'])
    sc.hex_id(checkpoint['sourceCursor'],40)
    for k in ('eventDigest','profileDigest'):sc.hex_id(checkpoint[k],64)
    sc.need(checkpoint['sourceRevision']>0 and checkpoint['snapshotRevision']>=checkpoint['sourceRevision'])
    roles=paired_subjects(repository)
    sc.fields(value['items'],roles);sc.fields(value['artifacts'],roles)
    for role,subject in roles.items():
        item=value['items'][role]
        sc.begin_item(item)
        sc.hex_id(value['artifacts'][role],64)
        sc.need(item['subject']==subject and item['source']['artifactSha256'] in
                (None,value['artifacts'][role]),'MAINTENANCE_PAIRED_SCOPE')
    a,b=(value['items'][role]['source'] for role in ('gateway','registry'))
    sc.need(all(a[k]==b[k] for k in ('sourceSha','catalogCommitSha','catalogSha256')),
            'MAINTENANCE_PAIRED_SOURCE_CHANGED')
    for k in ('controllerReceiptDigest','compatibilityReadbackDigest'):sc.hex_id(value[k],64)
    sc.need(value['controllerReceiptDigest']!=value['compatibilityReadbackDigest'])
    return sc.loads_strict(sc.canonical(value))


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
        if b['phase']=='RECOVERY_HOLD' and b['generation']==b['attempt']['targetGeneration']:
            sc.need(a['phase']=='COMPLETION_PENDING' and a['generation']==b['generation'],
                    'MAINTENANCE_GENERATION_CHANGED')
        if b['phase']=='COMPLETION_PENDING' and (a['phase']=='PROMOTE_FROZEN' or
                (a['phase']=='RECOVERY_HOLD' and a['generation']==a['attempt']['targetGeneration'])):
            sc.need(b['generation']==a['generation'],'MAINTENANCE_GENERATION_CHANGED')
    return b


def latest_projection(record, *, committed, registry_digest):
    """Projection of an independently durable controller publication.

    This is not a second authority or a signature. The controller must keep
    its protected host anchor outside rollback volumes, and publish this
    projection on a distinct fixed mount. Pending never admits a runtime.
    """
    rec=validate_record(record)
    sc.need(type(committed) is bool)
    if rec['phase']=='NORMAL':
        sc.need(registry_digest is None,'MAINTENANCE_LATEST_PIN_INVALID')
    else:
        sc.hex_id(registry_digest,64)
    return {'schemaVersion':1,'state':'Committed' if committed else 'Pending',
            'instanceId':rec['registryInstanceId'],'scopeDigest':rec['scopeDigest'],
            'sequence':rec['sequence'],'generation':rec['generation'],
            'phase':rec['phase'],'interlockDigest':sc.digest(rec),'registryDigest':registry_digest}


def bind_latest_projection(value, record):
    sc.fields(value,('schemaVersion','state','instanceId','scopeDigest','sequence','generation',
                     'phase','interlockDigest','registryDigest'))
    sc.revision(value['sequence'])
    sc.need(type(value['schemaVersion']) is int and value['schemaVersion']==1
            and value['state']=='Committed'
            and value==latest_projection(record,committed=True,registry_digest=value['registryDigest']),
            'MAINTENANCE_LATEST_PIN_CHANGED')
    return value


def matching_holds(holds, attempt):
    """Exactly the ordinary single hold or the closed authenticated pair.

    Pair digest is part of the gateway hold restriction pin. Neither
    arbitrary additional holds nor a lone surviving pair member qualify.
    """
    if attempt is None:return False
    matches=[h for h in holds if h['stateFreeze'] and all(h[k]==attempt[k] for k in
                ('attemptId','subject','source','restrictionDigest'))]
    if len(matches)!=1:return False
    selected=matches[0]
    if 'pairId' not in selected:return len(holds)==1
    if len(holds)!=2 or selected['pairId']!=attempt['attemptId']:return False
    peer=next(h for h in holds if h is not selected)
    subjects=paired_subjects(attempt['subject']['repository'])
    return (selected['subject']==subjects['gateway'] and peer['subject']==subjects['registry']
            and peer.get('pairId')==selected['pairId'] and peer.get('pairDigest')==selected['pairDigest']
            and peer['attemptId']==paired_operation_id(selected['pairId'],'registry')
            and peer['stateFreeze'] and all(peer['source'][k]==selected['source'][k] for k in
                    ('sourceSha','catalogCommitSha','catalogSha256')))


def latest_startup(record, projection, holds):
    """Shared receiver proof against the independent current phase pin.

    This permits passive restart at the exact receiver phase only; it is not
    activation, compatibility verification or permission to write.
    """
    record=validate_record(record)
    bind_latest_projection(projection,record)
    phase=record['phase']
    if phase=='NORMAL':
        sc.need(not any(h['stateFreeze'] for h in holds['holds']),
                'MAINTENANCE_STARTUP_HANDOFF_REQUIRED')
    else:
        sc.need(phase in ('STAGED_TARGET_FROZEN','BACKUP_FROZEN','PROMOTE_FROZEN',
                         'COMPLETION_PENDING','RECOVERY_HOLD')
                and (phase!='RECOVERY_HOLD' or record['generation']==record['attempt']['sourceGeneration']
                     or (record['generation']==record['attempt']['targetGeneration']
                         and len(holds['holds'])==2 and all(h.get('pairDigest') for h in holds['holds']))),
                'MAINTENANCE_STARTUP_HANDOFF_REQUIRED')
        sc.need(sc.digest(holds)==projection['registryDigest'] and matching_holds(holds['holds'],record['attempt']),
                'MAINTENANCE_STARTUP_HOLD_CHANGED')
    return record


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


def bootstrap_compatibility_digest(checked):
    sc.fields(checked,('gateway','registry','artifacts'))
    gateway,registry=checked['gateway'],checked['registry']
    sc.fields(gateway,('result','profileDigest','sourceDigest','releaseNonce','incumbentProfileDigest','companion','binding'))
    sc.fields(registry,('result','profileDigest','binding','checkpoint','items','sourceMigrationReceipt','review'))
    sc.fields(checked['artifacts'],('gateway','registry'))
    for v in checked['artifacts'].values():sc.hex_id(v,64)
    sc.need(gateway['result']=='BOOTSTRAP_GATEWAY_MATERIAL_ONLY'
            and registry['result']=='BOOTSTRAP_REGISTRY_MATERIAL_ONLY'
            and gateway['binding']==registry['binding']
            and gateway['companion']['authorityWitnessDigest']==registry['review']['authorityWitnessDigest'],
            'SOURCE_BOOTSTRAP_PAIR_COMPATIBILITY_CHANGED')
    return sc.digest(checked)


def maintenance_coordinate(service, operation):
    for v in (service,operation):
        sc.need(type(v) is str and 0<len(v)<=64 and
                all(c.isascii() and (c.islower() or c.isdigit() or c in '_-') for c in v))
    return service,operation


def hold_snapshot(value):
    """Trusted Registry-derived aggregate, not a public filtered READ DTO."""
    sc.fields(value,('instanceId','scopeDigest','snapshotRevision','eventDigest','holds'))
    sc.uuid_id(value['instanceId'])
    sc.hex_id(value['scopeDigest'],64)
    sc.revision(value['snapshotRevision'])
    sc.hex_id(value['eventDigest'],64)
    sc.need(type(value['holds']) is list and len(value['holds'])<=200)
    seen=set()
    for hold in value['holds']:
        fields=('attemptId','subject','source','restrictionDigest','stateFreeze','blockedOperations')
        paired='pairId' in hold or 'pairDigest' in hold
        sc.fields(hold,fields+('pairId','pairDigest') if paired else fields)
        if paired:
            sc.uuid_id(hold['pairId']);sc.hex_id(hold['pairDigest'],64)
            subjects=paired_subjects(hold['subject']['repository'])
            role=next((r for r,s in subjects.items() if hold['subject']==s),None)
            sc.need(role is not None and hold['stateFreeze'] is True and
                    hold['attemptId']==paired_operation_id(hold['pairId'],role),
                    'MAINTENANCE_PAIRED_HOLD_INVALID')
        sc.uuid_id(hold['attemptId'])
        sc.subject(hold['subject'])
        sc.source(hold['source'])
        sc.hex_id(hold['restrictionDigest'],64)
        sc.need(hold['attemptId'] not in seen and type(hold['stateFreeze']) is bool)
        seen.add(hold['attemptId'])
        sc.need(type(hold['blockedOperations']) is list and len(hold['blockedOperations'])<=100)
        coords=set()
        for op in hold['blockedOperations']:
            sc.fields(op,('service','operation'))
            coord=maintenance_coordinate(op['service'],op['operation'])
            sc.need(coord not in coords)
            coords.add(coord)
    return sc.loads_strict(sc.canonical(value))


def bootstrap_pair_authorization(checked, owner_go, source_receipt, *,
                                 review_sha256, evidence_sha256, seed_digest):
    """Bind the existing host's durable GO and actual frozen source receipt.

    The host authenticates the protected record and independently verifies
    the physical freeze. This function only canonicalizes the exact binding.
    It cannot create a GO or certify that Docker is stopped.
    """
    sc.fields(owner_go,('schemaVersion','attemptId','checkDigest','compatibilityDigest',
        'sourceRecordDigest','reviewDigest','evidenceDigest','reviewProofDigest',
        'targetGeneration','recordedAt'))
    sc.need(type(owner_go['schemaVersion']) is int and owner_go['schemaVersion']==1)
    sc.uuid_id(owner_go['attemptId']);sc.revision(owner_go['recordedAt'])
    for k in ('checkDigest','compatibilityDigest','sourceRecordDigest','reviewDigest',
              'evidenceDigest','reviewProofDigest','targetGeneration'):
        sc.hex_id(owner_go[k],64)
    sc.hex_id(seed_digest,64)
    binding=checked['registry']['binding']
    sc.need(owner_go['compatibilityDigest']==bootstrap_compatibility_digest(checked)
            and owner_go['reviewDigest']==review_sha256
            and owner_go['evidenceDigest']==evidence_sha256
            and owner_go['reviewProofDigest']==checked['registry']['review']['ownerReviewProofDigest']
            and owner_go['targetGeneration']!=binding['generation']
            and seed_digest==binding['interlockDigest'],
            'SOURCE_BOOTSTRAP_OWNER_GO_CHANGED')
    sc.fields(source_receipt,('sha256','summary'))
    # Same full source receipt used by existing Check and physical freeze.
    return {'schemaVersion':1,'attemptId':owner_go['attemptId'],'checkDigest':owner_go['checkDigest'],
            'compatibilityDigest':owner_go['compatibilityDigest'],
            'sourceRecordDigest':owner_go['sourceRecordDigest'],
            'frozenSourceReceiptDigest':sc.digest(source_receipt),'seedDigest':seed_digest,
            'recordedAt':owner_go['recordedAt'],'ownerGoDigest':sc.digest(owner_go),
            'targetGeneration':owner_go['targetGeneration']}


def ordinary_pair_intent(value):
    """Exact owner-controller intent for a later paired maintenance window.

    The two package inspections and owner authorization are independently
    checked on the host. This contract does not authenticate supplied hashes.
    Only the protected owner mount may supply this intent to the live writer.
    """
    sc.fields(value,('schemaVersion','normal','authorization','compatibility'))
    sc.need(type(value['schemaVersion']) is int and value['schemaVersion']==1)
    normal=validate_record(value['normal']);auth=value['authorization'];checked=value['compatibility']
    sc.fields(auth,('attemptId','sourceRecordDigest','targetGeneration','targetNonce',
                    'recordedAt','normalDigest','compatibilityDigest'))
    sc.uuid_id(auth['attemptId']);sc.uuid_id(auth['targetNonce']);sc.revision(auth['recordedAt'])
    for k in ('sourceRecordDigest','targetGeneration','normalDigest','compatibilityDigest'):
        sc.hex_id(auth[k],64)
    sc.fields(checked,('gateway','registry','artifacts','roots'))
    sc.fields(checked['roots'],('gateway','registry','state','backup'))
    identities=[]
    for root in checked['roots'].values():
        sc.fields(root,('device','inode'))
        sc.need(all(type(root[k]) is int and 0<=root[k]<2**64 for k in ('device','inode')))
        identities.append((root['device'],root['inode']))
    sc.need(len(set(identities))==4,'MAINTENANCE_ORDINARY_TARGET_ALIAS')
    g,r=checked['gateway'],checked['registry']
    sc.fields(g,('result','profileDigest','sourceDigest','releaseNonce','incumbentProfileDigest','companion','binding'))
    sc.fields(r,('result','profileDigest','incumbentProfileDigest','binding','checkpoint','items','holdSnapshot'))
    for data in (g,r):
        for k in ('profileDigest','incumbentProfileDigest'):sc.hex_id(data[k],64)
    sc.hex_id(g['sourceDigest'],64)
    binding=r['binding']
    sc.fields(binding,('instanceId','scopeDigest','profileDigest','generation','internalActor',
                       'peerKeyDigest','frameKeyDigest','socketPath','readerUid','readerGid',
                       'authorityDigest','interlockDigest'))
    for k in ('scopeDigest','profileDigest','generation','peerKeyDigest','frameKeyDigest','authorityDigest','interlockDigest'):
        sc.hex_id(binding[k],64)
    sc.fields(g['companion'],('schemaDigest','companionDigest','authorityWitnessDigest'))
    for pin in g['companion'].values():sc.hex_id(pin,64)
    holds=hold_snapshot(r['holdSnapshot'])
    sc.need(normal['phase']=='NORMAL' and auth['normalDigest']==sc.digest(normal)
            and auth['targetGeneration']!=normal['generation']
            and (normal['attempt'] is None or normal['attempt']['attemptId']!=auth['attemptId'])
            and auth['compatibilityDigest']==sc.digest(checked)
            and g['result']=='ORDINARY_GATEWAY_MATERIAL_ONLY'
            and r['result']=='ORDINARY_REGISTRY_MATERIAL_ONLY'
            and g['binding']==binding and g['releaseNonce']==auth['targetNonce']
            and binding['instanceId']==normal['registryInstanceId']==holds['instanceId']
            and binding['scopeDigest']==normal['scopeDigest']==holds['scopeDigest']
            and binding['generation']==normal['generation']
            and binding['profileDigest']==r['checkpoint']['profileDigest']
            and binding['peerKeyDigest']!=binding['frameKeyDigest']
            and not holds['holds'] and holds['snapshotRevision']==r['checkpoint']['snapshotRevision']
            and holds['eventDigest']==r['checkpoint']['eventDigest'],
            'MAINTENANCE_ORDINARY_BEGIN_PROOF_CHANGED')
    return paired_begin({'schemaVersion':1,'attemptId':auth['attemptId'],
        'checkpoint':r['checkpoint'],'items':r['items'],'artifacts':checked['artifacts'],
        'controllerReceiptDigest':sc.digest(auth),
        'compatibilityReadbackDigest':auth['compatibilityDigest']},
        r['items']['gateway']['subject']['repository'])


def controller_begin_projection(value):
    """Fixed owner anchor: revocation forbids new effects, never readback."""
    sc.fields(value,('intent','revoked'))
    sc.need(type(value['revoked']) is bool,'MAINTENANCE_CONTROLLER_BEGIN_CHANGED')
    ordinary_pair_intent(value['intent'])
    return value


def begin_replacement(previous,absence,next_intent):
    """Only a revoked, independently read back no-effect intent can be replaced."""
    previous=controller_begin_projection(previous)
    old=previous['intent'];new=ordinary_pair_intent(next_intent)
    sc.fields(absence,('result','intentDigest','exactPredecessor','receipts','checkpoint',
                      'holdSnapshot','revoked','expired'))
    sc.need(previous['revoked'] and absence['revoked'] is True
            and absence['result']=='PROTECTED_PAIR_BEGIN_NOT_APPLIED'
            and absence['intentDigest']==sc.digest(old)
            and absence['receipts'] is None
            and type(absence['expired']) is bool and type(absence['exactPredecessor']) is bool
            and next_intent['normal']==old['normal']
            and new['attemptId']!=old['authorization']['attemptId']
            and next_intent['authorization']['recordedAt']>old['authorization']['recordedAt']
            and absence['checkpoint']==new['checkpoint']
            and absence['holdSnapshot']==next_intent['compatibility']['registry']['holdSnapshot'],
            'MAINTENANCE_CONTROLLER_BEGIN_REPLACEMENT_CHANGED')
    return new


def paired_draining_record(normal, pair, receipts, holds, *, target_generation, recorded_at):
    """The ordinary DRAINING edge comes from actual atomic begin receipts."""
    normal=validate_record(normal);holds=hold_snapshot(holds)
    pair=paired_begin(pair,pair['items']['gateway']['subject']['repository'])
    sc.hex_id(target_generation,64);sc.revision(recorded_at)
    sc.need(normal['phase']=='NORMAL' and normal['generation']!=target_generation
            and normal['registryInstanceId']==holds['instanceId']
            and normal['scopeDigest']==holds['scopeDigest']
            and holds['snapshotRevision']==pair['checkpoint']['snapshotRevision']+2
            and type(receipts) is list and len(receipts)==2,
            'MAINTENANCE_PAIRED_BEGIN_READBACK_CHANGED')
    for role,receipt in zip(('registry','gateway'),receipts):
        sc.need(receipt['operationId']==paired_operation_id(pair['attemptId'],role)
                and receipt['eventKind']=='PROTECTED_PAIRED_BEGIN'
                and receipt['instanceId']==holds['instanceId']
                and receipt['subject']==pair['items'][role]['subject']
                and receipt['recordedAt']==recorded_at
                and receipt['technicalInstallationVerified'] is False,
                'MAINTENANCE_PAIRED_BEGIN_READBACK_CHANGED')
    selected=next((h for h in holds['holds'] if h['attemptId']==pair['attemptId']),None)
    sc.need(selected is not None and selected.get('pairDigest')==sc.digest(pair)
            and selected['source']==pair['items']['gateway']['source'],
            'MAINTENANCE_PAIRED_BEGIN_READBACK_CHANGED')
    attempt={k:selected[k] for k in ('attemptId','subject','source','restrictionDigest')}
    attempt.update(sourceGeneration=normal['generation'],targetGeneration=target_generation)
    sc.need(matching_holds(holds['holds'],attempt),'MAINTENANCE_PAIRED_BEGIN_READBACK_CHANGED')
    proof=sc.digest({'kind':'PROTECTED_PAIRED_BEGIN','pair':pair,'receipts':receipts,'holdSnapshot':holds})
    return validate_transition(normal,{**normal,'phase':'DRAINING','sequence':normal['sequence']+1,
        'previousDigest':sc.digest(normal),'attempt':attempt,'proofDigest':proof})


def bootstrap_phase_plan(seed, authorization, pair, receipts, holds):
    """Plan the bounded offline phase chain; never assert live drain.

    #289 cannot participate in operational DRAINING. All four source
    phases refer to the SAME physical freeze / original two-event proof.
    No publication or receiver startup is authorized by this projection.
    """
    seed=validate_record(seed)
    holds=hold_snapshot(holds)
    pair=paired_begin(pair,pair['items']['gateway']['subject']['repository'])
    sc.need(seed['sequence']==0 and seed['phase']=='NORMAL'
            and sc.digest(seed)==authorization['seedDigest']
            and seed['registryInstanceId']==holds['instanceId']
            and seed['scopeDigest']==holds['scopeDigest']
            and pair['attemptId']==authorization['attemptId']
            and pair['controllerReceiptDigest']==sc.digest(authorization)
            and pair['compatibilityReadbackDigest']==authorization['compatibilityDigest']
            and holds['snapshotRevision']==pair['checkpoint']['snapshotRevision']+2,
            'SOURCE_BOOTSTRAP_PHASE_PROOF_CHANGED')
    sc.need(type(receipts) is list and len(receipts)==2,
            'SOURCE_BOOTSTRAP_PHASE_PROOF_CHANGED')
    for role,receipt in zip(('registry','gateway'),receipts):
        sc.need(receipt['operationId']==paired_operation_id(pair['attemptId'],role)
                and receipt['eventKind']=='PROTECTED_PAIRED_BEGIN'
                and receipt['instanceId']==holds['instanceId']
                and receipt['subject']==pair['items'][role]['subject']
                and receipt['recordedAt']==authorization['recordedAt']
                and receipt['technicalInstallationVerified'] is False,
                'SOURCE_BOOTSTRAP_PHASE_PROOF_CHANGED')
    selected=next((h for h in holds['holds'] if h['attemptId']==pair['attemptId']),None)
    sc.need(selected is not None and selected.get('pairDigest')==sc.digest(pair)
            and selected['source']==pair['items']['gateway']['source'],
            'SOURCE_BOOTSTRAP_PHASE_PROOF_CHANGED')
    generation=authorization['targetGeneration']
    sc.hex_id(generation,64)
    sc.need(generation!=seed['generation'],'SOURCE_BOOTSTRAP_PHASE_PROOF_CHANGED')
    attempt={k:selected[k] for k in ('attemptId','subject','source','restrictionDigest')}
    attempt.update(sourceGeneration=seed['generation'],targetGeneration=generation)
    sc.need(matching_holds(holds['holds'],attempt),'SOURCE_BOOTSTRAP_PHASE_PROOF_CHANGED')
    proof=sc.digest({'kind':'BOOTSTRAP_PHYSICAL_FREEZE','authorization':authorization,
                     'pair':pair,'receipts':receipts,'holdSnapshot':holds})
    phases=[]
    current=seed
    for phase in ('DRAINING','FROZEN_BEFORE_CHECK','CHECK_SEALED','APPLY_STOP','STAGED_TARGET_FROZEN'):
        current=validate_transition(current,{**current,'phase':phase,'attempt':attempt,
            'generation':generation if phase=='STAGED_TARGET_FROZEN' else seed['generation'],
            'sequence':current['sequence']+1,'previousDigest':sc.digest(current),'proofDigest':proof})
        phases.append(current)
    return {'proofKind':'BOOTSTRAP_PHYSICAL_FREEZE','proofDigest':proof,'records':phases,
            'registryDigest':sc.digest(holds),
            'handoff':{'role':'staged_target','attemptId':attempt['attemptId'],
                'restrictionDigest':attempt['restrictionDigest'],'interlockDigest':sc.digest(current),
                'registryDigest':sc.digest(holds)}}


def bootstrap_final_handoff(checked, authorization, seed, begin, publication):
    """Exact next frozen material, NOT a phase publication or runtime GO.

    The caller must independently obtain the begin result from the actual
    inactive journal and the committed owner anchor and mounted projection.
    Recompute the complete chain; a saved plan is never itself authority.
    """
    sc.fields(begin,('result','pair','receipts','holdSnapshot','registryDigest',
                     'phasePlan','hostAccepted','admissionAllowed'))
    sc.need(begin['result']=='BOOTSTRAP_PAIR_BEGIN_ACCOUNTED_ONLY'
            and begin['hostAccepted'] is False and begin['admissionAllowed'] is False
            and authorization['compatibilityDigest']==bootstrap_compatibility_digest(checked),
            'SOURCE_BOOTSTRAP_FINAL_PROOF_CHANGED')
    registry=checked['registry']
    pair=paired_begin(begin['pair'],registry['items']['gateway']['subject']['repository'])
    sc.need(pair['checkpoint']==registry['checkpoint'] and pair['items']==registry['items']
            and pair['artifacts']==checked['artifacts'],
            'SOURCE_BOOTSTRAP_FINAL_PROOF_CHANGED')
    plan=bootstrap_phase_plan(seed,authorization,pair,begin['receipts'],begin['holdSnapshot'])
    sc.need(plan==begin['phasePlan'] and plan['registryDigest']==begin['registryDigest'],
            'SOURCE_BOOTSTRAP_FINAL_PROOF_CHANGED')
    sc.fields(publication,('schema','state','sourceRecordHash','record','digest',
                           'registryDigest','previous','previousRegistryDigest'))
    previous,stop,staged=plan['records'][-3:]
    source_hash=publication['sourceRecordHash']
    sc.need(type(source_hash) is str and source_hash.lower()==authorization['sourceRecordDigest']
            and publication['schema']=='fortis-successor-maintenance-publication-v2'
            and publication['state']=='Committed'
            and publication['record']==stop and publication['digest']==sc.digest(stop)
            and publication['previous']==previous
            and publication['previousRegistryDigest']==publication['registryDigest']==plan['registryDigest'],
            'SOURCE_BOOTSTRAP_FINAL_PUBLICATION_CHANGED')
    return {'record':staged,'handoff':plan['handoff']}


def staged_registry_profile(registry, *, handoff, staged_record):
    """Same exact Registry projection for Gateway planning and owner sealing."""
    record=bind_startup_handoff(handoff,staged_record)
    pins=registry['semantic']
    sc.need(handoff['role']=='staged_target' and registry['schemaVersion']==3
            and record['registryInstanceId']==registry['instanceId']
            and record['scopeDigest']==sc.digest(registry['scope'])
            and record['attempt']['sourceGeneration']==pins['generation'],
            'R7_REGISTRY_STAGED_PAIR_CHANGED')
    return {**registry,'semantic':{**pins,'generation':record['generation']},
            'sourceWrite':{**registry['sourceWrite'],'interlockDigest':handoff['interlockDigest'],
                           'latestPin':True}}

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
    sc.need(record['phase']=='COMPLETION_PENDING')
    attempt=record['attempt']
    sc.fields(controller,('schemaVersion','attemptId','subject','source','generation',
                          'applyRecordDigest','backupRecordDigest','primaryRecordDigest',
                          'finalSealDigest','completionTime'))
    sc.fields(observation,('schemaVersion','attemptId','subject','source','generation',
                           'primaryRecordDigest','observedAt','stateReceiptDigest','healthy'))
    for data in (controller,observation):
        sc.need(type(data['schemaVersion']) is int and data['schemaVersion']==1)
        sc.need(data['attemptId']==attempt['attemptId'] and data['subject']==attempt['subject']
                and data['source']==attempt['source'] and data['generation']==record['generation'],
                'MAINTENANCE_COMPLETION_IDENTITY')
    for k in ('applyRecordDigest','backupRecordDigest','primaryRecordDigest','finalSealDigest'):
        sc.hex_id(controller[k],64)
    sc.hex_id(observation['stateReceiptDigest'],64)
    for pin in (expected_controller_digest,expected_observation_digest):
        sc.hex_id(pin,64)
    sc.need(sc.digest(controller)==expected_controller_digest and
            sc.digest(observation)==expected_observation_digest and
            record['proofDigest']==expected_controller_digest and
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
            and record['generation']==attempt['targetGeneration']
            and attempt['source']['artifactSha256'] is not None,
            'MAINTENANCE_COMPLETION_OBSERVATION_UNVERIFIED')
    sc.revision(expected_target_revision)
    sc.hex_id(expected_desired_record,64)
    return {'subject':attempt['subject'],'source':attempt['source'],
            'expected':{'targetRevision':expected_target_revision,
                        'desiredRecordId':expected_desired_record,
                        'catalogSha256':attempt['source']['catalogSha256']},
            'attemptId':attempt['attemptId'],'controllerReceiptDigest':expected_controller_digest,
            'readbackDigest':expected_observation_digest,'observedAt':observation['observedAt']}

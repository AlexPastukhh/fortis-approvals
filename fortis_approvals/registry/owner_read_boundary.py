"""P5 fixed owner-checkpoint read adapter for an already accepted Unix peer.

Source only: no listener, socket creation, WebAuthn, CAS advance, protected
witness or live grants. This is NOT an owner authority or an installed API.
Only the existing Linux SO_PEERCRED guard may admit a peer; no caller-supplied
identity or filesystem path is honored.
"""
from ..core import Denied, canonical
from .checkpoint_cas import OfflineCheckpointCAS
from .owner_peer_boundary import _endpoint, _profile, observe_accepted_peer
from .state_journal import _hash, _need, _uuid

_MAX_RESPONSE_BYTES=8192


def read_accepted_checkpoint(*, connection, profile_reader, expected_profile_digest,
                             ledger):
    """Read one fixed owner ledger through a previously accepted connection.

    Caller must provision and own the Unix listener in a separate owner
    process. This function neither binds a socket nor sends network bytes.
    It intentionally cannot advance the checkpoint or authenticate a real
    WebAuthn owner decision. Positive fixture tests are NOT host isolation.
    """
    _need(type(ledger) is OfflineCheckpointCAS and callable(profile_reader),
          'REGISTRY_OWNER_READ_LEDGER_REQUIRED')
    profile=_profile(profile_reader(),expected_profile_digest)
    _need(ledger.instance_id==profile['instanceId']
          and _hash(ledger.scope)==profile['scopeDigest']
          and ledger.enrollment_receipt_digest==profile['enrollmentReceiptDigest'],
          'REGISTRY_OWNER_READ_LEDGER_BINDING')
    before=_endpoint(profile)
    observed=observe_accepted_peer(connection=connection,
                                   profile_reader=profile_reader,
                                   expected_profile_digest=expected_profile_digest)
    _need(type(observed) is dict
          and observed.get('result')=='OWNER_PEER_BOUNDARY_CANDIDATE'
          and observed.get('instanceId')==profile['instanceId']
          and observed.get('scopeDigest')==profile['scopeDigest']
          and observed.get('dispatchAllowed') is False
          and observed.get('protectedAuthorityVerified') is False
          and observed.get('ownerAcceptanceVerified') is False,
          'REGISTRY_OWNER_READ_PEER_INVALID')
    operation=observed.get('operation')
    if operation=='checkpoint.get':
        _need(observed.get('role') in ('registry-reader','owner-operator')
              and 'operationId' not in observed,
              'REGISTRY_OWNER_READ_ROLE_DENIED')
        payload=ledger.read_checkpoint()
    elif operation=='checkpoint.original':
        _need(observed.get('role')=='owner-operator'
              and _uuid(observed.get('operationId')),
              'REGISTRY_OWNER_READ_ROLE_DENIED')
        payload=ledger.original(observed['operationId'])
        _need(payload.get('result') in ('CHECKPOINT_CAS_CANDIDATE',
                                        'CHECKPOINT_OPERATION_NOT_FOUND'),
              'REGISTRY_OWNER_READ_ORIGINAL_INVALID')
        if payload['result']=='CHECKPOINT_CAS_CANDIDATE':
            _need(payload.get('receipt',{}).get('operationId')==observed['operationId'],
                  'REGISTRY_OWNER_READ_ORIGINAL_INVALID')
    else:
        raise Denied('REGISTRY_OWNER_READ_OPERATION_CLOSED')

    # Revalidate profile, socket identity and fixed ledger binding AFTER
    # reading; never use an untrusted request path or identity claim.
    _need(_endpoint(profile)==before
          and _profile(profile_reader(),expected_profile_digest)==profile
          and ledger.instance_id==profile['instanceId']
          and _hash(ledger.scope)==profile['scopeDigest']
          and ledger.enrollment_receipt_digest==profile['enrollmentReceiptDigest'],
          'REGISTRY_OWNER_READ_BINDING_CHANGED')
    result={'schemaVersion':1,'result':'OWNER_CHECKPOINT_READ_CANDIDATE',
            'requestId':observed['requestId'],
            'operation':operation,'instanceId':profile['instanceId'],
            'scopeDigest':profile['scopeDigest'],
            'data':payload,
            'protectedAuthorityVerified':False,
            'ownerAcceptanceVerified':False,
            'dispatchAllowed':False,'admissionAllowed':False}
    if operation=='checkpoint.original':
        result['operationId']=observed['operationId']
    _need(len(canonical(result).encode('utf-8'))<=_MAX_RESPONSE_BYTES,
          'REGISTRY_OWNER_READ_RESPONSE_LIMIT')
    return result

"""P5 exact first-enrollment cutover preflight, source-only.

Reconciles a pinned baseline/current-main reading, empty Registry v2 and owner
CAS genesis, and matching host/isolation/denial candidate observations.
It NEVER creates an enrollment, grants authority, advances an anchor or
asserts genuine host/owner attestation: all inputs are offline candidates.
"""
from ..core import Denied, Stale
from . import owner_storage_denial as denial
from . import owner_runtime_isolation as runtime
from . import recovery_reconcile as recovery
from .checkpoint_cas import OfflineCheckpointCAS
from .state_journal import _hash, _hex, _need, _uuid, REPOSITORY
from .state_journal_v2 import RegistryStateJournalV2

_BASELINE_KEYS={'schemaVersion','enrollmentId','repository','baselineSha',
                'catalogSha256','acceptanceReceiptDigest','bindingDigest'}
_MAIN_KEYS={'repository','branch','sha'}


def _baseline(value,scope,owner,pin):
    _need(type(value) is dict and set(value)==_BASELINE_KEYS
          and type(value['schemaVersion']) is int and value['schemaVersion']==1
          and value['repository']==REPOSITORY
          and _uuid(value['enrollmentId'])
          and _hex(value['baselineSha'],40)
          and all(_hex(value[k],64) for k in
                  ('catalogSha256','acceptanceReceiptDigest','bindingDigest'))
          and _hex(pin,64) and _hash(value)==pin
          and scope['baselineDigest']==pin
          and all(value[k]==scope[k] for k in
                  ('repository','enrollmentId','baselineSha','catalogSha256','bindingDigest'))
          and value['acceptanceReceiptDigest']==owner.enrollment_receipt_digest,
          'REGISTRY_ENROLLMENT_BASELINE_MISMATCH')
    return value


def _main(value,baseline):
    _need(type(value) is dict and set(value)==_MAIN_KEYS
          and value['repository']==REPOSITORY
          and value['branch']=='main'
          and value['sha']==baseline['baselineSha'],
          'REGISTRY_ENROLLMENT_MAIN_CHANGED')
    return value


def _host(isolation_observation,registry_denial_observation,
          repo_denial_observation,*,peer,layout,owner,store):
    _need(peer['instanceId']==store.instance_id
          and peer['scopeDigest']==_hash(store.scope)
          and peer['enrollmentReceiptDigest']==owner.enrollment_receipt_digest
          and layout['ownerStatePath']==str(owner.path)
          and layout['registryStatePath']==str(store.path),
          'REGISTRY_ENROLLMENT_HOST_BINDING_MISMATCH')
    _need(type(isolation_observation) is dict
          and set(isolation_observation)=={'result','observation','observationDigest',
              'protectedAnchorVerified','enrollmentVerified','hostStorageVerified',
              'ownerAcceptanceVerified','runtimeActivationAllowed','admissionAllowed'}
          and all(isolation_observation[k] is False for k in
                  ('protectedAnchorVerified','enrollmentVerified','hostStorageVerified',
                   'ownerAcceptanceVerified','runtimeActivationAllowed','admissionAllowed'))
          and isolation_observation['result']=='OWNER_RUNTIME_ISOLATION_OBSERVATION_CANDIDATE',
          'REGISTRY_ENROLLMENT_ISOLATION_INVALID')
    o=isolation_observation['observation']
    _need(type(o) is dict
          and set(o)=={'schemaVersion','format','instanceId','scopeDigest',
                        'bootId','peerProfileDigest','layoutDigest','processes',
                        'stateFiles','socketDev','socketInode'}
          and _hex(isolation_observation['observationDigest'],64)
          and _hash(o)==isolation_observation['observationDigest'],
          'REGISTRY_ENROLLMENT_ISOLATION_INVALID')
    _need(isolation_observation==runtime._assess(
              layout,peer,o['processes'],o['stateFiles'],
              (o['socketDev'],o['socketInode'])),
          'REGISTRY_ENROLLMENT_ISOLATION_INVALID')
    registry=denial._checked_observation(registry_denial_observation,'registry',layout,peer)
    repo=denial._checked_observation(repo_denial_observation,'repo',layout,peer)
    _need(registry['process']==o['processes']['registry']
          and repo['process']==o['processes']['repo'],
          'REGISTRY_ENROLLMENT_DENIAL_PROCESS_MISMATCH')
    review=denial.compose_storage_denial_review(
        registry_observation=registry_denial_observation,
        repo_observation=repo_denial_observation,
        peer_profile_reader=lambda:peer,expected_peer_profile_digest=_hash(peer),
        layout_reader=lambda:layout,expected_layout_digest=_hash(layout))
    return review['observationDigest']


def _genesis(store,owner,baseline):
    recovery._bind(store,owner)
    owner_cp,owner_ops=recovery._read_owner(owner)
    state_cp,cursor,state_ops=recovery._read_registry(store)
    _need(owner_cp==store.initial==state_cp
          and owner_cp['revision']==0
          and not owner_ops and not state_ops
          and cursor==baseline['baselineSha'],
          'REGISTRY_ENROLLMENT_NONEMPTY_OR_UNANCHORED')
    return {'checkpoint':state_cp,'cursor':cursor,
            'ownerOperationCount':len(owner_ops),
            'registryOperationCount':len(state_ops)}


def inspect_first_enrollment(*,store,owner,baseline_reader,
                             expected_baseline_digest,selected_main_reader,
                             peer_profile_reader,expected_peer_profile_digest,
                             layout_reader,expected_layout_digest,
                             isolation_observation,
                             registry_denial_observation,repo_denial_observation):
    """Compare exact pre-enrollment snapshots without any authority grant.

    Owner acceptance, authenticated collector, trusted original host probes
    and the actual independent protected checkpoint are NOT provided here.
    """
    _need(type(store) is RegistryStateJournalV2 and
          type(owner) is OfflineCheckpointCAS
          and all(callable(x) for x in (baseline_reader,selected_main_reader,
                                      peer_profile_reader,layout_reader)),
          'REGISTRY_ENROLLMENT_SOURCE_REQUIRED')
    baseline=_baseline(baseline_reader(),store.scope,owner,expected_baseline_digest)
    main=_main(selected_main_reader(),baseline)
    peer=runtime._profile(peer_profile_reader(),expected_peer_profile_digest)
    layout=runtime._layout(layout_reader(),expected_layout_digest,peer)
    head=_genesis(store,owner,baseline)
    denial_digest=_host(isolation_observation,registry_denial_observation,
                        repo_denial_observation,peer=peer,layout=layout,
                        store=store,owner=owner)
    second_head=_genesis(store,owner,baseline)
    if (head!=second_head
        or _baseline(baseline_reader(),store.scope,owner,expected_baseline_digest)!=baseline
        or _main(selected_main_reader(),baseline)!=main
        or runtime._profile(peer_profile_reader(),expected_peer_profile_digest)!=peer
        or runtime._layout(layout_reader(),expected_layout_digest,peer)!=layout):
        raise Stale('REGISTRY_ENROLLMENT_PREFLIGHT_CHANGED')
    observation={'schemaVersion':1,
                 'format':'registry-first-enrollment-cutover-preflight-v1',
                 'repository':REPOSITORY,'instanceId':store.instance_id,
                 'scopeDigest':_hash(store.scope),
                 'enrollmentId':baseline['enrollmentId'],
                 'baselineSha':baseline['baselineSha'],
                 'baselineDigest':expected_baseline_digest,
                 'catalogSha256':baseline['catalogSha256'],
                 'bindingDigest':baseline['bindingDigest'],
                 'policyReferenceDigest':store.scope['policyReferenceDigest'],
                 'ownerEnrollmentReceiptDigest':owner.enrollment_receipt_digest,
                 'ownerCheckpoint':head['checkpoint'],
                 'ownerOperationCount':head['ownerOperationCount'],
                 'registryOperationCount':head['registryOperationCount'],
                 'candidateCursor':head['cursor'],
                 'peerProfileDigest':_hash(peer),'layoutDigest':_hash(layout),
                 'isolationDigest':isolation_observation['observationDigest'],
                 'storageDenialReviewDigest':denial_digest}
    return {'result':'FIRST_ENROLLMENT_CUTOVER_PREFLIGHT_CANDIDATE',
            'observation':observation,'observationDigest':_hash(observation),
            'originalHostEvidenceAuthenticated':False,
            'ownerAcceptanceVerified':False,
            'protectedCheckpointVerified':False,
            'runtimeActivated':False,'enrollmentAllowed':False,
            'registryWriteAllowed':False,'admissionAllowed':False}

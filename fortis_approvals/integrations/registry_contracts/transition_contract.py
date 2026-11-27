"""Pure #286 successor transition bindings. Not an evidence verifier or GO.

Trusted composition must independently authenticate the owner decision,
obtain the old state witness and Git/CI evidence, and pin the manifest
digest. No caller-supplied digest by itself authorizes migration.
"""
from ...core import Denied, canonical, loads_strict
from .semantic_contract import digest, fields, hex_id, need, revision, uuid_id

REPOSITORY = 'AlexPastukhh/fortis-approvals'
BASE_SHA = 'bfd9dd40895c43aa0d73758fb9d27c627f5f8131'
BASE_CATALOG = 'ed0ed1e667eabd14afb5b550194df68dee689892265d22910b4749d2521e0667'
GAP_PREFIX = '91e1de5b02af9e2eaa0cf33b251f2e2db16edf13baab70e49b06a1ffc4dd9c36'
MAX_BYTES = 16384
_KIND = 'REGISTRY_286_SUCCESSOR_TRANSITION'


def _bounded(value):
    try:
        raw = canonical(value).encode('utf-8')
        need(len(raw) <= MAX_BYTES, 'TRANSITION_SIZE_LIMIT')
        return loads_strict(raw)
    except (TypeError, ValueError, UnicodeError, RecursionError, OverflowError) as exc:
        if isinstance(exc, Denied):
            raise
        raise Denied('TRANSITION_INVALID') from None


def _hash_fields(obj, names):
    fields(obj, names)
    for name in names:
        hex_id(obj[name], 64)


def _capture_checkpoint(cp):
    # Existing ReviewCaptureStore checkpoint has no invented instance ID.
    fields(cp, ('revision', 'eventDigest'))
    revision(cp['revision'])
    hex_id(cp['eventDigest'], 64)


def _collector_checkpoint(cp):
    fields(cp, ('schemaVersion', 'instanceId', 'revision', 'eventDigest'))
    need(type(cp['schemaVersion']) is int and cp['schemaVersion'] == 1)
    uuid_id(cp['instanceId'])
    revision(cp['revision'])
    hex_id(cp['eventDigest'], 64)


def validate_registry_witness(reg):
    fields(reg, ('schemaVersion', 'instanceId', 'scopeDigest', 'genesisDigest',
                 'revision', 'eventDigest', 'cursorSha', 'prefixDigest'))
    need(type(reg['schemaVersion']) is int and reg['schemaVersion'] == 3)
    uuid_id(reg['instanceId'])
    revision(reg['revision'])
    need(reg['revision'] <= 64)
    for key in ('scopeDigest', 'genesisDigest', 'eventDigest', 'prefixDigest'):
        hex_id(reg[key], 64)
    hex_id(reg['cursorSha'], 40)
    need(reg['revision'] != 0 or reg['genesisDigest'] == reg['eventDigest'])
    return _bounded(reg)



def validate_manifest(value):
    """Closed manifest for one exact delivery PR; no effect or owner proof."""
    detached = _bounded(value)
    fields(value, ('schemaVersion', 'kind', 'transitionId', 'repository',
                   'old', 'pr', 'successor', 'recovery'))
    need(type(value['schemaVersion']) is int and value['schemaVersion'] == 1
         and value['kind'] == _KIND and value['repository'] == REPOSITORY,
         'TRANSITION_SCOPE_INVALID')
    uuid_id(value['transitionId'])
    old = value['old']
    fields(old, ('sourceSha', 'catalogSha256', 'historicalGapDigest',
                 'historicalGapPrefixDigest', 'registry', 'capture', 'collector',
                 'policy', 'corePreservationDigest', 'protectedStateDigest'))
    need(old['sourceSha'] == BASE_SHA and old['catalogSha256'] == BASE_CATALOG
         and old['historicalGapPrefixDigest'] == GAP_PREFIX,
         'TRANSITION_BASE_CHANGED')
    for key in ('historicalGapDigest', 'corePreservationDigest', 'protectedStateDigest'):
        hex_id(old[key], 64)
    validate_registry_witness(old['registry'])
    _capture_checkpoint(old['capture'])
    _collector_checkpoint(old['collector'])
    # 128 is the functional pilot admission cap, not Capture's store cap.
    for key in ('capture', 'collector'):
        need(old[key]['revision'] <= 128)
    policy = old['policy']
    fields(policy, ('revision', 'authorityDigest', 'historyDigest'))
    revision(policy['revision'])
    hex_id(policy['authorityDigest'], 64)
    hex_id(policy['historyDigest'], 64)
    pr = value['pr']
    fields(pr, ('number', 'baseSha', 'headSha', 'treeSha', 'mergeMethod',
                'bodyDigest', 'impactDigest', 'pathsDigest', 'ciDigest'))
    need(type(pr['number']) is int and 286 < pr['number'] <= 1_000_000
         and pr['baseSha'] == BASE_SHA and pr['mergeMethod'] == 'merge',
         'TRANSITION_PR_SCOPE_INVALID')
    for key in ('headSha', 'treeSha'):
        hex_id(pr[key], 40)
    need(pr['headSha'] != BASE_SHA)
    for key in ('bodyDigest', 'impactDigest', 'pathsDigest', 'ciDigest'):
        hex_id(pr[key], 64)
    successor = value['successor']
    fields(successor, ('registrySchemaVersion', 'catalogSha256',
                       'authorityDigest', 'coreSchemaDigest', 'validatorRevision',
                       'actionRevision', 'migrationContractDigest'))
    need(type(successor['registrySchemaVersion']) is int
         and successor['registrySchemaVersion'] == 4)
    for key in ('catalogSha256', 'authorityDigest', 'coreSchemaDigest', 'migrationContractDigest'):
        hex_id(successor[key], 64)
    for key in ('validatorRevision', 'actionRevision'):
        hex_id(successor[key], 40)
    _hash_fields(value['recovery'], ('primaryRecordDigest', 'backupRecordDigest',
                                    'registryBackupDigest'))
    return detached


def bind_old_state(manifest, observed_old, *, expected_manifest_digest):
    """Match the exact independently obtained predecessor witness to its pin."""
    approved = validate_manifest(manifest)
    hex_id(expected_manifest_digest, 64)
    need(digest(approved) == expected_manifest_digest, 'TRANSITION_MANIFEST_CHANGED')
    actual = _bounded(observed_old)
    need(type(observed_old) is dict and digest(actual) == digest(approved['old']),
         'TRANSITION_OLD_STATE_CHANGED')
    return {'result': 'TRANSITION_OLD_BINDINGS_MATCH_ONLY',
            'transitionId': approved['transitionId'],
            'manifestDigest': expected_manifest_digest,
            'oldStateDigest': digest(actual)}


def bind_merge(manifest, observation, *, expected_manifest_digest):
    """Compare independently obtained records to a trusted manifest pin.

    Does not authenticate observation provenance, CI, owner proof, or
    historical gap. A match is deliberately not a receipt or permission.
    """
    approved = validate_manifest(manifest)
    hex_id(expected_manifest_digest, 64)
    need(digest(approved) == expected_manifest_digest, 'TRANSITION_MANIFEST_CHANGED')
    detached = _bounded(observation)
    fields(observation, ('repository', 'number', 'headSha', 'mergeSha',
                         'mainSha', 'parents', 'treeSha', 'catalogSha256',
                         'bodyDigest', 'impactDigest', 'pathsDigest', 'ciDigest'))
    pr = approved['pr']
    hex_id(observation['mergeSha'], 40)
    need(observation['mergeSha'] not in (BASE_SHA, pr['headSha'])
         and observation['mainSha'] == observation['mergeSha']
         and observation['parents'] == [BASE_SHA, pr['headSha']]
         and observation['repository'] == approved['repository']
         and type(observation['number']) is int
         and observation['number'] == pr['number']
         and observation['headSha'] == pr['headSha']
         and observation['treeSha'] == pr['treeSha']
         and observation['catalogSha256'] == approved['successor']['catalogSha256']
         and all(observation[key] == pr[key] for key in
                 ('bodyDigest', 'impactDigest', 'pathsDigest', 'ciDigest')),
         'TRANSITION_MERGE_MISMATCH')
    return {'result': 'TRANSITION_BINDINGS_MATCH_ONLY',
            'transitionId': approved['transitionId'],
            'manifestDigest': expected_manifest_digest,
            'observationDigest': digest(detached),
            'mergeSha': detached['mergeSha']}

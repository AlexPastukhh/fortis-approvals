"""Internal pre-merge material collection, not trusted historical evidence."""
import base64
import hashlib

from ....core import Denied, Stale, canonical
from ..post_merge_proof_bindings import _impact_yaml, EvidenceEnvelopeError
from .path_ci_observation import observe_path_ci
from .post_merge_reader import PILOT_REPOSITORY

MAX_CATALOG_BYTES = 120_000
MAX_BUNDLE_BYTES = 240_000


def digest(value):
    return hashlib.sha256(canonical(value).encode('utf-8')).hexdigest()


def collect_bundle(adapter, *, number, head, base, body, body_sha, branch, policy_bound=False):
    """No caller-selected catalog URL/ref or unverified CI material."""
    if hashlib.sha256(body.encode('utf-8')).hexdigest() != body_sha:
        raise Denied('P5_BUNDLE_BODY_MISMATCH')
    try:
        impact = _impact_yaml(body)
    except EvidenceEnvelopeError:
        raise Denied('P5_BUNDLE_IMPACT_MARKERS_INVALID') from None
    repo = adapter._repo(PILOT_REPOSITORY)
    origin = adapter.owner + '/' + repo

    def catalog():
        raw = adapter._api('GET', adapter._path(repo, 'contents/release/targets.yaml'),
                           params={'ref': head})
        if not (type(raw) is dict and raw.get('type') == 'file'
                and raw.get('path') == 'release/targets.yaml'
                and raw.get('encoding') == 'base64' and type(raw.get('size')) is int
                and 0 < raw['size'] <= MAX_CATALOG_BYTES and type(raw.get('content')) is str
                and len(raw['content']) <= 2 * MAX_CATALOG_BYTES):
            raise Denied('P5_BUNDLE_CATALOG_INVALID')
        try:
            data = base64.b64decode(raw['content'].replace('\n', ''), validate=True)
            body_text = data.decode('utf-8')
        except (ValueError, UnicodeError):
            raise Denied('P5_BUNDLE_CATALOG_ENCODING') from None
        git_blob = hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()
        if len(data) != raw['size'] or git_blob != raw.get('sha'):
            raise Denied('P5_BUNDLE_CATALOG_HASH')
        return {'path': 'release/targets.yaml', 'headSha': head, 'gitBlobSha': git_blob,
                'sha256': hashlib.sha256(data).hexdigest(), 'text': body_text}

    first = catalog()
    observed = observe_path_ci(adapter, number=number, expected_head_sha=head,
                               expected_base_sha=base, expected_body_sha256=body_sha,
                               policy_bound=policy_bound)
    value = observed['observation']
    if (value['repository'] != origin or value['number'] != number or
            value['pr']['headSha'] != head or value['pr']['baseSha'] != base or
            value['pr']['bodySha256'] != body_sha or value['pr']['branch'] != branch or
            observed['observationDigest'] != digest(value)):
        raise Denied('P5_BUNDLE_OBSERVATION_MISMATCH')
    if catalog() != first:
        raise Stale('P5_BUNDLE_CATALOG_CHANGED')
    material = {'schemaVersion': 2 if policy_bound else 1, 'catalog': first, 'pathCi': value,
                'impactSha256': hashlib.sha256(impact.encode('utf-8')).hexdigest()}
    if len(canonical(material).encode('utf-8')) > MAX_BUNDLE_BYTES:
        raise Denied('P5_BUNDLE_SIZE_LIMIT')
    return material


def observe_reviewed_merge(*, adapter, store, core, checkpoint_reader, owner,
                           owner_request_id, expected_merge_sha, selected_main_sha):
    """Compose independently read stored decision, anchored capture and merge.

    Exact pre-merge base and selected-main catalog continuity are required for
    this conservative pilot. Does not prove effective historical branch rules,
    the body at merge time, a merge tree diff or owner intent beyond Core ASK.
    """
    from datetime import datetime, timezone
    from .post_merge_reader import observe_post_merge
    from .review_attestation import read_bound_owner_decision

    decision = read_bound_owner_decision(core, owner_request_id, owner=owner)
    if decision['result'] != 'OWNER_BUNDLE_DECISION_BOUND':
        raise Denied('P5_MERGE_BUNDLE_REVIEW_REQUIRED')
    checkpoint = checkpoint_reader()
    capture_id = decision['captureOperationId']
    retained = store.retained_material(capture_id, expected_checkpoint=checkpoint)
    receipt = store.operation(capture_id)
    if (receipt is None or receipt['eventDigest'] != decision['captureEventDigest'] or
            receipt.get('bundleDigest') != decision['bundleDigest'] or
            retained.get('bundleDigest') != decision['bundleDigest'] or
            digest(retained['bundle']) != decision['bundleDigest']):
        raise Denied('P5_MERGE_RETAINED_BUNDLE_MISMATCH')
    pre = retained['bundle']
    post = observe_post_merge(adapter, number=decision['number'],
                              expected_head_sha=decision['headSha'],
                              expected_merge_sha=expected_merge_sha,
                              selected_main_sha=selected_main_sha)
    value = post['observation']
    merge = value['firstParent'][-1]
    if (value['repository'] != decision['repository'] or
            merge['parents'][0] != retained['baseSha'] or
            value['pullRequest']['headBranch'] != retained['headBranch'] or
            value['catalog']['contentSha256'] != pre['catalog']['sha256'] or
            value['catalog']['gitBlobSha'] != pre['catalog']['gitBlobSha']):
        raise Denied('P5_MERGE_BASE_OR_CATALOG_CHANGED')
    merged_at = datetime.fromisoformat(value['pullRequest']['mergedAt'])
    executed_at = datetime.fromtimestamp(decision['ownerExecutionAt'], timezone.utc)
    if executed_at >= merged_at:
        raise Denied('P5_MERGE_REVIEW_ORDER_UNPROVEN')
    if checkpoint_reader() != checkpoint or store.checkpoint(expected=checkpoint) != checkpoint:
        raise Stale('P5_MERGE_CHECKPOINT_CHANGED')
    if read_bound_owner_decision(core, owner_request_id, owner=owner) != decision:
        raise Stale('P5_MERGE_OWNER_DECISION_CHANGED')
    material = {'ownerDecision': decision, 'bundleDigest': decision['bundleDigest'],
                'checkpoint': checkpoint, 'mergeObservation': value}
    if pre['schemaVersion'] == 2:
        binding = pre['pathCi']['ciPolicyBinding']
        captured_at = datetime.fromisoformat(retained['capturedAt'])
        if any(datetime.fromisoformat(check['completedAt']) > captured_at or
               datetime.fromisoformat(check['completedAt']) >= executed_at
               for check in binding['checks']):
            raise Denied('P5_MERGE_CI_REVIEW_ORDER_UNPROVEN')
        material['retainedCiPolicySha256'] = binding['policySha256']
        material['retainedCiBindingSha256'] = digest(binding)
    return {'result': 'REVIEWED_BUNDLE_MERGE_OBSERVED',
            'observation': material, 'observationDigest': digest(material),
            'historicalMergeCutoffVerified': False, 'historicalPolicyVerified': False,
            'requiredPolicySatisfied': False, 'evidenceVerified': False,
            'admissionAllowed': False, 'deploymentAllowed': False}

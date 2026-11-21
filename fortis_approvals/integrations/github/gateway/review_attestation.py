"""Unregistered P5 Core ASK adapter and protected decision readback.

The future server must supply the actual protected capture store, independent
checkpoint reader, provider adapter and Core. No request can supply them.
This is a body-review decision, not a GitHub merge or full release approval.
"""
from ....core import Denied, Stale, loads_strict
from .review_capture import _hash, _uuid, _hex, _need
from .post_merge_reader import PILOT_REPOSITORY

SERVICE = 'release-review'
OPERATION = 'attest_capture'
BUNDLE_OPERATION = 'attest_bundle'
ACTOR = 'release-registry-collector-v1'
_FIELDS = {'captureOperationId', 'captureEventDigest', 'headSha', 'bodySha256',
           'number', 'checkpointDigest'}


def _params(payload):
    params = payload.get('params')
    operation = payload.get('operation')
    fields = _FIELDS | {'bundleDigest'} if operation == BUNDLE_OPERATION else _FIELDS
    _need(payload.get('service') == SERVICE and operation in (OPERATION, BUNDLE_OPERATION)
          and payload.get('target') == PILOT_REPOSITORY
          and _uuid(payload.get('requestId')) and type(params) is dict
          and set(params) == fields and _uuid(params['captureOperationId'])
          and _hex(params['captureEventDigest'], 64) and _hex(params['headSha'], 40)
          and _hex(params['bodySha256'], 64) and _hex(params['checkpointDigest'], 64)
          and type(params['number']) is int and 0 < params['number'] <= 1_000_000
          and type(payload.get('expectedVersion')) is int and payload['expectedVersion'] > 0,
          'P5_REVIEW_REQUEST_INVALID')
    _need(operation != BUNDLE_OPERATION or _hex(params['bundleDigest'], 64),
          'P5_REVIEW_REQUEST_INVALID')
    return params


def review_policy(actor, payload):
    """Candidate exact-scope ASK predicate, not installed in any policy map."""
    try:
        _params(payload)
        return 'ASK' if actor == ACTOR else 'DENY'
    except (Denied, AttributeError, TypeError):
        return 'DENY'


class ReviewAttestationAdapter:
    def __init__(self, *, store, provider, checkpoint_reader):
        self.store = store
        self.provider = provider
        self.checkpoint_reader = checkpoint_reader

    def prepare(self, payload):
        params = _params(payload)
        expected = {'revision': payload['expectedVersion'],
                    'eventDigest': params['checkpointDigest']}
        # The expected checkpoint in the request is only a CAS precondition;
        # trusted composition supplies an independently anchored readback.
        if self.checkpoint_reader() != expected:
            raise Stale('P5_REVIEW_CHECKPOINT_CHANGED')
        material = self.store.retained_material(params['captureOperationId'],
                                                expected_checkpoint=expected)
        receipt = self.store.operation(params['captureOperationId'])
        if self.store.checkpoint(expected=expected) != expected:
            raise Stale('P5_REVIEW_CHECKPOINT_CHANGED')
        _need(receipt is not None and receipt['eventDigest'] == params['captureEventDigest']
              and receipt['number'] == params['number']
              and receipt['headSha'] == params['headSha']
              and receipt['bodySha256'] == params['bodySha256'],
              'P5_REVIEW_CAPTURE_MISMATCH')
        repo = self.provider._repo(PILOT_REPOSITORY)
        origin = self.provider.owner + '/' + repo
        current = self.provider._release_impact_pr_evidence(repo, params['number'], params['headSha'])
        _need(current['headRepository'] == origin == receipt['repository']
              and current['baseRepository'] == origin
              and current['baseSha'] == material['baseSha']
              and current['headBranch'] == material['headBranch']
              and current['body'] == material['body']
              and current['bodySha256'] == params['bodySha256'],
              'P5_REVIEW_OPEN_PR_DRIFT')
        bundle_review = payload['operation'] == BUNDLE_OPERATION
        if bundle_review:
            _need(receipt['result'] == 'PRE_MERGE_BUNDLE_RETAINED' and
                  receipt.get('bundleDigest') == params['bundleDigest'] and
                  _hash(material['bundle']) == params['bundleDigest'],
                  'P5_REVIEW_BUNDLE_MISMATCH')
            from .premerge_bundle import collect_bundle
            fresh = collect_bundle(self.provider, number=params['number'], head=params['headSha'],
                                   base=material['baseSha'], body=material['body'],
                                   body_sha=params['bodySha256'], branch=material['headBranch'])
            if fresh != material['bundle']:
                raise Stale('P5_REVIEW_BUNDLE_CHANGED')
        else:
            _need(receipt['result'] == 'PRE_MERGE_OBSERVATION_RETAINED',
                  'P5_REVIEW_BUNDLE_OPERATION_REQUIRED')
        if self.checkpoint_reader() != expected or self.store.checkpoint(expected=expected) != expected:
            raise Stale('P5_REVIEW_CHECKPOINT_CHANGED')
        return {'repository': origin, 'params': dict(params), 'checkpoint': expected,
                'baseSha': material['baseSha'], 'headBranch': material['headBranch'],
                'capturedAt': receipt['capturedAt'], 'captureRevision': receipt['revision'],
                'purpose': ('ATTEST_RETAINED_PRE_MERGE_BUNDLE' if bundle_review else
                            'ATTEST_EXACT_RETAINED_PR_BODY_ONLY'),
                'admissionAllowed': False, 'deploymentAllowed': False}

    def apply(self, payload):
        # Core authorizes execution. No side effect on GitHub or capture store.
        # Only Core's durable executed decision is an attestation, not this result.
        return {'requestId': payload['requestId'], 'preview': self.prepare(payload)}

    def confirm(self, request_id, result):
        if type(result) is not dict or set(result) != {'requestId', 'preview'} or result['requestId'] != request_id:
            return False
        try:
            preview = result['preview']
            operation = BUNDLE_OPERATION if preview['purpose'] == 'ATTEST_RETAINED_PRE_MERGE_BUNDLE' else OPERATION
            payload = {'requestId': request_id, 'service': SERVICE, 'operation': operation,
                       'target': PILOT_REPOSITORY, 'params': preview['params'],
                       'expectedVersion': preview['checkpoint']['revision']}
            return self.prepare(payload) == preview
        except (Denied, Stale, KeyError, TypeError):
            return False

    def receipt(self, request_id):
        # No separately committed adapter effect. Lost Core outcome must remain
        # unknown; never synthesize a receipt from the current PR.
        return None


def read_bound_owner_decision(core, request_id, *, owner):
    """Internal trusted Core readback; NOT a caller-supplied approval DTO.

    The owner identity is deployment configuration, not a request parameter.
    Source tests exercise Core with a test verifier; live owner ceremony and
    independently protected audit retention need separate acceptance.
    """
    _need(_uuid(request_id) and type(owner) is str and bool(owner),
          'P5_REVIEW_DECISION_REQUEST_INVALID')
    row = core._read(request_id)
    request = row['request']
    params = _params(request)
    preview = row['preview']
    fingerprint = _hash({'actor': row['actor'], 'request': request,
                         'policyVersion': row['policyVersion'], 'preview': preview})
    bundle_review = request['operation'] == BUNDLE_OPERATION
    purpose = 'ATTEST_RETAINED_PRE_MERGE_BUNDLE' if bundle_review else 'ATTEST_EXACT_RETAINED_PR_BODY_ONLY'
    _need(preview['purpose'] == purpose and row['requestId'] == request_id == request['requestId']
          and row['actor'] == ACTOR and row['fingerprint'] == fingerprint
          and row['state'] == 'EXECUTED' and row['decision'] == 'approve'
          and row['owner'] == owner and row['failure'] is None
          and row['result'] == {'requestId': request_id, 'preview': preview}
          and preview['params'] == params
          and preview['checkpoint'] == {'revision': request['expectedVersion'],
                                        'eventDigest': params['checkpointDigest']},
          'P5_REVIEW_DECISION_NOT_BOUND')
    events = core.events(request_id)
    _need([event['state'] for event in events] ==
          ['PENDING', 'APPROVED', 'DISPATCHED', 'EXECUTED'],
          'P5_REVIEW_AUDIT_SEQUENCE_INVALID')
    _need(all(event['request_id'] == request_id for event in events)
          and all(a['seq'] < b['seq'] and a['at'] <= b['at']
                  for a, b in zip(events, events[1:]))
          and row['createdAt'] == events[0]['at']
          and events[1]['at'] < row['expiresAt'],
          'P5_REVIEW_AUDIT_SEQUENCE_INVALID')
    pending, approved = (loads_strict(event['detail']) for event in events[:2])
    _need(pending == {'policy': 'ASK'} and type(approved) is dict
          and set(approved) == {'owner', 'proofSHA256', 'requestSHA256'}
          and approved['owner'] == owner and approved['requestSHA256'] == fingerprint
          and _hex(approved['proofSHA256'], 64), 'P5_REVIEW_AUDIT_BINDING_INVALID')
    result = {'result': 'OWNER_CAPTURE_DECISION_BOUND', 'requestId': request_id,
            'requestFingerprint': fingerprint, 'captureOperationId': params['captureOperationId'],
            'captureEventDigest': params['captureEventDigest'], 'repository': preview['repository'],
            'number': params['number'], 'headSha': params['headSha'],
            'bodySha256': params['bodySha256'], 'ownerDecisionAt': events[1]['at'],
            'ownerDecisionBound': True, 'historicalMergeCutoffVerified': False,
            'evidenceVerified': False, 'admissionAllowed': False, 'deploymentAllowed': False}
    if bundle_review:
        result.update(result='OWNER_BUNDLE_DECISION_BOUND', bundleDigest=params['bundleDigest'],
                      ownerExecutionAt=events[-1]['at'],
                      historicalPolicyVerified=False, requiredPolicySatisfied=False)
    return result

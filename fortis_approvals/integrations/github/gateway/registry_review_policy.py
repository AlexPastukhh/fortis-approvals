"""Registry-specific cutoff candidate (container PR43), never live authority.

First policy revision only. Host composition pins an independent enrollment
policy reference and clock. Neither a matching digest nor this source test
proves owner enrollment acceptance, protected Core storage or trusted clocks.
"""
import math
from datetime import datetime
import time

from ....core import Denied, Stale, canonical, loads_strict
from ..release_label_ci import _inventory, _latest
from .collector_snapshot import REPOSITORY
from .p5_ci_binding import P5CIReader, P5_WORKFLOWS, policy, observe_check_witnesses
from .post_merge_reader import PILOT_REPOSITORY, _timestamp
from .review_attestation import ReviewAttestationAdapter, BUNDLE_OPERATION, read_bound_owner_decision
from .review_capture import _hash, _hex, _need, _uuid
from .selected_main_binding import observe_selected_main

FIELDS={'schemaVersion','repository','enrollmentId','baselineSha','revision',
        'previousDigest','acceptanceReceiptDigest','effectiveAt',
        'maxReviewToMergeSeconds','clockToleranceSeconds','profile'}


def policy_reference(reader, pin):
    _need(_hex(pin,64),'P5_REGISTRY_POLICY_PIN_INVALID')
    try:
        value=reader()
        _need(type(value) is dict and set(value)==FIELDS
              and type(value['schemaVersion']) is int and value['schemaVersion']==1
              and value['repository']==REPOSITORY and _uuid(value['enrollmentId'])
              and _hex(value['baselineSha'],40)
              and type(value['revision']) is int and value['revision']==1
              and value['previousDigest']=='0'*64
              and _hex(value['acceptanceReceiptDigest'],64)
              and type(value['effectiveAt']) is int and value['effectiveAt']>0
              and type(value['maxReviewToMergeSeconds']) is int
              and 0<value['maxReviewToMergeSeconds']<=86400
              and type(value['clockToleranceSeconds']) is int
              and 0<=value['clockToleranceSeconds']<=60
              and value['profile']==policy() and _hash(value)==pin,
              'P5_REGISTRY_POLICY_REFERENCE_MISMATCH')
        return loads_strict(canonical(value))
    except Denied:
        raise
    except Exception:
        raise Denied('P5_REGISTRY_POLICY_REFERENCE_UNAVAILABLE') from None


def _epoch(value):
    try:
        _need(type(value) is str and len(value)<=40,'P5_REGISTRY_CUTOFF_TIME_INVALID')
        d=datetime.fromisoformat(value)
        _need(d.utcoffset() is not None,'P5_REGISTRY_CUTOFF_TIME_INVALID')
        return d.timestamp()
    except Denied:
        raise
    except (ValueError,OverflowError,OSError,TypeError):
        raise Denied('P5_REGISTRY_CUTOFF_TIME_INVALID') from None


def _binding(ref,pin):
    return {'enrollmentId':ref['enrollmentId'],'baselineSha':ref['baselineSha'],
            'revision':ref['revision'],'policyReferenceDigest':pin,
            'profileDigest':_hash(ref['profile']),
            'acceptanceReceiptDigest':ref['acceptanceReceiptDigest']}


class RegistryPolicyReviewAdapter(ReviewAttestationAdapter):
    """Unregistered distinct composition using the original exact Core ASK.

    The policy binding is in the Core preview/fingerprint before approval;
    it is not an optional post-merge annotation. Original adapter unaffected.
    """
    def __init__(self, *, policy_reader, expected_policy_digest, **kwargs):
        super().__init__(**kwargs)
        self.policy_reader=policy_reader
        self.expected_policy_digest=expected_policy_digest

    def prepare(self,payload):
        _need(payload.get('operation')==BUNDLE_OPERATION,'P5_REGISTRY_POLICY_BUNDLE_REQUIRED')
        ref=policy_reference(self.policy_reader,self.expected_policy_digest)
        preview=super().prepare(payload)
        expected=preview['checkpoint']
        material=self.store.retained_material(preview['params']['captureOperationId'],
                                              expected_checkpoint=expected)
        bundle=material['bundle']
        _need(preview['repository']==REPOSITORY and bundle['schemaVersion']==2
              and bundle['pathCi']['ciPolicyBinding']['policy']==ref['profile']
              and _epoch(preview['capturedAt'])>=ref['effectiveAt'],
              'P5_REGISTRY_POLICY_CAPTURE_MISMATCH')
        if policy_reference(self.policy_reader,self.expected_policy_digest)!=ref or self.checkpoint_reader()!=expected:
            raise Stale('P5_REGISTRY_POLICY_CHANGED')
        return {**preview,'registryPolicyBinding':_binding(ref,self.expected_policy_digest)}


def _post_consistency(adapter, o, material):
    """Current body/attempt consistency only, never reconstruct historical PR text."""
    review=o['reviewedMerge'];pr=review['mergeObservation']['pullRequest']
    head=pr['headSha'];repo=adapter._repo(PILOT_REPOSITORY)
    reader=P5CIReader(adapter)
    _need(adapter.owner+'/'+repo==REPOSITORY,'P5_REGISTRY_POLICY_SCOPE')
    path=material['bundle']['pathCi'];binding=path['ciPolicyBinding'];runs=path['pinnedWorkflowCI']
    def check_pr():
        raw=reader.get('pulls/'+str(pr['number']))
        _need(type(raw) is dict and raw.get('number')==pr['number'] and raw.get('state')=='closed'
              and raw.get('merged') is True and raw.get('draft') is False
              and raw.get('merge_commit_sha')==pr['mergeSha']
              and _timestamp(raw.get('merged_at'))==pr['mergedAt']
              and raw.get('body')==material['body'],'P5_REGISTRY_POST_REVIEW_BODY_OR_MERGE_DRIFT')
        for name,sha,branch in (('head',head,pr['headBranch']),('base',pr['baseSha'],'main')):
            part=raw.get(name)
            _need(type(part) is dict and part.get('sha')==sha and part.get('ref')==branch
                  and type(part.get('repo')) is dict and part['repo'].get('full_name')==REPOSITORY,
                  'P5_REGISTRY_POST_REVIEW_PR_DRIFT')
    def inventory():
        current=_inventory(reader,head)
        for w,old in zip(P5_WORKFLOWS,runs):
            row=_latest(current,w)
            _need((row['id'],row['runAttempt'],row['runNumber'],row['headBranch'])==
                  (old['runId'],old['attempt'],old['runNumber'],pr['headBranch']),
                  'P5_REGISTRY_POST_REVIEW_ATTEMPT_DRIFT')
    check_pr();inventory()
    expected={}
    _need(len(runs)==len(P5_WORKFLOWS),'P5_REGISTRY_POLICY_RUN_SET')
    for w,old in zip(P5_WORKFLOWS,runs):
        _need(old['workflowId']==w.ident and old['workflowPath']==w.path and old['workflowSha256']==w.sha256
              and {j['name'] for j in old['jobs']}==set(w.jobs),'P5_REGISTRY_POLICY_RUN_SET')
        run=reader.run(old['runId'],old['attempt'])
        _need(run['id']==old['runId'] and run['attempt']==old['attempt'] and run['headSha']==head
              and run['headBranch']==pr['headBranch'] and run['repository']==REPOSITORY
              and run['headRepository']==REPOSITORY and run['workflowId']==w.ident
              and run['workflowPath']==w.path and run['event']=='pull_request'
              and run['status']=='completed' and run['conclusion']=='success'
              and type(run['pullRequests']) is list
              and (not run['pullRequests'] or any(p['number']==pr['number'] and p['headSha']==head
                   and p['baseSha']==pr['baseSha'] for p in run['pullRequests'])),
              'P5_REGISTRY_POST_REVIEW_RUN_DRIFT')
        jobs=reader.jobs(run)['items']
        current=sorted([dict(id=j['id'], name=j['name'], status=j['status'],
                             conclusion=j['conclusion']) for j in jobs],key=lambda j:j['name'])
        _need(current==old['jobs'],'P5_REGISTRY_POST_REVIEW_JOB_DRIFT')
        for job in old['jobs']:
            _need(job['name'] not in expected and job['status']=='completed' and job['conclusion']=='success',
                  'P5_REGISTRY_POLICY_RUN_SET')
            expected[job['name']]=(old,job)
    for _ in range(2):
        _need(observe_check_witnesses(reader,owner=adapter.owner,head=head,expected=expected)==binding['checks'],
              'P5_REGISTRY_POST_REVIEW_CHECK_DRIFT')
    inventory();check_pr()


def _observe_registry_review_pair(*, adapter, store, core, checkpoint_reader, owner,
                            owner_request_id, validator, selected_main_sha,
                            policy_reader, expected_policy_digest, clock=time.time):
    """Exact current-tip composition; no admission or protected policy lifecycle."""
    ref=policy_reference(policy_reader,expected_policy_digest)
    checkpoint=checkpoint_reader()
    def anchored():
        if checkpoint_reader()!=checkpoint:
            raise Stale('P5_REGISTRY_POLICY_CAPTURE_CHANGED')
        return checkpoint
    selected=observe_selected_main(adapter=adapter,store=store,core=core,
        checkpoint_reader=anchored,owner=owner,owner_request_id=owner_request_id,
        validator=validator,expected_merge_sha=selected_main_sha,selected_main_sha=selected_main_sha)
    o=selected['observation'];decision=o['reviewedMerge']['ownerDecision']
    row=core._read(owner_request_id)
    bound=_binding(ref,expected_policy_digest)
    _need(row['fingerprint']==decision['requestFingerprint']
          and row['preview'].get('registryPolicyBinding')==bound,
          'P5_REGISTRY_POLICY_REVIEW_NOT_BOUND')
    material=store.retained_material(decision['captureOperationId'],expected_checkpoint=anchored())
    _need(material['bundle']['schemaVersion']==2 and _hash(material['bundle'])==decision['bundleDigest']
          and material['bundle']['pathCi']['ciPolicyBinding']['policy']==ref['profile'],
          'P5_REGISTRY_POLICY_CAPTURE_MISMATCH')
    capture=_epoch(material['capturedAt']);approved=decision['ownerDecisionAt'];executed=decision['ownerExecutionAt']
    merge=_epoch(o['reviewedMerge']['mergeObservation']['pullRequest']['mergedAt'])
    now=clock();tol=ref['clockToleranceSeconds']
    checks=material['bundle']['pathCi']['ciPolicyBinding']['checks']
    _need(type(now) in (float,int) and 0<now<253402300800 and math.isfinite(now)
          and type(approved) is int and type(executed) is int
          and ref['effectiveAt']<=capture<approved<=executed<merge
          and merge<=now+tol and merge-approved<=ref['maxReviewToMergeSeconds']
          and all(_epoch(c['startedAt'])<=_epoch(c['completedAt'])<=capture for c in checks),
          'P5_REGISTRY_REVIEW_CUTOFF_UNPROVEN')
    _post_consistency(adapter,o,material)
    # Repeat original authority/readback identities, not a mutable PR body
    # as the source of impact. Exact selected main is required through finish.
    if (read_bound_owner_decision(core,owner_request_id,owner=owner)!=decision
        or core._read(owner_request_id)!=row
        or policy_reference(policy_reader,expected_policy_digest)!=ref
        or store.checkpoint(expected=anchored())!=checkpoint):
        raise Stale('P5_REGISTRY_REVIEW_CHANGED')
    branch=adapter._project_branch(adapter._api('GET',adapter._path(PILOT_REPOSITORY,'branches/main')))
    if branch['name']!='main' or branch['sha']!=selected_main_sha:
        raise Stale('P5_REGISTRY_REVIEW_MAIN_CHANGED')
    observation={'repository':REPOSITORY,'policyBinding':bound,'selectedMainSha':selected_main_sha,
                 'ownerRequestId':owner_request_id,'ownerRequestFingerprint':decision['requestFingerprint'],
                 'captureEventDigest':decision['captureEventDigest'],'bundleDigest':decision['bundleDigest'],
                 'captureCheckpoint':checkpoint,'capturedAt':material['capturedAt'],
                 'ownerDecisionAt':approved,'ownerExecutionAt':executed,
                 'mergedAt':o['reviewedMerge']['mergeObservation']['pullRequest']['mergedAt'],
                 'selectedMainObservationDigest':selected['observationDigest'],
                 'ciBindingDigest':o['reviewedMerge']['retainedCiBindingSha256']}
    return selected, {'result':'REGISTRY_REVIEW_POLICY_MATCH_CANDIDATE',
            'observation':observation,'observationDigest':_hash(observation),
            'registryReviewPolicyVerified':False,'registryReviewCutoffVerified':False,
            'historicalPolicyVerified':False,'historicalMergeCutoffVerified':False,
            'evidenceVerified':False,'admissionAllowed':False,'deploymentAllowed':False}

def observe_registry_review(**kwargs):
    """Preserve the standalone candidate projection; collect the pair once."""
    return _observe_registry_review_pair(**kwargs)[1]

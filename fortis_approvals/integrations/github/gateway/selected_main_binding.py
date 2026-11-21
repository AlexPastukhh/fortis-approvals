"""Conservative one-merge P5 observation, not a Registry admission envelope.

Owner composition supplies the protected store/Core/provider and pinned
validator/object store. This source has no ingress, grant or write authority.
"""
import hashlib
from pathlib import Path
import tempfile

from ....core import Denied, Stale
from ....workflow.common import Git
from ..post_merge_git_lineage import _read_commit
from ..post_merge_registry_envelope import EvidenceEnvelopeError
from .p5_ci_binding import policy
from .premerge_bundle import observe_reviewed_merge
from .review_capture import _hash, _hex, _need


def _commit(git, repository, sha):
    _need(_hex(sha,40), 'P5_SELECTED_COMMIT_INVALID')
    raw = git.run(['--no-replace-objects','cat-file','commit',sha],cwd=repository)[1]
    _need(0<len(raw)<=64000,'P5_SELECTED_COMMIT_INVALID')
    try:
        return _read_commit({'sha':sha,'rawHex':raw.hex()})
    except EvidenceEnvelopeError:
        raise Denied('P5_SELECTED_COMMIT_INVALID') from None


def observe_selected_main(*, adapter, store, core, checkpoint_reader,
                          owner, owner_request_id, validator,
                          expected_merge_sha, selected_main_sha):
    """Bind a v2 reviewed bundle to identical HEAD/merge tree and local graph.

    An exact tip merge only. No attribution of later commits or cross-repo
    dependencies; no mutable checkout or caller-supplied evidence assertions.
    """
    _need(_hex(selected_main_sha,40) and selected_main_sha==expected_merge_sha,
          'P5_SELECTED_MAIN_MUST_BE_EXACT_MERGE')
    checkpoint=checkpoint_reader()

    def anchored():
        if checkpoint_reader()!=checkpoint:
            raise Stale('P5_SELECTED_CHECKPOINT_CHANGED')
        return checkpoint

    def reviewed():
        return observe_reviewed_merge(adapter=adapter,store=store,core=core,
            checkpoint_reader=anchored,owner=owner,owner_request_id=owner_request_id,
            expected_merge_sha=expected_merge_sha,selected_main_sha=selected_main_sha)

    review=reviewed()
    value=review['observation'];decision=value['ownerDecision']
    capture_id=decision['captureOperationId']
    retained=store.retained_material(capture_id,expected_checkpoint=anchored())
    bundle=retained['bundle']
    _need(bundle['schemaVersion']==2,'P5_SELECTED_V2_BUNDLE_REQUIRED')
    binding=bundle['pathCi']['ciPolicyBinding']
    _need(binding['policy']==policy() and binding['policySha256']==_hash(binding['policy'])
          and binding['policySha256']==value['retainedCiPolicySha256']
          and _hash(binding)==value['retainedCiBindingSha256'],
          'P5_SELECTED_POLICY_PIN_MISMATCH')
    provider=value['mergeObservation']
    base,head=retained['baseSha'],decision['headSha']
    paths=bundle['pathCi']['paths']
    _need(paths['mergeBaseSha']==base,'P5_SELECTED_DIVERGED_BASE_UNSUPPORTED')

    with tempfile.TemporaryDirectory(dir=validator.state,prefix='p5-selected-') as folder:
        git=Git(Path(folder)/'git')
        merge_object=_commit(git,validator.source,expected_merge_sha)
        head_object=_commit(git,validator.source,head)
        base_object=_commit(git,validator.source,base)
        _need(provider['firstParent']==[merge_object]
              and provider['headCommit']==head_object
              and merge_object['parents']==[base,head]
              and merge_object['treeSha']==head_object['treeSha'],
              'P5_SELECTED_MERGE_TREE_MISMATCH')
        _need(git.text(['--no-replace-objects','merge-base','--all',base,head],
                       cwd=validator.source)==base,'P5_SELECTED_DIVERGED_BASE_UNSUPPORTED')
        # The validator below materializes every regular HEAD blob. A source
        # workflow projection alone is insufficient: check its raw Git bytes
        # against the fixed reviewed policy as well.
        for w in binding['policy']['workflows']:
            raw=git.run(['--no-replace-objects','cat-file','blob',head+':'+w['path']],
                        cwd=validator.source)[1]
            _need(0<len(raw)<=65536 and hashlib.sha256(raw).hexdigest()==w['sha256'],
                  'P5_SELECTED_WORKFLOW_BYTES_MISMATCH')

    validated=validator.validate_retained(store=store,operation_id=capture_id,
                                          checkpoint_reader=anchored)
    impact=validated['observation']
    _need(impact['repository']==provider['repository']==decision['repository']
          and impact['number']==decision['number']
          and impact['headSha']==head and impact['baseSha']==base
          and impact['captureEventDigest']==decision['captureEventDigest']
          and impact['bundleDigest']==value['bundleDigest']==decision['bundleDigest']
          and impact['catalogSha256']==provider['catalog']['contentSha256']
          and impact['changedPathRecordsSha256']==paths['sha256']
          and impact['impactSha256']==bundle['impactSha256']
          and validated['observationDigest']==_hash(impact),
          'P5_SELECTED_IMPACT_BINDING_MISMATCH')
    deps=impact['dependencyObservation']
    _need(impact['dependencyObservationSha256']==_hash(deps)
          and deps['catalogHeadSha']==head and deps['repository']==impact['repository']
          and deps['catalogSha256']==impact['catalogSha256']
          and all(e['sourceSha']==head and e['repository']==impact['repository']
                  for e in deps['localDependencyEdges']), 'P5_SELECTED_DEPENDENCY_BINDING_MISMATCH')
    # Equal complete tree identity permits these local source versions only.
    local=[{**e,'sourceSha':selected_main_sha} for e in deps['localDependencyEdges']]
    if reviewed()!=review or store.checkpoint(expected=anchored())!=checkpoint:
        raise Stale('P5_SELECTED_OBSERVATION_CHANGED')
    observation={'repository':impact['repository'],'number':impact['number'],
                 'selectedMainSha':selected_main_sha,'treeSha':merge_object['treeSha'],
                 'rawCommitBindingSha256':_hash([base_object,head_object,merge_object]),
                 'reviewedMerge':value,'reviewedMergeSha256':review['observationDigest'],
                 'retainedImpact':impact,'retainedImpactSha256':validated['observationDigest'],
                 'selectedMainLocalDependencies':local,
                 'unresolvedExternalTargets':deps['graph']['unresolvedExternalTargets'],
                 'unresolvedPullRequests':deps['graph']['unresolvedPullRequests']}
    return {'result':'SELECTED_MAIN_LOCAL_SOURCE_BOUND','observation':observation,
            'observationDigest':_hash(observation),
            'historicalPolicyVerified':False,'historicalMergeCutoffVerified':False,
            'dependencyClosureVerified':False,'componentBindingsVerified':False,
            'evidenceVerified':False,'admissionAllowed':False,'deploymentAllowed':False,
            'missingProofs':['HISTORICAL_EFFECTIVE_POLICY_AND_MERGE_CUTOFF',
                'CROSS_REPOSITORY_AND_PR_DEPENDENCY_CLOSURE',
                'OWNER_COMPONENT_ENVIRONMENT_BINDINGS','PROTECTED_COLLECTOR_AND_RECOVERY']}

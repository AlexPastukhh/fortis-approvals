"""Forward-only P5 candidate coverage. No enrollment or admission authority.

Host composition pins an immutable baseline reference and independent reader;
the referenced acceptance and bindings are NOT validated by this module.
No earlier PR reads, mutable body reconstruction, or cursor advancement.
"""
import hashlib
from pathlib import Path
import tempfile

from ....core import Denied, Stale, canonical, loads_strict
from ....workflow.common import Git
from .collector_snapshot import REPOSITORY, _source
from .post_merge_reader import PILOT_REPOSITORY
from .review_capture import _hash, _hex, _need, _uuid
from .selected_main_binding import _commit

MAX_MERGES=64
CURSOR_FIELDS={'checkpoint','candidateCursor','evidenceVerified','admissionAllowed'}
BASELINE_FIELDS={'schemaVersion','enrollmentId','repository','baselineSha',
                 'catalogSha256','acceptanceReceiptDigest','bindingDigest'}


def _baseline(reader, pin):
    _need(_hex(pin,64),'P5_BASELINE_PIN_INVALID')
    try:
        value=reader()
        _need(type(value) is dict and set(value)==BASELINE_FIELDS
              and type(value['schemaVersion']) is int and value['schemaVersion']==1
              and value['repository']==REPOSITORY
              and _uuid(value['enrollmentId']) and _hex(value['baselineSha'],40)
              and all(_hex(value[k],64) for k in ('catalogSha256','acceptanceReceiptDigest','bindingDigest'))
              and _hash(value)==pin,'P5_BASELINE_REFERENCE_MISMATCH')
        return loads_strict(canonical(value))
    except Denied:
        raise
    except Exception:
        raise Denied('P5_BASELINE_REFERENCE_INVALID') from None


def _registry_cursor(reader, baseline, baseline_digest, policy_digest):
    """Read the exact Registry journal cursor, never caller-selected SHA.

    Schemas 1/2 use an independent checkpoint. Functional source schema 3
    exposes a *local event-chain head only*. It is valid for candidate
    planning, NEVER owner acceptance, protected rollback verification or
    admission. Do not accept a generic wrapper or a fake checkpoint reader.
    """
    from ...registry.candidate_gateway import PinnedRegistryCursor
    owner=getattr(reader,'__self__',None)
    method=getattr(reader,'__func__',None)
    remote=(type(owner) is PinnedRegistryCursor and method is PinnedRegistryCursor.checkpoint)
    if remote:
        local=True
    else:
        # These offline schema classes are NOT packaged in the Gateway image.
        from ....registry.state_journal import RegistryStateJournal
        from ....registry.state_journal_v2 import RegistryStateJournalV2
        from ....registry.functional_v1_journal import FunctionalV1CandidateJournal
        local=(type(owner) is FunctionalV1CandidateJournal and
               method is FunctionalV1CandidateJournal.checkpoint)
        _need(local or
              (type(owner) is RegistryStateJournal and
               method is RegistryStateJournal.checkpoint) or
              (type(owner) is RegistryStateJournalV2 and
               method is RegistryStateJournalV2.checkpoint),
              'P5_FORWARD_CURSOR_READER_REQUIRED')
    scope={'repository':REPOSITORY,'enrollmentId':baseline['enrollmentId'],
           'baselineSha':baseline['baselineSha'],'baselineDigest':baseline_digest,
           'catalogSha256':baseline['catalogSha256'],'bindingDigest':baseline['bindingDigest'],
           'policyReferenceDigest':policy_digest}
    _need(reader.__self__.scope==scope,'P5_FORWARD_CURSOR_SCOPE_MISMATCH')
    try:
        ref=reader()
        if local:
            _need(type(ref) is dict and set(ref)=={
                'result','localCheckpoint','candidateCursor','integrityModel',
                'evidenceVerified','admissionAllowed','deploymentAllowed'}
                and ref['result']=='LOCAL_SOURCE_CANDIDATE_HEAD'
                and ref['integrityModel']=='LOCAL_EVENT_CHAIN_ONLY'
                and ref['deploymentAllowed'] is False,
                'P5_FORWARD_LOCAL_CURSOR_INVALID')
            # Schema 3's strictly owned LOCAL checkpoint is normalized only
            # for source-plan schema compatibility. NOT a witnessed anchor.
            ref={'checkpoint':ref['localCheckpoint'],
                 'candidateCursor':ref['candidateCursor'],
                 'evidenceVerified':ref['evidenceVerified'],
                 'admissionAllowed':ref['admissionAllowed']}
        _need(type(ref) is dict and set(ref)==CURSOR_FIELDS
              and ref['evidenceVerified'] is False and ref['admissionAllowed'] is False
              and _hex(ref['candidateCursor'],40),'P5_FORWARD_CURSOR_INVALID')
        cp=ref['checkpoint']
        _need(type(cp) is dict
              and set(cp)=={'schemaVersion','instanceId','scopeDigest','revision','eventDigest'}
              and type(cp['schemaVersion']) is int and cp['schemaVersion']==1
              and _uuid(cp['instanceId']) and cp['scopeDigest']==_hash(scope)
              and type(cp['revision']) is int and 1<=cp['revision']<=2**63-1
              and _hex(cp['eventDigest'],64),'P5_FORWARD_CURSOR_INVALID')
        return loads_strict(canonical(ref))
    except Denied:
        raise
    except Exception:
        raise Denied('P5_FORWARD_CURSOR_UNAVAILABLE') from None


# Recovery is limited to the exact interval for this pilot.
_CUTOVER_BASELINE = 'd27b2cab342521239d1ba7745c4ee4b8d70e66d9'
_CUTOVER_253 = {
    'number': 253,
    'headSha': '8f29a4c754c40ccadf2e53550f7415dbfad048a0',
    'mergeSha': '9bdb42b2cdaa0c24b942ff75d18111e59eebb51b',
    'impact': {'gateway-owner-controller': ['windows-update']},
}
_CUTOVER_RECOVERY_IMPACT = {
    'fortis-gateway': ['image-rebuild'],
    'fortis-registry-pilot': ['image-rebuild'],
    # Release Impact's conservative GitHub source glob also covers the publisher.
    'release-label-publisher': ['image-rebuild'],
}


def cutover_start(gap, baseline_sha):
    """Validate the owner-sealed two-merge interval before checking Git."""
    _need(baseline_sha == _CUTOVER_BASELINE and type(gap) is dict
          and set(gap) == {'disposition', 'merges'}
          and gap['disposition'] == 'OWNER_REVIEWED_PRE_CAPTURE_GAP'
          and type(gap['merges']) is list and len(gap['merges']) == 2
          and gap['merges'][0] == _CUTOVER_253, 'P5_CUTOVER_GAP_SCOPE')
    recovery = gap['merges'][1]
    _need(type(recovery) is dict and set(recovery) == set(_CUTOVER_253)
          and type(recovery['number']) is int and recovery['number'] > 253
          and _hex(recovery['headSha'], 40) and _hex(recovery['mergeSha'], 40)
          and recovery['impact'] == _CUTOVER_RECOVERY_IMPACT,
          'P5_CUTOVER_GAP_SCOPE')
    return recovery['mergeSha']


def verify_cutover_commits(gap, baseline, git, repository):
    start = cutover_start(gap, baseline['baselineSha'])
    parent = baseline['baselineSha']
    for row in gap['merges']:
        node = _commit(git, repository, row['mergeSha'])
        head = _commit(git, repository, row['headSha'])
        _need(node['parents'] == [parent, row['headSha']]
              and head['parents'] == [parent]
              and node['treeSha'] == head['treeSha'], 'P5_CUTOVER_GAP_LINEAGE')
        raw = git.run(['--no-replace-objects', 'cat-file', 'blob',
                       row['mergeSha'] + ':release/targets.yaml'], cwd=repository)[1]
        _need(0 < len(raw) <= 120_000 and hashlib.sha256(raw).hexdigest() ==
              baseline['catalogSha256'], 'P5_CUTOVER_GAP_CATALOG')
        parent = row['mergeSha']
    return start


def observe_forward_lineage(*, adapter, journal, validator, baseline_reader,
                            expected_baseline_digest, selected_main_sha, evidence_ids,
                            policy_reader=None, expected_policy_digest=None,
                            cursor_reader=None, cutover_gap=None):
    """Check every first-parent node from a pinned enrollment source to main.

    Earlier tip captures must already exist in the anchored journal. The
    caller cannot supply evidence payloads, a replacement baseline or a
    claimed coverage checkpoint. Catalog continuity is deliberately strict
    in this first pilot (unchanged bytes); remapping needs a later verifier.
    """
    _need(_hex(selected_main_sha,40) and type(evidence_ids) is list
          and len(evidence_ids)<=MAX_MERGES and all(_uuid(e) for e in evidence_ids)
          and len(set(evidence_ids))==len(evidence_ids),'P5_FORWARD_REQUEST_INVALID')
    baseline=_baseline(baseline_reader,expected_baseline_digest)
    bound=policy_reader is not None or expected_policy_digest is not None
    if bound:
        from .registry_review_policy import policy_reference
        _need(callable(policy_reader) and _hex(expected_policy_digest,64),'P5_FORWARD_POLICY_REQUEST_INVALID')
        policy_ref=policy_reference(policy_reader,expected_policy_digest)
        _need(all(policy_ref[k]==baseline[k] for k in
                  ('repository','enrollmentId','baselineSha','acceptanceReceiptDigest')),
              'P5_FORWARD_POLICY_BASELINE_MISMATCH')
    _need(cutover_gap is None or (bound and cursor_reader is None),
          'P5_CUTOVER_GAP_INITIAL_ONLY')
    if cursor_reader is not None:
        _need(bound and callable(cursor_reader),'P5_FORWARD_CURSOR_POLICY_REQUIRED')
        cursor_ref=_registry_cursor(cursor_reader,baseline,expected_baseline_digest,expected_policy_digest)
        start_sha=cursor_ref['candidateCursor']
    else:
        cursor_ref=None
        start_sha=(baseline['baselineSha'] if cutover_gap is None else
                   cutover_start(cutover_gap, baseline['baselineSha']))
    repo=adapter._repo(PILOT_REPOSITORY)
    _need(adapter.owner+'/'+repo==REPOSITORY,'P5_FORWARD_SCOPE_DENIED')

    def check_main():
        branch=adapter._project_branch(adapter._api('GET',adapter._path(repo,'branches/main')))
        if branch['name']!='main' or branch['sha']!=selected_main_sha:
            raise Stale('P5_FORWARD_MAIN_CHANGED')

    check_main()
    batch=journal.anchored_batch(evidence_ids)
    checkpoint=batch['checkpoint']
    entries=batch['entries']
    _need(len(entries)==len(evidence_ids),'P5_FORWARD_EVIDENCE_SET_MISMATCH')
    by_merge={};numbers=set();owners=set()
    for eid,entry in zip(evidence_ids,entries):
        snapshot,receipt=entry['snapshot'],entry['receipt']
        o=snapshot['result']['observation'];merge=o['selectedMainSha']
        decision=o['reviewedMerge']['ownerDecision']
        req={'evidenceId':eid,'selectedMainSha':merge,'ownerRequestId':decision['requestId']}
        if bound:
            _need(snapshot.get('schemaVersion')==2
                  and snapshot.get('registryPolicy')==policy_ref
                  and receipt.get('policyReferenceDigest')==expected_policy_digest
                  and receipt.get('registryReviewDigest')==snapshot.get('registryReview',{}).get('observationDigest'),
                  'P5_FORWARD_POLICY_EVIDENCE_REQUIRED')
            req['policyReferenceDigest']=expected_policy_digest
        else:
            # Explicit mode separation: no silent downgrade of v2 evidence.
            _need(snapshot.get('schemaVersion')==1 and 'policyReferenceDigest' not in receipt,
                  'P5_FORWARD_POLICY_MODE_REQUIRED')
        _source(snapshot,req)
        _need(receipt['result']=='ANCHORED_CANDIDATE_EVIDENCE_RETAINED'
              and receipt['repository']==REPOSITORY and receipt['evidenceId']==eid
              and receipt['evidenceDigest']==_hash(snapshot)
              and receipt['selectedMainSha']==merge
              and receipt['ownerRequestId']==decision['requestId']
              and receipt['checkpoint']['instanceId']==checkpoint['instanceId']
              and 0<receipt['checkpoint']['revision']<=checkpoint['revision']
              and all(receipt[k] is False for k in ('evidenceVerified','admissionAllowed','deploymentAllowed')),
              'P5_FORWARD_RECEIPT_MISMATCH')
        _need(merge not in by_merge and o['number'] not in numbers
              and decision['requestId'] not in owners,'P5_FORWARD_DUPLICATE_ATTRIBUTION')
        by_merge[merge]=(o,receipt);numbers.add(o['number']);owners.add(decision['requestId'])

    origin=start_sha;cursor=selected_main_sha
    newest=[];seen=set()
    with tempfile.TemporaryDirectory(dir=validator.state,prefix='p5-forward-') as folder:
        git=Git(Path(folder)/'git')
        base_object=_commit(git,validator.source,baseline['baselineSha'])
        if cutover_gap is not None:
            verify_cutover_commits(cutover_gap, baseline, git, validator.source)
        start_object=base_object if origin==baseline['baselineSha'] else _commit(git,validator.source,origin)
        raw=git.run(['--no-replace-objects','cat-file','blob',baseline['baselineSha']+':release/targets.yaml'],
                    cwd=validator.source)[1]
        _need(0<len(raw)<=120_000 and hashlib.sha256(raw).hexdigest()==baseline['catalogSha256'],
              'P5_BASELINE_CATALOG_MISMATCH')
        del raw
        while cursor!=origin:
            _need(cursor not in seen and len(newest)<MAX_MERGES,'P5_FORWARD_LINEAGE_BOUND')
            seen.add(cursor)
            node=_commit(git,validator.source,cursor)
            _need(len(node['parents'])==2,'P5_FORWARD_UNATTRIBUTED_NON_MERGE')
            _need(cursor in by_merge,'P5_FORWARD_MISSING_MERGE_EVIDENCE')
            o,receipt=by_merge[cursor]
            review=o['reviewedMerge'];provider=review['mergeObservation'];pr=provider['pullRequest']
            impact=o['retainedImpact'];parent,head=node['parents']
            head_object=_commit(git,validator.source,head)
            parent_object=_commit(git,validator.source,parent)
            _need(provider['firstParent']==[node] and provider['headCommit']==head_object
                  and pr['mergeSha']==cursor and pr['headSha']==head
                  and pr['baseSha']==parent and impact['baseSha']==parent
                  and impact['headSha']==head and node['treeSha']==head_object['treeSha']==o['treeSha']
                  and o['rawCommitBindingSha256']==_hash([parent_object,head_object,node]),
                  'P5_FORWARD_MERGE_BINDING_MISMATCH')
            raw=git.run(['--no-replace-objects','cat-file','blob',cursor+':release/targets.yaml'],
                        cwd=validator.source)[1]
            _need(0<len(raw)<=120_000 and hashlib.sha256(raw).hexdigest()==
                  impact['catalogSha256']==provider['catalog']['contentSha256']==baseline['catalogSha256'],
                  'P5_FORWARD_CATALOG_CHANGE_UNSUPPORTED')
            # A retained receipt is evidence of observation, not admission.
            _need(not o['unresolvedExternalTargets'] and not o['unresolvedPullRequests'],
                  'P5_FORWARD_UNRESOLVED_DEPENDENCY')
            newest.append({'mergeSha':cursor,'baseSha':parent,'headSha':head,
                           'number':o['number'],'treeSha':node['treeSha'],
                           'evidenceId':receipt['evidenceId'],'evidenceDigest':receipt['evidenceDigest'],
                           'ownerRequestId':receipt['ownerRequestId'],
                           'collectorCheckpoint':receipt['checkpoint']})
            if bound:
                newest[-1].update(registryReviewDigest=receipt['registryReviewDigest'],
                                  policyReferenceDigest=expected_policy_digest)
            cursor=parent
    _need(seen==set(by_merge),'P5_FORWARD_UNUSED_EVIDENCE')
    _need(all(a['collectorCheckpoint']['revision']>b['collectorCheckpoint']['revision']
              for a,b in zip(newest,newest[1:])),'P5_FORWARD_CAPTURE_ORDER_MISMATCH')
    if journal.anchored_batch(evidence_ids)!=batch or _baseline(
            baseline_reader,expected_baseline_digest)!=baseline:
        raise Stale('P5_FORWARD_CHECKPOINT_CHANGED')
    if bound and policy_reference(policy_reader,expected_policy_digest)!=policy_ref:
        raise Stale('P5_FORWARD_POLICY_CHANGED')
    if cursor_ref is not None and _registry_cursor(cursor_reader,baseline,
            expected_baseline_digest,expected_policy_digest)!=cursor_ref:
        raise Stale('P5_FORWARD_CURSOR_CHANGED')
    check_main()
    observation={'repository':REPOSITORY,'enrollmentId':baseline['enrollmentId'],
                 'baselineSha':baseline['baselineSha'],'baselineDigest':expected_baseline_digest,
                 'baselineTreeSha':base_object['treeSha'],'selectedMainSha':selected_main_sha,
                 'catalogSha256':baseline['catalogSha256'],'collectorCheckpoint':checkpoint,
                 'merges':list(reversed(newest))}
    if cutover_gap is not None:
        observation['cutoverGap'] = cutover_gap
    if bound:
        observation['policyReferenceDigest']=expected_policy_digest
    if cursor_ref is not None:
        observation.update(startCursorSha=start_sha,startCursorTreeSha=start_object['treeSha'],
                           registryCursorCheckpoint=cursor_ref['checkpoint'])
    return {'result':'FORWARD_SOURCE_COVERAGE_MATCH_CANDIDATE',
            'observation':observation,'observationDigest':_hash(observation),
            'baselineAcceptanceVerified':False,'sourceCoverageVerified':False,
            'historicalPolicyVerified':False,'historicalMergeCutoffVerified':False,
            'dependencyClosureVerified':False,'componentBindingsVerified':False,
            'evidenceVerified':False,'admissionAllowed':False,'deploymentAllowed':False}

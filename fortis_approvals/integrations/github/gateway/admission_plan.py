"""P5 combined initial-range planning candidate. Not a Registry writer.

All material is read through existing internal composed dependencies; no
caller-supplied plan, completeness flags, actions or component IDs.
Only initial range from enrollment baseline, no cursor advance or authority.
"""
from ....core import Denied, Stale
from .collector_snapshot import REPOSITORY
from .component_bindings import _observe_component_pair, _mapping
from .forward_lineage import _baseline
from .registry_review_policy import policy_reference
from .review_capture import _hash, _hex, _need

_ACTIONS={'image-rebuild','config-deploy','windows-update','package-build','migration-required'}


def _requirements(impact, catalog):
    """Recompute reachable source requirements, not installed dependencies."""
    graph=impact['dependencyObservation']['graph'];validated=impact['validatedImpact']
    targets={t['id']:t for t in catalog['targets']}
    roots=sorted(t['id'] for t in validated['declaredTargets'])
    explicit=graph['explicitTargets']
    _need(graph==validated['dependencyGraph'] and not graph['unresolvedExternalTargets']
          and not graph['unresolvedPullRequests'] and validated['pullRequestDependencies']==[]
          and graph['declaredRoots']==roots,'P5_PLAN_DEPENDENCY_UNRESOLVED')
    _need(type(explicit) is list and len(explicit)<=50
          and all(type(x) is dict and set(x)=={'repository','target'}
                  and x['repository']=='fortis-approvals' and x['target'] in targets for x in explicit),
          'P5_PLAN_DEPENDENCY_UNRESOLVED')
    extras={x['target'] for x in explicit}
    _need(len(extras)==len(explicit),'P5_PLAN_DEPENDENCY_GRAPH_MISMATCH')
    visited=set();active=set();edges=set()
    def visit(t):
        _need(t in targets and t not in active,'P5_PLAN_DEPENDENCY_GRAPH_MISMATCH')
        if t in visited:return
        active.add(t)
        for dep in targets[t].get('dependsOn',[]):
            _need(dep['repository']=='fortis-approvals','P5_PLAN_DEPENDENCY_UNRESOLVED')
            edges.add((t,dep['target']))
            _need(len(edges)<=256,'P5_PLAN_DEPENDENCY_GRAPH_MISMATCH')
            visit(dep['target'])
        active.remove(t);visited.add(t)
    for t in sorted(set(roots)|extras):visit(t)
    local=sorted(extras|{b for _,b in edges})
    _need(graph['localTargets']==sorted(visited) and graph['localDependencyTargets']==local
          and graph['catalogEdges']==[{'fromTarget':a,'repository':'fortis-approvals','target':b} for a,b in sorted(edges)]
          and graph['explicitTargets']==[{'repository':'fortis-approvals','target':t} for t in sorted(extras)]
          and impact['dependencyObservationSha256']==_hash(impact['dependencyObservation'])
          and impact['dependencyObservation']['unresolvedRequirements'] is False,
          'P5_PLAN_DEPENDENCY_GRAPH_MISMATCH')
    # Direct declared dependencies from the existing validator protocol.
    direct=extras|{b for a,b in edges if a in roots}
    _need(validated['targetDependencies']==[{'repository':'fortis-approvals','target':t} for t in sorted(direct)],
          'P5_PLAN_DEPENDENCY_GRAPH_MISMATCH')
    return local


def _derive(lineage, mapping, catalog, batch):
    """Deterministic internal projection of a previously checked source range."""
    lo=lineage['observation'];mo=mapping['observation']
    src=lo['selectedMainSha'];bindings={b['targetId']:b for b in mo['bindings']}
    entries={e['receipt']['evidenceId']:e for e in batch['entries']}
    _need(len(entries)==len(batch['entries'])==len(lo['merges'])
          and batch['checkpoint']==lo['collectorCheckpoint']==mo['collectorCheckpoint'],
          'P5_PLAN_BATCH_MISMATCH')
    actions={};sources={};requirements=set();audit=[]
    for merge in lo['merges']:
        eid=merge['evidenceId']
        _need(eid in entries,'P5_PLAN_BATCH_MISMATCH')
        row=entries[eid];snap=row['snapshot'];receipt=row['receipt']
        _need(_hash(snap)==merge['evidenceDigest']==receipt['evidenceDigest']
              and receipt['checkpoint']==merge['collectorCheckpoint']
              and receipt['ownerRequestId']==merge['ownerRequestId']
              and receipt['registryReviewDigest']==merge['registryReviewDigest']
              and receipt['policyReferenceDigest']==lo['policyReferenceDigest']
              and receipt['selectedMainSha']==merge['mergeSha'],'P5_PLAN_BATCH_MISMATCH')
        o=snap['result']['observation'];impact=o['retainedImpact'];v=impact['validatedImpact']
        _need(o['repository']==REPOSITORY and o['selectedMainSha']==merge['mergeSha']
              and o['number']==merge['number'] and impact['catalogSha256']==lo['catalogSha256']
              and _hash(impact)==o['retainedImpactSha256'],'P5_PLAN_IMPACT_MISMATCH')
        declared=v['declaredTargets'];ids=[t['id'] for t in declared]
        _need(type(declared) is list and len(ids)==len(set(ids)) and set(ids)<=bindings.keys()
              and set(v['affectedTargets'])<=set(ids)
              and v['classification'] in ('deployment','no-deployment')
              and bool(ids)==(v['classification']=='deployment'),'P5_PLAN_IMPACT_MISMATCH')
        local=_requirements(impact,catalog)
        expected=[{'repository':REPOSITORY,'target':t,'sourceSha':merge['mergeSha']} for t in local]
        _need(o['selectedMainLocalDependencies']==expected,'P5_PLAN_DEPENDENCY_GRAPH_MISMATCH')
        requirements.update(local)
        audit.append({**merge,'impactDigest':o['retainedImpactSha256'],
                      'classification':v['classification'],'sourceDependencyTargets':local})
        for t in declared:
            aa=t['actions']
            _need(type(aa) is list and aa and len(set(aa))==len(aa)
                  and set(aa)<=_ACTIONS,'P5_PLAN_ACTION_INVALID')
            actions.setdefault(t['id'],set()).update(aa)
            sources.setdefault(t['id'],[]).append(eid)
    candidates=[]
    for target in sorted(actions):
        b=bindings[target]
        subject={'repository':REPOSITORY,'targetId':target,'environment':b['environment']}
        identity={**subject,'desiredSourceSha':src,'catalogCommitSha':lo['baselineSha'],
                  'catalogSha256':lo['catalogSha256']}
        candidates.append({'subjectId':_hash(subject),'recordId':_hash(identity),'identity':identity,
                           'componentId':b['componentId'],'resourceIds':b['resourceIds'],
                           'requiresComponentIds':b['requiresComponentIds'],
                           'buildUnitId':b['buildUnit'],'deploymentProcedure':b['deployment']['procedure'],
                           'verification':b['verification'],'requiredActions':sorted(actions[target]),
                           'evidenceIds':sources[target],'artifact':{'state':'NOT_BUILT','digest':None},
                           'actual':None,'planningState':'PLANNED_UNVERIFIED','evidenceVerified':False})
    return {'rangeClassification':('EMPTY_RANGE' if not audit else
                                  'DEPLOYMENT_CANDIDATE' if candidates else 'NO_DEPLOYMENT_CANDIDATE'),
            'mergeAudit':audit,'recordCandidates':candidates,
            'sourceDependencyRequirements':[{'repository':REPOSITORY,'targetId':t,
                'environment':bindings[t]['environment'],'sourceSha':src,'actual':None}
                for t in sorted(requirements)]}


def observe_initial_plan(*,adapter,journal,validator,baseline_reader,expected_baseline_digest,
                         selected_main_sha,evidence_ids,policy_reader,expected_policy_digest,binding_reader):
    """Compose only the initial complete range; no arbitrary caller plan DTO."""
    mapping,lineage,catalog,baseline=_observe_component_pair(
        adapter=adapter,journal=journal,validator=validator,baseline_reader=baseline_reader,
        expected_baseline_digest=expected_baseline_digest,selected_main_sha=selected_main_sha,
        evidence_ids=evidence_ids,policy_reader=policy_reader,
        expected_policy_digest=expected_policy_digest,binding_reader=binding_reader)
    o=mapping['observation'];lo=lineage['observation']
    _need(o['lineageDigest']==_hash(lo)==lineage['observationDigest']
          and o['catalogProjectionSha256']==_hash(catalog)
          and _hash(o)==mapping['observationDigest'],'P5_PLAN_COMPOSITION_MISMATCH')
    batch=journal.anchored_batch(evidence_ids)
    derived=_derive(lineage,mapping,catalog,batch)
    if (journal.anchored_batch(evidence_ids)!=batch
        or _baseline(baseline_reader,expected_baseline_digest)!=baseline
        or _hash(_mapping(binding_reader,baseline))!=o['bindingDigest']
        or _hash(policy_reference(policy_reader,expected_policy_digest))!=expected_policy_digest):
        raise Stale('P5_PLAN_REFERENCE_CHANGED')
    branch=adapter._project_branch(adapter._api('GET',adapter._path('fortis-approvals','branches/main')))
    if branch['name']!='main' or branch['sha']!=selected_main_sha:
        raise Stale('P5_PLAN_MAIN_CHANGED')
    observation={'repository':REPOSITORY,'enrollmentId':baseline['enrollmentId'],
                 'baselineDigest':expected_baseline_digest,'baselineSha':baseline['baselineSha'],
                 'selectedMainSha':selected_main_sha,'catalogSha256':baseline['catalogSha256'],
                 'policyReferenceDigest':expected_policy_digest,'bindingDigest':baseline['bindingDigest'],
                 'collectorCheckpoint':lo['collectorCheckpoint'],'lineageDigest':lineage['observationDigest'],
                 'componentObservationDigest':mapping['observationDigest'],
                 **derived}
    return {'result':'INITIAL_RANGE_PLAN_CANDIDATE','observation':observation,
            'observationDigest':_hash(observation),'evidenceVerified':False,
            'admissionAllowed':False,'deploymentAllowed':False,
            'missingProofs':['PROTECTED_ENROLLMENT_AND_RESOURCE_ATTESTATION',
                             'AUTHENTICATED_COLLECTOR_AND_TRUSTED_CLOCK',
                             'PROTECTED_REGISTRY_STATE_AND_RECOVERY']}

"""Stateless bounded release planning over one consistent Registry snapshot.

No saved Batch, deployment approval, fabricated compatibility, or source
retargeting. The current legacy-only source transition is always UNKNOWN.
"""
from ..integrations.registry_contracts import semantic_contract as sc
from .release_domain import key, _overlap, dependency_check


def plan(view, items, *, visible):
    selected = {key(i['subject']):i for i in items}
    states, profiles = view['states'], view['profiles']
    checks = []
    groups = {}
    targets = []
    conflicts = []
    order = []
    visited, visiting = set(), set()

    def check(code, status, subject=None):
        checks.append({'code':code,'status':status,'subject':subject})

    def visit(k):
        if k in visiting:
            check('DEPENDENCY_CYCLE','FAIL')
            return
        if k in visited:
            return
        visiting.add(k)
        if k not in profiles or not visible(profiles[k]['subject']):
            check('DEPENDENCY_UNAVAILABLE','UNKNOWN')
        else:
            p = profiles[k]
            if p['unresolvedDependencies']:
                check('DEPENDENCY_UNAVAILABLE','UNKNOWN',p['subject'])
            dependencies={key(dep) for dep in p['dependencies']}
            for requirement in states[k].get('sourceRequirements',()):
                matches=[dk for dk,candidate in profiles.items()
                         if candidate['subject']['repository']==requirement['repository']
                         and candidate['subject']['targetId']==requirement['targetId']]
                if len(matches)==1:
                    dependencies.add(matches[0])
                else:
                    check('SOURCE_DEPENDENCY_COMPATIBILITY','UNKNOWN',p['subject'])
            for dk in sorted(dependencies):
                visit(dk)
                if dk in states and visible(states[dk]['subject']):
                    state=states[dk]
                    status=dependency_check(state)
                    if (status!='PASS' and dk in selected and state['desired'] is not None
                            and state['desired'].get('evidenceVerified') is True):
                        check('DEPENDENCY_RELEASE_FIRST','REQUIRED',state['subject'])
                    else:
                        check('DEPENDENCY_COMPATIBILITY',status,state['subject'])
            if k in selected:
                order.append(selected[k]['subject'])
        visiting.remove(k)
        visited.add(k)

    for k,item in selected.items():
        sc.need(k in states and states[k]['subject'] == item['subject'] and visible(item['subject']),
                'REGISTRY_SEMANTIC_SCOPE_DENIED')
        st,p = states[k],profiles[k]
        desired = st['desired']
        check('EXACT_DESIRED_SOURCE',
              'UNKNOWN' if desired is None else 'PASS' if item['source']==desired['source'] else 'STALE',
              item['subject'])
        if desired is not None and desired.get('evidenceVerified') is False:
            check('SOURCE_EVIDENCE_ADMISSION','UNKNOWN',item['subject'])
        if view.get('catalogSha256') is not None:
            check('CATALOG_EPOCH','PASS' if item['source']['catalogSha256']==view['catalogSha256']
                  else 'UNKNOWN',item['subject'])
        if not p['deployable']:
            check('NONDEPLOYABLE_TARGET','FAIL',item['subject'])
        check('MAINTENANCE_CLASSIFICATION','UNKNOWN' if p['maintenance'] is None else 'PASS',item['subject'])
        if st['activeAttempt'] is not None:
            check('ACTIVE_ATTEMPT','FAIL',item['subject'])
        else:
            check('ACTIVE_ATTEMPT','PASS',item['subject'])
        if p['maintenance'] is not None:
            for other, state in states.items():
                if state['activeAttempt'] is not None and other != k and (
                        profiles[other]['maintenance'] is None or _overlap(p, profiles[other])):
                    check('RESOURCE_HELD','FAIL' if visible(state['subject']) else 'UNKNOWN',item['subject'])
        if p['build'] is not None:
            if p['build']['recipeDigest'] is None:
                check('BUILD_INPUT_BINDING','UNKNOWN',item['subject'])
            else:
                ident = {'repository':item['subject']['repository'],**p['build'],**item['source']}
                gid = sc.digest(ident)
                groups.setdefault(gid,{'identity':ident,'subjects':[],
                    'artifactState':'BUILD_REQUIRED' if item['source']['artifactSha256'] is None else 'PINNED',
                    'affectedUnselected':[]})['subjects'].append(item['subject'])
            if item['source']['artifactSha256'] is None and p['build']['recipeDigest'] is not None:
                check('BUILD_REQUIRED','REQUIRED',item['subject'])
            else:
                check('ARTIFACT_IDENTITY','UNKNOWN' if item['source']['artifactSha256'] is None
                      else 'PASS',item['subject'])
        else:
            check('ARTIFACT_IDENTITY','NOT_APPLICABLE',item['subject'])
        targets.append({'subject':item['subject'],'source':item['source'],
                        'outstandingActions':st['outstandingActions'],
                        'procedure':p['procedure'],'verification':p['verification'],
                        'maintenance':p['maintenance']})
        visit(k)
    keys = list(selected)
    for i,k in enumerate(keys):
        for other in keys[i+1:]:
            p,q = profiles[k],profiles[other]
            if p['maintenance'] is not None and q['maintenance'] is not None and _overlap(p,q):
                conflicts.append({'subjects':[p['subject'],q['subject']],
                                  'reason':'SEQUENTIAL_WINDOWS_REQUIRED'})
    for group in groups.values():
        ident=group['identity']
        for k,p in profiles.items():
            desired=states[k]['desired']
            if k not in selected and p['build'] is not None and desired is not None and (
                {'repository':p['subject']['repository'],**p['build'],**desired['source']}==ident):
                if visible(p['subject']):
                    group['affectedUnselected'].append(p['subject'])
                else:
                    check('SHARED_BUILD_SCOPE_UNAVAILABLE','UNKNOWN')
    if any('sourceSha' in dep for dep in view.get('sourceRequirements',())):
        check('SOURCE_DEPENDENCY_COMPATIBILITY','UNKNOWN')
    if view['sourceTransitionPending']:
        check('SOURCE_TRANSITION','UNKNOWN')
    statuses={c['status'] for c in checks}
    status='STALE' if 'STALE' in statuses else 'BLOCKED' if 'FAIL' in statuses else 'UNKNOWN' if 'UNKNOWN' in statuses else 'PLAN_READY'
    result={'status':status,'snapshotRevision':view['snapshotRevision'],
            'eventDigest':view['eventDigest'],'targets':targets,'checks':checks,
            'buildGroups':list(groups.values()),'windowConflicts':conflicts,'order':order,
            'deploymentAuthorized':False}
    return {**result,'planFingerprint':sc.digest(result)}

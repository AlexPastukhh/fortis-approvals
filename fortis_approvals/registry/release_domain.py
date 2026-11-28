"""Registry-local deterministic domain, only for isolated successor rehearsal.

A pinned source/binding projection is supplied by reviewed composition,
not by semantic API callers. Actual W5 source transition and W4 controller
verification remain required before admission. No installed setter route.
"""
from ..core import Conflict, Denied, Stale, canonical, loads_strict
from ..integrations.registry_contracts import semantic_contract as sc
from .release_event_journal import ReleaseEventJournal, _request, protected_params
from .state_journal import _CommitUncertain
from . import source_event_journal as sources
from ..integrations.registry_contracts.maintenance_contract import paired_begin, paired_operation_id

_ACTIONS = frozenset(('image-rebuild','config-deploy','windows-update',
                      'package-build','migration-required'))


def _copy(value):
    return loads_strict(canonical(value))


def key(subject):
    return sc.digest(list(sc.subject_key(subject)))


def restriction_digest(profile_digest, profile):
    return sc.digest({'profileDigest':profile_digest,'resources':profile['resources'],
                      'maintenance':profile['maintenance']})


def _strings(items, limit=100):
    sc.need(type(items) is list and len(items) <= limit and
            all(type(v) is str and 0 < len(v) <= 500 for v in items)
            and items == sorted(set(items)))


def profile_rows(profile, repo, catalog):
    """Validate a bounded already-reviewed binding projection, not a catalog parser."""
    sc.fields(profile, ('schemaVersion', 'repository', 'catalogSha256', 'subjects'))
    sc.need(type(profile['schemaVersion']) is int and profile['schemaVersion'] == 1
            and profile['repository'] == repo and profile['catalogSha256'] == catalog)
    rows = profile['subjects']
    sc.need(type(rows) is list and 0 < len(rows) <= 200)
    result = {}
    for row in rows:
        sc.fields(row, ('subject','componentId','resources','dependencies','unresolvedDependencies',
                        'maintenance','procedure','verification','build','deployable'))
        sc.subject(row['subject'])
        k = key(row['subject'])
        sc.need(row['subject']['repository'] == repo and k not in result)
        sc.name(row['componentId'])
        sc.need(type(row['deployable']) is bool)
        _strings(row['resources'])
        sc.need(bool(row['resources']), 'REGISTRY_DOMAIN_RESOURCES_UNKNOWN')
        _strings(row['verification'], 40)
        sc.need(type(row['procedure']) is str and 0 < len(row['procedure']) <= 240)
        deps = row['dependencies']
        sc.need(type(deps) is list and len(deps) <= 50)
        dep_keys = [key(dep) for dep in deps]
        sc.need(len(dep_keys) == len(set(dep_keys)))
        unresolved=row['unresolvedDependencies']
        sc.need(type(unresolved) is list and len(unresolved)<=50)
        for dep in unresolved:
            sc.fields(dep,('repository','target'))
            sc.need(type(dep['repository']) is str and 0<len(dep['repository'])<=100)
            sc.name(dep['target'])
        sc.need(len({canonical(d) for d in unresolved})==len(unresolved))
        m = row['maintenance']
        if m is not None:
            sc.fields(m, ('beginRequired','stateFreeze','blockedOperations','notes'))
            sc.need(type(m['beginRequired']) is bool and type(m['stateFreeze']) is bool)
            ops = m['blockedOperations']
            sc.need(type(ops) is list and len(ops) <= 100)
            for op in ops:
                sc.fields(op, ('service','operation'))
                for v in op.values():
                    sc.need(type(v) is str and 0 < len(v) <= 64
                            and v[0].isascii() and v[0].islower()
                            and all(c.isascii() and (c.islower() or c.isdigit() or c=='_') for c in v))
            sc.need(len({canonical(op) for op in ops}) == len(ops)
                    and (m['beginRequired'] or not (m['stateFreeze'] or ops)))
            _strings(m['notes'], 20)
            sc.need(all(note.strip() and not any(ord(c)<32 or ord(c)==127 for c in note) for note in m['notes']))
        if row['build'] is not None:
            sc.fields(row['build'], ('buildUnitId','recipeDigest','configDigest'))
            sc.name(row['build']['buildUnitId'])
            recipe, config = row['build']['recipeDigest'], row['build']['configDigest']
            sc.need((recipe is None)==(config is None))
            if recipe is not None:
                sc.hex_id(recipe,64)
                sc.hex_id(config,64)
        result[k] = _copy(row)
    sc.need(len({r['componentId'] for r in result.values()})==len(result))
    return result


def same_source(a, b):
    # Unknown artifact is not a wildcard for an exact known artifact.
    return a == b


def same_source_lineage(a,b):
    return (a is not None and b is not None and all(a[k]==b[k] for k in
            ('sourceSha','catalogCommitSha','catalogSha256')))


def dependency_check(state):
    desired=state.get('desired')
    installed=state.get('installed')
    if (desired is None or desired.get('evidenceVerified') is not True
            or installed is None or installed['validity']!='LAST_ACCEPTED_TECHNICAL_OBSERVATION'):
        return 'UNKNOWN'
    if not same_source_lineage(installed['source'],desired['source']):
        return 'FAIL'
    return 'PASS' if state.get('planningState')=='DEPLOYED' else 'UNKNOWN'


def _desired_source(record):
    ident = record['identity']
    return {'sourceSha': ident['desiredSourceSha'],
            'catalogCommitSha': ident['catalogCommitSha'],
            'catalogSha256': ident['catalogSha256'],
            'artifactSha256': record['artifact']['digest']}


def _overlap(a, b):
    return (a['maintenance']['stateFreeze'] or b['maintenance']['stateFreeze']
            or bool(set(a['resources']) & set(b['resources'])))


class ReleaseDomain:
    """One writer transaction for domain replay, validation and append.

    Internal rehearsal object; raw storage methods are not exposed.
    Protected verification callback is trusted source, not a caller proof.
    No public method can select it, supply actor, or install authority.
    """
    def __init__(self, journal, profile, *, expected_profile_digest, protected_verify=None,
                 successor_profile=None, expected_successor_profile_digest=None,
                 source_verify=None):
        sc.need(type(journal) is ReleaseEventJournal, 'REGISTRY_DOMAIN_STORE_REQUIRED')
        sc.hex_id(expected_profile_digest,64)
        sc.need(sc.digest(profile) == expected_profile_digest,'REGISTRY_DOMAIN_PROFILE_PIN')
        self.store = journal
        self.profile_digest = expected_profile_digest
        self._profile = canonical(profile)
        self._protected_verify = protected_verify
        profile_rows(profile,journal.scope['repository'],journal.scope['catalogSha256'])
        self._source_verify=source_verify
        self._successor_profile=None
        self._successor_digest=expected_successor_profile_digest
        if successor_profile is not None:
            sc.hex_id(expected_successor_profile_digest,64)
            sc.need(sc.digest(successor_profile)==expected_successor_profile_digest,
                    'SOURCE_PROFILE_PIN_CHANGED')
            self._successor_profile=canonical(successor_profile)
            profile_rows(successor_profile,journal.scope['repository'],successor_profile['catalogSha256'])
        else:
            sc.need(expected_successor_profile_digest is None)


    def _profiles(self):
        return profile_rows(loads_strict(self._profile),self.store.scope['repository'],
                            self.store.scope['catalogSha256'])

    def _project(self, db):
        head, seen, _ = self.store._replay(db)
        profiles = self._profiles()
        states = {k: {'subject': p['subject'], 'targetRevision': 0, 'desired': None,
                      'installed': None, 'ownerReported': None, 'activeAttempt': None,
                      'requiredActions': [], 'outstandingActions': [], 'actionCoverage': [], 'history': [],
                      'sourceRequirements': []}
                  for k,p in profiles.items()}
        # V3 source is a retained candidate, never promoted to verified Desired.
        for raw, in db.execute('SELECT payload FROM records ORDER BY revision,record_id'):
            record = loads_strict(raw)
            k = key({field:record['identity'][field] for field in
                     ('repository','targetId','environment')})
            sc.need(k in states, 'REGISTRY_DOMAIN_LEGACY_SUBJECT_UNBOUND')
            p = profiles[k]
            required_components={profiles[key(dep)]['componentId'] for dep in p['dependencies']
                                 if key(dep) in profiles}
            sc.need(record['componentId']==p['componentId']
                    and set(record['requiresComponentIds']) <= required_components
                    and record['resourceIds'] == p['resources']
                    and record['deploymentProcedure'] == p['procedure']
                    and sorted(record['verification']) == p['verification']
                    and record['buildUnitId'] == (None if p['build'] is None else p['build']['buildUnitId']),
                    'REGISTRY_DOMAIN_LEGACY_BINDING_CHANGED')
            state = states[k]
            state['desired'] = {'recordId':record['recordId'],'source':_desired_source(record),
                                'provenance':'LEGACY_CANDIDATE','evidenceVerified':False}
            self._add_actions(state,record['recordId'],record['requiredActions'])
        source=sources.replay(self.store,db,seen)
        source_rows=list(source['events'].values())
        index=0
        catalog=self.store.scope['catalogSha256']
        profile_digest=self.profile_digest
        catalog_commit=self.store.scope['baselineSha']
        source_requirements=[]
        def advance(anchor):
            nonlocal index,profiles,catalog,profile_digest,catalog_commit
            while index<len(source_rows) and source_rows[index][2]==anchor:
                req,receipt,_=source_rows[index]
                p=req['proposal']
                if req['kind']=='TRANSITION':
                    sc.need(self._successor_profile is not None and
                            p['profileDigest']==self._successor_digest,'SOURCE_PROFILE_NOT_REVIEWED')
                    next_profiles=profile_rows(loads_strict(self._successor_profile),
                                               self.store.scope['repository'],p['catalogSha256'])
                    # Initial successor only: retain exact subjects and
                    # stable component/resource identities. Mapping changes
                    # require a separate reviewed migration, not guessed rename.
                    sc.need(set(next_profiles)==set(profiles) and all(
                        next_profiles[k]['componentId']==profiles[k]['componentId'] and
                        next_profiles[k]['resources']==profiles[k]['resources']
                        for k in profiles),'SOURCE_PROFILE_REMAP_REQUIRED')
                    profiles=next_profiles
                    catalog=p['catalogSha256']
                    profile_digest=p['profileDigest']
                    catalog_commit=req['observation']['mergeSha']
                sc.need(p['profileDigest']==profile_digest and p['catalogSha256']==catalog)
                for row in p['targets']:
                    k=key(row['subject'])
                    sc.need(k in profiles and profiles[k]['subject']==row['subject']
                            and profiles[k]['deployable'],'SOURCE_IMPACT_SUBJECT_UNBOUND')
                    state=states[k]
                    identity={**row['subject'],'desiredSourceSha':receipt['sourceCursor'],
                              'catalogCommitSha':catalog_commit,'catalogSha256':catalog}
                    state['desired']={'recordId':sc.digest(identity),
                        'source':{'sourceSha':receipt['sourceCursor'],'catalogCommitSha':catalog_commit,
                                  'catalogSha256':catalog,'artifactSha256':None},
                        'provenance':{'TRANSITION':'REVIEWED_TRANSITION','MERGE':'ACCOUNTED_MERGE',
                                      'EXTERNAL_MERGE':'ACCOUNTED_EXTERNAL_MERGE',
                                      sources.DELIVERY_REPAIR:'REVIEWED_DELIVERY_REPAIR',
                                      sources.BOOTSTRAP_MIGRATION:'REVIEWED_BOOTSTRAP_MIGRATION'}[req['kind']],
                        'sourceRevision':receipt['sourceRevision'],
                        'sourceEventDigest':receipt['eventDigest'],
                        'evidenceDigest':req['evidenceDigest'],
                        'pullRequest':{'repository':p['repository'],'number':p['number'],
                                       'headSha':p['headSha'],'baseSha':p['baseSha']},
                        'evidenceVerified':req['kind'] in ('MERGE','EXTERNAL_MERGE',sources.DELIVERY_REPAIR,
                                                         sources.BOOTSTRAP_MIGRATION)}
                    self._add_actions(state,state['desired']['recordId'],row['actions'])
                    previous={sc.canonical(dep):dep for dep in state['sourceRequirements']}
                    previous.update({sc.canonical(dep):dep for dep in p['dependencies']})
                    state['sourceRequirements']=list(previous.values())
                    state['history'].append({'event':{'kind':req['kind'],'operationId':req['operationId'],
                        'number':p['number'],'sourceSha':receipt['sourceCursor'],'actions':row['actions']},
                        'receipt':_copy(receipt)})
                source_requirements.extend(p['dependencies'])
                index+=1
        advance(0)
        rows = iter(seen.values())
        previous_release=sources.release_anchor(self.store,seen,0)
        for req, receipt in rows:
            sc.need(req.get('profileDigest') == profile_digest,
                    'REGISTRY_DOMAIN_EVENT_PROFILE_CHANGED')
            if req['kind'] in ('PROTECTED_PAIRED_BEGIN','PROTECTED_PAIRED_CLOSE'):
                other=next(rows,None)
                sc.need(other is not None,'REGISTRY_PROTECTED_PAIR_INCOMPLETE')
                # No source event or another write may intervene in this pair.
                sc.need(index==len(source_rows) or source_rows[index][2]>receipt['snapshotRevision'],
                        'REGISTRY_PROTECTED_PAIR_INCOMPLETE')
                checkpoint={'sourceRevision':index,
                    'sourceCursor':source_rows[index-1][1]['sourceCursor'] if index else self.store.expected_legacy['cursorSha'],
                    'snapshotRevision':receipt['snapshotRevision']-1+index,
                    'eventDigest':sc.digest([previous_release,source_rows[index-1][1]['eventDigest']]) if index else previous_release,
                    'profileDigest':profile_digest}
                self._apply_pair(states,profiles,[(req,receipt),other],checkpoint,catalog)
                receipt=other[1]
            else:
                self._apply(states, profiles, req, receipt,catalog=catalog)
            previous_release=receipt['eventDigest']
            advance(receipt['snapshotRevision'])
        sc.need(index==len(source_rows),'SOURCE_EVENT_ORDER_CHANGED')
        for state in states.values():
            state['planningState'] = self._planning_state(state)
        for raw, in db.execute('SELECT evidence FROM operations ORDER BY revision'):
            source_requirements.extend(loads_strict(raw)['plan']['observation']['sourceDependencyRequirements'])
        return {'snapshotRevision':len(seen)+source['sourceRevision'],
                'eventDigest':sc.digest([head,source['eventDigest']]) if source['sourceRevision'] else head,
                'sourceRevision':source['sourceRevision'],'sourceCursor':source['cursor'],
                'sourceEventBytes':source['eventBytes'],
                'profileDigest':profile_digest,'catalogSha256':catalog,
                'sourceRequirements':source_requirements,'sourceOperations':source['events'],
                'sourceTransitionPending':not source['sourceRevision'],'states':states,
                'profiles':profiles,'operations':seen}

    @staticmethod
    def _planning_state(state):
        desired = state['desired']
        if desired is None:
            return 'UNKNOWN'
        if not desired['evidenceVerified']:
            return 'PLANNED_UNVERIFIED'
        active = state['activeAttempt']
        if active is not None and active['desiredRecordId'] == desired['recordId']:
            return {'REPORTED_FAILED':'FAILED','UNKNOWN':'UNKNOWN'}.get(active['result'],'IN_PROGRESS')
        installed=state['installed']
        if (installed is not None and installed['validity']=='LAST_ACCEPTED_TECHNICAL_OBSERVATION'
                and same_source(installed['source'],desired['source'])
                and all(a['technicallyVerified'] for a in state['actionCoverage'])):
            return 'DEPLOYED'
        reported = state['ownerReported']
        if reported is not None and same_source(reported['source'],desired['source']):
            if reported['outcome']=='REPORTED_FAILED':
                return 'FAILED'
            if reported['outcome']=='UNKNOWN':
                return 'UNKNOWN'
        return 'QUEUED'

    @staticmethod
    def _refresh_actions(state):
        state['requiredActions']=sorted({a['action'] for a in state['actionCoverage']})
        state['outstandingActions']=sorted({a['action'] for a in state['actionCoverage']
                                            if not (a['ownerReported'] or a['technicallyVerified'])})

    @classmethod
    def _add_actions(cls,state,record_id,actions):
        for action in actions:
            state['actionCoverage'].append({'recordId':record_id,'action':action,
                                            'ownerReported':False,'technicallyVerified':False})
        cls._refresh_actions(state)

    def _apply_pair(self, states, profiles, rows, checkpoint, catalog):
        first,second=(row[0] for row in rows)
        pair=paired_begin(first['pair'],self.store.scope['repository'])
        closing=first['kind']=='PROTECTED_PAIRED_CLOSE'
        sc.need((closing or pair['checkpoint']==checkpoint) and all(
            req['kind']==first['kind'] and req.get('pair')==pair
            and req['actor']==first['actor'] and req['profileDigest']==checkpoint['profileDigest']
            and req['operationId']==paired_operation_id(pair['attemptId'],role,closing=closing)
            for req,role in zip((first,second),('registry','gateway'))),
            'REGISTRY_PROTECTED_PAIR_CHANGED')
        if closing:
            # The original pair, per-target CAS and accepted technical
            # observations are all required; neither member can close alone.
            for req,receipt in rows:
                self._apply(states,profiles,req,receipt,catalog=catalog,paired_closing=True)
            return
        sc.need(all(req['params']==pair['items'][role]
                    for req,role in zip((first,second),('registry','gateway'))),
                'REGISTRY_PROTECTED_PAIR_CHANGED')
        registry,gateway=(key(pair['items'][role]['subject']) for role in ('registry','gateway'))
        sc.need(registry in profiles and gateway in profiles
                and all(profiles[k]['maintenance'] is not None
                        and profiles[k]['maintenance']['beginRequired']
                        and profiles[k]['maintenance']['stateFreeze']
                        and states[k]['desired'] is not None
                        and states[k]['desired']['evidenceVerified'] is True
                        for k in (registry,gateway))
                and pair['items']['registry']['subject'] in profiles[gateway]['dependencies']
                and not any(state['activeAttempt'] is not None for state in states.values()),
                'REGISTRY_PROTECTED_PAIR_SCOPE_OR_HOLD')
        for req,receipt in rows:
            self._apply(states,profiles,req,receipt,catalog=catalog,paired_registry=registry)

    def _apply(self, states, profiles, req, receipt=None, *, catalog=None, paired_registry=None, paired_closing=False):
        p = req['params']
        k = key(p['subject'])
        sc.need(k in states and states[k]['subject'] == p['subject'],
                'REGISTRY_DOMAIN_SUBJECT_UNBOUND')
        state, profile = states[k], profiles[k]
        desired, active = state['desired'], state['activeAttempt']
        expected = p['expected']
        if (expected['targetRevision'] != state['targetRevision'] or
            expected['desiredRecordId'] != (desired['recordId'] if desired else None) or
            expected['catalogSha256'] != (catalog or self.store.scope['catalogSha256'])):
            raise Stale('REGISTRY_DOMAIN_STATE_STALE')
        kind = req['kind']
        sc.need(profile['deployable'], 'REGISTRY_DOMAIN_NONDEPLOYABLE')
        if kind in ('RELEASE_ATTEMPT_STARTED','PROTECTED_PAIRED_BEGIN'):
            paired=kind=='PROTECTED_PAIRED_BEGIN'
            sc.need(paired==(paired_registry is not None),'REGISTRY_PROTECTED_PAIR_CHANGED')
            sc.need(profile['deployable'] and active is None and desired is not None
                    and p['source']['catalogSha256']==(catalog or self.store.scope['catalogSha256'])
                    and same_source(p['source'], desired['source']),
                    'REGISTRY_DOMAIN_BEGIN_SOURCE_OR_ACTIVE')
            sc.need(profile['maintenance'] is not None, 'REGISTRY_MAINTENANCE_UNKNOWN')
            dependencies={key(dep) for dep in profile['dependencies']}
            for requirement in state['sourceRequirements']:
                matches=[k for k,s in states.items()
                         if s['subject']['repository']==requirement['repository']
                         and s['subject']['targetId']==requirement['targetId']]
                sc.need(len(matches)==1,'REGISTRY_DOMAIN_DEPENDENCY_UNVERIFIED')
                dependencies.add(matches[0])
            sc.need(not profile['unresolvedDependencies'] and all(
                dep in states and (self._planning_state(states[dep])=='DEPLOYED'
                    or (paired and k!=paired_registry and dep==paired_registry))
                for dep in dependencies),'REGISTRY_DOMAIN_DEPENDENCY_UNVERIFIED')
            for other_key, other in states.items():
                if other['activeAttempt'] is not None:
                    sc.need((paired and k!=paired_registry and other_key==paired_registry
                             and other['activeAttempt'].get('pairDigest')==sc.digest(req['pair']))
                            or not _overlap(profile, profiles[other_key]),
                            'REGISTRY_DOMAIN_RESOURCE_CONFLICT')
            state['activeAttempt'] = {'attemptId':req['operationId'],'source':_copy(p['source']),
                                      'desiredRecordId':desired['recordId'],
                                      'maintenance':_copy(profile['maintenance']),
                                      'resources':list(profile['resources']),
                                      'coveredRecordIds':sorted({a['recordId'] for a in state['actionCoverage']}),
                                      'state':'OWNER_WINDOW','result':None}
            if paired:
                role='registry' if k==paired_registry else 'gateway'
                state['activeAttempt'].update(pairId=req['pair']['attemptId'],
                    pairDigest=sc.digest(req['pair']),preparedArtifactSha256=req['pair']['artifacts'][role])
        elif kind == 'OWNER_RESULT_RECORDED':
            historical = p['context'] == 'historical'
            if not historical:
                if p['attemptId'] is not None:
                    sc.need(active is not None and p['attemptId'] == active['attemptId']
                            and same_source(p['source'],active.get('verifiedSource',active['source']))
                            and p['context'] == 'release',
                            'REGISTRY_DOMAIN_ATTEMPT_MISMATCH')
                elif p['context'] == 'release':
                    sc.need(active is None and profile['maintenance'] is not None
                            and not profile['maintenance']['beginRequired']
                            and desired is not None and p['source']['catalogSha256']==(catalog or self.store.scope['catalogSha256'])
                            and same_source(p['source'],desired['source']),
                            'REGISTRY_DOMAIN_BEGIN_REQUIRED')
                else:
                    sc.need(active is None, 'REGISTRY_DOMAIN_ACTIVE_HOLD')
                sc.need(p['context'] != 'initial' or state['ownerReported'] is None,
                        'REGISTRY_DOMAIN_INITIAL_ALREADY_REPORTED')
                previous = state['ownerReported']
                if previous is not None and previous['observedAt'] is not None and p['observedAt'] is not None:
                    sc.need(p['observedAt'] >= previous['observedAt'], 'REGISTRY_DOMAIN_OBSERVATION_ORDER')
                state['ownerReported'] = {'source':_copy(p['source']),'context':p['context'],
                     'outcome':p['outcome'],'actor':req['actor'],
                     'assertionSource':req['assertionSource'],'observedAt':p['observedAt'],
                     'evidenceDigests':list(p['evidenceDigests']),'operationId':req['operationId']}
                if p['context']=='release' and active is not None:
                    current=desired is not None and active['desiredRecordId']==desired['recordId']
                else:
                    current=True
                if current and state['installed'] is not None and (
                    p['outcome'] != 'REPORTED_COMPLETE' or
                    not same_source(p['source'], state['installed']['source'])):
                    state['installed']['validity'] = 'UNKNOWN'
                    for action in state['actionCoverage']:
                        action['technicallyVerified']=False
                if active is not None:
                    active['result'] = p['outcome']
                    if p['outcome'] == 'REPORTED_COMPLETE' and not active['maintenance']['beginRequired']:
                        state['activeAttempt'] = None
                if p['outcome']=='REPORTED_COMPLETE' and p['context']!='rollback':
                    covered=set()
                    if active is not None:
                        covered=set(active['coveredRecordIds'])
                    elif desired is not None and same_source(p['source'],desired['source']):
                        covered={a['recordId'] for a in state['actionCoverage']}
                    for a in state['actionCoverage']:
                        if a['recordId'] in covered and a['action']!='migration-required':
                            a['ownerReported']=True
                else:
                    # An old attempt can invalidate only the coverage it
                    # declared. Current rollback/external reports affect all.
                    covered=(set(active['coveredRecordIds']) if active is not None else None)
                    for a in state['actionCoverage']:
                        if covered is None or a['recordId'] in covered:
                            a['ownerReported']=False
                self._refresh_actions(state)
        else:
            sc.need(kind in ('TECHNICAL_OBSERVATION_ACCEPTED','RELEASE_HOLD_CLOSED','PROTECTED_PAIRED_CLOSE'),
                    'REGISTRY_DOMAIN_EVENT_KIND')
            coverage=p.get('coveredRecordIds')
            if p['attemptId'] is not None:
                sc.need(active is not None and p['attemptId'] == active['attemptId']
                        and (same_source(p['source'],active['source']) or
                             same_source(p['source'],active.get('verifiedSource')) or
                             (kind=='TECHNICAL_OBSERVATION_ACCEPTED' and coverage is not None
                              and active['source']['artifactSha256'] is None
                              and same_source_lineage(p['source'],active['source']))),
                        'REGISTRY_DOMAIN_ATTEMPT_MISMATCH')
            elif active is not None:
                raise Denied('REGISTRY_DOMAIN_ACTIVE_HOLD')
            if kind in ('RELEASE_HOLD_CLOSED','PROTECTED_PAIRED_CLOSE'):
                sc.need(active is not None, 'REGISTRY_DOMAIN_NO_ACTIVE_HOLD')
                sc.need(('pairId' in active)==paired_closing
                        and paired_closing==(kind=='PROTECTED_PAIRED_CLOSE'),
                        'REGISTRY_PROTECTED_PAIR_CLOSE_REQUIRED')
                if paired_closing:
                    installed=state['installed']
                    sc.need(active['pairId']==req['pair']['attemptId']
                            and active['pairDigest']==sc.digest(req['pair'])
                            and active.get('verifiedSource')==p['source']
                            and installed is not None
                            and installed['validity']=='LAST_ACCEPTED_TECHNICAL_OBSERVATION'
                            and same_source(installed['source'],p['source'])
                            and all(installed[k]==p[k] for k in ('controllerReceiptDigest','readbackDigest','observedAt'))
                            and desired is not None and same_source(desired['source'],p['source'])
                            and all(a['technicallyVerified'] for a in state['actionCoverage']),
                            'REGISTRY_PROTECTED_PAIR_COMPLETION_UNVERIFIED')
                state['activeAttempt'] = None
            else:
                prior = state['installed']
                sc.need(prior is None or p['observedAt'] >= prior['observedAt'],
                        'REGISTRY_DOMAIN_OBSERVATION_ORDER')
                if active is not None and 'pairId' in active:
                    sc.need(coverage is not None and p['source']['artifactSha256']==active['preparedArtifactSha256'],
                            'REGISTRY_PROTECTED_PAIR_ARTIFACT_CHANGED')
                if coverage is not None:
                    current=(desired is not None and desired['evidenceVerified']
                             and same_source_lineage(p['source'],desired['source']))
                    known={a['recordId'] for a in state['actionCoverage']}
                    permitted=(set(active['coveredRecordIds']) if active is not None else
                               known if current else set())
                    sc.need(set(coverage)<=permitted and
                            (not current or profile['build'] is None
                             or p['source']['artifactSha256'] is not None),
                            'REGISTRY_TECHNICAL_COVERAGE_CHANGED')
                    if active is not None and active.get('verifiedSource') is not None:
                        sc.need(same_source(p['source'],active['verifiedSource']),
                                'REGISTRY_VERIFIED_ARTIFACT_CHANGED')
                    if current and p['source']['artifactSha256'] is not None:
                        sc.need(desired['source']['artifactSha256'] in (None,p['source']['artifactSha256']),
                                'REGISTRY_VERIFIED_ARTIFACT_CHANGED')
                        desired['source']['artifactSha256']=p['source']['artifactSha256']
                        if active is not None and active['desiredRecordId']==desired['recordId']:
                            active['verifiedSource']=_copy(p['source'])
                for action in state['actionCoverage']:
                    action['technicallyVerified']=coverage is not None and action['recordId'] in coverage
                self._refresh_actions(state)
                state['installed'] = {'source':_copy(p['source']),'observedAt':p['observedAt'],
                    'controllerReceiptDigest':p['controllerReceiptDigest'],
                    'readbackDigest':p['readbackDigest'],'operationId':req['operationId'],
                    'validity':'LAST_ACCEPTED_TECHNICAL_OBSERVATION'}
        if receipt is not None:
            state['targetRevision'] = receipt['targetRevision']
            state['history'].append({'event':_copy(req),'receipt':_copy(receipt)})

    def snapshot(self):
        with self.store._read_only_db() as db:
            return self._project(db)

    def maintenance_snapshot(self):
        """Unfiltered internal witness, never a public Board response.

        The trusted peer must authenticate this snapshot; it is a candidate
        view while the source transition and protected admission are open.
        """
        return self._maintenance_snapshot(self.snapshot())

    def _maintenance_snapshot(self, view):
        holds=[]
        for k,state in sorted(view['states'].items()):
            h=state['activeAttempt']
            if h is None:
                continue
            holds.append({'attemptId':h['attemptId'],'subject':state['subject'],
                          'source':h['source'],
                          'restrictionDigest':restriction_digest(view['profileDigest'],h),
                          'stateFreeze':h['maintenance']['stateFreeze'],
                          'blockedOperations':h['maintenance']['blockedOperations']})
            if 'pairId' in h:
                holds[-1].update(pairId=h['pairId'],pairDigest=h['pairDigest'])
                holds[-1]['restrictionDigest']=sc.digest([holds[-1]['restrictionDigest'],h['pairDigest']])
        return {'instanceId':self.store.instance_id,
                'scopeDigest':self.store.expected_legacy['scopeDigest'],
                'snapshotRevision':view['snapshotRevision'],'eventDigest':view['eventDigest'],
                'holds':holds}

    def _write(self, reqs, recorded_at):
        sc.revision(recorded_at)
        try:
            with self.store._db() as db:
                view = self._project(db)
                ids = [r['operationId'] for r in reqs]
                sc.need(len(set(ids)) == len(ids), 'REGISTRY_DOMAIN_DUPLICATE_OPERATION')
                existing = [i in view['operations'] for i in ids]
                sc.need(not any(existing) or all(existing),'REGISTRY_DOMAIN_PARTIAL_REPLAY')
                results = []
                for req in reqs:
                    ident = req['operationId']
                    if ident in view['operations']:
                        old, r = view['operations'][ident]
                        if old != req:
                            raise Conflict('REGISTRY_RELEASE_OPERATION_CONFLICT')
                    else:
                        sc.need(req.get('profileDigest')==view['profileDigest'],'SOURCE_PROFILE_CHANGED')
                        self._apply(view['states'], view['profiles'], req,catalog=view['catalogSha256'])
                        r = self.store._append_in_transaction(db,req,recorded_at)
                    results.append(r)
                self._project(db)
            try:
                readback = self.snapshot()['operations']
                if all(readback[r['operationId']][1] == r for r in results):
                    return results
            except (Denied, KeyError, Stale):
                pass
            return {'result':'UNKNOWN_OUTCOME','operationIds':[r['operationId'] for r in reqs]}
        except _CommitUncertain:
            return {'result':'UNKNOWN_OUTCOME','operationIds':[r['operationId'] for r in reqs]}

    def source_preflight(self, value):
        """Passive exact source admission witness for a trusted merge binding."""
        from ..integrations.registry_contracts.source_lineage_contract import proposal
        p=proposal(value)
        view=self.snapshot()
        sc.need(not view['sourceTransitionPending'] and
                p['repository']==self.store.scope['repository'],
                'SOURCE_TRANSITION_REQUIRED')
        if (p['expectedSourceRevision']!=view['sourceRevision'] or
                p['baseSha']!=view['sourceCursor'] or
                p['catalogSha256']!=view['catalogSha256'] or
                p['profileDigest']!=view['profileDigest']):
            raise Stale('SOURCE_PREVIEW_STALE')
        sources.require_merge_capacity(
            {'sourceRevision':view['sourceRevision'],'eventBytes':view['sourceEventBytes']},p)
        sc.need(not any(r[0]['proposal']['number']==p['number']
                        for r in view['sourceOperations'].values()),
                'SOURCE_PR_ALREADY_ACCOUNTED')
        sc.need(not any(s['activeAttempt'] and s['activeAttempt']['maintenance']['stateFreeze']
                        for s in view['states'].values()),'SOURCE_MAINTENANCE_BLOCKED')
        for row in p['targets']:
            k=key(row['subject'])
            sc.need(k in view['profiles'] and view['profiles'][k]['subject']==row['subject']
                    and view['profiles'][k]['deployable'],'SOURCE_IMPACT_SUBJECT_UNBOUND')
        return {'sourceRevision':view['sourceRevision'],'sourceCursor':view['sourceCursor'],
                'profileDigest':view['profileDigest'],'proposalDigest':sc.digest(p),
                'admissionAllowed':False}

    def register_source(self, value, *, effect_guard=None):
        """Trusted source writer only, not a semantic/ordinary owner route.

        New effects require independently verified evidence. Original lookup
        after an ambiguous acknowledgement never repeats upstream merge.
        """
        req=sources.request(value,self.store)
        sc.need(req['kind'] != sources.DELIVERY_REPAIR, 'SOURCE_DELIVERY_REPAIR_OFFLINE_REQUIRED')
        sc.need(req['kind'] != sources.BOOTSTRAP_MIGRATION, 'SOURCE_BOOTSTRAP_OFFLINE_REQUIRED')
        prior=self.snapshot()['sourceOperations'].get(req['operationId'])
        if prior is not None:
            if prior[0]!=req:
                raise Conflict('SOURCE_OPERATION_CONFLICT')
            return prior[1]
        sc.need(callable(self._source_verify) and self._source_verify(_copy(req)) is True,
                'SOURCE_EVIDENCE_UNVERIFIED')
        try:
            with self.store._db() as db:
                view=self._project(db)
                if req['kind']=='TRANSITION':
                    sc.need(not view['operations'],'SOURCE_TRANSITION_RELEASE_HISTORY_PRESENT')
                # A global freeze is never a route to new merge accounting.
                sc.need(not any(s['activeAttempt'] and s['activeAttempt']['maintenance']['stateFreeze']
                                for s in view['states'].values()),'SOURCE_MAINTENANCE_BLOCKED')
                if effect_guard is not None:
                    sc.need(effect_guard() is True,'SOURCE_EFFECT_SCOPE_DENIED')
                result=sources.append(self.store,db,req,view['operations'])
                self._project(db)
            try:
                if self.source_operation(req['operationId'])==result:
                    return result
            except Denied:
                pass
        except _CommitUncertain:
            pass
        return {'result':'UNKNOWN_OUTCOME','operationId':req['operationId']}

    def source_operation(self, ident):
        sc.uuid_id(ident)
        row=self.snapshot()['sourceOperations'].get(ident)
        return row[1] if row is not None else None

    def owner_event(self, operation, params, *, actor, assertion_source, operation_id,
                    recorded_at, parent_id=None):
        sc.need(operation in ('begin_release','report_release_result'))
        kind = 'RELEASE_ATTEMPT_STARTED' if operation == 'begin_release' else 'OWNER_RESULT_RECORDED'
        req = _request({'operationId':operation_id,'kind':kind,'actor':actor,
                        'assertionSource':assertion_source,'parentRequestId':parent_id,
                        'profileDigest':self.snapshot()['profileDigest'],'params':params},
                       self.store.scope['repository'])
        result = self._write([req],recorded_at)
        return result[0] if type(result) is list else result

    def begin_group(self, items, *, actor, assertion_source, operation_ids, parent_id, recorded_at):
        """One Registry-local transaction, no claim of external atomicity."""
        sc.group_items(items,sc.begin_item)
        sc.uuid_id(parent_id)
        sc.need(type(operation_ids) is list and len(operation_ids)==len(items))
        profile_digest=self.snapshot()['profileDigest']
        reqs = [_request({'operationId':ident,'kind':'RELEASE_ATTEMPT_STARTED','actor':actor,
                        'assertionSource':assertion_source,'parentRequestId':parent_id,
                        'profileDigest':profile_digest,'params':item},
                       self.store.scope['repository'])
                for item,ident in zip(items,operation_ids)]
        return self._write(reqs,recorded_at)

    def protected_begin_pair(self, value, *, actor, recorded_at):
        """One exact private controller intent, two immutable receipts atomically.

        Only a separately composed trusted verifier can admit the actual
        compatibility/readback proof. Ordinary semantic routes cannot call this.
        """
        sc.revision(recorded_at)
        return self._protected_pair_write(self._paired_begin_requests(value,actor),recorded_at)

    def _paired_begin_requests(self,value,actor):
        pair=paired_begin(value,self.store.scope['repository'])
        return [_request({'operationId':paired_operation_id(pair['attemptId'],role),
            'kind':'PROTECTED_PAIRED_BEGIN','actor':actor,'assertionSource':'PROTECTED_CONTROLLER',
            'parentRequestId':None,'profileDigest':pair['checkpoint']['profileDigest'],
            'params':pair['items'][role],'pair':pair},self.store.scope['repository'])
            for role in ('registry','gateway')]

    def protected_pair_begin_readback(self,value,*,actor):
        """Exact begin at the replay tip, or independently observed absence."""
        reqs=self._paired_begin_requests(value,actor);pair=reqs[0]['pair']
        view=self.snapshot();operations=view['operations']
        checkpoint={k:view[k] for k in pair['checkpoint']}
        holds=self._maintenance_snapshot(view)
        rows=[operations.get(req['operationId']) for req in reqs]
        if not any(rows):
            return {'receipts':None,'checkpoint':checkpoint,'holdSnapshot':holds}
        sc.need(all(row is not None and row[0]==req for row,req in zip(rows,reqs))
                and list(operations)[-2:]==[req['operationId'] for req in reqs]
                and checkpoint['snapshotRevision']==pair['checkpoint']['snapshotRevision']+2
                and all(checkpoint[k]==pair['checkpoint'][k] for k in ('sourceCursor','sourceRevision','profileDigest'))
                and len(holds['holds'])==2 and all(h.get('pairDigest')==sc.digest(pair) for h in holds['holds']),
                'REGISTRY_PROTECTED_BEGIN_READBACK_CHANGED')
        return {'receipts':[row[1] for row in rows],'checkpoint':checkpoint,'holdSnapshot':holds}

    def protected_close_pair(self, value, items, *, actor, recorded_at):
        """Atomic successful closure; trusted verifier must prove real completion.

        Two accepted technical observations remain independent evidence.
        Return/failure is not successful completion and cannot use this path.
        """
        reqs=self._paired_close_requests(value,items,actor=actor)
        sc.revision(recorded_at)
        sc.need(all(req['params']['observedAt']<=recorded_at for req in reqs),
                'REGISTRY_PROTECTED_OBSERVATION_TIME')
        return self._protected_pair_write(reqs,recorded_at)

    def _paired_close_requests(self,value,items,*,actor):
        pair=paired_begin(value,self.store.scope['repository'])
        sc.fields(items,('registry','gateway'))
        return [_request({'operationId':paired_operation_id(pair['attemptId'],role,closing=True),
            'kind':'PROTECTED_PAIRED_CLOSE','actor':actor,'assertionSource':'PROTECTED_CONTROLLER',
            'parentRequestId':None,'profileDigest':pair['checkpoint']['profileDigest'],
            'params':protected_params('RELEASE_HOLD_CLOSED',items[role]),'pair':pair},
            self.store.scope['repository']) for role in ('registry','gateway')]

    def protected_pair_completion_readback(self,value,items,*,actor):
        """Read only the exact completed attempt at the current journal tip.

        This does not retry an observation or close, authenticate the host
        intent, or allow NORMAL. A trusted controller compares this evidence
        with its independently durable COMPLETION_PENDING intent. Any later
        source or release event makes this recovery witness inapplicable.
        """
        reqs=self._paired_close_requests(value,items,actor=actor)
        pair=reqs[0]['pair']
        view=self.snapshot()
        current={k:view[k] for k in pair['checkpoint']}
        sc.need(all(current[k]==pair['checkpoint'][k]
                    for k in ('sourceRevision','sourceCursor','profileDigest')),
                'REGISTRY_PROTECTED_COMPLETION_CHECKPOINT_CHANGED')
        operations=view['operations']
        rows=[operations.get(req['operationId']) for req in reqs]
        sc.need(all(row is not None and row[0]==req for row,req in zip(rows,reqs)),
                'REGISTRY_PROTECTED_COMPLETION_RECEIPTS_MISSING')
        receipts=[row[1] for row in rows]
        sc.need(list(operations)[-2:]==[req['operationId'] for req in reqs]
                and current['snapshotRevision']==receipts[-1]['snapshotRevision']+current['sourceRevision'],
                'REGISTRY_PROTECTED_COMPLETION_CHECKPOINT_CHANGED')
        holds=self._maintenance_snapshot(view)
        sc.need(not holds['holds'],'REGISTRY_PROTECTED_COMPLETION_HOLD_REMAINS')
        observed={}
        for req,role in zip(reqs,('registry','gateway')):
            state=view['states'][key(req['params']['subject'])]
            installed=state['installed']
            sc.need(state['planningState']=='DEPLOYED' and installed is not None,
                    'REGISTRY_PROTECTED_PAIR_COMPLETION_UNVERIFIED')
            row=operations.get(installed['operationId'])
            sc.need(row is not None and row[0]['kind']=='TECHNICAL_OBSERVATION_ACCEPTED'
                    and all(row[0]['params'][k]==req['params'][k] for k in
                            ('attemptId','subject','source','controllerReceiptDigest','readbackDigest','observedAt')),
                    'REGISTRY_PROTECTED_PAIR_COMPLETION_UNVERIFIED')
            observed[role]=row[1]
        return {'result':'PROTECTED_PAIR_COMPLETION_READBACK_ONLY','attemptId':pair['attemptId'],
                'pairDigest':sc.digest(pair),'checkpoint':current,'holdSnapshot':holds,
                'closeReceipts':receipts,'observationReceipts':observed}

    def protected_complete_pair(self, value, observations, *, actor, recorded_at):
        """One private transaction: two observations followed by two closes.

        The trusted verifier must authenticate the exact protected host
        intent and fresh technical proofs. No ingress exposes this method.
        """
        sc.revision(recorded_at)
        pair,reqs,items=self._paired_completion_requests(value,observations,actor=actor)
        sc.need(all(req['params']['observedAt']<=recorded_at for req in reqs),
                'REGISTRY_PROTECTED_OBSERVATION_TIME')
        result=self._protected_pair_write(self._paired_close_requests(pair,items,actor=actor),
            recorded_at,observations=reqs)
        if type(result) is not list:return result
        readback=self.protected_complete_pair_readback(pair,observations,actor=actor)
        sc.need([readback['observationReceipts'][r] for r in ('registry','gateway')]+readback['closeReceipts']==result,
                'REGISTRY_PROTECTED_PAIR_COMPLETION_UNVERIFIED')
        return readback

    def _paired_completion_requests(self,value,observations,*,actor):
        pair=paired_begin(value,self.store.scope['repository'])
        sc.fields(observations,('registry','gateway'))
        from ..integrations.registry_contracts.maintenance_evidence import paired_observation_id
        reqs=[];items={}
        for role in ('registry','gateway'):
            p=protected_params('TECHNICAL_OBSERVATION_ACCEPTED',observations[role])
            original=pair['items'][role]
            sc.need(p['subject']==original['subject']
                    and p['source']=={**original['source'],'artifactSha256':pair['artifacts'][role]}
                    and p['attemptId']==paired_operation_id(pair['attemptId'],role)
                    and p['expected']=={**original['expected'],'targetRevision':original['expected']['targetRevision']+1}
                    and 'coveredRecordIds' in p,
                    'REGISTRY_PROTECTED_PAIR_COMPLETION_UNVERIFIED')
            reqs.append(_request({'operationId':paired_observation_id(pair['attemptId'],role),
                'kind':'TECHNICAL_OBSERVATION_ACCEPTED','actor':actor,'assertionSource':'PROTECTED_CONTROLLER',
                'parentRequestId':None,'profileDigest':pair['checkpoint']['profileDigest'],'params':p},
                self.store.scope['repository']))
            items[role]={**{k:v for k,v in p.items() if k!='coveredRecordIds'},
                         'expected':{**p['expected'],'targetRevision':p['expected']['targetRevision']+1}}
        return pair,reqs,items

    def protected_complete_pair_readback(self,value,observations,*,actor):
        pair,reqs,items=self._paired_completion_requests(value,observations,actor=actor)
        readback=self.protected_pair_completion_readback(pair,items,actor=actor)
        view=self.snapshot()
        sc.need(all(req['operationId'] in view['operations'] and view['operations'][req['operationId']][0]==req
                    and view['operations'][req['operationId']][1]==readback['observationReceipts'][role]
                    for req,role in zip(reqs,('registry','gateway')))
                and list(view['operations'])[-4:]==[req['operationId'] for req in reqs]+
                     [row['operationId'] for row in readback['closeReceipts']],
                'REGISTRY_PROTECTED_PAIR_COMPLETION_UNVERIFIED')
        return readback

    def _protected_pair_write(self, reqs, recorded_at, *, observations=()):
        pair=reqs[0]['pair']
        all_reqs=[*observations,*reqs]
        # Readback of existing original receipts does not repeat proof/effect.
        def existing(view):
            old=[view['operations'].get(req['operationId']) for req in all_reqs]
            sc.need(not any(old) or all(old),'REGISTRY_DOMAIN_PARTIAL_REPLAY')
            if not any(old):return None
            if any(row[0]!=req for row,req in zip(old,all_reqs)):
                raise Conflict('REGISTRY_RELEASE_OPERATION_CONFLICT')
            return [row[1] for row in old]
        prior=existing(self.snapshot())
        if prior is not None:return prior
        sc.need(callable(self._protected_verify) and all(self._protected_verify(_copy(req)) is True
                for req in all_reqs),'REGISTRY_PROTECTED_PROOF_REQUIRED')
        try:
            with self.store._db() as db:
                view=self._project(db)
                prior=existing(view)
                if prior is not None:return prior
                result=[]
                if observations:
                    sc.need(view['snapshotRevision']==pair['checkpoint']['snapshotRevision']+2
                            and all(view[k]==pair['checkpoint'][k] for k in ('sourceCursor','sourceRevision','profileDigest')),
                            'REGISTRY_PROTECTED_COMPLETION_CHECKPOINT_CHANGED')
                    for req in observations:
                        state=view['states'][key(req['params']['subject'])]
                        active=state['activeAttempt']
                        sc.need(active is not None and active.get('pairDigest')==sc.digest(pair)
                                and req['params']['coveredRecordIds']==active['coveredRecordIds'],
                                'REGISTRY_PROTECTED_PAIR_COMPLETION_UNVERIFIED')
                        self._apply(view['states'],view['profiles'],req,catalog=view['catalogSha256'])
                        result.append(self.store._append_in_transaction(db,req,recorded_at))
                    # Re-project the observations within the SAME transaction
                    # to obtain their actual per-target CAS and Installed.
                    view=self._project(db)
                checkpoint={k:view[k] for k in pair['checkpoint']}
                self._apply_pair(view['states'],view['profiles'],[(req,None) for req in reqs],
                                 checkpoint,view['catalogSha256'])
                result.extend(self.store._append_in_transaction(db,req,recorded_at) for req in reqs)
                self._project(db)
            try:
                if existing(self.snapshot())==result:return result
            except (Denied,KeyError,Stale):pass
        except _CommitUncertain:pass
        return {'result':'UNKNOWN_OUTCOME','operationIds':[r['operationId'] for r in all_reqs]}

    def protected_event(self, kind, params, *, actor, operation_id, recorded_at):
        """Separate trusted internal evidence adapter; never a semantic method.

        Test verifier proves only the fixture. Production verifier must bind
        real controller receipt/readback, scope, freshness and safe closure.
        """
        sc.need(kind in ('TECHNICAL_OBSERVATION_ACCEPTED','RELEASE_HOLD_CLOSED'))
        sc.revision(recorded_at)
        req = _request({'operationId':operation_id,'kind':kind,'actor':actor,
                       'assertionSource':'PROTECTED_CONTROLLER','parentRequestId':None,
                       'profileDigest':self.snapshot()['profileDigest'],'params':protected_params(kind,params)},
                      self.store.scope['repository'])
        sc.need(req['params']['observedAt']<=recorded_at,'REGISTRY_PROTECTED_OBSERVATION_TIME')
        # Recovery of an already accepted original receipt does not reverify
        # mutable upstream observations or create any new effects.
        old = self.snapshot()['operations'].get(operation_id)
        if old is not None:
            if old[0] != req:
                raise Conflict('REGISTRY_RELEASE_OPERATION_CONFLICT')
            return old[1]
        sc.need(callable(self._protected_verify) and
                self._protected_verify(_copy(req)) is True, 'REGISTRY_PROTECTED_PROOF_REQUIRED')
        result = self._write([req],recorded_at)
        return result[0] if type(result) is list else result

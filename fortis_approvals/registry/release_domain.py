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
                                      'EXTERNAL_MERGE':'ACCOUNTED_EXTERNAL_MERGE'}[req['kind']],
                        'sourceRevision':receipt['sourceRevision'],
                        'sourceEventDigest':receipt['eventDigest'],
                        'evidenceDigest':req['evidenceDigest'],
                        'pullRequest':{'repository':p['repository'],'number':p['number'],
                                       'headSha':p['headSha'],'baseSha':p['baseSha']},
                        'evidenceVerified':req['kind'] in ('MERGE','EXTERNAL_MERGE')}
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
        for req, receipt in seen.values():
            sc.need(req.get('profileDigest') == profile_digest,
                    'REGISTRY_DOMAIN_EVENT_PROFILE_CHANGED')
            self._apply(states, profiles, req, receipt,catalog=catalog)
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

    def _apply(self, states, profiles, req, receipt=None, *, catalog=None):
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
        if kind == 'RELEASE_ATTEMPT_STARTED':
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
                dep in states and self._planning_state(states[dep])=='DEPLOYED'
                for dep in dependencies),'REGISTRY_DOMAIN_DEPENDENCY_UNVERIFIED')
            for other_key, other in states.items():
                if other['activeAttempt'] is not None:
                    sc.need(not _overlap(profile, profiles[other_key]),
                            'REGISTRY_DOMAIN_RESOURCE_CONFLICT')
            state['activeAttempt'] = {'attemptId':req['operationId'],'source':_copy(p['source']),
                                      'desiredRecordId':desired['recordId'],
                                      'maintenance':_copy(profile['maintenance']),
                                      'resources':list(profile['resources']),
                                      'coveredRecordIds':sorted({a['recordId'] for a in state['actionCoverage']}),
                                      'state':'OWNER_WINDOW','result':None}
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
            sc.need(kind in ('TECHNICAL_OBSERVATION_ACCEPTED','RELEASE_HOLD_CLOSED'),
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
            if kind == 'RELEASE_HOLD_CLOSED':
                sc.need(active is not None, 'REGISTRY_DOMAIN_NO_ACTIVE_HOLD')
                state['activeAttempt'] = None
            else:
                prior = state['installed']
                sc.need(prior is None or p['observedAt'] >= prior['observedAt'],
                        'REGISTRY_DOMAIN_OBSERVATION_ORDER')
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
        view=self.snapshot()
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

"""Evidence-based source onboarding assessment. Read-only, source-only.

It chooses an economical, verifiable *implementation technique per method*;
there are no No-code/Low-code/Custom runtime modes or alternative grant flows.
Recommendations do not authorize writes, credentials, network, or release.
"""
import argparse
from copy import deepcopy
from pathlib import Path
from hashlib import sha256

from ..core import Denied, canonical, loads_strict
from .model import check, ident
from .source_generator import render_package

_EVIDENCE_KEYS = ('schemaVersion','provider','reviewed','transport','operations')
_METHOD_KEYS = ('name','reviewed','effect','verb','response','customization','descriptionReady')
_CUSTOMIZATIONS = frozenset(('none','resultPostcheck','contextCheck','manualOperation'))
_TRANSPORTS = ('standardJsonapi','trustedManual','unknown')
_KNOWN_EFFECTS = ('READ','WRITE','UNKNOWN')
_KNOWN_VERBS = ('GET','POST','PATCH','PUT','DELETE','UNKNOWN')
_KNOWN_RESPONSE = ('json','nonJson','unknown')
# Only explicit compiler *capability* gaps can be considered for a manual
# implementation. Every other preflight denial is a security/contract STOP,
# not a reason to relax validations by switching implementation techniques.
_CAPABILITY_GAPS = frozenset((
    # A reviewed upstream schema may demand a type or value format outside the
    # intentionally finite declarative grammar. Route/shape mismatches are
    # errors in the source contract, NOT a reason to bypass it with custom code.
    'DECLARATIVE_SCHEMA_TYPE_UNSUPPORTED',
    'DECLARATIVE_FORMAT_UNSUPPORTED',
))

# Deliberately modest *comparative effort proxies*, not measured elapsed time,
# business costs, or an API-safety classification. Values are externally
# overridable for a specific source onboarding assessment.
_DEFAULT_EFFORT = {'compiled':1,'draftDescriptor':2,'resultPostcheck':2,'contextCheck':3,
                   'manualOperation':7,'trustedTransport':5}


def _strict(value, keys, code):
    check(type(value) is dict and set(value)==set(keys),code)


def _assessment_input(evidence, source_description, effort):
    _strict(evidence,_EVIDENCE_KEYS,'ASSESSMENT_EVIDENCE_INVALID')
    check(type(evidence['schemaVersion']) is int and evidence['schemaVersion']==1 and
          type(evidence['reviewed']) is bool,'ASSESSMENT_EVIDENCE_INVALID')
    check(type(evidence['provider']) is str, 'ASSESSMENT_EVIDENCE_INVALID')
    provider=ident(evidence['provider'])
    check(type(evidence['transport']) is str and evidence['transport'] in _TRANSPORTS,
          'ASSESSMENT_TRANSPORT_UNKNOWN')
    operations=evidence['operations']
    check(type(operations) is list and 1<=len(operations)<=100,
          'ASSESSMENT_OPERATIONS_INVALID')
    names=set()
    for op in operations:
        _strict(op,_METHOD_KEYS,'ASSESSMENT_OPERATION_INVALID')
        check(type(op['name']) is str, 'ASSESSMENT_OPERATION_INVALID')
        name=ident(op['name'])
        check(name not in names,'ASSESSMENT_DUPLICATE_METHOD');names.add(name)
        check(type(op['reviewed']) is bool and type(op['descriptionReady']) is bool and
              op['effect'] in _KNOWN_EFFECTS and op['verb'] in _KNOWN_VERBS and
              op['response'] in _KNOWN_RESPONSE and
              type(op['customization']) is str and
              op['customization'] in _CUSTOMIZATIONS,
              'ASSESSMENT_OPERATION_INVALID')
    check(source_description is None or type(source_description) is dict,
          'ASSESSMENT_DESCRIPTION_INVALID')
    if source_description is not None:
        actual_transport=source_description.get('transport')
        expected_transport={'standardJsonapi':'jsonapi','trustedManual':'manual',
                            'unknown':None}[evidence['transport']]
        check(expected_transport is None or actual_transport==expected_transport,
              'ASSESSMENT_SOURCE_TRANSPORT_MISMATCH')
        # Bind trusted description to the same provider and only to reviewed
        # operations. A mismatch must not be repaired through fallback.
        check(source_description.get('provider')==provider,
              'ASSESSMENT_SOURCE_PROVIDER_MISMATCH')
        methods=source_description.get('methods')
        check(type(methods) is list and all(type(m) is dict and
              type(m.get('name')) is str for m in methods),
              'ASSESSMENT_SOURCE_METHODS_INVALID')
        check(len({m['name'] for m in methods})==len(methods) and
              {m['name'] for m in methods} <= names,
              'ASSESSMENT_SOURCE_METHOD_MISMATCH')
    costs=dict(_DEFAULT_EFFORT)
    if effort is not None:
        _strict(effort,_DEFAULT_EFFORT,'ASSESSMENT_EFFORT_INVALID')
        check(all(type(x) is int and 0<x<=100 for x in effort.values()),
              'ASSESSMENT_EFFORT_INVALID')
        costs=deepcopy(effort)
    return costs


def _preflight(method_name, source_description):
    """Run real strict compiler on one reviewed source method, no writes."""
    if source_description is None:
        return 'DESCRIPTOR_MISSING'
    methods=source_description['methods']
    found=[m for m in methods if m['name']==method_name]
    if not found:
        return 'DESCRIPTOR_MISSING'
    individual=deepcopy(source_description)
    individual['methods']=found
    try:
        render_package(individual)
    except Denied as exc:
        return str(exc)
    return None


def advise_onboarding(evidence, source_description=None, *, effort=None):
    """Pure decision, with truthful STOP and manual handoff artifacts.

    Only reviews explicit verified facts and runs source compiler preflights.
    It never executes, writes a package, changes policy, or chooses WRITE safety.
    The next technique is a *candidate* pending review, not an instruction to
    silently retry a live request when its outcome is unknown.
    """
    costs=_assessment_input(evidence,source_description,effort)
    descriptor_methods=set() if source_description is None else {
        row['name'] for row in source_description['methods']}
    provider=evidence['provider']
    digest=sha256(canonical({'evidence':evidence,'source':source_description,
                             'costs':costs}).encode()).hexdigest()
    decisions=[]
    for operation in evidence['operations']:
        name=operation['name']
        base=dict(operation=name,selected=None,attempts=[],manualTasks=[],
                  stopReasons=[],estimatedEffort=None)
        if not evidence['reviewed'] or not operation['reviewed']:
            base['stopReasons'].append('SOURCE_EVIDENCE_NOT_REVIEWED')
        if operation['effect']=='UNKNOWN' or operation['verb']=='UNKNOWN' or \
           operation['response']=='unknown' or evidence['transport']=='unknown':
            base['stopReasons'].append('CAPABILITY_DISCOVERY_REQUIRED')
        if operation['effect']=='WRITE' or operation['verb'] in ('POST','PATCH','PUT','DELETE'):
            base['stopReasons'].append('WRITE_EFFECT_REVIEW_REQUIRED')
        if operation['effect']=='READ' and operation['verb'] not in ('GET','UNKNOWN'):
            base['stopReasons'].append('READ_EFFECT_UNSUPPORTED_VERB')
        if not operation['descriptionReady'] and name in descriptor_methods:
            base['stopReasons'].append('UNREVIEWED_METHOD_DESCRIPTION')
        if base['stopReasons']:
            base['manualTasks'].append('Review effect, protocol, trust and method facts; do not generate or send requests.')
            base['status']='REVIEW_REQUIRED'
            decisions.append(base)
            continue
        # For verified GET/READ, do not infer that non-JSON response or custom
        # transport can be auto-executed; manual source is still possible.
        transport_manual=evidence['transport']=='trustedManual'
        custom=operation['customization']
        outcome=_preflight(name,source_description) if operation['descriptionReady'] else 'DESCRIPTOR_MISSING'
        # Security/contract rejections are not capability misses: STOP instead
        # of silently trying weaker source generation.
        if outcome not in (None,'DESCRIPTOR_MISSING') and outcome not in _CAPABILITY_GAPS:
            base['status']='REVIEW_REQUIRED'
            base['stopReasons'].append('SOURCE_PREFLIGHT_SECURITY_OR_CONTRACT_DENIED')
            base['stopReasons'].append(outcome)
            base['manualTasks'].append('Investigate the source contract denial; do not downgrade to a different implementation automatically.')
            decisions.append(base)
            continue
        generic_ready=(operation['response']=='json' and
                       custom!='manualOperation' and outcome is None)
        attempts=[]
        if generic_ready:
            if custom in ('resultPostcheck','contextCheck'):
                effort_cost=costs['compiled']+costs[custom]
                attempts.append(dict(technique='compiledWithTrustedCheck',
                     effort=effort_cost,preflight='PASS',needsManual=True))
                base['manualTasks'].append(
                    'Implement reviewed %s for %s; keep it under source/CI and validate the invariant.'
                    %(custom,name))
            else:
                attempts.append(dict(technique='compiledRead',
                     effort=costs['compiled'],preflight='PASS',needsManual=False))
                # A checked, *additive* business invariant may be cheaper than
                # rewriting a valid compiled READ method. It cannot replace
                # broken projections, missing data or weaker security rules.
                attempts.append(dict(technique='compiledWithTrustedCheck',
                     effort=costs['compiled']+costs['resultPostcheck'],
                     preflight='CONDITIONAL',needsManual=True,
                     reason='ONLY_AFTER_REVIEWED_ADDITIVE_VALIDATION_GAP'))
        elif (operation['response']=='json' and custom!='manualOperation' and
              outcome=='DESCRIPTOR_MISSING'):
            extra=costs[custom] if custom in ('resultPostcheck','contextCheck') else 0
            attempts.append(dict(technique='prepareDescriptorThenCompile',
                 effort=costs['compiled']+costs['draftDescriptor']+extra,
                 preflight='MANUAL_REQUIRED',needsManual=True))
            base['manualTasks'].append('Draft and review method %s descriptor and tests from verified API evidence, then repeat strict compiler preflight.'%name)
            if custom!='none':
                base['manualTasks'].append('Prepare trusted %s for method %s.'%(custom,name))
        else:
            code=('REQUIRES_FULL_OPERATION' if custom=='manualOperation' else
                  'NON_JSON_RESPONSE' if operation['response']!='json' else outcome)
            attempts.append(dict(technique='compiledRead',effort=None,
                                 preflight='UNSUPPORTED',reason=code,needsManual=False))
            if custom!='manualOperation' and operation['response']=='json':
                base['manualTasks'].append('Review unsupported source descriptor for %s; compiler capability diagnostic: %s.'
                                           %(name,outcome))
        # A full custom Operation is always a valid source-level fallback for a
        # *verified* READ/GET, but is never a substitute for trust or owner grants.
        attempts.append(dict(technique='handwrittenOperation',
            effort=costs['manualOperation'],preflight='MANUAL_REQUIRED',needsManual=True))
        if transport_manual:
            base['manualTasks'].append('Provide and review a trusted transport (TLS/CA/auth/route bindings); not a direct caller URL.')
        # We only rank feasible techniques. A lower numerical cost is a local
        # heuristic; safety prerequisites are not traded for effort points.
        feasible=[a for a in attempts if a['preflight'] in ('PASS','MANUAL_REQUIRED')]
        chosen=min(feasible,key=lambda a:(a['effort'],a['technique']))
        # Only tasks for the selected technique belong in the immediate handoff.
        if chosen['technique']=='handwrittenOperation':
            base['manualTasks']=[x for x in base['manualTasks'] if
                                 x.startswith('Provide and review a trusted transport')]
        base['selected']=chosen['technique']
        base['attempts']=sorted(attempts,key=lambda a:(a['effort'] is None, a['effort'] if a['effort'] is not None else 999))
        base['estimatedEffort']=chosen['effort'] + (costs['trustedTransport'] if transport_manual else 0)
        if chosen['technique']=='handwrittenOperation':
            base['manualTasks'].append('Implement a typed Operation with closed schemas, negative tests and standard source review.')
        base['status']='MANUAL_REQUIRED' if base['manualTasks'] or chosen['needsManual'] else 'SOURCE_PREFLIGHT_READY'
        decisions.append(base)
    statuses={v['status'] for v in decisions}
    overall=('REVIEW_REQUIRED' if 'REVIEW_REQUIRED' in statuses else
             'MANUAL_REQUIRED' if 'MANUAL_REQUIRED' in statuses else
             'SOURCE_PREFLIGHT_READY')
    return dict(schemaVersion=1,provider=provider,assessmentDigest=digest,
       status=overall,operations=decisions,workflow=[
        'DISCOVER','ASSESS','REVIEW','SOURCE_PREPARE','TEST','OWNER_RELEASE','LIVE_VERIFY'],
       reminder='Preflight is source-only. Never auto-retry unknown WRITE or bypass owner grants.')


def next_source_attempt(plan, method, failure):
    """Pure fallback after one *source-only* candidate fails validation.

    Only a verified capability mismatch or a repeatable source contract test
    failure may try a less economical technique. An additive validation gap
    can try one trusted result hook, never an arbitrary behavior rewrite.
    Security denial, an unknown
    external effect and any real execution result have no automatic fallback.
    Never replays Core/worker requests, pushes, approvals or HTTP effects.
    """
    check(type(plan) is dict and plan.get('schemaVersion')==1 and
          type(plan.get('operations')) is list, 'ASSESSMENT_PLAN_INVALID')
    ident(method)
    check(failure in ('CAPABILITY_UNSUPPORTED','SOURCE_TEST_MISMATCH',
                      'ADDITIVE_VALIDATION_GAP','SECURITY_OR_UNKNOWN_EFFECT'),
          'ASSESSMENT_FAILURE_INVALID')
    updated=deepcopy(plan)
    rows=[r for r in updated['operations'] if r['operation']==method]
    check(len(rows)==1, 'ASSESSMENT_OPERATION_UNKNOWN')
    row=rows[0]
    check(row['selected'] is not None and row['status']!='REVIEW_REQUIRED',
          'ASSESSMENT_NOT_ATTEMPTABLE')
    previous=row['selected']
    history=row.setdefault('attemptHistory',[])
    history.append({'technique':previous,'result':failure})
    if failure=='SECURITY_OR_UNKNOWN_EFFECT':
        row['selected']=None
        row['status']='REVIEW_REQUIRED'
        row['stopReasons'].append('SOURCE_ATTEMPT_SECURITY_STOP')
        row['manualTasks']=['Investigate the failure; no automatic fallback or effect replay.']
    else:
        admissible=('PASS','MANUAL_REQUIRED','CONDITIONAL') if (
            failure=='ADDITIVE_VALIDATION_GAP') else ('PASS','MANUAL_REQUIRED')
        remaining=[a for a in row['attempts'] if a['technique']!=previous and
                   a['preflight'] in admissible and
                   a['technique'] not in {x['technique'] for x in history}]
        # Move only to a not-yet-tried, strictly higher-effort alternative.
        current=next(a for a in row['attempts'] if a['technique']==previous)
        remaining=[a for a in remaining if a['effort']>current['effort']]
        if not remaining:
            row['status']='REVIEW_REQUIRED';row['selected']=None
            row['stopReasons'].append('NO_SAFE_SOURCE_FALLBACK')
        else:
            next_step=min(remaining,key=lambda a:(a['effort'],a['technique']))
            row['selected']=next_step['technique']
            row['status']='MANUAL_REQUIRED'
            row['estimatedEffort']=next_step['effort']
            row['manualTasks']=['Implement and review %s for %s, preserving previously accepted source artifacts.'
                                %(next_step['technique'],method)]
    statuses={r['status'] for r in updated['operations']}
    updated['status']=('REVIEW_REQUIRED' if 'REVIEW_REQUIRED' in statuses else
                       'MANUAL_REQUIRED' if 'MANUAL_REQUIRED' in statuses else
                       'SOURCE_PREFLIGHT_READY')
    return updated


def main():
    """Inspect only locally supplied source evidence; no mutating action."""
    parser=argparse.ArgumentParser(description='Fortis offline source onboarding assessment')
    parser.add_argument('--evidence',required=True,help='Reviewed capabilities of the API and operations')
    parser.add_argument('--source-description',help='Optional reviewed source generator description')
    args=parser.parse_args()
    facts=loads_strict(Path(args.evidence).read_text(encoding='utf-8'))
    desc=(None if args.source_description is None else
          loads_strict(Path(args.source_description).read_text(encoding='utf-8')))
    print(canonical(advise_onboarding(facts,desc)))


if __name__=='__main__':
    main()

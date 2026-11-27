"""Closed source accounting inputs; no provider authority or merge invocation.

Actual validated impact, CI, source and owner proof must be obtained by a
trusted reader. A matching DTO alone is not evidence verification.
"""
import uuid
from . import semantic_contract as sc
from . import transition_contract as tc

ACTIONS=frozenset(('image-rebuild','config-deploy','windows-update',
                   'package-build','migration-required'))
BASELINE='d27b2cab342521239d1ba7745c4ee4b8d70e66d9'
FINAL_GAP={'number':286,'headSha':'efbae421876cbf5a927d5c9672cabe34c41b15fb',
           'mergeSha':tc.BASE_SHA,'impact':{
               'fortis-gateway':['image-rebuild'],'fortis-registry-pilot':['image-rebuild'],
               'release-label-publisher':['image-rebuild']}}


def proposal(value):
    sc.fields(value,('repository','number','baseSha','headSha','treeSha','catalogSha256',
                     'bodyDigest','impactDigest','pathsDigest','ciDigest','profileDigest',
                     'expectedSourceRevision','classification','targets','dependencyDigest','dependencies'))
    sc.repository(value['repository'])
    sc.need(type(value['number']) is int and 0<value['number']<=1000000)
    for k in ('baseSha','headSha','treeSha'):
        sc.hex_id(value[k],40)
    sc.need(value['baseSha']!=value['headSha'])
    for k in ('catalogSha256','bodyDigest','impactDigest','pathsDigest','ciDigest',
              'profileDigest','dependencyDigest'):
        sc.hex_id(value[k],64)
    sc.revision(value['expectedSourceRevision'])
    rows=value['targets']
    sc.need(type(rows) is list and len(rows)<=200 and value['classification'] in
            ('deployment','no-deployment') and bool(rows)==(value['classification']=='deployment'))
    ids=[]
    for row in rows:
        sc.fields(row,('subject','actions'))
        sc.subject(row['subject'])
        sc.need(row['subject']['repository']==value['repository'])
        ids.append(sc.subject_key(row['subject']))
        actions=row['actions']
        sc.need(type(actions) is list and bool(actions) and all(type(a) is str and a in ACTIONS for a in actions)
                and actions==sorted(set(actions)))
    sc.need(ids==sorted(set(ids)))
    deps=value['dependencies']
    sc.need(type(deps) is list and len(deps)<=256)
    for dep in deps:
        sc.fields(dep,('repository','targetId'))
        sc.repository(dep['repository'])
        sc.name(dep['targetId'])
    sc.need(deps==sorted(deps,key=sc.canonical) and len({sc.canonical(d) for d in deps})==len(deps))
    sc.need(sc.digest(deps)==value['dependencyDigest'],'SOURCE_DEPENDENCY_BINDING')

    sc.need(len(sc.canonical(value).encode())<=32768)
    return sc.loads_strict(sc.canonical(value))


def observation(value,p):
    p=proposal(p)
    sc.fields(value,('repository','number','headSha','mergeSha','mainSha','parents','treeSha',
                     'catalogSha256','bodyDigest','impactDigest','pathsDigest','ciDigest'))
    sc.hex_id(value['mergeSha'],40)
    sc.need(type(value['number']) is int and value['mergeSha'] not in (p['baseSha'],p['headSha'])
            and value['mainSha']==value['mergeSha'] and value['parents']==[p['baseSha'],p['headSha']]
            and all(value[k]==p[k] for k in ('repository','number','headSha','treeSha',
                'catalogSha256','bodyDigest','impactDigest','pathsDigest','ciDigest')),
            'SOURCE_MERGE_EVIDENCE_CHANGED')
    return sc.loads_strict(sc.canonical(value))


def transition(value,p,observed,legacy,scope,manifest_pin):
    sc.fields(value,('manifest','gap','oldStateDigest','gapObservationDigest'))
    m=tc.validate_manifest(value['manifest'])
    sc.hex_id(manifest_pin,64)
    sc.need(sc.digest(m)==manifest_pin and m['old']['registry']==legacy
            and m['old']['catalogSha256']==scope['catalogSha256']
            and scope['repository']==tc.REPOSITORY and scope['baselineSha']==BASELINE
            and value['oldStateDigest']==sc.digest(m['old']),
            'SOURCE_TRANSITION_PREDECESSOR_CHANGED')
    tc.bind_merge(m,observed,expected_manifest_digest=manifest_pin)
    sc.need(p['expectedSourceRevision']==0 and p['baseSha']==tc.BASE_SHA and
            p['number']==m['pr']['number'])
    gap=value['gap']
    sc.fields(gap,('disposition','merges'))
    sc.need(gap['disposition']=='OWNER_REVIEWED_POST_285_CAPTURE_GAP'
            and type(gap['merges']) is list and len(gap['merges'])==31
            and sc.digest(gap['merges'][:-1])==tc.GAP_PREFIX
            and gap['merges'][-1]==FINAL_GAP and sc.digest(gap)==m['old']['historicalGapDigest'],
            'SOURCE_TRANSITION_GAP_CHANGED')
    sc.hex_id(value['gapObservationDigest'],64)
    # Exact legacy cursor, never a generic rebase. Genesis gap is historical,
    # nonzero state must already cover the exact #286 cursor.
    sc.need((legacy['revision']==0 and legacy['cursorSha']==BASELINE) or
            (legacy['revision']>0 and legacy['cursorSha']==tc.BASE_SHA),
            'SOURCE_TRANSITION_CURSOR_UNSUPPORTED')
    return sc.loads_strict(sc.canonical(value))

def merge_expansion(parent_id, value):
    """Shared pure identity contract, also available in the Registry image."""
    sc.uuid_id(parent_id)
    p=proposal(value)
    children=[{'service':'github','operation':'merge_pull_request','version':1},
              {'service':'registry','operation':'register_merge','version':1}]
    recipe={'service':'release','operation':'merge_and_register','version':1,
            'operationKind':'composite','children':children,
            'expansion':'bound_verified_outputs','protectedOwnerGate':True}
    definition_digest=sc.digest(recipe)
    steps=[]
    for ordinal,child in enumerate(children):
        item={'proposal':p}
        if ordinal:item['verifiedMergeStepId']=steps[0]['stepId']
        binding={'parentId':parent_id,'definitionDigest':definition_digest,
                 'ordinal':ordinal,'paramsDigest':sc.digest(p),**child,
                 'payloadDigest':sc.digest(item)}
        steps.append({**binding,'stepId':str(uuid.uuid5(uuid.UUID(parent_id),sc.digest(binding))),
                      'params':item})
    return {'parentId':parent_id,'definitionDigest':definition_digest,
            'paramsDigest':sc.digest(p),'steps':steps}


def source_context(value,p):
    """Identity binding only; authentication/authorization are separate."""
    sc.fields(value,('parentId','stepId','definitionDigest','authorityDigest',
                     'policyAuthorityDigest','fingerprint','policyVersion','owner','target'))
    for k in ('parentId','stepId'):sc.uuid_id(value[k])
    for k in ('definitionDigest','authorityDigest','policyAuthorityDigest','fingerprint'):
        sc.hex_id(value[k],64)
    for k in ('policyVersion','owner','target'):
        sc.need(type(value[k]) is str and 0<len(value[k])<=512)
    expansion=merge_expansion(value['parentId'],p)
    sc.need(value['stepId']==expansion['steps'][1]['stepId'] and
            value['definitionDigest']==expansion['definitionDigest'],
            'SOURCE_CONTEXT_IDENTITY_CHANGED')
    return expansion


def merge_registration(body):
    sc.fields(body,('context','request','mergeReceipt'))
    req=body['request']
    sc.fields(req,('operationId','kind','parentRequestId','proposal','observation',
                   'evidenceDigest','transition'))
    p=proposal(req['proposal'])
    ctx=body['context'];exp=source_context(ctx,p)
    sc.need(req['kind']=='MERGE' and req['transition'] is None and
            req['operationId']==ctx['stepId'] and req['parentRequestId']==ctx['parentId'],
            'SOURCE_CONTEXT_IDENTITY_CHANGED')
    receipt=body['mergeReceipt']
    sc.fields(receipt,('operationId','parentRequestId','proposalDigest',
                       'captureDigest','observation'))
    sc.hex_id(receipt['captureDigest'],64)
    sc.need(receipt['operationId']==exp['steps'][0]['stepId'] and
            receipt['parentRequestId']==ctx['parentId'] and
            receipt['proposalDigest']==sc.digest(p) and
            receipt['observation']==req['observation'] and
            req['evidenceDigest']==sc.digest(receipt),'SOURCE_ORIGINAL_MERGE_RECEIPT_CHANGED')
    observation(req['observation'],p)
    return sc.loads_strict(sc.canonical(body))


def external_operation(parent_id):
    sc.uuid_id(parent_id)
    return str(uuid.uuid5(uuid.UUID(parent_id),'registry-external-merge-v1'))


def external_registration(body):
    sc.fields(body,('request','owner','approvalFingerprint','proofDigest'))
    req=body['request']
    sc.fields(req,('operationId','kind','parentRequestId','proposal','observation',
                   'evidenceDigest','transition'))
    p=proposal(req['proposal'])
    o=observation(req['observation'],p)
    sc.need(req['kind']=='EXTERNAL_MERGE' and req['transition'] is None
            and req['operationId']==external_operation(req['parentRequestId']))
    owner=body['owner']
    sc.need(type(owner) is str and 0<len(owner)<=128)
    for k in ('approvalFingerprint','proofDigest'):
        sc.hex_id(body[k],64)
    sc.need(req['evidenceDigest']==sc.digest(['external-merge-evidence-v1',req['parentRequestId'],
            p,o,owner,body['approvalFingerprint'],body['proofDigest']]),
            'SOURCE_EXTERNAL_APPROVAL_CHANGED')
    return sc.loads_strict(sc.canonical(body))

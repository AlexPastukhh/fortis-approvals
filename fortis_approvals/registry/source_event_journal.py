"""Same Registry DB, bounded independent source cursor and immutable receipts.

Release event anchors interleave source and target events without rewriting
the old v3 prefix or target revision sequence. No live ingress.
"""
from ..core import Conflict, Denied, Stale
from ..integrations.registry_contracts import semantic_contract as sc
from ..integrations.registry_contracts import source_lineage_contract as lc

MAX_SOURCE_EVENTS=64
MAX_SOURCE_BYTES=4_000_000
SCHEMA="""CREATE TABLE source_events(revision INTEGER PRIMARY KEY CHECK(revision>=1),
    operation_id TEXT UNIQUE NOT NULL, release_revision INTEGER NOT NULL,
    release_digest TEXT NOT NULL, request TEXT NOT NULL, previous_digest TEXT NOT NULL,
    event_digest TEXT UNIQUE NOT NULL, receipt TEXT NOT NULL)"""


def request(value,store):
    sc.fields(value,('operationId','kind','parentRequestId','proposal','observation',
                     'evidenceDigest','transition'))
    sc.uuid_id(value['operationId'])
    sc.need(value['kind'] in ('TRANSITION','MERGE','EXTERNAL_MERGE'))
    p=lc.proposal(value['proposal'])
    sc.need(p['repository']==store.scope['repository'])
    lc.observation(value['observation'],p)
    sc.hex_id(value['evidenceDigest'],64)
    if value['kind']=='TRANSITION':
        sc.need(value['parentRequestId'] is None)
        lc.transition(value['transition'],p,value['observation'],store.expected_legacy,
                      store.scope,store.transition_digest)
    else:
        sc.uuid_id(value['parentRequestId'])
        sc.need(value['transition'] is None)
        if value['kind']=='EXTERNAL_MERGE':
            sc.need(value['operationId']==lc.external_operation(value['parentRequestId']))
    sc.need(len(sc.canonical(value).encode())<=131072)
    return sc.loads_strict(sc.canonical(value))


def release_anchor(store,seen,revision):
    sc.revision(revision)
    sc.need(revision<=len(seen),'SOURCE_RELEASE_ANCHOR_CHANGED')
    if revision==0:
        return sc.digest(['registry-v4-release-genesis',store.instance_id,
                          store.expected_legacy,store.transition_digest])
    return list(seen.values())[revision-1][1]['eventDigest']


def replay(store,db,seen):
    count, byte_count = db.execute(
        'SELECT COUNT(*),COALESCE(SUM(length(CAST(request AS BLOB)) + '
        'length(CAST(receipt AS BLOB))),0) FROM source_events'
    ).fetchone()
    sc.need(count <= MAX_SOURCE_EVENTS and byte_count <= MAX_SOURCE_BYTES,
            'SOURCE_EVENT_CAPACITY')
    previous=sc.digest(['registry-v4-source-genesis',store.instance_id,
                        store.expected_legacy,store.transition_digest])
    cursor=store.expected_legacy['cursorSha']
    catalog=store.scope['catalogSha256']
    profile=None
    last_anchor=0
    events={}
    numbers=set()
    merges={cursor}
    for rev,ident,anchor,anchor_digest,raw,prev,event,receipt in db.execute(
            'SELECT * FROM source_events ORDER BY revision'):
        try:
            req=request(sc.loads_strict(raw),store)
        except (ValueError,TypeError,KeyError,UnicodeError,RecursionError):
            raise Denied('SOURCE_EVENT_CHAIN') from None
        p=req['proposal'];o=req['observation']
        sc.need(rev==len(events)+1 and ident==req['operationId'] and raw==sc.canonical(req)
                and ident not in seen and ident not in events and
                not db.execute('SELECT 1 FROM operations WHERE operation_id=?',(ident,)).fetchone()
                and prev==previous and anchor>=last_anchor and
                anchor_digest==release_anchor(store,seen,anchor) and
                p['expectedSourceRevision']==rev-1 and p['number'] not in numbers
                and o['mergeSha'] not in merges,'SOURCE_EVENT_CHAIN')
        if rev==1:
            sc.need(req['kind']=='TRANSITION' and anchor==0,'SOURCE_TRANSITION_FIRST_REQUIRED')
        else:
            sc.need(req['kind'] in ('MERGE','EXTERNAL_MERGE') and p['baseSha']==cursor and
                    p['catalogSha256']==catalog and p['profileDigest']==profile,
                    'SOURCE_CURSOR_OR_EPOCH_CHANGED')
        calculated=sc.digest([previous,rev,anchor,anchor_digest,sc.digest(req)])
        result={'schemaVersion':4,'instanceId':store.instance_id,'operationId':ident,
                'sourceRevision':rev,'sourceCursor':o['mergeSha'],'eventDigest':calculated,
                'requestDigest':sc.digest(req),'kind':req['kind'],'deploymentAuthorized':False,
                'integrityModel':'LOCAL_EVENT_CHAIN_ONLY'}
        sc.need(event==calculated and receipt==sc.canonical(result),'SOURCE_EVENT_CHAIN')
        events[ident]=(req,result,anchor)
        numbers.add(p['number']);merges.add(o['mergeSha'])
        previous,cursor,catalog,profile,last_anchor=calculated,o['mergeSha'],p['catalogSha256'],p['profileDigest'],anchor
    return {'sourceRevision':len(events),'cursor':cursor,'eventDigest':previous,
            'catalogSha256':catalog,'profileDigest':profile,'events':events,
            'eventBytes':byte_count}


def require_merge_capacity(view, proposal):
    # A MERGE stores the canonical proposal once. The remaining request
    # fields (including the fixed-shape observation) and bounded receipt
    # fit in 4096 bytes even with the longest admitted repository name.
    maximum_bytes = len(sc.canonical(proposal).encode()) + 4096
    sc.need(view['sourceRevision'] < MAX_SOURCE_EVENTS and
            view['eventBytes'] + maximum_bytes <= MAX_SOURCE_BYTES,
            'SOURCE_EVENT_CAPACITY')


def append(store,db,req,seen):
    view=replay(store,db,seen)
    ident=req['operationId']
    prior=view['events'].get(ident)
    if prior:
        if prior[0]!=req:raise Conflict('SOURCE_OPERATION_CONFLICT')
        return prior[1]
    p=req['proposal']
    if p['expectedSourceRevision']!=view['sourceRevision']:
        raise Stale('SOURCE_REVISION_CHANGED')
    if view['sourceRevision'] and p['baseSha']!=view['cursor']:
        raise Stale('SOURCE_CURSOR_CHANGED')
    sc.need(view['sourceRevision']<MAX_SOURCE_EVENTS and ident not in seen,'SOURCE_EVENT_CAPACITY_OR_COLLISION')
    rev=view['sourceRevision']+1
    anchor=len(seen);ad=release_anchor(store,seen,anchor)
    event=sc.digest([view['eventDigest'],rev,anchor,ad,sc.digest(req)])
    result={'schemaVersion':4,'instanceId':store.instance_id,'operationId':ident,
            'sourceRevision':rev,'sourceCursor':req['observation']['mergeSha'],'eventDigest':event,
            'requestDigest':sc.digest(req),'kind':req['kind'],'deploymentAuthorized':False,
            'integrityModel':'LOCAL_EVENT_CHAIN_ONLY'}
    raw,receipt=sc.canonical(req),sc.canonical(result)
    sc.need(view['eventBytes']+len(raw.encode())+len(receipt.encode())<=MAX_SOURCE_BYTES,
            'SOURCE_EVENT_CAPACITY')
    db.execute('INSERT INTO source_events VALUES(?,?,?,?,?,?,?,?)',
               (rev,ident,anchor,ad,raw,view['eventDigest'],event,receipt))
    replay(store,db,seen)
    return result

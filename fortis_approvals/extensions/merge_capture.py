"""Private retained exact premerge bytes in the Core companion journal.

No legacy capture/collector ID fabricated. Trusted reader must independently
validate actual PR, raw Git/catalog/paths, policy/CI and impact projection.
This storage and hash check is not that verifier or an owner ceremony.
"""
import hashlib

from ..core import Conflict, Denied
from ..integrations.registry_contracts import semantic_contract as sc
from ..integrations.registry_contracts import source_lineage_contract as lc
from ..integrations.github.post_merge_proof_bindings import _impact_yaml, _paths, EvidenceEnvelopeError
from . import composite_journal as journal

MAX_BYTES=240000
MAX_CAPTURES=128


def validate(material,p):
    p=lc.proposal(p)
    sc.fields(material,('body','catalog','paths','ci','validatedProjectionDigest'))
    for field,limit in (('body',20000),('catalog',120000)):
        sc.need(type(material[field]) is str and 0<len(material[field].encode())<=limit)
    try:
        impact=_impact_yaml(material['body'])
        _paths(material['paths'],{'count':len(material['paths']),'sha256':p['pathsDigest']})
    except (EvidenceEnvelopeError,TypeError,ValueError):
        raise Denied('MERGE_CAPTURE_MATERIAL_INVALID') from None
    sc.need(hashlib.sha256(material['body'].encode()).hexdigest()==p['bodyDigest']
            and hashlib.sha256(material['catalog'].encode()).hexdigest()==p['catalogSha256']
            and hashlib.sha256(impact.encode()).hexdigest()==p['impactDigest']
            and type(material['ci']) is dict and sc.digest(material['ci'])==p['ciDigest'],
            'MERGE_CAPTURE_BYTES_CHANGED')
    # The independent validator must bind these projected actions/deps to
    # actual retained body/catalog/path/CI. No caller assertion is enough.
    sc.need(material['validatedProjectionDigest']==sc.digest({
        'classification':p['classification'],'targets':p['targets'],
        'dependencies':p['dependencies'],'profileDigest':p['profileDigest']}),
        'MERGE_CAPTURE_PROJECTION_CHANGED')
    raw=sc.canonical(material)
    sc.need(len(raw.encode())<=MAX_BYTES,'MERGE_CAPTURE_CAPACITY')
    return sc.loads_strict(raw)


def lookup(db,parent_id):
    row=db.execute('SELECT step_id,material,material_digest FROM composite_merge_captures WHERE parent_id=?',
                   (parent_id,)).fetchone()
    if row is None:return None
    parent,expansion,_=journal._parent(db,parent_id)
    sc.need(sc.loads_strict(parent['payload'])['service']=='release' and
            row[0]==expansion['steps'][0]['stepId'],'MERGE_CAPTURE_PARENT_CHANGED')
    material=validate(sc.loads_strict(row[1]),expansion['steps'][0]['params']['proposal'])
    sc.need(sc.canonical(material)==row[1] and sc.digest(material)==row[2],
            'MERGE_CAPTURE_BYTES_CHANGED')
    return {'stepId':row[0],'materialDigest':row[2],'material':material}


def retain(db,parent_id,step_id,material):
    journal._write_transaction(db)
    parent,expansion,_=journal._parent(db,parent_id)
    view=journal.inspect(db,parent_id)
    sc.need(sc.loads_strict(parent['payload'])['service']=='release'
            and parent['state']=='DISPATCHED' and parent['decision']=='approve'
            and bool(parent['owner']) and step_id==expansion['steps'][0]['stepId']
            and view['steps'][0]['state']=='DISPATCHED',
            'MERGE_CAPTURE_APPROVED_PARENT_REQUIRED')
    proposal=expansion['steps'][0]['params']['proposal']
    checked=validate(material,proposal)
    prior=lookup(db,parent_id)
    if prior is not None:
        if prior['material']!=checked:raise Conflict('MERGE_CAPTURE_CONFLICT')
        return prior
    sc.need(db.execute('SELECT COUNT(*) FROM composite_merge_captures').fetchone()[0]<MAX_CAPTURES,
            'MERGE_CAPTURE_CAPACITY')
    # Retaining the original capture also claims this source revision.
    # BEGIN IMMEDIATE serializes contenders across Core processes. Keep
    # an ambiguous capture reserved pending reviewed receipt accounting.
    taken = db.execute(
        """SELECT 1 FROM composite_merge_captures AS captures
           JOIN requests ON requests.id=captures.parent_id
           WHERE json_extract(requests.payload, '$.params.repository')=?
           AND json_extract(requests.payload, '$.params.expectedSourceRevision')=?
           LIMIT 1""",
        (proposal['repository'], proposal['expectedSourceRevision'])
    ).fetchone()
    sc.need(taken is None,'MERGE_SOURCE_REVISION_RESERVED')
    db.execute('INSERT INTO composite_merge_captures VALUES(?,?,?,?)',
               (parent_id,step_id,sc.canonical(checked),sc.digest(checked)))
    return lookup(db,parent_id)


def inspect(db):
    rows=db.execute('SELECT parent_id FROM composite_merge_captures ORDER BY parent_id LIMIT ?',
                    (MAX_CAPTURES+1,)).fetchall()
    sc.need(len(rows)<=MAX_CAPTURES,'MERGE_CAPTURE_CAPACITY')
    for row in rows:
        ident=row[0]
        capture=lookup(db,ident)
        view=journal.inspect(db,ident)
        sc.need(view['steps'][0]['state'] in ('DISPATCHED','UNKNOWN','CONFIRMED')
                and capture is not None,'MERGE_CAPTURE_ORPHAN')
    # A confirmed merge must have durable original capture; failure before
    # capture may leave UNKNOWN and is not evidence that merge happened.
    for ident, in db.execute("SELECT id FROM requests WHERE json_extract(payload,'$.service')='release' "
                            "AND json_extract(payload,'$.operation')='merge_and_register'"):
        view=journal.inspect(db,ident)
        if view['steps'][0]['state']=='CONFIRMED':
            sc.need(lookup(db,ident) is not None,'MERGE_CAPTURE_MISSING')

"""Core-owned, transaction-bound composite journal V1 (not wired to ingress).

The trusted executor must check live authority, exact child scope, expiry,
maintenance and provider evidence. This module only preserves the intent
and recorded facts; it does not dispatch, authenticate or grant permission.
All writes require the caller's Core BEGIN IMMEDIATE transaction. A child
effect must never start until its DISPATCHED transaction has committed.
"""
import sqlite3
import time

from ..core import Denied, Conflict, canonical, loads_strict
from ..integrations.registry_contracts.semantic_contract import digest, hex_id, need, uuid_id
from .composite_contract import expand_composite

SCHEMA_VERSION = 1
_SCHEMA = (
    "CREATE TABLE composite_meta(version INTEGER PRIMARY KEY CHECK(version=1))",
    """CREATE TABLE composite_instances(
        parent_id TEXT PRIMARY KEY NOT NULL REFERENCES requests(id),
        fingerprint TEXT NOT NULL, definition_digest TEXT NOT NULL,
        expansion_digest TEXT NOT NULL, authority_digest TEXT NOT NULL)""",
    """CREATE TABLE composite_step_events(
        parent_id TEXT NOT NULL REFERENCES composite_instances(parent_id),
        seq INTEGER NOT NULL CHECK(seq>=1), ordinal INTEGER NOT NULL CHECK(ordinal>=0),
        step_id TEXT NOT NULL, state TEXT NOT NULL, at INTEGER NOT NULL, detail TEXT NOT NULL,
        previous_digest TEXT NOT NULL, event_digest TEXT NOT NULL,
        PRIMARY KEY(parent_id,seq))""",
    """CREATE TABLE composite_merge_captures(
        parent_id TEXT PRIMARY KEY NOT NULL REFERENCES composite_instances(parent_id),
        step_id TEXT UNIQUE NOT NULL, material TEXT NOT NULL, material_digest TEXT NOT NULL)""",
)
_TABLE_NAMES = ('composite_meta', 'composite_instances', 'composite_step_events', 'composite_merge_captures')
_TABLES = frozenset(_TABLE_NAMES)
_STATES = frozenset(('DISPATCHED', 'CONFIRMED', 'UNKNOWN', 'BLOCKED',
                    'MERGE_REGISTRATION_STARTED'))
_MAX_EVENTS = 60


def _write_transaction(db):
    need(db.in_transaction and db.execute('PRAGMA query_only').fetchone()[0] == 0,
         'COMPOSITE_WRITE_TRANSACTION_REQUIRED')


def _schema_rows(db):
    return [tuple(row) for row in db.execute(
        "SELECT type,name,tbl_name,sql FROM sqlite_master "
        "WHERE name GLOB 'composite_*' OR tbl_name GLOB 'composite_*' "
        "ORDER BY type,name"
    ) if not row[1].startswith('sqlite_autoindex_')]


def check_schema(db):
    expected = sorted(('table', table, table, sql) for table, sql in zip(
        _TABLE_NAMES, _SCHEMA))
    need(_schema_rows(db) == expected
         and [tuple(row) for row in db.execute('SELECT version FROM composite_meta')] == [(1,)],
         'COMPOSITE_SCHEMA_MISMATCH')


def install_schema(db):
    """Explicit additive migration step, never called at Core startup.

    Only on a reviewed isolated/staged copy. Existing protected migration
    and complete schema/preservation proof are additional prerequisites.
    No implicit migration, deletion, or change to old Core tables.
    """
    _write_transaction(db)
    need(not _schema_rows(db), 'COMPOSITE_SCHEMA_ALREADY_PRESENT')
    need(not db.execute("SELECT 1 FROM requests WHERE state IN "
                        "('PENDING','APPROVED','DISPATCHED') LIMIT 1").fetchone(),
         'COMPOSITE_SCHEMA_IN_FLIGHT')
    for sql in _SCHEMA:
        db.execute(sql)
    db.execute('INSERT INTO composite_meta VALUES(1)')
    check_schema(db)


def _parent(db, parent_id):
    uuid_id(parent_id)
    row = db.execute('SELECT * FROM requests WHERE id=?', (parent_id,)).fetchone()
    need(row is not None, 'COMPOSITE_PARENT_MISSING')
    try:
        payload = loads_strict(row['payload'])
        preview = loads_strict(row['snapshot'])
        need(payload['requestId'] == parent_id, 'COMPOSITE_PARENT_BINDING')
        expansion = expand_composite(payload['service'], payload['operation'],
                                 parent_id, payload['params'])
        need(type(preview) is dict and canonical(preview['composite']) == canonical(expansion),
             'COMPOSITE_PREVIEW_BINDING')
        authority = preview['authorityDigest']
        hex_id(authority, 64)
        fingerprint = digest({'actor': row['actor'], 'request': payload,
                              'policyVersion': row['policy_version'], 'preview': preview})
        need(fingerprint == row['fingerprint'], 'COMPOSITE_PARENT_FINGERPRINT')
        return row, expansion, authority
    except (KeyError, TypeError, ValueError, IndexError, AttributeError) as exc:
        if isinstance(exc, Denied):
            raise
        raise Denied('COMPOSITE_PARENT_BINDING') from None


def bind_parent(db, parent_id):
    """Persist plan binding to the existing Core parent, never a child request."""
    _write_transaction(db)
    check_schema(db)
    row, expansion, authority = _parent(db, parent_id)
    need(row['state'] in ('PENDING', 'APPROVED'), 'COMPOSITE_PARENT_NOT_BINDABLE')
    values = (parent_id, row['fingerprint'], expansion['definitionDigest'],
              digest(expansion), authority)
    existing = db.execute('SELECT * FROM composite_instances WHERE parent_id=?',
                          (parent_id,)).fetchone()
    if existing is not None:
        if tuple(existing) != values:
            raise Conflict('COMPOSITE_PARENT_CONFLICT')
        return
    db.execute('INSERT INTO composite_instances VALUES(?,?,?,?,?)', values)


def _detail(state, step_id, detail):
    need(type(detail) is dict, 'COMPOSITE_EVENT_DETAIL')
    if state == 'DISPATCHED':
        need(detail == {}, 'COMPOSITE_EVENT_DETAIL')
    elif state == 'MERGE_REGISTRATION_STARTED':
        need(set(detail)=={'proofDigest'},'COMPOSITE_EVENT_DETAIL')
        hex_id(detail['proofDigest'],64)
    elif state == 'CONFIRMED':
        # The trusted provider binding verifies the original receipt before
        # recording its digest. The journal stores no arbitrary result/secrets.
        need(set(detail) == {'operationId', 'receiptDigest'}
             and detail['operationId'] == step_id, 'COMPOSITE_RECEIPT_BINDING')
        hex_id(detail['receiptDigest'], 64)
    else:
        need(detail == {}, 'COMPOSITE_EVENT_DETAIL')


def execution_mode(row):
    preview = loads_strict(row['snapshot'])
    mode = preview.get('executionMode', 'SEQUENTIAL')
    need(mode in ('SEQUENTIAL', 'ATOMIC_REGISTRY_LOCAL'), 'COMPOSITE_EXECUTION_MODE')
    need(mode != 'ATOMIC_REGISTRY_LOCAL' or
         loads_strict(row['payload'])['operation'] == 'begin_release_group',
         'COMPOSITE_EXECUTION_MODE')
    return mode


def _advance(steps, ordinal, state, detail, interrupted, *, atomic=False, merge=False):
    need(type(ordinal) is int and 0 <= ordinal < len(steps) and type(state) is str and state in _STATES,
         'COMPOSITE_STEP_INVALID')
    step = steps[ordinal]
    _detail(state, step['stepId'], detail)
    old = step['state']
    if state == 'MERGE_REGISTRATION_STARTED':
        need(merge and not atomic and ordinal==1 and old=='PLANNED'
             and steps[0]['state']=='CONFIRMED','COMPOSITE_MERGE_REGISTRATION_NOT_AVAILABLE')
        step['state']='DISPATCHED'
        step['receipt']=None
        step['recoveryStarted']=True
        return True
    if state in ('DISPATCHED', 'BLOCKED'):
        need(old == 'PLANNED' and not interrupted
             and all(s['state'] == ('DISPATCHED' if atomic and state == 'DISPATCHED' else 'CONFIRMED')
                     for s in steps[:ordinal]),
             'COMPOSITE_STEP_ORDER')
    elif state == 'UNKNOWN':
        need(old == 'DISPATCHED', 'COMPOSITE_STEP_NOT_DISPATCHED')
    else:
        need(old in ('DISPATCHED', 'UNKNOWN'), 'COMPOSITE_STEP_NOT_DISPATCHED')
    step['state'] = state
    step['receipt'] = detail if state == 'CONFIRMED' else None
    return interrupted or state in ('UNKNOWN', 'BLOCKED')


def _replay(db, parent_id):
    check_schema(db)
    row, expansion, authority = _parent(db, parent_id)
    inst = db.execute('SELECT * FROM composite_instances WHERE parent_id=?',
                      (parent_id,)).fetchone()
    need(inst is not None and tuple(inst) == (
        parent_id, row['fingerprint'], expansion['definitionDigest'],
        digest(expansion), authority), 'COMPOSITE_INSTANCE_BINDING')
    steps = [{**s, 'state': 'PLANNED', 'receipt': None} for s in expansion['steps']]
    previous = digest(['composite-journal-v1', list(inst)])
    seq = 0
    interrupted = False
    atomic = execution_mode(row) == 'ATOMIC_REGISTRY_LOCAL'
    merge = loads_strict(row['payload'])['service']=='release'
    for event in db.execute(
            'SELECT * FROM composite_step_events WHERE parent_id=? ORDER BY seq LIMIT ?',
            (parent_id, _MAX_EVENTS + 1)):
        seq += 1
        p, index, ordinal, step_id, state, at, raw, prev, event_digest = tuple(event)
        need(seq <= _MAX_EVENTS and p == parent_id and index == seq
             and type(ordinal) is int and 0 <= ordinal < len(steps)
             and step_id == steps[ordinal]['stepId'] and prev == previous
             and type(at) is int and 0 <= at <= 2**63-1
             and type(raw) is str and len(raw) <= 512,
             'COMPOSITE_EVENT_CHAIN')
        try:
            detail = loads_strict(raw)
            need(canonical(detail) == raw, 'COMPOSITE_EVENT_CHAIN')
        except (ValueError, TypeError, UnicodeError) as exc:
            if isinstance(exc, Denied):
                raise
            raise Denied('COMPOSITE_EVENT_CHAIN') from None
        computed = digest([p, index, ordinal, step_id, state, at, detail, prev])
        need(computed == event_digest, 'COMPOSITE_EVENT_CHAIN')
        interrupted = _advance(steps, ordinal, state, detail, interrupted, atomic=atomic, merge=merge)
        previous = computed
    # Reject terminal Core success unless every required child is confirmed.
    need(row['state'] != 'EXECUTED' or all(s['state'] == 'CONFIRMED' for s in steps),
         'COMPOSITE_PARENT_RESULT_INCOMPLETE')
    need(row['state'] not in ('PENDING', 'APPROVED', 'REJECTED',
                             'EXPIRED', 'REVOKED', 'CANCELLED_BEFORE_DISPATCH', 'STALE')
         or not any(s['state'] in ('DISPATCHED', 'CONFIRMED', 'UNKNOWN') for s in steps),
         'COMPOSITE_PARENT_STATE_CONFLICT')
    return row, steps, seq, previous, interrupted


def inspect(db, parent_id):
    """Passive, local trusted inspection; no provider lookup or authorization."""
    need(db.in_transaction, 'COMPOSITE_READ_TRANSACTION_REQUIRED')
    row, steps, _, _, interrupted = _replay(db, parent_id)
    atomic = execution_mode(row) == 'ATOMIC_REGISTRY_LOCAL'
    if atomic:
        states = {s['state'] for s in steps}
        need(not (states & {'DISPATCHED','CONFIRMED','UNKNOWN'} and states & {'PLANNED','BLOCKED'}),
             'COMPOSITE_ATOMIC_MARKERS_INCOMPLETE')
        need('CONFIRMED' not in states or states == {'CONFIRMED'},
             'COMPOSITE_ATOMIC_RECEIPTS_INCOMPLETE')
    return {'parentId': parent_id, 'parentState': row['state'],
            'interrupted': interrupted,
            'mergeRegistrationStarted':any(s.get('recoveryStarted') for s in steps),
            'steps': [{k: s[k] for k in ('ordinal', 'stepId', 'service', 'operation',
                                        'payloadDigest', 'state', 'receipt')} for s in steps],
            'allConfirmed': all(s['state'] == 'CONFIRMED' for s in steps)}


def append_step(db, parent_id, *, ordinal, step_id, state, detail):
    """Trusted journal append, not a public operation or execution capability.

    The caller must commit before invoking the bound provider. Confirming
    an UNKNOWN step is only for independently verified original readback.
    It cannot re-enable dispatch of any remaining steps in that parent.
    """
    _write_transaction(db)
    row, steps, seq, previous, interrupted = _replay(db, parent_id)
    need(type(ordinal) is int and 0 <= ordinal < len(steps)
         and steps[ordinal]['stepId'] == step_id, 'COMPOSITE_STEP_BINDING')
    need(row['state'] == 'DISPATCHED' or (
         row['state'] == 'UNCERTAIN' and state in ('CONFIRMED', 'UNKNOWN',
                                                  'MERGE_REGISTRATION_STARTED')),
         'COMPOSITE_PARENT_NOT_DISPATCHED')
    if state=='MERGE_REGISTRATION_STARTED':
        need(row['state']=='UNCERTAIN','COMPOSITE_MERGE_REGISTRATION_NOT_AVAILABLE')
    _advance(steps, ordinal, state, detail, interrupted,
             atomic=execution_mode(row) == 'ATOMIC_REGISTRY_LOCAL',
             merge=loads_strict(row['payload'])['service']=='release')
    need(seq < _MAX_EVENTS, 'COMPOSITE_EVENT_LIMIT')
    seq += 1
    at = int(time.time())
    need(0 <= at <= 2**63-1, 'COMPOSITE_EVENT_TIME')
    event_digest = digest([parent_id, seq, ordinal, step_id, state, at, detail, previous])
    try:
        db.execute('INSERT INTO composite_step_events VALUES(?,?,?,?,?,?,?,?,?)',
                   (parent_id, seq, ordinal, step_id, state, at, canonical(detail),
                    previous, event_digest))
    except sqlite3.IntegrityError:
        raise Conflict('COMPOSITE_EVENT_CONFLICT') from None
    return event_digest

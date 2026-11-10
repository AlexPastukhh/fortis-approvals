"""Machine actor-scoped, read-only UNCERTAIN inventory and safe incident triage.

No owner privilege or upstream effects. The explanation is evidence-derived:
it never infers that an unknown remote effect did not occur.
"""
import json

from ..core import Denied


def list_uncertain(core, credential, *, offset=0, limit=100):
    """Bounded Core-backed list for the authenticated initiating actor only.

    Pages are individually consistent SQLite snapshots, not a cross-request
    snapshot. A caller needing a complete stable set should recheck during
    quiescence, not claim completeness while state transitions are active.
    """
    if (type(offset) is not int or not 0 <= offset <= 1000000 or
            type(limit) is not int or not 1 <= limit <= 100):
        raise Denied('INCIDENT_INVENTORY_PAGINATION_INVALID')
    actor = core.auth.authenticate(credential)
    with core._db() as db:
        db.execute('BEGIN')  # one consistent read snapshot for total + page
        total = db.execute(
            "SELECT COUNT(*) FROM requests WHERE actor=? AND state='UNCERTAIN'",
            (actor,)).fetchone()[0]
        rows = db.execute(
            "SELECT id,payload,created_at,failure FROM requests "
            "WHERE actor=? AND state='UNCERTAIN' "
            "ORDER BY created_at DESC,id DESC LIMIT ? OFFSET ?",
            (actor, limit, offset)).fetchall()
    items = []
    for row in rows:
        request = json.loads(row['payload'])
        items.append({
            'requestId': row['id'], 'state': 'UNCERTAIN',
            'service': request['service'], 'operation': request['operation'],
            'target': request['target'], 'createdAt': row['created_at'],
            'failure': row['failure'],
        })
    next_offset = offset+len(items) if offset+len(items) < total else None
    return dict(schemaVersion=1, items=items, total=total, offset=offset,
                limit=limit, truncated=next_offset is not None,
                nextOffset=next_offset)


def diagnose(details):
    """Classify observable stages only, never claim the root cause/effect.

    No raw exception text, worker claim tokens or invented receipts.
    """
    row = details['request']
    worker = details.get('worker')
    receipt = details.get('receipt')
    service = row['request']['service']
    state = row['state']
    if state not in ('UNCERTAIN','CLOSED_UNCONFIRMED'):
        return None  # No incident to triage; do not imply unknown execution.
    events = details.get('events', [])
    start = next((x.get('at') for x in events
                  if x.get('state') == 'DISPATCHED'), None)
    end = next((x.get('at') for x in events
                if x.get('state') == 'UNCERTAIN'), None)
    duration = (end-start if type(start) is int and type(end) is int and end >= start
                else None)
    if receipt is not None:
        phase = 'RECEIPT_PRESENT_REVIEW_CORE_STATE'
    elif worker is not None:
        ws = worker.get('state')
        phase = {
            'CLAIMED': 'WORKER_CLAIMED_NO_FINISH',
            'FAILED': 'WORKER_FAILED_NO_RECEIPT',
            'DONE': 'WORKER_DONE_REVIEW_RECEIPT',
            'QUEUED': 'WORKER_QUEUED_NO_FINISH',
        }.get(ws, 'WORKER_STATE_UNCLASSIFIED')
    elif service == 'github':
        phase = 'GITHUB_RECEIPT_NOT_FOUND'
    elif service == 'workspace':
        phase = 'WORKSPACE_JOB_NOT_FOUND'
    else:
        phase = 'ADAPTER_OUTCOME_UNKNOWN'
    return dict(schemaVersion=1, phase=phase, rootCause='UNDETERMINED',
                originalEffect='UNCONFIRMED',
                workerState=worker.get('state') if worker else None,
                receiptPresent=receipt is not None,
                dispatchToUncertainSeconds=duration,
                note='Read-only evidence classification; not an effect verdict or retry permission.')

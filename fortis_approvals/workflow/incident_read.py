"""Machine actor-scoped, read-only UNCERTAIN inventory and safe incident triage.

No owner privilege or upstream effects. The explanation is evidence-derived:
it never infers that an unknown remote effect did not occur.
"""
import json
import re
import time

from ..core import Denied
from .error_diagnostics import ERROR_CODES, ERROR_STAGES
from .git_backend import GIT_PUSH_FAILURE_CODES, GIT_PUSH_PHASES
from ..integrations.github.gateway.pr_create_diagnostic import PR_CREATE_CODES, PR_CREATE_PHASES


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



def list_requests(core, credential, *, offset=0, limit=100, unresolved_only=True):
    """Global minimal incident inventory for *any authenticated machine actor*.

    The authenticated actor is the caller, not a SQL filter. This is metadata
    only: unlike actor-owned details(), it never exposes payload, parameters,
    preview, receipts, owner approval proof, token or raw audit fields.
    """
    if (type(offset) is not int or not 0 <= offset <= 1000000 or
            type(limit) is not int or not 1 <= limit <= 100 or
            type(unresolved_only) is not bool):
        raise Denied('GLOBAL_INVENTORY_PAGINATION_INVALID')
    core.auth.authenticate(credential)
    state_filter = (" WHERE state IN ('PENDING','APPROVED','DISPATCHED','UNCERTAIN')"
                    if unresolved_only else '')
    with core._db() as db:
        db.execute('BEGIN')
        total = db.execute('SELECT COUNT(*) FROM requests'+state_filter).fetchone()[0]
        counts = dict(db.execute('SELECT state,COUNT(*) FROM requests'+
                                 state_filter+' GROUP BY state'))
        rows = db.execute(
            'SELECT id,actor,state,payload,created_at FROM requests'+
            state_filter+' ORDER BY created_at DESC,id DESC LIMIT ? OFFSET ?',
            (limit, offset)).fetchall()
    items = []
    for row in rows:
        request = json.loads(row['payload'])
        items.append({
            'requestId':row['id'], 'actor':row['actor'],
            'state':row['state'], 'service':request['service'],
            'operation':request['operation'], 'target':request['target'],
            'createdAt':row['created_at'],
        })
    next_offset = offset+len(items) if offset+len(items) < total else None
    return dict(schemaVersion=1, readOnly=True, actorScoped=False,
                unresolvedOnly=unresolved_only, stateCounts=counts,
                items=items, total=total, offset=offset, limit=limit,
                truncated=next_offset is not None, nextOffset=next_offset)

def _bounded_core_error(value):
    if (type(value) is not dict or not {'stage','code'} <= set(value)
            or not set(value) <= {'stage','code','phase','gitPhase'}):
        return False
    if 'gitPhase' in value:
        from .artifact_diagnostics import ARTIFACT_VALIDATION_PHASES
        if (value.get('stage')!='GITHUB_ADAPTER' or
                value.get('code') not in GIT_PUSH_FAILURE_CODES or
                type(value['gitPhase']) is not str or
                value['gitPhase'] not in ARTIFACT_VALIDATION_PHASES or 'phase' not in value):
            return False
    if (type(value['stage']) is not str or value['stage'] not in ERROR_STAGES or
            type(value['code']) is not str or value['code'] not in ERROR_CODES):
        return False
    if 'phase' in value:
        if value['stage']!='GITHUB_ADAPTER' or type(value['phase']) is not str:
            return False
        return (
            value['code'] in GIT_PUSH_FAILURE_CODES and value['phase'] in GIT_PUSH_PHASES or
            value['code'] in PR_CREATE_CODES and value['phase'] in PR_CREATE_PHASES
        )
    return True


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
    # Event details are persisted at the effect boundary, not reconstructed
    # from provider error strings. Pagination can omit the event: return null.
    core_error = next((e.get('detail') for e in reversed(events)
                       if e.get('state')=='ERROR_OBSERVED' and
                       _bounded_core_error(e.get('detail'))),None)
    worker_error = worker.get('diagnostic') if worker is not None else None
    return dict(schemaVersion=1, phase=phase, rootCause='UNDETERMINED',
                coreError=core_error, workerError=worker_error,
                originalEffect='UNCONFIRMED',
                workerState=worker.get('state') if worker else None,
                receiptPresent=receipt is not None,
                dispatchToUncertainSeconds=duration,
                note='Read-only evidence classification; not an effect verdict or retry permission.')


def diagnose_v2(details):
    # One bounded, read-only incident projection for AI clients. The V1
    # projection is preserved byte-for-byte for older clients, and no raw
    # payload, error text, claim, provider URL or credential is copied here.
    legacy=diagnose(details)
    if legacy is None:
        return None
    row=details.get('request')
    ident=row.get('requestId') if type(row) is dict else None
    if type(ident) is not str:
        raise Denied('INCIDENT_DIAGNOSTIC_REQUEST_ID_INVALID')
    code='UNDETERMINED'
    origin='CORE_STATE'
    phase=legacy['phase']
    core_error=legacy.get('coreError')
    worker_error=legacy.get('workerError')
    if _bounded_core_error(core_error):
        origin=core_error['stage']
        code=core_error['code']
        phase=core_error.get('phase',phase)
    elif (type(worker_error) is dict and
          set(worker_error)=={'stage','code'} and
          type(worker_error['stage']) is str and
          worker_error['stage'] in ERROR_STAGES and
          type(worker_error['code']) is str and
          worker_error['code'] in ERROR_CODES):
        origin=worker_error['stage']
        code=worker_error['code']
    events=details.get('events')
    total=details.get('eventTotal')
    offset=details.get('eventOffset')
    complete=(type(events) is list and type(total) is int and
              type(offset) is int and offset==0 and total==len(events))
    return {
        'schemaVersion':2,
        'requestId':ident,
        'origin':origin,
        'phase':phase,
        'code':code,
        'effectAssessment':'UNCONFIRMED',
        'evidenceScope':'FULL_AUDIT_PAGE' if complete else 'PARTIAL_AUDIT_PAGE',
    }

# Bound the client-side read-only composite without changing Core state.
_UUID = re.compile(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\Z")
_SHA = re.compile(r"[0-9a-f]{40}\Z")
_MAX_EVENTS = 10000
_MAX_PAGES = 10

def _safe_identity(intent):
    """Whitelist identifiers only; never reflect request bodies or credentials."""
    p = intent.get('params', {})
    if type(p) is not dict:
        p = {}
    out = {}
    for key in ('task', 'head', 'base', 'branch', 'ref', 'runId'):
        value = p.get(key)
        if type(value) is str and len(value) <= 120 and re.fullmatch(r'[A-Za-z0-9_./-]+', value):
            out[key] = value
    for key in ('expectedHeadSha', 'newSha', 'baseSha', 'sourceSha', 'artifactSha256'):
        value = p.get(key)
        if type(value) is str and (_SHA.fullmatch(value) or (key == 'artifactSha256' and re.fullmatch(r'[0-9a-f]{64}', value))):
            out[key] = value
    if type(p.get('number')) is int and 0 < p['number'] <= 1000000:
        out['number'] = p['number']
    return out





def _safe_diagnostic(value, events):
    """Only stable safe diagnostic categories from deployed/PR1 evidence."""
    def clean(row):
        if type(row) is not dict:
            return None
        if not _bounded_core_error(row):
            return None
        return {key:row[key] for key in ('stage','phase','code','gitPhase') if key in row}
    observed=[clean(e.get('detail')) for e in events if e.get('state')=='ERROR_OBSERVED']
    observed=[row for row in observed if row]
    legacy=clean(value.get('coreError')) if type(value) is dict else None
    selected=observed[-1] if observed else legacy
    worker=value.get('workerError') if type(value) is dict else None
    if selected is None and type(worker) is dict and set(worker)=={'stage','code'}:
        if worker.get('stage') in ERROR_STAGES and worker.get('code') in ERROR_CODES:
            selected=worker
    checkpoints=[e['state'] for e in events if e.get('state') in
                 ('PR_CREATE_POST_STARTED','PR_CREATE_POST_ACKNOWLEDGED')]
    phase=(selected.get('phase') if selected and selected.get('phase') else
           checkpoints[-1] if checkpoints else
           value.get('phase') if type(value) is dict and
               type(value.get('phase')) is str and
               re.fullmatch(r'[A-Z0-9_]{1,80}',value['phase']) else 'UNDETERMINED')
    return {'origin':selected['stage'] if selected else 'CORE_STATE',
            'phase':phase,
            'code':selected['code'] if selected else 'UNDETERMINED',
            'server':legacy, 'observed':observed, 'rootCause':'UNDETERMINED'}


class IncidentInspector:
    def __init__(self, client):
        self.client = client

    def inspect(self, request_id, *, github_reads=True):
        """Aggregate bounded Core pages and typed provider READ, without writes.

        A changed audit snapshot or unavailable evidence remains UNCONFIRMED.
        Never calls result(reconcile=True), command(), resume() or claim().
        """
        if type(request_id) is not str or not _UUID.fullmatch(request_id):
            raise Denied('INCIDENT_INSPECT_UUID_INVALID')
        if type(github_reads) is not bool:
            raise Denied('INCIDENT_INSPECT_OPTIONS_INVALID')
        cap = self.client.gateway.post('/v1/workspace/capabilities', {})
        inventory = cap.get('globalRequestInventory', {})
        if (type(inventory) is not dict or inventory.get('readOnly') is not True or
                inventory.get('crossActorDetails') is not True):
            raise Denied('INCIDENT_INSPECT_GATEWAY_NOT_SUPPORTED')

        first = self.client.details(request_id, event_offset=0, event_limit=100)
        record = first['request']
        intent = record['request']
        if type(intent) is not dict or type(record.get('state')) is not str:
            raise Denied('INCIDENT_INSPECT_RESPONSE_INVALID')
        total = first['eventTotal']
        if type(total) is not int or total < 0:
            raise Denied('INCIDENT_INSPECT_RESPONSE_INVALID')
        events = []
        missing = []
        offset = 0
        if total > _MAX_EVENTS:
            missing.append('AUDIT_LIMIT')
        else:
            while offset < total:
                page = first if offset == 0 else self.client.details(
                    request_id, event_offset=offset, event_limit=100)
                if (page.get('eventTotal') != total or
                        page.get('request', {}).get('fingerprint') != record.get('fingerprint') or
                        page.get('request', {}).get('state') != record['state'] or
                        page.get('eventOffset') != offset or
                        type(page.get('events')) is not list):
                    missing.append('AUDIT_SNAPSHOT_CHANGED')
                    break
                chunk = page['events']
                if (len(chunk) != min(100, total - offset) or
                        any(type(x) is not dict for x in chunk)):
                    missing.append('AUDIT_PAGE_INVALID')
                    break
                # Core seq is global across requests, so other actors can
                # allocate IDs between these rows. Per-request offsets/counts
                # prove coverage; IDs must stay positive and strictly ordered.
                sequence = [row.get('seq') for row in chunk]
                if (any(type(value) is not int or value <= 0 for value in sequence) or
                        any(right <= left for left, right in zip(sequence, sequence[1:])) or
                        (events and sequence[0] <= events[-1]['seq'])):
                    missing.append('AUDIT_SEQUENCE_INVALID')
                    break
                events.extend(chunk)
                offset += len(chunk)
        if total == 0:
            missing.append('AUDIT_EMPTY')
        if not missing:
            check = self.client.details(request_id, event_offset=0, event_limit=1)
            if (check.get('eventTotal') != total or
                    check.get('request', {}).get('fingerprint') != record.get('fingerprint') or
                    check.get('request', {}).get('state') != record['state'] or
                    check.get('worker') != first.get('worker') or
                    check.get('receipt') != first.get('receipt')):
                missing.append('EVIDENCE_CHANGED_DURING_READ')

        worker = first.get('worker')
        receipt = first.get('receipt')
        worker_state = worker.get('state') if type(worker) is dict else None
        worker_evidence = {
            'state':worker_state, 'quiescenceProven':False,
            'claimedAt':worker.get('claimedAt') if type(worker) is dict and
                type(worker.get('claimedAt')) is int else None,
            'lastHeartbeatAt':worker.get('lastHeartbeatAt') if type(worker) is dict and
                type(worker.get('lastHeartbeatAt')) is int else None,
        }
        receipt_source = (receipt.get('source') if type(receipt) is dict and
                          receipt.get('source') in ('native-worker-job','github-receipts')
                          else None)
        visual = first.get('visualReview')
        visual_evidence = None
        if type(visual) is dict:
            visual_evidence = {
                'issueNumber':visual.get('issueNumber') if type(visual.get('issueNumber')) is int else None,
                'uploadedFiles':visual.get('uploadedFiles') if type(visual.get('uploadedFiles')) is int else None,
                'reservationObserved':True,
            }
        core_state = record['state']
        states = [x.get('state') for x in events]
        has_dispatch = 'DISPATCHED' in states
        confirmed_none = (core_state == 'CANCELLED_BEFORE_DISPATCH'
                          and not missing and not has_dispatch
                          and 'CANCELLED_BEFORE_DISPATCH' in states
                          and worker is None and receipt is None)
        receipt_result = receipt.get('result') if type(receipt) is dict else None
        bound_receipt = (receipt_source is not None and type(receipt_result) is dict and
            receipt_result.get('requestId') == request_id and
            receipt_result.get('operation') == intent.get('operation') and
            receipt_result.get('repository') == intent.get('target'))
        confirmed_done = (core_state == 'EXECUTED' and bound_receipt and
                          record.get('result') == receipt_result)
        assessment = ('CONFIRMED_EXECUTED' if confirmed_done else
                      'CONFIRMED_NOT_EXECUTED' if confirmed_none else 'UNCONFIRMED')
        identity = _safe_identity(intent)
        provider = {'status':'NOT_APPLICABLE'}
        if intent.get('service') == 'github':
            provider = {'status':'NOT_REQUESTED' if not github_reads else 'UNAVAILABLE'}
            if github_reads:
                repo = intent.get('target')
                if type(repo) is str and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,99}',repo):
                    try:
                        op = intent.get('operation')
                        if op in ('create_pull_request', 'push_commits'):
                            branch = identity.get('head') if op == 'create_pull_request' else 'task/'+identity.get('task', '')
                            if type(branch) is str and re.fullmatch(r'task/[a-z0-9][a-z0-9-]{0,99}',branch):
                                matched = []
                                complete = False
                                for page in range(1,_MAX_PAGES+1):
                                    data = self.client.github.list_pull_requests(repo,state='all',page=page,per_page=30)
                                    matched.extend({'number':i['number'],'headSha':i['head']['sha']}
                                        for i in data['items'] if i['head']['ref']==branch)
                                    # Legacy typed PR READ has no hasNextPage flag.
                                    if len(data['items']) < 30:
                                        complete = True
                                        break
                                provider = {'status':'OBSERVED' if complete else 'PARTIAL',
                                            'matchingPullRequests':matched[:30],
                                            'scope':'BOUNDED_PULL_REQUEST_LIST',
                                            'effectAttribution':'UNKNOWN'}
                                if not complete:
                                    missing.append('PROVIDER_PAGINATION_LIMIT')
                                if op == 'push_commits':
                                    branch_done = False
                                    observed_sha = None
                                    for n in range(1,_MAX_PAGES+1):
                                        branches = self.client.github.list_branches(repo,page=n,per_page=100)['items']
                                        for item in branches:
                                            if item['name'] == branch:
                                                observed_sha = item['sha']
                                        if len(branches) < 100:
                                            branch_done = True
                                            break
                                    provider['remoteBranchSha'] = observed_sha
                                    provider['desiredHeadObserved'] = (
                                        observed_sha == identity.get('newSha'))
                                    provider['branchReadComplete'] = branch_done
                                    if not branch_done:
                                        missing.append('PROVIDER_BRANCH_LIMIT')
                        elif op == 'create_branch':
                            branch = identity.get('branch')
                            expected = identity.get('sourceSha')
                            if (type(branch) is str and type(expected) is str and
                                    re.fullmatch(r'task/[a-z0-9][a-z0-9-]{0,99}', branch)):
                                observed_sha = None
                                complete = False
                                for page in range(1, _MAX_PAGES+1):
                                    rows = self.client.github.list_branches(
                                        repo, page=page, per_page=100)['items']
                                    for item in rows:
                                        if item['name'] == branch:
                                            observed_sha = item['sha']
                                    if len(rows) < 100:
                                        complete = True
                                        break
                                provider = {
                                    'status': 'OBSERVED' if complete else 'PARTIAL',
                                    'scope': 'BOUNDED_BRANCH_LIST',
                                    'remoteBranchSha': observed_sha,
                                    'desiredHeadObserved': observed_sha == expected,
                                    'branchReadComplete': complete,
                                    'effectAttribution': 'UNKNOWN',
                                }
                                if not complete:
                                    missing.append('PROVIDER_BRANCH_LIMIT')
                        elif op in ('merge_pull_request', 'mark_pr_ready'):
                            number = identity.get('number')
                            expected = identity.get('expectedHeadSha')
                            if type(number) is int and type(expected) is str:
                                pr = self.client.github.get_pull_request(
                                    repo, number)['pullRequest']
                                matching = pr['head']['sha'] == expected
                                desired = (pr['merged'] is True and
                                           pr['state'] == 'closed' and matching
                                           if op == 'merge_pull_request' else
                                           pr['draft'] is False and
                                           pr['state'] == 'open' and matching)
                                provider = {
                                    'status': 'OBSERVED',
                                    'scope': 'EXACT_PULL_REQUEST_READ',
                                    'pullNumber': number,
                                    'pullState': pr['state'],
                                    'headShaMatches': matching,
                                    'mergedObserved': pr['merged'],
                                    'desiredStateObserved': desired,
                                    'effectAttribution': 'UNKNOWN',
                                }
                        elif op == 'publish_visual_review':
                            run_id = identity.get('runId')
                            if run_id:
                                result = self.client.github.find_visual_review_run(repo,run_id,max_pages=_MAX_PAGES)
                                provider = {'status':'OBSERVED' if result['complete'] else 'PARTIAL',
                                            'matchedIssueNumber':result['issue']['number'] if result['found'] else None,
                                            'scope':'BOUNDED_ISSUE_RUN_MARKER'}
                                if not result['complete']:
                                    missing.append('PROVIDER_PAGINATION_LIMIT')
                        else:
                            provider = {'status':'UNSUPPORTED_OPERATION'}
                    except Exception:
                        provider = {'status':'READ_UNAVAILABLE'}
                        missing.append('PROVIDER_READ_UNAVAILABLE')
                else:
                    provider = {'status':'INVALID_TARGET'}
                    missing.append('PROVIDER_TARGET_INVALID')
        # A confirmed remote target state is not proof of which UUID caused it.
        target_reached = ((provider.get('desiredHeadObserved') is True and
                           provider.get('branchReadComplete') is True) or
                          provider.get('desiredStateObserved') is True)
        partial_issue = (core_state in ('UNCERTAIN','DISPATCHED','CLOSED_UNCONFIRMED') and
                         visual_evidence is not None and receipt is None and
                         visual_evidence['issueNumber'] is not None and
                         visual_evidence['uploadedFiles'] is not None and
                         type(intent.get('params',{}).get('media')) is list and
                         visual_evidence['uploadedFiles'] < len(intent['params']['media']))
        if confirmed_done and not any(x.startswith('AUDIT_') or
                                       x=='EVIDENCE_CHANGED_DURING_READ' for x in missing):
            outcome = 'ORIGINAL_EXECUTED_CONFIRMED'
        elif confirmed_none:
            outcome = 'ORIGINAL_NOT_EXECUTED_CONFIRMED'
        elif partial_issue:
            outcome = 'PARTIAL_EFFECT_CONFIRMED'
        elif target_reached:
            outcome = 'TARGET_STATE_CONFIRMED_ATTRIBUTION_UNKNOWN'
        else:
            outcome = 'OUTCOME_UNCONFIRMED'
        observed_at = int(time.time())
        if not bound_receipt and core_state in ('EXECUTED','UNCERTAIN','DISPATCHED','CLOSED_UNCONFIRMED'):
            missing.append('BOUND_RECEIPT_NOT_CONFIRMED')
        # Provider observations never attribute a remote effect to this UUID.
        diagnostic=_safe_diagnostic(first.get('diagnostic'),events)
        protocol=cap.get('diagnosticContract')
        protocol_version=('v2' if type(protocol) is dict and
                          protocol.get('schemaVersion')==2 else 'legacy')
        return {
            'schemaVersion':2, 'requestId':request_id, 'actor':record.get('actor'),
            'assessedAt':observed_at, 'evidenceFreshness':'OBSERVED_AT_REQUEST_TIME',
            'evidenceScope':{'core':'BOUNDED_PAGINATED_DETAILS',
                             'worker':'GATEWAY_DURABLE_JOB_ROW' if worker is not None else 'NOT_PRESENT',
                             'receipt':receipt_source or 'NOT_PRESENT',
                             'provider':provider.get('scope','NONE')},
            'outcomeAssessment':outcome,
            'operation':str(intent.get('service',''))+'.'+str(intent.get('operation','')),
            'target':intent.get('target'), 'coreState':core_state,
            'identity':identity, 'workerState':worker_state,
            'worker':worker_evidence,
            'workerHeartbeat':'UNCONFIRMED' if worker_state == 'CLAIMED' else 'NOT_PROVEN',
            'receiptPresent':receipt is not None,
            'receiptSource':receipt_source,
            'receiptBoundToRequest':bound_receipt,
            'visualReview':visual_evidence,
            'audit':{'eventTotal':total,'eventsCollected':len(events),
                     'complete':not bool([x for x in missing if x.startswith('AUDIT_') or x=='EVIDENCE_CHANGED_DURING_READ']),
                     'dispatchedObserved':has_dispatch,
                     'errorCodes':[d['code'] for e in events
                         if e.get('state')=='ERROR_OBSERVED'
                         for d in [e.get('detail')] if _bounded_core_error(d)]},
            'provider':provider,
            'diagnostic':diagnostic,
            'origin':diagnostic['origin'],
            'phase':diagnostic['phase'],
            'code':diagnostic['code'],
            'diagnosticContract':protocol_version,
            'assessment':('CONFIRMED_EXECUTED' if outcome=='ORIGINAL_EXECUTED_CONFIRMED' else
                          'CONFIRMED_NOT_EXECUTED' if outcome=='ORIGINAL_NOT_EXECUTED_CONFIRMED' else
                          'UNCONFIRMED'),
            'effectAttribution':'CORE_RECEIPT_CONFIRMED' if confirmed_done else 'NOT_PROVEN',
            'missingEvidence':sorted(set(missing)),
            'retryAuthorization':'NONE',
            'nextAction':'READ_ONLY_REVIEW' if outcome!='ORIGINAL_NOT_EXECUTED_CONFIRMED' else 'NEW_INTENT_REQUIRES_FRESH_AUTHORIZATION',
        }

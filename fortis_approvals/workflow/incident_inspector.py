"""Read-only incident evidence projection. Never authorizes another effect."""
import re
import time

from ..core import Denied
from .incident_read import _bounded_core_error
from .error_diagnostics import ERROR_CODES, ERROR_STAGES

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
    for key in ('expectedHeadSha', 'newSha', 'baseSha', 'artifactSha256'):
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
        return {key:row[key] for key in ('stage','phase','code') if key in row}
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
                if not chunk or len(chunk) > 100 or any(type(x) is not dict for x in chunk):
                    missing.append('AUDIT_PAGE_INVALID')
                    break
                if events and chunk[0].get('seq') != events[-1].get('seq', -2) + 1:
                    missing.append('AUDIT_SEQUENCE_GAP')
                    break
                if any(chunk[j].get('seq') != chunk[j-1].get('seq', -2)+1 for j in range(1,len(chunk))):
                    missing.append('AUDIT_SEQUENCE_GAP')
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
        target_reached = (provider.get('desiredHeadObserved') is True and
                          provider.get('branchReadComplete') is True)
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


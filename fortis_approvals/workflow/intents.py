"""Repo-side intent continuation. Every new effect attempt gets a fresh UUID.

The journal is coordination/evidence, never authorization. Existing Gateway
admission, CAS, owner ASK and single-delivery worker protections still apply.
"""
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
import re
from pathlib import Path
import sqlite3
import tempfile
import time
import uuid

from ..core import Denied, canonical
from ..clients.retries import RetryPolicy, transient
from .common import require, secure_dir, repository_lock
from .artifact_diagnostics import ARTIFACT_FAILURE_CODES, ARTIFACT_VALIDATION_PHASES
from ..integrations.github.publisher_evidence import own_label_evidence, allow_intent_details, check_own_record
from ..integrations.github.release_label_evidence import release_label_receipt_matches

WORKSPACE_COMMANDS = frozenset({'create_task', 'update_main', 'update_main_from_pr'})
GITHUB_COMMANDS = frozenset({'create_pull_request', 'create_branch', 'mark_pr_ready',
                            'update_pull_request', 'add_pr_release_labels',
                            'remove_pr_release_label'})
_ACTIVE = frozenset({'PENDING', 'APPROVED', 'DISPATCHED'})
_FINAL_DENIAL = frozenset({'DENIED', 'REJECTED', 'REVOKED', 'EXPIRED', 'STALE'})
_STATES = _ACTIVE | _FINAL_DENIAL | {'NOT_FOUND', 'EXECUTED', 'UNCERTAIN',
                                    'CLOSED_UNCONFIRMED', 'CANCELLED_BEFORE_DISPATCH'}


def _uuid(value):
    try:
        require(type(value) is str and str(uuid.UUID(value)) == value,
                'INTENT_ID_INVALID')
    except (ValueError, AttributeError):
        raise Denied('INTENT_ID_INVALID') from None
    return value


def _call_failure(exc, request_id, elapsed_ms):
    """Fixed evidence tied to the local attempt, including pre-Core failures."""
    evidence = dict(requestId=request_id, origin='REPO_CALL',
                    code='INTENT_CALL_FAILED', elapsedMs=elapsed_ms)
    code = exc.args[0] if len(exc.args) == 1 else None
    allowed = {'FORTIS_HTTP_' + str(n) for n in (400, 401, 403, 409, 422, 429, 500, 502, 503, 504)}
    allowed |= {'FORTIS_UPSTREAM_UNAVAILABLE_OR_INVALID', 'FORTIS_PRE_CORE_VALIDATION_REJECTED',
                'WORKFLOW_WORKER_WAIT_TIMEOUT'}
    if isinstance(exc, TimeoutError): evidence['code'] = 'TRANSPORT_TIMEOUT'
    elif isinstance(exc, ConnectionError): evidence['code'] = 'TRANSPORT_CONNECTION_FAILED'
    elif type(code) is str and code in allowed: evidence['code'] = code
    elif type(code) is str:
        for stage in ('ARTIFACT', 'FETCH'):
            prefix = 'FORTIS_' + stage + '_'
            if not code.startswith(prefix): continue
            tail = code[len(prefix):]
            if tail in ARTIFACT_FAILURE_CODES:
                evidence.update(code=code, stage=stage)
            for phase in ARTIFACT_VALIDATION_PHASES:
                if tail.endswith('_' + phase) and tail[:-len(phase)-1] in ARTIFACT_FAILURE_CODES:
                    evidence.update(code=code, stage=stage, phase=phase)
    return evidence


class IntentJournal:
    def __init__(self, root):
        self.root = Path(root)

    @contextmanager
    def locked(self, ident):
        _uuid(ident)
        root = secure_dir(self.root)
        fd = os.open(root / (ident + '.lock'),
                     os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'a+b') as stream:
            info = os.fstat(stream.fileno())
            require(info.st_uid == os.geteuid() and info.st_mode & 0o777 == 0o600,
                    'INTENT_JOURNAL_PERMISSIONS')
            try:
                fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise Denied('INTENT_BUSY') from None
            yield

    def load(self, ident):
        path = self.root / (_uuid(ident) + '.json')
        if not path.exists():
            return None
        require(not path.is_symlink() and path.is_file() and
                path.stat().st_uid == os.geteuid() and
                path.stat().st_mode & 0o777 == 0o600 and
                path.stat().st_size <= 1048576, 'INTENT_JOURNAL_PERMISSIONS')
        return json.loads(path.read_text())

    def save(self, record):
        path = self.root / (_uuid(record['intentId']) + '.json')
        fd, temporary = tempfile.mkstemp(prefix='.intent-', dir=self.root)
        try:
            with os.fdopen(fd, 'w') as stream:
                stream.write(canonical(record)); stream.flush(); os.fsync(stream.fileno())
            os.replace(temporary, path)
            directory = os.open(self.root, os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)


class IntentClient:
    def __init__(self, client, *, root='/workspace/repo/.fortis-command-intents',
                 retry_policy=None):
        self.client = client
        self.journal = IntentJournal(root)
        self.policy = retry_policy or RetryPolicy()
        self._capability_snapshot = None

    def _capabilities(self):
        reader = getattr(self.client, 'capabilities', None)
        if callable(reader):
            return reader()
        if self._capability_snapshot is None:
            value = self.client.gateway.post('/v1/workspace/capabilities', {})
            require(type(value) is dict, 'WORKFLOW_CAPABILITIES_RESPONSE_INVALID')
            self._capability_snapshot = value
        return self._capability_snapshot

    def _target_reads(self):
        value = self._capabilities().get('githubTargetReads')
        return (type(value) is dict and type(value.get('version')) is int and
                value['version'] == 1 and value.get('branch') == 'repository-access-checked-v1' and
                value.get('pullRequests') == 'same-repository-head-base-v1')

    def command(self, operation, repository, params, *, request_id=None,
                reason='Authorized workspace intent', wait_owner=False):
        require(operation in WORKSPACE_COMMANDS, 'INTENT_OPERATION_UNSUPPORTED')
        return self._start('workspace', operation, repository, params,
                           request_id, reason, wait_owner=wait_owner)

    def publish(self, repository, task, expected_old, new_sha, *, request_id=None,
                reason='Authorized task publication'):
        return self._start('publish', 'push_commits', repository,
            dict(task=task, expectedHeadSha=expected_old, newSha=new_sha), request_id, reason)

    def github_action(self, operation, repository, params, *, request_id=None,
                      reason='Authorized GitHub intent', journal_evidence=None):
        require(operation in GITHUB_COMMANDS, 'INTENT_OPERATION_UNSUPPORTED')
        # Caller evidence is private journal data, never Gateway authorization.
        # Existing intent identity and attempt/receipt machinery are unchanged.
        seed = None
        if journal_evidence is not None:
            require(type(journal_evidence) is dict and
                    len(canonical(journal_evidence).encode()) <= 65536,
                    'INTENT_JOURNAL_EVIDENCE_INVALID')
            seed = {'callerEvidence': json.loads(canonical(journal_evidence))}
        return self._start('github', operation, repository, params, request_id, reason, _seed=seed)

    def publish_visual_review(self, *, request_id=None, reason, **kwargs):
        preview = self.client.github.prepare_visual_review(**{
            k: v for k, v in kwargs.items() if k != 'expected_payload_sha256'})
        expected = kwargs.get('expected_payload_sha256')
        require(expected is None or expected == preview['payloadSha256'],
                'GITHUB_VISUAL_REVIEW_PREVIEW_CHANGED')
        kwargs = {**kwargs, 'expected_payload_sha256': preview['payloadSha256']}
        return self._start('visual', 'publish_visual_review', kwargs['repository'],
                           kwargs, request_id, reason)

    def _start(self, kind, operation, repository, params, ident, reason, *,
               _intent_id=None, _seed=None, **options):
        intent = json.loads(canonical(dict(kind=kind, operation=operation,
            repository=repository, params=params, reason=reason, options=options)))
        endpoint = getattr(self.client.gateway, 'endpoint', '')
        # Identical calls without a supplied ID resume the same logical intent.
        # It is separate from the UUIDs of the individual Gateway attempts.
        first_request_id = _uuid(ident) if ident else None
        ident = _uuid(_intent_id) if _intent_id else _uuid(ident) if ident else str(uuid.uuid5(uuid.NAMESPACE_URL,
            endpoint + '|' + canonical(intent)))
        with self.journal.locked(ident):
            record = self.journal.load(ident)
            if record is None:
                record = dict(intentId=ident, endpoint=endpoint, intent=intent,
                              attempts=[], budget=3, round=0, firstRequestId=first_request_id)
                record.update(_seed or {})
                self.journal.save(record)
            require(record['intent'] == intent and record['endpoint'] == endpoint,
                    'INTENT_PAYLOAD_CHANGED')
            require(all(record.get(k) == v for k, v in (_seed or {}).items()),
                    'INTENT_PAYLOAD_CHANGED')
            return self._run(record)

    def retry(self, intent_id):
        """Explicitly authorize another bounded round; caller never invents UUIDs."""
        with self.journal.locked(intent_id):
            record = self.journal.load(intent_id)
            require(record is not None, 'INTENT_NOT_FOUND')
            require(record['endpoint'] == getattr(self.client.gateway, 'endpoint', ''),
                    'INTENT_ENDPOINT_CHANGED')
            if record['attempts']:
                # Explicit continuation can test a repaired transport/config.
                # Keep the original evidence; Core DENY/ASK still wins below.
                record['manualRetryAfterAttempt'] = record['attempts'][-1]['requestId']
            if len(record['attempts']) >= record['budget']:
                record['budget'] += 3
                record['round'] += 1
                self.journal.save(record)
            self.journal.save(record)
            return self._run(record, manual_retry=True)

    def delivery(self, repository, task, new_sha, *, title, body, draft=False,
                 push_request_id=None, pr_request_id=None, reason):
        from .client import _identity
        branch = _identity(repository, task, new_sha)
        for ident in (push_request_id, pr_request_id):
            if ident is not None: _uuid(ident)
        require(push_request_id is None or pr_request_id is None or
                push_request_id != pr_request_id, 'GIT_DELIVERY_UUID_REUSE')
        require(type(reason) is str and bool(reason.strip()), 'GIT_DELIVERY_REASON_REQUIRED')
        from ..integrations.github.contract import validate_github_action
        validate_github_action('create_pull_request', repository,
            dict(head=branch, base='main', title=title, body=body, draft=draft))
        return self._start('delivery', 'publish_task_pr', repository,
            dict(task=task, newSha=new_sha, title=title, body=body, draft=draft,
                 pushRequestId=push_request_id, prRequestId=pr_request_id), None, reason)

    def _delivery_child(self, record, stage, kind, operation, params, request_id, manual_retry):
        children = record.setdefault('children', {})
        child = children.get(stage)
        if child is None:
            child = {'intentId': str(uuid.uuid5(uuid.UUID(record['intentId']), stage))}
            children[stage] = child
            self.journal.save(record)
        ident = child['intentId']
        if manual_retry and self.journal.load(ident) is not None and child.get('status') != 'DONE':
            result = self.retry(ident)
        else:
            result = self._start(kind, operation, record['intent']['repository'], params,
                request_id, record['intent']['reason'], _intent_id=ident,
                _seed={'expectedPrHead': record['intent']['params']['newSha']} if stage == 'pr' else None)
        children[stage] = result
        self.journal.save(record)
        return result

    def _delivery_answer(self, record, response, stage):
        p = record['intent']['params']; children = record.get('children', {})
        push = children.get('push', {}); pr = children.get('pr', {})
        answer = dict(response)
        target = pr.get('targetState') or {}
        view = record.get('deliveryPlan', {})
        answer.update(intentId=record['intentId'], stage=stage, children=children,
            repository=record['intent']['repository'], branch='task/' + p['task'], desiredHeadSha=p['newSha'],
            remoteHeadSha=p['newSha'] if response.get('status') == 'DONE' or push.get('status') == 'DONE' or not view.get('pushRequired', True)
                          else view.get('expectedRemoteSha'),
            expectedRemoteSha=view.get('expectedRemoteSha'),
            requestId=response.get('requestId') or pr.get('requestId') or push.get('requestId'),
            lastAttemptId=pr.get('lastAttemptId', pr.get('requestId')) or push.get('lastAttemptId', push.get('requestId')),
            pushRequestId=push.get('requestId'), prRequestId=pr.get('requestId'),
            pullRequestNumber=target.get('pullRequestNumber', response.get('pullRequestNumber')),
            pullRequestUrl=target.get('url', response.get('pullRequestUrl')),
            attemptIds=list(dict.fromkeys(push.get('attemptIds', []) + pr.get('attemptIds', []))))
        answer['nextAction'] = {**answer.get('nextAction', {}), 'intentId': record['intentId']}
        return answer

    def _run_delivery(self, record, manual_retry):
        intent = record['intent']; p = intent['params']; repo = intent['repository']
        try:
            if 'deliveryPlan' not in record:
                view = self.client.git_delivery.inspect(repo, p['task'], p['newSha'], draft=p['draft'])
                if view['status'] != 'CONTINUE':
                    response = self._answer(record, view['status'], view['code'], target=view)
                    response.update(pullRequestNumber=view.get('pullRequestNumber'),
                                    pullRequestUrl=view.get('pullRequestUrl'))
                    return self._delivery_answer(record, response, 'inspect')
                record['deliveryPlan'] = {'expectedRemoteSha': view['expectedRemoteSha'],
                    'pushRequired': view['code'] == 'GIT_DELIVERY_PUSH_REQUIRED'}
                self.journal.save(record)
            plan = record['deliveryPlan']
            if plan['pushRequired']:
                push = self._delivery_child(record, 'push', 'publish', 'push_commits',
                    dict(task=p['task'], expectedHeadSha=plan['expectedRemoteSha'], newSha=p['newSha']),
                    p['pushRequestId'], manual_retry)
                if push['status'] != 'DONE':
                    return self._delivery_answer(record, push, 'push')
            pr = self._delivery_child(record, 'pr', 'github', 'create_pull_request',
                dict(head='task/' + p['task'], base='main', title=p['title'], body=p['body'], draft=p['draft']),
                p['prRequestId'], manual_retry)
            return self._delivery_answer(record, pr, 'pr')
        except (Denied, OSError, ValueError, KeyError, TypeError) as exc:
            code = exc.args[0] if len(exc.args) == 1 else None
            if type(code) is not str or not re.fullmatch(r'[A-Z][A-Z0-9_]{0,119}', code):
                code = 'INTENT_READBACK_OR_PRECONDITION_FAILED'
            return self._delivery_answer(record, self._answer(record, 'STOP', code), 'inspect')

    def _answer(self, record, status, code, *, target=None, response=None):
        attempts = record['attempts']
        answer = dict(response or {})
        latest = attempts[-1]['requestId'] if attempts else None
        response_id = response.get('requestId') if response else None
        request_id = response_id if any(a['requestId'] == response_id for a in attempts) else latest
        answer.update(intentId=record['intentId'], status=status, code=code,
            requestId=request_id, lastAttemptId=latest,
            attemptIds=[a['requestId'] for a in attempts], targetState=target,
            retryRound=record['round'])
        if 'state' not in answer:
            answer['state'] = 'GOAL_REACHED' if status == 'DONE' else status
        executed = next((a for a in reversed(attempts) if a.get('observedState') == 'EXECUTED'), None)
        answer['effect'] = {'state': 'EXECUTED' if executed else 'UNCONFIRMED' if attempts else 'NOT_ATTEMPTED',
                            'requestId': executed['requestId'] if executed else answer['requestId']}
        answer['verification'] = {'state': 'CONFIRMED' if status == 'DONE' else 'UNCONFIRMED'}
        next_kind = ('NONE' if status == 'DONE' else
                     'FIX_PRECONDITION' if status == 'STOP' else
                     'RETRY_INTENT' if status == 'RETRY_EXHAUSTED' else
                     'WAIT_BACKOFF' if code == 'INTENT_BACKOFF_REQUIRED' else
                     'RETRY_READ' if executed else
                     'WAIT_OWNER' if response and response.get('state') == 'PENDING' else
                     'WAIT_EXISTING_REQUEST' if status == 'WAITING' else 'FIX_PRECONDITION')
        answer['nextAction'] = {'kind': next_kind, 'intentId': record['intentId']}
        if attempts and attempts[-1].get('failureEvidence'):
            answer['failureEvidence'] = attempts[-1]['failureEvidence']
        if record['intent']['kind'] == 'visual':
            answer['runIds'] = [a['runId'] for a in attempts]
            answer['manualDuplicateCheckRequired'] = True
        return answer

    def _confirmed_target(self, record, attempt, receipt):
        """Use a Core-confirmed, UUID-bound receipt; never re-scan inventories."""
        intent = record['intent']; p = intent['params']; op = intent['operation']
        require(type(receipt) is dict and receipt.get('requestId') == attempt['requestId'] and
                receipt.get('operation') == op and receipt.get('repository') == intent['repository'],
                'INTENT_RECEIPT_BINDING_INVALID')
        if intent['kind'] == 'workspace':
            data = receipt.get('data')
            require(type(data) is dict and data.get('clean') is True, 'INTENT_RECEIPT_BINDING_INVALID')
            if op == 'create_task':
                wanted = p['adoptHeadSha'] or p['baseSha']
                require(data.get('branch') == 'task/' + p['task'] and data.get('headSha') == wanted,
                        'INTENT_RECEIPT_BINDING_INVALID')
                return {'task': p['task'], 'headSha': wanted}
            wanted = p.get('expectedMergeSha') or record.get('expectedTargetHead')
            if wanted is None:
                merge = self.client.result(p['mergeRequestId'])
                require(merge['state'] == 'EXECUTED' and merge['result']['merged'],
                        'INTENT_MERGE_RECEIPT_REQUIRED')
                wanted = merge['result']['sha']
            require(data.get('branch') == 'main' and data.get('headSha') == wanted,
                    'INTENT_RECEIPT_BINDING_INVALID')
            return {'branch': 'main', 'headSha': wanted}
        if intent['kind'] == 'publish' or op == 'create_branch':
            branch = 'task/' + p['task'] if intent['kind'] == 'publish' else p['branch']
            wanted = p['newSha'] if intent['kind'] == 'publish' else p['sourceSha']
            require(receipt.get('branch') == branch and receipt.get('sha') == wanted,
                    'INTENT_RECEIPT_BINDING_INVALID')
            return {'branch': branch, 'sha': wanted}
        if op in ('create_pull_request', 'mark_pr_ready'):
            pr = receipt.get('pullRequest')
            require(type(pr) is dict and type(pr.get('number')) is int and pr['number'] > 0 and
                    type(pr.get('head')) is dict and type(pr.get('base')) is dict,
                    'INTENT_RECEIPT_BINDING_INVALID')
            if op == 'create_pull_request':
                require(pr.get('head', {}).get('ref') == p['head'] and
                        pr.get('head', {}).get('sha') == record.get('expectedPrHead') and
                        pr.get('base', {}).get('ref') == p['base'] and pr.get('draft') is p['draft'],
                        'INTENT_RECEIPT_BINDING_INVALID')
            else:
                require(pr['number'] == p['number'] and
                        pr.get('head', {}).get('sha') == p['expectedHeadSha'] and pr.get('draft') is False,
                        'INTENT_RECEIPT_BINDING_INVALID')
            return {'pullRequestNumber': pr['number'], 'url': pr.get('url')}
        if op == 'publish_visual_review':
            require(receipt.get('runId') == attempt['runId'] and
                    type(receipt.get('issueNumber')) is int and receipt['issueNumber'] > 0 and
                    receipt.get('uploadedFiles') == len(p['media']), 'INTENT_RECEIPT_BINDING_INVALID')
            return {'issueNumber': receipt['issueNumber'], 'runId': attempt['runId'], 'url': receipt.get('url')}
        require(receipt.get('number') == p['number'] and receipt.get('headSha') == p['expectedHeadSha'],
                'INTENT_RECEIPT_BINDING_INVALID')
        if op == 'update_pull_request':
            wanted = hashlib.sha256(p['body'].encode()).hexdigest()
            require(receipt.get('bodySha256') == wanted, 'INTENT_RECEIPT_BINDING_INVALID')
            return {'bodySha256': wanted}
        require(release_label_receipt_matches(op, intent['repository'], p,
                                             attempt['requestId'], receipt),
                'INTENT_RECEIPT_BINDING_INVALID')
        return {'labels': receipt['labels']}

    def _finish_confirmed(self, record, attempt, response=None):
        """Once execution was acknowledged, every continuation is READ-only."""
        try:
            result = self.client.result(attempt['requestId']) if response is None else response
            require(type(result) is dict and result.get('state') in _STATES, 'INTENT_STATE_INVALID')
            require(result.get('requestId') == attempt['requestId'], 'INTENT_RESULT_BINDING_INVALID')
            if result.get('state') != 'EXECUTED' or result.get('result') is None:
                answer = self._answer(record, 'WAITING', 'INTENT_EXECUTED_DETAILS_UNAVAILABLE')
                answer['verification'] = {'state': 'UNAVAILABLE', 'code': 'INTENT_RECEIPT_NOT_AVAILABLE'}
                return answer
            target = self._confirmed_target(record, attempt, result['result'])
            return self._answer(record, 'DONE', 'INTENT_EXECUTED', target=target, response=result)
        except Denied as exc:
            code = exc.args[0] if len(exc.args) == 1 else None
            if type(code) is str and code in ('INTENT_RECEIPT_BINDING_INVALID', 'INTENT_RESULT_BINDING_INVALID', 'INTENT_STATE_INVALID'):
                return self._answer(record, 'STOP', code)
            safe = code if type(code) is str and re.fullmatch(r'FORTIS_[A-Z0-9_]{1,100}', code) else 'INTENT_READ_UNAVAILABLE'
            answer = self._answer(record, 'WAITING', 'INTENT_EXECUTED_DETAILS_UNAVAILABLE')
            answer['verification'] = {'state': 'UNAVAILABLE', 'code': safe}
            return answer
        except (OSError, ValueError, KeyError, TypeError, TimeoutError):
            answer = self._answer(record, 'WAITING', 'INTENT_EXECUTED_DETAILS_UNAVAILABLE')
            answer['verification'] = {'state': 'UNAVAILABLE', 'code': 'INTENT_READ_UNAVAILABLE'}
            return answer

    def _observations(self, record):
        """Check exact attempts only; no scans through the entire Core history."""
        observations = []
        for attempt in record['attempts']:
            ident = attempt['requestId']
            result = self.client.result(ident)
            require(result.get('requestId') == ident, 'INTENT_RESULT_BINDING_INVALID')
            state = result['state']
            require(state in _STATES, 'INTENT_STATE_INVALID')
            if state == 'NOT_FOUND':
                observations.append((state, None, result))
                continue
            details = self.client.details(ident)
            row = details.get('request') or {}
            check_own_record(own_label_evidence(self._capabilities()), row)
            payload = row.get('request') or {}
            intent = record['intent']
            require(payload.get('target') == intent['repository'] and
                    payload.get('operation') == intent['operation'] and
                    payload.get('requestId') == ident, 'INTENT_DETAILS_BINDING_INVALID')
            params = payload.get('params') or {}
            expected = intent['params']
            if intent['kind'] in ('github', 'workspace'):
                require(params == expected, 'INTENT_DETAILS_BINDING_INVALID')
            elif intent['kind'] == 'publish':
                require(all(params.get(key) == value for key, value in expected.items()),
                        'INTENT_DETAILS_BINDING_INVALID')
            else:
                require(params.get('runId') == attempt['runId'], 'INTENT_DETAILS_BINDING_INVALID')
            if intent['operation'] == 'push_commits' and row.get('state') == 'UNCERTAIN':
                diagnostic = details.get('diagnostic')
                error = diagnostic.get('coreError') if type(diagnostic) is dict else None
                permanent = {'GIT_AUTH_FAILURE_REPORTED', 'GIT_REMOTE_ACCESS_DENIED',
                    'GIT_TLS_FAILURE_REPORTED', 'GIT_RESOURCE_FAILURE_REPORTED'}
                if (type(error) is dict and error.get('stage') == 'GITHUB_ADAPTER' and
                        error.get('code') in permanent | {'GIT_RATE_LIMIT_REPORTED'} and
                        not attempt.get('coreFailureEvidence')):
                    attempt['coreFailureEvidence'] = dict(requestId=ident, origin='CORE_DIAGNOSTIC',
                        stage=error['stage'], code=error['code'])
                    attempt['failureEvidence'] = attempt['coreFailureEvidence']
                    if error['code'] in permanent:
                        attempt['permanentFailure'] = error['code']
                    else:
                        attempt['notBefore'] = max(attempt.get('notBefore', 0), self.policy.clock() + 60)
                    self.journal.save(record)
            worker = details.get('worker')
            worker_state = worker.get('state') if type(worker) is dict else None
            require(row.get('state') in _STATES and
                    worker_state in (None, 'QUEUED', 'CLAIMED', 'DONE', 'FAILED'),
                    'INTENT_STATE_INVALID')
            if (intent['kind'] == 'workspace' and row.get('state') == 'DISPATCHED'
                    and worker_state == 'QUEUED'):
                # First delivery of an authorized, still-queued job after owner
                # approval; never redeliver an existing CLAIMED payload/token.
                result = self.client.resume(ident)
                details = self.client.details(ident)
                row = details.get('request') or {}
                worker = details.get('worker')
                worker_state = worker.get('state') if type(worker) is dict else None
            receipt = details.get('receipt')
            if (row.get('state') in ('UNCERTAIN', 'DISPATCHED') and
                    type(receipt) is dict and type(receipt.get('result')) is dict and
                    receipt['result'].get('requestId') == ident and
                    receipt['result'].get('operation') == intent['operation'] and
                    receipt['result'].get('repository') == intent['repository'] and
                    (intent['kind'] != 'workspace' or worker_state == 'DONE')):
                # Reconcile only a positive, original-UUID-bound receipt. This
                # authorized continuation never retries an effect or a claim.
                result = self.client.result(ident, reconcile=True)
                row = {**row, 'state': result['state']}
            observations.append((row.get('state'), worker_state, result))
        return observations

    def _run(self, record, *, manual_retry=False):
        if record['intent']['kind'] == 'delivery':
            return self._run_delivery(record, manual_retry)
        waited = 0
        while True:
            try:
                confirmed = next((a for a in reversed(record['attempts'])
                                  if a.get('observedState') == 'EXECUTED'), None)
                if confirmed is not None:
                    return self._finish_confirmed(record, confirmed)
                cap = self._capabilities()
                require(allow_intent_details(cap, record['intent']),
                        'INTENT_DETAILS_UNSUPPORTED')
                observations = self._observations(record)
                for state, worker, response in observations:
                    if state in _ACTIVE or worker in ('CLAIMED', 'QUEUED'):
                        # A still executing/approved request is not a failed attempt.
                        return self._answer(record, 'WAITING', 'INTENT_AWAITING_EXISTING_REQUEST',
                                            response=response)
                for attempt, (state, _, response) in zip(record['attempts'], observations):
                    if state == 'EXECUTED':
                        attempt['observedState'] = 'EXECUTED'
                        self.journal.save(record)
                        return self._finish_confirmed(record, attempt, response)
                target, complete = self._goal(record, observations)
                if complete:
                    response = observations[-1][2] if observations and observations[-1][0] == 'EXECUTED' else None
                    return self._answer(record, 'DONE', 'INTENT_TARGET_REACHED', target=target,
                                        response=response)
                if target.get('partialPublication'):
                    return self._answer(record, 'STOP', 'INTENT_ISSUE_PARTIAL_PUBLICATION', target=target)
                if any(s in _FINAL_DENIAL for s, _, _ in observations):
                    return self._answer(record, 'STOP', 'INTENT_ADMISSION_STOP', target=target)
                if any(s == 'EXECUTED' for s, _, _ in observations):
                    return self._answer(record, 'STOP', 'INTENT_TARGET_CHANGED_AFTER_EXECUTION', target=target)
                if len(record['attempts']) >= record['budget']:
                    return self._answer(record, 'RETRY_EXHAUSTED', 'INTENT_RETRY_BUDGET_EXHAUSTED', target=target)
                if record['attempts']:
                    last = record['attempts'][-1]
                    if (last.get('permanentFailure') and
                            record.get('manualRetryAfterAttempt') != last['requestId']):
                        return self._answer(record, 'STOP', last['permanentFailure'], target=target)
                    delay = max(0, last.get('notBefore', 0) - self.policy.clock())
                    if waited + delay > self.policy.max_wait:
                        answer = self._answer(record, 'WAITING', 'INTENT_BACKOFF_REQUIRED', target=target)
                        answer['retryAfterSeconds'] = delay
                        return answer
                    if delay > 0:
                        self.policy.sleep(delay); waited += delay
                    # Re-read after waiting before allocating a fresh attempt.
                    refreshed = self._observations(record) if delay > 0 else observations
                    if any(s in _ACTIVE or w in ('CLAIMED', 'QUEUED') for s, w, _ in refreshed):
                        return self._answer(record, 'WAITING', 'INTENT_AWAITING_EXISTING_REQUEST')
                    if any(s in _FINAL_DENIAL for s, _, _ in refreshed):
                        return self._answer(record, 'STOP', 'INTENT_ADMISSION_STOP')
                    for previous, (state, _, response) in zip(record['attempts'], refreshed):
                        if state == 'EXECUTED':
                            previous['observedState'] = 'EXECUTED'
                            self.journal.save(record)
                            return self._finish_confirmed(record, previous, response)
                    if delay > 0:
                        target, complete = self._goal(record, refreshed)
                    if complete:
                        return self._answer(record, 'DONE', 'INTENT_TARGET_REACHED', target=target)
                    if target.get('partialPublication'):
                        return self._answer(record, 'STOP', 'INTENT_ISSUE_PARTIAL_PUBLICATION', target=target)
                attempt = dict(requestId=(record.get('firstRequestId') if not record['attempts']
                                          else None) or str(uuid.uuid4()))
                if record['intent']['kind'] == 'visual':
                    original = record['intent']['params']['run_id']
                    attempt['runId'] = original if not record['attempts'] else original[:60] + '-r-' + uuid.uuid4().hex[:12]
                record['attempts'].append(attempt)
                # Persist the NEW UUID before any staging, submit, or network I/O.
                self.journal.save(record)
                started = time.monotonic()
                try:
                    response = self._once(record, attempt)
                    attempt['elapsedMs'] = max(0, int((time.monotonic() - started) * 1000))
                    require(response.get('requestId') == attempt['requestId'], 'INTENT_RESULT_BINDING_INVALID')
                    attempt['observedState'] = response.get('state')
                    self.journal.save(record)
                    if response.get('state') in _ACTIVE:
                        return self._answer(record, 'WAITING', 'INTENT_AWAITING_EXISTING_REQUEST', response=response)
                    if response.get('state') in _FINAL_DENIAL:
                        return self._answer(record, 'STOP', 'INTENT_ADMISSION_STOP', response=response)
                    if response.get('state') == 'EXECUTED':
                        return self._finish_confirmed(record, attempt)
                except Exception as exc:
                    attempt['elapsedMs'] = max(0, int((time.monotonic() - started) * 1000))
                    attempt['callFailureEvidence'] = _call_failure(exc, attempt['requestId'], attempt['elapsedMs'])
                    attempt['failureEvidence'] = attempt['callFailureEvidence']
                    attempt['delay'] = self.policy.delay(exc, len(record['attempts']) - 1)
                    attempt['notBefore'] = self.policy.clock() + attempt['delay']
                    if not transient(exc):
                        attempt['permanentFailure'] = 'INTENT_NONTRANSIENT_FAILURE'
                    self.journal.save(record)
            except Denied as exc:
                code = exc.args[0] if len(exc.args) == 1 else None
                if type(code) is not str or not re.fullmatch(r'[A-Z][A-Z0-9_]{0,119}', code):
                    code = 'INTENT_READBACK_OR_PRECONDITION_FAILED'
                return self._answer(record, 'STOP', code)
            except (OSError, ValueError, KeyError, TypeError):
                return self._answer(record, 'STOP', 'INTENT_READBACK_OR_PRECONDITION_FAILED')

    def _once(self, record, attempt):
        intent = record['intent']; p = intent['params']; repo = intent['repository']
        ident, reason = attempt['requestId'], intent['reason']
        if intent['kind'] == 'workspace':
            return self.client._command_once(intent['operation'], repo, p,
                request_id=ident, reason=reason, **intent['options'])
        if intent['kind'] == 'publish':
            return self.client._publish_once(repo, p['task'], p['expectedHeadSha'], p['newSha'],
                                             request_id=ident, reason=reason, package_id=record['intentId'])
        if intent['kind'] == 'github':
            return self.client.github._action_once(intent['operation'], repo, p,
                                                   request_id=ident, reason=reason)
        if intent['kind'] == 'visual':
            return self.client.github._publish_visual_review_once(**p,
                request_id=ident, reason=reason, publication_run_id=attempt['runId'])
        raise Denied('INTENT_OPERATION_UNSUPPORTED')

    @staticmethod
    def _pages(read, size):
        values = []
        for page in range(1, 101):
            response = read(page, size); rows = response['items']
            require(type(rows) is list and len(rows) <= size, 'INTENT_READ_INVALID')
            values.extend(rows)
            more = response.get('hasNextPage')
            if more is False or (more is None and len(rows) < size):
                return values
        raise Denied('INTENT_READ_INCOMPLETE')

    def _refs(self, repo):
        rows = self._pages(lambda page, size: self.client.github.list_branches(
            repo, page=page, per_page=size), 100)
        require(len({r['name'] for r in rows}) == len(rows), 'INTENT_REFS_CHANGED')
        return {r['name']: r['sha'] for r in rows}

    def _branch(self, repo, branch):
        if not self._target_reads():
            return self._refs(repo).get(branch)
        result = self.client.github.get_branch(repo, branch)
        require(type(result.get('found')) is bool, 'INTENT_READ_INVALID')
        row = result.get('branch')
        if result['found'] is False:
            require(row is None, 'INTENT_READ_INVALID')
            return None
        require(type(row) is dict and row.get('name') == branch and
                type(row.get('sha')) is str and re.fullmatch('[0-9a-f]{40}', row['sha']),
                'INTENT_READ_INVALID')
        return row['sha']

    def _pulls(self, repo, head, base):
        if self._target_reads():
            rows = self._pages(lambda page, size: self.client.github.find_pull_requests(
                repo, head, base, page=page, per_page=size), 50)
            require(all(r['head']['ref'] == head and r['base']['ref'] == base for r in rows),
                    'INTENT_PR_SEARCH_CHANGED')
        else:
            rows = self._pages(lambda page, size: self.client.github.list_pull_requests(
                repo, state='all', page=page, per_page=size), 50)
            rows = [r for r in rows if r['head']['ref'] == head and r['base']['ref'] == base]
        require(len({r['number'] for r in rows}) == len(rows), 'INTENT_PR_SEARCH_CHANGED')
        return rows

    def _goal(self, record, observations):
        intent = record['intent']; p = intent['params']; repo = intent['repository']
        kind, op = intent['kind'], intent['operation']
        if kind == 'workspace':
            return self._workspace_goal(record, observations)
        if kind == 'visual':
            runs = [p['run_id']] + [a['runId'] for a in record['attempts']]
            for run in dict.fromkeys(runs):
                hit = self.client.github.find_visual_review_run(repo, run)
                require(hit['complete'], 'INTENT_ISSUE_READ_INCOMPLETE')
                if hit['found']:
                    issue = hit['issue']
                    require(issue['title'] == p['title'], 'INTENT_ISSUE_IDENTITY_CHANGED')
                    intro = ('<!-- fortis-visual-review:' + run + ' -->\n\n' +
                        p['description'] + '\n\n**QA:** ' + p['qa_summary'] +
                        '\n\n**Duration:** ' + str(p['duration_seconds']) + ' seconds\n\n## Preview\n\n')
                    body = issue.get('body', '')
                    links = body[len(intro):].split('\n\n') if body.startswith(intro) else []
                    names = [item['name'].replace('\\', '\\\\').replace('[', '\\[').replace(']', '\\]')
                             .replace('\r', ' ').replace('\n', ' ') for item in p['media']]
                    complete = (body.startswith(intro) and len(links) == len(names) and all(re.fullmatch(
                        r'!\[' + re.escape(name) + r'\]\(https://github\.com/user-attachments/assets/[A-Za-z0-9_-]{1,200}\)',
                        link) for name, link in zip(names, links)))
                    return {'issueNumber': issue['number'], 'runId': run,
                            'partialPublication': not complete}, complete
            return {'issueFound': False}, False
        if kind == 'publish' or op == 'create_branch':
            branch = 'task/' + p['task'] if kind == 'publish' else p['branch']
            wanted = p['newSha'] if kind == 'publish' else p['sourceSha']
            actual = self._branch(repo, branch)
            if actual == wanted:
                return {'branch': branch, 'sha': actual}, True
            require(actual == p.get('expectedHeadSha'), 'INTENT_REMOTE_HEAD_CHANGED')
            if kind == 'publish':
                worker = self.client.worker
                root, state, run, text = worker._open(repo)
                with repository_lock(state / 'repository.lock'):
                    snapshot = worker._snapshot(repo, p['task'], root, run, text)
                require(snapshot['clean'] and snapshot['headSha'] == wanted,
                        'INTENT_LOCAL_HEAD_CHANGED')
            return {'branch': branch, 'sha': actual}, False
        if op == 'create_pull_request':
            head = self._branch(repo, p['head'])
            require(head is not None, 'INTENT_BRANCH_NOT_PUBLISHED')
            expected = record.get('expectedPrHead')
            if expected is None:
                record['expectedPrHead'] = head; self.journal.save(record)
            else:
                require(head == expected, 'INTENT_PR_HEAD_CHANGED')
            matches = self._pulls(repo, p['head'], p['base'])
            require(len(matches) <= 1, 'INTENT_PR_AMBIGUOUS')
            if matches:
                pr = self.client.github.get_pull_request(repo, matches[0]['number'])['pullRequest']
                require(pr['head']['sha'] == head and pr['draft'] is p['draft'] and
                        (pr['state'] == 'open' or pr['merged']), 'INTENT_PR_CHANGED')
                return {'pullRequestNumber': pr['number'], 'url': pr['url']}, True
            return {'pullRequestFound': False, 'headSha': head}, False
        if op == 'mark_pr_ready':
            pr = self.client.github.get_pull_request(repo, p['number'])['pullRequest']
            require(pr['head']['sha'] == p['expectedHeadSha'] and pr['state'] == 'open',
                    'INTENT_PR_CHANGED')
            return {'pullRequestNumber': p['number'], 'draft': pr['draft']}, not pr['draft']
        context = self.client.github.get_pr_release_label_context(repo, p['number'])
        require(context['headSha'] == p['expectedHeadSha'], 'INTENT_PR_CHANGED')
        if op == 'update_pull_request':
            wanted = hashlib.sha256(p['body'].encode()).hexdigest()
            return {'bodySha256': context['bodySha256']}, context['bodySha256'] == wanted
        labels = context['labels']
        done = (all(x in labels for x in p['labels']) if op == 'add_pr_release_labels'
                else p['name'] not in labels)
        if not done:
            for field in ('baseSha', 'bodySha256', 'labelsSha256'):
                require(context[field] == p['expected' + field[0].upper() + field[1:]],
                        'INTENT_LABEL_PRECONDITION_CHANGED')
        return {'labels': labels}, done

    def _workspace_goal(self, record, observations):
        intent = record['intent']; p = intent['params']; repo = intent['repository']
        worker = self.client.worker
        root, state, run, text = worker._open(repo)
        with repository_lock(state / 'repository.lock'):
            # Durable DISPATCHED without a terminal worker journal is not quiescence.
            path = state / 'receipts.sqlite'
            if path.is_file():
                require(not path.is_symlink(), 'INTENT_WORKER_JOURNAL_INVALID')
                with sqlite3.connect(path.absolute().as_uri() + '?mode=ro', uri=True) as db:
                    for attempt in record['attempts']:
                        row = db.execute('SELECT state FROM journal WHERE id=?', (attempt['requestId'],)).fetchone()
                        require(row is None or row[0] != 'DISPATCHED', 'INTENT_WORKER_STILL_ACTIVE')
            primary = worker._snapshot(repo, None, root, run, text)
            require(primary['clean'], 'INTENT_DIRTY_MAIN')
            remote_main = self._branch(repo, 'main')
            if intent['operation'] == 'create_task':
                require(remote_main == p['baseSha'], 'INTENT_BASE_CHANGED')
                target = worker._target(repo, p['task'], root, run, text, existing=False)
                present = target.exists() or bool(text(['branch', '--list', 'task/' + p['task']]))
                if present:
                    snap = worker._snapshot(repo, p['task'], root, run, text)
                    require(snap['clean'] and snap['headSha'] == (p['adoptHeadSha'] or p['baseSha']),
                            'INTENT_TASK_CHANGED')
                    # Creation also registers the task at Gateway. A matching
                    # local directory alone is not sufficient success evidence.
                    require(any(s == 'EXECUTED' for s, _, _ in observations),
                            'INTENT_TASK_REGISTRATION_UNCONFIRMED')
                    return {'task': p['task'], 'headSha': snap['headSha']}, True
                require(p['adoptHeadSha'] is None, 'INTENT_ADOPTION_MISSING')
                return {'task': p['task'], 'present': False}, False
            if intent['operation'] == 'update_main_from_pr':
                pr = self.client.github.get_pull_request(repo, p['number'])['pullRequest']
                require(pr['merged'] and pr['head']['sha'] == p['expectedPrHeadSha'],
                        'INTENT_MERGED_PR_CHANGED')
                wanted = p['expectedMergeSha']
            else:
                merge = self.client.result(p['mergeRequestId'])
                require(merge['state'] == 'EXECUTED' and merge['result']['merged'],
                        'INTENT_MERGE_RECEIPT_REQUIRED')
                wanted = merge['result']['sha']
            require(remote_main == wanted, 'INTENT_REMOTE_MAIN_CHANGED')
            if record.get('expectedTargetHead') is None:
                record['expectedTargetHead'] = wanted
                self.journal.save(record)
            if primary['headSha'] == wanted:
                return {'branch': 'main', 'headSha': wanted}, True
            require(primary['headSha'] == p['expectedHeadSha'], 'INTENT_LOCAL_MAIN_CHANGED')
            return {'branch': 'main', 'headSha': primary['headSha']}, False

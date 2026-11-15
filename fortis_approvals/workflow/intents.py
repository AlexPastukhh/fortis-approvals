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
import uuid

from ..core import Denied, canonical
from ..clients.retries import RetryPolicy, transient
from .common import require, secure_dir, repository_lock

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
                      reason='Authorized GitHub intent'):
        require(operation in GITHUB_COMMANDS, 'INTENT_OPERATION_UNSUPPORTED')
        return self._start('github', operation, repository, params, request_id, reason)

    def publish_visual_review(self, *, request_id=None, reason, **kwargs):
        preview = self.client.github.prepare_visual_review(**{
            k: v for k, v in kwargs.items() if k != 'expected_payload_sha256'})
        expected = kwargs.get('expected_payload_sha256')
        require(expected is None or expected == preview['payloadSha256'],
                'GITHUB_VISUAL_REVIEW_PREVIEW_CHANGED')
        kwargs = {**kwargs, 'expected_payload_sha256': preview['payloadSha256']}
        return self._start('visual', 'publish_visual_review', kwargs['repository'],
                           kwargs, request_id, reason)

    def _start(self, kind, operation, repository, params, ident, reason, **options):
        intent = json.loads(canonical(dict(kind=kind, operation=operation,
            repository=repository, params=params, reason=reason, options=options)))
        endpoint = getattr(self.client.gateway, 'endpoint', '')
        # Identical calls without a supplied ID resume the same logical intent.
        # It is separate from the UUIDs of the individual Gateway attempts.
        first_request_id = _uuid(ident) if ident else None
        ident = _uuid(ident) if ident else str(uuid.uuid5(uuid.NAMESPACE_URL,
            endpoint + '|' + canonical(intent)))
        with self.journal.locked(ident):
            record = self.journal.load(ident)
            if record is None:
                record = dict(intentId=ident, endpoint=endpoint, intent=intent,
                              attempts=[], budget=3, round=0, firstRequestId=first_request_id)
                self.journal.save(record)
            require(record['intent'] == intent and record['endpoint'] == endpoint,
                    'INTENT_PAYLOAD_CHANGED')
            return self._run(record)

    def retry(self, intent_id):
        """Explicitly authorize another bounded round; caller never invents UUIDs."""
        with self.journal.locked(intent_id):
            record = self.journal.load(intent_id)
            require(record is not None, 'INTENT_NOT_FOUND')
            require(record['endpoint'] == getattr(self.client.gateway, 'endpoint', ''),
                    'INTENT_ENDPOINT_CHANGED')
            if len(record['attempts']) >= record['budget']:
                record['budget'] += 3
                record['round'] += 1
                self.journal.save(record)
            return self._run(record)

    def _answer(self, record, status, code, *, target=None, response=None):
        attempts = record['attempts']
        answer = dict(response or {})
        answer.update(intentId=record['intentId'], status=status, code=code,
            requestId=attempts[-1]['requestId'] if attempts else None,
            attemptIds=[a['requestId'] for a in attempts], targetState=target,
            retryRound=record['round'])
        if 'state' not in answer:
            answer['state'] = 'GOAL_REACHED' if status == 'DONE' else status
        if record['intent']['kind'] == 'visual':
            answer['runIds'] = [a['runId'] for a in attempts]
            answer['manualDuplicateCheckRequired'] = True
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

    def _run(self, record):
        waited = 0
        while True:
            try:
                cap = self.client.gateway.post('/v1/workspace/capabilities', {})
                require((cap.get('globalRequestInventory') or {}).get('crossActorDetails') is True,
                        'INTENT_DETAILS_UNSUPPORTED')
                observations = self._observations(record)
                for state, worker, response in observations:
                    if state in _ACTIVE or worker in ('CLAIMED', 'QUEUED'):
                        # A still executing/approved request is not a failed attempt.
                        return self._answer(record, 'WAITING', 'INTENT_AWAITING_EXISTING_REQUEST',
                                            response=response)
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
                    if last.get('permanentFailure'):
                        return self._answer(record, 'STOP', last['permanentFailure'], target=target)
                    delay = max(0, last.get('notBefore', 0) - self.policy.clock())
                    if waited + delay > self.policy.max_wait:
                        answer = self._answer(record, 'WAITING', 'INTENT_BACKOFF_REQUIRED', target=target)
                        answer['retryAfterSeconds'] = delay
                        return answer
                    self.policy.sleep(delay); waited += delay
                    # Re-read after waiting before allocating a fresh attempt.
                    refreshed = self._observations(record)
                    if any(s in _ACTIVE or w in ('CLAIMED', 'QUEUED') for s, w, _ in refreshed):
                        return self._answer(record, 'WAITING', 'INTENT_AWAITING_EXISTING_REQUEST')
                    if any(s in _FINAL_DENIAL for s, _, _ in refreshed):
                        return self._answer(record, 'STOP', 'INTENT_ADMISSION_STOP')
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
                try:
                    response = self._once(record, attempt)
                    attempt['observedState'] = response.get('state')
                    self.journal.save(record)
                    if response.get('state') in _ACTIVE:
                        return self._answer(record, 'WAITING', 'INTENT_AWAITING_EXISTING_REQUEST', response=response)
                    if response.get('state') in _FINAL_DENIAL:
                        return self._answer(record, 'STOP', 'INTENT_ADMISSION_STOP', response=response)
                    if response.get('state') == 'EXECUTED':
                        # Provider adapters already bind receipt and effect readback.
                        # In particular: no second-Issue search after publication.
                        if record['intent']['kind'] == 'visual':
                            return self._answer(record, 'DONE', 'INTENT_EXECUTED', response=response)
                        final, confirmed = self._goal(record, self._observations(record))
                        return self._answer(record, 'DONE' if confirmed else 'STOP',
                            'INTENT_EXECUTED' if confirmed else 'INTENT_TARGET_CHANGED_AFTER_EXECUTION',
                            response=response, target=final)
                except Exception as exc:
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
                                             request_id=ident, reason=reason)
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
            refs = self._refs(repo)
            branch = 'task/' + p['task'] if kind == 'publish' else p['branch']
            wanted = p['newSha'] if kind == 'publish' else p['sourceSha']
            actual = refs.get(branch)
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
            refs = self._refs(repo)
            head = refs.get(p['head'])
            require(head is not None, 'INTENT_BRANCH_NOT_PUBLISHED')
            expected = record.get('expectedPrHead')
            if expected is None:
                record['expectedPrHead'] = head; self.journal.save(record)
            else:
                require(head == expected, 'INTENT_PR_HEAD_CHANGED')
            prs = self._pages(lambda page, size: self.client.github.list_pull_requests(
                repo, state='all', page=page, per_page=size), 50)
            matches = [r for r in prs if r['head']['ref'] == p['head'] and r['base']['ref'] == p['base']]
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
            refs = self._refs(repo)
            if intent['operation'] == 'create_task':
                require(refs.get('main') == p['baseSha'], 'INTENT_BASE_CHANGED')
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
            require(refs.get('main') == wanted, 'INTENT_REMOTE_MAIN_CHANGED')
            if primary['headSha'] == wanted:
                return {'branch': 'main', 'headSha': wanted}, True
            require(primary['headSha'] == p['expectedHeadSha'], 'INTENT_LOCAL_MAIN_CHANGED')
            return {'branch': 'main', 'headSha': primary['headSha']}, False

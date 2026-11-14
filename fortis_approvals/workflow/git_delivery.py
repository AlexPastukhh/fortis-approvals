"""Readback-first native Git/PR delivery facade for an authorized Repo actor.

No new server routes, owner decisions, direct GitHub writes or hidden retries.
Each submit can make at most one guarded push and one PR-create attempt,
with independent caller-supplied UUIDs and provider READ after each stage.
"""
import re
import uuid

from ..core import Denied
from ..integrations.github.contract import validate_github_action
from .common import require


_SHA = re.compile(r'[0-9a-f]{40}\Z')
_REPO = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,99}\Z')
_TASK = re.compile(r'[a-z0-9][a-z0-9-]{0,99}\Z')
_MAX_PAGES = 10


def _identity(repository, task, new_sha):
    require(type(repository) is str and _REPO.fullmatch(repository) is not None and
            repository not in ('.', '..'), 'GIT_DELIVERY_REPOSITORY_INVALID')
    require(type(task) is str and _TASK.fullmatch(task) is not None,
            'GIT_DELIVERY_TASK_INVALID')
    require(type(new_sha) is str and _SHA.fullmatch(new_sha) is not None,
            'GIT_DELIVERY_SHA_INVALID')
    return 'task/' + task


def _request_id(value):
    try:
        require(type(value) is str and str(uuid.UUID(value)) == value,
                'GIT_DELIVERY_UUID_INVALID')
    except (ValueError, AttributeError):
        raise Denied('GIT_DELIVERY_UUID_INVALID') from None


def _read_pages(read, *, page_size):
    """Only a complete bounded listing can establish absence of a ref/PR."""
    items = []
    for page in range(1, _MAX_PAGES + 1):
        response = read(page, page_size)
        rows = response['items']
        require(type(rows) is list and len(rows) <= page_size,
                'GIT_DELIVERY_READ_INVALID')
        items.extend(rows)
        if len(rows) < page_size:
            return items
    raise Denied('GIT_DELIVERY_READ_INCOMPLETE')


class GitDelivery:
    def __init__(self, client):
        self.client = client

    @staticmethod
    def _result(status, code, repository, branch, new_sha, *, remote_sha=None,
                pr=None, expected_remote_sha=None, push_request_id=None,
                pr_request_id=None):
        return {
            'status': status, 'code': code,
            'repository': repository, 'branch': branch, 'desiredHeadSha': new_sha,
            'remoteHeadSha': remote_sha, 'expectedRemoteSha': expected_remote_sha,
            'pullRequestNumber': pr['number'] if pr else None,
            'pullRequestUrl': pr['url'] if pr else None,
            'pushRequestId': push_request_id, 'prRequestId': pr_request_id,
        }

    def inspect(self, repository, task, new_sha, *, draft=None):
        """Return DONE/CONTINUE/STOP from complete typed GitHub GET only.

        This is a *goal-state* verdict, never attribution to a historic UUID.
        """
        branch = _identity(repository, task, new_sha)
        require(draft is None or type(draft) is bool, 'GIT_DELIVERY_DRAFT_INVALID')
        try:
            branches = _read_pages(
                lambda page, size: self.client.github.list_branches(
                    repository, page=page, per_page=size), page_size=100)
            prs = _read_pages(
                lambda page, size: self.client.github.list_pull_requests(
                    repository, state='all', page=page, per_page=size), page_size=50)
        except Exception:
            # Preserve any original UUID and fail closed on GET, bad payload,
            # truncated pages or transport errors; never guess non-execution.
            return self._result('STOP', 'GIT_DELIVERY_READ_UNAVAILABLE_OR_INCOMPLETE',
                                repository, branch, new_sha)
        refs = [row for row in branches if row['name'] == branch]
        if len(refs) > 1:
            return self._result('STOP', 'GIT_DELIVERY_BRANCH_AMBIGUOUS',
                                repository, branch, new_sha)
        remote_sha = refs[0]['sha'] if refs else None
        matches = [p for p in prs if p['head']['ref'] == branch and
                   p['base']['ref'] == 'main']
        if len(matches) > 1:
            return self._result('STOP', 'GIT_DELIVERY_PR_AMBIGUOUS', repository,
                                branch, new_sha, remote_sha=remote_sha)
        pr = matches[0] if matches else None
        if pr is not None and (pr['state'] != 'open' or pr['merged'] is True):
            return self._result('STOP', 'GIT_DELIVERY_PRIOR_PR_CLOSED', repository,
                                branch, new_sha, remote_sha=remote_sha, pr=pr)
        if pr is not None and pr['head']['sha'] != remote_sha:
            return self._result('STOP', 'GIT_DELIVERY_REF_PR_SHA_MISMATCH', repository,
                                branch, new_sha, remote_sha=remote_sha, pr=pr)
        if remote_sha == new_sha and pr is not None and (
                draft is not None and pr['draft'] is not draft):
            return self._result('STOP', 'GIT_DELIVERY_PR_DRAFT_MISMATCH',
                                repository, branch, new_sha, remote_sha=remote_sha, pr=pr)
        if remote_sha == new_sha and pr is not None:
            return self._result('DONE', 'GIT_DELIVERY_PR_EXISTS_EXACT_SHA',
                                repository, branch, new_sha, remote_sha=remote_sha, pr=pr)
        if remote_sha == new_sha:
            return self._result('CONTINUE', 'GIT_DELIVERY_PR_CREATE_REQUIRED',
                                repository, branch, new_sha, remote_sha=remote_sha)
        return self._result('CONTINUE', 'GIT_DELIVERY_PUSH_REQUIRED', repository,
                            branch, new_sha, remote_sha=remote_sha,
                            expected_remote_sha=remote_sha, pr=pr)

    def submit(self, repository, task, new_sha, *, title, body, draft=False,
               push_request_id, pr_request_id, reason):
        """At most 1 typed push and 1 typed PR POST; never merge/retry.

        On a lost response inspect remote target state, without fabricating
        an EXECUTED receipt for the original UUID. The caller decides whether
        any *new* authorized intent is appropriate after STOP.
        """
        branch = _identity(repository, task, new_sha)
        _request_id(push_request_id)
        _request_id(pr_request_id)
        require(push_request_id != pr_request_id, 'GIT_DELIVERY_UUID_REUSE')
        require(type(reason) is str and bool(reason.strip()),
                'GIT_DELIVERY_REASON_REQUIRED')
        validate_github_action('create_pull_request', repository, {
            'head': branch, 'base': 'main', 'title': title, 'body': body,
            'draft': draft,
        })
        view = self.inspect(repository, task, new_sha, draft=draft)
        if view['status'] != 'CONTINUE':
            return view

        if view['code'] == 'GIT_DELIVERY_PUSH_REQUIRED':
            # Server still validates exact worktree, ancestry, ref and CAS.
            # A local worktree mismatch must never cause a remote WRITE.
            try:
                root, _, run, text = self.client.worker._open(repository)
                self.client.worker._target(
                    repository, task, root, run, text)
                snap = self.client.worker._snapshot(repository, task, root, run, text)
                require(snap['clean'] is True and snap['headSha'] == new_sha,
                        'GIT_DELIVERY_LOCAL_HEAD_OR_CLEAN_MISMATCH')
            except Exception:
                return self._result('STOP', 'GIT_DELIVERY_LOCAL_PRECONDITION_FAILED',
                                    repository, branch, new_sha,
                                    remote_sha=view['remoteHeadSha'],
                                    push_request_id=push_request_id,
                                    pr_request_id=pr_request_id)
            try:
                old = view['expectedRemoteSha']
                push = self.client.publish(repository, task, old, new_sha,
                    request_id=push_request_id, reason=reason)
                push_state = push.get('state')
            except Exception:
                push_state = 'UNKNOWN'
            # Never resubmit push on UNCERTAIN/transport loss. Check actual ref.
            view = self.inspect(repository, task, new_sha, draft=draft)
            if view['status'] == 'STOP':
                return self._result('STOP', view['code'], repository, branch,
                                    new_sha, push_request_id=push_request_id,
                                    pr_request_id=pr_request_id)
            if view['remoteHeadSha'] != new_sha:
                return self._result('STOP', 'GIT_DELIVERY_PUSH_NOT_VERIFIED',
                                    repository, branch, new_sha,
                                    remote_sha=view['remoteHeadSha'],
                                    push_request_id=push_request_id,
                                    pr_request_id=pr_request_id)
            if push_state == 'PENDING':
                return self._result('CONTINUE', 'GIT_DELIVERY_PUSH_AWAITING_OWNER',
                                    repository, branch, new_sha,
                                    remote_sha=view['remoteHeadSha'],
                                    push_request_id=push_request_id,
                                    pr_request_id=pr_request_id)
            if view['status'] == 'DONE':
                view['pushRequestId'] = push_request_id
                view['prRequestId'] = pr_request_id
                return view

        # PR create only if a complete second readback says it is absent.
        if view['code'] != 'GIT_DELIVERY_PR_CREATE_REQUIRED':
            return self._result('STOP', 'GIT_DELIVERY_UNSAFE_TO_CREATE_PR',
                                repository, branch, new_sha,
                                remote_sha=view['remoteHeadSha'],
                                push_request_id=push_request_id,
                                pr_request_id=pr_request_id)
        try:
            created = self.client.github.create_pull_request(
                repository, branch, 'main', title, body=body, draft=draft,
                request_id=pr_request_id, reason=reason)
            pr_state = created.get('state')
        except Exception:
            pr_state = 'UNKNOWN'
        final = self.inspect(repository, task, new_sha, draft=draft)
        final['pushRequestId'] = push_request_id
        final['prRequestId'] = pr_request_id
        if final['status'] == 'DONE':
            return final
        if pr_state == 'PENDING' and final['code'] == 'GIT_DELIVERY_PR_CREATE_REQUIRED':
            final['status'] = 'CONTINUE'
            final['code'] = 'GIT_DELIVERY_PR_AWAITING_OWNER'
        else:
            final['status'] = 'STOP'
            final['code'] = ('GIT_DELIVERY_PR_NOT_VERIFIED' if
                             final['code'] == 'GIT_DELIVERY_PR_CREATE_REQUIRED' else
                             final['code'])
        return final

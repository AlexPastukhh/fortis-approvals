"""PR3: no hidden writes; guarded Git/PR readback and old UUID preservation."""
import unittest

from fortis_approvals.core import Denied
from fortis_approvals.workflow.client import GitDelivery

OLD = 'a' * 40
NEW = 'b' * 40
UUID_PUSH = '11111111-1111-4111-8111-111111111111'
UUID_PR = '22222222-2222-4222-8222-222222222222'
BRANCH = 'task/agent'


class FakeGitHub:
    def __init__(self, branch=None, prs=None):
        self.branch = branch
        self.prs = list(prs or [])
        self.reads = 0
        self.posts = 0
        self.read_broken = False
        self.post_lost = False
        self.post_missing = False
        self.post_pending = False

    def list_branches(self, repo, *, page=1, per_page=100):
        assert repo == 'sandbox'
        self.reads += 1
        if self.read_broken:
            raise Denied('FORTIS_HTTP_500')
        return {'items': ([{'name': BRANCH, 'sha': self.branch}]
                          if self.branch and page == 1 else [])}

    def list_pull_requests(self, repo, *, state, page=1, per_page=50):
        assert repo == 'sandbox' and state == 'all'
        self.reads += 1
        i = (page-1)*per_page
        return {'items': self.prs[i:i+per_page]}

    def create_pull_request(self, repo, head, base, title, body='', draft=False,
                            *, request_id, reason):
        assert repo == 'sandbox' and head == BRANCH and base == 'main'
        assert request_id == UUID_PR and title == 'Agent review'
        self.posts += 1
        if not self.post_missing:
            self.prs.append(make_pr(self.branch, number=len(self.prs)+1, draft=draft))
        if self.post_lost:
            raise TimeoutError('lost result after external write')
        return {'requestId': request_id, 'state': 'PENDING' if self.post_pending else 'EXECUTED'}


def make_pr(sha=NEW, number=1, state='open', merged=False, draft=False):
    return dict(number=number, state=state, merged=merged, draft=draft,
                head={'ref': BRANCH, 'sha': sha}, base={'ref': 'main', 'sha': OLD},
                url='https://github.com/Owner/sandbox/pull/' + str(number))


class FakeWorker:
    def __init__(self):
        self.clean = True
        self.head = NEW
        self.targets = 0

    def _open(self, repo):
        assert repo == 'sandbox'
        return ('/', None, None, None)

    def _target(self, repo, task, root, run, text):
        assert task == 'agent'
        self.targets += 1
        return '/path'

    def _snapshot(self, repo, task, root, run, text):
        return {'headSha': self.head, 'clean': self.clean}


class FakeClient:
    def __init__(self, branch=None, prs=None):
        self.github = FakeGitHub(branch, prs)
        self.worker = FakeWorker()
        self.pushes = []
        self.push_lost = False
        self.push_no_effect = False
        self.push_pending = False
        self.push_competed = False

    def publish(self, repo, task, old, new, *, request_id, reason):
        assert repo == 'sandbox' and task == 'agent'
        assert request_id == UUID_PUSH and new == NEW
        self.pushes.append(old)
        if self.push_competed:
            self.github.branch = 'c' * 40
        elif not self.push_no_effect and not self.push_pending:
            self.github.branch = new
            # GitHub's open pull request head follows the pushed branch.
            for pr in self.github.prs:
                if pr['head']['ref'] == BRANCH and pr['state'] == 'open':
                    pr['head']['sha'] = new
        if self.push_lost:
            raise TimeoutError('lost push ACK')
        return {'requestId':request_id,'state':'PENDING' if self.push_pending else 'EXECUTED'}


class GitDeliveryTests(unittest.TestCase):
    def facade(self, branch=None, prs=None):
        c=FakeClient(branch, prs)
        return GitDelivery(c), c

    @staticmethod
    def submit(delivery, *, push=UUID_PUSH, pr=UUID_PR):
        return delivery.submit('sandbox','agent',NEW,title='Agent review',body='review',
                               push_request_id=push,pr_request_id=pr,
                               reason='Delivery with exact readback')

    def test_read_only_prepare_absent_ref_uses_none_not_main_sha(self):
        d,c=self.facade()
        state=d.inspect('sandbox','agent',NEW)
        self.assertEqual((state['status'],state['code'],state['expectedRemoteSha']),
                         ('CONTINUE','GIT_DELIVERY_PUSH_REQUIRED',None))
        self.assertEqual(c.pushes,[])
        self.assertEqual(c.github.posts,0)

    def test_new_branch_one_push_then_one_pr(self):
        d,c=self.facade()
        result=self.submit(d)
        self.assertEqual(result['status'],'DONE')
        self.assertEqual(result['code'],'GIT_DELIVERY_PR_EXISTS_EXACT_SHA')
        self.assertEqual(c.pushes,[None])
        self.assertEqual(c.github.posts,1)
        self.assertEqual(result['prRequestId'],UUID_PR)

    def test_existing_branch_one_update_with_cas_and_existing_pr(self):
        d,c=self.facade(OLD,[make_pr(OLD)])
        result=self.submit(d)
        self.assertEqual(result['status'],'DONE')
        self.assertEqual(c.pushes,[OLD])
        self.assertEqual(c.github.posts,0)
        self.assertEqual(result['pullRequestNumber'],1)

    def test_already_published_no_mutations(self):
        d,c=self.facade(NEW,[make_pr()])
        result=self.submit(d)
        self.assertEqual(result['status'],'DONE')
        self.assertEqual(result['pullRequestNumber'],1)
        self.assertEqual(c.pushes,[])
        self.assertEqual(c.github.posts,0)
        self.assertEqual(c.worker.targets,0)

    def test_push_already_done_pr_missing_no_repush(self):
        d,c=self.facade(NEW)
        result=self.submit(d)
        self.assertEqual(result['status'],'DONE')
        self.assertEqual(c.pushes,[])
        self.assertEqual(c.github.posts,1)

    def test_push_lost_ack_effect_reached_proceeds_to_pr_without_retry(self):
        d,c=self.facade(); c.push_lost=True
        result=self.submit(d)
        self.assertEqual(result['status'],'DONE')
        self.assertEqual(c.pushes,[None])
        self.assertEqual(c.github.posts,1)

    def test_pr_post_lost_reply_but_exists_no_retry(self):
        d,c=self.facade(NEW); c.github.post_lost=True
        result=self.submit(d)
        self.assertEqual(result['status'],'DONE')
        self.assertEqual(c.github.posts,1)
        self.assertEqual(c.pushes,[])

    def test_pr_pending_without_object_returns_continue_not_another_post(self):
        d,c=self.facade(NEW)
        c.github.post_pending=True
        c.github.post_missing=True
        result=self.submit(d)
        self.assertEqual(result['status'],'CONTINUE')
        self.assertEqual(result['code'],'GIT_DELIVERY_PR_AWAITING_OWNER')
        self.assertEqual(c.github.posts,1)
        self.assertEqual(c.pushes,[])

    def test_pr_pending_with_provider_get_failure_stops(self):
        d,c=self.facade(NEW)
        c.github.post_pending=True
        c.github.post_missing=True
        original=c.github.create_pull_request
        def create(*args, **kwargs):
            result=original(*args,**kwargs)
            c.github.read_broken=True
            return result
        c.github.create_pull_request=create
        result=self.submit(d)
        self.assertEqual(result['status'],'STOP')
        self.assertEqual(result['code'],'GIT_DELIVERY_READ_UNAVAILABLE_OR_INCOMPLETE')
        self.assertEqual(c.github.posts,1)

    def test_pr_post_lost_without_result_stops_no_second_post(self):
        d,c=self.facade(NEW); c.github.post_lost=True;c.github.post_missing=True
        result=self.submit(d)
        self.assertEqual(result['status'],'STOP')
        self.assertEqual(result['code'],'GIT_DELIVERY_PR_NOT_VERIFIED')
        self.assertEqual(c.github.posts,1)

    def test_push_failed_without_effect_stops_before_pr(self):
        d,c=self.facade();c.push_no_effect=True;c.push_lost=True
        result=self.submit(d)
        self.assertEqual(result['status'],'STOP')
        self.assertEqual(result['code'],'GIT_DELIVERY_PUSH_NOT_VERIFIED')
        self.assertEqual(c.pushes,[None])
        self.assertEqual(c.github.posts,0)

    def test_competing_ref_stops_before_pr(self):
        d,c=self.facade(OLD);c.push_competed=True
        result=self.submit(d)
        self.assertEqual(result['status'],'STOP')
        self.assertEqual(c.github.branch,'c'*40)
        self.assertEqual(c.github.posts,0)

    def test_local_dirty_worktree_stops_before_post(self):
        d,c=self.facade();c.worker.clean=False
        result=self.submit(d)
        self.assertEqual(result['status'],'STOP')
        self.assertEqual(result['code'],'GIT_DELIVERY_LOCAL_PRECONDITION_FAILED')
        self.assertEqual(c.pushes,[])
        self.assertEqual(c.github.posts,0)

    def test_incomplete_read_and_http_500_stop_before_post(self):
        d,c=self.facade();c.github.read_broken=True
        r=self.submit(d)
        self.assertEqual(r['status'],'STOP')
        self.assertEqual(r['code'],'GIT_DELIVERY_READ_UNAVAILABLE_OR_INCOMPLETE')
        self.assertEqual(c.pushes,[])
        self.assertEqual(c.github.posts,0)
        c.github.read_broken=False
        c.github.prs=[make_pr(number=i+1) for i in range(500)]
        result=d.inspect('sandbox','agent',NEW)
        self.assertEqual(result['status'],'STOP')
        self.assertEqual(c.github.posts,0)

    def test_closed_or_duplicate_pr_blocks(self):
        d,c=self.facade(NEW,[make_pr(state='closed',merged=True)])
        self.assertEqual(self.submit(d)['code'],'GIT_DELIVERY_PRIOR_PR_CLOSED')
        self.assertEqual(c.github.posts,0)
        d,c=self.facade(NEW,[make_pr(number=1),make_pr(number=2)])
        self.assertEqual(self.submit(d)['code'],'GIT_DELIVERY_PR_AMBIGUOUS')
        self.assertEqual(c.github.posts,0)

    def test_existing_draft_pr_not_ready_for_non_draft_delivery(self):
        d,c=self.facade(NEW,[make_pr(draft=True)])
        self.assertEqual(self.submit(d)['code'],'GIT_DELIVERY_PR_DRAFT_MISMATCH')
        self.assertEqual(c.github.posts,0)
        self.assertEqual(c.pushes,[])
        self.assertEqual(d.inspect('sandbox','agent',NEW,draft=True)['status'],'DONE')

    def test_pr_remote_sha_disagreement_stops(self):
        d,c=self.facade(NEW,[make_pr(OLD)])
        self.assertEqual(self.submit(d)['code'],'GIT_DELIVERY_REF_PR_SHA_MISMATCH')
        self.assertEqual(c.github.posts,0)

    def test_pending_push_does_not_create_pr(self):
        d,c=self.facade();c.push_pending=True
        result=self.submit(d)
        self.assertEqual(result['status'],'STOP')
        self.assertEqual(c.github.posts,0)

    def test_invalid_payload_and_uuid_fail_before_any_read(self):
        d,c=self.facade()
        with self.assertRaises(Denied): self.submit(d,push=UUID_PR)
        with self.assertRaises(Denied): d.inspect('sandbox','agent','not-a-sha')
        with self.assertRaises(Denied):d.submit('sandbox','agent',NEW,title='',body='',
            push_request_id=UUID_PUSH,pr_request_id=UUID_PR,reason='hello')
        self.assertEqual(c.github.reads,0)
        self.assertEqual(c.github.posts,0)


if __name__ == '__main__':
    unittest.main()

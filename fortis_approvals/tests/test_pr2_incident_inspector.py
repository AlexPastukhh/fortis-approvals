"""PR2: incident inspection is strictly a bounded machine READ."""
import unittest
from fortis_approvals.core import Denied
from fortis_approvals.workflow.client import WorkflowClient

UUID='12345678-1234-1234-1234-123456789abc'


class FakeGateway:
    def __init__(self, state='UNCERTAIN', count=205, worker=None, receipt=None):
        self.state=state
        self.count=count
        self.worker=worker
        self.receipt=receipt
        self.calls=[]
        self.drift=False
        self.operation='push_commits'
        self.params={'task':'one','newSha':'a'*40,'secret':'should-not-leak'}
        self.visual=None
        self.event_states=None
        self.capable=True

    def post(self, path, body):
        self.calls.append((path,body))
        if path=='/v1/workspace/capabilities':
            return {'globalRequestInventory':{'readOnly':True,'crossActorDetails':self.capable}}
        if path!='/v1/workspace/details':
            raise AssertionError('UNEXPECTED_MUTATION_ROUTE')
        offset=body['eventOffset']
        limit=body['eventLimit']
        state=self.state if not (self.drift and offset>0) else 'DISPATCHED'
        states=self.event_states or ['APPROVED','DISPATCHED','UNCERTAIN']
        if self.state=='CANCELLED_BEFORE_DISPATCH':
            states=['APPROVED','CANCELLED_BEFORE_DISPATCH']
        event_list=[{'seq':i+1,'state':states[i%len(states)],'detail':{},'at':i}
                    for i in range(self.count)]
        if self.state=='CANCELLED_BEFORE_DISPATCH' and self.count:
            event_list[-1]['state']='CANCELLED_BEFORE_DISPATCH'
            event_list=[x for x in event_list if x['state']!='DISPATCHED']
            for i,row in enumerate(event_list):row['seq']=i+1
        total=len(event_list)
        return {'schemaVersion':1,'request':{'requestId':UUID,
            'actor':'agent-a','fingerprint':'fixed','state':state,
            'result':self.receipt['result'] if state=='EXECUTED' and self.receipt is not None else None,
            'request':{'service':'github','operation':self.operation,
                       'target':'test-repo','params':self.params}},
            'events':event_list[offset:offset+limit], 'eventOffset':offset,
            'eventTotal':total,'worker':self.worker,'receipt':self.receipt,
            'visualReview':self.visual}


class FakeGitHub:
    def __init__(self):self.calls=[]
    def list_branches(self, repo, **kw):
        self.calls.append((repo,kw))
        return {'items':[{'name':'task/one','sha':'a'*40}]}
    def list_pull_requests(self, repo, **kw):
        self.calls.append((repo,kw))
        return {'items':[{'number':88,'head':{'ref':'task/one','sha':'b'*40}}],
                'hasNextPage':False}


class IncidentInspectorTests(unittest.TestCase):
    def flow(self, **kw):
        gateway=FakeGateway(**kw)
        c=WorkflowClient(gateway=gateway,worker=None)
        c.github=FakeGitHub()
        return c,gateway

    def test_uncertain_pagination_and_remote_not_attributed(self):
        c,g=self.flow()
        r=c.incidents.inspect(UUID)
        self.assertEqual(r['assessment'],'UNCONFIRMED')
        self.assertEqual(r['audit']['eventsCollected'],205)
        self.assertTrue(r['audit']['complete'])
        self.assertEqual(r['retryAuthorization'],'NONE')
        self.assertEqual(r['provider']['matchingPullRequests'][0]['number'],88)
        self.assertTrue(r['provider']['desiredHeadObserved'])
        self.assertEqual(r['provider']['effectAttribution'],'UNKNOWN')
        self.assertEqual(r['outcomeAssessment'],'TARGET_STATE_CONFIRMED_ATTRIBUTION_UNKNOWN')
        self.assertNotIn('should-not-leak',str(r))
        self.assertEqual({p for p,_ in g.calls},
                         {'/v1/workspace/capabilities','/v1/workspace/details'})

    def test_changed_snapshot_fails_closed(self):
        c,g=self.flow()
        g.drift=True
        r=c.incidents.inspect(UUID,github_reads=False)
        self.assertEqual(r['assessment'],'UNCONFIRMED')
        self.assertIn('AUDIT_SNAPSHOT_CHANGED',r['missingEvidence'])

    def test_owner_cancelled_before_dispatch_positive_proof(self):
        c,g=self.flow(state='CANCELLED_BEFORE_DISPATCH',count=2)
        r=c.incidents.inspect(UUID,github_reads=False)
        self.assertEqual(r['assessment'],'CONFIRMED_NOT_EXECUTED')
        self.assertEqual(r['retryAuthorization'],'NONE')
        c2,g2=self.flow(state='CANCELLED_BEFORE_DISPATCH',count=2,worker={'state':'CLAIMED'})
        self.assertEqual(c2.incidents.inspect(UUID,github_reads=False)['assessment'],'UNCONFIRMED')

    def test_core_executed_requires_exact_bound_receipt(self):
        c,_=self.flow(state='EXECUTED',count=2)
        self.assertEqual(c.incidents.inspect(UUID,github_reads=False)['assessment'],'UNCONFIRMED')
        receipt={'source':'github-receipts','result':{
            'requestId':UUID,'operation':'push_commits','repository':'test-repo'}}
        c,_=self.flow(state='EXECUTED',count=2,receipt=receipt)
        r=c.incidents.inspect(UUID,github_reads=False)
        self.assertEqual(r['assessment'],'CONFIRMED_EXECUTED')
        self.assertTrue(r['receiptBoundToRequest'])
        wrong=dict(receipt, result=dict(receipt['result'], requestId='another-id'))
        c,_=self.flow(state='EXECUTED',count=2,receipt=wrong)
        self.assertEqual(c.incidents.inspect(UUID,github_reads=False)['assessment'],'UNCONFIRMED')

    def test_late_claimed_worker_never_proves_absent_effect(self):
        c,_=self.flow(state='UNCERTAIN',count=3,worker={
            'state':'CLAIMED','claimedAt':1700000000,
            'lastHeartbeatAt':1700000005,'hasClaim':True,
            'claim':'THIS_FIELD_MUST_NEVER_LEAK'})
        r=c.incidents.inspect(UUID,github_reads=False)
        self.assertEqual(r['assessment'],'UNCONFIRMED')
        self.assertFalse(r['worker']['quiescenceProven'])
        self.assertEqual(r['worker']['lastHeartbeatAt'],1700000005)
        self.assertNotIn('THIS_FIELD_MUST_NEVER_LEAK',str(r))
        self.assertEqual(r['retryAuthorization'],'NONE')

    def test_provider_unavailable_cannot_become_noneffect(self):
        c,_=self.flow()
        class Failure:
            def list_pull_requests(self, *args, **kwargs):
                raise PermissionError('SECRET-BEARER-DO-NOT-SERIALIZE')
        c.github=Failure()
        r=c.incidents.inspect(UUID)
        self.assertEqual(r['provider']['status'],'READ_UNAVAILABLE')
        self.assertIn('PROVIDER_READ_UNAVAILABLE',r['missingEvidence'])
        self.assertNotIn('SECRET-BEARER',str(r))
        self.assertEqual(r['assessment'],'UNCONFIRMED')

    def test_bounded_audit_limit_is_explicit_unknown(self):
        c,g=self.flow(count=10001)
        r=c.incidents.inspect(UUID,github_reads=False)
        self.assertIn('AUDIT_LIMIT',r['missingEvidence'])
        self.assertFalse(r['audit']['complete'])
        self.assertEqual(r['assessment'],'UNCONFIRMED')
        self.assertEqual(sum(path=='/v1/workspace/details' for path,_ in g.calls),1)

    def test_missing_receipt_not_proven_by_later_matching_branch(self):
        c,_=self.flow(state='CLOSED_UNCONFIRMED',count=3)
        r=c.incidents.inspect(UUID)
        self.assertEqual(r['outcomeAssessment'],'TARGET_STATE_CONFIRMED_ATTRIBUTION_UNKNOWN')
        self.assertEqual(r['assessment'],'UNCONFIRMED')
        self.assertIn('BOUND_RECEIPT_NOT_CONFIRMED',r['missingEvidence'])
        self.assertEqual(r['retryAuthorization'],'NONE')

    def test_partial_visual_receipt_does_not_retry_issue(self):
        c,g=self.flow(state='UNCERTAIN',count=3)
        g.operation='publish_visual_review'
        g.params={'runId':'run-safe','media':[{'index':0},{'index':1}]}
        g.visual={'issueNumber':44,'uploadedFiles':1,'repository':'visual-workspace'}
        r=c.incidents.inspect(UUID,github_reads=False)
        self.assertEqual(r['outcomeAssessment'],'PARTIAL_EFFECT_CONFIRMED')
        self.assertEqual(r['assessment'],'UNCONFIRMED')
        self.assertEqual(r['visualReview']['issueNumber'],44)
        self.assertEqual(r['retryAuthorization'],'NONE')

    def test_pr_create_pre_ack_checkpoint_is_not_nonexecution_proof(self):
        c,g=self.flow(state='UNCERTAIN',count=4)
        g.operation='create_pull_request'
        g.params={'head':'task/one','base':'main'}
        g.event_states=['APPROVED','DISPATCHED','PR_CREATE_POST_STARTED','UNCERTAIN']
        r=c.incidents.inspect(UUID,github_reads=False)
        self.assertEqual(r['phase'],'PR_CREATE_POST_STARTED')
        self.assertEqual(r['assessment'],'UNCONFIRMED')
        self.assertEqual(r['retryAuthorization'],'NONE')

    def test_legacy_and_bad_uuid_fail_closed(self):
        c,g=self.flow()
        g.capable=False
        with self.assertRaises(Denied):c.incidents.inspect(UUID)
        with self.assertRaises(Denied):c.incidents.inspect('bad-uuid')
        self.assertEqual(len(g.calls),1)


if __name__=='__main__':
    unittest.main()


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
        self.events=None
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
        if self.events is not None:
            event_list=self.events
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

    @staticmethod
    def audit_rows(sequence):
        states=('PENDING','APPROVED','DISPATCHED','EXECUTED')
        return [{'seq':seq,'state':states[i % len(states)],'detail':{},'at':i}
                for i,seq in enumerate(sequence)]

    def bound_audit_flow(self, events):
        receipt={'source':'github-receipts','result':{
            'requestId':UUID,'operation':'push_commits','repository':'test-repo'}}
        c,g=self.flow(state='EXECUTED',count=len(events),receipt=receipt)
        g.events=events
        return c,g

    def test_p1_sparse_global_audit_ids_are_complete(self):
        c,g=self.bound_audit_flow(self.audit_rows([8665,8672,8673,8674]))
        g.operation='add_pr_release_labels'
        g.params={'number':76,'expectedHeadSha':'a'*40}
        g.receipt['result'].update(operation=g.operation,number=76,
                                  headSha='a'*40,labels=['release:no-deployment'])
        report=c.incidents.inspect(UUID,github_reads=False)
        self.assertEqual(report['assessment'],'CONFIRMED_EXECUTED')
        self.assertEqual(report['missingEvidence'],[])
        self.assertEqual(report['audit']['eventsCollected'],4)
        self.assertTrue(report['audit']['complete'])
        self.assertTrue(report['audit']['dispatchedObserved'])
        self.assertEqual(report['retryAuthorization'],'NONE')
        self.assertEqual({path for path,_ in g.calls},
                         {'/v1/workspace/capabilities','/v1/workspace/details'})

    def test_sparse_global_ids_across_pages_are_complete(self):
        c,g=self.bound_audit_flow(self.audit_rows(range(1001,1411,2)))
        report=c.incidents.inspect(UUID,github_reads=False)
        self.assertEqual(report['assessment'],'CONFIRMED_EXECUTED')
        self.assertTrue(report['audit']['complete'])
        self.assertEqual(report['audit']['eventsCollected'],205)
        self.assertEqual(report['missingEvidence'],[])
        self.assertEqual([body['eventOffset'] for path,body in g.calls
                          if path=='/v1/workspace/details'],[0,100,200,0])
        self.assertEqual(report['retryAuthorization'],'NONE')

    def test_real_core_interleaved_requests_preserve_audit_completeness(self):
        import json
        import tempfile
        from pathlib import Path
        from fortis_approvals.core import Core, Authenticator
        from fortis_approvals.synthetic import SyntheticAdapter
        from fortis_approvals.tests.test_core import SyntheticOwnerVerifier

        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            adapter=SyntheticAdapter(root/'adapter.sqlite')
            adapter.seed('first','before')
            adapter.seed('other','before')
            owner=SyntheticOwnerVerifier()
            core=Core(root/'core.sqlite',adapters={'synthetic':adapter},
                      policies={('synthetic','set_ask'):'ASK',
                                ('synthetic','set_free'):'ALLOW'},
                      authenticator=Authenticator({'first-grant':'actor-a',
                                                   'other-grant':'actor-b'}),
                      owner_verifier=owner)
            def request(ident,target,operation):
                return dict(requestId=ident,service='synthetic',operation=operation,
                            target=target,params={'value':'after'},expectedVersion=0,
                            reason='Offline interleaved audit fixture')
            pending=core.client('first-grant','submit',request(UUID,'first','set_ask'))
            core.client('other-grant','submit',
                        request('22345678-1234-1234-1234-123456789abc','other','set_free'))
            core.owner_decide(UUID,'approve',owner.proof(UUID,pending['fingerprint'],'approve'))
            rows=core.events(UUID)
        sequence=[row['seq'] for row in rows]
        self.assertTrue(any(b>a+1 for a,b in zip(sequence,sequence[1:])))
        c,g=self.flow(state='EXECUTED',count=len(rows))
        g.events=[{**{k:row[k] for k in ('seq','state','at')},
                   'detail':json.loads(row['detail'])} for row in rows]
        report=c.incidents.inspect(UUID,github_reads=False)
        self.assertTrue(report['audit']['complete'])
        self.assertEqual(report['audit']['eventsCollected'],len(rows))
        self.assertEqual(report['assessment'],'UNCONFIRMED')  # No bound receipt.
        self.assertNotIn('AUDIT_SEQUENCE_GAP',report['missingEvidence'])

    def test_invalid_global_audit_ids_fail_closed(self):
        cases=[('duplicate',[1,1]),('reversed',[2,1]),('zero',[0]),
               ('negative',[-1]),('boolean',[True]),('string',['1']),
               ('null',[None]),('missing',[None])]
        for name,sequence in cases:
            with self.subTest(name=name):
                events=self.audit_rows(sequence)
                if name=='missing':events[0].pop('seq')
                c,g=self.bound_audit_flow(events)
                report=c.incidents.inspect(UUID,github_reads=False)
                self.assertEqual(report['assessment'],'UNCONFIRMED')
                self.assertIn('AUDIT_SEQUENCE_INVALID',report['missingEvidence'])
                self.assertFalse(report['audit']['complete'])
                self.assertEqual(report['retryAuthorization'],'NONE')
                self.assertEqual({path for path,_ in g.calls},
                                 {'/v1/workspace/capabilities','/v1/workspace/details'})

    def test_invalid_sequence_across_page_boundary_fails_closed(self):
        for boundary in (100,99,'101',True):
            with self.subTest(boundary=boundary):
                events=self.audit_rows(range(1,206))
                events[100]['seq']=boundary
                c,g=self.bound_audit_flow(events)
                report=c.incidents.inspect(UUID,github_reads=False)
                self.assertEqual(report['assessment'],'UNCONFIRMED')
                self.assertIn('AUDIT_SEQUENCE_INVALID',report['missingEvidence'])
                self.assertEqual(report['audit']['eventsCollected'],100)
                self.assertFalse(report['audit']['complete'])
                self.assertEqual(report['retryAuthorization'],'NONE')

    def test_incomplete_or_excess_audit_pages_fail_closed(self):
        for fault in ('short-first','short-middle','empty-middle','extra-final'):
            with self.subTest(fault=fault):
                count=101 if fault=='extra-final' else 205
                c,g=self.bound_audit_flow(self.audit_rows(range(1001,1001+count)))
                original=g.post
                def post(path,body,original=original,fault=fault):
                    data=original(path,body)
                    if path=='/v1/workspace/details' and body['eventLimit']==100:
                        offset=body['eventOffset']
                        if (fault=='short-first' and offset==0 or
                                fault=='short-middle' and offset==100):
                            data['events']=data['events'][:-1]
                        elif fault=='empty-middle' and offset==100:
                            data['events']=[]
                        elif fault=='extra-final' and offset==100:
                            data['events'].append(dict(data['events'][-1],seq=data['events'][-1]['seq']+1))
                    return data
                g.post=post
                report=c.incidents.inspect(UUID,github_reads=False)
                self.assertEqual(report['assessment'],'UNCONFIRMED')
                self.assertIn('AUDIT_PAGE_INVALID',report['missingEvidence'])
                self.assertFalse(report['audit']['complete'])
                self.assertEqual(report['retryAuthorization'],'NONE')

    def test_sparse_audit_metadata_drift_fails_closed(self):
        for field in ('eventTotal','eventOffset','fingerprint'):
            with self.subTest(field=field):
                c,g=self.bound_audit_flow(self.audit_rows(range(1001,1411,2)))
                original=g.post
                def post(path,body,original=original,field=field):
                    data=original(path,body)
                    if path=='/v1/workspace/details' and body['eventOffset']==100:
                        if field=='fingerprint':data['request']['fingerprint']='changed'
                        else:data[field]+=1
                    return data
                g.post=post
                report=c.incidents.inspect(UUID,github_reads=False)
                self.assertEqual(report['assessment'],'UNCONFIRMED')
                self.assertIn('AUDIT_SNAPSHOT_CHANGED',report['missingEvidence'])
                self.assertFalse(report['audit']['complete'])
                self.assertEqual(report['retryAuthorization'],'NONE')

    def test_sparse_audit_final_receipt_or_worker_drift_fails_closed(self):
        for field in ('receipt','worker'):
            with self.subTest(field=field):
                c,g=self.bound_audit_flow(self.audit_rows([8665,8672,8673,8674]))
                original=g.post
                def post(path,body,original=original,field=field):
                    data=original(path,body)
                    if path=='/v1/workspace/details' and body['eventLimit']==1:
                        data[field]=None if field=='receipt' else {'state':'CLAIMED'}
                    return data
                g.post=post
                report=c.incidents.inspect(UUID,github_reads=False)
                self.assertEqual(report['assessment'],'UNCONFIRMED')
                self.assertIn('EVIDENCE_CHANGED_DURING_READ',report['missingEvidence'])
                self.assertFalse(report['audit']['complete'])
                self.assertEqual(report['retryAuthorization'],'NONE')

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

    def test_create_branch_exact_sha_is_target_state_not_uuid_receipt(self):
        c,g=self.flow()
        g.operation='create_branch'
        g.params={'branch':'task/one','sourceSha':'a'*40}
        observed=c.incidents.inspect(UUID)
        self.assertEqual(observed['outcomeAssessment'],
                         'TARGET_STATE_CONFIRMED_ATTRIBUTION_UNKNOWN')
        self.assertEqual(observed['provider']['remoteBranchSha'],'a'*40)
        self.assertEqual(observed['assessment'],'UNCONFIRMED')
        self.assertEqual(observed['retryAuthorization'],'NONE')
        self.assertEqual({path for path,_ in g.calls},
                         {'/v1/workspace/capabilities','/v1/workspace/details'})
        g.params['sourceSha']='b'*40
        missing=c.incidents.inspect(UUID)
        self.assertEqual(missing['outcomeAssessment'],'OUTCOME_UNCONFIRMED')
        self.assertFalse(missing['provider']['desiredHeadObserved'])

    def test_merge_and_ready_exact_pr_readback_do_not_attrib_to_uuid(self):
        c,g=self.flow()
        class Pull:
            def __init__(self, *, merged, draft, state, head):
                self.merged=merged;self.draft=draft;self.state=state;self.head=head
                self.calls=[]
            def get_pull_request(self, repo, number):
                self.calls.append((repo,number))
                return {'pullRequest':{'number':number,
                    'head':{'sha':self.head},
                    'state':self.state,'merged':self.merged,'draft':self.draft}}
        g.operation='merge_pull_request'
        g.params={'number':89,'expectedHeadSha':'a'*40}
        c.github=Pull(merged=True,draft=False,state='closed',head='a'*40)
        result=c.incidents.inspect(UUID)
        self.assertEqual(result['outcomeAssessment'],
                         'TARGET_STATE_CONFIRMED_ATTRIBUTION_UNKNOWN')
        self.assertEqual(result['assessment'],'UNCONFIRMED')
        self.assertEqual(result['retryAuthorization'],'NONE')
        self.assertEqual(c.github.calls,[('test-repo',89)])
        c.github=Pull(merged=False,draft=False,state='open',head='a'*40)
        result=c.incidents.inspect(UUID)
        self.assertEqual(result['outcomeAssessment'],'OUTCOME_UNCONFIRMED')
        g.operation='mark_pr_ready'
        result=c.incidents.inspect(UUID)
        self.assertEqual(result['outcomeAssessment'],
                         'TARGET_STATE_CONFIRMED_ATTRIBUTION_UNKNOWN')
        c.github=Pull(merged=False,draft=True,state='open',head='a'*40)
        result=c.incidents.inspect(UUID)
        self.assertEqual(result['outcomeAssessment'],'OUTCOME_UNCONFIRMED')

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

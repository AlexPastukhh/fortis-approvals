"""No replay of a previously claimed native job, including across TLS clients."""
import concurrent.futures
from pathlib import Path
import tempfile
from threading import Thread
import time
import unittest
import uuid

from fortis_approvals.workflow.store import Store
import test_native_workflow as native


class OnceOnlyClaimStore(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory(prefix='claim-once-fixture-')
        self.addCleanup(temp.cleanup)
        self.store=Store(Path(temp.name)/'state')
        self.ident=str(uuid.uuid4())
        self.actor='same-actor'
        self.payload=dict(requestId=self.ident,service='workspace',
            operation='inspect',target='sandbox',params={'task':None},
            approvedPreview={'operation':'inspect'})
        self.store.enqueue(self.actor,self.payload)

    def test_second_claim_has_no_payload_or_claim_token_and_original_can_finish(self):
        first=self.store.claim(self.actor,self.ident)
        self.assertEqual(first['state'],'CLAIMED')
        self.assertEqual(first['payload'],self.payload)
        original_claim=first['claim']
        second=self.store.claim(self.actor,self.ident)
        self.assertEqual(second,{'state':'CLAIMED'})
        self.assertEqual(self.store.job(self.ident)['claim'],original_claim)
        self.assertEqual(self.store.job(self.ident)['state'],'CLAIMED')
        result=dict(requestId=self.ident,operation='inspect',repository='sandbox',data={'clean':True})
        self.store.finish(self.actor,self.ident,original_claim,result,None)
        self.assertEqual(self.store.job(self.ident)['state'],'DONE')
        self.assertEqual(self.store.claim(self.actor,self.ident),{'state':'DONE'})
        self.assertIsNone(self.store.claim('other-actor',self.ident))

    def test_simultaneous_consumers_receive_only_one_executable_claim(self):
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            answers=list(pool.map(lambda _:self.store.claim(self.actor,self.ident),range(2)))
        issued=[job for job in answers if job and 'payload' in job]
        withheld=[job for job in answers if job and 'payload' not in job]
        self.assertEqual(len(issued),1)
        self.assertEqual(withheld,[{'state':'CLAIMED'}])
        self.assertEqual(issued[0]['claim'],self.store.job(self.ident)['claim'])


class NativeTLSClaimNoReplay(unittest.TestCase):
    setUp=native.NativeTLS.setUp
    stop=native.NativeTLS.stop

    def test_same_actor_cannot_replay_claim_over_tls(self):
        app=self.machine.get_app()
        app.workspace.wait_seconds=8
        ident=str(uuid.uuid4())
        replies=[];failures=[]
        def submit():
            try:
                replies.append(self.gateway.post('/v1/workspace/submit',dict(
                    requestId=ident,operation='inspect',target='sandbox',
                    params={'task':None},reason='Offline single-delivery TLS claim'),accept_202=True))
            except Exception as exc:failures.append(type(exc).__name__)
        thread=Thread(target=submit,daemon=True);thread.start()
        for _ in range(200):
            job=app.store.job(ident)
            if job and job['state']=='QUEUED':break
            time.sleep(.01)
        else:self.fail('Gateway never queued test job')
        first=self.gateway.post('/v1/workspace/claim',{'requestId':ident})['job']
        self.assertIsNotNone(first)
        self.assertIn('payload',first)
        second=self.gateway.post('/v1/workspace/claim',{'requestId':ident})['job']
        # Finish the original worker, regardless of repeated claim response,
        # before asserting; avoid leaving a test fixture with an active job.
        result,error=self.worker.execute(first)
        self.gateway.post('/v1/workspace/finish',dict(
            requestId=ident,claim=first['claim'],result=result,error=error))
        thread.join(timeout=8)
        self.assertFalse(thread.is_alive())
        self.assertFalse(failures,failures)
        self.assertEqual(second,{'state':'CLAIMED'})
        self.assertEqual(self.flow.result(ident,reconcile=True)['state'],'EXECUTED')
        self.assertEqual(app.store.job(ident)['state'],'DONE')
        self.assertEqual(self.api.posts,0)


if __name__=='__main__':
    unittest.main()

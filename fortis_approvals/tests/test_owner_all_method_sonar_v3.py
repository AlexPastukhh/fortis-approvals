"""Owner-managed Sonar ALLOW through trusted broker, with CAS/readback."""
import tempfile
import unittest
import uuid
from pathlib import Path

from fortis_approvals.core import Authenticator, Denied
from fortis_approvals.extensions.owner_policy_engine_v2 import UnifiedPolicyCore
from fortis_approvals.extensions.owner_policy_editor_v2 import OwnerPolicyEditor
from fortis_approvals.repo_action_contract import RepoIntentBroker
from fortis_approvals.sonar import SonarIssueAdapter
from fortis_approvals.tests.test_sonar import FakeSonar
from fortis_approvals.tests.test_owner_policy_local_deny_http_phase6c2 import HTTPFixtureWebAuthn


class SonarOwnerPolicyTests(unittest.TestCase):
    def setUp(self):
        d=tempfile.TemporaryDirectory()
        self.addCleanup(d.cleanup)
        root=Path(d.name)
        self.remote=FakeSonar()
        self.owner=HTTPFixtureWebAuthn()
        self.adapter=SonarIssueAdapter(self.remote,project_keys={'gd-cap'},
                                      receipt_store=root/'receipt.sqlite')
        self.actor='agent-sonar'
        self.credential='sonar-machine-grant'
        self.coord=(self.actor,'sonarcloud','accept_issue')
        self.core=UnifiedPolicyCore(root/'core.sqlite',
            adapters={'sonarcloud':self.adapter},
            policies={self.coord:'ASK'},
            authenticator=Authenticator({self.credential:self.actor}),
            owner_verifier=self.owner,policy_version='sonar-v3')
        self.core.install_policy_authority({self.coord:{'DENY','ASK','ALLOW'}})
        self.broker=RepoIntentBroker(self.core,
            actor_operations={self.actor:{('sonarcloud','accept_issue')}})

    def set_policy(self,old,new):
        edit=OwnerPolicyEditor(self.core,self.owner,source_digest='a'*64,
                               credential_generation=lambda:'b'*64)
        candidate=dict(actor=self.actor,provider='sonarcloud',
            operation='accept_issue',scope='actor',target=None,
            expectedPolicy=old,desiredPolicy=new,
            expectedRevision=int(self.core.policy_version.rsplit(':',1)[1]),
            expectedPolicyVersion=self.core.policy_version,
            reasonCode='OWNER_POLICY_CHANGE')
        started=edit.begin(self.owner._session,self.owner._csrf,candidate)
        edit.finish(self.owner._session,self.owner._csrf,started['ceremonyId'],
                    {'syntheticTestOnlyUv':True},started['change'])

    def intent(self,issue='S1'):
        return dict(requestId=str(uuid.uuid4()),service='sonarcloud',
            operation='accept_issue',target=issue,
            params={'projectKey':'gd-cap'},reason='Owner policy Sonar action')

    def test_owner_allow_executes_without_per_request_ask_and_keeps_readback(self):
        self.set_policy('ASK','ALLOW')
        req=self.intent()
        executed=self.broker.submit(self.credential,req)
        self.assertEqual(executed['state'],'EXECUTED')
        self.assertEqual(self.remote.posts,1)
        self.assertIsNone(self.core._read(req['requestId'])['decision'])
        self.assertIsNone(self.core._read(req['requestId'])['owner'])
        self.assertEqual(self.adapter.receipt(req['requestId'])['status'],'ACCEPTED')
        self.assertEqual([e['state'] for e in self.core.events(req['requestId'])],
                         ['APPROVED','DISPATCHED','EXECUTED'])
        self.set_policy('ALLOW','DENY')
        with self.assertRaises(Denied):
            self.broker.submit(self.credential,self.intent())
        self.assertEqual(self.remote.posts,1)

    def test_ask_is_still_owner_approved_and_unconfirmed_not_retried(self):
        req=self.intent()
        pending=self.broker.submit(self.credential,req)
        self.assertEqual(pending['state'],'PENDING')
        self.assertEqual(self.remote.posts,0)
        self.assertEqual(self.core.client(self.credential,'status',req['requestId'])['state'],
                         'PENDING')


if __name__=='__main__':
    unittest.main()

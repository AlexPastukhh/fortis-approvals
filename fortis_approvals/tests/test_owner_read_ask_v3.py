"""Source-only exact one-shot native READ ASK contract, no provider network."""
import sqlite3
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
import uuid
from pathlib import Path
from unittest.mock import patch

from fortis_approvals.core import Authenticator, Conflict, Denied, Stale
from fortis_approvals.extensions.owner_policy_engine_v2 import UnifiedPolicyCore
from fortis_approvals.extensions.owner_policy_editor_v2 import OwnerPolicyEditor, UnifiedPolicyPortal
from fortis_approvals.repo_action_contract import RepoIntentBroker
from fortis_approvals.read_approval import install_owner_read_approval
from fortis_approvals.tests.test_owner_policy_local_deny_http_phase6c2 import HTTPFixtureWebAuthn

ACTOR='agent-1'
SERVICE='sonarcloud'
OPERATION='get_quality_gate'
COORD=(ACTOR,SERVICE,OPERATION)
GRANT='offline-grant'
SOURCE='a'*64
CREDS='b'*64


class Reader:
    def __init__(self):
        self.calls=[]
    def read(self,request):
        self.calls.append(request)
        return dict(operation=OPERATION,projectKey=request['target'],status='OK',
                    conditions=[],scope='offline-project',prShaBinding=None)


class ReadAskTests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root=Path(temp.name)
        self.owner=HTTPFixtureWebAuthn()
        self.owner.origin='http://localhost:18990'
        self.reader=Reader()
        self.core=UnifiedPolicyCore(self.root/'approvals.sqlite',
            adapters={'sonarcloud':object()},
            policies={COORD:'ALLOW'},authenticator=Authenticator({GRANT:ACTOR}),
            owner_verifier=self.owner,policy_version='native-read')
        self.broker=RepoIntentBroker(self.core,actor_operations={ACTOR:{('synthetic','set_ask')}},
            actor_read_operations={ACTOR:{(SERVICE,OPERATION)}},
            read_adapters={'sonarcloud':self.reader})
        self.core.install_policy_authority({COORD:{'DENY','ASK','ALLOW'}})
        self.portal=UnifiedPolicyPortal(self.core,self.owner)
        install_owner_read_approval(self.core,self.broker,self.portal)
        editor=OwnerPolicyEditor(self.core,self.owner,source_digest=SOURCE,
            credential_generation=lambda:CREDS)
        self.portal.bind_editor(editor)
        self.editor=editor

    def change(self,old,new):
        candidate=dict(actor=ACTOR,provider=SERVICE,operation=OPERATION,
            scope='actor',target=None,expectedPolicy=old,desiredPolicy=new,
            expectedRevision=int(self.core.policy_version.rsplit(':',1)[1]),
            expectedPolicyVersion=self.core.policy_version,reasonCode='OWNER_POLICY_CHANGE')
        b=self.editor.begin(self.owner._session,self.owner._csrf,candidate)
        self.editor.finish(self.owner._session,self.owner._csrf,
            b['ceremonyId'],{'syntheticTestOnlyUv':True},b['change'])

    @staticmethod
    def query():
        return dict(requestId=str(uuid.uuid4()),service=SERVICE,
            operation=OPERATION,target='offline_project',params={},
            reason='Ask owner before isolated read')

    def test_allow_ask_and_one_shot_owner_readback(self):
        allow=self.broker.read(GRANT,self.query())
        self.assertEqual(allow['data']['status'],'OK')
        self.change('ALLOW','ASK')
        query=self.query()
        pending=self.broker.read(GRANT,query)
        self.assertEqual(pending['state'],'PENDING')
        self.assertEqual(len(self.reader.calls),1)
        self.assertEqual(self.broker.read(GRANT,query)['state'],'PENDING')
        self.assertEqual(len(self.reader.calls),1)
        with patch.object(self.owner,'verify',return_value='offline-owner',create=True):
            approved=self.core.owner_decide(query['requestId'],'approve',{'offlineFakeProof':True})
        self.assertEqual(approved['state'],'EXECUTED')
        self.assertEqual(len(self.reader.calls),1)
        result=self.broker.read(GRANT,query)
        self.assertEqual(result['data']['status'],'OK')
        self.assertEqual(len(self.reader.calls),2)
        with self.assertRaisesRegex(Denied,'ALREADY_USED'):
            self.broker.read(GRANT,query)
        self.assertEqual(len(self.reader.calls),2)
        self.change('ASK','DENY')
        with self.assertRaises(Denied):
            self.broker.read(GRANT,self.query())
        self.assertEqual(len(self.reader.calls),2)

    def test_replay_changed_read_identity_fails_without_provider_effect(self):
        self.change('ALLOW','ASK')
        query=self.query()
        pending=self.broker.read(GRANT,query)
        self.assertEqual(pending['state'],'PENDING')
        changed=dict(query,target='different_project')
        with self.assertRaises((Denied,Stale,Conflict)):
            self.broker.read(GRANT,changed)
        self.assertEqual(self.reader.calls,[])

    def test_expired_approved_read_never_contacts_provider(self):
        self.change('ALLOW','ASK')
        query=self.query()
        self.assertEqual(self.broker.read(GRANT,query)['state'],'PENDING')
        with patch.object(self.owner,'verify',return_value='offline-owner',create=True):
            self.assertEqual(self.core.owner_decide(query['requestId'],'approve',
                             {'offlineFakeProof':True})['state'],'EXECUTED')
        expires=self.core._read(query['requestId'])['expiresAt']
        with patch.object(self.core,'clock',return_value=expires):
            with self.assertRaises(Stale):
                self.broker.read(GRANT,query)
        self.assertEqual(self.reader.calls,[])

    def test_parallel_consume_allows_exactly_one_provider_read(self):
        self.change('ALLOW','ASK')
        query=self.query()
        self.assertEqual(self.broker.read(GRANT,query)['state'],'PENDING')
        with patch.object(self.owner,'verify',return_value='offline-owner',create=True):
            self.assertEqual(self.core.owner_decide(query['requestId'],'approve',
                             {'offlineFakeProof':True})['state'],'EXECUTED')
        def attempt(_):
            try:
                return self.broker.read(GRANT,query)
            except Denied as exc:
                return str(exc)
        with ThreadPoolExecutor(max_workers=2) as pool:
            outcomes=list(pool.map(attempt,range(2)))
        self.assertEqual(sum(type(x) is dict and 'data' in x for x in outcomes),1)
        self.assertEqual(sum('ALREADY_USED' in x for x in outcomes if type(x) is str),1)
        self.assertEqual(len(self.reader.calls),1)

    def test_altered_spend_schema_fails_closed_before_read(self):
        self.change('ALLOW','ASK')
        query=self.query()
        self.assertEqual(self.broker.read(GRANT,query)['state'],'PENDING')
        with patch.object(self.owner,'verify',return_value='offline-owner',create=True):
            self.assertEqual(self.core.owner_decide(query['requestId'],'approve',
                             {'offlineFakeProof':True})['state'],'EXECUTED')
        with self.core._db() as db:
            db.execute('DROP TABLE owner_read_approval_spent')
            db.execute('CREATE TABLE owner_read_approval_spent('
                       'request_id TEXT,actor TEXT NOT NULL,used_at INTEGER NOT NULL)')
        with self.assertRaisesRegex(Denied,'OWNER_READ_SPEND_SCHEMA_INVALID'):
            self.broker.read(GRANT,query)
        self.assertEqual(self.reader.calls,[])

    def test_preexisting_unsafe_spend_schema_rejected_on_install(self):
        path=self.root/'unsafe-core.sqlite'
        with sqlite3.connect(path) as db:
            db.execute('CREATE TABLE owner_read_approval_spent('
                       'request_id TEXT,actor TEXT NOT NULL,used_at INTEGER NOT NULL)')
        path.chmod(0o600)
        core=UnifiedPolicyCore(path,adapters={'sonarcloud':object()},
            policies={COORD:'ALLOW'},authenticator=Authenticator({GRANT:ACTOR}),
            owner_verifier=self.owner,policy_version='native-read')
        core.install_policy_authority({COORD:{'DENY','ASK','ALLOW'}})
        broker=RepoIntentBroker(core,actor_operations={ACTOR:{('synthetic','set_ask')}},
            actor_read_operations={ACTOR:{(SERVICE,OPERATION)}},
            read_adapters={'sonarcloud':self.reader})
        portal=UnifiedPolicyPortal(core,self.owner)
        with self.assertRaisesRegex(Denied,'OWNER_READ_SPEND_SCHEMA_INVALID'):
            install_owner_read_approval(core,broker,portal)
        self.assertNotIn('read-authorization',core.adapters)
        self.assertIsNone(getattr(broker,'read_approval',None))

    def test_no_approval_if_owner_rejects(self):
        self.change('ALLOW','ASK')
        query=self.query()
        self.broker.read(GRANT,query)
        with patch.object(self.owner,'verify',return_value='offline-owner',create=True):
            rejected=self.core.owner_decide(query['requestId'],'reject',{'offlineFakeProof':True})
        self.assertEqual(rejected['state'],'REJECTED')
        result=self.broker.read(GRANT,query)
        self.assertEqual(result['state'],'REJECTED')
        self.assertEqual(self.reader.calls,[])


if __name__=='__main__':
    unittest.main()

"""Owner-only incident protocol extensions without altering the pinned Core/Portal."""
from pathlib import Path
from types import SimpleNamespace
import json
from unittest.mock import patch

from fortis_approvals.core import Denied
from fortis_approvals.incidents import IncidentCore, IncidentOwnerPortal, IncidentOwnerWebAuthn
from fortis_approvals.workflow.ingress import NativeIngress, NATIVE_PATHS
from test_owner_portal import G2WebAuthnTest
from test_owner_portal_input import OwnerPortalInputTests


class IncidentOwnerInputTests(OwnerPortalInputTests):
    def setUp(self):
        super().setUp()
        root=Path(self.temp.name)
        self.core=IncidentCore(
            root/'approvals.sqlite',
            adapters={'synthetic':self.adapter},
            policies={('synthetic','set_ask'):'ASK'},
            authenticator=self.auth,owner_verifier=self.owner)
        self.portal=IncidentOwnerPortal(self.core,self.owner)

    def test_machine_full_details_read_is_actor_scoped_and_nonmutating(self):
        row=self.submit()
        rid=row['requestId']
        assert '/v1/workspace/details' in NATIVE_PATHS
        native=NativeIngress(SimpleNamespace(
            broker=SimpleNamespace(core=self.core)),
            github=None,workspace=None,store=None,actor='agent-1')
        payload={'requestId':rid,'eventOffset':0,'eventLimit':100}
        details=native._dispatch('/v1/workspace/details',payload,'agent-secret','agent-1')
        self.assertEqual(details['request']['requestId'],rid)
        self.assertEqual(details['request']['request'],row['request'])
        self.assertEqual(details['request']['preview'],row['preview'])
        self.assertEqual(details['request']['actor'],'agent-1')
        self.assertEqual(details['eventTotal'],1)
        self.assertEqual(details['events'][0]['state'],'PENDING')
        self.assertIsNone(details['worker'])
        self.assertIsNone(details['receipt'])
        self.assertEqual(details['eventsTruncated'],False)
        self.assertEqual(self.core.events(rid)[0]['state'],'PENDING')
        self.assertEqual(native._dispatch('/v1/workspace/details',
            {**payload,'eventLimit':1},'agent-secret','agent-1')['eventTotal'],1)
        with self.assertRaises(Denied):
            native._dispatch('/v1/workspace/details',payload,'wrong-secret','agent-1')
        with self.assertRaises(Denied):
            native._dispatch('/v1/workspace/details',
                             {**payload,'operation':'execute'},'agent-secret','agent-1')
        with self.assertRaises(Denied):
            self.core.machine_request_details('agent-secret',rid,event_limit=100000)
        self.assertEqual(self.core._read(rid)['state'],'PENDING')

    def test_machine_details_hide_worker_claim_and_return_worker_metadata(self):
        row=self.submit()
        rid=row['requestId']
        class FakeStore:
            def job(self,request_id):
                assert request_id==rid
                return dict(id=rid,actor='agent-1',state='CLAIMED',
                            claim='DO_NOT_EXPOSE_SECRET_CLAIM',
                            error=None,result=None)
        self.adapter.store=FakeStore()
        details=self.core.machine_request_details('agent-secret',rid)
        self.assertEqual(details['worker'],{'state':'CLAIMED','actor':'agent-1',
            'error':None,'hasClaim':True,'result':None})
        self.assertNotIn('DO_NOT_EXPOSE_SECRET_CLAIM',json.dumps(details))
        self.assertEqual(details['request']['state'],'PENDING')

    def test_simple_close_session_csrf_audit_and_no_reexecution(self):
        row=self.submit()
        rid=row['requestId']
        with patch.object(self.adapter,'apply',side_effect=RuntimeError('UNKNOWN')):
            code,unknown,_=self.call('/v1/owner/decision/session',self.decision_body(row))
        self.assertEqual((code,unknown['state']),(200,'UNCERTAIN'))
        body={'requestId':rid,'fingerprint':unknown['fingerprint']}
        encoded=json.dumps(body).encode()
        self.assertEqual(self.call('/v1/owner/incidents/close/simple',encoded,cookie='')[0],403)
        self.assertEqual(self.call('/v1/owner/incidents/close/simple',encoded,csrf=None)[0],403)
        self.assertEqual(self.call('/v1/owner/incidents/close/simple',
            json.dumps({**body,'fingerprint':'a'*64}).encode())[0],403)
        self.assertEqual(self.call('/v1/owner/incidents/close/simple',
            json.dumps({'requestId':rid}).encode())[0],404)
        self.assertEqual(self.core._read(rid)['state'],'UNCERTAIN')
        self.portal.read_only_banner=True
        self.assertEqual(self.call('/v1/owner/incidents/close/simple',encoded)[0],403)
        self.portal.read_only_banner=False
        code,closed,_=self.call('/v1/owner/incidents/close/simple',encoded)
        self.assertEqual((code,closed['state']),(200,'CLOSED_UNCONFIRMED'))
        self.assertIsNone(closed['result'])
        self.assertEqual(closed['failure'],'REMOTE_OUTCOME_UNCONFIRMED')
        self.assertEqual(closed['incidentClosure']['owner'],'test-owner')
        self.assertEqual(closed['incidentClosure']['closeMethod'],'authenticated_owner_session')
        self.assertEqual(closed['incidentClosure']['outcome'],'UNCONFIRMED')
        self.assertEqual(self.adapter.get('R3')['version'],0)
        self.assertEqual(self.core.owner_unresolved()['total'],0)
        self.assertEqual(self.core.events(rid)[-1]['state'],'CLOSED_UNCONFIRMED')
        self.assertEqual(self.core.machine_request_details('agent-secret',rid)['incidentClosure'],
                         closed['incidentClosure'])
        self.assertEqual(self.call('/v1/owner/incidents/close/simple',encoded)[0],403)

    def test_unresolved_owner_listing_is_auth_bound_and_not_pending(self):
        pending=self.submit()
        self.assertEqual(self.call('/v1/owner/unresolved',cookie='')[0],403)
        code,unresolved,_=self.call('/v1/owner/unresolved')
        self.assertEqual(code,200)
        self.assertEqual(unresolved,{'items':[],'total':0,'truncated':False})
        self.assertEqual(self.core._read(pending['requestId'])['state'],'PENDING')
        # Synthetic failure after a real effect: no success claim without receipt.
        self.adapter.fail_after_commit_once=True
        done=self.call('/v1/owner/decision/session',self.decision_body(pending))
        self.assertEqual(done[1]['state'],'UNCERTAIN')
        code,unresolved,_=self.call('/v1/owner/unresolved')
        self.assertEqual(code,200)
        self.assertEqual(unresolved['total'],1)
        self.assertEqual(unresolved['items'][0]['requestId'],pending['requestId'])
        self.assertEqual(unresolved['items'][0]['state'],'UNCERTAIN')
        self.assertIn('Cache-Control',self.call('/v1/owner/unresolved')[2])
        self.assertEqual(self.call('/v1/owner/pending')[1],[])

    def test_reconcile_only_verifies_existing_receipt_never_reexecutes(self):
        row=self.submit()
        self.adapter.fail_after_commit_once=True
        code,unknown,_=self.call('/v1/owner/decision/session',self.decision_body(row))
        self.assertEqual((code,unknown['state']),(200,'UNCERTAIN'))
        self.assertEqual(self.adapter.get('R3')['version'],1)
        body=json.dumps({'requestId':row['requestId']}).encode()
        self.assertEqual(self.call('/v1/owner/reconcile',body,cookie='')[0],403)
        self.assertEqual(self.call('/v1/owner/reconcile',body,csrf=None)[0],403)
        self.assertEqual(self.call('/v1/owner/reconcile',b'{"requestId":"bad"}')[0],403)
        self.assertEqual(self.core._read(row['requestId'])['state'],'UNCERTAIN')
        code,confirmed,_=self.call('/v1/owner/reconcile',body)
        self.assertEqual((code,confirmed['state']),(200,'EXECUTED'))
        self.assertEqual(self.adapter.get('R3')['version'],1)
        self.assertIsNone(confirmed['failure'])
        self.assertEqual(self.call('/v1/owner/reconcile',body)[0],403)
        self.assertEqual(self.core.owner_unresolved()['total'],0)
        self.assertEqual([e['state'] for e in self.core.events(row['requestId'])],
                         ['PENDING','APPROVED','DISPATCHED','UNCERTAIN','EXECUTED'])

    def test_missing_receipt_keeps_unknown_and_never_dispatches(self):
        row=self.submit()
        with patch.object(self.adapter,'apply',side_effect=RuntimeError('LOST_RESULT')):
            code,unknown,_=self.call('/v1/owner/decision/session',self.decision_body(row))
        self.assertEqual((code,unknown['state']),(200,'UNCERTAIN'))
        self.assertEqual(self.adapter.get('R3')['version'],0)
        body=json.dumps({'requestId':row['requestId']}).encode()
        code,still,_=self.call('/v1/owner/reconcile',body)
        self.assertEqual((code,still['state']),(200,'UNCERTAIN'))
        self.assertEqual(self.adapter.get('R3')['version'],0)
        self.assertEqual(self.core.owner_unresolved()['total'],1)
        self.assertEqual([e['state'] for e in self.core.events(row['requestId'])],
                         ['PENDING','APPROVED','DISPATCHED','UNCERTAIN'])

    def test_unresolved_inventory_bounded_and_sorts_approved_dispatched(self):
        r1=self.submit()
        with self.core._db() as db:
            db.execute('UPDATE requests SET state=? WHERE id=?',('APPROVED',r1['requestId']))
        r2=self.submit()
        with self.core._db() as db:
            db.execute('UPDATE requests SET state=? WHERE id=?',('DISPATCHED',r2['requestId']))
        r3=self.submit() # PENDING, not counted.
        rows=self.core.owner_unresolved(limit=1)
        self.assertEqual(rows['total'],2)
        self.assertTrue(rows['truncated'])
        self.assertEqual(len(rows['items']),1)
        with self.assertRaises(Denied):
            self.core.owner_unresolved(limit=101)



class IncidentWebAuthnTests(G2WebAuthnTest):
    def setUp(self):
        super().setUp()
        root=Path(self.temp.name)
        self.owner=IncidentOwnerWebAuthn(
            root/'credentials.sqlite',origin='http://localhost:18990')
        self.core=IncidentCore(
            root/'requests.sqlite',
            adapters={'synthetic':self.adapter},
            policies={('synthetic','set_ask'):'ASK'},
            authenticator=self.auth,owner_verifier=self.owner)
        self.portal=IncidentOwnerPortal(self.core,self.owner)
        self.invite=self.owner.issue_invitation()

    def test_one_click_close_with_real_webauthn_login_needs_no_second_ceremony(self):
        row=self.core.client('agent-secret','submit',self.action())
        self.enroll();cookie,csrf=self.login()
        with patch.object(self.adapter,'apply',side_effect=RuntimeError('ambiguous effect')):
            code,unknown,_=self.call('/v1/owner/decision/session',{
                'requestId':row['requestId'],'fingerprint':row['fingerprint'],
                'decision':'approve'},cookie=cookie,csrf=csrf)
        self.assertEqual((code,unknown['state']),(200,'UNCERTAIN'))
        body={'requestId':row['requestId'],'fingerprint':row['fingerprint']}
        self.assertEqual(self.call('/v1/owner/incidents/close/simple',body,
                                   cookie=cookie,csrf='wrong')[0],403)
        code,closed,_=self.call('/v1/owner/incidents/close/simple',body,
                                cookie=cookie,csrf=csrf)
        self.assertEqual((code,closed['state']),(200,'CLOSED_UNCONFIRMED'))
        self.assertIsNone(closed['result'])
        self.assertEqual(closed['failure'],'REMOTE_OUTCOME_UNCONFIRMED')
        self.assertEqual(closed['incidentClosure']['owner'],self.owner.owner)
        self.assertEqual(closed['incidentClosure']['closeMethod'],
                         'authenticated_owner_session')
        self.assertEqual(closed['incidentClosure']['originalFingerprint'],
                         row['fingerprint'])
        self.assertEqual(self.adapter.get('R3')['version'],0)
        self.assertEqual(self.core.events(row['requestId'])[-1]['state'],'CLOSED_UNCONFIRMED')
        self.assertEqual(self.call('/v1/owner/incidents/close/simple',body,
                                   cookie=cookie,csrf=csrf)[0],403)

    def test_uncertain_owner_web_authn_closure_is_not_success(self):
        row=self.core.client('agent-secret','submit',self.action())
        self.enroll();cookie,csrf=self.login()
        raw={'requestId':row['requestId'],'fingerprint':row['fingerprint'],'decision':'approve'}
        with patch.object(self.adapter,'apply',side_effect=RuntimeError('response lost')):
            code,result,_=self.call('/v1/owner/decision/session',raw,cookie=cookie,csrf=csrf)
        self.assertEqual((code,result['state']),(200,'UNCERTAIN'))
        self.assertIsNone(self.adapter.receipt(row['requestId']))
        self.assertEqual(self.adapter.get('R3')['version'],0)
        closure={'requestId':row['requestId'],
                 'backupVolume':'fortis-gateway-backup-'+'a'*32,
                 'explanation':'Owner verified a cold backup and reviewed the unconfirmed effect.',
                 'acknowledgeUnknown':True}
        self.assertEqual(self.call('/v1/owner/incidents/close/begin',closure,cookie=cookie)[0],403)
        code,begin,_=self.call('/v1/owner/incidents/close/begin',closure,cookie=cookie,csrf=csrf)
        self.assertEqual(code,200,begin)
        code,closed,_=self.call('/v1/owner/incidents/close/finish',
            {**closure,'ceremonyId':begin['ceremonyId'],'response':self.key.assert_(begin)},
            cookie=cookie,csrf=csrf)
        self.assertEqual((code,closed['state']),(200,'CLOSED_UNCONFIRMED'))
        self.assertEqual(closed['failure'],'REMOTE_OUTCOME_UNCONFIRMED')
        self.assertIsNone(closed['result'])
        self.assertEqual(self.adapter.get('R3')['version'],0)
        self.assertEqual(self.core.owner_unresolved()['total'],0)
        self.assertEqual(self.core.events(row['requestId'])[-1]['state'],'CLOSED_UNCONFIRMED')
        self.assertFalse(self.core.events(row['requestId'])[-1]['detail']=='{}')
        self.assertEqual(closed['incidentClosure']['backupVolumeOwnerAttested'],
                         closure['backupVolume'])
        self.assertEqual(closed['incidentClosure']['remoteEffectVerified'],False)
        self.assertEqual(self.call('/v1/owner/history',cookie=cookie)[1][0][
            'incidentClosure']['explanation'],closure['explanation'])
        self.assertEqual(self.call('/v1/owner/incidents/close/begin',closure,
                                   cookie=cookie,csrf=csrf)[0],403)
        self.assertEqual(self.call('/v1/owner/reconcile',{'requestId':row['requestId']},
                                   cookie=cookie,csrf=csrf)[0],403)

    def test_uncertain_with_saved_receipt_requires_reconcile_not_closure(self):
        row=self.core.client('agent-secret','submit',self.action())
        self.enroll();cookie,csrf=self.login()
        self.adapter.fail_after_commit_once=True
        raw={'requestId':row['requestId'],'fingerprint':row['fingerprint'],'decision':'approve'}
        code,result,_=self.call('/v1/owner/decision/session',raw,cookie=cookie,csrf=csrf)
        self.assertEqual((code,result['state']),(200,'UNCERTAIN'))
        closure={'requestId':row['requestId'],
                 'backupVolume':'fortis-gateway-backup-'+'a'*32,
                 'explanation':'Owner verified a cold backup and reviewed the unconfirmed effect.',
                 'acknowledgeUnknown':True}
        code,begin,_=self.call('/v1/owner/incidents/close/begin',closure,cookie=cookie,csrf=csrf)
        self.assertEqual(code,200)
        code,closed,_=self.call('/v1/owner/incidents/close/finish',
            {**closure,'ceremonyId':begin['ceremonyId'],'response':self.key.assert_(begin)},
            cookie=cookie,csrf=csrf)
        self.assertEqual((code,closed['error']),
                         (403,'INCIDENT_RECEIPT_AVAILABLE_RECONCILE_FIRST'))
        self.assertEqual(self.core._read(row['requestId'])['state'],'UNCERTAIN')
        self.assertEqual(self.adapter.get('R3')['version'],1)

    def test_github_receipt_path_is_not_treated_as_worker_job_store(self):
        row=self.core.client('agent-secret','submit',self.action())
        self.enroll();cookie,csrf=self.login()
        with patch.object(self.adapter,'apply',side_effect=RuntimeError('uncertain remote')):
            code,unknown,_=self.call('/v1/owner/decision/session',{
                'requestId':row['requestId'],'fingerprint':row['fingerprint'],
                'decision':'approve'},cookie=cookie,csrf=csrf)
        self.assertEqual((code,unknown['state']),(200,'UNCERTAIN'))
        # Mimics GitHubAdapter.store (path to receipt DB, not Store.job).
        self.adapter.store=Path(self.temp.name)/'github-receipts.sqlite'
        closure={'requestId':row['requestId'],
                 'backupVolume':'fortis-gateway-backup-'+'d'*32,
                 'explanation':'Owner inspected remote outcome, retained backup evidence.',
                 'acknowledgeUnknown':True}
        code,begin,_=self.call('/v1/owner/incidents/close/begin',
                               closure,cookie=cookie,csrf=csrf)
        self.assertEqual(code,200)
        code,closed,_=self.call('/v1/owner/incidents/close/finish',
            {**closure,'ceremonyId':begin['ceremonyId'],
                'response':self.key.assert_(begin)},cookie=cookie,csrf=csrf)
        self.assertEqual((code,closed['state']),(200,'CLOSED_UNCONFIRMED'))

    def test_workspace_incident_requires_terminal_failed_job(self):
        row=self.core.client('agent-secret','submit',self.action())
        self.enroll();cookie,csrf=self.login()
        with patch.object(self.adapter,'apply',side_effect=RuntimeError('unconfirmed')):
            code,unknown,_=self.call('/v1/owner/decision/session',{
                'requestId':row['requestId'],'fingerprint':row['fingerprint'],
                'decision':'approve'},cookie=cookie,csrf=csrf)
        self.assertEqual((code,unknown['state']),(200,'UNCERTAIN'))
        class FakeStore:
            state='RUNNING'
            def job(self, ident):
                return dict(state=self.state)
        self.adapter.store=FakeStore()
        closure={'requestId':row['requestId'],
                 'backupVolume':'fortis-gateway-backup-'+'c'*32,
                 'explanation':'Owner verified backup and investigated worker outcome.',
                 'acknowledgeUnknown':True}
        code,begin,_=self.call('/v1/owner/incidents/close/begin',
                               closure,cookie=cookie,csrf=csrf)
        self.assertEqual(code,200)
        code,blocked,_=self.call('/v1/owner/incidents/close/finish',
            {**closure,'ceremonyId':begin['ceremonyId'],
                'response':self.key.assert_(begin)},cookie=cookie,csrf=csrf)
        self.assertEqual((code,blocked['error']),(403,'INCIDENT_WORKER_NOT_TERMINAL'))
        self.assertEqual(self.core._read(row['requestId'])['state'],'UNCERTAIN')
        self.adapter.store.state='FAILED'
        code,again,_=self.call('/v1/owner/incidents/close/begin',
                                closure,cookie=cookie,csrf=csrf)
        self.assertEqual(code,200)
        code,closed,_=self.call('/v1/owner/incidents/close/finish',
            {**closure,'ceremonyId':again['ceremonyId'],
                'response':self.key.assert_(again)},cookie=cookie,csrf=csrf)
        self.assertEqual((code,closed['state']),(200,'CLOSED_UNCONFIRMED'))
        self.assertEqual(self.adapter.get('R3')['version'],0)

    def test_incident_close_cannot_use_session_decision_or_false_attestation(self):
        row=self.core.client('agent-secret','submit',self.action())
        self.enroll();cookie,csrf=self.login()
        closure={'requestId':row['requestId'],
                 'backupVolume':'fortis-gateway-backup-'+'b'*32,
                 'explanation':'Owner verified a cold backup and reviewed the unconfirmed effect.',
                 'acknowledgeUnknown':True}
        self.assertEqual(self.call('/v1/owner/incidents/close/begin',closure,
                                   cookie=cookie,csrf=csrf)[0],403)
        self.assertEqual(self.call('/v1/owner/incidents/close/begin',
            {**closure,'acknowledgeUnknown':False},cookie=cookie,csrf=csrf)[0],403)
        self.assertEqual(self.call('/v1/owner/decision/session',
            {'requestId':row['requestId'],'fingerprint':row['fingerprint'],
             'decision':'close_uncertain'},cookie=cookie,csrf=csrf)[0],403)

"""Phase 6C.4: isolated R7 source builder opt-in, NEVER deployed.

The local fake owner exists only because the minimal Repo image lacks fido2.
Real R7/WebAuthn tests run in the crypto-capable GitHub Source CI.
"""
from io import BytesIO
import inspect
import json
from pathlib import Path
import tempfile
import unittest
import uuid
from unittest.mock import patch

from fortis_approvals.core import Denied
from fortis_approvals.incidents import IncidentCore, IncidentOwnerPortal
from fortis_approvals.r7_unified_candidate import (
    ACTOR,G4_OPERATION,build_r7_unified_candidate)
from fortis_approvals import r7_unified_server
from fortis_approvals.extensions.owner_policy_local_core_phase6c import LocalDenyCore
from fortis_approvals.extensions.owner_policy_local_bundle_phase6c3 import (
    OwnerLocalDenyInventoryPortal)
from fortis_approvals.extensions.owner_policy_r7_optin_phase6c4 import (
    R7LocalDenySourceOptIn)
from fortis_approvals.tests.test_owner_policy_local_deny_http_phase6c2 import (
    HTTPFixtureWebAuthn)


GRANT='R7-SOURCE-TEST-GRANT-00000000000000000001'
SOURCE='a'*64
CREDS='b'*64
ISSUE='ISSUE-1'


class NeverNetworkSonar:
    def __init__(self):
        self.calls=0
    def call(self,method,path,params):
        self.calls+=1
        raise AssertionError('REAL_SONAR_NETWORK_FORBIDDEN_IN_OFFLINE_TEST')


class OptInR7BuilderTests(unittest.TestCase):
    def setUp(self):
        td=tempfile.TemporaryDirectory(prefix='fortis-r7-local-')
        self.addCleanup(td.cleanup)
        self.root=Path(td.name)
        self.sonar=NeverNetworkSonar()
        self.owner=HTTPFixtureWebAuthn()
        self.owner.origin='http://localhost:19103'
        self.kwargs=dict(
            owner_origin='http://localhost:19103',
            ingress_host='host.docker.internal:19104',
            ingress_grant=GRANT,sonar_transport=self.sonar,
            organizations=('acme',))
        self._seq=0

    def build(self,selector=None):
        self._seq+=1
        state=self.root/('state-'+str(self._seq))
        state.mkdir(mode=0o700)
        args=dict(self.kwargs,state=state)
        if selector is not None:
            args['local_deny_source_opt_in']=selector
        with patch('fortis_approvals.r7_unified_candidate.IncidentOwnerWebAuthn',
                   return_value=self.owner):
            return build_r7_unified_candidate(**args)

    def candidate(self):
        return R7LocalDenySourceOptIn(SOURCE,CREDS)

    def test_current_server_never_passes_source_selector(self):
        self.assertNotIn('local_deny_source_opt_in',
                         inspect.signature(r7_unified_server.create_servers).parameters)
        self.assertNotIn('local_deny_source_opt_in',
                         inspect.signature(r7_unified_server.runtime_endpoints).parameters)
        self.assertFalse(self.candidate().runtime_verified)

    def test_legacy_default_is_unchanged_and_not_local_policy_aware(self):
        core,owner,portal,ingress=self.build()
        self.assertIs(type(core),IncidentCore)
        self.assertIs(type(portal),IncidentOwnerPortal)
        self.assertIs(ingress.broker.core,core)
        self.assertFalse(hasattr(portal,'_local_deny_apply'))
        self.assertEqual('r7-p1-sonar-accept-issue-write-v1',core.policy_version)
        with core._db() as db:
            self.assertFalse(db.execute("SELECT 1 FROM sqlite_master "
                "WHERE type='table' AND name='owner_local_policy_meta'").fetchone())
        self.assertEqual(0,self.sonar.calls)

    def test_explicit_opt_in_binds_all_r7_components_to_same_guarded_core(self):
        core,owner,portal,ingress=self.build(self.candidate())
        self.assertIs(type(core),LocalDenyCore)
        self.assertIs(type(portal),OwnerLocalDenyInventoryPortal)
        self.assertIs(portal.core,core)
        self.assertIs(portal.auth,owner)
        self.assertIs(portal._local_deny_apply.core,core)
        self.assertIs(portal._local_deny_apply.auth,owner)
        self.assertIs(ingress.broker.core,core)
        self.assertEqual('r7-p1-sonar-accept-issue-write-v1|owner-local-deny:0',
                         core.policy_version)
        self.assertEqual(core.auth.authenticate(GRANT),ACTOR)

        self.assertEqual(0,self.sonar.calls)

    def test_exact_local_deny_via_r7_core_prevents_sonar_before_network(self):
        core,owner,portal,ingress=self.build(self.candidate())
        coord=(ACTOR,'sonarcloud','accept_issue',ISSUE)
        # Test fixture exact grant, not present in the default R7 policies.
        core.policies[coord]='ASK'
        with core._db() as db:
            db.execute('BEGIN IMMEDIATE')
            db.execute("INSERT INTO owner_local_denials VALUES(?,?,?,?,'DENY')",
                       coord)
            db.execute('UPDATE owner_local_policy_meta SET revision=revision+1')
        self.assertEqual('DENY',core._policy(ACTOR,dict(
            service='sonarcloud',operation='accept_issue',target=ISSUE)))
        with self.assertRaises(Denied):
            core.submit(ACTOR,dict(requestId=str(uuid.uuid4()),
                 service='sonarcloud',operation='accept_issue',
                 target=ISSUE,params={'projectKey':'acme'},expectedVersion=0,
                 reason='offline deny'))
        self.assertEqual(0,self.sonar.calls)
        self.assertEqual('r7-p1-sonar-accept-issue-write-v1|owner-local-deny:1',
                         core.policy_version)

    def test_exact_local_deny_owner_inventory_is_truthful(self):
        core,owner,portal,ingress=self.build(self.candidate())
        coord=(ACTOR,'sonarcloud','accept_issue',ISSUE)
        core.policies[coord]='ASK'
        with core._db() as db:
            db.execute('BEGIN IMMEDIATE')
            db.execute("INSERT INTO owner_local_denials VALUES(?,?,?,?,'DENY')",
                       coord)
            db.execute('UPDATE owner_local_policy_meta SET revision=revision+1')
        response=[]
        env={'REQUEST_METHOD':'GET','PATH_INFO':'/v1/owner/provider-inventory',
             'QUERY_STRING':'','HTTP_HOST':'localhost:19103',
             'HTTP_COOKIE':'fortis_owner='+owner._session,
             'CONTENT_LENGTH':'0','wsgi.input':BytesIO(b'')}
        raw=b''.join(portal(env,lambda code,headers:response.append(code)))
        self.assertEqual('200 OK',response[0])
        result=json.loads(raw)
        rows=[r for r in result['operations'] if r['scope']=='exact']
        self.assertEqual(1,len(rows))
        self.assertEqual('DENY',rows[0]['effectivePolicy'])
        self.assertTrue(rows[0]['localDenialApplied'])
        self.assertEqual(1,result['localDeniedExactRules'])
        self.assertFalse(result['allWorkersVerified'])
        self.assertEqual(0,self.sonar.calls)

    def test_bad_opt_in_fails_before_creating_new_state(self):
        with self.assertRaises(Denied):
            R7LocalDenySourceOptIn('bad',CREDS)
        with self.assertRaises(Denied):
            R7LocalDenySourceOptIn(SOURCE,None)
        state=self.root/'untouched-state'
        state.mkdir(mode=0o700)
        with patch('fortis_approvals.r7_unified_candidate.IncidentOwnerWebAuthn',
                   return_value=self.owner):
            with self.assertRaisesRegex(Denied,'R7_LOCAL_DENY_SOURCE_OPT_IN_REJECTED'):
                build_r7_unified_candidate(**dict(self.kwargs,state=state),
                                           local_deny_source_opt_in=True)
        self.assertEqual([],list(state.iterdir()))


if __name__=='__main__':
    unittest.main()

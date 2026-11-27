"""Existing actual Repo/owner WSGI lab, isolated authenticated route checks.

This is not a production route classifier. The limited passive status and
static/session GET paths here are proved against this specific lab only.
"""
import unittest
from io import BytesIO

from fortis_approvals.core import Denied
from fortis_approvals.extensions.maintenance_ingress import MaintenanceIngress, RouteAdmission, owner_passive_route
from fortis_approvals.tests import test_maintenance_boundaries as fixture
from fortis_approvals.tests import test_repo_ingress as repo_fixture


class MaintenanceHTTPTests(unittest.TestCase):
    setUp=repo_fixture.RepoIngressTests.setUp
    portal_call=repo_fixture.RepoIngressTests.portal_call
    login=repo_fixture.RepoIngressTests.login
    synthetic_intent=staticmethod(repo_fixture.RepoIngressTests.synthetic_intent)
    sonar_intent=staticmethod(repo_fixture.RepoIngressTests.sonar_intent)
    call=repo_fixture.RepoIngressTests.call

    def test_existing_authenticated_routes_freeze_preserves_private_bytes(self):
        self.login()
        req=self.synthetic_intent()
        status,pending,_=self.call(data=req)
        self.assertEqual(status,202)
        ctrl,holds=fixture.blocked_fixture()
        gate=fixture.gate_for(ctrl,holds)
        base=self.ingress
        portal=self.portal

        def machine_classify(env):
            if not base._environment(env):
                raise Denied('route')
            base._credential(env)
            passive=(env.get('REQUEST_METHOD')=='GET' and
                     env.get('PATH_INFO')=='/v1/requests/'+req['requestId'])
            return RouteAdmission(passive)

        def owner_classify(env):
            if env.get('HTTP_HOST')!=portal.host:
                raise Denied('route')
            if owner_passive_route(env):
                return RouteAdmission(True)
            portal.auth.session(portal._cookie(env))
            return RouteAdmission(env.get('REQUEST_METHOD')=='GET' and
                                  env.get('PATH_INFO')=='/v1/owner/session')

        self.ingress=MaintenanceIngress(base,gate,classify=machine_classify)
        self.portal=MaintenanceIngress(portal,gate,classify=owner_classify)
        root=self.core.path.parent
        def snapshot():
            return {p.relative_to(root).as_posix():p.read_bytes() for p in root.rglob('*') if p.is_file()}
        before=snapshot()
        status,result,_=self.call(data=self.synthetic_intent('set_free','REC-FREE'))
        self.assertEqual((status,result),(403,{'error':'RELEASE_MAINTENANCE'}))
        status,result,_=self.call(path='/v1/reads',data=self.sonar_intent())
        self.assertEqual((status,result),(403,{'error':'RELEASE_MAINTENANCE'}))
        status,result,_=self.call(path='/v1/requests/'+req['requestId'],method='GET')
        self.assertEqual((status,result['state']),(200,'PENDING'))
        status,result,_=self.call(data=self.synthetic_intent(),credential='bad')
        self.assertEqual((status,result),(403,{'error':'POLICY_DENIED'}))
        row=self.core._read(req['requestId'])
        status,result,_=self.portal_call('/v1/owner/decision/session',{
            'requestId':row['requestId'],'fingerprint':row['fingerprint'],'decision':'approve'})
        self.assertEqual((status,result),(403,{'error':'RELEASE_MAINTENANCE'}))
        self.assertEqual(self.portal_call('/v1/login/finish',{})[:2],
                         (403,{'error':'RELEASE_MAINTENANCE'}))
        env={'HTTP_HOST':portal.host,'REQUEST_METHOD':'GET','PATH_INFO':'/v1/owner/session',
             'QUERY_STRING':'','HTTP_COOKIE':'fortis_owner='+self.cookie,
             'CONTENT_LENGTH':'0','wsgi.input':BytesIO(b'')}
        codes=[]
        body=b''.join(self.portal(env,lambda status,headers:codes.append(status)))
        self.assertTrue(codes[0].startswith('200'))
        self.assertTrue(body)
        self.assertEqual(snapshot(),before)
        self.assertEqual(gate.drain_status()['reservations'],0)


if __name__=='__main__':
    unittest.main()

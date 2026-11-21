"""Fixed route/auth/redaction and staged-routing tests, no Docker/provider network."""
import json
from types import SimpleNamespace
from urllib import error
import unittest

from fortis_approvals.core import Denied
from fortis_approvals.extensions.vault import Secret
from fortis_approvals.extensions.http import JSONAPI, Route
from fortis_approvals.extensions.runtime import Context
from fortis_approvals.extensions.staging import StagedMachine
import test_extensions as base_tests


class Response:
    def __init__(self, url, data=b'{"value":"safe"}', status=200):
        self.url, self.data, self.status = url, data, status
    def __enter__(self): return self
    def __exit__(self, *exc): pass
    def read(self, limit): return self.data[:limit]
    def geturl(self): return self.url


class Opener:
    def __init__(self): self.calls=[]; self.result=None
    def open(self, request, **kwargs):
        self.calls.append(request)
        if isinstance(self.result, Exception): raise self.result
        return self.result or Response(request.full_url)


class HTTPTests(unittest.TestCase):
    def setUp(self):
        self.opener = Opener()
        self.api = JSONAPI('https://api.example.invalid', (
            Route('get_item', 'GET', '/items/{id}', readonly=True, query_keys=('fields',)),
            Route('set_item', 'POST', '/items/{id}', idempotency_header='Idempotency-Key')),
            opener=self.opener)

    def test_fixed_origin_auth_and_quoted_path(self):
        result=self.api.call('get_item', credential=Secret('offline', base_tests.TOKEN), path={'id':'a/b'}, query={'fields':'name'})
        self.assertEqual(result, {'value':'safe'})
        request=self.opener.calls[0]
        self.assertEqual(request.full_url,'https://api.example.invalid/items/a%2Fb?fields=name')
        self.assertEqual(request.get_header('Authorization'),'Bearer '+base_tests.TOKEN)
        self.assertIsNone(request.get_header('Cookie'))

    def test_unknown_route_query_and_dot_segments_denied_before_io(self):
        for action in (lambda:self.api.call('unknown'),
                       lambda:self.api.call('get_item',path={'id':'..'}),
                       lambda:self.api.call('get_item',path={'id':'x'},query={'url':'https://evil.invalid'})):
            with self.assertRaises(Denied): action()
        self.assertEqual(self.opener.calls,[])

    def test_post_binds_request_id_and_capped_json(self):
        self.api.call('set_item',path={'id':'x'},body={'value':'new'},request_id='offline-id')
        request=self.opener.calls[0]
        self.assertEqual(request.get_header('Idempotency-key'),'offline-id')
        self.assertEqual(json.loads(request.data),{'value':'new'})
        with self.assertRaises(Denied):self.api.call('get_item',path={'id':'x'},body={})

    def test_redirect_errors_duplicate_and_oversized_results_fail_closed(self):
        results=(Response('https://evil.invalid/redirect'),Response('https://api.example.invalid/items/x',b'{"value":1,"value":2}'),
                 Response('https://api.example.invalid/items/x',b'x'*300000),
                 error.HTTPError('https://api.example.invalid',403,base_tests.TOKEN,{},None))
        for response in results:
            self.opener.result=response
            with self.subTest(response=response),self.assertRaises(Denied) as exc:self.api.call('get_item',path={'id':'x'})
            self.assertNotIn(base_tests.TOKEN,str(exc.exception))

    def test_source_route_cannot_be_an_http_or_credentialed_origin(self):
        for origin in ('http://api.example.invalid','https://token@api.example.invalid','https://api.example.invalid/path','https://api.example.invalid:8080'):
            with self.assertRaises(Denied):JSONAPI(origin,())


class BoundaryTests(base_tests.ExtensionTests):
    # Override inherited loading by exposing only the extra cases from this module below.
    def test_provider_secret_or_raw_exception_is_never_persisted(self):
        self.value=base_tests.TOKEN
        row=self.runtime.call(base_tests.GRANT,self.call())
        self.assertEqual(row['state'],'UNCERTAIN')
        self.assertIsNone(self.runtime.result(base_tests.GRANT,row['requestId'])['data'])
        self.assertNotIn(base_tests.TOKEN,self.core.path.read_bytes().decode(errors='ignore'))

    def test_json_escaped_credential_is_also_rejected_before_persistence(self):
        token = 'OFFLINE-QUOTE-"-BACKSLASH-\\-UNICODE-ю'
        self.vault.provision('tickets-test', token, expected_generation=self.provisioned['generation'])
        self.value = token
        row = self.runtime.call(base_tests.GRANT, self.call())
        self.assertEqual(row['state'], 'UNCERTAIN')
        self.assertIsNone(self.runtime.result(base_tests.GRANT, row['requestId'])['data'])
        self.assertNotIn('OFFLINE-QUOTE', self.core.path.read_bytes().decode(errors='ignore'))

    def test_staging_allows_only_safe_reads_and_preserves_normal_health_404(self):
        base=self.ingress.base;delegate=self.ingress
        gate=SimpleNamespace(ready=lambda:False)
        self.ingress=StagedMachine(delegate,base,self.runtime,gate)
        self.assertEqual(self.post('/v1/integrations/catalog',{})[0],200)
        self.assertEqual(self.post('/v1/integrations/call',self.call())[0],200)
        self.assertEqual(self.post('/v1/integrations/call',self.call('set_item',{'value':'after'}))[0],403)
        self.assertEqual(self.post('/v1/actions',self.call('set_item',{'value':'after'}))[0],403)
        status,_=self.post('/no-such-machine-route',{},REQUEST_METHOD='GET',HTTP_AUTHORIZATION='')
        self.assertEqual(status,404)
        gate.ready=lambda:True
        self.assertEqual(self.post('/v1/integrations/call',self.call('set_item',{'value':'after'}))[0],202)

    def test_extension_wrapper_preserves_native_auth_and_capabilities(self):
        from fortis_approvals.workflow.ingress import NativeIngress
        from fortis_approvals.extensions.ingress import ExtensionIngress
        base=self.ingress.base
        # The legacy wrapper has no broker grant list. Do not infer
        # registered GitHub methods from packaged source alone.
        native=NativeIngress(base,github=SimpleNamespace(config=SimpleNamespace(owner='OfflineOwner',repository='sandbox')),
                             workspace=None,store=None,actor='actor')
        self.ingress=ExtensionIngress(base,self.runtime,delegate=native)
        status,result=self.post('/v1/workspace/capabilities',{})
        self.assertEqual((status,result['repository']),(200,'sandbox'))
        self.assertIs(result['dynamicRepositories'],False)  # Legacy native config has no new field.
        self.assertEqual(result['githubMethodPolicies'],{})
        self.assertEqual(self.post('/v1/integrations/catalog',{})[0],200)


def load_tests(loader,tests,pattern):
    suite=unittest.TestSuite();suite.addTests(loader.loadTestsFromTestCase(HTTPTests))
    suite.addTests(BoundaryTests(name) for name in (
        'test_provider_secret_or_raw_exception_is_never_persisted',
        'test_json_escaped_credential_is_also_rejected_before_persistence',
        'test_staging_allows_only_safe_reads_and_preserves_normal_health_404',
        'test_extension_wrapper_preserves_native_auth_and_capabilities'))
    return suite

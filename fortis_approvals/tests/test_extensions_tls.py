"""Extension API through real TLS/R7 composition and cryptographic owner WebAuthn.

Remote provider callbacks are offline fixtures; no Docker/Windows/provider writes.
"""
import unittest
from unittest.mock import patch
from fortis_approvals.extensions.client import IntegrationClient, IntegrationTransport
from fortis_approvals.extensions.model import Operation, Provider
from fortis_approvals.extensions.runtime import ExtensionConfig
from fortis_approvals.integrations.review_schema import object_schema, text
from fortis_approvals import r7_unified_server as server
import test_github_pilot as shared


class ExtensionTLS(shared.PilotTLSWebAuthnTests):
    def setUp(self):
        self.value='before';self.effects=0
        data=object_schema({'value':text})
        def write(ctx):
            self.value=ctx.params['value'];self.effects+=1
            return {'value':self.value}
        provider=Provider('offlineexample',(
            Operation('read_item','Read one record','read',object_schema({}),data,lambda ctx:{'value':self.value}),
            Operation('set_item','Change one record','write',data,data,write,
                preview=lambda ctx:{'value':self.value},preview_result=data)))
        config=ExtensionConfig({'schemaVersion':1,'providers':{'offlineexample':{
            'credentials':{},'operations':{'read_item':{'policy':'ALLOW','targets':['one']},
                                         'set_item':{'policy':'ASK','targets':['one']}}}}})
        original=server.build_r7_unified_candidate
        def build(**kwargs):
            kwargs.update(extensions=config,extension_providers=(provider,))
            return original(**kwargs)
        with patch.object(server,'build_r7_unified_candidate',side_effect=build):super().setUp()
        self.integration=IntegrationClient(gateway=IntegrationTransport(endpoint='https://host.docker.internal:19204',
            grant_path=self.grant,certificate_path=self.cert,allow_test_endpoint=True))

    def test_extension_read_reject_uv_approve_and_replay(self):
        self.assertEqual(len(self.integration.catalog()['operations']),2)
        row=self.integration.call('offlineexample','read_item','one',{},reason='Offline read')
        self.assertEqual(self.integration.result(row['requestId'])['data'],{'value':'before'})
        rejected=self.integration.call('offlineexample','set_item','one',{'value':'rejected'},reason='Offline reject')
        self.assertEqual(rejected['state'],'PENDING');self.assertEqual(self.effects,0)
        self.login();self.assertEqual(self.decide(rejected['requestId'],'reject')[1]['state'],'REJECTED')
        self.assertEqual(self.effects,0)
        row=self.integration.call('offlineexample','set_item','one',{'value':'after'},reason='Offline approve')
        self.assertEqual(self.decide(row['requestId'],'approve',uv=False)[0],403)
        self.assertEqual(self.effects,0)
        self.assertEqual(self.decide(row['requestId'],'approve')[1]['state'],'EXECUTED')
        self.assertEqual(self.integration.result(row['requestId'])['data'],{'value':'after'})
        self.assertEqual(self.integration.call('offlineexample','set_item','one',{'value':'after'},
            reason='Offline approve',request_id=row['requestId'])['state'],'EXECUTED')
        self.assertEqual(self.effects,1)
        self.assertEqual(self.client.get_repository('sandbox')['repository']['default_branch'],'main')


def load_tests(loader,tests,pattern):
    return unittest.TestSuite([ExtensionTLS('test_extension_read_reject_uv_approve_and_replay')])

"""Observatory Docker HTTPS source-only manifest: exact two reads, no live claim."""
import importlib.util
import json
from pathlib import Path
import unittest

from fortis_approvals.integrations.observatory.extension import PROVIDER
from fortis_approvals.integrations.observatory.transport import _CA_PATH, _GATEWAY_HOST

ROOT=Path(__file__).resolve().parents[2]
MANIFEST=ROOT/'docs/templates/own-api/observatory-read.source.json'
LINTER=ROOT/'scripts/check-own-api-manifest.py'
SPEC=importlib.util.spec_from_file_location('ownapi_manifest_validator',LINTER)
CHECKER=importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECKER)


class ObservatoryManifestTests(unittest.TestCase):
    def test_manifest_valid_but_not_live_or_immutably_pinned(self):
        obj=CHECKER.load(MANIFEST)
        status=CHECKER.validate(obj)
        self.assertEqual(status['status'],'SOURCE_MANIFEST_VALID')
        self.assertEqual(status['operationCount'],2)
        self.assertFalse(status['sourcePinned'])
        self.assertFalse(status['readyToDeploy'])
        self.assertFalse(status['liveVerified'])
        self.assertIsNone(obj['sourceSha'])

    def test_manifest_exact_routes_network_ca_and_vault(self):
        obj=CHECKER.load(MANIFEST)
        self.assertEqual(obj['serviceId'],PROVIDER.name)
        self.assertEqual(obj['transport']['gatewayDockerNetwork'],'fortis-observatory-gw-net')
        self.assertEqual(obj['transport']['origin'],'https://fortis-observatory-api:443')
        self.assertEqual(obj['transport']['tlsServerName'],_GATEWAY_HOST)
        self.assertEqual(obj['transport']['pinnedCaPath'],str(_CA_PATH))
        self.assertEqual(obj['credential']['vaultAlias'],'observatory-read')
        self.assertEqual(obj['credential']['vaultOwner'],'OWNER_ONLY')
        self.assertEqual(obj['credential']['upstreamPrincipal'],'observatory-gateway-reader')
        self.assertEqual(set(obj['operations'][0]),set(obj['operations'][1]))
        self.assertEqual({op['name'] for op in obj['operations']},
                         {op.name for op in PROVIDER.operations})
        for manifest_op in obj['operations']:
            op=next(o for o in PROVIDER.operations if o.name==manifest_op['name'])
            self.assertEqual(op.kind,'read')
            self.assertEqual(manifest_op['policy'],'ALLOW')
            self.assertEqual(manifest_op['method'],'GET')
            self.assertEqual(manifest_op['effect'],'READ')
            self.assertEqual(len(op.routes),1)
            route=PROVIDER.api.routes[op.routes[0]]
            self.assertTrue(route.readonly)
            self.assertEqual((route.method,route.path),
                             (manifest_op['method'],manifest_op['path']))
            self.assertLessEqual(manifest_op['maxResponseBytes'],262144)


if __name__=='__main__':
    unittest.main()

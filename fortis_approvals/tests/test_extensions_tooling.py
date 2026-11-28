"""Real scaffold/discovery/config IO; release-gate unit boundaries. No host emulation."""
import importlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
import uuid

from fortis_approvals.core import Denied
from fortis_approvals import integrations
from fortis_approvals.extensions.cli import scaffold, check_config
from fortis_approvals.extensions.model import discover
from fortis_approvals.extensions.staging import ReleaseGate


class ToolingTests(unittest.TestCase):
    def test_scaffold_discovered_from_provider_home_and_disabled_until_implemented(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); (root/'fortis_approvals/extensions').mkdir(parents=True)
            (root/'fortis_approvals/extensions/model.py').write_text('# source-root sentinel')
            home=root/'fortis_approvals/integrations';home.mkdir()
            report=scaffold(root,'offlinefixture')
            self.assertEqual(report['status'],'SCAFFOLDED_DISABLED')
            self.assertTrue((home/'offlinefixture/tests/test_definition.py').is_file())
            with self.assertRaises(Denied):scaffold(root,'offlinefixture')
            with patch.object(integrations,'__file__',str(home/'__init__.py')),patch.object(integrations,'__path__',[str(home),*integrations.__path__]):
                importlib.invalidate_caches()
                try:
                    provider,=discover(('offlinefixture',))
                    self.assertFalse(provider.operations[0].ready)
                    self.assertEqual(len(provider.source_digest),64)
                    value={'schemaVersion':1,'providers':{'offlinefixture':{
                        'credentials':{'api':'offline-token'},'operations':{
                            'read_item':{'policy':'ALLOW','targets':['one']}}}}}
                    with self.assertRaisesRegex(Denied,'INTEGRATION_HANDLER_NOT_READY'):check_config(value)
                    with self.assertRaises(Denied):discover(('unknown_provider',))
                    # Tests do not change the deployed definition/approval digest.
                    before=provider.source_digest
                    (home/'offlinefixture/tests/test_definition.py').write_text('# revised tests only')
                    self.assertEqual(discover(('offlinefixture',))[0].source_digest,before)
                    (home/'offlinefixture/extra.py').write_text('# new trusted helper')
                    self.assertNotEqual(discover(('offlinefixture',))[0].source_digest,before)
                finally:
                    for key in list(sys.modules):
                        if key.startswith('fortis_approvals.integrations.offlinefixture'):sys.modules.pop(key)

    def test_empty_framework_config_is_ready_and_reads_no_token(self):
        with patch('fortis_approvals.extensions.vault.CredentialVault.get',side_effect=AssertionError('secret read')):
            result=check_config({'schemaVersion':1,'providers':{}})
        self.assertEqual(result['status'],'READY');self.assertEqual(result['operations'],[])

    def test_activation_marker_rejects_missing_wrong_metadata_and_symlink(self):
        with tempfile.TemporaryDirectory() as tmp:
            marker=Path(tmp)/'marker';nonce=str(uuid.uuid4());digest='a'*64
            gate=ReleaseGate(nonce,digest,marker=marker)
            self.assertFalse(gate.ready())
            self.assertEqual(gate.record_status(),{'active':False,'markerPresent':False})
            marker.write_text(json.dumps({'schemaVersion':1,'nonce':nonce,'configurationDigest':digest}))
            marker.chmod(0o600);self.assertFalse(gate.ready())
            self.assertEqual(gate.record_status(),{'active':False,'markerPresent':True})
            marker.chmod(0o444)
            if os.geteuid()!=0:
                self.assertFalse(gate.ready())
                with self.assertRaises(Denied):gate.activate()
            else:
                gate.activate();self.assertTrue(gate.ready())
                self.assertFalse(ReleaseGate(str(uuid.uuid4()),digest,marker=marker).ready())
            link=Path(tmp)/'link';link.symlink_to(marker)
            self.assertEqual(ReleaseGate(nonce,digest,marker=link).record_status(),
                             {'active':False,'markerPresent':True})
            with self.assertRaises(Denied):ReleaseGate(nonce,'x'*64)


if __name__=='__main__':unittest.main()

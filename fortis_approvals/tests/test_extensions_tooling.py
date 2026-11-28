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

    def test_frozen_probe_only_reviewed_allow_get_with_exact_witness(self):
        from contextlib import nullcontext
        from types import SimpleNamespace
        from unittest.mock import Mock
        from fortis_approvals.extensions.cli import frozen_probe, DEFAULT_ACTOR
        from fortis_approvals.extensions.runtime import ExtensionRuntime, ExtensionConfig
        from fortis_approvals.extensions.vault import Secret
        from fortis_approvals.integrations.mirror.tests.test_extension import sample
        from fortis_approvals.integrations.mirror.tls import MirrorPinnedAPI
        config={'schemaVersion':1,'providers':{'mirror':{
            'credentials':{'link':'fixture-link'},
            'operations':{'get_repository':{'policy':'ALLOW','targets':['fortis-approvals']}}}}}
        vault=Mock()
        vault.get.return_value=Secret(str(uuid.uuid4()),'synthetic-token-never-output')
        vault.readiness.return_value={'configured':True,'ready':True,'status':'READY'}
        runtime=ExtensionRuntime(ExtensionConfig(config),providers=discover(('mirror',)),
            actors=(DEFAULT_ACTOR,),default_actor=DEFAULT_ACTOR,vault=vault)
        client=Mock()
        catalog=runtime.catalog_for(DEFAULT_ACTOR)
        client.catalog.return_value=catalog
        probe={'service':'mirror','operation':'get_repository','target':'fortis-approvals','params':{}}
        value={'configurationDigest':runtime.digest,'interlockDigest':'a'*64,
               'profileDigest':'b'*64,'probes':[probe]}
        delivery={'profileDigest':value['profileDigest'],'maintenancePhase':'STAGED_TARGET_FROZEN'}
        holds={'holds':[{'blockedOperations':[]}]}
        gate=Mock()
        gate.verify_startup.return_value=({'phase':'STAGED_TARGET_FROZEN'},holds,
                                         {'interlockDigest':value['interlockDigest']})
        successor=SimpleNamespace(_raw=json.dumps({'latestPin':True,'frozenHandoff':{}}),
                                  _maintenance_gate=lambda *_:gate)
        with patch.dict(os.environ,{'FORTIS_EXTENSIONS_CONFIG':json.dumps(config),
                                     'FORTIS_RELEASE_NONCE':str(uuid.uuid4())}), \
             patch('os.geteuid',return_value=10001), \
             patch('fortis_approvals.extensions.runtime.CredentialVault',return_value=vault), \
             patch('fortis_approvals.extensions.staging.ReleaseGate.record_status',
                   return_value={'active':False,'markerPresent':False}), \
             patch('fortis_approvals.extensions.maintenance_interlock_reader.InterlockReservations.reserve',
                   side_effect=lambda:nullcontext()), \
             patch('fortis_approvals.r7_unified_server._installed_policy_source_digest',return_value='c'*64), \
             patch('fortis_approvals.r7_registry_reader_mount.load_owner_registry_reader',
                   return_value=SimpleNamespace(_successor_config=successor)), \
             patch('fortis_approvals.r7_registry_reader_mount.reviewed_successor_delivery',
                   return_value=delivery), \
             patch.object(MirrorPinnedAPI,'call',return_value=sample()) as upstream:
            self.assertEqual(frozen_probe(value,client),
                {'status':'READ_PROBES_PASS','count':1,'mutationEffectsVerified':False})
            self.assertEqual(upstream.call_args.args,('get_repo',))
            self.assertEqual(upstream.call_args.kwargs['path'],{'repo_id':'fortis-approvals'})
            with self.assertRaisesRegex(Denied,'RELEASE_FROZEN_PROBE_UNREVIEWED'):
                frozen_probe({**value,'probes':[{**probe,'target':'other'}]},client)
            catalog['operations'][0]['policy']='ASK'
            with self.assertRaisesRegex(Denied,'INTEGRATION_UNSAFE_PROBE'):
                frozen_probe(value,client)
            catalog['operations'][0]['policy']='ALLOW'
            holds['holds'][0]['blockedOperations']=[{'service':'mirror','operation':'get_repository'}]
            with self.assertRaisesRegex(Denied,'RELEASE_FROZEN_PROBE_RESTRICTED'):
                frozen_probe(value,client)
            self.assertEqual(upstream.call_count,1)

    def test_frozen_probe_preflight_preserves_exact_retained_set(self):
        from fortis_approvals.extensions.cli import check_frozen_probes
        probe={'service':'mirror','operation':'get_repository','target':'fortis-approvals','params':{}}
        retained=json.dumps([probe])
        self.assertEqual(check_frozen_probes({'retained':retained,'requested':retained})['count'],1)
        for requested in ('[]',json.dumps([probe,probe]),json.dumps([{**probe,'target':'other'}])):
            with self.assertRaises(Denied):
                check_frozen_probes({'retained':retained,'requested':requested})
        with self.assertRaises(Denied):
            check_frozen_probes({'retained':'[]','requested':retained})

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

"""Source component mapping with retained policy evidence and exact Git catalog."""
import copy
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch

from fortis_approvals.core import Denied
from fortis_approvals.integrations.github.gateway import component_bindings as m
from fortis_approvals.integrations.github.gateway.retained_impact import RetainedImpactValidator
from fortis_approvals.integrations.github.tests import test_retained_registry_policy as fixture
from fortis_approvals.integrations.github.tests import test_retained_impact as impact


class ComponentBindingsTests(unittest.TestCase):
    setUp=fixture.RetainedRegistryPolicyTests.setUp
    prepare=fixture.RetainedRegistryPolicyTests.prepare
    approve=fixture.RetainedRegistryPolicyTests.approve
    set_merge=fixture.RetainedRegistryPolicyTests.set_merge
    journal_setup=fixture.RetainedRegistryPolicyTests.journal_setup
    retain=fixture.RetainedRegistryPolicyTests.retain
    confirm=fixture.RetainedRegistryPolicyTests.confirm

    def build(self):
        self.journal_setup()
        self.enterContext(patch.object(m,'REPOSITORY',fixture.p.REPOSITORY))
        self.confirm(self.retain())
        self.mapping={**{k:self.baseline[k] for k in
                        ('schemaVersion','repository','enrollmentId','baselineSha','catalogSha256')},
                      'bindings':[{'targetId':'app','environment':'production','componentId':'app-runtime'},
                                  {'targetId':'dependency','environment':'production','componentId':'dep-runtime'}],
                      'components':[{'id':'app-runtime','resources':['shared-state'],'requires':['dep-runtime']},
                                    {'id':'dep-runtime','resources':['shared-state'],'requires':[]}]}
        self.repin()

    def repin(self):
        self.baseline['bindingDigest']=m._hash(self.mapping)

    def observe(self,**changes):
        args=dict(adapter=self.fixture.adapter,journal=self.journal,validator=self.fixture.validator,
                  baseline_reader=lambda:copy.deepcopy(self.baseline),
                  expected_baseline_digest=m._hash(self.baseline),
                  selected_main_sha=self.fixture.selected,evidence_ids=[self.eid],
                  policy_reader=self.reader,expected_policy_digest=self.pin,
                  binding_reader=lambda:copy.deepcopy(self.mapping))
        return m.observe_component_bindings(**(args|changes))

    def test_full_mapping_bound_to_range(self):
        self.build();r=self.observe();o=r['observation']
        self.assertEqual(r['result'],'COMPONENT_ENVIRONMENT_MATCH_CANDIDATE')
        self.assertEqual(o['bindingDigest'],self.baseline['bindingDigest'])
        self.assertEqual([x['targetId'] for x in o['bindings']],['app','dependency'])
        self.assertEqual(o['bindings'][0]['requiresComponentIds'],['dep-runtime'])
        self.assertEqual(o['bindings'][0]['resourceIds'],o['bindings'][1]['resourceIds'])
        self.assertEqual(o['bindings'][0]['deployment']['procedure'],'procedure.md')
        self.assertEqual(r,self.observe())
        for k,v in r.items():
            if k.endswith(('Verified','Allowed')):self.assertIs(v,False)

    def test_mapping_digest_and_environment(self):
        self.build();self.mapping['bindings'][0]['environment']='staging'
        with self.assertRaisesRegex(Denied,'P5_COMPONENT_BINDING_PIN_MISMATCH'):self.observe()
        self.repin()
        with self.assertRaisesRegex(Denied,'P5_COMPONENT_ENVIRONMENT_MISMATCH'):self.observe()

    def test_missing_target_and_duplicate_component(self):
        self.build();original=copy.deepcopy(self.mapping)
        self.mapping['bindings'].pop();self.repin()
        with self.assertRaisesRegex(Denied,'P5_COMPONENT_BINDING_SET'):self.observe()
        self.mapping=original
        self.mapping['bindings'][1]['componentId']='app-runtime';self.repin()
        with self.assertRaisesRegex(Denied,'P5_COMPONENT_TARGET_BINDING_INVALID'):self.observe()

    def test_dependency_and_cycle(self):
        self.build();self.mapping['components'][0]['requires']=[];self.repin()
        with self.assertRaisesRegex(Denied,'P5_COMPONENT_DEPENDENCY_MAPPING_INCOMPLETE'):self.observe()
        self.mapping['components'][0]['requires']=['dep-runtime']
        self.mapping['components'][1]['requires']=['app-runtime'];self.repin()
        with self.assertRaisesRegex(Denied,'P5_COMPONENT_GRAPH_CYCLE_OR_UNKNOWN'):self.observe()

    def test_empty_resources_and_unknown_requires(self):
        self.build();self.mapping['components'][0]['resources']=[];self.repin()
        with self.assertRaisesRegex(Denied,'P5_COMPONENT_GRAPH_INVALID'):self.observe()
        self.mapping['components'][0]['resources']=['shared-state']
        self.mapping['components'][0]['requires']=['absent'];self.repin()
        with self.assertRaisesRegex(Denied,'P5_COMPONENT_GRAPH_CYCLE_OR_UNKNOWN'):self.observe()

    def test_raw_catalog_pin_not_current_checkout(self):
        self.build()
        self.fixture.write(self.fixture.validator.source,'release/targets.yaml','untrusted edited checkout')
        self.assertEqual(self.observe()['result'],'COMPONENT_ENVIRONMENT_MATCH_CANDIDATE')
        self.baseline['catalogSha256']='a'*64;self.mapping['catalogSha256']='a'*64;self.repin()
        with self.assertRaisesRegex(Denied,'P5_COMPONENT_CATALOG_DIGEST'):self.observe()

    def test_no_policy_or_missing_range(self):
        self.build()
        with self.assertRaisesRegex(Denied,'P5_COMPONENT_POLICY_REQUIRED'):
            self.observe(policy_reader=None,expected_policy_digest=None)
        with self.assertRaisesRegex(Denied,'P5_FORWARD_MISSING_MERGE_EVIDENCE'):
            self.observe(evidence_ids=[])

    def test_mapping_drift_after_lineage(self):
        self.build()
        changed=copy.deepcopy(self.mapping);changed['bindings'][0]['environment']='other'
        with self.assertRaisesRegex(Denied,'P5_COMPONENT_BINDING_PIN_MISMATCH'):
            self.observe(binding_reader=iter([self.mapping,changed]).__next__)

    @unittest.skipUnless(impact.REAL_ROOT and importlib.util.find_spec('yaml')
                         and importlib.util.find_spec('jsonschema'),
                         'Requires exact shared validator and pinned dependencies')
    def test_real_component_catalog_semantics(self):
        self.fixture.validator=RetainedImpactValidator(
            validator_repository=Path(impact.REAL_ROOT),validator_revision=impact.REAL_PIN,
            source_repository=self.fixture.validator.source,state_root=self.fixture.validator.state)
        self.build()
        r=self.observe()
        self.assertEqual(r['observation']['validatorRevision'],impact.REAL_PIN)
        self.assertFalse(r['componentBindingsVerified'])
        self.assertEqual(len(r['observation']['bindings']),2)

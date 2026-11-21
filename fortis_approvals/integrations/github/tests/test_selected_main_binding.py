"""Real fixture Git objects, private capture/Core, synthetic provider."""
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from fortis_approvals.core import Denied
from fortis_approvals.workflow.common import Git, secure_dir
from fortis_approvals.integrations.github.gateway.selected_main_binding import observe_selected_main
from fortis_approvals.integrations.github.gateway.retained_impact import RetainedImpactValidator
from fortis_approvals.integrations.github.tests import test_retained_impact as impact_fixture
from fortis_approvals.integrations.github.tests import test_p5_ci_binding as ci_fixture
from fortis_approvals.integrations.github.tests import test_integrated_capture as fixture
from fortis_approvals.integrations.github.tests import publisher_fixture


class SelectedMainTests(unittest.TestCase):
    init_repo=impact_fixture.RetainedImpactTests.init_repo
    write=staticmethod(impact_fixture.RetainedImpactTests.write)
    commit=impact_fixture.RetainedImpactTests.commit
    capture=ci_fixture.PolicyBindingTests.capture
    prepare=ci_fixture.PolicyBindingTests.prepare
    decide=ci_fixture.PolicyBindingTests.decide
    merge=ci_fixture.PolicyBindingTests.merge

    def setup_case(self, *, wrong_tree=False, wrong_workflow=False, external=False):
        tmp=tempfile.TemporaryDirectory();self.addCleanup(tmp.cleanup)
        self.root=Path(tmp.name);self.git=Git(self.root/'git-state')
        source=self.init_repo('source')
        catalog=json.loads(json.dumps(impact_fixture.CATALOG))
        root=catalog['targets'][0]
        dep=json.loads(json.dumps(root));dep.update(id='dependency',inputs=['procedure.md'])
        if external:
            dep['dependsOn']=[{'repository':'other-repo','target':'external'}]
        root['dependsOn']=[{'repository':fixture.REPO,'target':'dependency'}]
        catalog['targets'].append(dep)
        raw_catalog=json.dumps(catalog).encode()
        self.write(source,'release/targets.yaml',raw_catalog.decode())
        self.write(source,'src/old.py','VALUE = 1\n')
        self.write(source,'procedure.md','Review procedure\n')
        self.write(source,'validate.py','raise RuntimeError("PR CODE EXECUTED")')
        for w in ci_fixture.P5_WORKFLOWS:
            content=(publisher_fixture.ROOT/w.path).read_text()
            if wrong_workflow and w==ci_fixture.P5_WORKFLOWS[-1]:
                content+='\n# changed source\n'
            self.write(source,w.path,content)
        base=self.commit(source)
        (source/'src/old.py').rename(source/'src/new.py')
        head=self.commit(source)
        head_tree=self.git.text(['rev-parse',head+'^{tree}'],cwd=source)
        tree=self.git.text(['rev-parse',base+'^{tree}'],cwd=source) if wrong_tree else head_tree
        merge=self.git.text(['commit-tree',tree,'-p',base,'-p',head,'-m','fixture merge'],cwd=source)
        code=self.init_repo('validator')
        self.write(code,'tools/release/validate.py',impact_fixture.STUB)
        for schema in ('build-target-catalog-v1','release-impact-v1'):
            self.write(code,'docs/schemas/'+schema+'.schema.json','{}')
        pin=self.commit(code)
        state=secure_dir(self.root/'state')
        self.validator=RetainedImpactValidator(validator_repository=code,validator_revision=pin,
                                    source_repository=source,state_root=state)
        self.selected=merge
        body='<!-- fortis-release-impact:start -->\n```yaml\n'+json.dumps(impact_fixture.IMPACT)+'\n```\n<!-- fortis-release-impact:end -->'
        for mod in (fixture,fixture.path_fixture,publisher_fixture):
            self.enterContext(patch.object(mod,'HEAD',head))
            self.enterContext(patch.object(mod,'BASE',base))
        for key,value in dict(MERGE=merge,TREE=tree,CATALOG=raw_catalog,BODY=body,
                              DIGEST=hashlib.sha256(body.encode()).hexdigest()).items():
            self.enterContext(patch.object(fixture,key,value))
        ci_fixture.PolicyBindingTests.setUp(self)
        self.api.changed_count=1
        self.api.files=[{'filename':'src/new.py','previous_filename':'src/old.py','status':'renamed'}]
        self.source_head=head

    def approve(self,*,v2=True):
        receipt=self.capture() if v2 else self.store.capture_bundle(self.adapter,**self.kw)
        self.assertEqual(self.decide(self.prepare(receipt))['state'],'EXECUTED')
        self.merge()
        return receipt

    def observe(self,**overrides):
        opts=dict(adapter=self.adapter,store=self.store,core=self.core,checkpoint_reader=lambda:self.anchor,
                  owner='test-owner',owner_request_id=self.payload['requestId'],validator=self.validator,
                  expected_merge_sha=self.selected,selected_main_sha=self.selected)
        opts.update(overrides)
        return observe_selected_main(**opts)

    def test_selected_main_local_graph_and_actual_core(self):
        self.setup_case()
        receipt=self.approve()
        result=self.observe();obs=result['observation']
        self.assertEqual(obs['selectedMainLocalDependencies'],[
            {'repository':fixture.OWNER+'/'+fixture.REPO,'target':'dependency','sourceSha':self.selected}])
        self.assertEqual(obs['retainedImpact']['headSha'],self.source_head)
        self.assertEqual(obs['retainedImpact']['bundleDigest'],receipt['bundleDigest'])
        self.assertEqual(result,self.observe())
        self.assertNotIn(self.api.body,repr(result))
        for key in ('evidenceVerified','dependencyClosureVerified','admissionAllowed','deploymentAllowed',
                    'historicalPolicyVerified','componentBindingsVerified','historicalMergeCutoffVerified'):
            self.assertIs(result[key],False)

    def test_external_remains_unresolved(self):
        self.setup_case(external=True);self.approve()
        result=self.observe()
        self.assertEqual(result['observation']['unresolvedExternalTargets'],
                         [{'repository':'other-repo','target':'external'}])
        self.assertFalse(result['dependencyClosureVerified'])

    def test_wrong_tree_denied(self):
        self.setup_case(wrong_tree=True);self.approve()
        with self.assertRaisesRegex(Denied,'P5_SELECTED_MERGE_TREE_MISMATCH'):
            self.observe()

    def test_workflow_raw_bytes_mismatch(self):
        self.setup_case(wrong_workflow=True);self.approve()
        with self.assertRaisesRegex(Denied,'P5_SELECTED_WORKFLOW_BYTES_MISMATCH'):
            self.observe()

    def test_later_main_denied(self):
        self.setup_case();self.approve()
        with self.assertRaisesRegex(Denied,'P5_SELECTED_MAIN_MUST_BE_EXACT_MERGE'):
            self.observe(selected_main_sha='e'*40)

    def test_v1_not_silently_promoted(self):
        self.setup_case();self.approve(v2=False)
        with self.assertRaisesRegex(Denied,'P5_SELECTED_V2_BUNDLE_REQUIRED'):
            self.observe()

    def test_provider_projection_mismatch(self):
        self.setup_case();self.approve()
        with patch.object(fixture,'TREE','f'*40):
            with self.assertRaisesRegex(Denied,'P5_SELECTED_MERGE_TREE_MISMATCH'):
                self.observe()


    @unittest.skipUnless(impact_fixture.REAL_ROOT and importlib.util.find_spec('yaml')
                         and importlib.util.find_spec('jsonschema'),
                         'Requires the exact shared validator and pinned dependencies')
    def test_real_selected_main_composition(self):
        self.setup_case()
        self.validator=RetainedImpactValidator(
            validator_repository=Path(impact_fixture.REAL_ROOT),
            validator_revision=impact_fixture.REAL_PIN,
            source_repository=self.validator.source,state_root=self.validator.state)
        self.approve()
        result=self.observe()
        self.assertEqual(result['observation']['selectedMainLocalDependencies'],
            [{'repository':fixture.OWNER+'/'+fixture.REPO,'target':'dependency','sourceSha':self.selected}])
        self.assertFalse(result['evidenceVerified'])

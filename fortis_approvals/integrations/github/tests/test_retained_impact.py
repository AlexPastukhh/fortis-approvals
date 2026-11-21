"""Raw Git fixture plus isolated validator protocol; real shared validator opt-in."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import uuid

from fortis_approvals.core import Denied
from fortis_approvals.workflow.common import Git, secure_dir
from fortis_approvals.integrations.github.gateway.review_capture import ReviewCaptureStore
from fortis_approvals.integrations.github.gateway.retained_impact import RetainedImpactValidator
from fortis_approvals.integrations.github.tests import test_integrated_capture as fixture

CATALOG = {
    'schemaVersion':1,'repository':'fortis-approvals','buildUnits':[],
    'targets':[{'id':'app','inputs':['src/*.py'],
                'deployment':{'kind':'configuration','procedure':'procedure.md','environments':['production']},
                'verification':['source-ci']}],
    'noDeploymentPaths':['procedure.md']
}
IMPACT = {'releaseImpact':{'schemaVersion':1,'classification':'deployment',
          'reason':'Reviewed source configuration modification.',
          'targets':[{'id':'app','actions':['config-deploy']}],
          'dependencies':{'pullRequests':[],'targets':[]},'verification':['source-ci']}}
# Protocol test doubles only. Never a semantic substitute for the real validator.
STUB = """
import json
from pathlib import Path
def load_data(text,fmt): return json.loads(text)
def validate_schema(data,path):
    assert path.is_file()
def validate_catalog(data,root,repository):
    assert repository=='fortis-approvals' and (root/'src/new.py').is_file()
    assert (root/'validate.py').read_text()=='raise RuntimeError("PR CODE EXECUTED")'
def extract_pr_impact(body):return body.split('```yaml\\n')[1].split('\\n```')[0]
def validate_impact(data,catalog,paths):
    assert paths==['src/new.py','src/old.py']
    assert data['releaseImpact']['classification']=='deployment'
    return dict(classification='deployment',affectedTargets=['app'],changedFiles=len(paths))
"""
REAL_ROOT = os.environ.get('FORTIS_TEST_RELEASE_VALIDATOR_ROOT')
REAL_PIN = '8c9abefdfbe4699aae97b9363a2a66c596680e62'


class RetainedImpactTests(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory();self.addCleanup(tmp.cleanup);self.root=Path(tmp.name)
        self.git=Git(self.root/'git-state')
        self.source=self.init_repo('source')
        self.write(self.source,'src/old.py','VALUE = 1\n')
        self.write(self.source,'release/targets.yaml',json.dumps(CATALOG))
        self.write(self.source,'procedure.md','Review procedure\n')
        self.write(self.source,'validate.py','raise RuntimeError("PR CODE EXECUTED")')
        self.base=self.commit(self.source)
        (self.source/'src/old.py').rename(self.source/'src/new.py')
        self.head=self.commit(self.source)
        self.code=self.init_repo('validator')
        self.write(self.code,'tools/release/validate.py',STUB)
        for name in ('build-target-catalog-v1','release-impact-v1'):
            self.write(self.code,'docs/schemas/'+name+'.schema.json','{}')
        self.pin=self.commit(self.code)
        self.api=fixture.Provider()
        self.api.head=self.head;self.api.base=self.base;self.api.ci_head=self.head
        self.api.body='<!-- fortis-release-impact:start -->\n```yaml\n'+json.dumps(IMPACT)+'\n```\n<!-- fortis-release-impact:end -->'
        self.api.sources['release/targets.yaml']=json.dumps(CATALOG).encode()
        self.api.files=[{'filename':'src/new.py','previous_filename':'src/old.py','status':'renamed'}]
        self.api.changed_count=1
        self.adapter=fixture.path_fixture.AnalysisGitHubAdapter(self.api,owner=fixture.OWNER,repositories=[fixture.REPO],
            receipt_store=self.root/'receipts.sqlite',
            bindings={fixture.REPO:{'workflows':{str(w.ident):w.path for w in fixture.path_fixture.WORKFLOWS},
                          'projectKey':'fixture','allowCiControl':False}})
        self.store=ReviewCaptureStore.initialize(self.root/'capture.sqlite')
        self.operation_id=str(uuid.uuid4())
        self.state=secure_dir(self.root/'state')

    def init_repo(self,name):
        path=secure_dir(self.root/name)
        self.git.run(['init','--quiet','--template=',path])
        self.git.run(['config','user.name','Fixture'],cwd=path)
        self.git.run(['config','user.email','fixture@example.invalid'],cwd=path)
        return path

    @staticmethod
    def write(root,name,text):
        p=root/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_text(text)

    def commit(self,repo):
        self.git.run(['add','--all'],cwd=repo);self.git.run(['commit','--quiet','-m','Fixture'],cwd=repo)
        return self.git.text(['rev-parse','HEAD'],cwd=repo)

    def capture(self):
        # The existing path fixture uses symbolic fixture SHAs in compare.
        # Serve the same projection under the actual fixture Git object IDs.
        api=self.api;old=api.request
        def compare(method,path,**kw):
            if '/compare/' in path:
                assert path.endswith(self.base+'...'+self.head)
                return {'status':'ahead','ahead_by':1,'base_commit':{'sha':self.base},
                        'merge_base_commit':{'sha':self.base},'files':api.files}
            return old(method,path,**kw)
        with patch.object(api,'request',side_effect=compare):
            receipt=self.store.capture_bundle(self.adapter,operation_id=self.operation_id,
                      expected_revision=0,number=7,expected_head_sha=self.head,
                      expected_base_sha=self.base,expected_body_sha256=hashlib.sha256(api.body.encode()).hexdigest())
        self.anchor=self.store.checkpoint()
        return receipt

    def validate(self,**kw):
        opts=dict(validator_repository=self.code,validator_revision=self.pin,
                  source_repository=self.source,state_root=self.state)
        opts.update(kw)
        return RetainedImpactValidator(**opts).validate_retained(store=self.store,
                        operation_id=self.operation_id,checkpoint_reader=lambda:self.anchor)

    def test_retained_exact_git_and_isolated_protocol(self):
        receipt=self.capture()
        # Modified checkout contents and PR modules are never executed.
        self.write(self.code,'tools/release/validate.py','raise RuntimeError("DIRTY CODE")')
        self.write(self.source,'release/targets.yaml','dirty catalog')
        result=self.validate();obs=result['observation']
        self.assertEqual(obs['bundleDigest'],receipt['bundleDigest'])
        self.assertEqual(obs['validatorRevision'],self.pin)
        self.assertEqual(obs['validatedImpact']['affectedTargets'],['app'])
        self.assertEqual(obs['validatedImpact']['changedFiles'],2)
        self.assertNotIn(self.api.body,repr(result))
        for flag in ('dependencyClosureVerified','historicalPolicyVerified','evidenceVerified',
                     'admissionAllowed','deploymentAllowed'):
            self.assertIs(result[flag],False)

    def test_provider_paths_mismatch_git_rejected(self):
        self.api.files=[{'filename':'src/new.py','status':'added'}]
        self.capture()
        with self.assertRaisesRegex(Denied,'P5_IMPACT_GIT_PATH_MISMATCH'):self.validate()

    def test_catalog_mismatch_git_rejected(self):
        self.api.sources['release/targets.yaml']+=b'\n'
        self.capture()
        with self.assertRaisesRegex(Denied,'P5_IMPACT_CATALOG_MISMATCH'):self.validate()

    def test_invalid_pin_stops(self):
        self.capture()
        with self.assertRaises(Denied):self.validate(validator_revision='z'*40)

    def test_validator_failure_opaque(self):
        self.capture()
        self.write(self.code,'tools/release/validate.py','raise RuntimeError("PRIVATE DETAIL")')
        pin=self.commit(self.code)
        with self.assertRaisesRegex(Denied,'^P5_IMPACT_VALIDATION_FAILED$'):
            self.validate(validator_revision=pin)

    def test_stale_checkpoint_stops(self):
        self.capture();self.anchor={'revision':0,'eventDigest':'0'*64}
        with self.assertRaises(Denied):self.validate()

    @unittest.skipUnless(REAL_ROOT and importlib.util.find_spec('yaml') and importlib.util.find_spec('jsonschema'),
                         'Requires explicitly supplied shared validator repository and its pinned dependencies')
    def test_real_shared_validator_semantics(self):
        self.capture()
        result=self.validate(validator_repository=Path(REAL_ROOT),validator_revision=REAL_PIN)
        self.assertEqual(result['observation']['validatedImpact']['affectedTargets'],['app'])
        self.assertFalse(result['admissionAllowed'])

    @unittest.skipUnless(REAL_ROOT and importlib.util.find_spec('yaml') and importlib.util.find_spec('jsonschema'),
                         'Requires explicitly supplied shared validator repository and its pinned dependencies')
    def test_real_validator_rejects_false_no_deployment(self):
        false=json.loads(json.dumps(IMPACT));false['releaseImpact'].update(classification='no-deployment',targets=[])
        self.api.body=self.api.body.replace(json.dumps(IMPACT),json.dumps(false))
        self.capture()
        with self.assertRaisesRegex(Denied,'P5_IMPACT_VALIDATION_FAILED'):
            self.validate(validator_repository=Path(REAL_ROOT),validator_revision=REAL_PIN)


    @unittest.skipUnless(REAL_ROOT and importlib.util.find_spec('yaml') and importlib.util.find_spec('jsonschema'),
                         'Requires explicitly supplied shared validator repository and its pinned dependencies')
    def test_real_validator_rejects_missing_local_dependency(self):
        impact=json.loads(json.dumps(IMPACT))
        impact['releaseImpact']['dependencies']['targets']=[{'repository':'fortis-approvals','target':'missing'}]
        self.api.body=self.api.body.replace(json.dumps(IMPACT),json.dumps(impact))
        self.capture()
        with self.assertRaisesRegex(Denied,'P5_IMPACT_VALIDATION_FAILED'):
            self.validate(validator_repository=Path(REAL_ROOT),validator_revision=REAL_PIN)

    @unittest.skipUnless(REAL_ROOT and importlib.util.find_spec('yaml') and importlib.util.find_spec('jsonschema'),
                         'Requires explicitly supplied shared validator repository and its pinned dependencies')
    def test_real_validator_rejects_duplicate_yaml_key(self):
        # Duplicate classification cannot be silently interpreted as last-wins.
        self.api.body=self.api.body.replace('"classification": "deployment"',
            '"classification": "no-deployment", "classification": "deployment"')
        self.capture()
        with self.assertRaisesRegex(Denied,'P5_IMPACT_VALIDATION_FAILED'):
            self.validate(validator_repository=Path(REAL_ROOT),validator_revision=REAL_PIN)

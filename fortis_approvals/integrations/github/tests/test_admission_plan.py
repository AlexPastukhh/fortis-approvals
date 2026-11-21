"""Initial range planning: real fixture collection, no authoritative writes."""
import copy
import unittest
from unittest.mock import patch

from fortis_approvals.core import Denied
from fortis_approvals.integrations.github.gateway import admission_plan as p
from fortis_approvals.integrations.github.tests import test_component_bindings as fixture


class AdmissionPlanTests(unittest.TestCase):
    setUp=fixture.ComponentBindingsTests.setUp
    prepare=fixture.ComponentBindingsTests.prepare
    approve=fixture.ComponentBindingsTests.approve
    set_merge=fixture.ComponentBindingsTests.set_merge
    journal_setup=fixture.ComponentBindingsTests.journal_setup
    retain=fixture.ComponentBindingsTests.retain
    confirm=fixture.ComponentBindingsTests.confirm
    build=fixture.ComponentBindingsTests.build
    repin=fixture.ComponentBindingsTests.repin

    def setup_plan(self):
        self.build()
        self.enterContext(patch.object(p,'REPOSITORY',fixture.m.REPOSITORY))

    def args(self):
        return dict(adapter=self.fixture.adapter,journal=self.journal,validator=self.fixture.validator,
                    baseline_reader=lambda:copy.deepcopy(self.baseline),
                    expected_baseline_digest=p._hash(self.baseline),
                    selected_main_sha=self.fixture.selected,evidence_ids=[self.eid],
                    policy_reader=self.reader,expected_policy_digest=self.pin,
                    binding_reader=lambda:copy.deepcopy(self.mapping))

    def observe(self,**changes):
        return p.observe_initial_plan(**(self.args()|changes))

    def test_original_evidence_to_stable_candidate(self):
        self.setup_plan();result=self.observe();o=result['observation']
        self.assertEqual(result['result'],'INITIAL_RANGE_PLAN_CANDIDATE')
        self.assertEqual(o['rangeClassification'],'DEPLOYMENT_CANDIDATE')
        self.assertEqual(len(o['recordCandidates']),1)
        row=o['recordCandidates'][0];identity=row['identity']
        self.assertEqual(identity['targetId'],'app')
        self.assertEqual(identity['desiredSourceSha'],self.fixture.selected)
        self.assertEqual(identity['catalogCommitSha'],self.baseline['baselineSha'])
        self.assertEqual(row['recordId'],p._hash(identity))
        self.assertEqual(row['subjectId'],p._hash({k:identity[k] for k in
                         ('repository','targetId','environment')}))
        self.assertEqual(row['requiredActions'],['config-deploy'])
        self.assertEqual(row['evidenceIds'],[self.eid])
        self.assertEqual(row['artifact'],{'state':'NOT_BUILT','digest':None})
        self.assertIsNone(row['actual'])
        self.assertEqual(o['sourceDependencyRequirements'],[
            {'repository':p.REPOSITORY,'targetId':'dependency','environment':'production',
             'sourceSha':self.fixture.selected,'actual':None}])
        self.assertEqual(result,self.observe())
        self.assertFalse(result['admissionAllowed'])
        self.assertFalse(result['evidenceVerified'])

    def test_partial_range_is_not_a_plan(self):
        self.setup_plan()
        with self.assertRaisesRegex(Denied,'P5_FORWARD_MISSING_MERGE_EVIDENCE'):
            self.observe(evidence_ids=[])

    def test_late_batch_drift(self):
        self.setup_plan()
        original=p._observe_component_pair
        def drift(**kw):
            pair=original(**kw)
            self.anchor={**self.anchor,'eventDigest':'f'*64}
            return pair
        with patch.object(p,'_observe_component_pair',side_effect=drift):
            with self.assertRaisesRegex(Denied,'P5_SNAPSHOT_ANCHOR_MISMATCH'):
                self.observe()

    def material(self):
        mapping,lineage,catalog,_=p._observe_component_pair(**self.args())
        batch=self.journal.anchored_batch([self.eid])
        return lineage,mapping,catalog,batch

    def changed(self,*,edit):
        # Synthetic internal projection protocol cases only, never trusted
        # collector input. Real source composition is exercised above.
        lineage,mapping,catalog,batch=self.material()
        entry=batch['entries'][0];snap=entry['snapshot'];o=snap['result']['observation']
        impact=o['retainedImpact'];edit(impact,o)
        o['retainedImpactSha256']=p._hash(impact)
        sd=p._hash(snap);entry['receipt']['evidenceDigest']=sd
        lineage['observation']['merges'][0]['evidenceDigest']=sd
        return lineage,mapping,catalog,batch

    def test_recomputed_graph_rejects_missing_transitive_target(self):
        self.setup_plan()
        def edit(impact,o):
            dep=impact['dependencyObservation'];dep['graph']['localDependencyTargets']=[]
            impact['validatedImpact']['dependencyGraph']=copy.deepcopy(dep['graph'])
            impact['dependencyObservationSha256']=p._hash(dep)
            o['selectedMainLocalDependencies']=[]
        with self.assertRaisesRegex(Denied,'P5_PLAN_DEPENDENCY_GRAPH_MISMATCH'):
            p._derive(*self.changed(edit=edit))

    def test_unknown_action_rejected(self):
        self.setup_plan()
        def edit(impact,o):
            impact['validatedImpact']['declaredTargets'][0]['actions']=['unknown']
        with self.assertRaisesRegex(Denied,'P5_PLAN_ACTION_INVALID'):
            p._derive(*self.changed(edit=edit))

    def test_no_deployment_and_empty_range_distinct(self):
        self.setup_plan()
        def edit(impact,o):
            v=impact['validatedImpact'];v.update(classification='no-deployment',affectedTargets=[],
                                                 declaredTargets=[],targetDependencies=[])
            dep=impact['dependencyObservation']
            dep['graph']={k:[] for k in dep['graph']}
            v['dependencyGraph']=copy.deepcopy(dep['graph'])
            dep['localDependencyEdges']=[];impact['dependencyObservationSha256']=p._hash(dep)
            o['selectedMainLocalDependencies']=[]
        lineage,mapping,catalog,batch=self.changed(edit=edit)
        r=p._derive(lineage,mapping,catalog,batch)
        self.assertEqual(r['rangeClassification'],'NO_DEPLOYMENT_CANDIDATE')
        self.assertEqual(r['recordCandidates'],[])
        self.assertEqual(len(r['mergeAudit']),1)
        lineage['observation']['merges']=[];batch['entries']=[]
        r=p._derive(lineage,mapping,catalog,batch)
        self.assertEqual(r['rangeClassification'],'EMPTY_RANGE')
        self.assertEqual(r['mergeAudit'],[])

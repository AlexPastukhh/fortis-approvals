"""Forward coverage against real Git objects and anchored source candidates."""
import copy
import hashlib
import unittest
import uuid
from unittest.mock import patch

from fortis_approvals.core import Denied, Stale
from fortis_approvals.integrations.github.gateway import forward_lineage as f
from fortis_approvals.integrations.github.tests import test_collector_snapshot as fixture


class ForwardLineageTests(unittest.TestCase):
    setUp=fixture.CollectorSnapshotTests.setUp
    retain=fixture.CollectorSnapshotTests.retain
    confirm=fixture.CollectorSnapshotTests.confirm

    def initialize_baseline(self):
        self.enterContext(patch.object(f,'REPOSITORY',fixture.c.REPOSITORY))
        self.baseline={'schemaVersion':1,'enrollmentId':str(uuid.uuid4()),
                       'repository':f.REPOSITORY,'baselineSha':self.fixture.kw['expected_base_sha'],
                       'catalogSha256':hashlib.sha256(self.fixture.api.sources['release/targets.yaml']).hexdigest(),
                       'acceptanceReceiptDigest':'a'*64,'bindingDigest':'b'*64}
        self.pin=f._hash(self.baseline)

    def observe(self,**changes):
        opts=dict(adapter=self.fixture.adapter,journal=self.journal,validator=self.fixture.validator,
                  baseline_reader=lambda:copy.deepcopy(self.baseline),expected_baseline_digest=self.pin,
                  selected_main_sha=self.fixture.selected,evidence_ids=[self.evidence])
        return f.observe_forward_lineage(**(opts|changes))

    def test_anchored_single_merge_and_no_prebaseline_traversal(self):
        self.initialize_baseline();self.confirm(self.retain())
        with patch.object(f,'_commit',wraps=f._commit) as read:
            r=self.observe()
        o=r['observation'];self.assertEqual(o['baselineSha'],self.baseline['baselineSha'])
        self.assertEqual(o['selectedMainSha'],self.fixture.selected)
        self.assertEqual([x['mergeSha'] for x in o['merges']],[self.fixture.selected])
        self.assertEqual({x.args[2] for x in read.call_args_list},
                         {self.fixture.selected,self.fixture.source_head,self.baseline['baselineSha']})
        self.assertEqual(o['merges'][0]['evidenceId'],self.evidence)
        self.assertEqual(r,self.observe())
        for key,value in r.items():
            if key.endswith(('Verified','Allowed')):self.assertIs(value,False)

    def test_cutover_prefix_requires_the_exact_two_merge_parents_and_catalog(self):
        self.initialize_baseline()
        git, repository = self.fixture.git, self.fixture.validator.source
        first = self.fixture.selected
        tree = git.text(['rev-parse', first + '^{tree}'], cwd=repository)
        recovery = git.text(['commit-tree', tree, '-p', first, '-m', 'recovery'], cwd=repository)
        head = git.text(['commit-tree', tree, '-p', recovery, '-m', 'follow-up'], cwd=repository)
        second = git.text(['commit-tree', tree, '-p', first, '-p', head, '-m', 'merge'], cwd=repository)
        gap = {'disposition': 'OWNER_REVIEWED_PRE_CAPTURE_GAP', 'merges': [
            {**f._CUTOVER_253, 'headSha': self.fixture.source_head, 'mergeSha': first},
            {'number': 254, 'headSha': head, 'mergeSha': second,
             'impact': f._CUTOVER_RECOVERY_IMPACT},
        ]}
        with patch.object(f, '_CUTOVER_BASELINE', self.baseline['baselineSha']), \
             patch.object(f, '_CUTOVER_253', gap['merges'][0]):
            self.assertEqual(f.verify_cutover_commits(gap, self.baseline, git, repository), second)
            with self.assertRaisesRegex(Denied, 'CUTOVER_GAP_CATALOG'):
                f.verify_cutover_commits(gap, {**self.baseline, 'catalogSha256': '0'*64}, git, repository)
            wrong = copy.deepcopy(gap)
            wrong['merges'][1]['mergeSha'] = head
            with self.assertRaisesRegex(Denied, 'CUTOVER_GAP_LINEAGE'):
                f.verify_cutover_commits(wrong, self.baseline, git, repository)
            wrong['merges'].append(gap['merges'][1])
            with self.assertRaisesRegex(Denied, 'CUTOVER_GAP_SCOPE'):
                f.verify_cutover_commits(wrong, self.baseline, git, repository)

    def test_post_255_gap_extends_the_exact_reviewed_prefix(self):
        self.initialize_baseline()
        git, repository = self.fixture.git, self.fixture.validator.source
        first = self.fixture.selected
        tree = git.text(['rev-parse', first + '^{tree}'], cwd=repository)
        rows = [{'number': 253, 'headSha': self.fixture.source_head, 'mergeSha': first,
                 'impact': f._CUTOVER_253['impact']}]
        parent = first
        for number in (254, 255, 256, 257, 258, 259, 260, 261, 262):
            head = git.text(['commit-tree', tree, '-p', parent, '-m', f'PR {number}'],
                            cwd=repository)
            merge = git.text(['commit-tree', tree, '-p', parent, '-p', head, '-m', f'Merge {number}'],
                             cwd=repository)
            impact = f._CUTOVER_255['impact'] if number == 255 else f._CUTOVER_RECOVERY_IMPACT
            if number in (257, 258, 259, 261, 262):
                impact = f._CUTOVER_HANDOVER_IMPACT
            if number == 260:
                impact = f._CUTOVER_260['impact']
            rows.append({'number': number, 'headSha': head, 'mergeSha': merge, 'impact': impact})
            parent = merge
        gap = {'disposition': f._POST_255_GAP, 'merges': rows}
        with patch.multiple(f, _CUTOVER_BASELINE=self.baseline['baselineSha'],
                            _CUTOVER_253=rows[0], _CUTOVER_254=rows[1],
                            _CUTOVER_255=rows[2], _CUTOVER_256=rows[3], _CUTOVER_257=rows[4],
                            _CUTOVER_258=rows[5], _CUTOVER_259=rows[6],
                            _CUTOVER_260=rows[7], _CUTOVER_261=rows[8]):
            legacy_gap={**gap, 'merges':rows[:4]}
            self.assertEqual(f.verify_cutover_commits(legacy_gap,self.baseline,git,repository),
                             rows[3]['mergeSha'])
            handover_gap={**gap, 'merges':rows[:5]}
            self.assertEqual(f.verify_cutover_commits(handover_gap,self.baseline,git,repository),
                             rows[4]['mergeSha'])
            prior_gap={**gap, 'merges':rows[:6]}
            self.assertEqual(f.verify_cutover_commits(prior_gap,self.baseline,git,repository),rows[5]['mergeSha'])
            through_259={**gap, 'merges':rows[:7]}
            self.assertEqual(f.verify_cutover_commits(through_259,self.baseline,git,repository),rows[6]['mergeSha'])
            self.assertEqual(f.verify_cutover_commits(gap, self.baseline, git, repository), parent)
            through_261={**gap,'merges':rows[:-1]}
            self.assertEqual(f.verify_cutover_commits(through_261,self.baseline,git,repository),rows[8]['mergeSha'])
            for invalid in (rows[:8], rows[:7] + rows[8:], [*rows[:8], rows[7], rows[9]]):
                with self.assertRaisesRegex(Denied, 'CUTOVER_GAP_SCOPE'):
                    f.cutover_start({**gap, 'merges':invalid}, self.baseline['baselineSha'])
            changed_260=copy.deepcopy(gap)
            changed_260['merges'][7]['headSha']=rows[6]['headSha']
            with self.assertRaisesRegex(Denied, 'CUTOVER_GAP_SCOPE'):
                f.cutover_start(changed_260, self.baseline['baselineSha'])
            unreviewed = copy.deepcopy(gap)
            unreviewed['merges'][3]['headSha'] = rows[2]['headSha']
            with self.assertRaisesRegex(Denied, 'CUTOVER_GAP_SCOPE'):
                f.cutover_start(unreviewed, self.baseline['baselineSha'])
            unreviewed = copy.deepcopy(gap)
            unreviewed['merges'][4]['impact'] = f._CUTOVER_RECOVERY_IMPACT
            with self.assertRaisesRegex(Denied, 'CUTOVER_GAP_SCOPE'):
                f.cutover_start(unreviewed, self.baseline['baselineSha'])
            changed = copy.deepcopy(gap)
            changed['merges'][2]['impact'] = f._CUTOVER_RECOVERY_IMPACT
            with self.assertRaisesRegex(Denied, 'CUTOVER_GAP_SCOPE'):
                f.cutover_start(changed, self.baseline['baselineSha'])
            missing = {**gap, 'merges': rows[:2] + rows[3:]}
            with self.assertRaisesRegex(Denied, 'CUTOVER_GAP_SCOPE'):
                f.cutover_start(missing, self.baseline['baselineSha'])
            wrong_impact = copy.deepcopy(gap)
            wrong_impact['merges'][6]['impact'] = f._CUTOVER_RECOVERY_IMPACT
            with self.assertRaisesRegex(Denied, 'CUTOVER_GAP_SCOPE'):
                f.cutover_start(wrong_impact, self.baseline['baselineSha'])
            extra = {**gap, 'merges': [*rows, rows[-1]]}
            with self.assertRaisesRegex(Denied, 'CUTOVER_GAP_SCOPE'):
                f.cutover_start(extra, self.baseline['baselineSha'])
            wrong_parent = copy.deepcopy(gap)
            wrong_parent['merges'][-1]['headSha'] = rows[-2]['headSha']
            with self.assertRaisesRegex(Denied, 'CUTOVER_GAP_LINEAGE'):
                f.verify_cutover_commits(wrong_parent, self.baseline, git, repository)

    def test_pending_anchor_and_missing_evidence(self):
        self.initialize_baseline();pending=self.retain()
        with self.assertRaisesRegex(Denied,'P5_SNAPSHOT_ANCHOR_MISMATCH'):self.observe()
        self.confirm(pending)
        with self.assertRaisesRegex(Denied,'P5_FORWARD_MISSING_MERGE_EVIDENCE'):
            self.observe(evidence_ids=[])

    def test_baseline_pin_and_catalog_mismatch(self):
        self.initialize_baseline();self.confirm(self.retain())
        self.baseline['baselineSha']=self.fixture.source_head
        with self.assertRaisesRegex(Denied,'P5_BASELINE_REFERENCE_MISMATCH'):self.observe()
        self.baseline['catalogSha256']='e'*64
        self.pin=f._hash(self.baseline)
        with self.assertRaisesRegex(Denied,'P5_BASELINE_CATALOG_MISMATCH'):self.observe()

    def test_baseline_equal_main_no_history_import(self):
        self.initialize_baseline()
        self.baseline['baselineSha']=self.fixture.selected;self.pin=f._hash(self.baseline)
        r=self.observe(evidence_ids=[])
        self.assertEqual(r['observation']['merges'],[])
        self.assertFalse(r['admissionAllowed'])
        self.confirm(self.retain())
        with self.assertRaisesRegex(Denied,'P5_FORWARD_UNUSED_EVIDENCE'):self.observe()

    def test_duplicate_and_extra_evidence(self):
        self.initialize_baseline();self.confirm(self.retain())
        with self.assertRaisesRegex(Denied,'P5_FORWARD_REQUEST_INVALID'):
            self.observe(evidence_ids=[self.evidence,self.evidence])
        extra=str(uuid.uuid4());self.confirm(self.retain(evidence_id=extra,expected_revision=1))
        with self.assertRaisesRegex(Denied,'P5_FORWARD_DUPLICATE_ATTRIBUTION'):
            self.observe(evidence_ids=[self.evidence,extra])

    def test_unreviewed_later_nonmerge_or_merge_is_not_skipped(self):
        self.initialize_baseline();self.confirm(self.retain())
        git=self.fixture.git;source=self.fixture.validator.source
        tree=git.text(['rev-parse',self.fixture.selected+'^{tree}'],cwd=source)
        direct=git.text(['commit-tree',tree,'-p',self.fixture.selected,'-m','unreviewed'],cwd=source)
        merge=git.text(['commit-tree',tree,'-p',self.fixture.selected,'-p',self.fixture.source_head,
                        '-m','unreviewed merge'],cwd=source)
        for sha,code in ((direct,'P5_FORWARD_UNATTRIBUTED_NON_MERGE'),
                         (merge,'P5_FORWARD_MISSING_MERGE_EVIDENCE')):
            with patch.object(self.fixture.adapter,'_project_branch',return_value={'name':'main','sha':sha}):
                with self.assertRaisesRegex(Denied,code):self.observe(selected_main_sha=sha)

    def test_main_and_witness_drift(self):
        self.initialize_baseline();self.confirm(self.retain())
        with patch.object(self.fixture.adapter,'_project_branch',side_effect=[
              {'name':'main','sha':self.fixture.selected},{'name':'main','sha':'e'*40}]):
            with self.assertRaisesRegex(Stale,'P5_FORWARD_MAIN_CHANGED'):self.observe()
        batch=self.journal.anchored_batch([self.evidence])
        drift=copy.deepcopy(batch);drift['checkpoint']['eventDigest']='f'*64
        with patch.object(self.journal,'anchored_batch',side_effect=[batch,drift]):
            with self.assertRaisesRegex(Stale,'P5_FORWARD_CHECKPOINT_CHANGED'):self.observe()

    def test_non_first_parent_baseline_rejected(self):
        self.initialize_baseline();self.confirm(self.retain())
        self.baseline['baselineSha']=self.fixture.source_head;self.pin=f._hash(self.baseline)
        with self.assertRaises(Denied):self.observe()

    def test_retained_receipt_digest_mismatch(self):
        self.initialize_baseline();self.confirm(self.retain())
        batch=self.journal.anchored_batch([self.evidence])
        batch['entries'][0]['receipt']['evidenceDigest']='f'*64
        with patch.object(self.journal,'anchored_batch',return_value=batch):
            with self.assertRaisesRegex(Denied,'P5_FORWARD_RECEIPT_MISMATCH'):self.observe()

    def second_entry(self):
        # Real second Git merge, synthetic retained projection/receipt only.
        # The first row comes from the actual private collector journal.
        git=self.fixture.git;source=self.fixture.validator.source
        parent=self.fixture.selected
        tree=git.text(['rev-parse',parent+'^{tree}'],cwd=source)
        head=git.text(['commit-tree',tree,'-p',parent,'-m','second head'],cwd=source)
        merge=git.text(['commit-tree',tree,'-p',parent,'-p',head,'-m','second merge'],cwd=source)
        batch=self.journal.anchored_batch([self.evidence])
        entry=copy.deepcopy(batch['entries'][0])
        snapshot,receipt=entry['snapshot'],entry['receipt']
        result=snapshot['result'];o=result['observation']
        review=o['reviewedMerge'];decision=review['ownerDecision']
        provider=review['mergeObservation'];impact=o['retainedImpact']
        eid=str(uuid.uuid4());oid=str(uuid.uuid4())
        node=f._commit(git,source,merge);head_obj=f._commit(git,source,head)
        parent_obj=f._commit(git,source,parent)
        snapshot['evidenceId']=eid
        o.update(selectedMainSha=merge,number=8,rawCommitBindingSha256=f._hash([parent_obj,head_obj,node]))
        decision.update(requestId=oid,number=8,headSha=head)
        provider.update(selectedMainSha=merge,firstParent=[node],headCommit=head_obj)
        provider['pullRequest'].update(number=8,mergeSha=merge,headSha=head,baseSha=parent)
        impact.update(number=8,headSha=head,baseSha=parent)
        o.update(reviewedMergeSha256=f._hash(review),retainedImpactSha256=f._hash(impact))
        result['observationDigest']=f._hash(o)
        next_cp={**batch['checkpoint'],'revision':2,'eventDigest':'f'*64}
        receipt.update(evidenceId=eid,ownerRequestId=oid,selectedMainSha=merge,
                       evidenceDigest=f._hash(snapshot),checkpoint=next_cp)
        batch.update(checkpoint=next_cp,entries=[entry,*batch['entries']])
        return merge,eid,batch

    def test_two_merge_order_and_missing_intermediate_protocol(self):
        self.initialize_baseline();self.confirm(self.retain())
        merge,eid,batch=self.second_entry()
        with patch.object(self.fixture.adapter,'_project_branch',return_value={'name':'main','sha':merge}):
            with patch.object(self.journal,'anchored_batch',return_value=batch):
                r=self.observe(selected_main_sha=merge,evidence_ids=[eid,self.evidence])
                self.assertEqual([x['mergeSha'] for x in r['observation']['merges']],
                                 [self.fixture.selected,merge])
            batch['entries']=batch['entries'][:1]
            with patch.object(self.journal,'anchored_batch',return_value=batch):
                with self.assertRaisesRegex(Denied,'P5_FORWARD_MISSING_MERGE_EVIDENCE'):
                    self.observe(selected_main_sha=merge,evidence_ids=[eid])

    def test_catalog_change_and_unresolved_dependency_protocol(self):
        self.initialize_baseline();self.confirm(self.retain())
        merge,eid,batch=self.second_entry()
        for flag,code in [('catalog','P5_FORWARD_CATALOG_CHANGE_UNSUPPORTED'),
                          ('dependency','P5_FORWARD_UNRESOLVED_DEPENDENCY')]:
            changed=copy.deepcopy(batch);entry=changed['entries'][0];snap=entry['snapshot']
            result=snap['result'];o=result['observation'];review=o['reviewedMerge'];impact=o['retainedImpact']
            if flag=='catalog':
                review['mergeObservation']['catalog']['contentSha256']='f'*64
                impact['catalogSha256']='f'*64
            else:
                o['unresolvedExternalTargets']=[{'repository':'other','target':'app'}]
            o.update(reviewedMergeSha256=f._hash(review),retainedImpactSha256=f._hash(impact))
            result['observationDigest']=f._hash(o);entry['receipt']['evidenceDigest']=f._hash(snap)
            with patch.object(self.fixture.adapter,'_project_branch',return_value={'name':'main','sha':merge}):
                with patch.object(self.journal,'anchored_batch',return_value=changed):
                    with self.assertRaisesRegex(Denied,code):
                        self.observe(selected_main_sha=merge,evidence_ids=[eid,self.evidence])

"""Offline claimed-byte hash bindings, never GitHub or Registry authority."""
import copy
import hashlib
import json
import unittest

from fortis_approvals.integrations.github.post_merge_registry_envelope import EvidenceEnvelopeError
from fortis_approvals.integrations.github.post_merge_proof_bindings import bind_claimed_material
from fortis_approvals.integrations.github.tests.test_post_merge_registry_envelope import example


def digest(raw):
    if type(raw) is not bytes:
        raw = json.dumps(raw, sort_keys=True, separators=(',', ':'),
                         ensure_ascii=False, allow_nan=False).encode('utf-8')
    return hashlib.sha256(raw).hexdigest()


def setup():
    env=example()
    yaml='releaseImpact:\n  schemaVersion: 1\n  classification: deployment\n'
    body='Reviewed PR source body\n\n<!-- fortis-release-impact:start -->\n```yaml\n'+yaml+'```\n<!-- fortis-release-impact:end -->\n'
    # The normalized YAML range excludes one delimiter newline.
    impact=yaml[:-1]
    paths=[
        {'status':'modified','path':'.github/workflows/release-impact.yml','previousPath':None},
        {'status':'renamed','path':'src/new.py','previousPath':'src/old.py'},
    ]
    cmap=[{'targetId':'fortis-gateway','componentIds':['gateway'],
           'resourceIds':['gateway-state']}]
    policy={'requiredChecks':['source-ci']}
    cat='schemaVersion: 1\nrepository: fortis-approvals\n'
    env['catalog']['contentSha256']=digest(cat.encode())
    env['catalog']['componentMapSha256']=digest(cmap)
    env['dependencyClosure']['digest']=digest([])
    item=env['mergedPullRequests'][0]
    item['reviewedBody']['bodySha256']=digest(body.encode())
    item['releaseImpactSha256']=digest(impact.encode())
    item['changedPaths']['sha256']=digest(paths)
    item['changedPaths']['count']=len(paths)
    item['ci']['policySha256']=digest(policy)
    return env,{'catalogText':cat,'componentMap':cmap,'dependencyEdges':[],
                'pullRequests':[{'number':item['number'],'reviewedBodyText':body,
                                'changedPathRecords':paths,'ciRequiredPolicy':policy}]}


class ClaimedByteTests(unittest.TestCase):
    def mismatch(self,fn,reason):
        env,mat=setup();fn(env,mat)
        with self.assertRaisesRegex(EvidenceEnvelopeError,reason):
            bind_claimed_material(env,mat)

    def test_bytes_match_but_never_trusted(self):
        env,mat=setup()
        row=bind_claimed_material(env,mat)
        self.assertEqual(row['result'],'SOURCE_BYTES_MATCH_UNTRUSTED')
        self.assertFalse(row['evidenceVerified'])
        self.assertFalse(row['admissionAllowed'])
        self.assertFalse(row['deploymentAllowed'])
        self.assertEqual(row['matchedPrCount'],1)
        self.assertEqual(row['matchedPathCount'],2)
        self.assertEqual(row,bind_claimed_material(env,mat))
        self.assertIn('PROVIDER_AUTHENTICITY',row['unverified'])

    def test_no_mutation(self):
        env,mat=setup();prev=copy.deepcopy((env,mat))
        bind_claimed_material(env,mat)
        self.assertEqual((env,mat),prev)

    def test_forged_actor_with_self_consistent_bytes_never_authorizes(self):
        env,mat=setup();env['collectorClaim']['actor']='owner-superuser'
        out=bind_claimed_material(env,mat)
        self.assertFalse(out['admissionAllowed'])
        self.assertFalse(out['evidenceVerified'])

    def test_two_prs_bind_distinct_material_without_duplicate_installs(self):
        env,mat=setup()
        second=copy.deepcopy(env['mergedPullRequests'][0])
        second['number']=41
        env['mergedPullRequests'].append(second)
        second_bytes=copy.deepcopy(mat['pullRequests'][0]);second_bytes['number']=41
        mat['pullRequests'].append(second_bytes)
        out=bind_claimed_material(env,mat)
        self.assertEqual(out['matchedPrCount'],2)
        self.assertEqual(out['matchedPathCount'],4)
        self.assertFalse(out['admissionAllowed'])

    def test_catalog_blob_claim_is_not_verified_by_content_hash(self):
        env,mat=setup()
        env['catalog']['blobSha256']='f'*64
        out=bind_claimed_material(env,mat)
        self.assertIn('CATALOG_GIT_BLOB_AND_COMPONENT_BINDINGS',out['unverified'])
        self.assertFalse(out['evidenceVerified'])

    def test_equal_bytes_do_not_validate_semantic_impact(self):
        env,mat=setup()
        body=mat['pullRequests'][0]['reviewedBodyText'].replace('deployment','unknown')
        mat['pullRequests'][0]['reviewedBodyText']=body
        pr=env['mergedPullRequests'][0]
        pr['reviewedBody']['bodySha256']=digest(body.encode())
        pr['releaseImpactSha256']=digest('releaseImpact:\n  schemaVersion: 1\n  classification: unknown'.encode())
        out=bind_claimed_material(env,mat)
        self.assertFalse(out['evidenceVerified'])
        self.assertFalse(out['admissionAllowed'])

    def test_changed_paths_must_remain_sorted(self):
        self.mismatch(lambda e,m:m['pullRequests'][0]['changedPathRecords'].reverse(),
                      'PATH_ORDER_INVALID')

    def test_internal_git_path_denied(self):
        self.mismatch(lambda e,m:m['pullRequests'][0]['changedPathRecords'][1].update(
            {'path':'.git/config'}),'PATH_ROW_INVALID')

    def test_component_target_ascii_only(self):
        self.mismatch(lambda e,m:m['componentMap'][0].update({'targetId':'шлюз'}),
                      'COMPONENT_TARGET_INVALID')

    def test_catalog_material_drift(self):
        self.mismatch(lambda e,m:m.update({'catalogText':m['catalogText']+'targets: []\n'}),
                      'CATALOG_BYTES_DIGEST_MISMATCH')

    def test_component_map_drift(self):
        self.mismatch(lambda e,m:m['componentMap'][0]['resourceIds'].append('other'),
                      'COMPONENT_MAP_DIGEST_MISMATCH')

    def test_component_map_duplicate_target(self):
        self.mismatch(lambda e,m:m['componentMap'].append(copy.deepcopy(m['componentMap'][0])),
                      'COMPONENT_MAP_DUPLICATE_OR_UNSORTED')

    def test_dependency_edges_drift(self):
        self.mismatch(lambda e,m:m['dependencyEdges'].append({'repository':'Owner/service',
                      'target':'api','sourceSha':'a'*40}),'DEPENDENCY_CONTENT_MISMATCH')

    def test_body_drift(self):
        self.mismatch(lambda e,m:m['pullRequests'][0].update(
            {'reviewedBodyText':m['pullRequests'][0]['reviewedBodyText']+'changed'}),
            'REVIEWED_BODY_DIGEST_MISMATCH')

    def test_missing_impact_block_even_with_matching_body_digest(self):
        def mutate(e,m):
            m['pullRequests'][0]['reviewedBodyText']='no impact available'
            e['mergedPullRequests'][0]['reviewedBody']['bodySha256']=digest(b'no impact available')
        self.mismatch(mutate,'IMPACT_MARKER_INVALID')

    def test_duplicate_impact_block_rejected(self):
        def mutate(e,m):
            body=m['pullRequests'][0]['reviewedBodyText']
            m['pullRequests'][0]['reviewedBodyText']=body+body
            e['mergedPullRequests'][0]['reviewedBody']['bodySha256']=digest((body+body).encode())
        self.mismatch(mutate,'IMPACT_MARKER_INVALID')

    def test_impact_yaml_changed_but_body_hash_updated(self):
        def mutate(e,m):
            body=m['pullRequests'][0]['reviewedBodyText'].replace('deployment','no-deployment')
            m['pullRequests'][0]['reviewedBodyText']=body
            e['mergedPullRequests'][0]['reviewedBody']['bodySha256']=digest(body.encode())
        self.mismatch(mutate,'IMPACT_YAML_DIGEST_MISMATCH')

    def test_path_count_drift(self):
        self.mismatch(lambda e,m:m['pullRequests'][0]['changedPathRecords'].pop(),
                      'PATH_COUNT_MISMATCH')

    def test_duplicate_paths_rejected(self):
        def mutate(e,m):
            rows=m['pullRequests'][0]['changedPathRecords']
            rows[1]['path']=rows[0]['path']
        self.mismatch(mutate,'PATH_DUPLICATE')

    def test_wrong_renamed_previous_path(self):
        self.mismatch(lambda e,m:m['pullRequests'][0]['changedPathRecords'][1].update(
            {'previousPath':None}),'PATH_RENAME_INVALID')

    def test_parent_escape_in_changed_path(self):
        self.mismatch(lambda e,m:m['pullRequests'][0]['changedPathRecords'][1].update(
            {'path':'../secrets'}),'PATH_ROW_INVALID')

    def test_windows_path_in_changed_path(self):
        self.mismatch(lambda e,m:m['pullRequests'][0]['changedPathRecords'][1].update(
            {'path':'C:\\windows\\bad'}),'PATH_ROW_INVALID')

    def test_path_digest_drift(self):
        self.mismatch(lambda e,m:m['pullRequests'][0]['changedPathRecords'][1].update(
            {'path':'src/elsewhere.py'}),'PATH_CONTENT_DIGEST_MISMATCH')

    def test_unknown_path_entry_field(self):
        self.mismatch(lambda e,m:m['pullRequests'][0]['changedPathRecords'][1].update(
            {'extra':True}),'PATH_ROW_FIELDS_INVALID')

    def test_ci_required_policy_drift(self):
        self.mismatch(lambda e,m:m['pullRequests'][0]['ciRequiredPolicy'].update(
            {'requiredChecks':['unknown']}),'CI_POLICY_CONTENT_MISMATCH')

    def test_ci_required_policy_hash_drift(self):
        self.mismatch(lambda e,m:e['mergedPullRequests'][0]['ci'].update(
            {'policySha256':'f'*64}),'CI_POLICY_CONTENT_MISMATCH')

    def test_inconsistent_merge_or_head_claim_fails_envelope_gate(self):
        self.mismatch(lambda e,m:e['mergedPullRequests'][0].update(
            {'mergedMainSha':'f'*40}),'MERGE_LINEAGE_CLAIM_INVALID')

    def test_wrong_pr_material_id(self):
        self.mismatch(lambda e,m:m['pullRequests'][0].update({'number':41}),
                      'PR_MATERIAL_ORDER_OR_ID_MISMATCH')

    def test_unknown_material_field(self):
        self.mismatch(lambda e,m:m.update({'trusted':True}),'MATERIAL_FIELDS_INVALID')

    def test_missing_pr_material(self):
        self.mismatch(lambda e,m:m.update({'pullRequests':[]}),
                      'MATERIAL_PR_COUNT_INVALID')

    def test_invalid_text_and_invalid_unicode(self):
        self.mismatch(lambda e,m:m.update({'catalogText':5}),'CATALOG_NOT_TEXT')
        self.mismatch(lambda e,m:m.update({'catalogText':'\ud800'}),'MATERIAL_NOT_CANONICAL_JSON')

    def test_absurdly_large_material_rejected(self):
        self.mismatch(lambda e,m:m.update({'catalogText':'x'*2_000_050}),
                      'MATERIAL_TOO_LARGE')


if __name__=='__main__':
    unittest.main()

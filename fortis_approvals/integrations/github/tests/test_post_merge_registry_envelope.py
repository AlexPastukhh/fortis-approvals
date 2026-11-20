"""Pure offline P5 post-merge evidence candidate; never a live broker grant."""
import copy
import unittest
from fortis_approvals.core import Denied
from fortis_approvals.integrations.github.contract import validate_github_read
from fortis_approvals.integrations.github.post_merge_registry_envelope import (
    inspect_candidate, EvidenceEnvelopeError,
)

MAIN = '1'*40
HEAD = '2'*40
MERGE = '3'*40
CAT = '4'*40
SHA256 = 'a'*64
REPO = 'AlexPastukhh/fortis-approvals'


def example():
    return {
        'schemaVersion': 1, 'repository': REPO, 'selectedMainSha': MAIN,
        'collectorClaim': {'requestId':'12345678-1234-1234-1234-123456789abc',
                           'actor':'unverified-test',
                           'capturedAt':'2026-11-20T15:00:00Z',
                           'sourceRef':'offline-claim-not-proven'},
        'catalog': {'repository':REPO, 'path':'release/targets.yaml',
                    'commitSha':CAT, 'blobSha256':SHA256,
                    'contentSha256':SHA256,'componentMapSha256':SHA256,
                    'snapshotRef':'offline-pinned-catalog-claim'},
        'mergedPullRequests': [{
            'number': 40, 'headSha': HEAD, 'mergeSha':MERGE,
            'mergedAt':'2026-11-20T13:00:00Z', 'mergedMainSha': MAIN,
            'mergeLineageRef':'offline-lineage', 'ancestryRef':'offline-ancestor-claim',
            'releaseImpactSha256':SHA256,
            'reviewedBody': {'headSha':HEAD, 'bodySha256':SHA256,
                             'captureRef':'offline-body', 'reviewCutoffRef':'offline-cutoff',
                             'reviewedAt':'2026-11-20T12:00:00Z'},
            'changedPaths': {'sha256':SHA256,'count':3,'complete':True,
                             'renamePolicy':'old-and-new','sourceRef':'offline-paths'},
            'ci': {'headSha':HEAD, 'policySha256':SHA256,
                   'requiredChecks':['source-ci'], 'complete':True,
                   'sourceRef':'offline-ci-policy',
                   'checkRuns':[{'name':'source-ci','headSha':HEAD,
                                 'runId':123,'attempt':1,'conclusion':'success',
                                 'sourceRef':'offline-check-run'}]},
        }],
        'dependencyClosure': {'edges':[], 'digest':SHA256,
                              'sourceRef':'offline-dependency-claim','complete':True},
        'coverage': {k:True for k in ('reviewedBody','mergeLineage',
                                     'changedPaths','catalog','ci','dependencies')},
    }


class EnvelopeTests(unittest.TestCase):
    def reject(self, edit, code):
        item=example();edit(item)
        with self.assertRaisesRegex(EvidenceEnvelopeError,code):
            inspect_candidate(item)

    def test_valid_structure_still_has_no_permission_or_proof(self):
        row=inspect_candidate(example())
        self.assertEqual(row['result'],'SOURCE_CANDIDATE_ONLY')
        self.assertEqual(row['claimedPrCount'],1)
        self.assertFalse(row['evidenceVerified'])
        self.assertFalse(row['admissionAllowed'])
        self.assertFalse(row['deploymentAllowed'])
        self.assertIn('PROVIDER_MERGE_ANCESTRY',row['missingTrustedAttestations'])
        self.assertEqual(row['candidateDigest'],inspect_candidate(example())['candidateDigest'])

    def test_bogus_claimed_actor_and_refs_do_not_authorize(self):
        x=example();x['collectorClaim']['actor']='owner';x['collectorClaim']['sourceRef']='signed-by-owner'
        x['mergedPullRequests'][0]['ancestryRef']='attested'
        self.assertFalse(inspect_candidate(x)['admissionAllowed'])
        self.assertFalse(inspect_candidate(x)['evidenceVerified'])

    def test_no_active_read_method_or_implicit_capability(self):
        with self.assertRaises(Denied):
            validate_github_read('get_post_merge_registry_evidence','fortis-approvals',
                                 {'number':40, 'selectedMainSha':MAIN})

    def test_unknown_fields_never_escape_into_authority(self):
        self.reject(lambda x:x.update({'admissionAllowed':True}), 'ENVELOPE_FIELDS_INVALID')
        self.reject(lambda x:x['collectorClaim'].update({'signed':True}), 'COLLECTOR_CLAIM_INVALID')
        self.reject(lambda x:x['mergedPullRequests'][0].update({'deployed':True}), 'PR_FIELDS_INVALID')

    def test_wrong_versions_and_repo(self):
        self.reject(lambda x:x.update({'schemaVersion':2}), 'SCHEMA_VERSION_UNSUPPORTED')
        self.reject(lambda x:x.update({'schemaVersion':True}), 'SCHEMA_VERSION_UNSUPPORTED')
        self.reject(lambda x:x.update({'repository':'../../secret'}), 'REPOSITORY_INVALID')
        self.reject(lambda x:x.update({'selectedMainSha':'not-sha'}), 'MAIN_SHA_INVALID')

    def test_missing_catalog_binding(self):
        self.reject(lambda x:x['catalog'].update({'repository':'Other/repo'}),'CATALOG_BINDING_INVALID')
        self.reject(lambda x:x['catalog'].update({'path':'../../secrets'}),'CATALOG_BINDING_INVALID')
        self.reject(lambda x:x['catalog'].update({'blobSha256':'not-digest'}),'CATALOG_BINDING_INVALID')

    def test_merge_sha_main_binding_and_time(self):
        self.reject(lambda x:x['mergedPullRequests'][0].update({'mergeSha':'no-sha'}), 'MERGE_LINEAGE_CLAIM_INVALID')
        self.reject(lambda x:x['mergedPullRequests'][0].update({'mergedMainSha':CAT}), 'MERGE_LINEAGE_CLAIM_INVALID')
        self.reject(lambda x:x['mergedPullRequests'][0].update({'mergedAt':'2026-11-20'}), 'MERGED_AT_INVALID')

    def test_post_merge_capture_cannot_predate_claimed_merge(self):
        self.reject(lambda x:x['collectorClaim'].update({'capturedAt':'2026-11-20T11:00:00Z'}),
                    'POST_MERGE_CAPTURE_BEFORE_MERGE')

    def test_body_capture_requires_pre_merge_cutoff(self):
        self.reject(lambda x:x['mergedPullRequests'][0]['reviewedBody'].update({'headSha':CAT}),
                    'REVIEWED_BODY_BINDING_INVALID')
        self.reject(lambda x:x['mergedPullRequests'][0]['reviewedBody'].update({'reviewedAt':'2026-11-21T12:00:00Z'}),
                    'REVIEW_CUTOFF_NOT_PROVEN')
        self.reject(lambda x:x['mergedPullRequests'][0]['reviewedBody'].update({'reviewCutoffRef':''}),
                    'REVIEWED_BODY_BINDING_INVALID')

    def test_changed_paths_require_full_rename_policy(self):
        self.reject(lambda x:x['mergedPullRequests'][0]['changedPaths'].update({'complete':False}),
                    'CHANGED_PATH_COVERAGE_INVALID')
        self.reject(lambda x:x['mergedPullRequests'][0]['changedPaths'].update({'renamePolicy':'new-only'}),
                    'CHANGED_PATH_COVERAGE_INVALID')
        self.reject(lambda x:x['mergedPullRequests'][0]['changedPaths'].update({'count':-1}),
                    'CHANGED_PATH_COVERAGE_INVALID')

    def test_ci_head_and_policy_and_required_sets(self):
        self.reject(lambda x:x['mergedPullRequests'][0]['ci'].update({'headSha':CAT}),
                    'CI_HEAD_POLICY_MISMATCH')
        self.reject(lambda x:x['mergedPullRequests'][0]['ci'].update({'policySha256':'bad'}),
                    'CI_HEAD_POLICY_MISMATCH')
        self.reject(lambda x:x['mergedPullRequests'][0]['ci'].update({'requiredChecks':[]}),
                    'CI_REQUIRED_SET_INVALID')
        self.reject(lambda x:x['mergedPullRequests'][0]['ci'].update({'requiredChecks':['another-check','source-ci']}),
                    'CI_REQUIRED_CHECK_MISSING')

    def test_ci_failed_or_stale_attempt_rejected(self):
        self.reject(lambda x:x['mergedPullRequests'][0]['ci']['checkRuns'][0].update({'conclusion':'failure'}),
                    'CI_RUN_NOT_EXACT_SUCCESS')
        self.reject(lambda x:x['mergedPullRequests'][0]['ci']['checkRuns'][0].update({'headSha':CAT}),
                    'CI_RUN_NOT_EXACT_SUCCESS')
        self.reject(lambda x:x['mergedPullRequests'][0]['ci']['checkRuns'][0].update({'runId':0}),
                    'CI_RUN_NOT_EXACT_SUCCESS')

    def test_ci_duplicate_run_attempt_is_ambiguous(self):
        def dupe(x):
            run=x['mergedPullRequests'][0]['ci']['checkRuns'][0]
            x['mergedPullRequests'][0]['ci']['checkRuns'].append(copy.deepcopy(run))
        self.reject(dupe,'CI_ATTEMPT_AMBIGUOUS')

    def test_coverage_claim_missing_is_not_success(self):
        self.reject(lambda x:x['coverage'].update({'mergeLineage':False}),'COVERAGE_CLAIM_INCOMPLETE')
        self.reject(lambda x:x['coverage'].update({'unexpected':True}),'COVERAGE_FIELDS_INVALID')

    def test_number_and_order(self):
        self.reject(lambda x:x['mergedPullRequests'][0].update({'number':0}),
                    'PR_NUMBER_DUPLICATE_OR_INVALID')
        def duplicate(x):
            x['mergedPullRequests'].append(copy.deepcopy(x['mergedPullRequests'][0]))
        self.reject(duplicate,'PR_NUMBER_DUPLICATE_OR_INVALID')
        self.reject(lambda x:x.update({'mergedPullRequests':[]}), 'MERGED_PR_LIST_INVALID')

    def test_dependency_edges_are_only_claims(self):
        x=example()
        x['dependencyClosure']['edges']=[{'repository':'Owner/service','target':'api',
                                          'sourceSha':CAT}]
        self.assertFalse(inspect_candidate(x)['evidenceVerified'])
        self.reject(lambda x:x['dependencyClosure'].update({'complete':False}),
                    'DEPENDENCY_CLOSURE_INVALID')
        self.reject(lambda x:x['dependencyClosure'].update({'digest':'invalid'}),
                    'DEPENDENCY_CLOSURE_INVALID')
        self.reject(lambda x:x['dependencyClosure']['edges'].append({'repository':'../repo',
                                                                     'target':'api','sourceSha':CAT}),
                    'DEPENDENCY_EDGE_INVALID')

    def test_bad_capture_and_opaque_datetime(self):
        self.reject(lambda x:x['collectorClaim'].update({'requestId':'bad'}),
                    'COLLECTOR_IDENTITY_INVALID')
        self.reject(lambda x:x['collectorClaim'].update({'capturedAt':'not-a-date'}),
                    'COLLECTOR_IDENTITY_INVALID')

    def test_pure_untrusted_input_does_not_change_data(self):
        source=example();before=copy.deepcopy(source)
        inspect_candidate(source)
        self.assertEqual(source,before)


if __name__ == '__main__':
    unittest.main()

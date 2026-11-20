"""P5 Git SHA-1 first-parent object consistency, never provider authenticity."""
import copy
import hashlib
import unittest

from fortis_approvals.integrations.github.post_merge_registry_envelope import EvidenceEnvelopeError
from fortis_approvals.integrations.github.post_merge_git_lineage import check_claimed_first_parent
from fortis_approvals.integrations.github.tests.test_post_merge_registry_envelope import example

_TREE = '1'*40


def commit(parents=(), *, message='Fixture only', extra=b''):
    raw = (b'tree ' + _TREE.encode() + b'\n'
           + b''.join(b'parent ' + p.encode() + b'\n' for p in parents)
           + b'author Offline Fixture <fixture@example.invalid> 1795170000 +0000\n'
           + b'committer Offline Fixture <fixture@example.invalid> 1795170000 +0000\n'
           + extra + b'\n' + message.encode() + b'\n')
    key = hashlib.sha1(b'commit ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()
    return {'sha':key,'rawHex':raw.hex()}


def fixture(two_prs=False, later_main=False):
    baseline = 'a'*40
    first_head = commit([baseline], message='PR1 HEAD')
    first_merge = commit([baseline,first_head['sha']],message='Merge #40')
    objects = [first_head, first_merge]
    target = first_merge['sha']
    env = example()
    first_pr = env['mergedPullRequests'][0]
    first_pr['headSha'] = first_head['sha']
    first_pr['mergeSha'] = first_merge['sha']
    first_pr['ci']['headSha']=first_head['sha']
    first_pr['ci']['checkRuns'][0]['headSha']=first_head['sha']
    first_pr['reviewedBody']['headSha']=first_head['sha']
    if two_prs:
        second_head = commit([first_merge['sha']],message='PR2 HEAD')
        second_merge = commit([first_merge['sha'],second_head['sha']],message='Merge #41')
        second_pr = copy.deepcopy(first_pr)
        second_pr['number']=41
        second_pr['headSha']=second_head['sha']
        second_pr['mergeSha']=second_merge['sha']
        second_pr['ci']['headSha']=second_head['sha']
        second_pr['ci']['checkRuns'][0]['headSha']=second_head['sha']
        second_pr['reviewedBody']['headSha']=second_head['sha']
        env['mergedPullRequests'].append(second_pr)
        objects.extend([second_head,second_merge])
        target = second_merge['sha']
    if later_main:
        later = commit([target],message='Post-merge docs commit')
        objects.append(later)
        target = later['sha']
    env['selectedMainSha'] = target
    for pr in env['mergedPullRequests']:
        pr['mergedMainSha'] = target
    return env, objects


class OfflineGitLineageTests(unittest.TestCase):
    def rejects(self, edit, reason, *, two=False, later=False):
        env,objects=fixture(two_prs=two,later_main=later)
        edit(env,objects)
        with self.assertRaisesRegex(EvidenceEnvelopeError,reason):
            check_claimed_first_parent(env,objects)

    def test_valid_one_merge_never_authorized(self):
        env,objects=fixture()
        result=check_claimed_first_parent(env,objects)
        self.assertEqual(result['result'],'SOURCE_GIT_DAG_MATCH_UNTRUSTED')
        self.assertEqual(result['observedMergeShasNewestFirst'],[env['mergedPullRequests'][0]['mergeSha']])
        self.assertEqual(result['firstParentDepth'],1)
        self.assertFalse(result['evidenceVerified'])
        self.assertFalse(result['admissionAllowed'])
        self.assertFalse(result['deploymentAllowed'])
        self.assertIn('AUTHENTICATED_PROVIDER_REF_AND_COMPLETE_OBJECT_READ',result['missingTrustedProofs'])

    def test_two_prs_first_parent_link_and_newer_commit(self):
        env,objects=fixture(two_prs=True,later_main=True)
        result=check_claimed_first_parent(env,objects)
        self.assertEqual(result['firstParentDepth'],3)
        self.assertEqual(result['observedMergeShasNewestFirst'],[
            env['mergedPullRequests'][1]['mergeSha'],env['mergedPullRequests'][0]['mergeSha']])
        self.assertFalse(result['admissionAllowed'])

    def test_fixture_order_independent_digest(self):
        env,objects=fixture(two_prs=True,later_main=True)
        alt=copy.deepcopy(objects)
        alt.reverse()
        self.assertEqual(check_claimed_first_parent(env,objects),check_claimed_first_parent(env,alt))

    def test_does_not_modify_inputs(self):
        env,objects=fixture()
        original=copy.deepcopy((env,objects))
        check_claimed_first_parent(env,objects)
        self.assertEqual((env,objects),original)

    def test_wrong_object_hash_stops(self):
        self.rejects(lambda e,o:o[0].update({'sha':'f'*40}),'COMMIT_OBJECT_SHA_MISMATCH')

    def test_modified_object_bytes_without_hash_update_stops(self):
        self.rejects(lambda e,o:o[0].update({'rawHex':o[0]['rawHex'][:-2]+'78'}),
                     'COMMIT_OBJECT_SHA_MISMATCH')

    def test_uppercase_object_digest_is_rejected(self):
        self.rejects(lambda e,o:o[0].update({'sha':o[0]['sha'].upper()}),
                     'COMMIT_OBJECT_SHA_INVALID')

    def test_bad_hex_and_invalid_object_fields(self):
        self.rejects(lambda e,o:o[0].update({'rawHex':'gh'}),'COMMIT_OBJECT_HEX_INVALID')
        self.rejects(lambda e,o:o[0].update({'rawHex':'abc'}),'COMMIT_OBJECT_HEX_INVALID')
        self.rejects(lambda e,o:o[0].update({'extra':'untrusted'}),'COMMIT_OBJECT_FIELDS_INVALID')

    def test_unknown_source_main_fails(self):
        self.rejects(lambda e,o:e.update({'selectedMainSha':'f'*40}) or
                     e['mergedPullRequests'][0].update({'mergedMainSha':'f'*40}),
                     'FIRST_PARENT_PROOF_GAP')

    def test_broken_first_parent_path_fails(self):
        self.rejects(lambda e,o:o.pop(-1),'FIRST_PARENT_PROOF_GAP',later=True)

    def test_missing_claimed_merge_object_fails(self):
        self.rejects(lambda e,o:o.pop(-1),'PR_MERGE_OBJECT_MISSING')

    def test_missing_pr_head_object_fails(self):
        self.rejects(lambda e,o:o.pop(0),'PR_HEAD_OBJECT_MISSING')

    def test_merge_claim_wrong_head_fails(self):
        def update(e,o):
            claimed=e['mergedPullRequests'][0]
            claimed['headSha']='f'*40
            claimed['ci']['headSha']='f'*40
            claimed['ci']['checkRuns'][0]['headSha']='f'*40
            claimed['reviewedBody']['headSha']='f'*40
        self.rejects(update,'PR_HEAD_OBJECT_MISSING')

    def test_wrong_second_parent_must_stop(self):
        def change(e,o):
            target=o[1]
            replacement=commit(['a'*40,'b'*40],message='Merge #40')
            o[1]=replacement
            e['mergedPullRequests'][0]['mergeSha']=replacement['sha']
            e['selectedMainSha']=replacement['sha']
            e['mergedPullRequests'][0]['mergedMainSha']=replacement['sha']
        self.rejects(change,'PR_MERGE_METHOD_OR_HEAD_MISMATCH')

    def test_one_parent_squash_must_stop(self):
        def change(e,o):
            replacement=commit(['a'*40],message='Squash style')
            o[1]=replacement
            e['mergedPullRequests'][0]['mergeSha']=replacement['sha']
            e['selectedMainSha']=replacement['sha']
            e['mergedPullRequests'][0]['mergedMainSha']=replacement['sha']
        self.rejects(change,'PR_MERGE_METHOD_OR_HEAD_MISMATCH')

    def test_octopus_merge_must_stop(self):
        def change(e,o):
            replacement=commit(['a'*40,o[0]['sha'],'b'*40],message='Octopus')
            o[1]=replacement
            e['mergedPullRequests'][0]['mergeSha']=replacement['sha']
            e['selectedMainSha']=replacement['sha']
            e['mergedPullRequests'][0]['mergedMainSha']=replacement['sha']
        self.rejects(change,'PR_MERGE_METHOD_OR_HEAD_MISMATCH')

    def test_fake_first_parent_without_claimed_older_merge_fails(self):
        def change(e,o):
            newer=commit(['f'*40,o[2]['sha']],message='Misleading newer merge')
            o[-1]=newer
            e['mergedPullRequests'][1]['mergeSha']=newer['sha']
            e['selectedMainSha']=newer['sha']
            for pr in e['mergedPullRequests']:
                pr['mergedMainSha']=newer['sha']
        self.rejects(change,'FIRST_PARENT_PROOF_GAP',two=True)

    def test_duplicate_object_fails(self):
        self.rejects(lambda e,o:o.append(copy.deepcopy(o[0])),'COMMIT_OBJECT_DUPLICATE')

    def test_extra_unused_object_fails(self):
        self.rejects(lambda e,o:o.append(commit(['b'*40],message='Unrelated')),
                     'UNUSED_COMMIT_PROOF_OBJECT')

    def test_duplicate_claimed_merge_sha_denied(self):
        def change(e,o):
            first=e['mergedPullRequests'][0]
            second=e['mergedPullRequests'][1]
            second['mergeSha']=first['mergeSha']
        self.rejects(change,'PR_MERGE_SHA_DUPLICATE',two=True)

    def test_wrong_git_object_header_stops(self):
        def change(e,o):
            malformed = b'notree '+('1'*40).encode()+b'\nauthor Someone\ncommitter Someone\n\nmessage\n'
            sha=hashlib.sha1(b'commit '+str(len(malformed)).encode()+b'\0'+malformed).hexdigest()
            o[0]={'sha':sha,'rawHex':malformed.hex()}
        self.rejects(change,'COMMIT_TREE_INVALID')

    def test_missing_committer_stops(self):
        def change(e,o):
            malformed = b'tree '+_TREE.encode()+b'\nauthor Someone\n\nmessage\n'
            sha=hashlib.sha1(b'commit '+str(len(malformed)).encode()+b'\0'+malformed).hexdigest()
            o[0]={'sha':sha,'rawHex':malformed.hex()}
        self.rejects(change,'COMMIT_IDENTITY_FIELDS_MISSING')

    def test_gpgsig_continuation_is_parsed(self):
        env,objects=fixture()
        # Extra multi-line header is allowed when commit hash and branch bindings match.
        older=objects[0]
        replacement=commit(['a'*40],message='PR1 HEAD',
            extra=b'gpgsig -----BEGIN PGP SIGNATURE-----\n data\n -----END PGP SIGNATURE-----\n')
        merge=commit(['a'*40,replacement['sha']],message='Merge #40')
        objects=[replacement,merge]
        pr=env['mergedPullRequests'][0]
        pr['headSha']=replacement['sha'];pr['ci']['headSha']=replacement['sha']
        pr['ci']['checkRuns'][0]['headSha']=replacement['sha']
        pr['reviewedBody']['headSha']=replacement['sha']
        pr['mergeSha']=merge['sha'];pr['mergedMainSha']=merge['sha']
        env['selectedMainSha']=merge['sha']
        self.assertFalse(check_claimed_first_parent(env,objects)['evidenceVerified'])

    def test_oversized_object_fails(self):
        self.rejects(lambda e,o:o[0].update({'rawHex':'ff'*65_000}),
                     'COMMIT_OBJECT_HEX_INVALID')

    def test_unrecognized_payload_shape_fails(self):
        with self.assertRaisesRegex(EvidenceEnvelopeError,'COMMIT_PROOF_OBJECT_COUNT_INVALID'):
            check_claimed_first_parent(*fixture()[0:1], [])


if __name__=='__main__':
    unittest.main()

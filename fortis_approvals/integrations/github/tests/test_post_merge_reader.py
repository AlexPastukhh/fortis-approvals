"""No live provider calls: exact routes, fail-closed bounded observations."""
import base64
import copy
import hashlib
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from fortis_approvals.core import Denied, Stale
from fortis_approvals.integrations.github.contract import validate_github_read
from fortis_approvals.integrations.github.gateway.adapter import GitHubAdapter
from fortis_approvals.integrations.github.gateway.transport import GitHubHTTPTransport, GitHubTransportError
from fortis_approvals.integrations.github.gateway.post_merge_reader import observe_post_merge

MAIN, MERGE, HEAD, BASE, TREE = (c*40 for c in 'abcde')
REPO = 'fortis-approvals'
PREFIX = '/repos/Alex/' + REPO + '/'
CATALOG = b'schemaVersion: 1\nrepository: fortis-approvals\n'


class FakeProvider:
    def __init__(self):
        self.calls = []
        self.branch = {'name':'main','commit':{'sha':MAIN},'protected':True}
        self.pr = {'number':42,'state':'closed','merged':True,'draft':False,
                   'merged_at':'2026-11-21T01:00:00Z','merge_commit_sha':MERGE,
                   'head':{'sha':HEAD,'ref':'task/example','repo':{'full_name':'Alex/'+REPO}},
                   'base':{'sha':BASE,'ref':'main','repo':{'full_name':'Alex/'+REPO}},
                   'body':'MUTABLE BODY MUST NOT BE RETAINED'}
        self.commits = {sha:{'sha':sha,'tree':{'sha':TREE},'parents':[{'sha':p} for p in parents]}
                        for sha,parents in ((MAIN,[MERGE]),(MERGE,[BASE,HEAD]),(HEAD,[BASE]))}
        self.catalog = {'type':'file','path':'release/targets.yaml','encoding':'base64',
                        'size':len(CATALOG),'content':base64.b64encode(CATALOG).decode(),
                        'sha':hashlib.sha1(b'blob '+str(len(CATALOG)).encode()+b'\0'+CATALOG).hexdigest()}
        self.change_pr = self.change_main = False
        self.raise_provider = None

    def request(self, method, path, *, params=None, body=None, expected_statuses=(200,), allow_not_found=False):
        assert method == 'GET' and body is None and path.startswith(PREFIX)
        assert GitHubHTTPTransport._route_allowed(method,path)
        self.calls.append((method,path,copy.deepcopy(params)))
        suffix = path[len(PREFIX):]
        if self.raise_provider == suffix:
            raise GitHubTransportError('GITHUB_HTTP_403')
        if suffix == 'branches/main':
            result = copy.deepcopy(self.branch)
            if self.change_main and sum(p.endswith('/branches/main') for _,p,_ in self.calls)>1:
                result['commit']['sha']=BASE
            return result
        if suffix == 'pulls/42':
            result = copy.deepcopy(self.pr)
            if self.change_pr and sum(p.endswith('/pulls/42') for _,p,_ in self.calls)>1:
                result['merged_at']='2026-11-21T02:00:00Z'
            return result
        if suffix.startswith('git/commits/'):
            return copy.deepcopy(self.commits.get(suffix.split('/')[-1]))
        if suffix == 'contents/release/targets.yaml':
            assert params == {'ref':MAIN}
            return copy.deepcopy(self.catalog)
        raise AssertionError(suffix)


class ProviderReaderTests(unittest.TestCase):
    def setUp(self):
        root = tempfile.TemporaryDirectory()
        self.addCleanup(root.cleanup)
        self.provider=FakeProvider()
        self.adapter=GitHubAdapter(self.provider,owner='Alex',repositories=[REPO],receipt_store=Path(root.name)/'receipts.sqlite')

    def observe(self, **kw):
        args=dict(number=42,expected_head_sha=HEAD,expected_merge_sha=MERGE,selected_main_sha=MAIN)
        args.update(kw)
        return observe_post_merge(self.adapter,**args)

    def test_exact_routes_no_authority_or_body(self):
        r=self.observe()
        self.assertEqual(r['result'],'PARTIAL_PROVIDER_OBSERVATION')
        for flag in ('evidenceVerified','admissionAllowed','deploymentAllowed'):
            self.assertIs(r[flag],False)
        self.assertEqual(r['observation']['catalog']['contentSha256'],hashlib.sha256(CATALOG).hexdigest())
        self.assertEqual([x['sha'] for x in r['observation']['firstParent']],[MAIN,MERGE])
        self.assertNotIn('MUTABLE BODY',repr(r));self.assertNotIn('schemaVersion:',repr(r))
        self.assertIn('OWNER_REVIEW_CUTOFF',r['missingProofs'])
        self.assertEqual([p[len(PREFIX):] for _,p,_ in self.provider.calls],[
            'branches/main','pulls/42','git/commits/'+MAIN,'git/commits/'+MERGE,
            'git/commits/'+HEAD,'contents/release/targets.yaml','pulls/42','branches/main'])
        self.assertEqual(r,self.observe())

    def test_no_registered_read(self):
        with self.assertRaises(Denied):
            validate_github_read('get_post_merge_registry_evidence',REPO,{'number':42})

    def test_invalid_number_before_reads(self):
        for value in (True,-1,0,'42',1_000_001):
            with self.subTest(value=value),self.assertRaisesRegex(Denied,'P5_PR_NUMBER_INVALID'):
                self.observe(number=value)
        self.assertFalse(self.provider.calls)

    def test_head_equals_merge_rejected_without_reads(self):
        with self.assertRaisesRegex(Denied,'P5_HEAD_EQUALS_MERGE'):self.observe(expected_merge_sha=HEAD)
        self.assertFalse(self.provider.calls)

    def test_self_parent_rejected(self):
        self.provider.commits[MERGE]['parents']=[{'sha':MERGE},{'sha':HEAD}]
        with self.assertRaisesRegex(Denied,'P5_COMMIT_PROJECTION_INVALID'):self.observe()

    def test_invalid_sha_before_reads(self):
        with self.assertRaises(Denied):self.observe(selected_main_sha='main')
        self.assertFalse(self.provider.calls)

    def test_repository_allowlist(self):
        self.adapter.repositories=frozenset({'unrelated'})
        with self.assertRaises(Denied):self.observe()
        self.assertFalse(self.provider.calls)

    def test_wrong_draft_open_or_unmerged(self):
        for key,value in [('number',True),('number',41),('state','open'),('merged',False),('draft',True)]:
            with self.subTest(key=key,value=value),patch.dict(self.provider.pr,{key:value}),self.assertRaisesRegex(Denied,'P5_PR_NOT_MERGED'):
                self.observe()

    def test_fork_rejected(self):
        self.provider.pr['head']['repo']['full_name']='Other/'+REPO
        with self.assertRaisesRegex(Denied,'P5_PR_PROVENANCE_INVALID'):self.observe()

    def test_time_invalid(self):
        self.provider.pr['merged_at']='not a timestamp'
        with self.assertRaisesRegex(Denied,'P5_MERGE_TIME_INVALID'):self.observe()

    def test_main_drift(self):
        with self.assertRaisesRegex(Stale,'P5_SELECTED_MAIN_CHANGED'):self.observe(selected_main_sha=BASE)

    def test_expected_head_or_merge(self):
        for kw in ({'expected_head_sha':BASE},{'expected_merge_sha':BASE}):
            with self.subTest(kw=kw),self.assertRaisesRegex(Stale,'P5_PR_HEAD_OR_MERGE_CHANGED'):self.observe(**kw)

    def test_bad_merge_parents(self):
        for parents in ([{'sha':BASE}],[{'sha':BASE},{'sha':TREE}]):
            with self.subTest(parents=parents),patch.dict(self.provider.commits[MERGE],{'parents':parents}),self.assertRaisesRegex(Denied,'P5_MERGE_METHOD_OR_HEAD_MISMATCH'):self.observe()

    def test_commit_missing_or_wrong(self):
        for malformed in (None,{'sha':BASE,'parents':[],'tree':{'sha':TREE}}):
            with self.subTest(malformed=malformed),patch.dict(self.provider.commits,{MAIN:malformed}),self.assertRaisesRegex(Denied,'P5_COMMIT_PROJECTION_INVALID'):self.observe()

    def test_missing_lineage(self):
        self.provider.commits[MAIN]['parents']=[]
        with self.assertRaisesRegex(Denied,'P5_MERGE_NOT_IN_FIRST_PARENT'):self.observe()

    def test_bound(self):
        with patch('fortis_approvals.integrations.github.gateway.post_merge_reader.MAX_FIRST_PARENT_NODES',1),self.assertRaisesRegex(Denied,'P5_FIRST_PARENT_BOUND_EXCEEDED'):self.observe()

    def test_wrong_catalog_path_or_kind(self):
        for fields in ({'path':'other.yaml'},{'type':'dir'},{'encoding':'none'},{'size':True}):
            with self.subTest(fields=fields),patch.dict(self.provider.catalog,fields),self.assertRaisesRegex(Denied,'P5_CATALOG_PROJECTION_INVALID'):self.observe()

    def test_catalog_encoding_size(self):
        with patch.dict(self.provider.catalog,{'content':'@@@'}),self.assertRaisesRegex(Denied,'P5_CATALOG_ENCODING_INVALID'):self.observe()
        with patch.dict(self.provider.catalog,{'size':len(CATALOG)+1}),self.assertRaisesRegex(Denied,'P5_CATALOG_SIZE_MISMATCH'):self.observe()

    def test_catalog_blob(self):
        self.provider.catalog['sha']=BASE
        with self.assertRaisesRegex(Denied,'P5_CATALOG_BLOB_MISMATCH'):self.observe()

    def test_races(self):
        self.provider.change_pr=True
        with self.assertRaisesRegex(Stale,'P5_PR_OBSERVATION_CHANGED'):self.observe()
        self.provider.change_pr=False;self.provider.change_main=True;self.provider.calls=[]
        with self.assertRaisesRegex(Stale,'P5_SELECTED_MAIN_CHANGED'):self.observe()

    def test_403_is_not_empty_success(self):
        self.provider.raise_provider='pulls/42'
        with self.assertRaisesRegex(GitHubTransportError,'GITHUB_HTTP_403'):self.observe()
        self.assertEqual(len(self.provider.calls),2)


if __name__=='__main__':unittest.main()

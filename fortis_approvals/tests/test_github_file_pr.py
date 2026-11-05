"""M2 through real TLS/WebAuthn, bounded readback and unchanged Core semantics."""
import base64
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from urllib.parse import unquote
import uuid

from fortis_approvals.core import Denied
from fortis_approvals.integrations.github.pilot import GitHubPilotConfig, GitHubPilotAdapter, config_from_environment
from fortis_approvals.integrations.github.repo_client import file_pr_scenario as scenario
import test_github_pilot as m1
FakeGitHub, SHA = m1.FakeGitHub, m1.SHA

BRANCH = 'fortis-e2e/11111111-1111-4111-8111-111111111111-approve'
CONFIG = GitHubPilotConfig('PilotOwner', 'sandbox', file_pr_branch=BRANCH)
NEW_SHA = 'b' * 40


class FileGitHub(FakeGitHub):
    def __init__(self):
        super().__init__()
        self.branches[BRANCH] = SHA
        self.blobs = {}; self.contents = {}; self.pulls = []; self.files_writes = 0; self.pr_writes = 0
        self.lose_operation = None

    def request(self, method, path, *, params=None, body=None, expected_statuses=(200,), allow_not_found=False):
        base = '/repos/PilotOwner/sandbox'
        kwargs = dict(params=params, body=body, expected_statuses=expected_statuses, allow_not_found=allow_not_found)
        if method == 'GET' and path.startswith(base + '/contents/'):
            name = unquote(path.split('/contents/', 1)[1]); ref = params['ref']
            ref = self.branches.get(ref, ref)
            if (ref, name) not in self.contents: return {'_httpStatus': 404}
            data = self.contents[ref, name]
            return dict(type='file', path=name, sha=hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest(),
                size=len(data), encoding='base64', content=base64.b64encode(data).decode())
        if method == 'GET' and path == base + '/git/commits/' + SHA:
            return dict(sha=SHA, tree={'sha':'c' * 40})
        if method == 'POST' and path == base + '/git/blobs':
            data = body['content'].encode('utf-8')
            ident = hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()
            self.blobs[ident] = data
            return {'sha': ident}
        if method == 'POST' and path == base + '/git/trees':
            self.tree = body['tree']; return {'sha':'d' * 40}
        if method == 'POST' and path == base + '/git/commits':
            assert body['parents'] == [SHA]
            for row in self.tree: self.contents[NEW_SHA,row['path']] = self.blobs[row['sha']]
            return {'sha':NEW_SHA}
        if method == 'PATCH' and path.startswith(base + '/git/refs/heads/'):
            name = unquote(path.split('/git/refs/heads/',1)[1]); assert body['force'] is False
            self.branches[name] = body['sha']; self.files_writes += 1
            if self.lose_operation == 'push': raise TimeoutError('OFFLINE_LOST_REF_REPLY')
            return {'object':{'sha':body['sha']}}
        if path == base + '/pulls' and method == 'POST':
            row = dict(number=7,title=body['title'],state='open',draft=body['draft'],merged=False,
                head=dict(ref=body['head'],sha=self.branches[body['head']]),
                base=dict(ref=body['base'],sha=self.branches[body['base']]),html_url='https://github.com/PilotOwner/sandbox/pull/7')
            self.pulls.append(row); self.pr_writes += 1
            if self.lose_operation == 'pr': raise TimeoutError('OFFLINE_LOST_PR_REPLY')
            return row
        if path == base + '/pulls' and method == 'GET':
            rows = self.pulls
            if params.get('head'): rows = [x for x in rows if params['head'] == 'PilotOwner:' + x['head']['ref']]
            start = (params['page']-1)*params['per_page']; return rows[start:start+params['per_page']]
        if path == base + '/pulls/7' and method == 'GET': return self.pulls[0]
        return super().request(method,path,**kwargs)


class ScopeTests(unittest.TestCase):
    def test_file_pr_requires_explicit_config_and_exact_uuid_branch(self):
        for value in ('main','fortis-e2e/test-approve','other/11111111-1111-4111-8111-111111111111-approve',None):
            with self.assertRaises(ValueError): GitHubPilotConfig('PilotOwner','sandbox',file_pr_branch=value)
        with self.assertRaises(ValueError): config_from_environment({'FORTIS_GITHUB_FILE_PR_BRANCH':BRANCH})
        self.assertEqual(CONFIG.file_path,'docs/fortis-e2e/11111111-1111-4111-8111-111111111111.txt')

    def test_out_of_scope_file_pr_and_merge_denied_before_provider(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)/'private';root.mkdir(mode=0o700);remote=FileGitHub()
            adapter=GitHubPilotAdapter(remote,config=CONFIG,receipt_store=root/'receipts.sqlite')
            state=scenario.new_run('PilotOwner','sandbox',BRANCH,SHA)
            for operation,params in [('push_files',{**scenario.params(state,'push'),'branch':'main'}),
                    ('push_files',{**scenario.params(state,'push'),'files':[dict(path='other.txt',content='x')]}),
                    ('create_pull_request',{**scenario.params(state,'pr'),'draft':False}),
                    ('create_pull_request',{**scenario.params(state,'pr'),'base':'other'}),('merge_pull_request',{})]:
                with self.assertRaises(Denied): adapter.prepare(dict(service='github',operation=operation,target='sandbox',params=params))
            with self.assertRaises(Denied): adapter.read(dict(service='github',operation='get_file',target='sandbox',params=dict(path='other.txt',ref=SHA)))
            self.assertEqual(remote.calls,[]);self.assertEqual(remote.files_writes,0);self.assertEqual(remote.pr_writes,0)

    def test_file_readback_checks_blob_digest_and_does_not_expose_content(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)/'private';root.mkdir(mode=0o700);remote=FileGitHub()
            adapter=GitHubPilotAdapter(remote,config=CONFIG,receipt_store=root/'receipts.sqlite')
            query=dict(service='github',operation='get_file',target='sandbox',params=dict(path=CONFIG.file_path,ref=NEW_SHA))
            self.assertFalse(adapter.read(query)['file']['exists'])
            remote.contents[NEW_SHA,CONFIG.file_path]=b'known content'
            result=adapter.read(query)['file']
            self.assertEqual(result['contentSha256'],hashlib.sha256(b'known content').hexdigest())
            self.assertNotIn('known content',json.dumps(result))
            original=remote.request
            def corrupt(*a,**k):
                row=original(*a,**k);row['sha']='e'*40;return row
            remote.request=corrupt
            with self.assertRaisesRegex(Denied,'HASH_MISMATCH'):adapter.read(query)


class FilePRTLSWebAuthnTests(m1.PilotTLSWebAuthnTests):
    def setUp(self):
        with patch('test_github_pilot.FakeGitHub',FileGitHub),patch('test_github_pilot.CONFIG',CONFIG):
            super().setUp()

    def progress(self,state):
        return scenario.advance(state,self.client)['state']

    def test_file_and_draft_pr_live_client_chain_and_durable_receipts(self):
        state=scenario.new_run('PilotOwner','sandbox',BRANCH,SHA)
        state=self.progress(state);state=self.progress(state)
        self.login()
        self.assertEqual(self.decide(state['pushRequestId'],'approve',uv=False)[0],403)
        self.assertEqual(self.remote.files_writes,0)
        code,row,_=self.decide(state['pushRequestId'],'approve')
        self.assertEqual((code,row['state']),(200,'EXECUTED'))
        state=self.progress(state);self.assertEqual(state['commitSha'],NEW_SHA)
        state=self.progress(state)
        code,row,_=self.decide(state['prRequestId'],'approve')
        self.assertEqual((code,row['state']),(200,'EXECUTED'))
        state=self.progress(state);self.assertEqual(state['phase'],'DONE')
        self.assertEqual((self.remote.files_writes,self.remote.pr_writes),(1,1))
        from test_github_pilot_package import HELPERS
        result=HELPERS.verify_file_pr_receipts(state,self.root/'private')
        self.assertTrue(result['receiptsVerified']);self.assertTrue(result['ownerDecisionsVerified'])
        self.assertEqual(self.remote.branches['main'],SHA)

    def test_rejected_file_never_writes_or_opens_pr(self):
        state=scenario.new_run('PilotOwner','sandbox',BRANCH,SHA)
        state=self.progress(state);state=self.progress(state);self.login()
        self.assertEqual(self.decide(state['pushRequestId'],'reject')[1]['state'],'REJECTED')
        with self.assertRaisesRegex(Denied,'DECISION_STOP_REJECTED'):self.progress(state)
        self.assertEqual((self.remote.files_writes,self.remote.pr_writes),(0,0))

    def test_lost_ref_response_is_uncertain_and_not_reapplied(self):
        state=scenario.new_run('PilotOwner','sandbox',BRANCH,SHA)
        state=self.progress(state);state=self.progress(state);self.login();self.remote.lose_operation='push'
        self.assertEqual(self.decide(state['pushRequestId'],'approve')[1]['state'],'UNCERTAIN')
        with self.assertRaisesRegex(Denied,'UNCERTAIN'):self.progress(state)
        self.assertEqual(scenario.submit(state,self.client,'push')['state'],'UNCERTAIN')
        self.assertEqual(self.remote.files_writes,1)

    def test_lost_pr_response_is_uncertain_and_not_reapplied(self):
        state=scenario.new_run('PilotOwner','sandbox',BRANCH,SHA)
        state=self.progress(state);state=self.progress(state);self.login()
        self.assertEqual(self.decide(state['pushRequestId'],'approve')[1]['state'],'EXECUTED')
        state=self.progress(state);state=self.progress(state);self.remote.lose_operation='pr'
        self.assertEqual(self.decide(state['prRequestId'],'approve')[1]['state'],'UNCERTAIN')
        with self.assertRaisesRegex(Denied,'UNCERTAIN'):self.progress(state)
        self.assertEqual(scenario.submit(state,self.client,'pr')['state'],'UNCERTAIN')
        self.assertEqual(self.remote.pr_writes,1)

    def test_lost_proposal_reply_resumes_with_one_request_id(self):
        state=self.progress(scenario.new_run('PilotOwner','sandbox',BRANCH,SHA))
        original=self.client.action
        def lost(*args,**kwargs):
            original(*args,**kwargs)
            raise TimeoutError('OFFLINE_LOST_PROPOSAL_REPLY')
        with patch.object(self.client,'action',side_effect=lost):
            with self.assertRaises(TimeoutError):self.progress(state)
        repeated=self.progress(state)
        self.assertEqual(repeated['pushRequestId'],state['pushRequestId'])
        self.assertEqual(self.client.status(state['pushRequestId'])['state'],'PENDING')
        self.assertEqual(self.remote.files_writes,0)

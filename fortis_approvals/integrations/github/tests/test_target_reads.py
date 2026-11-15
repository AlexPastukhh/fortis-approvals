"""Addressed target reads stay closed and do not turn masked 404 into absence."""
import copy
from pathlib import Path
import tempfile
import unittest

from fortis_approvals.core import Denied
from fortis_approvals.integrations.github.contract import (
    validate_github_read, validate_github_read_projection)
from fortis_approvals.integrations.github.gateway.adapter import GitHubAdapter
from fortis_approvals.integrations.github.gateway.transport import (
    GitHubHTTPTransport, GitHubTransportError)
from fortis_approvals.integrations.github.repo_client.client import GitHubClient

SHA='a'*40
BASE='/repos/Owner/sandbox'


def pull(number=1):
    return dict(number=number,title='Review',state='closed',draft=False,merged=True,
        head=dict(ref='task/agent',sha=SHA,repo={'full_name':'Owner/sandbox'}),
        base=dict(ref='main',sha=SHA,repo={'full_name':'Owner/sandbox'}),
        html_url='https://github.com/Owner/sandbox/pull/'+str(number))


class Transport:
    def __init__(self):
        self.calls=[];self.branch=None;self.rows=[];self.access=True
    def request(self,method,path,**kw):
        self.calls.append((method,path,kw))
        assert method=='GET' and GitHubHTTPTransport._route_allowed(method,path)
        if path==BASE:
            if not self.access:raise GitHubTransportError('GITHUB_HTTP_404')
            return {'full_name':'Owner/sandbox'}
        if path.startswith(BASE+'/branches/'):
            return copy.deepcopy(self.branch) if self.branch else {'_httpStatus':404}
        assert path==BASE+'/pulls'
        return copy.deepcopy(self.rows)


class TargetReadTests(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory();self.addCleanup(tmp.cleanup)
        self.transport=Transport()
        self.adapter=GitHubAdapter(self.transport,owner='Owner',repositories=['sandbox'],
            receipt_store=Path(tmp.name)/'receipts.sqlite')
    def read(self,op,params):
        return self.adapter.read(dict(service='github',operation=op,target='sandbox',params=params))
    def test_get_branch_escapes_ref_and_verifies_identity(self):
        self.transport.branch=dict(name='task/agent',commit={'sha':SHA},protected=False)
        result=self.read('get_branch',{'branch':'task/agent'})
        self.assertEqual(result['branch']['sha'],SHA)
        self.assertEqual(self.transport.calls[0][1],BASE+'/branches/task%2Fagent')
        self.transport.branch['name']='other'
        with self.assertRaisesRegex(Denied,'GITHUB_BRANCH_RESPONSE_INVALID'):
            self.read('get_branch',{'branch':'task/agent'})
    def test_branch_404_requires_repository_access(self):
        self.assertFalse(self.read('get_branch',{'branch':'task/agent'})['found'])
        self.assertEqual([c[1] for c in self.transport.calls],
                         [BASE+'/branches/task%2Fagent',BASE])
        self.transport.access=False
        with self.assertRaises(GitHubTransportError):
            self.read('get_branch',{'branch':'task/agent'})
    def test_search_includes_closed_and_merged_and_is_pair_scoped(self):
        self.transport.rows=[pull()]
        result=self.read('find_pull_requests',dict(head='task/agent',base='main',page=1,perPage=50))
        self.assertTrue(result['items'][0]['merged'])
        self.assertFalse(result['hasNextPage'])
        self.assertEqual(self.transport.calls[0][2]['params'],
            dict(head='Owner:task/agent',base='main',state='all',page=1,per_page=50))
    def test_search_never_filters_away_wrong_repository_or_pair(self):
        for field,value in [('ref','other'),('repo',{'full_name':'Someone/sandbox'})]:
            self.transport.rows=[pull()]
            self.transport.rows[0]['head'][field]=value
            with self.assertRaisesRegex(Denied,'GITHUB_PR_SEARCH_IDENTITY_INVALID'):
                self.read('find_pull_requests',dict(head='task/agent',base='main',page=1,perPage=50))
    def test_full_page_requires_more_and_projection_cannot_claim_complete(self):
        self.transport.rows=[pull(i+1) for i in range(50)]
        result=self.read('find_pull_requests',dict(head='task/agent',base='main',page=1,perPage=50))
        self.assertTrue(result['hasNextPage'])
        result['hasNextPage']=False
        with self.assertRaises(Denied):
            validate_github_read_projection('find_pull_requests',result)
    def test_closed_request_schema_rejects_url_owner_and_oversized_page(self):
        for op,params in [
            ('get_branch',dict(branch='../main')),
            ('get_branch',dict(branch='main',url='https://elsewhere')),
            ('find_pull_requests',dict(head='Owner:task/agent',base='main',page=1,perPage=50)),
            ('find_pull_requests',dict(head='task/agent',base='main',page=1,perPage=51))]:
            with self.assertRaises(Denied):validate_github_read(op,'sandbox',params)
    def test_transport_allows_get_branch_but_no_new_write_route(self):
        self.assertTrue(GitHubHTTPTransport._route_allowed('GET',BASE+'/branches/task%2Fagent'))
        self.assertFalse(GitHubHTTPTransport._route_allowed('POST',BASE+'/branches/task%2Fagent'))


if __name__=='__main__':unittest.main()

"""Actual native GitHubAdapter read calls over an offline REST fixture."""
import base64
import copy
import hashlib
import unittest

from fortis_approvals.core import Denied, Stale
from fortis_approvals.extensions.native_merge_discovery import NativeMergeDiscovery
from fortis_approvals.integrations.github.gateway.adapter import GitHubAdapter
from fortis_approvals.tests import test_registry_source_lineage as fixture


class NativeDiscoveryTests(fixture.LineageFixture,unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.domain.register_source(self.transition())
        self.p=self.merge()['proposal']
        self.repo=self.p['repository'];owner,repo=self.repo.split('/')
        self.base='/repos/'+self.repo
        self.pr={'number':self.p['number'],'title':'Owner changes','state':'open',
                 'draft':False,'merged':False,'merged_at':None,
                 'head':{'ref':'owner-fix','sha':self.p['headSha'],'repo':{'full_name':self.repo}},
                 'base':{'ref':'main','sha':self.p['baseSha'],'repo':{'full_name':self.repo}},
                 'html_url':'https://github.com/'+self.repo+'/pull/'+str(self.p['number']),
                 'body':'<!-- fortis-release-impact:start -->\n```yaml\nschemaVersion: 1\n```\n<!-- fortis-release-impact:end -->',
                 'changed_files':1}
        self.calls=[];self.allowed=True;self.projected=[];self.rows=[self.pr]
        self.adapter=GitHubAdapter(self,owner=owner,repositories=[repo],receipt_store=self.root/'github.sqlite')
        self.reader=NativeMergeDiscovery(self.adapter,repository=self.repo,
             read_guard=lambda a,r,o,p:self.allowed and a=='agent-1' and r==self.repo,
             branch_guard=lambda a,r,b:b=='owner-fix',project=self.project)

    def request(self,method,path,*,params=None,body=None,expected_statuses=(200,),allow_not_found=False):
        self.calls.append((method,path,params))
        self.assertEqual(method,'GET');self.assertIsNone(body)
        self.assertTrue(path.startswith(self.base+'/'))
        suffix=path[len(self.base)+1:]
        if suffix=='pulls':
            start=(params['page']-1)*params['per_page']
            return copy.deepcopy(self.rows[start:start+params['per_page']])
        if suffix.startswith('pulls/'):
            number=int(suffix.split('/')[1])
            return copy.deepcopy(next(r for r in self.rows if r['number']==number))
        if suffix=='branches/main':return {'name':'main','commit':{'sha':self.p['baseSha']}}
        if suffix=='contents/release/targets.yaml':
            self.assertEqual(params,{'ref':self.p['headSha']})
            data=self.catalog_text.encode()
            return {'type':'file','path':'release/targets.yaml','encoding':'base64','size':len(data),
                    'content':base64.b64encode(data).decode(),
                    'sha':hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest()}
        if suffix=='git/commits/'+self.p['headSha']:
            return {'sha':self.p['headSha'],'tree':{'sha':self.p['treeSha']}}
        if suffix=='compare/'+self.p['baseSha']+'...'+self.p['headSha']:
            return {'base_commit':{'sha':self.p['baseSha']},'merge_base_commit':{'sha':self.p['baseSha']},
                    'status':'ahead','ahead_by':1,'files':[{'filename':'app.py','status':'modified'}]}
        self.fail('unexpected GET '+suffix)

    def project(self,actor,observed):
        self.projected.append(observed)
        # Test-only successor projection; no real validator/CI claim.
        return {**self.p,**{k:observed[k] for k in ('bodyDigest','catalogSha256','impactDigest','pathsDigest')}}

    def test_native_list_and_evidence_non_task_branch_requires_explicit_scope(self):
        rows=self.reader('agent-1',self.repo)
        self.assertEqual(len(rows),1)
        self.assertEqual(rows[0]['headSha'],self.p['headSha'])
        self.assertEqual(self.projected[0]['headBranch'],'owner-fix')
        self.assertTrue(all(c[0]=='GET' for c in self.calls))
        self.reader.branch_guard=lambda *_:False
        with self.assertRaises(Denied):self.reader('agent-1',self.repo)

    def test_list_permission_does_not_authorize_evidence(self):
        self.reader.read_guard=lambda a,r,o,p:o=='list_pull_requests'
        with self.assertRaises(Denied):self.reader('agent-1',self.repo)
        self.assertEqual(len(self.calls),1)
        self.assertEqual(self.projected,[])

    def test_cross_repo_and_base_drift_refused(self):
        self.pr['head']['repo']['full_name']='Other/repo'
        with self.assertRaises(Denied):self.reader('agent-1',self.repo)
        self.pr['head']['repo']['full_name']=self.repo
        self.pr['base']['sha']='f'*40
        self.assertEqual(self.reader('agent-1',self.repo),[{'number':self.p['number'],
            'state':'BLOCKED','reason':'BASE_CHANGED'}])
        self.assertEqual(self.projected,[])

    def test_projection_mismatch_or_body_drift_refused(self):
        self.reader.project=lambda a,o:{**self.project(a,o),'treeSha':'f'*40}
        with self.assertRaises(Denied):self.reader('agent-1',self.repo)
        def changed(a,o):
            out=self.project(a,o);self.pr['body']+='changed';return out
        self.reader.project=changed
        with self.assertRaises(Stale):self.reader('agent-1',self.repo)

    def test_red_pr_does_not_hide_independently_ready_pr(self):
        n=self.pr['number']
        red={**copy.deepcopy(self.pr),'number':n-1}
        draft={**copy.deepcopy(self.pr),'number':n+1,'draft':True}
        self.rows=[red,self.pr,draft]
        real=self.reader.project
        def project(actor,observed):
            if observed['number']==n-1:
                raise Denied('GITHUB_RELEASE_CI_NOT_SUCCESSFUL')
            return real(actor,observed)
        self.reader.project=project
        rows=self.reader('agent-1',self.repo)
        self.assertEqual(rows[0],{'number':n-1,'state':'BLOCKED','reason':'CI_NOT_READY'})
        self.assertEqual(rows[1]['number'],n)
        self.assertNotIn('state',rows[1])
        self.assertEqual(rows[2],{'number':n+1,'state':'BLOCKED','reason':'DRAFT'})

    def test_scope_failure_after_ready_pr_still_aborts_scan(self):
        n=self.pr['number']
        self.rows=[self.pr,{**copy.deepcopy(self.pr),'number':n+1}]
        real=self.reader.project
        def project(actor,observed):
            if observed['number']==n+1:
                raise Denied('SUCCESSOR_CI_READ_DENIED')
            return real(actor,observed)
        self.reader.project=project
        with self.assertRaisesRegex(Denied,'SUCCESSOR_CI_READ_DENIED'):
            self.reader('agent-1',self.repo)

    def test_incomplete_inventory_refused_before_any_evidence(self):
        self.rows=[{**self.pr,'number':n} for n in range(1,22)]
        with self.assertRaises(Denied):self.reader('agent-1',self.repo)
        self.assertEqual(len(self.calls),2)
        self.assertEqual(self.projected,[])

    def test_revoked_scope_during_project_no_result(self):
        def changed(a,o):
            out=self.project(a,o);self.allowed=False;return out
        self.reader.project=changed
        with self.assertRaises(Denied):self.reader('agent-1',self.repo)

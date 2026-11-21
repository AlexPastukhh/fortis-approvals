import copy
import unittest
from types import SimpleNamespace

from fortis_approvals.core import Denied
from fortis_approvals.integrations.mirror.extension import (
    PROVIDER, MAX_WORKTREES, read_repository, validate_result)


def sample():
    repo='fortis-approvals'
    primary={'repoId':repo,'kind':'primary','branch':'main','head':'a'*40,
             'clean':True,'targetEligible':True,'origin':'sensitive',
             'changedFiles':['sensitive-filename']}
    win={'repoId':repo,'source':'windows','checkedAt':'2026-11-11T01:48:21+00:00',
         'exists':True,'branch':'main','head':'b'*40,'clean':True,
         'originValid':True,'relation':'unknown','error':None,
         'origin':'secret-or-sensitive'}
    row={'repoId':repo,'docker':{'primary':primary,'worktrees':[copy.deepcopy(primary)]},
         'windows':win,'github':{'error':'NOT_CHECKED','checkedAt':None,
                                 'head':None},
         'actions':{'pull_main':{'available':False}},
         'readTimingsMs':{'dockerInventory':20}}
    return {'schemaVersion':1,'repository':row}


class Fake:
    target='fortis-approvals'

    def __init__(self,response):
        self.response=response
        self.calls=[]

    def call(self,route,*,path):
        self.calls.append((route,path))
        return self.response


class MirrorReadProviderTests(unittest.TestCase):
    def test_provider_only_read_and_fixed_get(self):
        self.assertEqual('get_repository', PROVIDER.operations[0].name)
        self.assertTrue(all(op.kind == 'read' for op in PROVIDER.operations))
        self.assertEqual('read',PROVIDER.operations[0].kind)
        self.assertEqual(('get_repo',),PROVIDER.operations[0].routes)
        self.assertEqual('https://host.docker.internal',PROVIDER.api.origin)
        route=PROVIDER.api.routes['get_repo']
        self.assertEqual(('GET','/gateway/v1/repositories/{repo_id}',True),
                         (route.method,route.path,route.readonly))
        self.assertNotIn('pull',PROVIDER.api.routes)

    def test_positive_read_is_bounded_and_marks_github_unverified(self):
        ctx=Fake(sample())
        result=read_repository(ctx)
        self.assertEqual([('get_repo',{'repo_id':'fortis-approvals'})],ctx.calls)
        self.assertEqual('NOT_CHECKED',result['repository']['github']['verification'])
        self.assertEqual('b'*40,result['repository']['windows']['head'])
        self.assertNotIn('origin',result['repository']['windows'])
        self.assertNotIn('origin',result['repository']['docker']['primary'])
        self.assertNotIn('changedFiles',str(result))
        self.assertNotIn('actions',str(result))
        validate_result(result)

    def test_real_mirror_inventory_includes_primary_among_worktrees(self):
        data = sample()
        primary = data['repository']['docker']['primary']
        ordinary = dict(primary, kind='worktree', task='task-one', branch='task/one')
        # The Mirror exporter includes the primary in its complete list and
        # does not guarantee it will be at index zero.
        data['repository']['docker']['worktrees'] = [ordinary, copy.deepcopy(primary)]
        result = read_repository(Fake(data))['repository']['docker']
        self.assertEqual('main', result['primary']['branch'])
        self.assertEqual([{'branch':'task/one','head':'a'*40,'clean':True,
                           'targetEligible':True,'task':'task-one'}], result['worktrees'])
        self.assertNotIn('origin',str(result))
        self.assertNotIn('changedFiles',str(result))

    def test_71_upstream_entries_project_70_ordinary_worktrees(self):
        data = sample()
        primary = data['repository']['docker']['primary']
        data['repository']['docker']['worktrees'] = [copy.deepcopy(primary)] + [
            dict(primary, kind='worktree', task='task-%02d' % index,
                 branch='task/branch-%02d' % index)
            for index in range(70)
        ]
        result = read_repository(Fake(data))
        self.assertEqual(70,len(result['repository']['docker']['worktrees']))
        validate_result(result)

    def test_live_capacity_and_exact_boundary(self):
        for count in (128,130,MAX_WORKTREES):
            with self.subTest(count=count):
                data=sample()
                primary=data['repository']['docker']['primary']
                data['repository']['docker']['worktrees']=[copy.deepcopy(primary)]+[
                    dict(primary,kind='worktree',task='task-%03d'%i,
                         branch='task/branch-%03d'%i) for i in range(count-1)]
                result=read_repository(Fake(data))
                self.assertEqual(len(result['repository']['docker']['worktrees']),count-1)
                self.assertEqual(result['repository']['docker']['worktrees'][-1]['task'],
                                 'task-%03d'%(count-2))
                validate_result(result)

    def test_capacity_and_byte_limits_are_independent(self):
        data=sample()
        primary=data['repository']['docker']['primary']
        data['repository']['docker']['worktrees']=[copy.deepcopy(primary)]+[
            dict(primary,kind='worktree',task='task-%03d'%i,
                 branch='task/branch-%03d'%i) for i in range(MAX_WORKTREES)]
        with self.assertRaisesRegex(Denied,'MIRROR_UPSTREAM_INVALID'):
            read_repository(Fake(data))
        data['repository']['docker']['worktrees'].pop()
        for i,row in enumerate(data['repository']['docker']['worktrees'][1:]):
            row['task']='t'*110+str(i)
            row['branch']='task/'+'b'*145+str(i)
        # bounded() maps its own size Denied through ValueError to the
        # existing public JSON-invalid code. Preserve that contract.
        with self.assertRaisesRegex(Denied,'INTEGRATION_JSON_INVALID'):
            read_repository(Fake(data))
        result=read_repository(Fake(sample()))
        valid_row={'task':'task-one','branch':'task/one','head':'a'*40,
                   'clean':True,'targetEligible':True}
        result['repository']['docker']['worktrees']=[valid_row]*(MAX_WORKTREES+1)
        with self.assertRaisesRegex(Denied,'MIRROR_RESULT_INVALID'):
            validate_result(result)

    def test_reject_missing_duplicate_or_forged_primary_row(self):
        for mode in ('absent','duplicate','different-head','different-repo',
                     'wrong-kind','not-object'):
            with self.subTest(mode=mode):
                data = sample()
                primary = data['repository']['docker']['primary']
                rows = data['repository']['docker']['worktrees']
                if mode == 'absent': rows.clear()
                elif mode == 'duplicate': rows.append(copy.deepcopy(primary))
                elif mode == 'different-head': rows[0]['head'] = 'b'*40
                elif mode == 'different-repo': rows[0]['repoId'] = 'other'
                elif mode == 'wrong-kind': rows[0]['kind'] = 'worktree'
                else: rows[0] = 'not-a-worktree'
                with self.assertRaises(Denied):read_repository(Fake(data))

    def test_unknown_missing_windows_is_not_healthy(self):
        data=sample()
        data['repository']['windows'].update({
            'exists':False,'head':None,'clean':None,'branch':None,
            'originValid':False,'error':'WINDOWS_CLONE_NOT_FOUND'})
        result=read_repository(Fake(data))
        self.assertIsNone(result['repository']['windows']['clean'])
        self.assertEqual('WINDOWS_CLONE_NOT_FOUND',
                         result['repository']['windows']['error'])

    def test_reject_wrong_repo_and_unchecked_github_spoof(self):
        for change in [
            {'repoId':'another-repo'},
            {'github':{'error':None,'checkedAt':'2026-11-11T01:48:21+00:00'}},
            {'actions':{'pull_main':{'available':True}}},
            {'unexpected':1},
        ]:
            with self.subTest(change=change):
                data=sample()
                data['repository'].update(change)
                with self.assertRaises(Denied):
                    read_repository(Fake(data))

    def test_reject_bad_windows_and_docker(self):
        for key,value in [('source','other'),('checkedAt','bad'),
                          ('head','bogus'),('clean',1),
                          ('originValid','yes'),('relation','perfect')]:
            with self.subTest(key=key):
                data=sample();data['repository']['windows'][key]=value
                with self.assertRaises(Denied):
                    read_repository(Fake(data))
        data=sample()
        data['repository']['docker']['worktrees']=[{'repoId':'wrong','kind':'worktree'}]
        with self.assertRaises(Denied):read_repository(Fake(data))

    def test_reject_invalid_target_or_excess_worktrees(self):
        ctx=Fake(sample())
        ctx.target='../bad'
        with self.assertRaises(Denied):read_repository(ctx)
        self.assertFalse(ctx.calls)
        data=sample()
        data['repository']['docker']['worktrees']=[
            {'repoId':'fortis-approvals','kind':'worktree'}
            for _ in range(MAX_WORKTREES+1)]
        with self.assertRaises(Denied):read_repository(Fake(data))

    def test_result_rejects_extra_fields_and_fake_github(self):
        data=read_repository(Fake(sample()))
        data['repository']['github']={'verification':'VERIFIED'}
        with self.assertRaises(Denied):validate_result(data)
        data=read_repository(Fake(sample()))
        data['repository']['windows']['origin']='should-not-escape'
        with self.assertRaises(Denied):validate_result(data)


if __name__=='__main__':
    unittest.main()

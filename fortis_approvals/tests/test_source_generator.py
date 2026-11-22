"""Source-only package generator + actual Fortis discover, no network/effects."""
from copy import deepcopy
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch
import importlib
import sys
import unittest

from fortis_approvals import integrations
from fortis_approvals.extensions import source_generator as generator
_REAL_WORKTREE_CHECK = generator._check_task_worktree
from fortis_approvals.core import Denied
from fortis_approvals.extensions.model import discover
from fortis_approvals.extensions.runtime import ExtensionConfig, ExtensionRuntime
from fortis_approvals.extensions.source_generator import (
    render_package,source_plan,apply_source_package,build_generated_provider)
from fortis_approvals.tests.test_declarative_read import ACTION_SPEC,HEALTH_SPEC


def record_description():
    method=deepcopy(ACTION_SPEC)
    method['route']='get_record'
    method['credential']=None
    return dict(schemaVersion=1,provider='study_records',transport='jsonapi',
        origin='https://records.example.invalid',
        routes=[dict(name='get_record',path='/v1/records/{action_id}',queryKeys=[])],
        methods=[method])


def service_description():
    method=deepcopy(HEALTH_SPEC)
    method['credential']=None
    return dict(schemaVersion=1,provider='study_health',transport='jsonapi',
        origin='https://health.example.invalid',
        routes=[dict(name='health',path='/v1/health',queryKeys=[])],
        methods=[method])


MANUAL_CODE='''"""Trusted hand-authored module, MUST be preserved on update."""
from fortis_approvals.extensions.model import Operation, check

def make_transport():
    raise NotImplementedError('not needed')

def _reviewed(value):
    check(value['name'].startswith('Reviewed'), 'MANUAL_REVIEW_REQUIRED')

def result_postchecks():
    return {'read_action':_reviewed}

def context_postchecks():
    return {}

def manual_operations():
    def params(v):check(type(v) is dict and v == {}, 'MANUAL_PARAMS')
    def result(v):check(type(v) is dict and v.get('manual') is True,'MANUAL_RESULT')
    def execute(ctx):
        result={'manual':True};return result
    return (Operation('manual_read','Manual read alongside compiled method','read',
                      params,result,execute,routes=('get_record',)),)
'''


class GeneratorSourceTests(unittest.TestCase):
    def setUp(self):
        self.temp=TemporaryDirectory(prefix='fortis-source-generator-')
        self.addCleanup(self.temp.cleanup)
        self.addCleanup(self.clear_modules)
        self.root=Path(self.temp.name)
        home=self.root/'fortis_approvals'/'integrations'
        home.mkdir(parents=True)
        (self.root/'fortis_approvals'/'extensions').mkdir()
        (self.root/'fortis_approvals'/'extensions'/'model.py').write_text('# test sentinel')
        self.home=home
        # Unit fixture has no registered Git worktree: bypass the external
        # registered-root gate ONLY within these isolated in-memory tests.
        gate=patch.object(generator,'_check_task_worktree',return_value=None)
        gate.start()
        self.addCleanup(gate.stop)
    def clear_modules(self):
        for name in tuple(sys.modules):
            if name.startswith('fortis_approvals.integrations.study_'):
                sys.modules.pop(name,None)
    def discovered(self,*names):
        self.clear_modules()
        with patch.object(integrations,'__file__',str(self.home/'__init__.py')), \
             patch.object(integrations,'__path__',[str(self.home),*integrations.__path__]):
            importlib.invalidate_caches()
            return discover(tuple(names))
    def test_generates_regular_provider_discover_and_policy(self):
        desc=record_description()
        plan=source_plan(self.root,desc)
        self.assertEqual(plan['action'],'create')
        self.assertEqual(len(plan['changes']),5)
        out=apply_source_package(self.root,desc)
        self.assertEqual(len(out['changes']),5)
        self.assertEqual(len(out['appliedFiles']),5)
        provider,=self.discovered('study_records')
        self.assertEqual([op.name for op in provider.operations],['read_action'])
        self.assertEqual(provider.operations[0].allowed_targets,('3','4'))
        self.assertEqual(len(provider.source_digest),64)
        config=ExtensionConfig({'schemaVersion':1,'providers':{'study_records':{
            'credentials':{}, 'operations':{'read_action':{'policy':'ALLOW','targets':['3']}}}}})
        runtime=ExtensionRuntime(config,providers=(provider,),actors=('actor',),
                                 default_actor='actor')
        self.assertEqual(len(runtime.rules),1)
    def test_generated_package_real_core_ask_before_upstream_read(self):
        from io import BytesIO
        from types import SimpleNamespace
        import json
        import uuid
        from fortis_approvals.core import Core, Authenticator
        from fortis_approvals.tests.test_declarative_read import action_sample
        from test_core import SyntheticOwnerVerifier
        apply_source_package(self.root,record_description())
        provider,=self.discovered('study_records')
        class FakeResponse:
            status=200
            def __init__(self,url):
                self.url=url
                self.data=BytesIO(json.dumps(action_sample()).encode())
            def __enter__(self):return self
            def __exit__(self,*_):return False
            def geturl(self):return self.url
            def read(self,size):return self.data.read(size)
        class FakeOpener:
            def __init__(self):self.calls=[]
            def open(self,req,timeout=15):
                self.calls.append((req.get_method(),req.full_url))
                selfurl='https://records.example.invalid/v1/records/3'
                if req.full_url!=selfurl or req.get_method()!='GET':
                    raise Denied('OFFLINE_REQUEST_NOT_PERMITTED')
                return FakeResponse(req.full_url)
        opener=FakeOpener()
        provider.api.opener=opener
        owner=SyntheticOwnerVerifier()
        core=Core(self.root/'offline_core.sqlite',adapters={},policies={},
                  authenticator=Authenticator({'research-grant':'actor'}),
                  owner_verifier=owner)
        config=ExtensionConfig({'schemaVersion':1,'providers':{'study_records':{
          'credentials':{},'operations':{'read_action':{
              'policy':'ASK','targets':['3']}}}}})
        rt=ExtensionRuntime(config,providers=(provider,),actors=('actor',),
                            default_actor='actor').install(core,SimpleNamespace(strong_operations=frozenset()))
        request=dict(requestId=str(uuid.uuid4()),service='study_records',
                     operation='read_action',target='3',params={},reason='offline test')
        first=rt.call('research-grant',request)
        self.assertEqual(first['state'],'PENDING')
        self.assertEqual(opener.calls,[])
        persisted=core._read(request['requestId'])
        proof=owner.proof(request['requestId'],persisted['fingerprint'],'approve')
        self.assertEqual(core.owner_decide(request['requestId'],'approve',proof)['state'],
                         'EXECUTED')
        self.assertEqual(rt.result('research-grant',request['requestId'])['data'],action_sample())
        self.assertEqual(opener.calls,[('GET','https://records.example.invalid/v1/records/3')])

    def test_two_independent_providers_from_same_generator(self):
        apply_source_package(self.root,record_description())
        apply_source_package(self.root,service_description())
        one,two=self.discovered('study_health','study_records')
        self.assertEqual({one.name,two.name},{'study_health','study_records'})
        self.assertEqual(sum(len(x.operations) for x in (one,two)),2)
    def test_add_method_changes_digest_preserves_manual_code(self):
        original=record_description()
        apply_source_package(self.root,original)
        pkg=self.home/'study_records'
        (pkg/'manual.py').write_text(MANUAL_CODE)
        manual_before=(pkg/'manual.py').read_bytes()
        before=self.discovered('study_records')[0]
        self.assertEqual(len(before.operations),2)
        self.assertEqual(before.operations[1].name,'manual_read')
        expanded=deepcopy(original)
        extra=deepcopy(expanded['methods'][0]);extra['name']='read_record_summary'
        extra['route']='get_summary'
        expanded['routes'].append(dict(name='get_summary',
            path='/v1/records/{action_id}/summary',queryKeys=[]))
        expanded['methods'].append(extra)
        preview=source_plan(self.root,expanded)
        self.assertEqual(preview['action'],'update')
        self.assertIn('definition.py',{x['path'] for x in preview['changes']})
        apply_source_package(self.root,expanded)
        after=self.discovered('study_records')[0]
        self.assertNotEqual(after.source_digest,before.source_digest)
        self.assertEqual([x.name for x in after.operations],
                         ['read_action','read_record_summary','manual_read'])
        self.assertEqual((pkg/'manual.py').read_bytes(),manual_before)
        self.assertEqual((pkg/'tests'/'test_manual.py').read_text(),
                         '"""Hand-written regression tests for custom source components. Preserved."""\n')
        from fortis_approvals.tests.test_declarative_read import action_sample,Ctx
        with self.assertRaisesRegex(Denied,'MANUAL_REVIEW_REQUIRED'):
            after.operations[0].result(action_sample())
        reviewed=action_sample();reviewed['name']='Reviewed item'
        after.operations[0].result(reviewed)
    def test_manual_transport_explicit_stop_without_user_code(self):
        desc=service_description();desc['transport']='manual';desc['origin']=None
        apply_source_package(self.root,desc)
        with self.assertRaisesRegex(Denied,'MANUAL_TRANSPORT_REQUIRED'):
            self.discovered('study_health')
    def test_manual_transport_can_be_completed_without_regeneration(self):
        desc=service_description();desc['transport']='manual';desc['origin']=None
        apply_source_package(self.root,desc)
        pkg=self.home/'study_health'
        custom='''from fortis_approvals.extensions.http import JSONAPI,Route

def make_transport():
    return JSONAPI('https://trusted.example.invalid',(
        Route('health','GET','/v1/health',readonly=True),))

def result_postchecks():return {}
def context_postchecks():return {}
def manual_operations():return ()
'''
        (pkg/'manual.py').write_text(custom)
        provider,=self.discovered('study_health')
        self.assertEqual(provider.name,'study_health')
        self.assertEqual(provider.api.origin,'https://trusted.example.invalid')
    def test_manual_transport_route_mismatch_refused(self):
        desc=service_description();desc['transport']='manual';desc['origin']=None
        apply_source_package(self.root,desc)
        pkg=self.home/'study_health'
        (pkg/'manual.py').write_text('''from fortis_approvals.extensions.http import JSONAPI,Route

def make_transport():return JSONAPI('https://trusted.example.invalid',(
    Route('health','GET','/v1/incorrect',readonly=True),))
def result_postchecks():return {}
def context_postchecks():return {}
def manual_operations():return ()
''')
        with self.assertRaisesRegex(Denied,'SOURCE_MANUAL_ROUTE_MISMATCH'):
            self.discovered('study_health')
    def test_manual_only_method_can_use_same_package_and_release_mechanism(self):
        spec=service_description();spec['methods']=[]
        apply_source_package(self.root,spec)
        pkg=self.home/'study_health'
        # A fully manual method may use the same trusted fixed JSONAPI transport.
        (pkg/'manual.py').write_text("""from fortis_approvals.extensions.model import Operation,check

def make_transport():raise NotImplementedError('jsonapi already provided')
def result_postchecks():return {}
def context_postchecks():return {}
def manual_operations():
    def params(value):check(type(value) is dict and value == {},'CUSTOM_PARAMS')
    def result(value):check(value=={'manual':True},'CUSTOM_RESULT')
    def execute(ctx):return {'manual':True}
    return (Operation('manual_health','Manually implemented health read','read',
                      params,result,execute,routes=('health',)),)
""")
        provider,=self.discovered('study_health')
        self.assertEqual([op.name for op in provider.operations],['manual_health'])
        self.assertEqual(provider.operations[0].execute(None),{'manual':True})
        config=ExtensionConfig({'schemaVersion':1,'providers':{'study_health':{
          'credentials':{},'operations':{
             'manual_health':{'policy':'ASK','targets':['service']}}}}})
        self.assertEqual(len(ExtensionRuntime(config,providers=(provider,),
            actors=('actor',),default_actor='actor').rules),1)

    def test_existing_unmanaged_provider_is_never_overwritten(self):
        pkg=self.home/'study_records';pkg.mkdir()
        file=pkg/'extension.py';file.write_text('MANUAL SOURCE BY OWNER\n')
        with self.assertRaisesRegex(Denied,'SOURCE_UNMANAGED_PROVIDER_DENIED'):
            apply_source_package(self.root,record_description())
        self.assertEqual(file.read_text(),'MANUAL SOURCE BY OWNER\n')
    def test_generated_file_hand_edit_stops_without_overwrite(self):
        desc=record_description();apply_source_package(self.root,desc)
        pkg=self.home/'study_records'
        file=pkg/'definition.py';file.write_text(file.read_text()+'# human edit\n')
        with self.assertRaisesRegex(Denied,'SOURCE_GENERATED_FILE_EDITED_STOP'):
            apply_source_package(self.root,desc)
        self.assertIn('# human edit',file.read_text())
    def test_user_supplied_extra_python_data_fails_without_writes(self):
        desc=record_description();desc['eval']='bad'
        with self.assertRaises(Denied):apply_source_package(self.root,desc)
        self.assertEqual(list(self.home.iterdir()),[])
    def test_unsafe_origin_fails_without_writes(self):
        desc=record_description();desc['origin']='http://insecure.example.invalid'
        with self.assertRaises(Denied):apply_source_package(self.root,desc)
        self.assertEqual(list(self.home.iterdir()),[])
    def test_bad_route_fails_without_writes(self):
        desc=record_description();desc['routes'][0]['path']='//unexpected'
        with self.assertRaises(Denied):apply_source_package(self.root,desc)
        self.assertEqual(list(self.home.iterdir()),[])
    def test_spec_is_deterministic_and_preview_no_changes(self):
        desc=record_description()
        one=render_package(desc)
        two=render_package(deepcopy(desc))
        self.assertEqual(one,two)
        self.assertEqual(source_plan(self.root,desc)['action'],'create')
        self.assertEqual(list(self.home.iterdir()),[])
    def test_apply_rejects_unregistered_or_main_like_git_tree(self):
        # A real source root containing .git must be an authorized task/ branch.
        (self.root/'.git').write_text('not a task worktree')
        with patch.object(generator,'_check_task_worktree',_REAL_WORKTREE_CHECK):
            with self.assertRaisesRegex(Denied,'SOURCE_TASK_WORKTREE_REQUIRED'):
                apply_source_package(self.root,record_description())
        self.assertEqual(list(self.home.iterdir()),[])

    def test_manual_test_is_discovered_by_source_ci_pattern(self):
        from fnmatch import fnmatch
        apply_source_package(self.root,record_description())
        folder=self.home/'study_records'/'tests'
        self.assertTrue((folder/'test_manual.py').exists())
        self.assertTrue(fnmatch('test_manual.py','test_*.py'))
        self.assertFalse((folder/'manual_test.py').exists())

    def test_real_discovery_runs_manual_test_file_not_just_name_pattern(self):
        apply_source_package(self.root,record_description())
        package=self.home/'study_records'
        (package/'tests'/'test_manual.py').write_text(
            'import unittest\nclass CustomTests(unittest.TestCase):\n'
            '    def test_handwritten_guard(self): self.fail("manual CI sentinel")\n')
        import io
        from unittest import TestLoader,TextTestRunner
        self.clear_modules()
        with patch.object(integrations,'__file__',str(self.home/'__init__.py')), \
             patch.object(integrations,'__path__',[str(self.home),*integrations.__path__]):
            importlib.invalidate_caches()
            suite=TestLoader().discover(str(package/'tests'),pattern='test_*.py')
            result=TextTestRunner(stream=io.StringIO(),verbosity=0).run(suite)
        self.assertEqual(result.testsRun,3)
        self.assertEqual(len(result.failures),1)
        self.assertIn('manual CI sentinel',result.failures[0][1])

    def test_manual_transport_cannot_register_extra_routes(self):
        desc=service_description();desc['transport']='manual';desc['origin']=None
        apply_source_package(self.root,desc)
        package=self.home/'study_health'
        (package/'manual.py').write_text('''from fortis_approvals.extensions.http import JSONAPI,Route

def make_transport():
    return JSONAPI('https://trusted.example.invalid',(
        Route('health','GET','/v1/health',readonly=True),
        Route('hidden_post','POST','/v1/action',readonly=False)))
def result_postchecks():return {}
def context_postchecks():return {}
def manual_operations():return ()
''')
        with self.assertRaisesRegex(Denied,'SOURCE_MANUAL_ROUTE_MISMATCH'):
            self.discovered('study_health')

    def test_refuse_symlink_to_manual_file(self):
        desc=record_description();apply_source_package(self.root,desc)
        pkg=self.home/'study_records'
        (pkg/'manual.py').unlink();(pkg/'manual.py').symlink_to(pkg/'extension.py')
        with self.assertRaisesRegex(Denied,'SOURCE_SYMLINK_DENIED'):
            apply_source_package(self.root,desc)


if __name__=='__main__':unittest.main(verbosity=2)

"""Actual resolved catalog projection and deterministic bounded plan checks."""
import copy
import unittest

from fortis_approvals.core import Denied
from fortis_approvals.integrations.registry_contracts.release_profile import from_resolved_catalog
from fortis_approvals.integrations.github.gateway.component_bindings import _resolved
from fortis_approvals.registry.release_domain import profile_rows,key
from fortis_approvals.registry.release_planner import plan
from fortis_approvals.tests import test_registry_release_domain as fixture


class ProfilePlannerTests(unittest.TestCase):
    def setUp(self):
        self.repo='Owner/fortis-approvals'
        self.deploy={'kind':'owner-controlled','procedure':'UC.md','environments':['test']}
        self.catalog={'schemaVersion':1,'repository':'fortis-approvals',
                      'buildUnits':[{'id':'shared','artifactType':'docker-image','inputs':['src.py']}],
                      'targets':[{'id':n,'buildUnit':'shared','deployment':self.deploy,
                                  'verification':['health']} for n in ('a','b')]}
        self.binding={'bindings':[{'targetId':n,'environment':'test','componentId':n} for n in ('a','b')],
                      'components':[{'id':n,'resources':[n+'-state'],'requires':[]} for n in ('a','b')]}
        self.pins={'shared':{'recipeDigest':'a'*64,'configDigest':'b'*64}}

    def profile(self):
        resolved=_resolved(self.binding,self.catalog)
        return from_resolved_catalog(self.catalog,resolved,repository=self.repo,
                                      catalog_sha256='c'*64,build_pins=self.pins)

    def test_existing_mapping_v1_unknown_and_v2_explicit(self):
        p=self.profile()
        self.assertTrue(all(r['maintenance'] is None for r in p['subjects']))
        self.catalog['schemaVersion']=2
        for t in self.catalog['targets']:
            t['maintenance']=fixture.maintenance()
        p=self.profile()
        self.assertTrue(all(r['maintenance']==fixture.maintenance() for r in p['subjects']))
        self.assertEqual(len(profile_rows(p,self.repo,'c'*64)),2)
        self.catalog['targets'][0]['dependsOn']=[{'repository':'fortis-approvals','target':'b'}]
        self.binding['components'][0]['requires']=['b']
        p=self.profile()
        self.assertEqual(p['subjects'][0]['dependencies'],[p['subjects'][1]['subject']])

    def test_unknown_build_pins_not_assumed(self):
        self.pins={}
        p=self.profile()
        self.assertIsNone(p['subjects'][0]['build']['recipeDigest'])

    def view(self):
        self.catalog['schemaVersion']=2
        for t in self.catalog['targets']:
            t['maintenance']=fixture.maintenance()
        profiles=profile_rows(self.profile(),self.repo,'c'*64)
        source={'sourceSha':'d'*40,'catalogCommitSha':'e'*40,'catalogSha256':'c'*64,
                'artifactSha256':None}
        states={k:{'subject':p['subject'],'desired':{'source':copy.deepcopy(source)},
                   'activeAttempt':None,'outstandingActions':['image-rebuild']} for k,p in profiles.items()}
        view={'states':states,'profiles':profiles,'sourceTransitionPending':True,
              'sourceRequirements':[],'snapshotRevision':0,'eventDigest':'a'*64}
        items=[{'subject':p['subject'],'source':copy.deepcopy(source)} for p in profiles.values()]
        return view,items

    def test_shared_build_not_verified_artifact_and_unselected_preserved(self):
        view,items=self.view()
        result=plan(view,items,visible=lambda _:True)
        self.assertEqual(result['status'],'UNKNOWN')
        self.assertEqual(len(result['buildGroups']),1)
        self.assertEqual(result['buildGroups'][0]['artifactState'],'BUILD_REQUIRED')
        self.assertEqual(len(result['buildGroups'][0]['subjects']),2)
        one=plan(view,items[:1],visible=lambda _:True)
        self.assertEqual(one['buildGroups'][0]['affectedUnselected'],[items[1]['subject']])
        hidden=plan(view,items[:1],visible=lambda s:s==items[0]['subject'])
        self.assertEqual(hidden['buildGroups'][0]['affectedUnselected'],[])
        self.assertIn('SHARED_BUILD_SCOPE_UNAVAILABLE',[c['code'] for c in hidden['checks']])
        self.assertEqual(result,plan(view,items,visible=lambda _:True))

    def test_changed_source_stale_and_no_silent_retarget(self):
        view,items=self.view()
        items[0]['source']['sourceSha']='f'*40
        result=plan(view,items,visible=lambda _:True)
        self.assertEqual(result['status'],'STALE')
        self.assertEqual(result['targets'][0]['source']['sourceSha'],'f'*40)
        self.assertEqual(len(result['buildGroups']),2)

    def test_exact_configuration_and_artifact_binding(self):
        view,items=self.view()
        p=view['profiles'][key(items[1]['subject'])]
        p['build']['configDigest']='f'*64
        result=plan(view,items,visible=lambda _:True)
        self.assertEqual(len(result['buildGroups']),2)
        items[1]['source']['artifactSha256']='a'*64
        view['states'][key(items[1]['subject'])]['desired']['source']=copy.deepcopy(items[1]['source'])
        result=plan(view,items,visible=lambda _:True)
        self.assertEqual({g['artifactState'] for g in result['buildGroups']},{'PINNED','BUILD_REQUIRED'})

    def test_unresolved_external_catalog_dependency_not_guessed(self):
        resolved=_resolved(self.binding,self.catalog)
        self.catalog['targets'][0]['dependsOn']=[{'repository':'other-repo','target':'api'}]
        p=from_resolved_catalog(self.catalog,resolved,repository=self.repo,catalog_sha256='c'*64,
                                build_pins=self.pins)
        self.assertEqual(p['subjects'][0]['unresolvedDependencies'],
                         [{'repository':'other-repo','target':'api'}])
        self.assertEqual(p['subjects'][0]['dependencies'],[])

    def test_missing_dependency_mapping_refused(self):
        resolved=_resolved(self.binding,self.catalog)
        self.catalog['targets'][0]['dependsOn']=[{'repository':'fortis-approvals','target':'b'}]
        with self.assertRaises(Denied):
            from_resolved_catalog(self.catalog,resolved,repository=self.repo,catalog_sha256='c'*64,
                                  build_pins=self.pins)


if __name__=='__main__':
    unittest.main()

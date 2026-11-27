"""Pure source tests. No Gateway, live storage, policy or provider calls."""
from copy import deepcopy
import unittest
import uuid

from fortis_approvals.core import Denied
from fortis_approvals.integrations.registry_contracts import semantic_contract as sc
from fortis_approvals.extensions import composite_contract as cc


def subject(target='a', repo='Owner/repo'):
    return {'repository': repo, 'targetId': target, 'environment': 'test'}


def source():
    return {'sourceSha': 'a'*40, 'catalogCommitSha': 'b'*40,
            'catalogSha256': 'c'*64, 'artifactSha256': None}


def begin(target='a', repo='Owner/repo'):
    return {'subject': subject(target, repo), 'source': source(),
            'expected': {'targetRevision': 0, 'desiredRecordId': 'd'*64,
                         'catalogSha256': 'c'*64}}


def report(target='a'):
    item = begin(target)
    item.update(attemptId=None, context='release', outcome='REPORTED_COMPLETE',
                assertion='owner reported completion', observedAt=None,
                evidenceDigests=[])
    return item


class SemanticContractTests(unittest.TestCase):
    def test_all_read_shapes(self):
        page = {'limit': 20, 'cursor': None}
        cases = {
            'list_components': {'repository': 'Owner/repo', 'page': page},
            'get_component': {'subject': subject()},
            'plan_batch': {'items': [{'subject': subject(), 'source': source()}]},
            'list_history': {'subject': subject(), 'page': page},
            'get_operation': {'subject': subject(), 'operationId': str(uuid.uuid4())},
            'list_active_releases': {'repository': 'Owner/repo', 'page': page},
            'get_maintenance_status': {'repository': 'Owner/repo'},
        }
        self.assertEqual(set(cases), sc.READ_METHODS)
        for op, params in cases.items():
            with self.subTest(op=op):
                self.assertEqual(sc.validate_params(op, params), params)
                with self.assertRaises(Denied):
                    sc.validate_params(op, {**params, 'actor': 'owner'})

    def test_closed_write_shapes_and_detachment(self):
        cases = {
            'begin_release': begin(),
            'report_release_result': report(),
            'begin_release_group': {'items': [begin(), begin('b')]},
            'report_release_results': {'items': [report(), report('b')]},
        }
        self.assertEqual(set(cases), sc.WRITE_METHODS)
        for op, params in cases.items():
            with self.subTest(op=op):
                result = sc.validate_params(op, params)
                self.assertEqual(result, params)
                self.assertIsNot(result, params)
                with self.assertRaises(Denied):
                    sc.validate_params(op, {**params, 'policy': 'ALLOW'})
                with self.assertRaises(Denied):
                    sc.validate_params(op, {**params, 'operation': 'github.merge_pull_request'})

    def test_begin_rejects_bad_scope_source_and_guard(self):
        for path, value in (
            (('subject', 'repository'), 'Owner/../repo'),
            (('subject', 'targetId'), '*'),
            (('subject', 'environment'), 'Production'),
            (('source', 'sourceSha'), 'a'*39),
            (('source', 'artifactSha256'), 'sha256:bad'),
            (('expected', 'targetRevision'), True),
            (('expected', 'targetRevision'), -1),
            (('expected', 'targetRevision'), 2**63),
            (('expected', 'desiredRecordId'), None),
            (('expected', 'catalogSha256'), 'e'*64),
        ):
            item = begin()
            item[path[0]][path[1]] = value
            with self.subTest(path=path, value=value), self.assertRaises(Denied):
                sc.validate_params('begin_release', item)

    def test_report_context_unknown_and_evidence(self):
        for context in ('initial', 'release', 'external', 'historical', 'rollback'):
            item = report()
            item['context'] = context
            self.assertEqual(sc.validate_params('report_release_result', item), item)
        item = report()
        item.update(context='external', outcome='UNKNOWN', source=None)
        self.assertEqual(sc.validate_params('report_release_result', item), item)
        for patch in (
            {'outcome': 'DEPLOYED'}, {'outcome': 'VERIFIED'},
            {'attemptId': 'bad'}, {'source': None},
            {'context': 'historical', 'attemptId': str(uuid.uuid4())},
            {'evidenceDigests': ['a'*64, 'a'*64]},
            {'evidenceDigests': ['b'*64, 'a'*64]},
            {'observedAt': True}, {'assertion': ''},
            {'assertion': 'x'*2001}, {'actor': 'owner'},
        ):
            with self.subTest(patch=patch), self.assertRaises(Denied):
                sc.validate_params('report_release_result', {**report(), **patch})

    def test_group_order_unique_bounds_and_case_alias(self):
        good = {'items': [begin(), begin('b')]}
        self.assertEqual(sc.validate_params('begin_release_group', good), good)
        for items in (
            [], [begin()], [begin(), begin()], [begin('b'), begin()],
            [begin(repo='Owner/repo'), begin(repo='owner/REPO')],
            [begin('a%02d' % i) for i in range(sc.MAX_GROUP+1)],
            (begin(), begin('b')),
        ):
            with self.subTest(n=len(items)), self.assertRaises(Denied):
                sc.validate_params('begin_release_group', {'items': items})

    def test_read_limits_and_legacy_names_not_aliased(self):
        for page in (
            {'limit': True, 'cursor': None},
            {'limit': 101, 'cursor': None},
            {'limit': 1, 'cursor': 'a'*257},
            {'limit': 1, 'cursor': '../path'},
        ):
            with self.assertRaises(Denied):
                sc.validate_params('list_components', {'repository': 'Owner/repo', 'page': page})
        with self.assertRaises(Denied):
            sc.validate_params('candidate_head', {'repository': 'Owner/repo'})
        with self.assertRaises(Denied):
            sc.validate_params('list_components', {'repository': 'Owner/repo', 'page': {'limit': 1, 'cursor': None}, 'x': 'z'*5000})


class CompositeContractTests(unittest.TestCase):
    def test_definitions_and_deterministic_exact_child_steps(self):
        parent = str(uuid.uuid4())
        params = {'items': [begin(), begin('b')]}
        first = cc.expand_group('registry', 'begin_release_group', parent, params)
        self.assertEqual(first, cc.expand_group('registry', 'begin_release_group', parent, deepcopy(params)))
        self.assertEqual(len({s['stepId'] for s in first['steps']}), 2)
        self.assertEqual([s['operation'] for s in first['steps']], ['begin_release']*2)
        self.assertEqual([s['params'] for s in first['steps']], params['items'])
        self.assertEqual(first['definitionDigest'], cc.definition('registry', 'begin_release_group').definition_digest)
        params['items'][0]['expected']['targetRevision'] = 1
        second = cc.expand_group('registry', 'begin_release_group', parent, params)
        self.assertNotEqual(first['paramsDigest'], second['paramsDigest'])
        self.assertNotEqual(first['steps'][0]['stepId'], second['steps'][0]['stepId'])
        self.assertNotEqual(first['steps'][1]['stepId'], second['steps'][1]['stepId'])
        self.assertEqual(first['steps'][0]['params']['expected']['targetRevision'], 0)
        third = cc.expand_group('registry', 'begin_release_group', str(uuid.uuid4()), params)
        self.assertNotEqual(second['steps'][1]['stepId'], third['steps'][1]['stepId'])

    def test_report_expansion_and_no_arbitrary_workflow(self):
        parent = str(uuid.uuid4())
        valid = {'items': [report(), report('b')]}
        result = cc.expand_group('registry', 'report_release_results', parent, valid)
        self.assertEqual([s['operation'] for s in result['steps']], ['report_release_result']*2)
        for service, op, params in (
            ('registry', 'report_release_results', {**valid, 'children': []}),
            ('registry', 'begin_release', begin()),
            ('github', 'merge_pull_request', {}),
            ('release', 'merge_and_register', {}),
            ('registry', 'report_release_results', {'items': [report()]}),
        ):
            with self.subTest(op=op), self.assertRaises(Denied):
                cc.expand_group(service, op, parent, params)
        with self.assertRaises(Denied):
            cc.expand_group('registry', 'report_release_results', 'invalid', valid)

    def test_metadata_policy_not_a_grant(self):
        recipes = cc.definitions()
        self.assertEqual(len(recipes), 3)
        for recipe in recipes:
            metadata = recipe.metadata()
            self.assertEqual(metadata['operationKind'], 'composite')
            self.assertNotIn('policy', metadata)
            self.assertNotIn('credential', metadata)
            self.assertEqual(len(recipe.definition_digest), 64)
        self.assertTrue(cc.definition('release', 'merge_and_register').protected_owner_gate)
        self.assertFalse(cc.definition('registry', 'begin_release_group').protected_owner_gate)


if __name__ == '__main__':
    unittest.main()

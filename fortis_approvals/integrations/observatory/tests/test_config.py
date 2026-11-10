"""Offline registration, actor/target and vault readiness constraints."""
import unittest

from fortis_approvals.core import Denied
from fortis_approvals.extensions.model import discover
from fortis_approvals.extensions.runtime import ExtensionConfig, ExtensionRuntime


ACTOR = 'repo-sonar-read-proposal-actor'


class FakeVault:
    def __init__(self, ready=True):
        self.ready = ready
    def readiness(self, alias):
        assert alias == 'observatory-api'
        return {'configured': True, 'ready': self.ready,
                'status': 'READY' if self.ready else 'MISSING'}


def configuration():
    return {
        'schemaVersion': 1,
        'providers': {'observatory': {
            'credentials': {'api': 'observatory-api'},
            'operations': {
                'health': {'policy': 'ALLOW', 'targets': ['service']},
                'list_sessions': {'policy': 'ALLOW', 'targets': ['registry']},
            },
        }},
    }


def runtime(value, ready=True):
    return ExtensionRuntime(
        ExtensionConfig(value), providers=discover(('observatory',)),
        actors=(ACTOR,), default_actor=ACTOR, vault=FakeVault(ready))


class ConfigTests(unittest.TestCase):
    def test_closed_registration_and_readiness(self):
        rows = runtime(configuration()).catalog_for(ACTOR)['operations']
        self.assertEqual({x['operation'] for x in rows}, {'health', 'list_sessions'})
        self.assertEqual({x['target'] for x in rows}, {'service', 'registry'})
        self.assertTrue(all(x['ready'] and x['policy'] == 'ALLOW' for x in rows))
        missing = runtime(configuration(), ready=False).catalog_for(ACTOR)['operations']
        self.assertTrue(all(not x['ready'] for x in missing))

    def test_unknown_routes_actor_or_extra_fields_fail_closed(self):
        for modifier in (
            lambda v: v['providers']['observatory']['operations'].update(
                {'forward': {'policy': 'ALLOW', 'targets': ['service']}}),
            lambda v: v['providers']['observatory']['operations']['health'].update(
                {'extra': True}),
            lambda v: v['providers']['observatory']['operations']['health'].update(
                {'actors': ['not-authenticated']}),
            lambda v: v['providers']['observatory']['operations'].update({}),
        ):
            v = configuration()
            modifier(v)
            if v != configuration():
                with self.assertRaises(Denied):
                    runtime(v)
        self.assertEqual(len(runtime({'schemaVersion': 1, 'providers': {}}
                                     ).catalog_for(ACTOR)['operations']), 0)

    def test_no_write_operations_exposed(self):
        self.assertTrue(all(op.kind == 'read' for op in discover(('observatory',))[0].operations))


if __name__ == '__main__':
    unittest.main()

"""Generated structural baseline tests. Never replace test_manual.py."""
import unittest
from fortis_approvals.integrations.open_holidays_pilot.extension import PROVIDER
from fortis_approvals.integrations.open_holidays_pilot.definition import SOURCE_DESCRIPTION

class GeneratedContractTests(unittest.TestCase):
    def test_source_provider_and_compiled_method_presence(self):
        self.assertEqual(PROVIDER.name,SOURCE_DESCRIPTION['provider'])
        self.assertTrue({row['name'] for row in SOURCE_DESCRIPTION['methods']} <=
                        {op.name for op in PROVIDER.operations})
    def test_source_routes_are_readonly(self):
        self.assertTrue(all(PROVIDER.api.routes[r['name']].method=='GET' and
                        PROVIDER.api.routes[r['name']].readonly
                        for r in SOURCE_DESCRIPTION['routes']))

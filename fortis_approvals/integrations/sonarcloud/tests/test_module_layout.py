import unittest

from fortis_approvals import repo_sonar_tools, sonar, sonar_inventory, sonar_read
from fortis_approvals.integrations.sonarcloud.gateway import (
    inventory, read_adapter, sonar as sonar_impl,
)
from fortis_approvals.integrations.sonarcloud.repo_client import client


class ModuleLayoutTests(unittest.TestCase):
    def test_legacy_gateway_modules_are_identity_aliases(self):
        self.assertIs(sonar, sonar_impl)
        self.assertIs(sonar_inventory, inventory)
        self.assertIs(sonar_read, read_adapter)

    def test_legacy_repo_client_is_identity_alias(self):
        self.assertIs(repo_sonar_tools, client)
        self.assertTrue(callable(repo_sonar_tools.call))


if __name__ == "__main__":
    unittest.main()

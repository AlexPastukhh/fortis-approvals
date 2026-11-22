"""Source-test verifier for the staged, fixed-scope OpenHolidays READ."""
from importlib import import_module, util
import sys
import unittest
from unittest.mock import patch


_PACKAGE = "fortis_approvals.integrations.open_holidays_pilot"
_REQUIREMENTS = {("resultPostcheck", "public_holidays"), ("trustedTransport", None)}


def review_openholidays(directory, requirements):
    """Inspect generated provider and run the two reviewed staged suites."""
    assert len(requirements) == len(_REQUIREMENTS)
    assert {(item["kind"], item["method"]) for item in requirements} == _REQUIREMENTS

    spec = util.spec_from_file_location(_PACKAGE, directory / "__init__.py",
                                        submodule_search_locations=[str(directory)])
    assert spec is not None and spec.loader is not None
    package = util.module_from_spec(spec)
    with patch.dict(sys.modules, {_PACKAGE: package}):
        spec.loader.exec_module(package)
        provider = import_module(_PACKAGE + ".extension").PROVIDER
        assert provider.name == "open_holidays_pilot"
        operation, = provider.operations
        assert (operation.name, operation.kind, operation.allowed_targets) == (
            "public_holidays", "read", ("de",))
        assert operation.credential is None
        assert operation.routes == ("public_holidays",)
        assert provider.api.routes["public_holidays"].readonly is True

        suite = unittest.defaultTestLoader.discover(str(directory / "tests"))
        result = unittest.TextTestRunner(verbosity=2).run(suite)
        assert result.testsRun == 9 and result.wasSuccessful()

    return {"passed": True, "verified": requirements, "operations": [operation.name]}

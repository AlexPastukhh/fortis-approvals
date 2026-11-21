#!/usr/bin/env python3
"""Mandatory P5 semantic gate when invoked; never turn missing inputs into a skip."""
import importlib.metadata
import os
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
PIN = '8c9abefdfbe4699aae97b9363a2a66c596680e62'
TESTS = (
    'test_real_shared_validator_semantics',
    'test_real_validator_rejects_false_no_deployment',
    'test_real_validator_rejects_missing_local_dependency',
    'test_real_validator_rejects_duplicate_yaml_key',
    'test_real_transitive_dependency_graph',
    'test_real_external_dependency_is_unresolved',
)


def main():
    root = os.environ.get('FORTIS_TEST_RELEASE_VALIDATOR_ROOT')
    if not root or not Path(root).is_absolute() or not Path(root).is_dir():
        raise SystemExit('P5_REAL_VALIDATOR_ROOT_REQUIRED')
    for name, version in (('PyYAML','6.0.2'),('jsonschema','4.23.0')):
        try:
            actual = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError:
            raise SystemExit('P5_REAL_VALIDATOR_DEPENDENCY_MISSING: '+name) from None
        if actual != version:
            raise SystemExit('P5_REAL_VALIDATOR_DEPENDENCY_PIN_CHANGED: '+name)
    if subprocess.check_output(['git','--no-replace-objects','-C',root,'rev-parse','HEAD'],
                               text=True,timeout=8).strip() != PIN:
        raise SystemExit('P5_REAL_VALIDATOR_PIN_CHANGED')
    sys.path.insert(0,str(ROOT))
    from fortis_approvals.integrations.github.tests.test_retained_impact import RetainedImpactTests, REAL_PIN
    if REAL_PIN != PIN:
        raise SystemExit('P5_REAL_VALIDATOR_TEST_PIN_CHANGED')
    suite = unittest.TestSuite(RetainedImpactTests(name) for name in TESTS)
    from fortis_approvals.integrations.github.tests.test_selected_main_binding import SelectedMainTests
    suite.addTest(SelectedMainTests('test_real_selected_main_composition'))
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    if not result.wasSuccessful() or result.testsRun != len(TESTS)+1 or result.skipped:
        raise SystemExit('P5_REAL_VALIDATOR_GATE_FAILED')
    print('P5_REAL_VALIDATOR_GATE_PASS',PIN,'cases='+str(result.testsRun))


if __name__ == '__main__':
    main()

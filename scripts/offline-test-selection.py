"""Discover or execute an exact subset of the reviewed heavy unittest suites."""
import argparse
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
TARGETS = {
    "github": ("fortis_approvals/integrations/github/tests", "test_*.py"),
    "native": ("fortis_approvals/tests", "test_native_workflow.py"),
}


def flatten(suite):
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            yield from flatten(item)
        else:
            yield item


def discover(target):
    directory, pattern = TARGETS[target]
    loader = unittest.TestLoader()
    suite = loader.discover(str(ROOT / directory), pattern=pattern)
    if loader.errors:
        raise RuntimeError("discovery errors: " + repr(loader.errors))
    cases = list(flatten(suite))
    ids = [case.id() for case in cases]
    if not ids or len(ids) != len(set(ids)):
        raise RuntimeError("empty or duplicate test discovery")
    if target == "native":
        # Case-level splitting is only permitted without shared fixtures.
        for case in cases:
            cls = type(case)
            mod = sys.modules[cls.__module__]
            if any(hasattr(mod, name) for name in
                   ("setUpModule", "tearDownModule", "load_tests")):
                raise RuntimeError("native module fixture requires review")
            for name in ("setUpClass", "tearDownClass"):
                if getattr(cls, name).__func__ is not getattr(unittest.TestCase, name).__func__:
                    raise RuntimeError("native class fixture requires review")
    return cases


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("target", choices=TARGETS)
    parser.add_argument("--list", action="store_true")
    parser.add_argument("ids", nargs="*")
    args = parser.parse_args()
    cases = discover(args.target)
    ids = [case.id() for case in cases]
    if args.list:
        if args.ids:
            parser.error("--list cannot select tests")
        print(json.dumps(ids))
        return 0
    requested = set(args.ids)
    if not requested or len(requested) != len(args.ids) or not requested <= set(ids):
        raise RuntimeError("invalid test selection")
    if args.target == "github":
        # Keep each module whole, including its class/module fixtures.
        modules = {case.__class__.__module__ for case in cases if case.id() in requested}
        if {case.id() for case in cases if case.__class__.__module__ in modules} != requested:
            raise RuntimeError("GitHub module split is forbidden")
    selected = unittest.TestSuite(case for case in cases if case.id() in requested)
    result = unittest.TextTestRunner(verbosity=2).run(selected)
    return 0 if result.wasSuccessful() and result.testsRun == len(requested) else 1


if __name__ == "__main__":
    raise SystemExit(main())

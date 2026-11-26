"""Run independent offline suites in separate processes with bounded concurrency."""
import argparse
import hashlib
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
import subprocess
import sys
import tempfile
import time


def suite_commands(root, python, names):
    tests = root / "fortis_approvals/tests"
    if len(names) != len(set(names)):
        raise ValueError("duplicate mandatory suite")
    commands = []
    for directory in sorted(root.glob("fortis_approvals/integrations/*/tests")):
        if directory.is_dir():
            commands.append((directory.relative_to(root).as_posix(),
                [python, "-B", "-m", "unittest", "discover", "-s",
                 str(directory.relative_to(root)), "-p", "test_*.py", "-v"]))
    for name in names:
        if Path(name).name != name or not (tests / name).is_file():
            raise ValueError(f"missing or invalid mandatory suite: {name}")
        commands.append((name, [python, "-B", "-m", "unittest",
                         "discover", "-s", str(tests.relative_to(root)),
                         "-p", name, "-v"]))
    return commands


# Approximate local timings from #274; weights affect only scheduling.
WEIGHTS = {
    "test_intent_native_integration.py": 39,
    "test_registry_source_composition.py": 33,
    "test_registry_original_two_merges.py": 13,
    "test_r7_unified_candidate.py": 13,
    "test_github_file_pr.py": 10,
    "test_workspace_intents.py": 9,
    "test_github_ci_read.py": 9,
    "test_source_onboarding.py": 8,
    "test_registry_functional_review_runtime.py": 7,
    "fortis_approvals/integrations/action_core/tests": 10,
    "fortis_approvals/integrations/mirror/tests": 6,
}
SPLIT_TARGETS = {
    "fortis_approvals/integrations/github/tests": "github",
    "test_native_workflow.py": "native",
}


def expanded_commands(root, python, commands):
    weighted = []
    for label, command in commands:
        target = SPLIT_TARGETS.get(label)
        if target is None:
            weighted.append((WEIGHTS.get(label, 1), label, command))
            continue
        prefix = [python, "-B", "scripts/offline-test-selection.py", target]
        ids = json.loads(subprocess.check_output(prefix + ["--list"], cwd=root))
        if not ids or len(ids) != len(set(ids)):
            raise ValueError("invalid discovery: " + label)
        groups = {}
        for ident in ids:
            key = ident if target == "native" else ident.rsplit(".", 2)[0]
            groups.setdefault(key, []).append(ident)
        for key, members in groups.items():
            weight = 9 if target == "native" else max(1, 235 * len(members) / len(ids))
            weighted.append((weight, target + ":" + key, prefix + members))
    return weighted


def ordered_commands(weighted):
    labels = [label for _, label, _ in weighted]
    if not labels or len(labels) != len(set(labels)):
        raise ValueError("empty or duplicate work units")
    return [(label, command) for _, label, command in
            sorted(weighted, key=lambda x: (-x[0], x[1]))]


def run_suite(root, item):
    label, command = item
    start = time.monotonic()
    with tempfile.TemporaryFile() as output:
        try:
            result = subprocess.run(command, cwd=root, stdout=output,
                                    stderr=subprocess.STDOUT, check=False)
            status = result.returncode
        except OSError as exc:
            output.write(str(exc).encode())
            status = 1
        output.seek(0)
        log = output.read().decode("utf-8", errors="replace")
    if "Ran 0 tests" in log:
        status = 1
    return label, status, time.monotonic() - start, log


def run_all(root, commands, jobs):
    start = time.monotonic()
    failed = []
    count = 0
    with ThreadPoolExecutor(max_workers=jobs) as pool:
        futures = [pool.submit(run_suite, root, item) for item in commands]
        for future in as_completed(futures):
            label, status, seconds, log = future.result()
            count += 1
            print(f"=== {label} [{seconds:.2f}s] ===", flush=True)
            print(log, end="" if log.endswith("\n") else "\n", flush=True)
            if status:
                failed.append(label)
    print(f"OFFLINE_PYTHON suites={count}/{len(commands)} jobs={jobs} "
          f"failed={len(failed)} wall={time.monotonic()-start:.2f}s", flush=True)
    if failed:
        print("Failed suites: " + ", ".join(sorted(failed)), file=sys.stderr)
    return 1 if failed or count != len(commands) or not commands else 0


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--python", required=True)
    parser.add_argument("--jobs", type=int, choices=(1, 2, 3, 4), required=True)
    parser.add_argument("--plan-only", action="store_true")
    parser.add_argument("names", nargs="+")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    commands = suite_commands(root, args.python, args.names)
    if args.jobs > 1:
        commands = ordered_commands(expanded_commands(root, args.python, commands))
    digest = hashlib.sha256(json.dumps(commands, separators=(",", ":")).encode()).hexdigest()
    print("OFFLINE_PLAN units=" + str(len(commands)) + " sha256=" + digest, flush=True)
    if args.plan_only:
        return 0
    return run_all(root, commands, args.jobs)


if __name__ == "__main__":
    raise SystemExit(main())

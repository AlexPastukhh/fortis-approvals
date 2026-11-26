"""Run independent offline suites in separate processes with bounded concurrency."""
import argparse
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
    parser.add_argument("--jobs", type=int, choices=(1, 2), required=True)
    parser.add_argument("names", nargs="+")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    return run_all(root, suite_commands(root, args.python, args.names), args.jobs)


if __name__ == "__main__":
    raise SystemExit(main())

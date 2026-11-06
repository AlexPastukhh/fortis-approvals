"""Write public CI correlation metadata. Never reads credentials or scanner context."""
import argparse
import json
import os
from pathlib import Path
import subprocess

from ...github.analysis_contract import MANIFEST
from ...review_schema import require, sha


def build_manifest(*, environment, workflow_id, project_key, context, pr_head_sha,
                   checkout_sha, scanner_revision, report_text):
    require(type(report_text) is str and len(report_text.encode()) <= 8192)
    entries = {}
    for line in report_text.splitlines():
        if '=' not in line: continue
        key, value = line.split('=', 1)
        require(key not in entries, 'SONAR_REPORT_DUPLICATE_FIELD')
        entries[key] = value
    repository = environment['GITHUB_REPOSITORY']
    workflow_ref = environment['GITHUB_WORKFLOW_REF']
    prefix = repository + '/'
    require(workflow_ref.startswith(prefix) and '@' in workflow_ref, 'SONAR_WORKFLOW_REF_INVALID')
    result = dict(schemaVersion=1, repository=repository, workflowId=workflow_id,
        workflowPath=workflow_ref[len(prefix):].split('@', 1)[0],
        runId=int(environment['GITHUB_RUN_ID']), attempt=int(environment['GITHUB_RUN_ATTEMPT']),
        projectKey=project_key, context=context, prHeadSha=pr_head_sha,
        checkoutSha=checkout_sha, scannerRevision=scanner_revision, ceTaskId=entries.get('ceTaskId'))
    MANIFEST(result)
    require(('pullRequest' in context) == (pr_head_sha is not None), 'SONAR_MANIFEST_PR_CONTEXT')
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--workflow-id', type=int, required=True)
    parser.add_argument('--project-key', required=True)
    parser.add_argument('--report', default='.scannerwork/report-task.txt')
    parser.add_argument('--output', default='analysis-manifest.json')
    parser.add_argument('--scanner-revision', required=True,
                        help='The exact revision configured for this scan, not an inferred latest SHA')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--branch')
    group.add_argument('--pull-request')
    parser.add_argument('--pr-head-sha')
    args = parser.parse_args()
    # git rev-parse is read-only; no network, shell, helper or repository code.
    checkout = subprocess.run(['git', '-c', 'core.fsmonitor=false', 'rev-parse', 'HEAD'],
                              check=True, capture_output=True, text=True, timeout=10).stdout.strip()
    sha(checkout)
    path = Path(args.report)
    require(path.is_file() and not path.is_symlink() and path.stat().st_size <= 8192)
    context = {'pullRequest': args.pull_request} if args.pull_request else {'branch': args.branch}
    result = build_manifest(environment=os.environ, workflow_id=args.workflow_id,
        project_key=args.project_key, context=context, pr_head_sha=args.pr_head_sha,
        checkout_sha=checkout, scanner_revision=args.scanner_revision, report_text=path.read_text())
    # Refuse overwrite, including symlinks. Upload this one file, not scanner logs.
    with Path(args.output).open('x', encoding='utf-8') as output:
        json.dump(result, output, ensure_ascii=False, sort_keys=True)
        output.write('\n')


if __name__ == '__main__':
    main()

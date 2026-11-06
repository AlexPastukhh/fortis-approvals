"""Read-only CI/Sonar report composition and JSON CLI; never approves an ASK."""
import argparse
import json
from ..core import Denied
from ..integrations.review_schema import require, sha
from ..integrations.github.repo_client.client import GitHubClient
from ..integrations.sonarcloud.repo_client.analysis import SonarAnalysisClient
from .gateway_transport import GatewayTransport


class AnalysisReviewClient:
    def __init__(self, gateway=None):
        self.gateway = gateway or GatewayTransport(max_response_bytes=262144)
        self.github = GitHubClient(gateway=self.gateway)
        self.sonar = SonarAnalysisClient(self.gateway)

    def github_read(self, operation, repo, params):
        return self.github.read(operation, repo, params)['data']

    def get_ci_analysis_report(self, repository, *, run_id, attempt, artifact_id, expected_head_sha):
        sha(expected_head_sha)
        evidence = self.github_read('get_analysis_manifest', repository,
                    dict(runId=run_id, attempt=attempt, artifactId=artifact_id))
        run, m = evidence['run'], evidence['manifest']
        require(run['headSha'] == expected_head_sha, 'ANALYSIS_RUN_SHA_MISMATCH')
        if 'pullRequest' in m['context']:
            require(m['prHeadSha'] == expected_head_sha, 'ANALYSIS_PR_SHA_MISMATCH')
        else:
            require(m['prHeadSha'] is None and m['checkoutSha'] == expected_head_sha and
                    m['scannerRevision'] == expected_head_sha, 'ANALYSIS_BRANCH_SHA_MISMATCH')
        key = m['projectKey']
        task = self.sonar.read('get_analysis_task', key, {'taskId': m['ceTaskId']})
        report = dict(repository=run['repository'], run=run, manifest=m, task=task,
            binding='CI_METADATA_ONLY', gate=None, currentIssues=None, currentMeasures=None,
            contextFreshness='UNKNOWN', issuesComplete=False, limitations=[
              'CI metadata is not proof that the scanner inspected the recorded bytes.',
              'Current issues/measures are not a historical analysis snapshot.',
              'Quality Gate can change after issue triage without a new scan.'])
        if task['status'] != 'SUCCESS' or task['analysisId'] is None:
            report['state'] = 'ANALYSIS_' + task['status']; return report
        report['gate'] = self.sonar.read('get_quality_gate_details', key,
             dict(context={}, analysisId=task['analysisId'], taskId=task['id']))
        ctx = m['context']
        if 'pullRequest' not in ctx:
            latest = self.sonar.read('list_analyses', key, dict(context=ctx, page=1, pageSize=1))['items']
            if latest and latest[0]['key'] == task['analysisId'] and latest[0]['revision'] == m['scannerRevision']:
                report['binding'] = 'SONAR_REVISION_MATCH_CI_RECORDED'
                report['contextFreshness'] = 'LATEST_AT_READ'
            else:
                report['contextFreshness'] = 'STALE_OR_UNVERIFIED'
        # Expose useful current context even for a historical run, labelled
        # separately. Never silently treat these mutable pages as that run.
        report['currentIssues'] = self.sonar.read('search_issues', key,
            dict(context=ctx, page=1, pageSize=100, filters={'issueStatuses': ['OPEN', 'CONFIRMED']}))
        report['issuesComplete'] = not report['currentIssues']['hasMore']
        report['currentMeasures'] = self.sonar.read('get_measures', key,
            dict(context=ctx, metricKeys=['new_coverage', 'new_duplicated_lines_density',
                'new_reliability_rating', 'new_security_rating', 'new_maintainability_rating']))
        if report['contextFreshness'] == 'LATEST_AT_READ':
            after = self.sonar.read('list_analyses', key, dict(context=ctx, page=1, pageSize=1))['items']
            if not after or after[0]['key'] != task['analysisId']:
                report['contextFreshness'] = 'CHANGED_DURING_READ'
        report['state'] = 'ANALYSIS_PROCESSED'
        return report


def main():
    p = argparse.ArgumentParser(description='Typed analysis review through Gateway; JSON body on stdin')
    p.add_argument('service', choices=('sonar', 'github', 'report'))
    p.add_argument('operation')
    p.add_argument('--target', required=True)
    p.add_argument('--endpoint', default='https://host.docker.internal:19204')
    p.add_argument('--request-id')
    p.add_argument('--reason', default='Owner-requested analysis review')
    args = p.parse_args(); body = json.load(__import__('sys').stdin)
    client = AnalysisReviewClient(GatewayTransport(endpoint=args.endpoint, allow_test_endpoint=True, max_response_bytes=262144))
    if args.service == 'report':
        require(args.operation == 'get_ci_analysis_report')
        result = client.get_ci_analysis_report(args.target, **body)
    elif args.service == 'sonar':
        from ..integrations.sonarcloud.analysis_contract import ACTION_NAMES
        if args.operation in ACTION_NAMES | {'accept_issue'}:
            require(args.request_id is not None, 'STABLE_REQUEST_ID_REQUIRED')
            result = client.sonar.propose(args.operation, args.target, body, request_id=args.request_id, reason=args.reason)
        else: result = client.sonar.read(args.operation, args.target, body)
    else:
        from ..integrations.github.analysis_contract import ACTION_NAMES
        if args.operation in ACTION_NAMES:
            require(args.request_id is not None, 'STABLE_REQUEST_ID_REQUIRED')
            result = client.github.action(args.operation, args.target, body, request_id=args.request_id, reason=args.reason)
        else: result = client.github_read(args.operation, args.target, body)
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))


if __name__ == '__main__':
    main()

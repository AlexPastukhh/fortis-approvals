"""CI-only adapter/router: repository/workflow-scoped reads and ASK controls."""
import hashlib
import io
import zipfile
from urllib.parse import quote

from ....core import Denied, Stale, canonical
from ...review_schema import require, project, array, number, sha, strict_json
from ..analysis_contract import (READ_NAMES, ACTION_NAMES, RUN, JOB, ARTIFACT, CHECK,
                                ANNOTATION, MANIFEST, validate_read, validate_action, validate_result)
from .adapter import GitHubAdapter
from .transport import GitHubTransportError


class AnalysisGitHubAdapter(GitHubAdapter):
    def __init__(self, *args, bindings, **kwargs):
        super().__init__(*args, **kwargs)
        self.bindings = bindings

    def _workflow(self, repo, ident, path):
        workflows = self.bindings[repo]['workflows']
        require(type(ident) is int and str(ident) in workflows and workflows[str(ident)] == path,
                'GITHUB_ANALYSIS_WORKFLOW_DENIED')

    def _manifest_project_key(self, repo):
        return self.bindings[repo]['projectKey']

    def _ci_control_allowed(self, repo):
        return self.bindings[repo]['allowCiControl']

    def _run(self, repo, ident, attempt):
        raw = self._api('GET', self._path(repo, 'actions/runs/' + str(ident) + '/attempts/' + str(attempt)))
        require(type(raw) is dict and raw.get('id') == ident and raw.get('run_attempt') == attempt)
        require(raw.get('repository', {}).get('full_name') == self.owner + '/' + repo, 'GITHUB_RUN_REPOSITORY_MISMATCH')
        path = raw.get('path')
        require(type(path) is str)
        path = path.split('@', 1)[0]
        self._workflow(repo, raw.get('workflow_id'), path)
        out = dict(id=ident, attempt=attempt, workflowId=raw.get('workflow_id'), workflowPath=path,
            event=raw.get('event'), status=raw.get('status'), conclusion=raw.get('conclusion'),
            headSha=raw.get('head_sha'), headBranch=raw.get('head_branch'),
            repository=raw['repository']['full_name'], headRepository=raw.get('head_repository', {}).get('full_name'),
            createdAt=raw.get('created_at'), updatedAt=raw.get('updated_at'),
            pullRequests=[dict(number=x.get('number'), headSha=x.get('head', {}).get('sha'),
                               baseSha=x.get('base', {}).get('sha'))
                          for x in array(lambda x: x)(raw.get('pull_requests', []))])
        return RUN(out)

    def _job(self, repo, run, ident):
        raw = self._api('GET', self._path(repo, 'actions/jobs/' + str(ident)))
        require(type(raw) is dict and raw.get('id') == ident and raw.get('run_id') == run['id'] and
                raw.get('run_attempt') == run['attempt'] and raw.get('head_sha') == run['headSha'],
                'GITHUB_JOB_ATTEMPT_MISMATCH')
        return raw

    @staticmethod
    def _project_job(raw):
        require(type(raw) is dict)
        steps = [dict(number=x.get('number'), name=x.get('name'), status=x.get('status'),
                      conclusion=x.get('conclusion')) for x in array(lambda x: x, 200)(raw.get('steps', []))]
        return JOB(dict(id=raw.get('id'), name=raw.get('name'), status=raw.get('status'),
                        conclusion=raw.get('conclusion'), steps=steps))

    def _check(self, repo, p):
        raw = self._api('GET', self._path(repo, 'check-runs/' + str(p['checkRunId'])))
        require(type(raw) is dict and raw.get('id') == p['checkRunId'] and raw.get('head_sha') == p['expectedHeadSha'],
                'GITHUB_CHECK_SHA_MISMATCH')
        output = raw.get('output'); app = raw.get('app')
        require(type(output) is dict and type(app) is dict)
        return CHECK(dict(id=raw['id'], name=raw.get('name'), headSha=raw['head_sha'],
            status=raw.get('status'), conclusion=raw.get('conclusion'), appId=app.get('id'),
            appSlug=app.get('slug'), title=output.get('title'), summary=output.get('summary'),
            text=output.get('text'), annotationCount=output.get('annotations_count', 0)))

    def _artifact(self, repo, run, raw):
        require(type(raw) is dict)
        witness = raw.get('workflow_run')
        require(type(witness) is dict and witness.get('id') == run['id'] and
                witness.get('head_sha') == run['headSha'], 'GITHUB_ARTIFACT_RUN_MISMATCH')
        return ARTIFACT(dict(id=raw.get('id'), name=raw.get('name'), size=raw.get('size_in_bytes'),
                            expired=raw.get('expired'), digest=raw.get('digest'), createdAt=raw.get('created_at')))

    def read(self, request):
        repo = self._repo(request['target']); op = request['operation']; p = request['params']
        require(op in READ_NAMES)
        validate_read(op, p)
        if op in ('get_check_run', 'list_check_annotations'):
            check = self._check(repo, p)
            if op == 'get_check_run': data = dict(check=check)
            else:
                raw = self._api('GET', self._path(repo, 'check-runs/' + str(p['checkRunId']) + '/annotations'),
                                params={'page': p['page'], 'per_page': p['perPage']})
                require(type(raw) is list and len(raw) <= p['perPage'])
                rows = [ANNOTATION(dict(path=x.get('path'), startLine=x.get('start_line'), endLine=x.get('end_line'),
                        level=x.get('annotation_level'), message=x.get('message'), title=x.get('title'))) for x in raw]
                data = dict(check=check, items=rows, page=p['page'], perPage=p['perPage'],
                            complete=(p['page']-1)*p['perPage']+len(rows) >= check['annotationCount'])
        else:
            run = self._run(repo, p['runId'], p['attempt'])
            if op == 'get_workflow_run': data = dict(run=run)
            elif op in ('list_workflow_jobs', 'list_run_artifacts'):
                suffix = ('/attempts/' + str(p['attempt']) + '/jobs') if op == 'list_workflow_jobs' else '/artifacts'
                raw = self._api('GET', self._path(repo, 'actions/runs/' + str(p['runId']) + suffix),
                                params={'page': p['page'], 'per_page': p['perPage']})
                field = 'jobs' if op == 'list_workflow_jobs' else 'artifacts'
                require(type(raw) is dict and type(raw.get(field)) is list and len(raw[field]) <= p['perPage'])
                total = number(raw.get('total_count'), minimum=0)
                rows = []
                for x in raw[field]:
                    if field == 'jobs':
                        require(x.get('run_id') == run['id'] and x.get('head_sha') == run['headSha'] and
                                x.get('run_attempt') == run['attempt'], 'GITHUB_JOB_ATTEMPT_MISMATCH')
                        rows.append(self._project_job(x))
                    else: rows.append(self._artifact(repo, run, x))
                offset = (p['page']-1)*p['perPage']
                require(len(rows) == min(p['perPage'], max(0, total-offset)), 'GITHUB_CI_PAGE_INCOMPLETE')
                data = dict(run=run, items=rows, total=total, page=p['page'], perPage=p['perPage'],
                            complete=offset+len(rows) >= total)
            elif op == 'get_job_log':
                self._job(repo, run, p['jobId'])
                content = self.transport.download(self._path(repo, 'actions/jobs/' + str(p['jobId']) + '/logs'), maximum=2*1024*1024)
                decoded = self.transport.redact(content.decode('utf-8', 'replace'))
                lines = decoded.splitlines(); start = p['offsetLines']; stop = start + p['maxLines']
                selected = '\n'.join(lines[start:stop])
                # Never silently truncate a line or claim the returned page is complete.
                require(len(selected.encode()) <= 64000, 'GITHUB_LOG_PAGE_TOO_LARGE')
                data = dict(run=run, jobId=p['jobId'], offsetLines=start, text=selected,
                            hasMore=stop < len(lines), redacted=True)
            elif op == 'get_analysis_manifest':
                raw = self._api('GET', self._path(repo, 'actions/artifacts/' + str(p['artifactId'])))
                item = self._artifact(repo, run, raw)
                require(not item['expired'] and item['size'] <= 65536 and
                    item['name'] == 'fortis-sonar-analysis-' + str(run['id']) + '-' + str(run['attempt']),
                    'GITHUB_ANALYSIS_ARTIFACT_DENIED')
                content = self.transport.download(self._path(repo, 'actions/artifacts/' + str(item['id']) + '/zip'), maximum=65536)
                try:
                    with zipfile.ZipFile(io.BytesIO(content)) as archive:
                        entries = archive.infolist()
                        require(len(entries) == 1 and entries[0].filename == 'analysis-manifest.json' and
                            entries[0].file_size <= 16384 and not entries[0].flag_bits & 1,
                            'GITHUB_MANIFEST_ARCHIVE_DENIED')
                        raw_manifest = archive.read(entries[0])
                    manifest = strict_json(raw_manifest)
                except (ValueError, OSError, zipfile.BadZipFile, UnicodeError, RuntimeError):
                    raise Denied('GITHUB_MANIFEST_INVALID') from None
                if item['digest'] is not None:
                    require(item['digest'] == 'sha256:' + hashlib.sha256(content).hexdigest(),
                            'GITHUB_ARTIFACT_DIGEST_MISMATCH')
                MANIFEST(manifest)
                project_key = self._manifest_project_key(repo)
                require(manifest['repository'] == run['repository'] and manifest['workflowId'] == run['workflowId'] and
                    manifest['workflowPath'] == run['workflowPath'] and manifest['runId'] == run['id'] and
                    manifest['attempt'] == run['attempt'] and
                    (project_key is None or manifest['projectKey'] == project_key),
                    'GITHUB_MANIFEST_BINDING_MISMATCH')
                if 'pullRequest' in manifest['context']:
                    require(run['event'] == 'pull_request' and any(
                        str(x['number']) == manifest['context']['pullRequest'] and
                        x['headSha'] == manifest['prHeadSha'] == run['headSha']
                        for x in run['pullRequests']), 'GITHUB_MANIFEST_PR_CONTEXT_MISMATCH')
                else:
                    require(run['event'] in ('push', 'workflow_dispatch') and manifest['prHeadSha'] is None and
                            manifest['context'].get('branch') == run['headBranch'],
                            'GITHUB_MANIFEST_BRANCH_CONTEXT_MISMATCH')
                # Artifact contents are CI-recorded assertions, not cryptographic
                # proof of scanned bytes or Sonar confirmation of a revision.
                data = dict(run=run, artifactId=item['id'], manifest=manifest, trust='CI_RECORDED_NOT_SONAR_VERIFIED')
            else: raise Denied('GITHUB_ANALYSIS_READ_DENIED')
        return validate_result(op, dict(operation=op, data=data))

    def prepare(self, request):
        op, repo, p = request['operation'], self._repo(request['target']), request['params']
        require(op in ACTION_NAMES and self._ci_control_allowed(repo), 'GITHUB_CI_CONTROL_DISABLED')
        validate_action(op, p)
        if op == 'dispatch_analysis_workflow':
            workflow = self._api('GET', self._path(repo, 'actions/workflows/' + str(p['workflowId'])))
            require(type(workflow) is dict and workflow.get('state') == 'active' and workflow.get('id') == p['workflowId'])
            self._workflow(repo, p['workflowId'], workflow.get('path'))
            require(p['ref'] == 'main' or p['ref'].startswith('task/'), 'GITHUB_ANALYSIS_REF_DENIED')
            ref = self._ref(repo, p['ref']); actual = ref.get('object', {}).get('sha')
            if actual != p['expectedHeadSha']: raise Stale('GITHUB_ANALYSIS_REF_CHANGED')
            # Freeze the workflow blob at that exact commit as well as its ID.
            source = self._api('GET', self._path(repo, 'contents/' + quote(workflow['path'], safe='/-._~')),
                               params={'ref': actual})
            require(type(source) is dict and source.get('path') == workflow['path'] and source.get('type') == 'file')
            return dict(operation=op, repository=repo, workflowId=p['workflowId'], workflowPath=workflow['path'],
                        ref=p['ref'], headSha=sha(actual), workflowBlobSha=sha(source.get('sha')),
                        limitation='DISPATCH_REF_HAS_NO_ATOMIC_CAS')
        run = self._run(repo, p['runId'], p['attempt'])
        if run['headSha'] != p['expectedHeadSha']: raise Stale('GITHUB_RUN_SHA_CHANGED')
        latest = self._api('GET', self._path(repo, 'actions/runs/' + str(p['runId'])))
        if latest.get('run_attempt') != p['attempt']: raise Stale('GITHUB_RUN_ATTEMPT_CHANGED')
        require(run['headRepository'] == run['repository'], 'GITHUB_FORK_CONTROL_DENIED')
        if op == 'cancel_analysis_run': require(run['status'] in ('queued', 'in_progress', 'waiting', 'requested'))
        else: require(run['status'] == 'completed' and run['conclusion'] in ('failure', 'timed_out', 'cancelled'))
        job = None
        if op == 'rerun_job':
            job = self._project_job(self._job(repo, run, p['jobId']))
            require(job['conclusion'] in ('failure', 'timed_out', 'cancelled'))
        return dict(operation=op, repository=repo, run=run, job=job)

    def apply(self, request):
        prior = self.receipt(request['requestId'])
        if prior is not None: return prior
        preview = self.prepare(request); p = request['params']; repo = request['target']; op = request['operation']
        # Core has already compared the approved preview; recheck immediately
        # before POST. Provider still has no CAS, so an ambiguous POST is never retried.
        if self.prepare(request) != preview: raise Stale('GITHUB_ANALYSIS_PREVIEW_CHANGED')
        if op == 'dispatch_analysis_workflow':
            path = 'actions/workflows/' + str(p['workflowId']) + '/dispatches'
            body = {'ref': p['ref'], 'inputs': {}}
            expected = (204,)
        elif op == 'rerun_job':
            path = 'actions/jobs/' + str(p['jobId']) + '/rerun'; body = {'enable_debug_logging': False}; expected = (201,)
        else:
            suffix = 'rerun-failed-jobs' if op == 'rerun_failed_jobs' else 'cancel'
            path = 'actions/runs/' + str(p['runId']) + '/' + suffix; body = {}
            expected = (201,) if op == 'rerun_failed_jobs' else (202,)
        self._api('POST', self._path(repo, path), body=body, expected=expected)
        result = dict(requestId=request['requestId'], operation=op, repository=repo,
                      accepted=True, effect='PROVIDER_ACCEPTED_NOT_COMPLETED',
                      bindingSha256=hashlib.sha256(canonical(preview).encode()).hexdigest())
        self._save_receipt(request['requestId'], result)
        return result


class GitHubReviewRouter:
    """Extra repositories only receive CI operations, never native Git grants."""
    def __init__(self, review, existing=None):
        self.review, self.existing = review, existing

    def read(self, request):
        if request['operation'] in READ_NAMES: return self.review.read(request)
        require(self.existing is not None, 'GITHUB_BASE_PROFILE_DISABLED')
        return self.existing.read(request)

    def prepare(self, request):
        if request['operation'] in ACTION_NAMES: return self.review.prepare(request)
        require(self.existing is not None, 'GITHUB_BASE_PROFILE_DISABLED')
        return self.existing.prepare(request)

    def apply(self, request):
        if request['operation'] in ACTION_NAMES: return self.review.apply(request)
        require(self.existing is not None, 'GITHUB_BASE_PROFILE_DISABLED')
        return self.existing.apply(request)

    def receipt(self, request_id):
        return self.review.receipt(request_id) or (self.existing.receipt(request_id) if self.existing else None)

    def confirm(self, request_id, result):
        if type(result) is dict and result.get('operation') in ACTION_NAMES:
            return self.review.confirm(request_id, result)
        return self.existing is not None and self.existing.confirm(request_id, result)

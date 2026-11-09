"""Typed Repo-side GitHub client. Never contains or reads the GitHub token."""
import uuid

from ....core import Denied
from ....clients.gateway_transport import GatewayTransport
from ..contract import (
    validate_github_action, validate_github_read, validate_github_read_projection,
)
from ....repo_action_contract import validate_intent, validate_read_query


class GitHubClient:
    def __init__(self, gateway=None, *, endpoint=None, grant_path=None,
                 certificate_path=None, opener=None):
        if gateway is not None:
            self.gateway = gateway
        else:
            kwargs = {"opener": opener}
            if endpoint is not None:
                kwargs["endpoint"] = endpoint
            if grant_path is not None:
                kwargs["grant_path"] = grant_path
            if certificate_path is not None:
                kwargs["certificate_path"] = certificate_path
            self.gateway = GatewayTransport(**kwargs)
    @staticmethod
    def _request_id(value=None):
        ident = value or str(uuid.uuid4())
        try:
            canonical = str(uuid.UUID(ident))
        except (TypeError, ValueError, AttributeError):
            raise Denied("GITHUB_REQUEST_ID_INVALID") from None
        if canonical != ident:
            raise Denied("GITHUB_REQUEST_ID_INVALID")
        return ident

    def read(self, operation, target, params=None):
        body = {
            "requestId": self._request_id(), "service": "github",
            "operation": operation, "target": target,
            "params": {} if params is None else params,
            "reason": "Read GitHub repository or CI metadata",
        }
        validate_github_read(operation, target, body["params"])
        validate_read_query(body)
        result = self.gateway.post("/v1/reads", body)
        if (type(result) is not dict or
                set(result) != {"requestId", "service", "operation", "data"} or
                result["requestId"] != body["requestId"] or
                result["service"] != "github" or result["operation"] != operation or
                type(result["data"]) is not dict):
            raise Denied("GITHUB_GATEWAY_READ_RESPONSE_INVALID")
        validate_github_read_projection(operation, result["data"])
        return result["data"]

    def action(self, operation, target, params, *, request_id, reason):
        if request_id is None:
            raise Denied("GITHUB_STABLE_REQUEST_ID_REQUIRED")
        body = {
            "requestId": self._request_id(request_id), "service": "github",
            "operation": operation, "target": target, "params": params,
            "reason": reason,
        }
        validate_github_action(operation, target, params)
        validate_intent(body)
        result = self.gateway.post("/v1/actions", body, accept_202=True)
        if (type(result) is not dict or
                set(result) != {"requestId", "state"} or
                result["requestId"] != body["requestId"] or
                type(result["state"]) is not str):
            raise Denied("GITHUB_GATEWAY_ACTION_RESPONSE_INVALID")
        return result

    def status(self, request_id):
        ident = self._request_id(request_id)
        result = self.gateway.get_status(ident)
        if (type(result) is not dict or
                set(result) != {"requestId", "state"} or result["requestId"] != ident or
                result["state"] not in ("PENDING", "APPROVED", "DISPATCHED",
                                        "EXECUTED", "REJECTED", "DENIED",
                                        "EXPIRED", "STALE", "UNCERTAIN",
                                        "CLOSED_UNCONFIRMED")):
            raise Denied("GITHUB_GATEWAY_STATUS_RESPONSE_INVALID")
        return result

    def list_repositories(self, owner):
        return self.read("list_repositories", owner)

    def get_repository(self, repo):
        return self.read("get_repository", repo)

    def list_branches(self, repo, *, page=1, per_page=100):
        return self.read("list_branches", repo, {"page": page, "perPage": per_page})

    def get_file(self, repo, path, ref):
        return self.read("get_file", repo, {"path": path, "ref": ref})

    def list_commits(self, repo, *, page=1, per_page=30):
        return self.read("list_commits", repo, {"page": page, "perPage": per_page})

    def list_pull_requests(self, repo, *, state="open", page=1, per_page=30):
        return self.read("list_pull_requests", repo,
                         {"page": page, "perPage": per_page, "state": state})
    def get_pull_request(self, repo, number):
        return self.read("get_pull_request", repo, {"number": number})

    def list_workflow_runs(self, repo, *, page=1, per_page=30):
        return self.read("list_workflow_runs", repo, {"page": page, "perPage": per_page})

    def list_check_runs(self, repo, ref):
        return self.read("list_check_runs", repo, {"ref": ref})

    def get_commit_status(self, repo, ref):
        return self.read("get_commit_status", repo, {"ref": ref})

    # GitHub Actions analysis reads. Not dependent on SonarCloud.
    def get_workflow_run(self, repo, run_id, attempt):
        return self.read('get_workflow_run',repo,dict(runId=run_id,attempt=attempt))

    def list_workflow_jobs(self, repo, run_id, attempt, *, page=1, per_page=100):
        return self.read('list_workflow_jobs',repo,dict(
            runId=run_id,attempt=attempt,page=page,perPage=per_page))

    def get_job_log(self, repo, run_id, attempt, job_id, *, offset_lines=0, max_lines=200):
        return self.read('get_job_log',repo,dict(
            runId=run_id,attempt=attempt,jobId=job_id,
            offsetLines=offset_lines,maxLines=max_lines))

    def get_check_run(self, repo, check_run_id, expected_head_sha):
        return self.read('get_check_run',repo,dict(
            checkRunId=check_run_id,expectedHeadSha=expected_head_sha))

    def list_check_annotations(self, repo, check_run_id, expected_head_sha,
                               *, page=1, per_page=100):
        return self.read('list_check_annotations',repo,dict(
            checkRunId=check_run_id,expectedHeadSha=expected_head_sha,
            page=page,perPage=per_page))

    def list_run_artifacts(self, repo, run_id, attempt, *, page=1, per_page=100):
        return self.read('list_run_artifacts',repo,dict(
            runId=run_id,attempt=attempt,page=page,perPage=per_page))

    def get_analysis_manifest(self, repo, run_id, attempt, artifact_id):
        # CI-recorded Sonar metadata, never proof that Sonar analysed this SHA.
        return self.read('get_analysis_manifest',repo,dict(
            runId=run_id,attempt=attempt,artifactId=artifact_id))

    # CI changes require explicit trusted repo opt-in and owner ASK approval.
    def rerun_failed_jobs(self, repo, run_id, attempt, expected_head_sha, *,
                          request_id, reason):
        return self.action('rerun_failed_jobs',repo,dict(
            runId=run_id,attempt=attempt,expectedHeadSha=expected_head_sha),
            request_id=request_id,reason=reason)

    def rerun_job(self, repo, run_id, attempt, job_id, expected_head_sha, *,
                  request_id, reason):
        return self.action('rerun_job',repo,dict(
            runId=run_id,attempt=attempt,jobId=job_id,expectedHeadSha=expected_head_sha),
            request_id=request_id,reason=reason)

    def cancel_analysis_run(self, repo, run_id, attempt, expected_head_sha, *,
                            request_id, reason):
        return self.action('cancel_analysis_run',repo,dict(
            runId=run_id,attempt=attempt,expectedHeadSha=expected_head_sha),
            request_id=request_id,reason=reason)

    def dispatch_analysis_workflow(self, repo, workflow_id, ref, expected_head_sha, *,
                                   request_id, reason):
        return self.action('dispatch_analysis_workflow',repo,dict(
            workflowId=workflow_id,ref=ref,expectedHeadSha=expected_head_sha),
            request_id=request_id,reason=reason)

    def create_branch(self, repo, branch, source_sha, *, request_id, reason):
        return self.action("create_branch", repo,
                           {"branch": branch, "sourceSha": source_sha},
                           request_id=request_id, reason=reason)

    def push_files(self, repo, branch, expected_head_sha, message, files,
                   *, request_id, reason):
        return self.action("push_files", repo, {
            "branch": branch, "expectedHeadSha": expected_head_sha,
            "message": message, "files": files,
        }, request_id=request_id, reason=reason)

    def create_pull_request(self, repo, head, base, title, body="", draft=False,
                            *, request_id, reason):
        return self.action("create_pull_request", repo, {
            "head": head, "base": base, "title": title,
            "body": body, "draft": draft,
        }, request_id=request_id, reason=reason)

    def push_commits(self, repo, task, artifact_sha256, expected_head_sha, new_sha, *, request_id, reason):
        return self.action("push_commits",repo,dict(task=task,artifactSha256=artifact_sha256,
            expectedHeadSha=expected_head_sha,newSha=new_sha),request_id=request_id,reason=reason)

    def mark_pr_ready(self, repo, number, expected_head_sha, *, request_id, reason):
        return self.action("mark_pr_ready",repo,dict(number=number,expectedHeadSha=expected_head_sha),
            request_id=request_id,reason=reason)

    def merge_pull_request(self, repo, number, expected_head_sha,
                           merge_method="squash", *, request_id, reason):
        return self.action("merge_pull_request", repo, {
            "number": number, "expectedHeadSha": expected_head_sha,
            "mergeMethod": merge_method,
        }, request_id=request_id, reason=reason)

    def update_workflow_file(self, repo, branch, path, expected_head_sha,
                             expected_file_sha, message, content,
                             *, request_id, reason):
        return self.action("update_workflow_file", repo, {
            "branch": branch, "path": path, "expectedHeadSha": expected_head_sha,
            "expectedFileSha": expected_file_sha, "message": message,
            "content": content,
        }, request_id=request_id, reason=reason)

    def dispatch_workflow(self, repo, workflow_id, ref, inputs,
                          *, request_id, reason):
        return self.action("dispatch_workflow", repo, {
            "workflowId": workflow_id, "ref": ref, "inputs": inputs,
        }, request_id=request_id, reason=reason)

    def rerun_workflow(self, repo, run_id, *, request_id, reason):
        return self.action("rerun_workflow", repo, {"runId": run_id},
                           request_id=request_id, reason=reason)

    def cancel_workflow(self, repo, run_id, *, request_id, reason):
        return self.action("cancel_workflow", repo, {"runId": run_id},
                           request_id=request_id, reason=reason)

    def approve_workflow_run(self, repo, run_id, *, request_id, reason):
        return self.action("approve_workflow_run", repo, {"runId": run_id},
                           request_id=request_id, reason=reason)

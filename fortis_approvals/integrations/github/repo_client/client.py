"""Typed Repo-side GitHub client. Never contains or reads the GitHub token."""
import uuid
import base64
import hashlib
import os
import stat
from pathlib import Path

from ....core import Denied, canonical
from ....clients.gateway_transport import GatewayTransport
from ..contract import (
    validate_github_action, validate_github_read, validate_github_read_projection,
)
from ....repo_action_contract import validate_intent, validate_read_query


WORKFILES_ROOT = Path('/workspace/repo/Workfiles')


class GitHubClient:
    def __init__(self, gateway=None, *, endpoint=None, grant_path=None,
                 certificate_path=None, opener=None):
        self.intent_client = None
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

    def read(self, operation, target, params=None, *, request_id=None):
        # For ASK reads, reuse the exact request_id returned by the first
        # PENDING call after the owner has approved it. Never generate a new
        # request identity when consuming an existing one-use approval.
        body = {
            "requestId": self._request_id(request_id), "service": "github",
            "operation": operation, "target": target,
            "params": {} if params is None else params,
            "reason": "Read GitHub repository or CI metadata",
        }
        validate_github_read(operation, target, body["params"])
        validate_read_query(body)
        result = self.gateway.post("/v1/reads", body, accept_202=True)
        if (type(result) is dict and
                set(result)=={"requestId","service","operation","state"} and
                result["requestId"]==body["requestId"] and
                result["service"]=="github" and
                result["operation"]==operation and
                result["state"] in ("PENDING","REJECTED","EXPIRED","STALE")):
            return result
        if (type(result) is not dict or
                set(result) != {"requestId", "service", "operation", "data"} or
                result["requestId"] != body["requestId"] or
                result["service"] != "github" or result["operation"] != operation or
                type(result["data"]) is not dict):
            raise Denied("GITHUB_GATEWAY_READ_RESPONSE_INVALID")
        validate_github_read_projection(operation, result["data"])
        return result["data"]

    def action(self, operation, target, params, *, request_id=None, reason):
        if self.intent_client is not None:
            from ....workflow.intents import GITHUB_COMMANDS
            if operation in GITHUB_COMMANDS:
                validate_github_action(operation, target, params)
                return self.intent_client.github_action(operation, target, params,
                                                        request_id=request_id, reason=reason)
        return self._action_once(operation, target, params, request_id=request_id, reason=reason)

    def _action_once(self, operation, target, params, *, request_id, reason):
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
                                        "CLOSED_UNCONFIRMED", "CANCELLED_BEFORE_DISPATCH")):
            raise Denied("GITHUB_GATEWAY_STATUS_RESPONSE_INVALID")
        return result

    def _visual_payload(self, *, repository, run_id, title, description, media,
                        qa_summary, duration_seconds):
        # Pure local validation; no Gateway request or upstream write.
        # Always re-read the PNG bytes when publishing to detect changes.
        if repository!='visual-workspace' or type(media) is not list or not 1<=len(media)<=5:
            raise Denied('GITHUB_VISUAL_REVIEW_MEDIA_INVALID')
        root=WORKFILES_ROOT
        if not root.is_absolute() or root.is_symlink() or not root.is_dir():
            raise Denied('GITHUB_VISUAL_REVIEW_ROOT_DENIED')
        root=root.resolve(strict=True)
        staged=[]
        for index,item in enumerate(media):
            if type(item) is not dict or set(item)!={'path','name'} or type(item['path']) is not str:
                raise Denied('GITHUB_VISUAL_REVIEW_MEDIA_INVALID')
            file=Path(item['path'])
            if not file.is_absolute() or file.suffix.lower()!='.png':
                raise Denied('GITHUB_VISUAL_REVIEW_PATH_DENIED')
            try:
                relative=file.relative_to(root)
                if run_id not in relative.parts[:-1] or any(part in ('', '.', '..') for part in relative.parts):
                    raise ValueError('scope')
                # Pin every directory and the final regular file with O_NOFOLLOW.
                # A symlink swap between a Path check and open must never read secrets.
                flags=os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC
                fd=os.open(root,flags|os.O_DIRECTORY)
                try:
                    for part in relative.parts[:-1]:
                        next_fd=os.open(part,flags|os.O_DIRECTORY,dir_fd=fd)
                        os.close(fd);fd=next_fd
                    leaf=os.open(relative.parts[-1],flags,dir_fd=fd)
                    try:
                        info=os.fstat(leaf)
                        if not stat.S_ISREG(info.st_mode) or not 24<=info.st_size<=10*1024*1024:
                            raise ValueError('file')
                        with os.fdopen(leaf,'rb',closefd=False) as stream:
                            data=stream.read(10*1024*1024+1)
                        if len(data)!=info.st_size or len(data)>10*1024*1024:
                            raise ValueError('changed')
                    finally:os.close(leaf)
                finally:os.close(fd)
            except (OSError,ValueError):
                raise Denied('GITHUB_VISUAL_REVIEW_PATH_DENIED') from None
            if not data.startswith(b'\x89PNG\r\n\x1a\n') or data[12:16]!=b'IHDR':
                raise Denied('GITHUB_VISUAL_REVIEW_NOT_PNG')
            digest=hashlib.sha256(data).hexdigest()
            staged.append((dict(index=index,name=item['name'],sha256=digest,size=len(data)),data))
        params=dict(runId=run_id,title=title,description=description,
                    qaSummary=qa_summary,durationSeconds=duration_seconds,
                    media=[row for row,_ in staged])
        validate_github_action('publish_visual_review',repository,params)
        return params,staged

    def prepare_visual_review(self, *, repository, run_id, title, description,
                              media, qa_summary, duration_seconds):
        """Local read-only PNG preview. Hash binds business data and actual bytes.

        Nothing is staged at Gateway. Preserve stable runId and requestId for
        later publication; preview alone never authorizes an upstream write.
        """
        params,_=self._visual_payload(
            repository=repository,run_id=run_id,title=title,description=description,
            media=media,qa_summary=qa_summary,duration_seconds=duration_seconds)
        return dict(repository=repository,runId=run_id,
                    media=params['media'],
                    payloadSha256=hashlib.sha256(canonical(params).encode()).hexdigest())

    def publish_visual_review(self, *, repository, run_id, title, description, media,
                              qa_summary, duration_seconds, request_id=None, reason,
                              expected_payload_sha256=None):
        kwargs=dict(repository=repository,run_id=run_id,title=title,description=description,
                    media=media,qa_summary=qa_summary,duration_seconds=duration_seconds,
                    expected_payload_sha256=expected_payload_sha256)
        if self.intent_client is not None:
            return self.intent_client.publish_visual_review(**kwargs,
                request_id=request_id,reason=reason)
        return self._publish_visual_review_once(**kwargs,request_id=request_id,reason=reason)

    def prepare_visual_revision(self, *, repository, issue_number, base_run_id,
                                asset_id, revision, run_id, source_sha, description,
                                media, qa_summary, duration_seconds):
        """Read-only local preview binding version metadata to exact PNG bytes."""
        old,rows=self._visual_payload(repository=repository,run_id=run_id,
            title='Visual revision',description=description,media=media,
            qa_summary=qa_summary,duration_seconds=duration_seconds)
        params=dict(issueNumber=issue_number,baseRunId=base_run_id,assetId=asset_id,
                    revision=revision,runId=run_id,sourceSha=source_sha,
                    description=description,qaSummary=qa_summary,
                    durationSeconds=duration_seconds,media=old['media'])
        validate_github_action('append_visual_revision',repository,params)
        return dict(repository=repository,runId=run_id,issueNumber=issue_number,
                    revision=revision,media=params['media'],
                    payloadSha256=hashlib.sha256(canonical(params).encode()).hexdigest())

    def append_visual_revision(self, *, repository, issue_number, base_run_id,
                               asset_id, revision, run_id, source_sha, description,
                               media, qa_summary, duration_seconds, request_id,
                               reason, expected_payload_sha256=None):
        """Stage PNGs and send one owner-policy-controlled GitHub comment intent.

        Never automatically retry a lost comment POST: the Gateway permanently
        reserves the logical revision before the first upstream side effect.
        """
        ident=self._request_id(request_id)
        # Re-read actual bytes, exactly like the existing PNG publisher.
        old,staged=self._visual_payload(repository=repository,run_id=run_id,
            title='Visual revision',description=description,media=media,
            qa_summary=qa_summary,duration_seconds=duration_seconds)
        params=dict(issueNumber=issue_number,baseRunId=base_run_id,assetId=asset_id,
                    revision=revision,runId=run_id,sourceSha=source_sha,
                    description=description,qaSummary=qa_summary,
                    durationSeconds=duration_seconds,media=old['media'])
        validate_github_action('append_visual_revision',repository,params)
        payload_digest=hashlib.sha256(canonical(params).encode()).hexdigest()
        if expected_payload_sha256 is not None and (
                type(expected_payload_sha256) is not str or
                expected_payload_sha256!=payload_digest):
            raise Denied('GITHUB_VISUAL_REVISION_PREVIEW_CHANGED')
        validate_intent(dict(requestId=ident,service='github',
            operation='append_visual_revision',target=repository,params=params,
            reason=reason))
        for row,data in staged:
            reply=self.gateway.post('/v1/github/visual-review/stage',dict(
                requestId=ident,repository=repository,runId=run_id,
                index=row['index'],name=row['name'],sha256=row['sha256'],
                data=base64.b64encode(data).decode('ascii')))
            if reply != row:
                raise Denied('GITHUB_VISUAL_REVISION_STAGE_RESPONSE_INVALID')
        # Do not send through a generic operation-retry loop. ASK still requires
        # owner WebAuthn; no Core grant => explicit DENY.
        return self._action_once('append_visual_revision',repository,params,
                                 request_id=ident,reason=reason)

    def _publish_visual_review_once(self, *, repository, run_id, title, description, media,
                              qa_summary, duration_seconds, request_id, reason,
                              expected_payload_sha256=None, publication_run_id=None):
        """Stage trusted PNG bytes via machine TLS, then submit typed action once."""
        if request_id is None:
            raise Denied('GITHUB_STABLE_REQUEST_ID_REQUIRED')
        ident=self._request_id(request_id)
        params,staged=self._visual_payload(
            repository=repository,run_id=run_id,title=title,description=description,
            media=media,qa_summary=qa_summary,duration_seconds=duration_seconds)
        if expected_payload_sha256 is not None:
            if (type(expected_payload_sha256) is not str or
                    len(expected_payload_sha256)!=64 or
                    any(ch not in '0123456789abcdef' for ch in expected_payload_sha256) or
                    hashlib.sha256(canonical(params).encode()).hexdigest()!=expected_payload_sha256):
                raise Denied('GITHUB_VISUAL_REVIEW_PREVIEW_CHANGED')
        if publication_run_id is not None:
            params['runId']=publication_run_id
        validate_intent(dict(requestId=ident,service='github',operation='publish_visual_review',
                             target=repository,params=params,reason=reason))
        # Retry policy lives in IntentClient; this primitive stages/submits once.
        for row,data in staged:
            reply=self.gateway.post('/v1/github/visual-review/stage',dict(
                requestId=ident,repository=repository,runId=params['runId'],
                index=row['index'],name=row['name'],sha256=row['sha256'],
                data=base64.b64encode(data).decode('ascii')))
            if reply != row:
                raise Denied('GITHUB_VISUAL_REVIEW_STAGE_RESPONSE_INVALID')
        return self._action_once('publish_visual_review',repository,params,
                           request_id=ident,reason=reason)

    def list_repositories(self, owner):
        return self.read("list_repositories", owner)

    def get_repository(self, repo):
        return self.read("get_repository", repo)

    def list_repository_labels(self, repo, *, page=1, per_page=50):
        return self.read("list_repository_labels",repo,
                         {"page":page,"perPage":per_page})

    def list_pr_labels(self, repo, number, *, page=1, per_page=50):
        return self.read("list_pr_labels",repo,
                         {"number":number,"page":page,"perPage":per_page})

    # P4 source-only READ candidate. Calls remain DENIED until separate
    # owner-reviewed native actor grants and Gateway image rollout.
    def list_deployments(self, repo, *, page=1, per_page=30, sha=None, environment=None):
        return self.read("list_deployments", repo, {
            "page": page, "perPage": per_page, "sha": sha, "environment": environment})

    def get_deployment(self, repo, deployment_id):
        return self.read("get_deployment", repo, {"deploymentId": deployment_id})

    def list_deployment_statuses(self, repo, deployment_id, *, page=1, per_page=30):
        return self.read("list_deployment_statuses", repo, {
            "deploymentId": deployment_id, "page": page, "perPage": per_page})

    def get_deployment_status(self, repo, deployment_id, status_id):
        return self.read("get_deployment_status", repo, {
            "deploymentId": deployment_id, "statusId": status_id})

    def list_cd_projection_inventory(self, repo, target, environment, *,
                                     per_page=10, max_pages=3,
                                     max_status_pages=3):
        """Bounded READ-only GitHub projection snapshot, never installed truth.

        Completeness is only over requested GitHub list pages at observation
        time; error, missing permission, exhaustion or drift means UNKNOWN to
        callers. The actual installed version and merged PR lineage are NEVER
        inferred from provider projection/status or client-provided fields.
        """
        import re
        slug = r"[a-z0-9][a-z0-9-]{0,62}"
        if (type(target) is not str or re.fullmatch(slug, target) is None or
                type(environment) is not str or re.fullmatch(slug, environment) is None or
                type(per_page) is not int or not 1 <= per_page <= 10 or
                type(max_pages) is not int or not 1 <= max_pages <= 3 or
                type(max_status_pages) is not int or not 1 <= max_status_pages <= 3):
            raise Denied("GITHUB_CD_INVENTORY_SCOPE_DENIED")
        namespace = "fortis-cd/" + target + "/" + environment

        def scan(fetch, limit):
            rows = []
            seen_ids = set()
            first = None
            for page in range(1, limit + 1):
                result = fetch(page)
                # Every typed READ was individually validated at the broker.
                # Enforce cross-page consistency in addition to DTO shape.
                if (result.get("page") != page or result.get("perPage") != per_page or
                        result.get("evidenceClass") != "GITHUB_PROJECTION_ONLY"):
                    raise Denied("GITHUB_CD_INVENTORY_PAGE_CHANGED")
                if first is None:
                    first = result
                for row in result["items"]:
                    ident = row["id"]
                    if ident in seen_ids:
                        raise Denied("GITHUB_CD_INVENTORY_DUPLICATE")
                    seen_ids.add(ident)
                    rows.append(row)
                if not result["hasNextPage"]:
                    break
            else:
                raise Denied("GITHUB_CD_INVENTORY_LIMIT_UNKNOWN")
            if fetch(1) != first:
                raise Denied("GITHUB_CD_INVENTORY_RACE_UNKNOWN")
            return rows, first

        def deployment_page(page):
            return self.list_deployments(repo,page=page,per_page=per_page,
                                         sha=None,environment=namespace)

        deployments, deployment_first = scan(deployment_page,max_pages)
        projections = []
        projection_ids = set()
        for row in deployments:
            data = row["payload"]
            if (row["environment"] != namespace or data["target"] != target or
                    data["environment"] != environment):
                raise Denied("GITHUB_CD_INVENTORY_TARGET_MISMATCH")
            if data["projectionId"] in projection_ids:
                # Repeated/uncertain publisher effect: never collapse attempts.
                raise Denied("GITHUB_CD_INVENTORY_REPEATED_PROJECTION_UNKNOWN")
            projection_ids.add(data["projectionId"])
            detail = self.get_deployment(repo,row["id"])
            if (detail.get("evidenceClass") != "GITHUB_PROJECTION_ONLY" or
                    detail["deployment"] != row):
                raise Denied("GITHUB_CD_INVENTORY_DEPLOYMENT_CHANGED")

            def status_page(page):
                return self.list_deployment_statuses(
                    repo,row["id"],page=page,per_page=per_page)
            statuses, status_first = scan(status_page,max_status_pages)
            if any(item["deploymentId"] != row["id"] or
                   item["environment"] != namespace for item in statuses):
                raise Denied("GITHUB_CD_INVENTORY_STATUS_MISMATCH")
            if status_first["deploymentId"] != row["id"]:
                raise Denied("GITHUB_CD_INVENTORY_STATUS_MISMATCH")
            # A status can appear after page scan; recheck this exact deployment.
            if self.get_deployment(repo,row["id"])["deployment"] != row:
                raise Denied("GITHUB_CD_INVENTORY_DEPLOYMENT_CHANGED")
            projections.append({
                "deploymentId":row["id"],
                "projectionId":data["projectionId"],
                "desiredSourceSha":data["desiredSourceSha"],
                "catalogShaClaimed":data["catalogSha"],
                "buildUnitClaimed":data["buildUnit"],
                "artifactDigestClaimed":data["artifactDigest"],
                "actionsClaimed":list(data["actions"]),
                "linkedPRsClaimed":list(data["linkedPRs"]),
                "observedGitHubStatuses":[item["state"] for item in statuses],
                "retainedGitHubStatusCount":len(statuses),
                "fortisState":"UNKNOWN",
                "actualInstalledVersion":None,
            })
        if deployment_page(1) != deployment_first:
            raise Denied("GITHUB_CD_INVENTORY_RACE_UNKNOWN")
        return dict(repository=repo,target=target,environment=environment,
                    evidenceClass="GITHUB_PROJECTION_ONLY",
                    paginationComplete=True,atomicSnapshot=False,
                    actualInstalledVersion=None,actualState="UNKNOWN",
                    items=projections)

    def get_pr_release_label_context(self, repo, number):
        """Read SHA/body and complete-label fingerprints for exact-head ASK writes."""
        return self.read("get_pr_release_label_context",repo,{"number":number})

    def get_pr_release_impact_evidence(self, repo, number, expected_head_sha):
        """Read-only exact-head bounded PR body/provenance for trusted planning.

        This is NOT label-write permission or proof of successful CI.
        """
        return self.read("get_pr_release_impact_evidence", repo, {
            "number": number, "expectedHeadSha": expected_head_sha})

    def create_release_label(self, repo, name, *, request_id, reason):
        """ASK: create one strictly managed label with server-chosen styling."""
        return self.action("create_release_label",repo,{"name":name},
                           request_id=request_id,reason=reason)

    def add_pr_release_labels(self, repo, number, expected_head_sha, expected_base_sha,
                              expected_body_sha256, expected_labels_sha256, labels,
                              *, request_id=None, reason):
        """ASK: additive GitHub labels; never replaces human label list."""
        return self.action("add_pr_release_labels",repo,{
            "number":number,"expectedHeadSha":expected_head_sha,
            "expectedBaseSha":expected_base_sha,
            "expectedBodySha256":expected_body_sha256,
            "expectedLabelsSha256":expected_labels_sha256,
            "labels":labels},request_id=request_id,reason=reason)

    def remove_pr_release_label(self, repo, number, expected_head_sha, expected_base_sha,
                                expected_body_sha256, expected_labels_sha256, name,
                                *, request_id=None, reason):
        """ASK: remove one managed label, never sticky owner-review marker."""
        return self.action("remove_pr_release_label",repo,{
            "number":number,"expectedHeadSha":expected_head_sha,
            "expectedBaseSha":expected_base_sha,
            "expectedBodySha256":expected_body_sha256,
            "expectedLabelsSha256":expected_labels_sha256,
            "name":name},request_id=request_id,reason=reason)

    def list_branches(self, repo, *, page=1, per_page=100):
        return self.read("list_branches", repo, {"page": page, "perPage": per_page})

    def get_branch(self, repo, branch):
        result = self.read("get_branch", repo, {"branch": branch})
        if result["found"] and result["branch"]["name"] != branch:
            raise Denied("GITHUB_BRANCH_RESPONSE_INVALID")
        return result

    def find_pull_requests(self, repo, head, base="main", *, page=1, per_page=50):
        result = self.read("find_pull_requests", repo,
            {"head": head, "base": base, "page": page, "perPage": per_page})
        if (result["page"] != page or result["perPage"] != per_page or
                any(row["head"]["ref"] != head or row["base"]["ref"] != base
                    for row in result["items"])):
            raise Denied("GITHUB_PR_SEARCH_IDENTITY_INVALID")
        return result

    def get_file(self, repo, path, ref):
        return self.read("get_file", repo, {"path": path, "ref": ref})

    def list_commits(self, repo, *, page=1, per_page=30):
        return self.read("list_commits", repo, {"page": page, "perPage": per_page})

    def list_issues(self, repo, *, state="all", page=1, per_page=30):
        return self.read("list_issues",repo,{"page":page,"perPage":per_page,"state":state})

    def get_issue(self, repo, number):
        return self.read("get_issue",repo,{"number":number})

    def list_issue_comments(self, repo, number, *, page=1, per_page=30):
        return self.read("list_issue_comments",repo,{"number":number,"page":page,"perPage":per_page})

    def find_visual_review_run(self, repo, run_id, *, max_pages=10):
        """Find an Issue claiming this run marker; absence is not retry authorization."""
        if (type(run_id) is not str or not __import__('re').fullmatch(
                r'[A-Za-z0-9][A-Za-z0-9_-]{0,79}',run_id) or
                type(max_pages) is not int or not 1 <= max_pages <= 10):
            raise Denied('GITHUB_VISUAL_REVIEW_LOOKUP_INVALID')
        for page in range(1,max_pages+1):
            listing=self.list_issues(repo,state='all',page=page,per_page=30)
            for issue in listing['items']:
                if issue['runIdMarker']==run_id:
                    detail=self.get_issue(repo,issue['number'])
                    if detail['found'] and detail['issue']['runIdMarker']==run_id:
                        return dict(found=True,complete=True,issue=detail['issue'])
            if not listing['hasNextPage']:
                return dict(found=False,complete=True,issue=None)
        return dict(found=False,complete=False,issue=None)

    def list_pull_requests(self, repo, *, state="open", page=1, per_page=30):
        return self.read("list_pull_requests", repo,
                         {"page": page, "perPage": per_page, "state": state})
    def get_pull_request(self, repo, number):
        return self.read("get_pull_request", repo, {"number": number})

    def list_head_workflow_runs(self, repo, head_sha, *, page=1, per_page=20):
        return self.read("list_head_workflow_runs", repo, {
            "headSha": head_sha, "page": page, "perPage": per_page})

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

    def create_branch(self, repo, branch, source_sha, *, request_id=None, reason):
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
                            *, request_id=None, reason):
        return self.action("create_pull_request", repo, {
            "head": head, "base": base, "title": title,
            "body": body, "draft": draft,
        }, request_id=request_id, reason=reason)

    def push_commits(self, repo, task, artifact_sha256, expected_head_sha, new_sha, *, request_id, reason):
        return self.action("push_commits",repo,dict(task=task,artifactSha256=artifact_sha256,
            expectedHeadSha=expected_head_sha,newSha=new_sha),request_id=request_id,reason=reason)

    def mark_pr_ready(self, repo, number, expected_head_sha, *, request_id=None, reason):
        return self.action("mark_pr_ready",repo,dict(number=number,expectedHeadSha=expected_head_sha),
            request_id=request_id,reason=reason)

    def update_pull_request(self, repo, number, expected_head_sha, body, *, request_id=None, reason):
        """ASK to replace only the description of an open, registered PR."""
        return self.action("update_pull_request", repo, {
            "number": number, "expectedHeadSha": expected_head_sha,
            "body": body,
        }, request_id=request_id, reason=reason)

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

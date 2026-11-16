"""Closed GitHub operation catalogue and strict request/response contracts.

No GitHub credential, network transport or policy is defined here. All
operations are denied by Core until a trusted owner explicitly registers
actor grants and ALLOW/ASK policy for them.
"""
import hashlib
import re
from urllib.parse import urlsplit

from ...core import Denied
from .release_label_contract import managed, checked_names, label_definition

from .analysis_contract import READS as ANALYSIS_READS, ACTIONS as ANALYSIS_ACTIONS, READ_NAMES as ANALYSIS_READ_NAMES, ACTION_NAMES as ANALYSIS_ACTION_NAMES, validate_read as validate_analysis_read, validate_action as validate_analysis_action, validate_result as validate_analysis_result

GITHUB_READ_OPERATIONS = frozenset({
    ("github", "list_repositories"), ("github", "get_repository"),
    ("github", "list_branches"), ("github", "get_branch"),
    ("github", "find_pull_requests"), ("github", "list_commits"), ("github", "get_file"),
    ("github", "list_pull_requests"), ("github", "get_pull_request"),
    ("github", "list_issues"), ("github", "get_issue"),
    ("github", "list_issue_comments"),
    ("github", "list_repository_labels"), ("github", "list_pr_labels"),
    ("github", "get_pr_release_label_context"),
    ("github", "get_pr_release_impact_evidence"),
    ("github", "list_workflow_runs"), ("github", "list_check_runs"),
    ("github", "get_commit_status"),
})
GITHUB_ACTION_OPERATIONS = frozenset({
    ("github", "create_branch"), ("github", "push_files"), ("github", "push_commits"), ("github", "mark_pr_ready"), ("github", "create_pull_request"),
    ("github", "merge_pull_request"), ("github", "update_pull_request"), ("github", "update_workflow_file"),
    ("github", "dispatch_workflow"), ("github", "rerun_workflow"),
    ("github", "cancel_workflow"), ("github", "approve_workflow_run"),
    ("github", "publish_visual_review"), ("github", "append_visual_revision"),
    ("github", "create_release_label"), ("github", "add_pr_release_labels"),
    ("github", "remove_pr_release_label"),
})
LEGACY_READ_OPERATIONS = GITHUB_READ_OPERATIONS
# Additive P3 transport. Registration never inherits a legacy actor ALLOW.
HEAD_READ_OPERATIONS = frozenset({("github", "list_head_workflow_runs")})
GITHUB_READ_OPERATIONS = GITHUB_READ_OPERATIONS | ANALYSIS_READS | HEAD_READ_OPERATIONS
GITHUB_ACTION_OPERATIONS = GITHUB_ACTION_OPERATIONS | ANALYSIS_ACTIONS
_REPO = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,99}")
_BRANCH = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,199}")
_SHA = re.compile(r"[0-9a-f]{40}")
_SLUG = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,99}")
def _repo(target):
    if type(target) is not str or not _REPO.fullmatch(target) or target in (".", ".."):
        raise Denied("GITHUB_REPOSITORY_TARGET_DENIED")


def _branch(value):
    if (type(value) is not str or not _BRANCH.fullmatch(value) or
            value.startswith("/") or value.endswith("/") or value.endswith(".") or
            "//" in value or ".." in value or "@{" in value or
            any(part.startswith(".") or part.endswith(".lock")
                for part in value.split("/"))):
        raise Denied("GITHUB_BRANCH_INVALID")


def _sha(value):
    if type(value) is not str or not _SHA.fullmatch(value):
        raise Denied("GITHUB_SHA_INVALID")


def _page(params):
    if (set(params) != {"page", "perPage"} or
            type(params["page"]) is not int or not 1 <= params["page"] <= 1000 or
            type(params["perPage"]) is not int or not 1 <= params["perPage"] <= 100):
        raise Denied("GITHUB_PAGE_INVALID")


def _utf8_size(value, code):
    try:
        return len(value.encode("utf-8"))
    except UnicodeEncodeError:
        raise Denied(code) from None


def validate_github_read(operation, target, params):
    if type(operation) is not str or operation not in {
            name for service, name in GITHUB_READ_OPERATIONS}:
        raise Denied("GITHUB_READ_OPERATION_DENIED")
    if type(params) is not dict:
        raise Denied("GITHUB_READ_PARAMS_DENIED")
    if operation == "list_repositories":
        if type(target) is not str or not _SLUG.fullmatch(target) or params:
            raise Denied("GITHUB_OWNER_OR_PARAMS_DENIED")
        return params
    _repo(target)
    if operation in ANALYSIS_READ_NAMES:
        return validate_analysis_read(operation, params)
    if operation in ("get_repository",):
        if params:
            raise Denied("GITHUB_READ_PARAMS_DENIED")
    elif operation == "get_branch":
        if set(params) != {"branch"}:
            raise Denied("GITHUB_READ_PARAMS_DENIED")
        _branch(params["branch"])
    elif operation == "find_pull_requests":
        if set(params) != {"head", "base", "page", "perPage"}:
            raise Denied("GITHUB_READ_PARAMS_DENIED")
        _branch(params["head"]); _branch(params["base"])
        _page({"page": params["page"], "perPage": params["perPage"]})
        if params["perPage"] > 50:
            raise Denied("GITHUB_PR_PAGE_TOO_LARGE")
    elif operation == "list_head_workflow_runs":
        if set(params) != {"headSha", "page", "perPage"}:
            raise Denied("GITHUB_READ_PARAMS_DENIED")
        _sha(params["headSha"])
        _page({"page": params["page"], "perPage": params["perPage"]})
        if params["perPage"] != 20 or params["page"] > 5:
            raise Denied("GITHUB_HEAD_RUNS_LIMIT")
    elif operation in ("list_branches", "list_commits", "list_workflow_runs"):
        _page(params)
    elif operation in ("list_issues", "list_issue_comments"):
        if operation == "list_issues":
            if set(params) != {"page", "perPage", "state"} or params.get("state") not in ("open", "closed", "all"):
                raise Denied("GITHUB_READ_PARAMS_DENIED")
        else:
            if set(params) != {"page", "perPage", "number"} or type(params.get("number")) is not int or not 1 <= params["number"] <= 1_000_000:
                raise Denied("GITHUB_READ_PARAMS_DENIED")
        _page({"page": params["page"], "perPage": params["perPage"]})
        # GitHub sends full Issue/comment objects; 100 per page can exceed the
        # transport's closed 1 MiB response limit even when projections are small.
        if params["perPage"] > 30:
            raise Denied("GITHUB_ISSUE_PAGE_TOO_LARGE")
    elif operation == "get_issue":
        if set(params) != {"number"} or type(params["number"]) is not int or not 1 <= params["number"] <= 1_000_000:
            raise Denied("GITHUB_READ_PARAMS_DENIED")
    elif operation == "get_pr_release_label_context":
        if set(params)!={"number"} or type(params["number"]) is not int or not 1<=params["number"]<=1_000_000:
            raise Denied("GITHUB_LABEL_PR_INVALID")
    elif operation == "get_pr_release_impact_evidence":
        if (set(params) != {"number", "expectedHeadSha"} or
                type(params["number"]) is not int or not 1 <= params["number"] <= 1_000_000):
            raise Denied("GITHUB_IMPACT_PR_PARAMS_INVALID")
        _sha(params["expectedHeadSha"])
    elif operation == "list_repository_labels":
        _page(params)
        if params["perPage"] > 50:
            raise Denied("GITHUB_LABEL_PAGE_TOO_LARGE")
    elif operation == "list_pr_labels":
        if set(params) != {"number", "page", "perPage"} or (
            type(params["number"]) is not int or not 1 <= params["number"] <= 1_000_000):
            raise Denied("GITHUB_LABEL_PR_INVALID")
        _page({"page": params["page"], "perPage": params["perPage"]})
        if params["perPage"] > 50:
            raise Denied("GITHUB_LABEL_PAGE_TOO_LARGE")
    elif operation == "list_pull_requests":
        if set(params) != {"page", "perPage", "state"} or params.get("state") not in ("open", "closed", "all"):
            raise Denied("GITHUB_READ_PARAMS_DENIED")
        _page({"page": params["page"], "perPage": params["perPage"]})
    elif operation == "get_file":
        if set(params) != {"path", "ref"}:
            raise Denied("GITHUB_READ_PARAMS_DENIED")
        _safe_file_path(params["path"])
        if not (type(params["ref"]) is str and _SHA.fullmatch(params["ref"])):
            _branch(params["ref"])
    elif operation == "get_pull_request":
        if set(params) != {"number"} or type(params["number"]) is not int or not 1 <= params["number"] <= 1_000_000:
            raise Denied("GITHUB_READ_PARAMS_DENIED")
    elif operation in ("list_check_runs", "get_commit_status"):
        if set(params) != {"ref"} or type(params["ref"]) is not str:
            raise Denied("GITHUB_READ_PARAMS_DENIED")
        if not _SHA.fullmatch(params["ref"]):
            _branch(params["ref"])
    return params


def _safe_file_path(value):
    if (type(value) is not str or not value or len(value) > 240 or
            value.startswith("/") or "\\\\" in value or
            any(part in ("", ".", "..") for part in value.split("/")) or
            value.split("/", 1)[0].lower() == ".git"):
        raise Denied("GITHUB_FILE_PATH_DENIED")
    return value
def validate_github_action(operation, target, params):
    if type(operation) is not str or operation not in {
            name for service, name in GITHUB_ACTION_OPERATIONS}:
        raise Denied("GITHUB_ACTION_OPERATION_DENIED")
    if type(params) is not dict:
        raise Denied("GITHUB_ACTION_PARAMS_DENIED")
    _repo(target)
    if operation in ANALYSIS_ACTION_NAMES:
        return validate_analysis_action(operation, params)
    if operation == "create_release_label":
        if set(params) != {"name"}:
            raise Denied("GITHUB_RELEASE_LABEL_PARAMS_INVALID")
        label_definition(params["name"])
    elif operation in ("add_pr_release_labels", "remove_pr_release_label"):
        required = {"number", "expectedHeadSha", "expectedBaseSha",
                    "expectedBodySha256", "expectedLabelsSha256"}
        required |= {"labels"} if operation == "add_pr_release_labels" else {"name"}
        if set(params) != required or type(params["number"]) is not int or (
            not 1 <= params["number"] <= 1_000_000):
            raise Denied("GITHUB_RELEASE_LABEL_PARAMS_INVALID")
        _sha(params["expectedHeadSha"])
        _sha(params["expectedBaseSha"])
        for field in ("expectedBodySha256","expectedLabelsSha256"):
            if type(params[field]) is not str or not re.fullmatch("[0-9a-f]{64}",params[field]):
                raise Denied("GITHUB_RELEASE_LABEL_PROOF_INVALID")
        if operation == "add_pr_release_labels":
            checked_names(params["labels"],managed_only=True,nonempty=True,limit=5)
        else:
            managed(params["name"],removable=True)
    elif operation == "publish_visual_review":
        if target != "visual-workspace" or set(params) != {"runId", "title", "description", "qaSummary", "durationSeconds", "media"}:
            raise Denied("GITHUB_VISUAL_REVIEW_SCOPE_DENIED")
        if (type(params["runId"]) is not str or not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_-]{0,79}", params["runId"]) or
                type(params["title"]) is not str or not 1 <= len(params["title"].strip()) <= 200 or
                type(params["description"]) is not str or len(params["description"]) > 12000 or
                type(params["qaSummary"]) is not str or len(params["qaSummary"]) > 2000 or
                type(params["durationSeconds"]) is not int or not 0 <= params["durationSeconds"] <= 604800):
            raise Denied("GITHUB_VISUAL_REVIEW_FIELDS_INVALID")
        for key in ("title", "description", "qaSummary"):
            _utf8_size(params[key], "GITHUB_VISUAL_REVIEW_FIELDS_INVALID")
        media = params["media"]
        if type(media) is not list or not 1 <= len(media) <= 5:
            raise Denied("GITHUB_VISUAL_REVIEW_MEDIA_INVALID")
        indices = set()
        for item in media:
            if type(item) is not dict or set(item) != {"index", "name", "sha256", "size"}:
                raise Denied("GITHUB_VISUAL_REVIEW_MEDIA_INVALID")
            if (type(item["index"]) is not int or not 0 <= item["index"] < 5 or item["index"] in indices or
                    type(item["name"]) is not str or not 1 <= len(item["name"]) <= 120 or
                    type(item["sha256"]) is not str or not re.fullmatch(r"[0-9a-f]{64}", item["sha256"]) or
                    type(item["size"]) is not int or not 24 <= item["size"] <= 10 * 1024 * 1024):
                raise Denied("GITHUB_VISUAL_REVIEW_MEDIA_INVALID")
            _utf8_size(item["name"], "GITHUB_VISUAL_REVIEW_MEDIA_INVALID")
            indices.add(item["index"])
        if indices != set(range(len(media))):
            raise Denied("GITHUB_VISUAL_REVIEW_MEDIA_INVALID")
    elif operation == "append_visual_revision":
        keys={"issueNumber","baseRunId","assetId","revision","runId","sourceSha",
              "description","qaSummary","durationSeconds","media"}
        if target!="visual-workspace" or set(params)!=keys:
            raise Denied("GITHUB_VISUAL_REVISION_SCOPE_DENIED")
        for field in ("runId","baseRunId","assetId"):
            if (type(params[field]) is not str or
                not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,79}",params[field])):
                raise Denied("GITHUB_VISUAL_REVISION_ID_INVALID")
        if params["runId"] == params["baseRunId"]:
            raise Denied("GITHUB_VISUAL_REVISION_ID_INVALID")
        if (type(params["issueNumber"]) is not int or
            not 1<=params["issueNumber"]<=1_000_000 or
            type(params["revision"]) is not int or
            not 2<=params["revision"]<=1000 or
            type(params["sourceSha"]) is not str or
            not re.fullmatch(r"[0-9a-f]{40}",params["sourceSha"])):
            raise Denied("GITHUB_VISUAL_REVISION_ID_INVALID")
        for field,maximum in (("description",12000),("qaSummary",2000)):
            if type(params[field]) is not str or not 1<=len(params[field].strip())<=maximum:
                raise Denied("GITHUB_VISUAL_REVISION_FIELDS_INVALID")
            _utf8_size(params[field],"GITHUB_VISUAL_REVISION_FIELDS_INVALID")
        if (type(params["durationSeconds"]) is not int or
            not 0<=params["durationSeconds"]<=604800):
            raise Denied("GITHUB_VISUAL_REVISION_FIELDS_INVALID")
        # Reuse the strict, tested PNG index/size/digest contract.
        validate_github_action("publish_visual_review",target,{
            "runId":params["runId"],"title":"Visual revision","description":params["description"],
            "qaSummary":params["qaSummary"],"durationSeconds":params["durationSeconds"],
            "media":params["media"]})
    elif operation == "create_branch":
        if set(params) != {"branch", "sourceSha"}:
            raise Denied("GITHUB_CREATE_BRANCH_PARAMS_DENIED")
        _branch(params["branch"])
        _sha(params["sourceSha"])
    elif operation == "push_commits":
        if set(params) != {"task", "artifactSha256", "expectedHeadSha", "newSha"}:
            raise Denied("GITHUB_PUSH_COMMITS_PARAMS_DENIED")
        if type(params["task"]) is not str or not re.fullmatch("[a-z0-9][a-z0-9-]{0,99}",params["task"]):
            raise Denied("GITHUB_TASK_INVALID")
        if type(params["artifactSha256"]) is not str or not re.fullmatch("[0-9a-f]{64}",params["artifactSha256"]):
            raise Denied("GITHUB_ARTIFACT_INVALID")
        if params["expectedHeadSha"] is not None: _sha(params["expectedHeadSha"])
        _sha(params["newSha"])
    elif operation == "mark_pr_ready":
        if set(params) != {"number","expectedHeadSha"} or type(params["number"]) is not int or not 1 <= params["number"] <= 1000000:
            raise Denied("GITHUB_READY_PARAMS_DENIED")
        _sha(params["expectedHeadSha"])
    elif operation == "push_files":
        if set(params) != {"branch", "expectedHeadSha", "message", "files"}:
            raise Denied("GITHUB_PUSH_PARAMS_DENIED")
        _branch(params["branch"])
        _sha(params["expectedHeadSha"])
        if (type(params["message"]) is not str or
                not 1 <= len(params["message"].strip()) <= 500):
            raise Denied("GITHUB_COMMIT_MESSAGE_INVALID")
        _utf8_size(params["message"], "GITHUB_COMMIT_MESSAGE_INVALID")
        files = params["files"]
        if type(files) is not list or not 1 <= len(files) <= 20:
            raise Denied("GITHUB_FILES_INVALID")
        total = 0
        for row in files:
            if type(row) is not dict or set(row) != {"path", "content"}:
                raise Denied("GITHUB_FILE_INVALID")
            path = _safe_file_path(row["path"])
            if path == ".github/workflows" or path.startswith(".github/workflows/"):
                raise Denied("GITHUB_WORKFLOW_REQUIRES_SEPARATE_OPERATION")
            if type(row["content"]) is not str:
                raise Denied("GITHUB_FILE_CONTENT_INVALID")
            content_size = _utf8_size(row["content"], "GITHUB_FILE_CONTENT_INVALID")
            if content_size > 64_000:
                raise Denied("GITHUB_FILE_CONTENT_INVALID")
            total += content_size
        if total > 200_000 or len({row["path"] for row in files}) != len(files):
            raise Denied("GITHUB_PUSH_SIZE_OR_DUPLICATE_PATH")
    elif operation == "create_pull_request":
        if set(params) != {"head", "base", "title", "body", "draft"}:
            raise Denied("GITHUB_PR_PARAMS_DENIED")
        _branch(params["head"])
        _branch(params["base"])
        if (type(params["title"]) is not str or not 1 <= len(params["title"].strip()) <= 256 or
                type(params["body"]) is not str or len(params["body"]) > 20_000 or
                type(params["draft"]) is not bool):
            raise Denied("GITHUB_PR_FIELDS_INVALID")
        _utf8_size(params["title"], "GITHUB_PR_FIELDS_INVALID")
        _utf8_size(params["body"], "GITHUB_PR_FIELDS_INVALID")
    elif operation == "update_pull_request":
        if (set(params) != {"number", "expectedHeadSha", "body"} or
                type(params["number"]) is not int or not 1 <= params["number"] <= 1_000_000 or
                type(params["body"]) is not str):
            raise Denied("GITHUB_UPDATE_PR_PARAMS_DENIED")
        _sha(params["expectedHeadSha"])
        if _utf8_size(params["body"], "GITHUB_UPDATE_PR_BODY_INVALID") > 20_000:
            raise Denied("GITHUB_UPDATE_PR_BODY_INVALID")
    elif operation == "merge_pull_request":
        if set(params) != {"number", "expectedHeadSha", "mergeMethod"}:
            raise Denied("GITHUB_MERGE_PARAMS_DENIED")
        if type(params["number"]) is not int or not 1 <= params["number"] <= 1_000_000:
            raise Denied("GITHUB_PR_NUMBER_INVALID")
        _sha(params["expectedHeadSha"])
        if params["mergeMethod"] not in ("merge", "squash", "rebase"):
            raise Denied("GITHUB_MERGE_METHOD_INVALID")
    elif operation == "update_workflow_file":
        if set(params) != {"branch", "path", "expectedHeadSha", "expectedFileSha", "message", "content"}:
            raise Denied("GITHUB_WORKFLOW_PARAMS_DENIED")
        _branch(params["branch"])
        path = _safe_file_path(params["path"])
        if (not path.startswith(".github/workflows/") or
                not path.lower().endswith((".yml", ".yaml"))):
            raise Denied("GITHUB_WORKFLOW_PATH_DENIED")
        _sha(params["expectedHeadSha"])
        _sha(params["expectedFileSha"])
        if (type(params["message"]) is not str or not 1 <= len(params["message"].strip()) <= 500 or
                type(params["content"]) is not str):
            raise Denied("GITHUB_WORKFLOW_CONTENT_INVALID")
        _utf8_size(params["message"], "GITHUB_WORKFLOW_CONTENT_INVALID")
        if _utf8_size(params["content"], "GITHUB_WORKFLOW_CONTENT_INVALID") > 64_000:
            raise Denied("GITHUB_WORKFLOW_CONTENT_INVALID")
    elif operation == "dispatch_workflow":
        if set(params) != {"workflowId", "ref", "inputs"}:
            raise Denied("GITHUB_DISPATCH_PARAMS_DENIED")
        if not (type(params["workflowId"]) is int and params["workflowId"] > 0 or
                type(params["workflowId"]) is str and _SLUG.fullmatch(params["workflowId"])):
            raise Denied("GITHUB_WORKFLOW_ID_INVALID")
        _branch(params["ref"])
        inputs = params["inputs"]
        if (type(inputs) is not dict or len(inputs) > 20 or
                any(type(k) is not str or not _SLUG.fullmatch(k) or
                    type(v) is not str or len(v) > 200 for k, v in inputs.items())):
            raise Denied("GITHUB_WORKFLOW_INPUTS_INVALID")
        for value in inputs.values():
            _utf8_size(value, "GITHUB_WORKFLOW_INPUTS_INVALID")
    elif operation in ("rerun_workflow", "cancel_workflow", "approve_workflow_run"):
        if set(params) != {"runId"} or type(params["runId"]) is not int or not 1 <= params["runId"] <= 2**63 - 1:
            raise Denied("GITHUB_RUN_ID_INVALID")
    return params


def validate_github_read_projection(operation, result):
    """Reject raw provider responses and enforce exact public projections."""
    if operation in ANALYSIS_READ_NAMES:
        return validate_analysis_result(operation, result)
    if type(result) is not dict or result.get("operation") != operation:
        raise Denied("GITHUB_READ_PROJECTION_DENIED")

    def exact(row, fields):
        return type(row) is dict and set(row) == set(fields)

    def text(value, limit=500, optional=False):
        return ((optional and value is None) or
                (type(value) is str and len(value) <= limit))

    def positive(value, allow_zero=False):
        return (type(value) is int and
                (value >= 0 if allow_zero else value > 0))

    def sha(value):
        return type(value) is str and _SHA.fullmatch(value) is not None

    def https_url(value, optional=False):
        if optional and value in (None, ""):
            return True
        if not text(value):
            return False
        try:
            parsed = urlsplit(value)
            return (parsed.scheme == "https" and bool(parsed.hostname) and
                    parsed.username is None and parsed.password is None and
                    parsed.port in (None, 443))
        except ValueError:
            return False

    def github_url(value):
        return https_url(value) and urlsplit(value).hostname == "github.com"

    def ref(value):
        return (exact(value, ("ref", "sha")) and text(value["ref"], 200) and
                bool(value["ref"]) and sha(value["sha"]))

    def rows(field, fields):
        items = result.get(field)
        return (type(items) is list and len(items) <= 100 and
                all(exact(item, fields) for item in items))

    valid = False
    if operation == "get_pr_release_impact_evidence":
        fields = ("operation", "number", "headSha", "baseSha", "headRepository",
                  "baseRepository", "headBranch", "baseBranch", "body",
                  "bodySha256", "state", "draft", "merged")
        body = result.get("body")
        digest = result.get("bodySha256")
        body_bytes = (_utf8_size(body, "GITHUB_IMPACT_BODY_UTF8_DENIED")
                      if type(body) is str else 0)
        valid = (
            exact(result, fields) and positive(result["number"]) and
            sha(result["headSha"]) and sha(result["baseSha"]) and
            type(result["headRepository"]) is str and
            type(result["baseRepository"]) is str and
            bool(re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", result["headRepository"])) and
            result["headRepository"] == result["baseRepository"] and
            type(result["headBranch"]) is str and
            result["headBranch"].startswith("task/") and
            result["baseBranch"] == "main" and
            type(body) is str and 0 < body_bytes <= 20000 and
            type(digest) is str and
            digest == hashlib.sha256(body.encode("utf-8")).hexdigest() and
            result["state"] == "open" and
            result["draft"] is False and result["merged"] is False
        )
    elif operation == "list_repositories":
        valid = (exact(result, ("operation", "items")) and
                 rows("items", ("name", "owner")) and
                 all(text(x["name"], 100) and text(x["owner"], 100)
                     for x in result["items"]))
    elif operation == "get_pr_release_label_context":
        valid=(exact(result,("operation","number","headSha","baseSha",
                             "bodySha256","labelsSha256","labels","branch")) and
               positive(result["number"]) and sha(result["headSha"]) and
               sha(result["baseSha"]) and
               all(type(result[k]) is str and re.fullmatch("[0-9a-f]{64}",result[k])
                   for k in ("bodySha256","labelsSha256")) and
               type(result["branch"]) is str and result["branch"].startswith("task/") and
               type(result["labels"]) is list and len(result["labels"])<=250 and
               all(text(x,50) and bool(x) for x in result["labels"]) and
               len(set(result["labels"]))==len(result["labels"]))
    elif operation in ("list_repository_labels", "list_pr_labels"):
        fields=("name","color","description")
        valid=(exact(result,("operation","items","page","perPage","hasNextPage")) and
               rows("items",fields) and positive(result["page"]) and
               type(result["perPage"]) is int and 1<=result["perPage"]<=50 and
               type(result["hasNextPage"]) is bool and
               all(text(x["name"],50) and bool(x["name"]) and
                   type(x["color"]) is str and
                   re.fullmatch("[0-9a-fA-F]{6}",x["color"]) and
                   text(x["description"],500,optional=True)
                   for x in result["items"]))
        if operation=="list_pr_labels":
            valid=(exact(result,("operation","number","items","page","perPage","hasNextPage"))
                   and positive(result.get("number")) and
                   type(result.get("items")) is list and len(result["items"])<=50 and
                   all(exact(item,fields) and text(item["name"],50) and bool(item["name"]) and
                       type(item["color"]) is str and
                       re.fullmatch("[0-9a-fA-F]{6}",item["color"]) and
                       text(item["description"],500,optional=True)
                       for item in result["items"]) and
                   positive(result["page"]) and type(result["perPage"]) is int and
                   1<=result["perPage"]<=50 and type(result["hasNextPage"]) is bool)
    elif operation == "get_repository":
        fields = ("name", "full_name", "private", "default_branch",
                  "archived", "disabled", "html_url", "pushed_at")
        if exact(result, ("operation", "repository")) and exact(result["repository"], fields):
            row = result["repository"]
            valid = (text(row["name"], 100) and text(row["full_name"], 201) and
                     type(row["private"]) is bool and text(row["default_branch"], 200) and
                     type(row["archived"]) is bool and type(row["disabled"]) is bool and
                     github_url(row["html_url"]) and text(row["pushed_at"], 80, optional=True))
    elif operation == "get_branch":
        valid = (exact(result, ("operation", "found", "branch")) and
                 type(result["found"]) is bool)
        if valid:
            row = result["branch"]
            valid = ((result["found"] is False and row is None) or
                     (result["found"] is True and exact(row, ("name", "sha", "protected")) and
                      text(row["name"], 200) and bool(row["name"]) and sha(row["sha"]) and
                      type(row["protected"]) is bool))
    elif operation == "list_branches":
        valid = (exact(result, ("operation", "items", "page", "perPage")) and
                 rows("items", ("name", "sha", "protected")) and
                 positive(result["page"]) and positive(result["perPage"]) and
                 all(text(x["name"], 200) and bool(x["name"]) and sha(x["sha"]) and
                     type(x["protected"]) is bool for x in result["items"]))
    elif operation == "list_commits":
        valid = (exact(result, ("operation", "items", "page", "perPage")) and
                 rows("items", ("sha", "message", "author", "date", "url")) and
                 positive(result["page"]) and positive(result["perPage"]) and
                 all(sha(x["sha"]) and text(x["message"], 1000) and
                     text(x["author"], 200) and text(x["date"], 80) and
                     github_url(x["url"]) for x in result["items"]))
    elif operation == "get_file":
        valid = (exact(result, ("operation", "file")) and
                 exact(result.get("file"), ("path", "ref", "exists", "sha", "size", "contentSha256")))
        if valid:
            row = result["file"]
            valid = (text(row["path"], 240) and text(row["ref"], 200) and type(row["exists"]) is bool and
                     ((row["exists"] and sha(row["sha"]) and type(row["size"]) is int and
                       0 <= row["size"] <= 4096 and type(row["contentSha256"]) is str and
                       re.fullmatch('[0-9a-f]{64}', row["contentSha256"]) is not None) or
                      (row["exists"] is False and row["sha"] is None and row["size"] == 0 and
                       type(row["size"]) is int and row["contentSha256"] is None)))
    elif operation in ("list_issues", "get_issue", "list_issue_comments"):
        issue_fields = ("number", "title", "state", "url", "createdAt", "updatedAt", "runIdMarker", "embeddedMediaCount")
        def issue(row):
            return (exact(row, issue_fields) and positive(row["number"]) and row["number"] <= 1_000_000 and
                    text(row["title"], 500) and row["state"] in ("open", "closed") and
                    github_url(row["url"]) and "/issues/" + str(row["number"]) in row["url"] and
                    text(row["createdAt"], 80) and text(row["updatedAt"], 80) and
                    (row["runIdMarker"] is None or
                     (text(row["runIdMarker"], 80) and bool(re.fullmatch('[A-Za-z0-9][A-Za-z0-9_-]{0,79}', row["runIdMarker"])))) and
                    type(row["embeddedMediaCount"]) is int and 0 <= row["embeddedMediaCount"] <= 100)
        if operation == "list_issues":
            valid = (exact(result, ("operation", "items", "page", "perPage", "hasNextPage")) and
                     rows("items", issue_fields) and positive(result["page"]) and
                     positive(result["perPage"]) and type(result["hasNextPage"]) is bool and
                     all(issue(x) for x in result["items"]))
        elif operation == "get_issue":
            valid = (exact(result, ("operation", "found", "issue")) and type(result["found"]) is bool and
                     ((result["found"] is False and result["issue"] is None) or
                      (result["found"] is True and type(result["issue"]) is dict and
                       exact(result["issue"], (*issue_fields, "body", "embeddedMediaUrls")) and
                       issue({key: result["issue"][key] for key in issue_fields}) and
                       text(result["issue"]["body"], 24000) and
                       type(result["issue"]["embeddedMediaUrls"]) is list and
                       result["issue"]["embeddedMediaCount"] == len(result["issue"]["embeddedMediaUrls"]) and
                       len(result["issue"]["embeddedMediaUrls"]) <= 100 and
                       all(type(u) is str and re.fullmatch(
                           r'https://github\.com/user-attachments/assets/[A-Za-z0-9_-]{1,200}',u)
                           for u in result["issue"]["embeddedMediaUrls"]))))
        else:
            fields = ("id", "url", "body", "createdAt", "embeddedMediaUrls")
            valid = (exact(result, ("operation", "issueNumber", "items", "page", "perPage", "hasNextPage")) and
                     positive(result["issueNumber"]) and result["issueNumber"] <= 1_000_000 and
                     rows("items", fields) and positive(result["page"]) and positive(result["perPage"]) and
                     type(result["hasNextPage"]) is bool and all(
                         positive(x["id"]) and github_url(x["url"]) and text(x["body"], 24000) and
                         text(x["createdAt"], 80) and type(x["embeddedMediaUrls"]) is list and
                         len(x["embeddedMediaUrls"]) <= 100 and all(
                             type(u) is str and re.fullmatch(
                                 r'https://github\.com/user-attachments/assets/[A-Za-z0-9_-]{1,200}',u)
                             for u in x["embeddedMediaUrls"]) for x in result["items"]))
    elif operation in ("list_pull_requests", "find_pull_requests", "get_pull_request"):
        if operation in ("list_pull_requests", "find_pull_requests"):
            fields = ("operation", "items", "page", "perPage")
            if operation == "find_pull_requests": fields += ("hasNextPage",)
            valid_shape = (exact(result, fields) and
                           rows("items", ("number", "title", "state", "draft", "head",
                                          "base", "merged", "url")) and
                           positive(result["page"]) and positive(result["perPage"]))
            if operation == "find_pull_requests":
                valid_shape = (valid_shape and result["perPage"] <= 50 and
                               len(result["items"]) <= result["perPage"] and
                               type(result["hasNextPage"]) is bool and
                               result["hasNextPage"] is (len(result["items"]) == result["perPage"]))
            items = result.get("items", [])
        else:
            valid_shape = (exact(result, ("operation", "pullRequest")) and
                           exact(result.get("pullRequest"), ("number", "title", "state",
                                 "draft", "head", "base", "merged", "url")))
            items = [result["pullRequest"]] if valid_shape else []
        valid = (valid_shape and all(
            positive(x["number"]) and text(x["title"], 500) and
            x["state"] in ("open", "closed") and type(x["draft"]) is bool and
            ref(x["head"]) and ref(x["base"]) and type(x["merged"]) is bool and
            github_url(x["url"]) for x in items))
    elif operation == "list_head_workflow_runs":
        fields = ("id", "name", "event", "status", "conclusion", "headBranch", "headSha",
                  "runNumber", "runAttempt", "createdAt", "updatedAt", "url",
                  "workflowId", "workflowPath")
        valid = (exact(result, ("operation", "items", "totalCount", "headSha",
                               "page", "perPage", "complete")) and rows("items", fields) and
                 sha(result["headSha"]) and positive(result["totalCount"], allow_zero=True) and
                 result["totalCount"] <= 100 and type(result["page"]) is int and
                 1 <= result["page"] <= 5 and type(result["perPage"]) is int and
                 result["perPage"] == 20 and type(result["complete"]) is bool and
                 len(result["items"]) == min(20, max(0, result["totalCount"] - (result["page"]-1)*20)) and
                 result["complete"] == ((result["page"]-1)*20+len(result["items"]) >= result["totalCount"]) and
                 len({x["id"] for x in result["items"]}) == len(result["items"]) and
                 all(positive(x["id"]) and text(x["name"], 200) and x["event"] == "pull_request" and
                     text(x["status"], 40) and text(x["conclusion"], 40, optional=True) and
                     text(x["headBranch"], 200) and x["headSha"] == result["headSha"] and
                     positive(x["runNumber"]) and positive(x["runAttempt"]) and
                     positive(x["workflowId"]) and text(x["workflowPath"], 180) and
                     text(x["createdAt"], 80) and text(x["updatedAt"], 80) and
                     github_url(x["url"]) for x in result["items"]))
    elif operation == "list_workflow_runs":
        valid = (exact(result, ("operation", "items", "totalCount")) and
                 rows("items", ("id", "name", "event", "status", "conclusion",
                                "headBranch", "headSha", "runNumber", "runAttempt",
                                "createdAt", "updatedAt", "url")) and
                 positive(result["totalCount"], allow_zero=True) and
                 all(positive(x["id"]) and text(x["name"], 200) and text(x["event"], 80) and
                     text(x["status"], 40) and text(x["conclusion"], 40, optional=True) and
                     text(x["headBranch"], 200) and sha(x["headSha"]) and
                     positive(x["runNumber"]) and positive(x["runAttempt"]) and
                     text(x["createdAt"], 80) and text(x["updatedAt"], 80) and
                     github_url(x["url"]) for x in result["items"]))
    elif operation == "list_check_runs":
        valid = (exact(result, ("operation", "items", "totalCount")) and
                 rows("items", ("id", "name", "status", "conclusion", "headSha",
                                "startedAt", "completedAt", "url")) and
                 positive(result["totalCount"], allow_zero=True) and
                 all(positive(x["id"]) and text(x["name"], 200) and text(x["status"], 40) and
                     text(x["conclusion"], 40, optional=True) and sha(x["headSha"]) and
                     text(x["startedAt"], 80, optional=True) and
                     text(x["completedAt"], 80, optional=True) and https_url(x["url"], optional=True)
                     for x in result["items"]))
    elif operation == "get_commit_status":
        fields = ("context", "state", "description", "url", "updatedAt")
        valid = (exact(result, ("operation", "state", "sha", "totalCount", "statuses")) and
                 result["state"] in ("pending", "success", "error", "failure") and
                 sha(result["sha"]) and positive(result["totalCount"], allow_zero=True) and
                 type(result["statuses"]) is list and len(result["statuses"]) <= 100 and
                 all(exact(x, fields) and text(x["context"], 200) and
                     x["state"] in ("pending", "success", "error", "failure") and
                     text(x["description"], 500) and https_url(x["url"], optional=True) and
                     text(x["updatedAt"], 80) for x in result["statuses"]))
    if not valid:
        raise Denied("GITHUB_READ_PROJECTION_DENIED")
    return result

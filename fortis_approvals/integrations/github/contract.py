"""Closed GitHub operation catalogue and strict request/response contracts.

No GitHub credential, network transport or policy is defined here. All
operations are denied by Core until a trusted owner explicitly registers
actor grants and ALLOW/ASK policy for them.
"""
import re
from urllib.parse import urlsplit

from ...core import Denied

GITHUB_READ_OPERATIONS = frozenset({
    ("github", "list_repositories"), ("github", "get_repository"),
    ("github", "list_branches"), ("github", "list_commits"), ("github", "get_file"),
    ("github", "list_pull_requests"), ("github", "get_pull_request"),
    ("github", "list_workflow_runs"), ("github", "list_check_runs"),
    ("github", "get_commit_status"),
})
GITHUB_ACTION_OPERATIONS = frozenset({
    ("github", "create_branch"), ("github", "push_files"), ("github", "create_pull_request"),
    ("github", "merge_pull_request"), ("github", "update_workflow_file"),
    ("github", "dispatch_workflow"), ("github", "rerun_workflow"),
    ("github", "cancel_workflow"), ("github", "approve_workflow_run"),
})
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
    if operation in ("get_repository",):
        if params:
            raise Denied("GITHUB_READ_PARAMS_DENIED")
    elif operation in ("list_branches", "list_commits", "list_workflow_runs"):
        _page(params)
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
    if operation == "create_branch":
        if set(params) != {"branch", "sourceSha"}:
            raise Denied("GITHUB_CREATE_BRANCH_PARAMS_DENIED")
        _branch(params["branch"])
        _sha(params["sourceSha"])
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
    if operation == "list_repositories":
        valid = (exact(result, ("operation", "items")) and
                 rows("items", ("name", "owner")) and
                 all(text(x["name"], 100) and text(x["owner"], 100)
                     for x in result["items"]))
    elif operation == "get_repository":
        fields = ("name", "full_name", "private", "default_branch",
                  "archived", "disabled", "html_url", "pushed_at")
        if exact(result, ("operation", "repository")) and exact(result["repository"], fields):
            row = result["repository"]
            valid = (text(row["name"], 100) and text(row["full_name"], 201) and
                     type(row["private"]) is bool and text(row["default_branch"], 200) and
                     type(row["archived"]) is bool and type(row["disabled"]) is bool and
                     github_url(row["html_url"]) and text(row["pushed_at"], 80, optional=True))
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
    elif operation in ("list_pull_requests", "get_pull_request"):
        if operation == "list_pull_requests":
            valid_shape = (exact(result, ("operation", "items", "page", "perPage")) and
                           rows("items", ("number", "title", "state", "draft", "head",
                                          "base", "merged", "url")) and
                           positive(result["page"]) and positive(result["perPage"]))
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

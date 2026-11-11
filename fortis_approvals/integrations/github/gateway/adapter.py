"""Typed GitHub Gateway adapter for allowlisted repositories.

The adapter has no default grants or policies. It is registered only by
trusted composition; Core's default policy is DENY until owner configuration.
"""
import base64
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
from urllib.parse import quote

from ....core import Denied, Stale, canonical
from ..contract import (
    GITHUB_ACTION_OPERATIONS, GITHUB_READ_OPERATIONS,
    validate_github_action, validate_github_read,
    validate_github_read_projection,
)
from .transport import GitHubHTTPTransport, GitHubTransportError
from ..release_label_contract import (managed, checked_names, names_hash, label_definition, MAX_LABELS)


class GitHubAdapter:
    SERVICE = "github"
    def __init__(self, transport, *, owner, repositories, receipt_store,
                 protected_branches=("main", "master")):
        if not callable(getattr(transport, "request", None)):
            raise ValueError("GITHUB_TRANSPORT_REQUIRED")
        if type(owner) is not str or not re.fullmatch(r"[A-Za-z0-9_.-]{1,100}", owner):
            raise ValueError("GITHUB_OWNER_INVALID")
        if (type(repositories) not in (tuple, list, set, frozenset) or
                not repositories or len(repositories) > 100 or
                any(type(x) is not str or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,99}", x)
                    or x in (".", "..") for x in repositories)):
            raise ValueError("GITHUB_REPOSITORY_ALLOWLIST_INVALID")
        if (type(protected_branches) not in (tuple, list, set, frozenset) or
                any(type(x) is not str or not x for x in protected_branches)):
            raise ValueError("GITHUB_PROTECTED_BRANCHES_INVALID")
        self.transport = transport
        self.owner = owner
        self.repositories = frozenset(repositories)
        self.protected_branches = frozenset(protected_branches)
        self.store = Path(receipt_store)
        parent = self.store.parent
        if not self.store.is_absolute() or parent.is_symlink():
            raise Denied("GITHUB_RECEIPT_STORE_PATH_DENIED")
        try:
            parent.mkdir(mode=0o700, exist_ok=True)
        except OSError:
            raise Denied("GITHUB_RECEIPT_STORE_PATH_DENIED") from None
        parent_info = parent.stat()
        if (not stat.S_ISDIR(parent_info.st_mode) or
                parent_info.st_uid != os.geteuid() or
                stat.S_IMODE(parent_info.st_mode) & 0o077):
            raise Denied("GITHUB_RECEIPT_STORE_DIRECTORY_INSECURE")
        flags = os.O_CREAT | os.O_EXCL | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
        try:
            fd = os.open(self.store, flags, 0o600)
        except FileExistsError:
            fd = None
        except OSError:
            raise Denied("GITHUB_RECEIPT_STORE_PATH_DENIED") from None
        if fd is not None:
            os.close(fd)
        try:
            store_info = self.store.stat(follow_symlinks=False)
        except OSError:
            raise Denied("GITHUB_RECEIPT_STORE_REQUIRED") from None
        if (not stat.S_ISREG(store_info.st_mode) or
                store_info.st_uid != os.geteuid() or
                stat.S_IMODE(store_info.st_mode) != 0o600):
            raise Denied("GITHUB_RECEIPT_STORE_PERMISSIONS")
        with self._db() as db:
            db.execute("""CREATE TABLE IF NOT EXISTS receipts
                (request_id TEXT PRIMARY KEY, result TEXT NOT NULL)""")

    @contextmanager
    def _db(self):
        db = sqlite3.connect(self.store, timeout=5)
        db.execute("PRAGMA synchronous=FULL")
        try:
            with db:
                yield db
        finally:
            db.close()

    def _repo(self, target):
        if type(target) is not str or target not in self.repositories:
            raise Denied("GITHUB_REPOSITORY_NOT_ALLOWLISTED")
        return target

    def _path(self, repo, suffix=""):
        self._repo(repo)
        prefix = "/repos/{}/{}".format(
            quote(self.owner, safe="-._~"), quote(repo, safe="-._~"))
        return prefix + ("/" + suffix.lstrip("/") if suffix else "")

    @staticmethod
    def _branch_ref(branch):
        return "git/ref/heads/" + quote(branch, safe="-._~")

    def _api(self, method, path, *, params=None, body=None,
             expected=(200,), allow_not_found=False):
        return self.transport.request(method, path, params=params, body=body,
                                      expected_statuses=expected,
                                      allow_not_found=allow_not_found)
    @staticmethod
    def _sha(value):
        if type(value) is not str or not re.fullmatch(r"[0-9a-f]{40}", value):
            raise Denied("GITHUB_UPSTREAM_SHA_INVALID")
        return value

    @staticmethod
    def _project_branch(row):
        if type(row) is not dict or type(row.get("name")) is not str:
            raise Denied("GITHUB_BRANCH_RESPONSE_INVALID")
        commit = row.get("commit")
        if type(commit) is not dict:
            raise Denied("GITHUB_BRANCH_RESPONSE_INVALID")
        protected = row.get("protected", False)
        if type(protected) is not bool:
            raise Denied("GITHUB_BRANCH_RESPONSE_INVALID")
        return {"name": row["name"], "sha": GitHubAdapter._sha(commit.get("sha")),
                "protected": protected}

    @staticmethod
    def _project_commit(row):
        if type(row) is not dict or type(row.get("commit")) is not dict:
            raise Denied("GITHUB_COMMIT_RESPONSE_INVALID")
        commit = row["commit"]
        author = commit.get("author") if type(commit.get("author")) is dict else {}
        message, name, date, url = (
            commit.get("message", ""), author.get("name", ""),
            author.get("date", ""), row.get("html_url", ""))
        if any(type(x) is not str for x in (message, name, date, url)):
            raise Denied("GITHUB_COMMIT_RESPONSE_INVALID")
        return {
            "sha": GitHubAdapter._sha(row.get("sha")),
            "message": message[:1000], "author": name[:200],
            "date": date[:80], "url": url[:500],
        }

    @staticmethod
    def _project_pull(row):
        if type(row) is not dict or type(row.get("head")) is not dict or type(row.get("base")) is not dict:
            raise Denied("GITHUB_PR_RESPONSE_INVALID")
        head, base = row["head"], row["base"]
        title, state, draft, merged, url = (
            row.get("title", ""), row.get("state"), row.get("draft", False),
            row.get("merged", False), row.get("html_url", ""))
        if (type(title) is not str or type(state) is not str or
                type(draft) is not bool or type(merged) is not bool or
                type(url) is not str or type(head.get("ref")) is not str or
                type(base.get("ref")) is not str):
            raise Denied("GITHUB_PR_RESPONSE_INVALID")
        projected = {
            "number": row.get("number"), "title": title[:500],
            "state": state, "draft": draft,
            "head": {"ref": head["ref"], "sha": GitHubAdapter._sha(head.get("sha"))},
            "base": {"ref": base["ref"], "sha": GitHubAdapter._sha(base.get("sha"))},
            "merged": merged, "url": url[:500],
        }
        validate_github_read_projection(
            "get_pull_request", {"operation": "get_pull_request",
                                 "pullRequest": projected})
        return projected

    @staticmethod
    def _visual_issue_links(body):
        """GitHub Markdown references only; NOT authenticated attachment-byte verification."""
        if type(body) is not str or len(body) > 24000:
            raise Denied("GITHUB_ISSUE_BODY_LIMIT")
        urls = re.findall(
            r'!\[[^\r\n]{0,400}\]\((https://github\.com/user-attachments/assets/[A-Za-z0-9_-]{1,200})\)',body)
        if len(urls) > 100:
            raise Denied("GITHUB_ISSUE_MEDIA_LIMIT")
        return urls

    def _project_issue(self, repo, row, *, with_body=False):
        if type(row) is not dict or 'pull_request' in row:
            raise Denied("GITHUB_ISSUE_RESPONSE_INVALID")
        number = row.get('number');title=row.get('title');body=row.get('body')
        if body is None:body=''
        if (type(number) is not int or not 1 <= number <= 1_000_000 or
                type(title) is not str or len(title) > 500 or
                type(body) is not str or
                row.get('state') not in ('open', 'closed') or
                row.get('html_url') != 'https://github.com/'+self.owner+'/'+repo+'/issues/'+str(number) or
                type(row.get('created_at')) is not str or len(row['created_at']) > 80 or
                type(row.get('updated_at')) is not str or len(row['updated_at']) > 80):
            raise Denied("GITHUB_ISSUE_RESPONSE_INVALID")
        # We only parse Fortis's own leading marker, not comments or arbitrary HTML.
        matched=re.match(r'<!-- fortis-visual-review:([A-Za-z0-9][A-Za-z0-9_-]{0,79}) -->',body)
        media=self._visual_issue_links(body) if with_body else []
        if not with_body:
            # GitHub list response bodies can be long; validate media references only for get_issue.
            media_count=len(re.findall(r'!\[[^\r\n]{0,400}\]\(https://github\.com/user-attachments/assets/[A-Za-z0-9_-]{1,200}\)',body))
            if media_count > 100:raise Denied('GITHUB_ISSUE_MEDIA_LIMIT')
        else:media_count=len(media)
        result=dict(number=number,title=title,state=row['state'],url=row['html_url'],
                    createdAt=row['created_at'],updatedAt=row['updated_at'],
                    runIdMarker=matched.group(1) if matched else None,
                    embeddedMediaCount=media_count)
        if with_body:result.update(body=body,embeddedMediaUrls=media)
        return result

    def read(self, request):
        if type(request) is not dict or request.get("service") != self.SERVICE:
            raise Denied("GITHUB_READ_REQUEST_DENIED")
        operation, repo, params = (
            request.get("operation"), request.get("target"), request.get("params"))
        validate_github_read(operation, repo, params)
        if operation == "list_repositories":
            if repo != self.owner:
                raise Denied("GITHUB_OWNER_NOT_ALLOWLISTED")
            result = {"operation": operation,
                      "items": [{"name": name, "owner": self.owner}
                                for name in sorted(self.repositories)]}
            validate_github_read_projection(operation, result)
            return result
        self._repo(repo)
        base = self._path(repo)
        if operation == "get_repository":
            raw = self._api("GET", base)
            if type(raw) is not dict:
                raise Denied("GITHUB_REPOSITORY_RESPONSE_INVALID")
            result = {"operation": operation, "repository": {
                key: raw.get(key) for key in (
                    "name", "full_name", "private", "default_branch",
                    "archived", "disabled", "html_url", "pushed_at")
            }}
        elif operation == "list_branches":
            raw = self._api("GET", base + "/branches",
                            params={"page": params["page"], "per_page": params["perPage"]})
            if type(raw) is not list or len(raw) > 100:
                raise Denied("GITHUB_BRANCHES_RESPONSE_INVALID")
            result = {"operation": operation,
                      "items": [self._project_branch(x) for x in raw],
                      "page": params["page"], "perPage": params["perPage"]}
        elif operation == "get_file":
            raw = self._api("GET", base + "/contents/" + quote(params["path"], safe="/-._~"),
                            params={"ref": params["ref"]}, allow_not_found=True)
            if type(raw) is not dict: raise Denied("GITHUB_FILE_READ_RESPONSE_INVALID")
            item = dict(path=params["path"], ref=params["ref"], exists=False,
                        sha=None, size=0, contentSha256=None)
            if raw.get("_httpStatus") != 404:
                if (raw.get("type") != "file" or raw.get("path") != params["path"] or
                        raw.get("encoding") != "base64" or type(raw.get("size")) is not int or
                        not 0 <= raw["size"] <= 4096 or type(raw.get("content")) is not str or
                        len(raw["content"]) > 6000):
                    raise Denied("GITHUB_FILE_READ_RESPONSE_INVALID")
                try:
                    content = base64.b64decode(raw["content"].replace("\n", ""), validate=True)
                    content.decode("utf-8", errors="strict")
                except (ValueError, UnicodeError):
                    raise Denied("GITHUB_FILE_READ_RESPONSE_INVALID") from None
                blob_sha = hashlib.sha1(b"blob " + str(len(content)).encode() + b"\0" + content).hexdigest()
                if len(content) != raw["size"] or blob_sha != self._sha(raw.get("sha")):
                    raise Denied("GITHUB_FILE_READBACK_HASH_MISMATCH")
                item.update(exists=True, sha=blob_sha, size=len(content),
                            contentSha256=hashlib.sha256(content).hexdigest())
            result = {"operation": operation, "file": item}
        elif operation == "list_commits":
            raw = self._api("GET", base + "/commits",
                            params={"page": params["page"], "per_page": params["perPage"]})
            if type(raw) is not list or len(raw) > 100:
                raise Denied("GITHUB_COMMITS_RESPONSE_INVALID")
            result = {"operation": operation,
                      "items": [self._project_commit(x) for x in raw],
                      "page": params["page"], "perPage": params["perPage"]}
        elif operation == "list_issues":
            raw = self._api("GET", base + "/issues",params={
                "page":params["page"],"per_page":params["perPage"],"state":params["state"]})
            if (type(raw) is not list or len(raw) > params["perPage"] or
                    any(type(x) is not dict for x in raw)):
                raise Denied("GITHUB_ISSUES_RESPONSE_INVALID")
            result = {"operation":operation,
                      "items":[self._project_issue(repo,x) for x in raw if type(x) is dict and 'pull_request' not in x],
                      "page":params["page"],"perPage":params["perPage"],
                      "hasNextPage":len(raw)==params["perPage"]}
        elif operation == "get_issue":
            raw=self._api("GET",base+"/issues/"+str(params["number"]),allow_not_found=True)
            if type(raw) is not dict:
                raise Denied("GITHUB_ISSUE_RESPONSE_INVALID")
            result={"operation":operation,"found":raw.get("_httpStatus")!=404,
                    "issue":None if raw.get("_httpStatus")==404 else self._project_issue(repo,raw,with_body=True)}
        elif operation == "list_issue_comments":
            raw=self._api("GET",base+"/issues/"+str(params["number"])+"/comments",
                          params={"page":params["page"],"per_page":params["perPage"]})
            if type(raw) is not list or len(raw)>params["perPage"]:
                raise Denied("GITHUB_ISSUE_COMMENTS_RESPONSE_INVALID")
            items=[]
            for row in raw:
                if (type(row) is not dict or type(row.get('id')) is not int or
                    row['id']<=0 or type(row.get('body')) is not str or
                    type(row.get('created_at')) is not str or
                    row.get('html_url')!='https://github.com/'+self.owner+'/'+repo+
                        '/issues/'+str(params['number'])+'#issuecomment-'+str(row['id'])):
                    raise Denied('GITHUB_ISSUE_COMMENT_RESPONSE_INVALID')
                items.append(dict(id=row['id'],url=row['html_url'],body=row['body'],
                                  createdAt=row['created_at'],
                                  embeddedMediaUrls=self._visual_issue_links(row['body'])))
            result={"operation":operation,"issueNumber":params["number"],"items":items,
                    "page":params["page"],"perPage":params["perPage"],
                    "hasNextPage":len(raw)==params["perPage"]}
        elif operation == "get_pr_release_label_context":
            context=self._release_pr_context(repo,params["number"])
            result=context
        elif operation in ("list_repository_labels","list_pr_labels"):
            suffix=("labels" if operation=="list_repository_labels" else
                    "issues/"+str(params["number"])+"/labels")
            if operation=="list_pr_labels":
                # Do not expose arbitrary issue label inventories via a PR method.
                check=self._api("GET",base+"/pulls/"+str(params["number"]))
                if type(check) is not dict or check.get("number")!=params["number"]:
                    raise Denied("GITHUB_LABEL_PR_INVALID")
            items=self._label_page(repo,suffix,params["page"],params["perPage"])
            result={"operation":operation,"items":items,
                    "page":params["page"],"perPage":params["perPage"],
                    "hasNextPage":len(items)==params["perPage"]}
            if operation=="list_pr_labels":result["number"]=params["number"]
        elif operation == "list_pull_requests":
            raw = self._api("GET", base + "/pulls",
                            params={"page": params["page"], "per_page": params["perPage"],
                                    "state": params["state"]})
            if type(raw) is not list or len(raw) > 100:
                raise Denied("GITHUB_PULLS_RESPONSE_INVALID")
            result = {"operation": operation,
                      "items": [self._project_pull(x) for x in raw],
                      "page": params["page"], "perPage": params["perPage"]}
        elif operation == "get_pull_request":
            raw = self._api("GET", base + "/pulls/" + str(params["number"]))
            result = {"operation": operation, "pullRequest": self._project_pull(raw)}
        elif operation == "list_workflow_runs":
            raw = self._api("GET", base + "/actions/runs",
                            params={"page": params["page"], "per_page": params["perPage"]})
            runs = raw.get("workflow_runs") if type(raw) is dict else None
            if type(runs) is not list or len(runs) > 100 or any(type(x) is not dict for x in runs):
                raise Denied("GITHUB_WORKFLOW_RUNS_RESPONSE_INVALID")
            result = {"operation": operation, "items": [{
                "id": x.get("id"), "name": x.get("name", ""),
                "event": x.get("event"), "status": x.get("status"),
                "conclusion": x.get("conclusion"), "headBranch": x.get("head_branch"),
                "headSha": self._sha(x.get("head_sha")),
                "runNumber": x.get("run_number"), "runAttempt": x.get("run_attempt"),
                "createdAt": x.get("created_at"), "updatedAt": x.get("updated_at"),
                "url": x.get("html_url", ""),
            } for x in runs], "totalCount": raw.get("total_count")}
        elif operation == "list_check_runs":
            raw = self._api("GET", base + "/commits/" +
                            quote(params["ref"], safe="-._~") + "/check-runs")
            if type(raw) is not dict:
                raise Denied("GITHUB_CHECKS_RESPONSE_INVALID")
            checks = raw.get("check_runs")
            if type(checks) is not list or len(checks) > 100 or any(type(x) is not dict for x in checks):
                raise Denied("GITHUB_CHECKS_RESPONSE_INVALID")
            result = {"operation": operation, "items": [{
                "id": x.get("id"), "name": x.get("name", ""),
                "status": x.get("status"), "conclusion": x.get("conclusion"),
                "headSha": self._sha(x.get("head_sha")),
                "startedAt": x.get("started_at"), "completedAt": x.get("completed_at"),
                "url": x.get("details_url", ""),
            } for x in checks], "totalCount": raw.get("total_count")}
        elif operation == "get_commit_status":
            raw = self._api("GET", base + "/commits/" +
                            quote(params["ref"], safe="-._~") + "/status")
            if type(raw) is not dict:
                raise Denied("GITHUB_STATUS_RESPONSE_INVALID")
            statuses = raw.get("statuses")
            if type(statuses) is not list or len(statuses) > 100 or any(type(x) is not dict for x in statuses):
                raise Denied("GITHUB_STATUS_RESPONSE_INVALID")
            result = {"operation": operation, "state": raw.get("state"),
                      "sha": self._sha(raw.get("sha")),
                      "totalCount": raw.get("total_count"),
                      "statuses": [{
                          "context": x.get("context", ""),
                          "state": x.get("state"),
                          "description": x.get("description") or "",
                          "url": x.get("target_url") or "",
                          "updatedAt": x.get("updated_at"),
                      } for x in statuses]}
        else:
            raise Denied("GITHUB_READ_OPERATION_DENIED")
        validate_github_read_projection(operation, result)
        return result

    @staticmethod
    def _label_row(row):
        if (type(row) is not dict or type(row.get("name")) is not str or
                len(row["name"])>50 or type(row.get("color")) is not str or
                re.fullmatch("[0-9a-fA-F]{6}",row["color"]) is None or
                row.get("description") is not None and type(row.get("description")) is not str):
            raise Denied("GITHUB_LABEL_RESPONSE_INVALID")
        checked_names([row["name"]])
        description=row.get("description")
        if description is not None and len(description)>500:
            raise Denied("GITHUB_LABEL_RESPONSE_INVALID")
        return dict(name=row["name"],color=row["color"].lower(),
                    description=description)

    def _label_page(self,repo,suffix,page,per_page):
        raw=self._api("GET",self._path(repo,suffix),
                      params={"page":page,"per_page":per_page})
        if type(raw) is not list or len(raw)>per_page:
            raise Denied("GITHUB_LABEL_RESPONSE_INVALID")
        result=[self._label_row(x) for x in raw]
        checked_names([x["name"] for x in result])
        return result

    def _complete_label_rows(self,repo,suffix):
        items=[]
        for page in range(1,5):
            chunk=self._label_page(repo,suffix,page,100)
            items+=chunk
            if len(items)>MAX_LABELS:
                raise Denied("GITHUB_LABEL_INVENTORY_LIMIT")
            if len(chunk)<100:
                checked_names([x["name"] for x in items])
                return items
        raise Denied("GITHUB_LABEL_INVENTORY_LIMIT")

    def _release_pr_context(self,repo,number):
        raw=self._api("GET",self._path(repo,"pulls/"+str(number)))
        if (type(raw) is not dict or raw.get("number")!=number or
                raw.get("state")!="open" or raw.get("draft") is not False or
                raw.get("merged") is True or raw.get("merged_at") is not None):
            raise Denied("GITHUB_RELEASE_PR_NOT_OPEN")
        head=raw.get("head");base=raw.get("base")
        if type(head) is not dict or type(base) is not dict:
            raise Denied("GITHUB_RELEASE_PR_PROVENANCE_INVALID")
        fullname=(self.owner+"/"+repo).casefold()
        if (type(head.get("repo")) is not dict or
                type(base.get("repo")) is not dict or
                str(head["repo"].get("full_name","")).casefold()!=fullname or
                str(base["repo"].get("full_name","")).casefold()!=fullname or
                base.get("ref")!="main" or type(head.get("ref")) is not str or
                not head["ref"].startswith("task/")):
            raise Denied("GITHUB_RELEASE_PR_PROVENANCE_INVALID")
        head_sha=self._sha(head.get("sha"))
        base_sha=self._sha(base.get("sha"))
        body=raw.get("body") or ""
        if type(body) is not str or len(body)>20000:
            raise Denied("GITHUB_RELEASE_PR_BODY_INVALID")
        current=self._complete_label_rows(repo,"issues/"+str(number)+"/labels")
        names=[x["name"] for x in current]
        return dict(operation="get_pr_release_label_context",number=number,
                    headSha=head_sha,baseSha=base_sha,
                    bodySha256=hashlib.sha256(body.encode("utf-8")).hexdigest(),
                    labelsSha256=names_hash(names),labels=sorted(names),
                    branch=head["ref"])

    def _release_pr_snapshot(self,repo,params,operation):
        context=self._release_pr_context(repo,params["number"])
        for field,actual in (
            ("expectedHeadSha",context["headSha"]),
            ("expectedBaseSha",context["baseSha"]),
            ("expectedBodySha256",context["bodySha256"]),
            ("expectedLabelsSha256",context["labelsSha256"])):
            if params[field]!=actual:
                raise Stale("GITHUB_RELEASE_PR_"+field+"_CHANGED")
        return dict(operation=operation,repository=repo,number=params["number"],
                    headSha=context["headSha"],baseSha=context["baseSha"],
                    bodySha256=context["bodySha256"],
                    currentLabels=context["labels"],
                    currentLabelsSha256=context["labelsSha256"])

    def _ref(self, repo, branch, *, allow_not_found=False):
        return self._api("GET", self._path(repo, self._branch_ref(branch)),
                         allow_not_found=allow_not_found)
    def _assert_working_branch(self, branch):
        protected = {name.lower() for name in self.protected_branches}
        if branch.lower() in protected or branch.split("/")[0].lower() in protected:
            raise Denied("GITHUB_PROTECTED_BRANCH_DENIED")

    def prepare(self, request):
        if type(request) is not dict:
            raise Denied("GITHUB_ACTION_DENIED")
        if request.get("service") != self.SERVICE:
            raise Denied("GITHUB_SERVICE_DENIED")
        operation, repo, params = (
            request.get("operation"), self._repo(request.get("target")),
            request.get("params"))
        if (self.SERVICE, operation) not in GITHUB_ACTION_OPERATIONS:
            raise Denied("GITHUB_ACTION_DENIED")
        validate_github_action(operation, repo, params)
        base = self._path(repo)
        if operation=="create_release_label":
            definition=label_definition(params["name"])
            names=[x["name"] for x in self._complete_label_rows(repo,"labels")]
            if params["name"] in names:raise Denied("GITHUB_RELEASE_LABEL_ALREADY_DEFINED")
            return {"operation":operation,"repository":repo,
                    "definition":definition,"currentLabelsSha256":names_hash(names)}
        if operation in ("add_pr_release_labels","remove_pr_release_label"):
            snapshot=self._release_pr_snapshot(repo,params,operation)
            if operation=="add_pr_release_labels":
                desired=checked_names(params["labels"],managed_only=True,nonempty=True,limit=5)
                defined=[x["name"] for x in self._complete_label_rows(repo,"labels")]
                if not set(desired)<=set(defined):
                    raise Denied("GITHUB_RELEASE_LABEL_MISSING_DEFINITION")
                snapshot["add"]=desired
            else:
                snapshot["remove"]=managed(params["name"],removable=True)
            return snapshot
        if operation == "create_branch":
            self._assert_working_branch(params["branch"])
            existing = self._ref(repo, params["branch"], allow_not_found=True)
            if existing.get("_httpStatus") != 404:
                raise Denied("GITHUB_BRANCH_ALREADY_EXISTS")
            self._api("GET", base + "/git/commits/" + params["sourceSha"])
            return {"operation": operation, "repository": repo,
                    "branch": params["branch"], "sourceSha": params["sourceSha"]}
        if operation == "push_files":
            self._assert_working_branch(params["branch"])
            ref = self._ref(repo, params["branch"])
            head = self._sha(ref.get("object", {}).get("sha"))
            if head != params["expectedHeadSha"]:
                raise Stale("GITHUB_BRANCH_HEAD_CHANGED")
            content_hash = hashlib.sha256(canonical(params["files"]).encode()).hexdigest()
            return {"operation": operation, "repository": repo,
                    "branch": params["branch"], "headSha": head,
                    "filesSha256": content_hash,
                    "paths": sorted(x["path"] for x in params["files"]),
                    "messageSha256": hashlib.sha256(params["message"].encode()).hexdigest()}
        if operation == "create_pull_request":
            base_ref = self._ref(repo, params["base"])
            head_ref = self._ref(repo, params["head"])
            return {"operation": operation, "repository": repo,
                    "base": params["base"], "head": params["head"],
                    "baseSha": self._sha(base_ref.get("object", {}).get("sha")),
                    "headSha": self._sha(head_ref.get("object", {}).get("sha")),
                    "titleSha256": hashlib.sha256(params["title"].encode()).hexdigest(),
                    "bodySha256": hashlib.sha256(params["body"].encode()).hexdigest(),
                    "draft": params["draft"]}
        if operation == "update_pull_request":
            raw = self._api("GET", base + "/pulls/" + str(params["number"]))
            pr = self._project_pull(raw)
            if pr["state"] != "open" or pr["merged"]:
                raise Denied("GITHUB_PR_NOT_EDITABLE")
            if pr["head"]["sha"] != params["expectedHeadSha"]:
                raise Stale("GITHUB_PR_HEAD_CHANGED")
            current_body = raw.get("body")
            if current_body is None:
                current_body = ""
            if type(current_body) is not str or len(current_body) > 100_000:
                raise Denied("GITHUB_PR_BODY_INVALID")
            try:
                title_hash = hashlib.sha256(pr["title"].encode("utf-8")).hexdigest()
                before_hash = hashlib.sha256(current_body.encode("utf-8")).hexdigest()
            except UnicodeEncodeError:
                raise Denied("GITHUB_PR_BODY_INVALID") from None
            return {"operation": operation, "repository": repo,
                    "number": params["number"],
                    "head": pr["head"], "base": pr["base"],
                    "titleSha256": title_hash,
                    "currentBodySha256": before_hash,
                    "nextBodySha256": hashlib.sha256(params["body"].encode("utf-8")).hexdigest()}
        if operation == "merge_pull_request":
            pr = self._api("GET", base + "/pulls/" + str(params["number"]))
            projected = self._project_pull(pr)
            if projected["state"] != "open" or projected["merged"]:
                raise Denied("GITHUB_PR_NOT_MERGEABLE")
            if projected["head"]["sha"] != params["expectedHeadSha"]:
                raise Stale("GITHUB_PR_HEAD_CHANGED")
            return {"operation": operation, "repository": repo,
                    "number": params["number"], "headSha": projected["head"]["sha"],
                    "baseSha": projected["base"]["sha"], "mergeMethod": params["mergeMethod"]}
        if operation == "update_workflow_file":
            self._assert_working_branch(params["branch"])
            ref = self._ref(repo, params["branch"])
            head = self._sha(ref.get("object", {}).get("sha"))
            if head != params["expectedHeadSha"]:
                raise Stale("GITHUB_BRANCH_HEAD_CHANGED")
            content = self._api("GET", base + "/contents/" +
                                quote(params["path"], safe="/-._~"),
                                params={"ref": params["branch"]})
            if content.get("sha") != params["expectedFileSha"]:
                raise Stale("GITHUB_WORKFLOW_FILE_CHANGED")
            return {"operation": operation, "repository": repo,
                    "branch": params["branch"], "headSha": head,
                    "path": params["path"], "fileSha": content["sha"],
                    "contentSha256": hashlib.sha256(params["content"].encode()).hexdigest()}
        if operation == "dispatch_workflow":
            workflow = self._api("GET", base + "/actions/workflows/" + str(params["workflowId"]))
            if workflow.get("state") != "active":
                raise Denied("GITHUB_WORKFLOW_NOT_ACTIVE")
            ref = self._ref(repo, params["ref"])
            return {"operation": operation, "repository": repo,
                    "workflowId": params["workflowId"], "workflowState": workflow["state"],
                    "ref": params["ref"], "refSha": self._sha(ref.get("object", {}).get("sha")),
                    "inputsSha256": hashlib.sha256(canonical(params["inputs"]).encode()).hexdigest()}
        if operation in ("rerun_workflow", "cancel_workflow", "approve_workflow_run"):
            run = self._api("GET", base + "/actions/runs/" + str(params["runId"]))
            status = run.get("status")
            if operation == "rerun_workflow" and status != "completed":
                raise Denied("GITHUB_RUN_NOT_COMPLETED")
            if operation == "cancel_workflow" and status not in ("queued", "in_progress", "requested", "waiting"):
                raise Denied("GITHUB_RUN_NOT_CANCELLABLE")
            if operation == "approve_workflow_run" and status != "waiting":
                raise Denied("GITHUB_RUN_NOT_WAITING")
            return {"operation": operation, "repository": repo,
                    "runId": params["runId"], "status": status,
                    "runAttempt": run.get("run_attempt"),
                    "headSha": self._sha(run.get("head_sha"))}
        raise Denied("GITHUB_ACTION_NOT_IMPLEMENTED")

    def _save_receipt(self, request_id, result):
        with self._db() as db:
            db.execute("INSERT INTO receipts(request_id,result) VALUES(?,?)",
                       (request_id, canonical(result)))

    def receipt(self, request_id):
        with self._db() as db:
            row = db.execute("SELECT result FROM receipts WHERE request_id=?",
                             (request_id,)).fetchone()
            return json.loads(row[0]) if row else None
    def confirm(self, request_id, result):
        return (type(result) is dict and result.get("requestId") == request_id and
                self.receipt(request_id) == result)

    def apply(self, request):
        request_id = request["requestId"]
        prior = self.receipt(request_id)
        if prior is not None:
            return prior
        snapshot = self.prepare(request)
        operation, repo, params = request["operation"], request["target"], request["params"]
        base = self._path(repo)
        if operation=="create_release_label":
            again=self.prepare(request)
            if canonical(again)!=canonical(snapshot):
                raise Stale("GITHUB_RELEASE_LABEL_DEFINITIONS_CHANGED")
            created=self._api("POST",base+"/labels",body=snapshot["definition"],expected=(201,))
            if type(created) is not dict or created.get("name")!=params["name"]:
                raise GitHubTransportError("GITHUB_RELEASE_LABEL_CREATE_UNCONFIRMED")
            defined=[x["name"] for x in self._complete_label_rows(repo,"labels")]
            if params["name"] not in defined:
                raise GitHubTransportError("GITHUB_RELEASE_LABEL_READBACK_UNCONFIRMED")
            result={"requestId":request_id,"operation":operation,
                    "repository":repo,"name":params["name"],"created":True}
        elif operation in ("add_pr_release_labels","remove_pr_release_label"):
            again=self.prepare(request)
            if canonical(again)!=canonical(snapshot):
                raise Stale("GITHUB_RELEASE_PR_LABELS_OR_HEAD_CHANGED")
            before=set(snapshot["currentLabels"])
            number=params["number"]
            if operation=="add_pr_release_labels":
                desired=set(snapshot["add"])
                expected=before|desired
                changed=expected!=before
                if changed:
                    self._api("POST",base+"/issues/"+str(number)+"/labels",
                              body={"labels":sorted(desired)},expected=(200,))
            else:
                value=snapshot["remove"]
                expected=before-{value}
                changed=expected!=before
                if changed:
                    self._api("DELETE",base+"/issues/"+str(number)+"/labels/"+
                              quote(value,safe="-._~"),expected=(200,))
            # The Issue labels API has no PR HEAD CAS. Verify both HEAD and full
            # label inventory after effect; ambiguity means UNCERTAIN, no retry.
            fresh=self._api("GET",base+"/pulls/"+str(number))
            if (type(fresh) is not dict or fresh.get("number")!=number or
                    fresh.get("head",{}).get("sha")!=snapshot["headSha"] or
                    fresh.get("base",{}).get("sha")!=snapshot["baseSha"] or
                    fresh.get("state")!="open" or fresh.get("draft") is not False or
                    hashlib.sha256((fresh.get("body") or "").encode("utf-8")).hexdigest()!=snapshot["bodySha256"]):
                raise GitHubTransportError("GITHUB_RELEASE_PR_AFTER_WRITE_UNCONFIRMED")
            actual={x["name"] for x in self._complete_label_rows(
                repo,"issues/"+str(number)+"/labels")}
            if actual!=expected:
                raise GitHubTransportError("GITHUB_RELEASE_LABEL_READBACK_UNCONFIRMED")
            result={"requestId":request_id,"operation":operation,
                    "repository":repo,"number":number,
                    "headSha":snapshot["headSha"],"changed":changed,
                    "labels":sorted(actual)}
        elif operation == "create_branch":
            self._api("POST", base + "/git/refs",
                      body={"ref": "refs/heads/" + params["branch"], "sha": params["sourceSha"]},
                      expected=(201,))
            ref = self._ref(repo, params["branch"])
            if self._sha(ref.get("object", {}).get("sha")) != params["sourceSha"]:
                raise GitHubTransportError("GITHUB_BRANCH_READBACK_UNCONFIRMED")
            result = {"requestId": request_id, "operation": operation,
                      "repository": repo, "branch": params["branch"], "sha": params["sourceSha"]}
        elif operation == "push_files":
            ref = self._ref(repo, params["branch"])
            head = self._sha(ref.get("object", {}).get("sha"))
            if head != snapshot["headSha"]:
                raise Stale("GITHUB_BRANCH_HEAD_CHANGED")
            commit = self._api("GET", base + "/git/commits/" + head)
            tree_entries = []
            for item in params["files"]:
                blob = self._api("POST", base + "/git/blobs",
                                 body={"content": item["content"], "encoding": "utf-8"},
                                 expected=(201,))
                tree_entries.append({"path": item["path"], "mode": "100644",
                                     "type": "blob", "sha": self._sha(blob.get("sha"))})
            tree = self._api("POST", base + "/git/trees",
                             body={"base_tree": commit["tree"]["sha"], "tree": tree_entries},
                             expected=(201,))
            new_commit = self._api("POST", base + "/git/commits",
                                   body={"message": params["message"], "tree": tree["sha"],
                                         "parents": [head]}, expected=(201,))
            new_sha = self._sha(new_commit.get("sha"))
            self._api("PATCH", base + "/git/refs/heads/" +
                      quote(params["branch"], safe="-._~"),
                      body={"sha": new_sha, "force": False}, expected=(200,))
            readback = self._ref(repo, params["branch"])
            if self._sha(readback.get("object", {}).get("sha")) != new_sha:
                raise GitHubTransportError("GITHUB_PUSH_READBACK_UNCONFIRMED")
            result = {"requestId": request_id, "operation": operation,
                      "repository": repo, "branch": params["branch"], "sha": new_sha,
                      "paths": snapshot["paths"]}
        elif operation == "create_pull_request":
            latest = self.prepare(request)
            if canonical(latest) != canonical(snapshot):
                raise Stale("GITHUB_PR_BRANCH_CHANGED")
            pr = self._api("POST", base + "/pulls", body={
                "title": params["title"], "body": params["body"],
                "head": params["head"], "base": params["base"],
                "draft": params["draft"]}, expected=(201,))
            if type(pr) is not dict or type(pr.get("number")) is not int or pr["number"] <= 0:
                raise GitHubTransportError("GITHUB_PR_READBACK_UNCONFIRMED")
            number = pr["number"]
            readback = self._api("GET", base + "/pulls/" + str(number))
            projected = self._project_pull(readback)
            if (type(number) is not int or number <= 0 or
                    projected["number"] != number or
                    projected["head"]["ref"] != params["head"] or
                    projected["base"]["ref"] != params["base"] or
                    projected["head"]["sha"] != snapshot["headSha"] or
                    projected["base"]["sha"] != snapshot["baseSha"]):
                raise GitHubTransportError("GITHUB_PR_READBACK_UNCONFIRMED")
            result = {"requestId": request_id, "operation": operation,
                      "repository": repo, "pullRequest": projected}
        elif operation == "update_pull_request":
            latest = self.prepare(request)
            if canonical(latest) != canonical(snapshot):
                raise Stale("GITHUB_PR_CHANGED_BEFORE_UPDATE")
            updated = self._api("PATCH", base + "/pulls/" + str(params["number"]),
                                body={"body": params["body"]}, expected=(200,))
            if type(updated) is not dict or updated.get("number") != params["number"]:
                raise GitHubTransportError("GITHUB_PR_UPDATE_UNCONFIRMED")
            after = self._api("GET", base + "/pulls/" + str(params["number"]))
            pr = self._project_pull(after)
            if (pr["number"] != params["number"] or
                    pr["head"] != snapshot["head"] or pr["base"] != snapshot["base"] or
                    pr["state"] != "open" or pr["merged"] or
                    hashlib.sha256(pr["title"].encode()).hexdigest() != snapshot["titleSha256"] or
                    (after.get("body") or "") != params["body"]):
                raise GitHubTransportError("GITHUB_PR_UPDATE_UNCONFIRMED")
            result = {"requestId": request_id, "operation": operation,
                      "repository": repo, "number": params["number"],
                      "headSha": pr["head"]["sha"],
                      "bodySha256": snapshot["nextBodySha256"], "url": pr["url"]}
        elif operation == "merge_pull_request":
            latest = self.prepare(request)
            if canonical(latest) != canonical(snapshot):
                raise Stale("GITHUB_PR_CHANGED_BEFORE_MERGE")
            merged = self._api("PUT", base + "/pulls/" +
                               str(params["number"]) + "/merge",
                               body={"sha": params["expectedHeadSha"],
                                     "merge_method": params["mergeMethod"]},
                               expected=(200,))
            readback = self._api("GET", base + "/pulls/" + str(params["number"]))
            if type(merged) is not dict or merged.get("merged") is not True:
                raise GitHubTransportError("GITHUB_MERGE_READBACK_UNCONFIRMED")
            merge_sha = self._sha(merged.get("sha"))
            projected = self._project_pull(readback)
            if (projected["number"] != params["number"] or
                    projected["state"] != "closed" or projected["merged"] is not True or
                    projected["head"]["sha"] != params["expectedHeadSha"]):
                raise GitHubTransportError("GITHUB_MERGE_READBACK_UNCONFIRMED")
            result = {"requestId": request_id, "operation": operation,
                      "repository": repo, "number": params["number"],
                      "merged": True, "sha": merge_sha}
        elif operation == "update_workflow_file":
            latest = self.prepare(request)
            if canonical(latest) != canonical(snapshot):
                raise Stale("GITHUB_WORKFLOW_CHANGED_BEFORE_UPDATE")
            content = base64.b64encode(params["content"].encode("utf-8")).decode("ascii")
            updated = self._api("PUT", base + "/contents/" +
                                quote(params["path"], safe="/-._~"),
                                body={"message": params["message"], "content": content,
                                      "sha": params["expectedFileSha"],
                                      "branch": params["branch"]}, expected=(200,))
            if type(updated) is not dict or type(updated.get("content")) is not dict:
                raise GitHubTransportError("GITHUB_WORKFLOW_READBACK_UNCONFIRMED")
            updated_sha = self._sha(updated["content"].get("sha"))
            readback = self._api("GET", base + "/contents/" +
                                 quote(params["path"], safe="/-._~"),
                                 params={"ref": params["branch"]})
            if type(readback) is not dict:
                raise GitHubTransportError("GITHUB_WORKFLOW_READBACK_UNCONFIRMED")
            readback_sha = self._sha(readback.get("sha"))
            if readback_sha != updated_sha:
                raise GitHubTransportError("GITHUB_WORKFLOW_READBACK_UNCONFIRMED")
            result = {"requestId": request_id, "operation": operation,
                      "repository": repo, "path": params["path"],
                      "sha": readback_sha, "branch": params["branch"]}
        elif operation == "dispatch_workflow":
            latest = self.prepare(request)
            if canonical(latest) != canonical(snapshot):
                raise Stale("GITHUB_WORKFLOW_REF_CHANGED")
            self._api("POST", base + "/actions/workflows/" +
                      str(params["workflowId"]) + "/dispatches",
                      body={"ref": params["ref"], "inputs": params["inputs"]},
                      expected=(204,))
            result = {"requestId": request_id, "operation": operation,
                      "repository": repo, "accepted": True}
        elif operation == "rerun_workflow":
            latest = self.prepare(request)
            if canonical(latest) != canonical(snapshot):
                raise Stale("GITHUB_RUN_CHANGED")
            self._api("POST", base + "/actions/runs/" +
                      str(params["runId"]) + "/rerun", body={}, expected=(201,))
            after = self._api("GET", base + "/actions/runs/" + str(params["runId"]))
            if (type(after) is not dict or type(after.get("run_attempt")) is not int or
                    after["run_attempt"] <= snapshot.get("runAttempt", 0) or
                    self._sha(after.get("head_sha")) != snapshot["headSha"]):
                raise GitHubTransportError("GITHUB_RERUN_READBACK_UNCONFIRMED")
            result = {"requestId": request_id, "operation": operation,
                      "repository": repo, "runId": params["runId"],
                      "runAttempt": after["run_attempt"]}
        elif operation == "cancel_workflow":
            latest = self.prepare(request)
            if canonical(latest) != canonical(snapshot):
                raise Stale("GITHUB_RUN_CHANGED")
            self._api("POST", base + "/actions/runs/" +
                      str(params["runId"]) + "/cancel", body={}, expected=(202,))
            result = {"requestId": request_id, "operation": operation,
                      "repository": repo, "runId": params["runId"], "accepted": True}
        elif operation == "approve_workflow_run":
            latest = self.prepare(request)
            if canonical(latest) != canonical(snapshot):
                raise Stale("GITHUB_RUN_CHANGED")
            self._api("POST", base + "/actions/runs/" +
                      str(params["runId"]) + "/approve", body={}, expected=(201,))
            result = {"requestId": request_id, "operation": operation,
                      "repository": repo, "runId": params["runId"], "approved": True}
        else:
            raise Denied("GITHUB_ACTION_NOT_IMPLEMENTED")
        self._save_receipt(request_id, result)
        return result

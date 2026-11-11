# GitHub integration

**Current runtime:** GitHub/native worktree operations are live in Primary
`fortis-gateway` on 19204 with token-scoped multi-repo access. The original
2026-11-06 isolated review and initial 2026-11-07 promotion are dated evidence;
later releases changed the runtime image. [Current state](../../../docs/guides/FORTIS-APPROVALS-SECURE-DEVELOPMENT.md)
owns accepted source/image and deployed scope; do not copy old container IDs.

## Source map

| Concern | Location |
| --- | --- |
| Typed READ/ACTION schemas and public projections | `contract.py` |
| Fixed-origin REST transport and secure token loader | `gateway/transport.py` |
| REST adapter, ref preconditions and durable provider receipts | `gateway/adapter.py` |
| Opt-in registration, deliberately no implicit grants/policies | `registration.py` |
| Typed Repo-side provider client | `repo_client/client.py` |
| Historical M1–M3 pilot configuration/scenarios | `pilot.py`, `repo_client/pilot_scenario.py`, `repo_client/file_pr_scenario.py`, `repo_client/ci_read_scenario.py` |
| Native profile/policy and workspace adapter | `../../workflow/runtime.py`, `../../workflow/adapters.py` |
| Native bundle validation/publication | `../../workflow/git_backend.py` |
| Native Repo client/worker and closed machine routes | `../../workflow/client.py`, `../../workflow/worker.py`, `../../workflow/ingress.py` |

The [native contract](../../../docs/NATIVE-WORKTREE-GATEWAY-2026-11-06.md) is the
single source operation/policy table; deployed scope is in current state. Source implementation is broader than
admitted operations. Native includes `push_commits` and `mark_pr_ready`; ordinary
registered task push is ALLOW. PR creation is ALLOW for the installed actor and repositories admitted by the
active single-repo or dynamic mode, as described in that contract. Never infer access from a client method or the
provider token alone. Reads use closed public projections, not arbitrary provider
responses or raw file contents; `get_file` reports verified hashes/size.

## Optional analysis review

The [analysis-review source contract](../../../docs/ANALYSIS-REVIEW-CONTRACT.md) owns the new run/attempt, jobs/logs, check/annotation and artifact/manifest reads plus ASK CI controls. The CI-only router can admit explicitly configured repositories without widening native Git scope. This source profile is not deployed and has no default grants.

## Two Git write mechanisms

`push_files` is the legacy bounded REST interface: create a new commit from at
most 20 UTF-8 files, 64 KiB per file and 200 KiB total, envelope below 500 KiB.
It rejects workflow-file paths. M2 further restricted it to one selected UUID
text file (4096 bytes) and a selected pilot branch. It does not transport local
Git commits, binary files or their original SHA.

Native `push_commits` transfers the existing worktree commit objects in a Git
bundle, validates ancestry/expected remote SHA and publishes the same commit.
Bounds are recorded in the native contract and enforced in `workflow/common.py`
and the adapters. Every new commit is scanned for sensitive CI paths, including changes
reverted at the tip. Native does not grant legacy `push_files`/`create_branch`;
old pilot APIs remain implemented for their retained profiles.

## Credential and permission boundary

The isolated pilot uses a separate Gateway-only credential at
`/run/github-token/token`, regular non-symlink file, UID 10001, mode 0600,
read-only mounted. The exact run-specific volume is in the owner record.
Never copy the shared Repo helper PAT into this mount or expose a provider
credential to Repo, request arguments, environment or logs.

Accepted task push/PR/CI uses selected-repository Contents read/write, Pull
requests read/write and Actions read (plus Metadata read). Checks/status reads
need their own corresponding provider permission; workflow-file publication
needs workflow write permission. Those capabilities are not proved merely by
the accepted ordinary push/CI path. Missing actor policy/grant remains DENY
even if the token could perform the upstream operation.

The REST adapter pins `https://api.github.com`. Mark-ready uses a fixed typed
GraphQL route; native Git uses the fixed repository HTTPS origin. None accepts
an arbitrary URL, method, refspec, credential or shell body from the client.

## Token-scoped native repository discovery

With the explicit `FORTIS_GITHUB_NATIVE_MULTI_REPO=1` native opt-in,
`list_repositories` reads the authenticated token's `GET /user/repos` inventory
for the configured owner. It returns only repositories that are visible to that
token, owned by the configured account, active, and use `main` as default
branch. A target repository is independently checked through the fixed
`GET /repos/{owner}/{repo}` route before native work; there is no second local
repository allowlist. Token visibility is upstream access, not operation
authorization: Core ALLOW/ASK/DENY policy still applies, and the local worker
requires an existing non-symlink directory under `Repos/` and `Worktrees/` with
the exact HTTPS origin. Enabling this mode does not clone or onboard local
repositories automatically.

## Deployment and retained pilots

Default startup keeps GitHub disabled. M1–M3 used explicit trusted pilot scope;
native uses its separate opt-in with registered `task/*` worktrees. Shared
Core, machine identity and owner WebAuthn/queue are reused.

- M1: `Run-GitHub-Pilot-E2E.ps1`, [branch approval evidence](../../evidence/FORTIS-GITHUB-PILOT-M1-20261106.md).
- M2/M3: `Run-GitHub-FilePR-E2E.ps1`, [file/PR evidence](../../evidence/FORTIS-GITHUB-PILOT-M2-20261106.md), [completed onboarding](../../../docs/INTEGRATION-MODULARIZATION-AND-GITHUB-ONBOARDING-PLAN.md).
- Native: the same FilePR entrypoint with `-ScenarioKind Native`; [bootstrap/return contract](../../../docs/NATIVE-WORKTREE-GATEWAY-2026-11-06.md).

Resume uses original record/request IDs; ambiguous results require reconciliation.
The **historical** M1–M3 Return/rollback scripts affect only their specifically
admitted review context, not already-created GitHub branches/PRs. After Primary
promotion, use the [Primary recovery boundary](../../../docs/PRIMARY-GATEWAY-OPERATIONS.md)
and its protected records, **not** historical pilot Return as automatic fallback.
Preserve retained M3 state and the protected bootstrap worktree until owner-run
references are deliberately replaced.

Owner token replacement uses the existing controller: see the
[credential rotation runbook](../../../docs/CREDENTIAL-ROTATION.md). No provider
secret belongs in Repo/chat; source availability is separate from live rotation.

## Visual review (PNG MVP)

`WorkflowClient.github.publish_visual_review(repository="visual-workspace", run_id=...,
 title=..., description=..., media=[{"path": "/workspace/repo/Workfiles/.../<run_id>/preview.png",
 "name": "Preview"}], qa_summary=..., duration_seconds=..., request_id=..., reason=...)`

is a single typed GitHub action. `media` contains 1–5 PNG files (up to 10 MiB
each), each a regular non-symlink file inside `/workspace/repo/Workfiles`
under a directory named for `run_id`. The client stages bytes using a pinned
machine-authenticated TLS route, then submits `github.publish_visual_review`
for the exact target's runtime policy. **Only `visual-workspace`** is authorized. A fresh
run ID is used for each distinct published result; the Gateway reserves each
repository/run pair and refuses conflicting requests.

After the **installed Gateway is updated**, this exact-target action uses
`ALLOW` (no Owner Portal ASK) **only for `visual-workspace`**; the generic
`publish_visual_review` policy stays `DENY`, other GitHub writes keep their
existing ASK/ALLOW restrictions. The existing installed Gateway still uses
ASK until its owner-gated release is completed. A controlled auto-publication
request remains a real GitHub side effect: do not publish every draft.

The Gateway creates one private Issue, uploads bounded PNG user attachments
to the pinned GitHub upload host, updates the Issue and reads it back. The
final URL is returned by `WorkflowClient.result(request_id)` after EXECUTED.
`GitHubClient.list_issues(repo, state='all', page=1, per_page=30)`,
`get_issue(repo, number)` and `list_issue_comments(repo, number)` provide
read-only, paginated, exact-repository issue/comment views. `list_issues`
filters Pull Requests (the GitHub Issues endpoint includes PRs). Exact
`get_issue` and comments return recognized `github.com/user-attachments`
Markdown **references** and body: these do **not** independently prove
that attachment bytes are still accessible. `find_visual_review_run(repo,
run_id)` scans bounded pages for the Fortis *claim marker*, and requires an
exact Issue readback; a manually inserted marker is not authoritative proof
of a GitHub effect. No match or a 404 never authorizes re-sending an
UNCERTAIN/CLOSED_UNCONFIRMED request.

`WorkflowClient.details(request_id)` now attaches durable `visualReview`
evidence from the separate publisher reservation store for a correctly
identified nested Core request. This can show an `issueNumber`/upload count
for an earlier unconfirmed run after the new Gateway has been released.
No issue number or matching marker is not proof of no remote effect.
Future GithubTransportError events carry only a strictly allowlisted,
non-secret HTTP status category, e.g. `GITHUB_HTTP_403` for the REST Issues
write or `GITHUB_VISUAL_UPLOAD_HTTP_404` for an upload failure. Old generic
`RUNTIME_ERROR` events do not retroactively become more precise.

**Upload dependency and credentials:** the pinned `uploads.github.com/user-
attachments/assets` endpoint is not a standard documented GitHub REST route.
The official GitHub CLI media attachment support uses OAuth or classic PAT
credentials. GitHub App installation tokens can return 404 at the media
upload endpoint despite repository write permission. Credential type,
repository Issue-write permission and the exact failed phase must be checked
with owner-owned secure diagnostics; do not print, copy or replace any token
in this Repo client. In addition to valid JSON metadata, a live positive
E2E must verify an actual Issue and browser-visible PNGs before declaring
success. No read method validates the remote media bytes.

The running Gateway must be separately released; a source-only client cannot
enable these changes. Preserve exact UNCERTAIN, CLAIMED and worker activity
state through any owner-controlled release. A new successful E2E requires
separate approval of its source/release and no blind replay of old requests.

# Native Git/worktree Gateway workflow

Status: native source and new-task live cycles accepted on 2026-11-06 in isolated review. [Dated live evidence](../fortis_approvals/evidence/FORTIS-NATIVE-GIT-LIVE-20261106.md) owns SHA/CI/request receipts and verification limits. **The statement that Legacy Production was unchanged applies to that 2026-11-06 acceptance, not to today's deployment:** the accepted Primary was promoted on 2026-11-07 and Legacy was stopped; use [current state](guides/FORTIS-APPROVALS-SECURE-DEVELOPMENT.md) and [cutover evidence](../fortis_approvals/evidence/FORTIS-PRIMARY-CUTOVER-LIVE-20261107.md). This profile remains explicit/opt-in and uses the existing Core, TLS machine grant, owner session and WebAuthn device.

## Policy in the native source profile

This is the source contract. Before cleanup, check live capabilities:
`cleanupTask = {merged: ALLOW, unmerged: ASK, proof: github-main-v1}` identifies
this policy. A runtime without that marker retains the previous receipt-only
ASK contract; do not send it the new request shape. Installed release and dated
live verification belong to [current state](guides/FORTIS-APPROVALS-SECURE-DEVELOPMENT.md);
remaining acceptance belongs only to the [backlog](BACKLOG-IMPROVEMENTS.md).

All grants are restricted to the configured owner, admitted repository mode and authenticated Repo actor. An operation missing from this profile is denied.

| Operation | Policy | Conditions |
| --- | --- | --- |
| get_repository, list_branches, list_commits, get_file, list_pull_requests, get_pull_request, list_workflow_runs, list_check_runs, get_commit_status | ALLOW | Selected repository, closed projected read contracts |
| list_repository_labels, list_pr_labels, get_pr_release_label_context | ALLOW (**SOURCE CANDIDATE; not live until owner release**) | Selected token-scoped repo, bounded projections, only PR context, exact SHA/body/labels fingerprints; see UC-GW-011 |
| create_release_label, add_pr_release_labels, remove_pr_release_label | ASK (**SOURCE CANDIDATE; not live until owner release**) | Narrow managed names only, registered same-repo open task PR, exact head/base/body/label digest, full readback + Core receipt; owner approval and STOP on UNCERTAIN |
| get_workflow_run, list_workflow_jobs, get_job_log | ALLOW (new source, awaiting release) | Exact GitHub repo/run/attempt/SHA and job membership, bounded/redacted logs, no Sonar project required |
| get_check_run, list_check_annotations, list_run_artifacts | ALLOW (new source, awaiting release) | Same owner/token scope; Checks endpoints may require unavailable provider token permission |
| get_analysis_manifest | ALLOW (new source, awaiting release) | GitHub CI artifact metadata is CI_RECORDED_NOT_SONAR_VERIFIED; unpinned project key proves nothing about Sonar |
| rerun_failed_jobs, rerun_job, cancel_analysis_run, dispatch_analysis_workflow | DENY by default; per-repository ASK opt-in (new source) | Exact approved repositories, run/attempt/SHA/fork checks, owner WebAuthn; no silent CI mutations |
| workspace.inspect | ALLOW | Canonical main or registered linked task worktree; HEAD/status/diff/index/tree digest and worktree inventory |
| workspace.fetch | ALLOW | main or task/<slug>; Gateway provides verified Git bundle |
| workspace.create_task | ALLOW | Clean canonical main; upstream main SHA; canonical linked worktree path; optional explicit adoption of an existing clean task at an exact SHA |
| workspace.edit | ALLOW | Registered task, exact HEAD/tree digest, bounded file changes |
| workspace.check | ALLOW | Fixed syntax profile; isolated Python compile, no project code execution or cache writes |
| workspace.stage | ALLOW | Selected paths, exact HEAD/tree digest |
| workspace.commit | ALLOW | Exact parent/index digest; local commit objects retained |
| workspace.sync_task | ALLOW | Clean task, exact HEAD and upstream main; ordinary merge |
| github.push_commits | ALLOW | Registered task/*, exact existing Git commit SHA and expected remote SHA, ancestry and atomic remote lease |
| github.push_commits affecting .github/workflows | ASK | Every new commit is scanned, including intermediate changes reverted at the tip; preview bound to bundle digest |
| github.create_pull_request | ALLOW | Admitted actor; registered task branch to main. Single-repo mode pins the configured repo; dynamic mode admits token-scoped owner repos. No grant for other actors |
| github.update_pull_request | ASK (source candidate; not live until owner release) | Replace **only** PR description on a registered, open, same-repository task PR to main; exact HEAD, immutable body digest in preview, recheck before PATCH, bounded UTF-8, independent readback and receipt; no title/refs/merge or retry on UNKNOWN |
| github.mark_pr_ready | ASK | Open draft from this repository, exact HEAD/node ID |
| github.merge_pull_request | ASK | Implemented machine gate, not the normal AI delivery route: exact ready PR HEAD and required CI; bootstrap uses its configured workflow ID, dynamic repos use supported active branch rules |
| github.update_workflow_file | ASK | Existing dedicated typed workflow operation on a registered task branch; separate GitHub workflow permission |
| workspace.update_main | ALLOW | Legacy route: executed Gateway merge receipt and exact main SHA; clean local main, fast-forward only |
| workspace.update_main_from_pr | ALLOW | Owner GitHub UI merge evidence, exact PR head/merge/current remote main; clean local main, fast-forward only |
| workspace.cleanup_task, merged task | ALLOW | Trusted proof of exact task HEAD accepted in current GitHub main; local worker verifies immutable main bundle/ancestry. Clean task including ignored files, exact registered path/branch, bootstrap retained |
| workspace.cleanup_task, unmerged or unproven task | ASK | Same local guards; explicit owner WebAuthn decision binds exact repository/task/HEAD and preview before removing unmerged local work |
| create_branch, push_files | DENY in native profile | Old M1–M3 APIs remain available only in their old pilot profiles |
| list_repositories | ALLOW in dynamic mode; DENY in single-repo mode | Authenticated token inventory for configured owner; visibility is not write permission |
| direct main push, force history rewrite, remote deletion, raw shell/URL/refspec | DENY | Not exposed by this profile |
| dispatch_workflow, rerun_workflow, cancel_workflow, approve_workflow_run | DENY | No grants |
| Sonar reads / accept_issue | Existing ALLOW / ASK | Existing Sonar integration unchanged |

GitHub token permissions already used by the accepted pilot cover Contents read/write, Pull requests read/write and Actions read. Checks and commit-status reads need their corresponding read permissions if used. Workflow-file publication additionally needs GitHub workflow write permission. No token belongs in Repo or chat.

## Ordinary native GitHub CI diagnosis — source candidate (2026-11-09)

The native Gateway profile reuses the typed GitHub analysis adapter for
**seven** GitHub READ operations and **four** CI control operations independently
of SonarCloud. `get_workflow_run` → `list_workflow_jobs` → `get_job_log` permits
diagnosing an exact failed run without a GitHub connector. Read grants are
restricted to the authenticated Repo actor and GitHub owner/token scope.
Workflow ID/path and run/job/SHA/attempt are checked using GitHub responses.

`get_job_log` downloads only the selected job via narrowly scoped redirect,
with no bearer on the second hop, a 2 MiB download limit, 500 lines/64 KiB per
response and best-effort secret redaction. Arbitrary CI logs may still contain
secrets. GitHub Checks reads require provider permissions independent of Actions
Read. `get_analysis_manifest` returns only a CI-recorded claim, not proof of
Sonar analysis; Sonar reports remain a separate optional profile.

CI controls are DENY until an owner-reviewed release sets
`FORTIS_GITHUB_CI_CONTROL_REPOSITORIES=repo1,repo2` using Windows controller
`-CiControlRepositories` with `-Build -SourceSha`. Each selected owner-scoped
repo then receives ASK; every mutation requires the owner's WebAuthn decision.
The protected release record and admission checks bind this opt-in; it cannot
come from AI params or an unreviewed environment edit. After deployment,
`/v1/workspace/capabilities` advertises `githubCiReads` and the exact trusted
`githubCiControls` opt-in, allowing Repo to distinguish source availability
from live activation.

**Rollout boundary:** these are source changes, not live Primary capabilities.
Owner merges the PR, verifies exact SHA and CI, performs controlled release,
then confirms jobs and logs for a real failed CI run. Never edit the running
Gateway env or protected records manually. See
[analysis-review contract](ANALYSIS-REVIEW-CONTRACT.md) for Sonar-only opt-in.

## Dynamic token-scoped repositories — activated 2026-11-07

The reviewed source and current Gateway release include an **explicit opt-in**
`FORTIS_GITHUB_NATIVE_MULTI_REPO=1` to the native workflow. The existing
`FORTIS_GITHUB_REPOSITORY` stays as the legacy/bootstrap identity (and keeps its
previous pinned required-workflow ID). It is **not** a repository allowlist in
the new mode. Other repository names must be valid owner-owned GitHub repo
slugs; upstream access is checked using the Gateway-only credential. The actual
permission to publish is exercised by GitHub during the request, not inferred
from publicly visible repository metadata. Caller-supplied Git remotes/URLs,
filesystem paths, tokens, arbitrary Git commands and cross-owner targets stay
denied. The Repo-local worker resolves the exact canonical checkout beneath
`/workspace/repo/Repos/<repo>` and linked worktrees under
`/workspace/repo/Worktrees/<repo>`, requiring an existing real primary Git
repository, registered task worktree and correct origin. Missing directories or
symlink paths mean STOP, not automatic repository creation.

For machine merge operations on repositories other than the bootstrap source,
policy still requires ASK + Owner WebAuthn. This describes the implemented gate,
not an instruction for the AI to submit merge requests: the normal delivery
route is owner GitHub UI merge under UC-CONT-002. The implementation reads **active branch rules for `main`**
from GitHub; `required_status_checks` must be present. It checks all required
statuses against the exact PR HEAD, supports check-run/commit-status evidence,
and rejects failed, pending, missing, unsupported or unknown requirements.
GitHub classic branch-protection rules without available equivalent active
rules are **not automatically supported for merging**: require explicit owner
review and a verified follow-up, not a guessed workflow ID. The original
bootstrap repo retains its pinned required-workflow check.

**Rollout boundary:** installing this image alone does not enable the feature.
The reviewed implementation extends `Manage-Integrations.ps1` with
`-EnableDynamicGitHubRepositories`, accepted only with a source-pinned
`-Build -SourceSha <approved-main-sha>` for `-Action Check`/`-Action Apply`.
The owner controller binds the flag to the protected runtime release record,
regenerates the public environment and makes `State-Helper` reject a mismatched
container (including flag absence, duplication or unexpected enablement).
The flag is retained on later accepted releases when the source runtime has it;
`Backup`/`Promote` cannot independently enable it. The owner applied exact merged source `0a262ea50832aae4db200ce0d0b431e45c22dd07`
on 2026-11-07 and confirmed the active multi-repo Primary. Repo-side live read
and `tunnel` task-branch push confirmed token-scoped access; see
[multi-repo workflow evidence](MULTI-REPO-WORKFLOW-REVIEW-20261107.md).
This evidence does not guarantee write scope, PR/CI rules or merge for every
discovered repository. Do not edit the running container env or release records
manually; all future updates still use the owner controller.
[GitHub active branch rule API](https://docs.github.com/en/rest/repos/rules#get-rules-for-a-branch)
is the source for new-repo required check names; this is not a second repo list.

## PR creation source rollout

The active policy is composed in `fortis_approvals/workflow/runtime.py` and
advertised by live capabilities. PR creation is ALLOW for the admitted actor;
dynamic mode uses token-scoped owner repositories, while single-repo mode pins
the configured repository. Registered task/main/ref checks, durable request IDs
and no-blind-retry semantics remain enforced. The original review rollout is
[dated evidence](../fortis_approvals/evidence/PR-CREATION-ALLOW-LIVE-20261106.md),
not the identity of today's Primary. Runtime scope belongs to
[current state](guides/FORTIS-APPROVALS-SECURE-DEVELOPMENT.md).

## Caller authorization for ASK submission

The user permits preparing and submitting necessary ASK proposals within the
assigned task without an extra conversational permission round. Submit the
reviewable intent directly; the external effect remains behind Owner Portal.
A chat confirmation is not a WebAuthn proof. A real outer MCP/tool-review block
must still be reported and respected. For PR merge, UC-CONT-002 requires the owner to merge in GitHub UI; AI does not
call `merge_pull_request` or create its ASK. Container UC-CONT-007 owns the other ASK usage routes;
this contract owns the operation policy and preconditions.

## Execution boundary

Repo sends typed requests to the Gateway. Local operations are queued only after Core authorization. The Repo worker claims the existing request, checks authoritative git worktree list --porcelain -z, canonical paths, common Git directory, branch and immutable preconditions, executes the fixed command, then reports a durable local receipt. Core remains DISPATCHED until that effect is confirmed. Cleanup authorization alone is never reported as successful deletion.

For push, Repo freezes a bundle containing the actual local commit objects. Gateway quarantines and verifies it, checks ancestry, paths and every new commit, then publishes exactly one task ref with native Git over its fixed GitHub HTTPS origin. The internal explicit force-with-lease is a compare-and-swap safeguard after ancestry validation, not permission to rewrite history. Readback must equal the original local commit SHA. Binary content, executable mode, deletions, parent history and signatures are not reconstructed as API file commits.

Fetch also goes through Gateway; Repo imports the returned bundle locally. Neither path invokes the old credential helper or a GitHub connector. The provider credential remains in Gateway, supplied to Git through a private temporary configuration, absent from Git arguments and Repo. Redirects, proxies, configured credential helpers, hooks, external protocols, submodule recursion and configured checkout filters are disabled for these operations.

Local operations are serialized across worktrees using the common Git directory. Request UUIDs and frozen payload digests prevent duplicate commits and repeat publication. An uncertain effect is stopped and shown as UNCERTAIN; reconciliation reads durable receipts and never blindly repeats a mutation. External ambiguous results without a durable receipt require inspection.

The command-line entrypoint is python3 -B -m fortis_approvals.workflow.client OPERATION --request-id UUID. It reads a typed JSON body on stdin. The WorkflowClient Python interface additionally provides the existing typed GitHub read/PR methods. resume services the same queued local request after an owner decision; it does not create a replacement request.

This is a Linux Docker Repo worker, not a Windows shell bridge or a transparent arbitrary git push proxy. The existing Windows Mirror receiver remains a separate established mechanism after approved main update. No new arbitrary Windows-command capability is introduced.

## Bounds

Bundle: 24 MiB; at most 200 new commits. Edited content: 16 KiB per request,
20 files; selected stage paths: 64. Paths/preview are bounded, Git processes
resource-limited and operations serialized. Larger repositories, Git LFS,
submodule workflows, remote branch deletion, conflict-resolution automation
and squash/rebase merges are not accepted by this slice. Required CI is an
explicit configured workflow ID for bootstrap and supported active branch rules
for dynamic repositories. Unsupported rule models remain STOP.

## Completed first source bootstrap

The retained M3 image could not receive native Git bundles. The implementation was committed locally and packaged from its exact clean task worktree. This explicit bootstrap exception allowed the owner to start the isolated native image first; source publication, CI and merges then completed through that Gateway without the old helper or connector. It was not a Production deployment. The following sequence describes the completed bootstrap, not a request to run it again.

The owner package uses Run-GitHub-FilePR-E2E.ps1 -ScenarioKind Native. It:

1. Verifies package hashes, exact source commit, canonical linked task worktree and unchanged clean primary main at e8dd217e1279c5ec8e1ad6b4e2ff893d01aa5dbc.
2. Admits the accepted protected M3 record, its exact source/image/CI result and retained M2/M1 receipts. Runs Windows self-tests in child PowerShell 5.1 processes before any build/stop.
3. Builds and smoke-tests the image offline, including installed native Git/runtime imports, without a provider mutation.
4. Stops only the admitted M3 review container; copies its stopped state into a fresh dedicated volume, preserving credentials/history/receipt bytes. Keeps M3 image/container/state and token volume for return.
5. Starts a new isolated review container on 19203/19204, with native opt-in, exact repository/required workflow and protected bootstrap task. Checks capabilities, retained receipts, ordinary Sonar read and Production baseline.
6. Emits FORTIS_GITHUB_NATIVE_WORKTREE_READY and liveNativeCycleVerified=false. This marker is readiness, not live E2E PASS.

Use the existing owner device at http://localhost:19203. No fresh enrollment or token provisioning is needed for the initial ordinary task push. Resume and Rollback use the same schema-4 record and expected source commit. Rollback stops only the new review and starts the retained M3 after unchanged-state verification. Do not delete either state volume.

The bootstrap source task cannot be cleaned while an owner deployment record
depends on its source path. Retargeting work is tracked in the backlog, not
as an additional step of ordinary task delivery.

<a id="accepted-live-path-and-remaining-work"></a>

## Accepted live path and client status

Both existing-source publication and a newly created task completed through
Gateway: source PR №10 and test PR №11, exact-head Source CI, approved merge,
Docker main fast-forward and approved test-task cleanup. [Live evidence](../fortis_approvals/evidence/FORTIS-NATIVE-GIT-LIVE-20261106.md)
records the receipts; [offline evidence](../fortis_approvals/evidence/FORTIS-NATIVE-GIT-OFFLINE-20261106.md)
records the broader denial, binary and concurrency cases. Do not treat those
offline cases as additional live GitHub acceptance.

The current Repo client rejects HTTP 202 when `result`/`reconcile` reads PENDING.
Use the typed `WorkflowTransport.post` result/reconcile route with
`accept_202=True` for pending reads; preserve the request ID and never resubmit
an action merely to work around status handling. An early owner decision does
not change that requirement. Client fixes and other unfinished acceptance are
tracked only in the [backlog](BACKLOG-IMPROVEMENTS.md).

<a id="source-candidate-external-owner-github-ui-merge-acceptance-not-deployed"></a>

## Owner GitHub UI merge acceptance — active

For normal delivery, the AI creates the PR and reports its exact HEAD/CI and
GitHub URL; the owner merges in GitHub UI. The installed Primary advertises
`workspace.update_main_from_pr`; live use has been verified after the
owner-managed source/image update of 2026-11-07. Source presence alone remains
insufficient for other runtimes: check their capabilities first.

`workspace.update_main_from_pr` takes `expectedHeadSha`, `number`,
`expectedPrHeadSha`, `expectedMergeSha`. It checks authenticated GitHub evidence:
closed, merged, ready same-repo `task/*` PR; actual owner `merged_by`; exact
head/merge SHA and current remote `main`. The Repo worker only fast-forwards a
clean local primary. This route validates owner merge evidence; it does not
forge a Core approval or independently certify every GitHub CI requirement.
Required checks/review must be satisfied through the configured GitHub process.
The older `workspace.update_main` requires a Gateway merge request ID and is
not a substitute after owner UI merge.

`workspace.create_task` retains the clean canonical `main` requirement: a task
starts from a commit, so staged/unstaged/untracked primary changes would be
omitted. Preserve and migrate historical changes by UC-CONT-019, without
automatic stash/reset/clean. Both main-update routes also require clean primary.
The client/API change procedure belongs to
[UC-GW-003](use-cases/integrations.md#uc-gw-003).

## PR3: Repo-side Git/PR delivery facade (source candidate)

The Repo-side `default_client().git_delivery` (implemented in
`fortis_approvals/workflow/client.py`) composes the existing native
`publish()` (real Git bundle, exact SHA and server-side `--force-with-lease`)
with the existing typed GitHub PR creation. It needs **no new Gateway endpoint,
credential, capability, policy or production image change**. `inspect()` only
reads bounded GitHub branch and PR inventories (open **and** closed); it returns
`DONE` if the open PR already points at the intended commit, `CONTINUE` if a
push or PR is needed, and `STOP` on inconclusive/inconsistent evidence. A
complete list is required before an absence-based decision. Existing PRs on
closed/merged branches are never silently duplicated.

```python
from uuid import uuid4
from fortis_approvals.workflow.client import default_client

c = default_client()
repo, task = 'my-repo', 'my-task'  # registered worktree and authorized repo
sha = '0' * 40                    # replace with the actual committed task HEAD
view = c.git_delivery.inspect(repo, task, sha)  # READ-only, no UUID created
if view['status'] == 'CONTINUE':
    # Preserve these two real UUIDs in the task record before submit.
    # Include the repository's exact-head Release Impact YAML block in body.
    result = c.git_delivery.submit(
        repo, task, sha, title='Reviewed change', body='PR body with releaseImpact',
        draft=False, push_request_id=str(uuid4()), pr_request_id=str(uuid4()),
        reason='Authorized task publication and review PR')
```

`submit()` performs **at most one push and one PR creation** per call, with
separate immutable request IDs and a provider READ after each stage. It
computes the actual remote `expectedHeadSha`: **`None` when the branch does
not exist**, the exact remote SHA when updating. It never treats the local
`main` SHA as the remote task ref precondition. It validates the registered,
clean local worktree and committed HEAD before pushing. If the branch is
already published, it skips the push; if the exact open PR already exists,
it skips both WRITE calls. A lost response can resolve as goal-state `DONE`
without fabricating an original Core receipt. `STOP` means **do not call the
facade again blindly**: inspect the preserved UUID(s) with `details()` /
`incidents.inspect()` and compare fresh exact GitHub state. It does not issue
retries automatically; the bounded budget of up to three logical mutation
attempts, fresh ALLOW/ASK/DENY and new UUIDs for genuinely new intents remain
under [UC-CONT-003](https://github.com/AlexPastukhh/fortis-container/blob/main/docs/use-cases/delivery.md#uc-cont-003).
`PENDING` requires owner approval before further work. Owner merges the PR
only through GitHub UI; this facade does **not** merge, sync primary `main`,
manage Issues/PNG, deploy Gateway or bypass any existing policy.

## Task worktree cleanup

Use `WorkflowClient.cleanup_task(repository, task, expected_head_sha, request_id=...,
reason=...)` after inspecting the exact registered task. The closed request
contains only `task` and `expectedHeadSha`; the caller cannot select ALLOW,
assert `merged`, pass `force`, or supply a filesystem path. No Gateway merge ASK
is needed after a GitHub UI merge. Older requests with `mergeRequestId` remain
accepted and validate that executed merge receipt too; old queued worker jobs
retain their previous exact-main/ancestry guards. New previews also retain
`mergeSha` for older Repo workers: those workers can refuse the new proof,
but cannot remove unmerged work or fail because that legacy field is missing.

The Gateway derives ALLOW from authenticated GitHub evidence: either exact task
HEAD is an ancestor of current remote `main`, or a closed merged same-repository
`task/<slug>` PR has that exact HEAD, targets `main`, and its merge SHA is an
ancestor of current main. The second path covers squash/rebase. Associated PR
lookup is bounded to 100 entries; missing or inconclusive merge evidence is
ASK, never automatic deletion. Invalid responses/access failures do not grant
ALLOW. A later main commit is fine; a changed main during one request invalidates
its original proof (approval is denied or execution becomes stale). A PR for an older task head does not cover additional local commits.

Both paths bind the proof in the Core preview and recheck it before dispatch.
For ASK the owner authorizes loss of the unmerged **committed** local task;
without approval there is no removal. The worker independently fetches the
exact main bundle through Gateway, verifies the accepted commit's ancestry,
then checks the selected task's actual HEAD, canonical path/branch, common Git
directory, worktree lock and tracked/index/untracked/ignored state. A stale
local primary may remain untouched. Dirty or ignored files block removal even
after approval; preserve or publish them first, without automatic reset/clean.

Only that clean linked worktree and its exact local `task/<slug>` branch are
removed, then its Gateway registration is closed. The remote branch and main
are unchanged. No `worktree remove --force`, bulk prune or remote deletion is
exposed. Bootstrap/deployment source still must be retained while protected
records refer to it. Reuse the UUID only for the same intent; an uncertain
partial effect goes to reconcile, never a blind new deletion request.

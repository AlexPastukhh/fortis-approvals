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

The command-line entrypoint is python3 -B -m fortis_approvals.workflow.client OPERATION. Supported coordinated operations accept a typed JSON body on stdin and do not require --request-id; other commands retain their explicit UUID. Use retry --intent-id INTENT_ID to continue an intent without stdin. The WorkflowClient Python interface additionally provides the existing typed GitHub read/PR methods. resume services the same queued local request after an owner decision; it does not create a replacement request.

This is a Linux Docker Repo worker, not a Windows shell bridge or a transparent arbitrary git push proxy. The existing Windows Mirror receiver remains a separate established mechanism after approved main update. No new arbitrary Windows-command capability is introduced.

## Git transfer failure evidence and quarantine reuse (source)

The Git runner keeps bounded failure classes for reported authentication/access,
rate limits, TLS/network, upstream HTTP failures, local resource failures,
process signals and an unclassified non-zero exit. A subprocess deadline is
reported as `GIT_OUTCOME_TIMEOUT` only when that deadline actually fires.
Operator logs contain fixed codes, elapsed milliseconds and exit codes, never
Git stderr, command arguments or credential configuration. These observations
are symptoms, not proof of a root cause or of non-execution.

Artifact and fetch errors carry bounded diagnostic/phase headers. New clients
can distinguish a permanent reported auth/configuration problem from a
retryable network failure without treating every Git error as policy DENY.
Core push errors preserve the outer phase and, when known, `gitPhase` within
validation. Historical generic errors cannot be reconstructed retroactively.
These server diagnostics require an owner-managed Gateway release.

Within `backend.push`, a fresh validation now retains its private quarantine
through the lease-protected push and independent remote readback. This removes
the second main fetch and repeated bundle import inside that push. Artifact
admission remains a separate validation, so a complete successful publication
still validates at admission and immediately before effect. SHA/CAS, ancestry,
object limits and every-new-commit sensitive-path checks remain enforced.

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

## Repo-side Git/PR delivery facade (source)

The default Repo client composes task publication and PR creation through one
durable parent intent. The child push and PR intents own all effect retries,
budgets, fresh attempt UUIDs, owner waits and exact-SHA checks.

```python
from fortis_approvals.workflow.client import default_client

c = default_client()
result = c.git_delivery.submit(
    repo, task, committed_sha, title='Reviewed change',
    body='PR body with exact-head releaseImpact', draft=False,
    reason='Authorized task publication and review PR')
# If the returned nextAction permits continuation:
result = c.intents.retry(result['intentId'])
```

There is no need to allocate push/pr UUIDs or manually repeat their readbacks.
An unchanged submit resumes the same parent and does not reset child budgets.
Explicit retry continues the stage that is waiting or exhausted. A completed
push is not repeated while continuing PR creation. The result contains the
parent intentId, stage, children, all attemptIds and actual latest
pushRequestId/prRequestId. Explicit legacy push/pr IDs remain the first
attempt IDs; later attempts still receive fresh UUIDs.

The initial READ-only inspect() remains available. It checks an exact branch
and all PR matches for the same repository/head/base when the new target-READ
capability is present, with complete legacy inventories as fallback. Closed
or ambiguous prior PRs, a mismatched draft flag and competing SHAs stop delivery.
The remote task ref precondition is None for an absent branch and the exact
remote SHA for an update. The parent pins the requested commit for PR checks;
a changed branch cannot silently change the intended PR head.

Confirmed child receipts replace facade postflight inventory scans. The facade
does not merge, update main, publish Issues or deploy Gateway. Owner PENDING
waits on the existing request; owner merges through GitHub UI.

## Automatic READ retries and intent continuation (Repo source)

The shared Repo transport retries semantic READ routes up to three times for
HTTP 429, transient 5xx and network errors. GitHub 403 is retried only with a
rate-limit/backoff signal; permission, authentication and validation failures
stop. READs do not inspect effect receipts or create new mutation intents.
The client respects bounded `Retry-After` and primary reset evidence, with a
120-second wait budget. Older local 429 responses without a header wait 60
seconds. Longer backoff is returned to the caller without an early retry.
New Gateway source supplies bounded Retry-After for its own throttles and
for GitHub READ backoff. Source changes require separate Gateway deployment;
the Repo client's fallback also works with older Gateway images.

`default_client()` enables the Repo-side `client.intents` coordinator for
`create_task`, `update_main`, `update_main_from_pr`, task commit publication,
PR creation, branch creation, mark-ready, PR-description update, managed PR
label add/remove and visual-review Issue publication. Existing public command
methods delegate to it; unsupported effects, merge and workflow dispatch are
not given generic HTTP retries. Directly constructed WorkflowClient keeps
single-attempt behavior unless `automatic_recovery=True` is explicitly set.
Gateway `diagnosticContract.automaticRetry=false` describes server-side effect
recovery; it does not disable this separately implemented Repo coordinator.

```python
c = default_client()
# A request_id can be omitted for supported commands. Identical inputs select
# the same durable logical intent; the machine grant is never journaled.
r = c.command('create_task', 'my-repo',
    {'task': 'my-task', 'baseSha': verified_main_sha, 'adoptHeadSha': None},
    reason='Create the task worktree')
if r['status'] == 'RETRY_EXHAUSTED':
    r = c.intents.retry(r['intentId'])
```

**intentId is not an attempt requestId.** The first supplied request_id remains
the first Gateway UUID for compatibility. Every genuinely NEW attempt uses a
fresh UUID, written durably before staging/submit. The journal preserves all
attempt IDs for status/readback; it never overwrites their payloads or replays
UNCERTAIN claims. Without an explicit ID, identical typed inputs derive a
stable logical intent. Changing input under a supplied intent ID is rejected.
The journal is Repo-local private coordination, not authorization or a receipt.

One automatic round permits three attempts. An unchanged ordinary call resumes
the same journal and cannot silently reset that budget. Explicit
`client.intents.retry(intentId)` permits the next bounded round and generates
new attempt IDs internally. It rechecks current results and preconditions;
it does not bypass a real denial, changed SHA, dirty/partial worktree, incomplete
READ, existing owner PENDING or potentially active worker. Exact queued local
jobs may receive their first authorized delivery after owner approval, never
an existing CLAIMED token. Reconciliation is restricted to positive bound
receipts and is an authorized continuation, not a hidden read-only operation.

Results carry `intentId`, result-bound `requestId`, `lastAttemptId`, `attemptIds`, `status`
(`DONE`, `WAITING`, `STOP`, `RETRY_EXHAUSTED`) and target-state evidence. A goal
confirmed by READ without the original receipt stays `GOAL_REACHED`, not a
fabricated EXECUTED result. If an earlier attempt confirms late, requestId and effect.requestId identify that receipt; lastAttemptId still identifies the latest attempted UUID. A matching local worktree without confirmed Gateway
registration is incomplete and is not silently adopted.

### Results and continuation

Results separate effect.state from verification.state. Once the original
request has acknowledged EXECUTED, an unavailable receipt READ returns WAITING
with effect.state=EXECUTED and nextAction.kind=RETRY_READ. Continuation reads
that original result and cannot submit another effect. A complete receipt must
match requestId, operation, repository and the target identity/SHA. A later
unavailable details() or a changed live target does not erase that execution.
Conflicting receipt identity is STOP. READ-confirmed target success without an
attributable receipt stays GOAL_REACHED with an unconfirmed original effect.

| nextAction.kind | Caller action |
| --- | --- |
| NONE | Intent complete |
| RETRY_INTENT | Continue the same intentId when another round is intended |
| RETRY_READ | Continue the same intentId to obtain the acknowledged result |
| WAIT_BACKOFF | Respect retryAfterSeconds; continuation retains backoff |
| WAIT_OWNER | Wait for the existing owner ASK |
| WAIT_EXISTING_REQUEST | Wait for the existing job; no replacement WRITE |
| FIX_PRECONDITION | Resolve the reported denial, conflict or configuration |

CLI uses the same coordinator:
```sh
python3 -B -m fortis_approvals.workflow.client create_task < task.json
python3 -B -m fortis_approvals.workflow.client publish < publish.json
python3 -B -m fortis_approvals.workflow.client git-delivery < delivery.json
python3 -B -m fortis_approvals.workflow.client retry --intent-id INTENT_ID
```

resume --request-id UUID keeps its existing meaning: service the same queued
local request after owner approval. It is distinct from intent retry. The
--request-id compatibility argument does not make a failed attempt replayable.

Capabilities are passed from default_client() into the coordinator once and
remain advisory. A fresh server admission still checks every WRITE. New
githubTargetReads version 1 supports repository-access-checked get_branch and
same-repository head/base find_pull_requests. A branch 404 requires a successful
repository access check; a search includes open/closed/merged PRs, validates
repository/ref identity and follows bounded pages. Multiple matches or incomplete
READ stop. Missing capability uses the old complete lists; a denied new READ
does not trigger a permission fallback. Source/server deployment is required
for the new capability. Offline budgets are at most 4 coordinator READs on
normal PR creation and 10 after one pre-effect 500, excluding one initial
capabilities READ and counting provider-side reads separately.

Task publication reuses one immutable intent-bound local bundle across new
attempt UUIDs, with fresh clean worktree/HEAD checks and digest validation.
Each new effect still gets fresh server artifact admission and Git validation.
No server artifact lifetime or cross-operation quarantine cache is assumed.
There is no overall intent deadline. The existing per-call wait budget only
limits blocking backoff and returns WAITING for a longer required pause.

Automatic retries stop on reported Git auth/access, TLS or resource failures.
After repairing a transport/configuration failure, explicit retry can recheck
current conditions under a new UUID. Original failure evidence is retained;
a real Core denial, active worker, changed SHA or owner ASK cannot be overridden.

For visual-review Issues the duplicate risk is accepted. Before a new attempt,
the coordinator searches known run markers and stops at the first matching
publication. A new attempt has a new requestId and runId, while unchanged PNG
bytes remain bound to the original preview. The coordinator does not treat an initial Issue
without its final expected preview links as a complete visual publication;
such a partial result stops with the Issue number for separate recovery.
After a complete publication it
does **not** perform an automatic second-Issue/duplicate scan. The result always
returns `manualDuplicateCheckRequired=true` and all attempt/run IDs. A separate
manual check must inspect open/closed Issues for all markers and the common
task identity, report any copies and identify the canonical Issue; do not
automatically delete/close them. Provider support is visual-review Issue
publication, not an invented generic create_issue operation.

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
records refer to it. Reuse the original UUID only for readback of its
original intent; neither an HTTP 500 nor an unknown historical receipt alone
blocks safe completion of cleanup. **Decision for a new `cleanup_task`:** read
current `git worktree list --porcelain`, exact registered repo/task/HEAD,
branch, ignored/untracked/tracked cleanliness, live capability/policy and
worker state. If the exact worktree **and** task branch have already gone,
cleanup is complete (do not repeat). If the exact registered worktree remains
clean at the expected HEAD, its branch remains, no worker is actively
executing it, and fresh admission permits deletion, **submit a new typed
request with a new requestId**; the Core preview and worker revalidate the
same exact object, so an earlier completed cleanup makes the new attempt
fail closed rather than silently removing another task. Up to three attempts
in total, including the original, with fresh readback after each. Missing
original receipt or `result(UUID)=NOT_FOUND` is not a reason to postpone
forever; `details(UUID)` returning 403 is not permission to bypass Gateway,
but use the other authorized readbacks and live preconditions. If the removal
is partial (missing worktree but lingering branch/registration), the old
worker is still `CLAIMED`, protected source is still needed, or the exact
checks cannot be completed, STOP with the concrete discrepancy, **not**
force-clean/prune/replay. Reconcile is a separate Core-state operation, not
a prerequisite for every new, safely authorized cleanup intent.

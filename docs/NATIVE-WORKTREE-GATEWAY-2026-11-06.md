# Native Git/worktree Gateway workflow

Status: implemented source and offline acceptance. Native GitHub live acceptance is still required. Production remains unchanged. This profile is opt-in and uses the existing Core, TLS machine grant, owner session and WebAuthn device.

## Active policy in the native profile

All grants are restricted to the configured owner/repository and authenticated Repo actor. An operation missing from this profile is denied.

| Operation | Policy | Conditions |
| --- | --- | --- |
| get_repository, list_branches, list_commits, get_file, list_pull_requests, get_pull_request, list_workflow_runs, list_check_runs, get_commit_status | ALLOW | Selected repository, closed projected read contracts |
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
| github.create_pull_request | ASK | Registered task branch to main; draft or regular PR |
| github.mark_pr_ready | ASK | Open draft from this repository, exact HEAD/node ID |
| github.merge_pull_request | ASK | Open ready PR, exact HEAD, required workflow ID 408327525 successful for that HEAD; merge method merge |
| github.update_workflow_file | ASK | Existing dedicated typed workflow operation on a registered task branch; separate GitHub workflow permission |
| workspace.update_main | ALLOW | Previously owner-approved and executed merge receipt, exact resulting upstream main SHA; clean local main, fast-forward only |
| workspace.cleanup_task | ASK | Exact approved merged head, main already updated, clean task including ignored files, branch not in another worktree; bootstrap source task retained |
| create_branch, push_files | DENY in native profile | Old M1–M3 APIs remain available only in their old pilot profiles |
| list_repositories, direct main push, force history rewrite, remote deletion, raw shell/URL/refspec | DENY | Not exposed by this profile |
| dispatch_workflow, rerun_workflow, cancel_workflow, approve_workflow_run | DENY | No grants |
| Sonar reads / accept_issue | Existing ALLOW / ASK | Existing Sonar integration unchanged |

GitHub token permissions already used by the accepted pilot cover Contents read/write, Pull requests read/write and Actions read. Checks and commit-status reads need their corresponding read permissions if used. Workflow-file publication additionally needs GitHub workflow write permission. No token belongs in Repo or chat.

## Execution boundary

Repo sends typed requests to the Gateway. Local operations are queued only after Core authorization. The Repo worker claims the existing request, checks authoritative git worktree list --porcelain -z, canonical paths, common Git directory, branch and immutable preconditions, executes the fixed command, then reports a durable local receipt. Core remains DISPATCHED until that effect is confirmed. Cleanup authorization alone is never reported as successful deletion.

For push, Repo freezes a bundle containing the actual local commit objects. Gateway quarantines and verifies it, checks ancestry, paths and every new commit, then publishes exactly one task ref with native Git over its fixed GitHub HTTPS origin. The internal explicit force-with-lease is a compare-and-swap safeguard after ancestry validation, not permission to rewrite history. Readback must equal the original local commit SHA. Binary content, executable mode, deletions, parent history and signatures are not reconstructed as API file commits.

Fetch also goes through Gateway; Repo imports the returned bundle locally. Neither path invokes the old credential helper or a GitHub connector. The provider credential remains in Gateway, supplied to Git through a private temporary configuration, absent from Git arguments and Repo. Redirects, proxies, configured credential helpers, hooks, external protocols, submodule recursion and configured checkout filters are disabled for these operations.

Local operations are serialized across worktrees using the common Git directory. Request UUIDs and frozen payload digests prevent duplicate commits and repeat publication. An uncertain effect is stopped and shown as UNCERTAIN; reconciliation reads durable receipts and never blindly repeats a mutation. External ambiguous results without a durable receipt require inspection.

The command-line entrypoint is python3 -B -m fortis_approvals.workflow.client OPERATION --request-id UUID. It reads a typed JSON body on stdin. The WorkflowClient Python interface additionally provides the existing typed GitHub read/PR methods. resume services the same queued local request after an owner decision; it does not create a replacement request.

This is a Linux Docker Repo worker, not a Windows shell bridge or a transparent arbitrary git push proxy. The existing Windows Mirror receiver remains a separate established mechanism after approved main update. No new arbitrary Windows-command capability is introduced.

## First source bootstrap

The currently accepted M3 image cannot receive native Git bundles. To honor Gateway-only publication, this implementation is committed locally and packaged from that exact clean task worktree, without publishing through the old helper or connector. This is one explicit source-bootstrap exception to publication-before-owner-build: source review/CI publication follows through the new isolated Gateway. It is not a Production deployment.

The owner package uses Run-GitHub-FilePR-E2E.ps1 -ScenarioKind Native. It:

1. Verifies package hashes, exact source commit, canonical linked task worktree and unchanged clean primary main at e8dd217e1279c5ec8e1ad6b4e2ff893d01aa5dbc.
2. Admits the accepted protected M3 record, its exact source/image/CI result and retained M2/M1 receipts. Runs Windows self-tests in child PowerShell 5.1 processes before any build/stop.
3. Builds and smoke-tests the image offline, including installed native Git/runtime imports, without a provider mutation.
4. Stops only the admitted M3 review container; copies its stopped state into a fresh dedicated volume, preserving credentials/history/receipt bytes. Keeps M3 image/container/state and token volume for return.
5. Starts a new isolated review container on 19203/19204, with native opt-in, exact repository/required workflow and protected bootstrap task. Checks capabilities, retained receipts, ordinary Sonar read and Production baseline.
6. Emits FORTIS_GITHUB_NATIVE_WORKTREE_READY and liveNativeCycleVerified=false. This marker is readiness, not live E2E PASS.

Use the existing owner device at http://localhost:19203. No fresh enrollment or token provisioning is needed for the initial ordinary task push. Resume and Rollback use the same schema-4 record and expected source commit. Rollback stops only the new review and starts the retained M3 after unchanged-state verification. Do not delete either state volume.

The bootstrap task gateway-worktree-native-git-20261106 cannot be cleaned by the new profile while the owner record depends on its source path. Retargeting an accepted future package to merged canonical main is a separate small follow-up, after the source merge.

## Live acceptance to perform next

Use requests through the new Gateway exclusively:

1. Register/adopt the exact clean bootstrap task and publish its existing source commits; confirm identical local/upstream SHA and successful repeated request-ID readback.
2. Propose a draft source PR (ASK), approve on the existing owner device, and read Source CI through Gateway for that exact head.
3. Mark ready (ASK), merge the exact successful head (ASK), then update canonical Docker main through the typed fast-forward operation.
4. On a disposable task, exercise edit/check/stage/commit/push, a second fast-forward push, stale-head rejection, rejected sensitive proposal, and approved cleanup. Preserve evidence and request IDs; no connector/helper fallback.
5. Read Sonar again and verify the Production baseline. Review any missing catalog permission based on an actual denied required read; no broad privilege expansion.

Limits: bundle 24 MiB, 200 new commits, bounded paths/preview, edited content 16 KiB per request/20 files, selected stage paths 64. Git objects are resource-limited and operations serialized. Larger repositories, Git LFS, submodule workflows, remote branch deletion, conflict-resolution automation and squash/rebase merges are not accepted by this slice. Required CI is an explicit configured workflow ID; this is not a claim that every future repository's branch-protection rules have been modeled.

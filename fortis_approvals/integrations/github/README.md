# GitHub integration

**Status, 2026-11-06:** opt-in GitHub/native worktree profile is live in isolated
review; source PR №10 and new-task PR №11 completed through Gateway. Production
remains Sonar-only. [Current state](../../../docs/guides/FORTIS-APPROVALS-SECURE-DEVELOPMENT.md)
owns runtime details; [live evidence](../../evidence/FORTIS-NATIVE-GIT-LIVE-20261106.md)
owns results and limits. No reprovisioning is needed for the accepted review.

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
single current operation/policy table. Source implementation is broader than
admitted operations. Native includes `push_commits` and `mark_pr_ready`; ordinary
registered task push is ALLOW. Never infer access from a client method or the
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

## Deployment and retained pilots

Default startup keeps GitHub disabled. M1–M3 used explicit trusted pilot scope;
native uses its separate opt-in with registered `task/*` worktrees. Shared
Core, machine identity and owner WebAuthn/queue are reused.

- M1: `Run-GitHub-Pilot-E2E.ps1`, [branch approval evidence](../../evidence/FORTIS-GITHUB-PILOT-M1-20261106.md).
- M2/M3: `Run-GitHub-FilePR-E2E.ps1`, [file/PR evidence](../../evidence/FORTIS-GITHUB-PILOT-M2-20261106.md), [completed onboarding](../../../docs/INTEGRATION-MODULARIZATION-AND-GITHUB-ONBOARDING-PLAN.md).
- Native: the same FilePR entrypoint with `-ScenarioKind Native`; [bootstrap/return contract](../../../docs/NATIVE-WORKTREE-GATEWAY-2026-11-06.md).

Resume uses original record/request IDs; ambiguous results require reconciliation.
Return/rollback only changes the admitted review instance, not Production or
already-created GitHub branches/PRs. Preserve retained M3 state and the protected
bootstrap worktree until their owner-run references are deliberately replaced.

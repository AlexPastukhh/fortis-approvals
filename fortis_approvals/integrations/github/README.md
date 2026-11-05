# GitHub integration

**Status:** adapter/client/contracts are source-present; GitHub is not registered, granted or policy-enabled in the live composition. No provider token volume has been provisioned.

**Next acceptance target (2026-11-06):** minimal isolated READ -> ASK/Reject -> ASK/strong-WebAuthn Approve -> create_branch -> typed readback E2E. Production rollout and additional GitHub operations follow that acceptance. See the [current plan](../../../docs/INTEGRATION-MODULARIZATION-AND-GITHUB-ONBOARDING-PLAN.md).

## Source map

- Closed operation schemas and response projection: `contract.py`.
- Fixed-origin GitHub REST transport and secure token-file loader: `gateway/transport.py`.
- GitHub API adapter, read projections, compare-and-swap mutations and durable receipts: `gateway/adapter.py`.
- Explicit adapter factory/registration helper: `registration.py`.
- Fortis Repo typed client: `repo_client/client.py`.
- Offline tests: `tests/test_integration.py`.

## Typed READ operations

- `list_repositories` — returns only the configured allowlist (does not enumerate all account repositories).
- `get_repository`, `list_branches`, `list_commits`.
- `list_pull_requests`, `get_pull_request`.
- `list_workflow_runs`, `list_check_runs`, `get_commit_status`.

All upstream responses are projected to explicit public fields. The adapter uses only `https://api.github.com`, a fixed route catalogue, pinned API version, no redirects, bounded responses and redacted errors.
## Typed ACTION operations

- `create_branch` — create a new non-protected branch from an existing commit SHA.
- `push_files` — create a Git commit from a bounded batch of text-file updates and fast-forward the named existing branch (`force=false`).
- `create_pull_request` — create a PR after re-reading its base/head refs.
- `merge_pull_request` — merge only if the exact expected head SHA still matches.
- `update_workflow_file` — update an existing `.github/workflows/*.yml|yaml` file with exact branch/file SHA preconditions.
- `dispatch_workflow`, `rerun_workflow`, `cancel_workflow`, `approve_workflow_run` — typed Actions operations.

The adapter re-reads preconditions immediately before mutation and stores durable request receipts. Unknown operations, arbitrary URLs/methods, arbitrary refs and repository deletion are not exposed. Branch deletion is not implemented.
## Bounded Git write payloads

The current machine ingress candidate is capped at 512 KiB. `push_files` accepts at most 20 UTF-8 text files, 64 KiB per file and 200 KiB total; the JSON-escaped envelope is capped below 500 KiB. Workflow-file updates are limited to 64 KiB. Files under `.github/workflows/` are rejected by `push_files` and must use the dedicated workflow operation.

This is a typed REST commit-batch interface, **not a general Git smart-HTTP/packfile push protocol**. Binary files, large artifacts and unrestricted whole-repository pushes are not supported by this initial adapter. A later secure Git transport design is required if those are needed.
## Permission and policy boundary

The first E2E needs selected-repository Metadata read and Contents read/write only. Enable get_repository/list_branches READ and create_branch ASK with strong owner WebAuthn, exact repository scope and an enforced pilot branch prefix. Other operations remain DENY/no grant. Add Pull requests, Actions, Checks, statuses or Workflows permissions only for a later accepted workflow that needs them.

The provider token's permissions do not define AI permissions. `register_github_integration(core, broker, adapter)` only connects the typed adapter to Core/READ dispatch. It deliberately does **not** add actor grants or policy entries. Core defaults missing policy to `DENY`; the live R7 composition does not call this registration helper.

The later owner-reviewed policy setup must separately decide ALLOW/ASK/DENY for every operation. The planned split is documented in [the onboarding plan](../../../docs/INTEGRATION-MODULARIZATION-AND-GITHUB-ONBOARDING-PLAN.md). Do not enable GitHub operations before that review.
## Credential boundary

The planned credential is a separate Gateway-only Fine-grained PAT or GitHub App installation credential. For the PAT pilot, the file path is `/run/github-token/token`, expected owner UID 10001, mode 0600, regular file, no symlink. The intended external Docker volume name is `fortis-github-token`, mounted read-only.

**Not provisioned:** no volume has been created, no token has been written, no Compose mount has been added, and no running Gateway has access to GitHub. Never copy the existing Fortis Repo Git credential into this volume. Never put this token in Repo, source control, environment variables, request bodies, command arguments or logs.

The adapter and token loader are source-ready. The next work is the thin opt-in runtime/policy connection and one isolated pilot package; the live Gateway remains Sonar-only until that owner-run pilot is provisioned. Preserve the prior review state/container as the pilot return path. This pilot does not depend on first switching Production.

## Isolated pilot entrypoint (source candidate)

The minimal runtime is opt-in via FORTIS_GITHUB_PILOT=1, exact public owner and
repository configuration and a branch prefix (default fortis-e2e/). It is
restricted to owner/machine endpoints 19203/19204. Default startup stays
GitHub-disabled and reads no GitHub credential. The existing shared machine
actor gets only get_repository/list_branches ALLOW and create_branch ASK.
Owner approval requires strong WebAuthn; the same Core, portal and queue are
used. Other actor grants and Sonar policy versions are preserved.

- Runtime scope and wiring: pilot.py.
- Resumable typed Repo scenario: repo_client/pilot_scenario.py.
- Owner-run package entrypoint: ../../deploy/Run-GitHub-Pilot-E2E.ps1.
- Private clone/provision/admission/receipt helpers: ../../deploy/github_pilot_helpers.py.

The entrypoint is part of the full manifested source package produced by
scripts/package-review-source.py after source approval/merge. Pass the exact
approved source commit. Start requires an owner-selected test repository and
an explicit acknowledgement that creating pilot branches is safe there. The
separate credential is entered through a hidden console prompt and private
stdin, written only into a unique Gateway-only volume; no token is returned.

Start retains the existing review container, clones its stopped persistent
state into a fresh pilot volume, verifies byte-for-byte preservation, starts
one isolated pilot image on 19203/19204, and runs the scenario. The production
Gateway is only baseline-inspected; it is never stopped or mounted. The Repo
primary checkout must be clean at the approved source commit before calls.

The console prints the request ID and expected REJECT or APPROVE decision;
perform it in the existing owner portal/device. A 15-minute wait timeout or
scenario transport error preserves the same run record. Resume uses saved
request IDs. UNCERTAIN requires reconciliation and is never retried as a new
proposal. Setup failures attempt return to the retained review; later scenario
pauses leave the pilot available for inspection/resume. Rollback explicitly
stops only the admitted pilot and starts the original review after checking
its preserved data. Pilot volumes, results and created GitHub branches are
retained; rollback does not undo an external branch creation.

Use the same entrypoint with Mode Start, Resume or Rollback, an exact
ExpectedSourceCommit, and the printed record.json path for Resume/Rollback.
The record is owner/SYSTEM/Administrators-only under LocalAppData Fortis
GitHubPilot. Success requires typed branch readback, replay, local durable
receipt plus owner-approved Core state, and a Sonar GET regression; marker:
FORTIS_GITHUB_PILOT_LIVE_E2E_PASS. Offline tests are not that live marker.

### Resume a build interrupted before setup

Windows PowerShell 5.1 requires an explicit `NullString.Value` for the optional
`File.Replace` backup path. The Windows self-test exercises initial record
creation, two real atomic replacements and retained ACLs/IDs.

`-Mode Resume -Record <existing-record> -ExpectedSourceCommit <approved-new-source>
-ResumePreparedSourceCommit <exact-old-source>` also resumes a `Prepared` record
from a failed build. It retains the run and request IDs. Before resuming, the
runner requires no saved image, credential/state volumes, pilot container or
scenario progress, and verifies the retained review and Production baseline.
Changing the source requires that explicit old-commit acknowledgement. Later
setup phases remain blocked for inspection; running scenarios use ordinary
Resume without source migration.

### M2: one test file and draft PR

M1 live acceptance is recorded in `fortis_approvals/evidence/FORTIS-GITHUB-PILOT-M1-20261106.md`.
The optional trusted `FORTIS_GITHUB_FILE_PR_BRANCH` pins M2 to the accepted
`fortis-e2e/<M1-run-UUID>-approve` branch. The only writable path is
`docs/fortis-e2e/<M1-run-UUID>.txt`, with one UTF-8 file up to 4096 bytes per push.
`push_files` and `create_pull_request` use ASK + strong WebAuthn. PR creation
requires that exact head, base main, and draft=true. Merge and workflow controls
remain denied. File reads expose verified blob/content digests, not raw content.

The owner-run `Run-GitHub-FilePR-E2E.ps1` takes Start/Resume/Rollback/SelfTest.
Start requires the protected completed M1 record and explicit acknowledgement
that its separate Gateway credential now has Pull requests read/write alongside
Contents read/write and Metadata read for the same selected repository. The
credential volume is reused RO; no secret is transferred to Repo or re-entered.
The script builds the verified source, stops only the admitted M1 pilot and
clones all M1 owner/history/provider-receipt state through a RO source mount into
a fresh isolated volume. The retained M1 container/image/state is the return
point. No container, state volume, branch, PR or source is automatically deleted.

After startup it submits the bounded file change, waits for owner Approve,
checks the new commit/content hashes and completed-request replay, then submits
the draft PR. The PR preview states that existing pull_request CI will run.
It checks exact PR refs/SHAs, both durable owner-approved receipts, replay and
Sonar GET before printing `FORTIS_GITHUB_FILE_PR_LIVE_E2E_PASS`.
Save the printed FILE_PR_RECORD path: Resume uses that record and original IDs;
UNCERTAIN stops for reconciliation. Rollback stops only the admitted new pilot,
checks the retained M1 data hashes and restarts M1. It does not undo GitHub
mutations or merge/close the test PR. Production has no lifecycle operations.

The exact `docs/fortis-e2e/<canonical-UUID>.txt` files are live non-release test
data, excluded from the release source manifest/package. This lets the draft
PR's existing Source CI verify the unchanged release source. Code, other paths
and non-UUID files in the same directory remain manifested; a packaging
regression verifies this narrow boundary.

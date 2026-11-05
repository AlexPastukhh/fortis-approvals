# GitHub integration

**Status:** implementation prepared in source; NOT registered in the live R7 composition, NOT granted to the current actor, NOT policy-enabled and NOT deployed. No GitHub token volume exists yet.

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

The intended pilot token permissions are Contents read/write; Pull requests read/write; Actions read/write; Checks read; Commit statuses read; Workflows read/write; Metadata read (automatic), restricted to the selected repositories.

The provider token's permissions do not define AI permissions. `register_github_integration(core, broker, adapter)` only connects the typed adapter to Core/READ dispatch. It deliberately does **not** add actor grants or policy entries. Core defaults missing policy to `DENY`; the live R7 composition does not call this registration helper.

The later owner-reviewed policy setup must separately decide ALLOW/ASK/DENY for every operation. The planned split is documented in [the onboarding plan](../../../docs/INTEGRATION-MODULARIZATION-AND-GITHUB-ONBOARDING-PLAN.md). Do not enable GitHub operations before that review.
## Credential boundary

The planned credential is a separate Gateway-only Fine-grained PAT or GitHub App installation credential. For the PAT pilot, the file path is `/run/github-token/token`, expected owner UID 10001, mode 0600, regular file, no symlink. The intended external Docker volume name is `fortis-github-token`, mounted read-only.

**Not provisioned:** no volume has been created, no token has been written, no Compose mount has been added, and no running Gateway has access to GitHub. Never copy the existing Fortis Repo Git credential into this volume. Never put this token in Repo, source control, environment variables, request bodies, command arguments or logs.

The adapter and token loader are source-ready for later provisioning, but the live Gateway remains Sonar-only until a separate policy + credential + deployment release.

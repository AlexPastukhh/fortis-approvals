# Integration modularization and GitHub onboarding plan

> **Status (2026-11-05):** Sonar source moved into its provider package with legacy import shims; shared Repo→Gateway transport extracted; migrated live Sonar GET verified. GitHub typed contract, fixed-origin transport, Gateway adapter, Repo client, registration helper and offline tests are implemented in source. GitHub is NOT registered in live R7, has no actor grants/policy, no token volume and no deployment. Live Sonar runtime and credentials remain unchanged.

The isolated modularized review has since been built and started on
19203/19204 with separately restored Production backup state. The owner's
existing WebAuthn login and six History entries are confirmed, and review
Sonar GET returns OK. The reject-only ASK/owner Reject check passed with the Sonar Issue remaining OPEN. Production
is unchanged, and this does not activate GitHub. The current image, snapshot,
backup hashes and 282-test validation are recorded in
[review evidence](../fortis_approvals/evidence/FORTIS-REVIEW-PREFLIGHT-20261105.md).

## Architecture decisions

1. Keep one Fortis Approvals Gateway, one machine ingress, one Core, one Owner Portal and one owner-approval queue.
2. Give every provider its own integration package, typed contract, Gateway adapter, Repo-side client, tests, policy registration and deployment notes.
3. Keep TLS, machine authentication, request envelope, policy evaluation and owner approval in shared infrastructure.
4. Use one shared Gateway transport implementation, with a separate typed client for each provider.
5. Keep upstream credentials provider-specific and Gateway-only. Never put provider tokens in Repo, source control, request payloads, command arguments or logs.
6. Unknown operations and unregistered integrations fail closed. A directory or credential alone must not make an operation available.

## Current source locations

- Shared Repo→Gateway TLS/machine-grant transport: `fortis_approvals/clients/gateway_transport.py`.
- Sonar operation schemas: `fortis_approvals/integrations/sonarcloud/contract.py`.
- Sonar Gateway modules: `fortis_approvals/integrations/sonarcloud/gateway/`.
- Sonar Repo client/workflow: `fortis_approvals/integrations/sonarcloud/repo_client/`.
- Sonar legacy import/CLI shims: `fortis_approvals/sonar.py`, `sonar_read.py`, `sonar_inventory.py`, `sonar_probe.py`, `sonar_preflight.py`, `repo_sonar_tools.py`, `sonar_review_scenario.py`.
- GitHub operation schemas: `fortis_approvals/integrations/github/contract.py`.
- GitHub Gateway transport/adapter: `fortis_approvals/integrations/github/gateway/`.
- GitHub Repo client and opt-in registration: `integrations/github/repo_client/` and `integrations/github/registration.py`.
- Shared broker/ingress/runtime composition: `repo_action_contract.py`, `repo_ingress.py`, `r7_unified_candidate.py` and `r7_unified_server.py`.

The compatibility shims remain until the next reviewed image release includes the provider packages. New source imports use canonical integration paths.
## Target package layout

```text
fortis_approvals/
  clients/
    gateway_transport.py
  integrations/
    README.md
    sonarcloud/
      README.md
      contract.py
      gateway/
      repo_client/
      tests/
      deployment/
    github/
      README.md
      contract.py
      gateway/
      repo_client/
      tests/
      deployment/
    _integration_template/
      README.md
```

Shared Core, Owner Portal, machine ingress and transport remain outside provider folders. Provider code must not own or duplicate machine authentication or owner WebAuthn.

## GitHub credential recommendation

**Preferred long-term:** GitHub App installed only on the approved repositories. Store the App private key and non-secret App/installation identifiers in Gateway-only provisioning; mint short-lived installation tokens at runtime.

**Practical pilot:** a Fine-grained Personal Access Token (PAT), not a classic PAT. Restrict it to the exact approved repository list and set an expiry (prefer 30–90 days, subject to organization policy). Do not create it with access to all repositories.

The Gateway credential is separate from the existing Repo Git credential helper. Do not copy the existing shared Repo PAT into Gateway. Keep the old Git helper until direct Git CLI operations have a separately reviewed replacement.
## Initial Fine-grained PAT permissions — functional pilot

The first pilot should support the intended typed Git workflow while remaining limited to an exact owner-approved repository allowlist. Repository names, token type and expiry are not configured in this source-only phase. The token itself does not encode owner-approval policy; Fortis Gateway does.

| Repository permission | Pilot level | Why it is included |
|---|---|---|
| Metadata | Read (automatic) | Repository metadata |
| Contents | Read and write | Read code/branches/commits, create/update working branches and push commits |
| Pull requests | Read and write | Read/create/review/merge PRs; Gateway will gate selected mutations |
| Actions | Read and write | Read workflow-run metadata and allow explicitly registered run dispatch, rerun, cancel or approval operations; log retrieval is not implemented in this adapter |
| Checks | Read-only | Read check suites and check runs |
| Commit statuses | Read-only | Read commit status contexts as well as Checks API results |
| Workflows | Read and write | Create/update files under `.github/workflows`; Gateway will gate these changes |

This is the deliberately capable pilot profile, not the final least-privilege profile. Do not add Administration, Secrets, Variables, Environments, Webhooks, organization administration, repository deletion or unrelated permissions. Do not grant Issues unless a separately approved Issues workflow requires it.

**Important permission coupling:** GitHub does not provide a token permission that allows PR creation but forbids PR merge: both require Pull requests write. Contents write permits more than a push, including Git reference deletion. Actions write enables several run-control endpoints, not only the specific action the agent may request. Workflows write allows workflow-file changes. Fortis Gateway must therefore expose only typed operations and enforce the operation policy below; never expose arbitrary API routes or give the token to the Repo/AI process directly.

Contents write is repository-wide, not branch-specific. Enforce repository and branch allowlists in Gateway, disable force updates, and rely on GitHub branch protection as an additional provider-side control. The broader pilot permissions are acceptable only while the credential remains Gateway-only and every mutation passes the appropriate ALLOW/ASK/DENY policy.
## GitHub operation policy target

| Implemented operation | Policy state now | Boundary |
|---|---|---|
| READ: repositories, branches, commits, PRs, Actions, Checks, statuses | NOT REGISTERED | Typed read schemas and projections exist |
| `create_branch`, `push_files` | NOT REGISTERED | Repository allowlist; main/master protected; no force update; bounded UTF-8 file batch |
| `create_pull_request` | NOT REGISTERED | Re-reads base/head refs before create |
| `merge_pull_request` | NOT REGISTERED | Expected PR head SHA required; merge readback |
| `update_workflow_file` | NOT REGISTERED | Existing workflow file SHA and branch SHA preconditions |
| `dispatch_workflow`, `rerun_workflow`, `cancel_workflow`, `approve_workflow_run` | NOT REGISTERED | Typed Actions endpoints only |
| Branch deletion, repository creation/deletion, webhooks, rulesets, secrets, variables | NOT IMPLEMENTED | No operation or route exposed |

No GitHub actor grant or policy entry is present in live R7. The registration helper attaches only the adapter/read dispatcher and deliberately does not configure grants or policies. Core defaults missing policies to DENY. The owner will separately decide which implemented operations become ALLOW, ASK or remain DENY. An upstream token permission never grants the AI an operation by itself.

## Credential volume target

- External Docker volume: `fortis-github-token`.
- Read-only Gateway mount: `/run/github-token`.
- Fine-grained PAT file: `/run/github-token/token`.
- File owner: Gateway runtime UID 10001; mode 0600; regular file, no symlink.
- No environment variable containing the token, no Repo mount, no Git-tracked secret, no token output in logs.
- The volume is **planned only**. It has not been created, populated or attached to the running Gateway.

For a GitHub App, the same separate-volume principle applies, but the mounted secret is the App private key and the Gateway mints short-lived installation tokens.
## Implementation and release phases

1. **Completed — inventory and baseline:** preserved the live Sonar code path, current credentials and active image; created a source backup before moving modules.
2. **Completed — provider package scaffold:** provider catalog, SonarCloud/GitHub READMEs, reusable template and navigation.
3. **Completed — SonarCloud extraction:** moved provider implementation and Repo client/workflow into `integrations/sonarcloud`; retained compatibility import/CLI shims; updated active source imports.
4. **Completed — shared transport/contracts:** extracted the fixed typed Repo→Gateway machine transport; Sonar and GitHub contracts are provider-owned. Extended the candidate ingress/Core payload cap only for bounded GitHub requests.
5. **Completed in source — GitHub implementation:** fixed-origin REST transport, strict typed contracts, public projections, repository allowlist, compare-and-swap branch/PR/workflow mutations, durable receipts, Repo client and opt-in adapter registration. Registration does not grant or set policy.
6. **Completed — supported offline suite:** `bash scripts/test-source.sh` passes 245 tests across GitHub (contracts, fixed-origin transport, token-file security, projections, Repo client, default-DENY registration), Sonar package compatibility, Core, Gateway, Owner Portal, Repo ingress/client, Sonar READ/ASK, TLS 1.3 R6/R7 end-to-end and isolated candidate-image imports. `compileall` and shell syntax checks pass. A live Sonar GET on 2026-11-05 returned Quality Gate `OK` after the migration; evidence is recorded under `fortis_approvals/evidence/`. Historical image audit tests remain separate provenance checks.
7. **Next — owner release review:** the new `Dockerfile-Gateway-Modularized-Candidate` COPY/import context and source manifests are validated; the owner-approved isolated image has been built and validated beside Production, with preserved credential and History. The reject-only functional check passed without changing Sonar. Production deployment still requires a distinct release GO with final backup and rollback; do not use the old R7 Dockerfile/build script after the source layout change.
8. **Later owner-controlled provisioning/deployment:** after policy decisions, create/populate the separate GitHub volume, attach it read-only, identify the maintained Compose source, deploy only after explicit release GO, and verify Sonar regression plus GitHub read/write/approval E2E.
9. **Separate future task — legacy Git CLI credential retirement:** only after a Gateway-backed Git workflow is proven, migrate/revoke the shared Repo PAT. Do not remove the current helper as part of this integration source work.

## Acceptance gates

- Sonar live behavior and owner approval remain unchanged.
- GitHub token is not readable from Fortis Repo or exposed in any response/log.
- Each provider can be independently enabled/disabled by registration, actor grant and policy.
- Every mutation has an exact typed operation, scope checks, durable request state and owner approval where required.
- No arbitrary HTTP proxy, arbitrary GitHub URL, token-return route, AI owner route or arbitrary workflow dispatch is introduced. Workflow dispatch is available only as an explicitly typed ASK operation with owner approval.
- Deployment evidence identifies the exact image, source manifest, mounted volumes and rollback target.

## Official GitHub permission references

- [Fine-grained PAT permission-to-endpoint mapping](https://docs.github.com/en/rest/authentication/permissions-required-for-fine-grained-personal-access-tokens)
- [Create a pull request — Pull requests: write](https://docs.github.com/en/rest/pulls/pulls)
- [Merge a pull request — Pull requests: write](https://docs.github.com/en/rest/pulls/pulls)
- [Git references — Contents: write, including delete reference](https://docs.github.com/en/rest/git/refs)
- [Workflow runs — Actions: read/write endpoints](https://docs.github.com/en/rest/actions/workflow-runs)
- [Check runs — Checks: read](https://docs.github.com/en/rest/checks/runs)
- [Commit statuses — Commit statuses: read](https://docs.github.com/en/rest/commits/statuses)

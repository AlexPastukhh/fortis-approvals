# Fortis Approvals Gateway — guide for AI agents and service integrations

> **Before this service-specific guide:** in Fortis Repo, open `/workspace/repo/README.md`, read the short introduction of the linked container use-case registry and UC-CONT-002, UC-CONT-003 and [UC-GW-009](use-cases/incidents.md#uc-gw-009) in full; do not scan the entire registry. The registry owns the cross-project Docker/GitHub/CI/Windows/Mirror workflow. This document owns the Gateway-specific rules, not a second workflow.
>
> **Start here when an AI agent needs an authenticated request to an external service.** Fortis Approvals is the intended central broker for service credentials, typed operations and owner approvals. It is not a generic HTTP proxy.

## If you are an AI agent

1. If a task needs a token, API key or privileged action against an external service, use the Fortis Approvals Gateway path documented for that operation.
2. Never ask the user to paste a service token into chat, read a Gateway secret, copy credentials into the workspace, or call the provider directly with a stored credential.
3. Send only a documented typed operation and its permitted parameters. Do not invent URLs, HTTP methods, headers, operation names or policy values.
4. Treat the policy result as authoritative: `ALLOW` runs without owner approval, `ASK` creates a request for the owner, and `DENY` stops the operation.
5. If the service or operation is not listed as implemented, do not improvise a direct API call. Report that the Gateway integration is not available yet.

**Quick links:** [current implementation and commands](../fortis_approvals/README.md) · [provider integration catalog](../fortis_approvals/integrations/README.md) · [modularization and GitHub onboarding plan](INTEGRATION-MODULARIZATION-AND-GITHUB-ONBOARDING-PLAN.md) · [live operating scope](guides/FORTIS-APPROVALS-SECURE-DEVELOPMENT.md) · [deployment references](../fortis_approvals/deploy/README.md)

## What the Gateway owns

Fortis Approvals is separate from the Fortis Repo workspace. Repo sends typed
requests over authenticated TLS; Gateway validates schemas and grants, applies
policy, keeps provider credentials private and calls the selected adapter.
The native profile also authorizes typed local workspace jobs; a Repo worker
executes them and reports durable receipts. Ordinary process/file access in the
shared Repo container remains a separate capability.

For `ASK`, the Gateway freezes the request/preview and creates a durable `PENDING` item. The owner decides in the Gateway Owner Portal using WebAuthn. The AI client cannot approve, reject, call owner routes or bypass the policy. Before execution, Core rechecks the request, policy version, active machine identity and adapter preview.

Three controls are separate and must stay separate:

- **Machine authentication:** Repo proves its identity to Gateway using the Fortis machine grant.
- **Upstream authorization:** Gateway uses the service-specific credential stored on the Gateway side.
- **Owner approval:** WebAuthn proves that the human owner approved this exact ASK request.

An approval does not create missing provider permissions. Provider credentials still need the minimum upstream scopes required for the operation.

## Policy model

| Policy | Meaning | Expected behavior |
|---|---|---|
| `ALLOW` | This exact operation is permitted for this actor and scope | Execute automatically; no owner decision |
| `ASK` | This exact operation requires owner consent | Create `PENDING`; execute only after owner WebAuthn approval |
| `DENY` | This operation is unavailable | Reject without upstream execution |

Unknown operations and missing policy rules must fail closed as `DENY`. Do not assign policy by broad verb alone: one kind of creation can be allowed while another requires approval. The [native contract](NATIVE-WORKTREE-GATEWAY-2026-11-06.md) owns its operation-specific rules; check live capabilities for the installed policy.

Use operation-level rules and explicit scopes (organization, repository, project, branch, resource). Keep the upstream token scope as narrow as practical. If an operation is not intended to be available, withhold its actor grant/policy and avoid unnecessary upstream token scope. Implemented adapter methods alone do not provide access.

## Current implementation

[Current state](guides/FORTIS-APPROVALS-SECURE-DEVELOPMENT.md) owns the latest
owner-confirmed source/image/release record and deployed scope. Normal work uses
Primary `fortis-gateway` on 19203/19204; Sonar-only Legacy on 19103/19104 is
retained and stopped. Runtime IDs change on later releases; do not reuse the
initial cutover ID as a current pin. Read protected records and live identity
before an owner operation. [Primary operations](PRIMARY-GATEWAY-OPERATIONS.md)
own backup, promotion, autostart and rollback; initial cutover evidence is dated.

- Sonar typed reads are ALLOW; `accept_issue` is ASK + owner WebAuthn for the
  configured project. The [optional analysis-review source profile](ANALYSIS-REVIEW-CONTRACT.md) is disabled in the accepted runtime; source presence does not enable its operations.
- The [native contract](NATIVE-WORKTREE-GATEWAY-2026-11-06.md) owns the exact
  operation/policy table and preconditions; do not maintain a second policy
  matrix here. Check effective capabilities before acting.
- GitHub registration is opt-in; it does not itself assign grants or policies.
  Source-present legacy methods are not automatically admitted in native mode.
- Provider credentials stay in Gateway. The separate legacy Repo Git helper
  still exists; its removal and migration of other repositories were not part
  of acceptance. Do not use that helper or a connector for this Gateway path.
- Rules are trusted configuration/code; an owner policy editor is not built.

## How an AI agent should use it today

Run from the approved source/task worktree. For native operations use
`fortis_approvals.workflow.client` / `default_client()`, which selects the
**Primary machine endpoint 19204**; see the [command contract](NATIVE-WORKTREE-GATEWAY-2026-11-06.md).
The installed Docker main includes the accepted shared typed transport default
on Primary 19204 for native, Sonar and extensions clients. Check the actual
client/version and live capabilities before each new integration or target.
Do not point normal work to the stopped Legacy 19104 or use direct provider URLs.

For Sonar, use the canonical
`fortis_approvals.integrations.sonarcloud.repo_client.workflows` review/status
entry point or the existing `sonar_review_scenario` compatibility CLI. Its
normal default becomes Primary 19204 once the accepted client source is installed.
Reads inspect existing analysis; they do not start a scan. Source/CLI usage is in the [package map](../fortis_approvals/README.md).

Keep stable request IDs. `PENDING` means wait for the owner, not an error or a
reason to submit another request. Follow the native contract's HTTP 202 caveat
when using the client version currently in main. For local ASK operations,
keep a worker available or resume the same request after the owner decision;
verify `EXECUTED` plus effect/receipt, not just approval. On `UNCERTAIN`,
use [UC-GW-009](use-cases/incidents.md#uc-gw-009):
`default_client().details(uuid)` reads the full actor-owned request, audit,
worker and receipt without retry/reconcile. Independently inspect upstream
GitHub and local Git evidence before attributing the effect. An absent receipt
does not prove the action failed. `reconcile` is a separate operation
with its own contract, not a mandatory read-only viewing step.
The AI never invokes owner routes or administratively closes requests.
Unsupported services or operations stop at the integration boundary.

**UNCERTAIN investigation is AI-first.** When the user reports unresolved
operations, recover their UUIDs from the original Gateway responses, prior
conversation/task output and (if connected) the Fortis Repo
`get_recent_tool_calls` history; match repository, operation, task, SHA and
creation time. For each candidate call **`default_client().details(uuid)`**
and independently inspect authorized GitHub READ, local Git/worktree and worker
journal evidence. Report original-request evidence separately from any later
successful request. Do **not** ask the owner to manually open incident cards
just to copy IDs or inspect technical diagnostics that the Repo tools can read.

**Do not overstate coverage:** the present machine API has no actor-scoped
`list_uncertain`; `details(UUID)` reads only requests initiated by the
machine actor, and local tool-call history is finite/incomplete. The
`/v1/owner/unresolved` inventory is owner-only, not a permitted machine
endpoint. If a *complete* current uncertainty inventory is required (for
example a Windows release preservation scope), report the known verified IDs
and any remaining completeness gap; request the minimum owner-supplied
inventory only if the authorized tools cannot resolve it. `result()` and
`details()` do not replace a true inventory. Never call `claim`, `resume`,
`finish`, `reconcile` or owner routes as part of routine incident review;
`reconcile` may mutate Core state. Owner Portal is for decisions and
administrative closure, not a mandatory technical investigation step.
See [UC-GW-009](use-cases/incidents.md#uc-gw-009) for the complete sequence.

## One owner approval per ASK effect

Within an assigned task the user authorizes the AI to submit the necessary
reviewable ASK intents without a preliminary conversational permission question.
Submit with the typed client, keep the same requestId, report PENDING/portal,
then wait for Owner Portal Approve/Reject. This authorization to create a proposal
does not impersonate owner WebAuthn or authorize unrelated effects. ALLOW runs
within task scope; DENY is not a reason to switch credentials/channels.
An actual outer tool-review rejection must be reported and respected.

The full goal/route lives in container UC-CONT-007, reached via
`/workspace/repo/README.md`. Container cases also own new client/provider/operation/
token and delivery goals; the contracts here remain their technical owners.

## Adding a new service or authorization

For new providers use the [extension contract](INTEGRATION-EXTENSIONS.md): one
provider package, declared ALLOW/ASK scopes, named Gateway credentials, shared
client/routes, automatic test/image discovery and a persistent owner controller.
The generated stub stays disabled until implemented and tested. No manual Core,
Docker COPY or CI registry edits are needed for each provider.

Existing native Git and Sonar/GitHub implementations retain their own operation
contracts. **When extending a native client method, machine route or operation,
follow the accepted [UC-GW-003](use-cases/integrations.md#uc-gw-003)**:
contract and policy, ingress, worker/adapter, Repo-side typed client, negative
and compatibility tests, source manifest, PR CI, one release and live readback.
Do not scaffold a provider to add `workspace` operations or assume a new client
method itself grants permission. Source changes do not activate a deployed
container; deployment and real permission/effect acceptance are separate
recorded outcomes.

## Code ownership map

| Concern | Current source of truth |
|---|---|
| New provider registration/config/catalog/credentials | [`extensions/`](../fortis_approvals/extensions/README.md) |
| Existing closed operation names and request schemas | [`repo_action_contract.py`](../fortis_approvals/repo_action_contract.py) |
| Actor grants, adapter wiring and current policy map | [`r7_unified_candidate.py`](../fortis_approvals/r7_unified_candidate.py) |
| Default-DENY policy lookup, durable request lifecycle and execution | [`core.py`](../fortis_approvals/core.py) |
| Authenticated typed machine ingress | [`repo_ingress.py`](../fortis_approvals/repo_ingress.py) |
| Existing Sonar read/write adapters | `integrations/sonarcloud/gateway/read_adapter.py` and `integrations/sonarcloud/gateway/sonar.py` |
| Current Repo-side Sonar client | `integrations/sonarcloud/repo_client/client.py` |
| Native policies / Git publication / local worker | `workflow/runtime.py`, `workflow/adapters.py`, `workflow/git_backend.py`, `workflow/worker.py` |
| Contract/Core/ingress regression tests | `fortis_approvals/tests/test_repo_action_contract.py`, `test_core.py`, `test_repo_ingress.py`, `test_r7_unified_candidate.py` |

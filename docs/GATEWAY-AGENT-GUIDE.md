# Fortis Approvals Gateway — guide for AI agents and service integrations

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

Unknown operations and missing policy rules must fail closed as `DENY`. Do not assign policy by broad verb alone: one kind of creation can be allowed while another requires approval. The configured native profile uses ASK for PR creation; its operation-specific table is authoritative.

Use operation-level rules and explicit scopes (organization, repository, project, branch, resource). Keep the upstream token scope as narrow as practical. If an operation is not intended to be available, withhold its actor grant/policy and avoid unnecessary upstream token scope. Implemented adapter methods alone do not provide access.

## Current implementation

[Current state](guides/FORTIS-APPROVALS-SECURE-DEVELOPMENT.md) owns deployed images,
endpoints and accepted scope. Production remains the Sonar instance on
19103/19104. The isolated review on 19203/19204 has completed the native
GitHub/worktree live cycle in `AlexPastukhh/fortis-approvals`.

- Sonar typed reads are ALLOW; `accept_issue` is ASK + owner WebAuthn for the
  configured project. The [optional analysis-review source profile](ANALYSIS-REVIEW-CONTRACT.md) is not deployed; do not send its operations to an older runtime.
- The [native contract](NATIVE-WORKTREE-GATEWAY-2026-11-06.md) owns the exact
  operation/policy table. Ordinary registered task push is ALLOW; CI-file
  changes, PR/ready/merge and cleanup require ASK. No per-commit approval is
  needed for an ordinary task push.
- GitHub registration is opt-in; it does not itself assign grants or policies.
  Source-present legacy methods are not automatically admitted in native mode.
- Provider credentials stay in Gateway. The separate legacy Repo Git helper
  still exists; its removal and migration of other repositories were not part
  of acceptance. Do not use that helper or a connector for this Gateway path.
- Rules are trusted configuration/code; an owner policy editor is not built.

## How an AI agent should use it today

Run from the approved source/task worktree. For native operations use
`fortis_approvals.workflow.client` / `default_client()`, which selects the review
machine endpoint on 19204; see the [command contract](NATIVE-WORKTREE-GATEWAY-2026-11-06.md).
The generic provider client defaults to Production 19104; it does not silently
select the GitHub-enabled review. Use the explicit native transport, not a
provider URL or a direct token.

For Sonar, use the canonical
`fortis_approvals.integrations.sonarcloud.repo_client.workflows` review/status
entry point or the existing `sonar_review_scenario` compatibility CLI. Its
normal default is Production 19104. Reads inspect existing analysis; they do
not start a scan. Source/CLI usage is in the [package map](../fortis_approvals/README.md).

Keep stable request IDs. `PENDING` means wait for the owner, not an error or a
reason to submit another request. Follow the native contract's HTTP 202 caveat
when using the client version currently in main. For local ASK operations,
keep a worker available or resume the same request after the owner decision;
verify `EXECUTED` plus effect/receipt, not just approval. Reconcile `UNCERTAIN`
without blindly repeating a mutation. The AI never invokes owner routes.
Unsupported services or operations stop at the integration boundary.

## Adding a new service or authorization

Follow the [operation onboarding workflow](OPERATION-ONBOARDING-WORKFLOW.md)
for both a new provider and an extension of an existing integration. It owns
change classification, code/config/scope preparation, validation, owner release
and feature acceptance. Start with its short change card; keep provider details
in the [integration template](../fortis_approvals/integrations/_integration_template/README.md).
Do not repeat historical bootstrap or create a provider-specific Core/approval
queue. An image update with the requested profile disabled is an intermediate
result, not completion of the requested integration.

### Code ownership map

| Concern | Current source of truth |
|---|---|
| Closed operation names and request schemas | [`repo_action_contract.py`](../fortis_approvals/repo_action_contract.py) |
| Actor grants, adapter wiring and current policy map | [`r7_unified_candidate.py`](../fortis_approvals/r7_unified_candidate.py) |
| Default-DENY policy lookup, durable request lifecycle and execution | [`core.py`](../fortis_approvals/core.py) |
| Authenticated typed machine ingress | [`repo_ingress.py`](../fortis_approvals/repo_ingress.py) |
| Existing Sonar read/write adapters | `integrations/sonarcloud/gateway/read_adapter.py` and `integrations/sonarcloud/gateway/sonar.py` |
| Current Repo-side Sonar client | `integrations/sonarcloud/repo_client/client.py` |
| Native policies / Git publication / local worker | `workflow/runtime.py`, `workflow/adapters.py`, `workflow/git_backend.py`, `workflow/worker.py` |
| Contract/Core/ingress regression tests | `fortis_approvals/tests/test_repo_action_contract.py`, `test_core.py`, `test_repo_ingress.py`, `test_r7_unified_candidate.py` |

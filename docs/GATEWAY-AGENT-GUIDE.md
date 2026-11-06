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
  configured project. The [optional analysis-review profile](ANALYSIS-REVIEW-CONTRACT.md) is packaged in the updated review image but remains disabled; image update does not grant its operations. Check [current state](guides/FORTIS-APPROVALS-SECURE-DEVELOPMENT.md) before using it.
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

A new token alone does not make a service available. A service integration is complete only when its credential, adapter, typed contract, actor grant, policy, client operation, tests and deployment are all connected. Use the [provider integration template](../fortis_approvals/integrations/_integration_template/README.md) and keep each provider's implementation and documentation in its own folder.

1. **Define scope first.** Record the service, trusted tenant/organization, allowed resources, region, required operations and minimum provider scopes. Decide which operations are `ALLOW`, `ASK` or `DENY`. Keep high-risk provider scopes out of the initial credential if they are not needed yet.
2. **Provision the credential on the Gateway side.** Use a dedicated secret/volume and owner-controlled provisioning. Never put the provider token in Git, a Repo workspace, an AI request, a client grant or a log. The Repo machine grant authenticates Repo to Gateway; it is not the provider token.
3. **Implement a service-specific adapter.** Pin trusted upstream origins, HTTP methods, routes and parameter sets. Validate targets and upstream responses; bound timeouts and response sizes; disable unsafe redirects; redact errors. Separate read-only transport from mutation transport where appropriate. Do not create a generic `request(url, method, headers, body)` escape hatch.
4. **Register typed operations and schemas.** Extend the closed operation allowlists and validators in [`repo_action_contract.py`](../fortis_approvals/repo_action_contract.py). Keep READ queries separate from ACTION intents. Define exact required fields, types, bounds, target scope and public response projection; reject extra fields and caller-supplied tokens, URLs, methods, actors or policy.
5. **Wire actor grants and policy.** Extend the trusted composition in [`r7_unified_candidate.py`](../fortis_approvals/r7_unified_candidate.py): read operations go into `actor_read_operations`; action operations go into `actor_operations`; policy entries are registered in the trusted `policies` map. Use `ALLOW`, `ASK` or `DENY` per actor/service/operation (and narrower target rules where needed). The module name is a retained historical name, not a promise that this is the final architecture.
6. **Connect ingress and the client.** Add only explicit typed routes/dispatch and matching client methods. Base machine ingress exposes `POST /v1/reads`, `POST /v1/actions` and `GET /v1/requests/{requestId}`. Native adds only the closed workspace/Git routes in `workflow/ingress.py`; neither surface is a general proxy. The shared Repo transport is [`clients/gateway_transport.py`](../fortis_approvals/clients/gateway_transport.py); provider clients live under `integrations/<provider>/repo_client/`. GitHub adapter plumbing is attached only through [`integrations/github/registration.py`](../fortis_approvals/integrations/github/registration.py), which does not configure actor grants or policies.
7. **Test the security boundary.** Add tests for schema rejection, unknown operations, actor grants, target scopes, default DENY, ALLOW execution, ASK/PENDING, Reject with no dispatch, approval-bound execution, stale previews, credential redaction and upstream response validation. Use mocked/offline transports for normal tests; reserve live mutation for a separately approved owner-run E2E.
8. **Review deployment separately.** Update the image source allowlist, secret provisioning and deployment artifacts only through the approved release procedure. Editing this development checkout does not change the active Gateway image or container.

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

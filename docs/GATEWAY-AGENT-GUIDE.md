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

Fortis Approvals is a separate trusted service/container from the Fortis Repo workspace. It is the standard control point between AI clients and credentialed upstream services. It does not replace ordinary local file, Git or process tools; it brokers authenticated external-service operations and privileged upstream effects:

```text
AI agent
  │ typed request; no provider token
  ▼
Fortis Repo client
  │ machine grant + TLS
  ▼
Fortis Approvals Gateway
  ├─ authenticate machine actor
  ├─ validate operation schema and actor grant
  ├─ apply ALLOW / ASK / DENY policy
  ├─ keep provider credentials private
  └─ call a service-specific adapter
          │
          ▼
   External service (GitHub, SonarCloud, ...)
```

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

Unknown operations and missing policy rules must fail closed as `DENY`. Do not assign policy by broad verb alone: one kind of creation can be allowed while another requires approval. For example, creating a pull request may be `ALLOW`, while creating a repository is `ASK`.

Use operation-level rules and explicit scopes (organization, repository, project, branch, resource). Keep the upstream token scope as narrow as practical. If an operation is not intended to be available yet, do not register it and do not grant the corresponding upstream token scope.

## Current implementation — do not confuse it with the target

The Gateway is the intended universal broker, but the deployed implementation is **not yet universal**:

- Live integration: one Fortis Repo machine actor and the current SonarCloud scope.
- Sonar typed reads (`list_projects`, `list_issues`, `get_issue`, `get_quality_gate`): `ALLOW`.
- `sonarcloud.accept_issue`: `ASK`; owner WebAuthn is required before the Sonar mutation.
- Request status is available to the initiating machine actor.
- GitHub integration code now exists under `fortis_approvals/integrations/github/`, but it is **not registered in the live R7 composition**, no GitHub actor grants or policies are configured, and no Gateway GitHub credential/volume exists. The existing PAT under `/workspace/repo/.fortis-auth/` remains the separate Fortis Repo Git credential helper; do not copy it into Gateway. The new integration registration helper deliberately adds no grants or policy. The current Repo credential boundary is documented in Fortis Container's `docs/AUTHORIZATION-AND-APPROVALS.md` and `docs/GIT-AND-RECOVERY.md`.
- A generic HTTP proxy, arbitrary URL/method forwarding, token-return endpoint and AI owner/execute route do not exist and must not be added as shortcuts.

### Agreed GitHub policy target (not implemented)

| Operation family | Source implementation | Live policy/grant state |
|---|---|---|
| GitHub READ: repository, branch, commit, PR, Actions, Checks, status | Typed adapter/client implemented | NOT REGISTERED; unavailable |
| GitHub ACTION: branch create, file push, PR create/merge, workflow update, Actions run control | Typed adapter/client implemented | NOT REGISTERED; unavailable |
| Branch/repository deletion, webhooks, rulesets, secrets, variables | Not implemented | DENY / unavailable |

This table records the intended policy, not current capability. A policy of `ASK` does not override GitHub App/PAT permissions or branch protection. If the provider credential lacks a permission, the operation remains unavailable even after approval. GitHub permissions are coarser than Gateway operations: `Pull requests: write` permits both PR creation and merge; `Contents: write` permits Git reference deletion as well as writes; `Actions: write` permits multiple run-control operations; and `Workflows: write` permits workflow-file changes. The pilot intentionally grants these capabilities so they can be exposed as typed `ASK` operations. The Gateway must enforce the operation allowlist and owner approval; do not expose arbitrary provider endpoints or give the token to Repo/AI directly. See the [permission-specific onboarding plan](INTEGRATION-MODULARIZATION-AND-GITHUB-ONBOARDING-PLAN.md).

## How an AI agent should use it today

- Read [the source map and current commands](../fortis_approvals/README.md) to see what is actually available.
- Use only the documented Fortis Repo typed client/command for a supported operation. The current Sonar example is `python3 -m fortis_approvals.sonar_review_scenario review`; check status with its `status --request-id ...` command.
- For an unsupported service or operation, stop at the integration boundary and report what is missing. Do not fall back to a token in the workspace or a direct provider API call.
- Never use Owner Portal credentials or WebAuthn on behalf of the owner. The owner completes the approval in the separate Portal.

## Adding a new service or authorization

A new token alone does not make a service available. A service integration is complete only when its credential, adapter, typed contract, actor grant, policy, client operation, tests and deployment are all connected. Use the [provider integration template](../fortis_approvals/integrations/_integration_template/README.md) and keep each provider's implementation and documentation in its own folder.

1. **Define scope first.** Record the service, trusted tenant/organization, allowed resources, region, required operations and minimum provider scopes. Decide which operations are `ALLOW`, `ASK` or `DENY`. Keep high-risk provider scopes out of the initial credential if they are not needed yet.
2. **Provision the credential on the Gateway side.** Use a dedicated secret/volume and owner-controlled provisioning. Never put the provider token in Git, a Repo workspace, an AI request, a client grant or a log. The Repo machine grant authenticates Repo to Gateway; it is not the provider token.
3. **Implement a service-specific adapter.** Pin trusted upstream origins, HTTP methods, routes and parameter sets. Validate targets and upstream responses; bound timeouts and response sizes; disable unsafe redirects; redact errors. Separate read-only transport from mutation transport where appropriate. Do not create a generic `request(url, method, headers, body)` escape hatch.
4. **Register typed operations and schemas.** Extend the closed operation allowlists and validators in [`repo_action_contract.py`](../fortis_approvals/repo_action_contract.py). Keep READ queries separate from ACTION intents. Define exact required fields, types, bounds, target scope and public response projection; reject extra fields and caller-supplied tokens, URLs, methods, actors or policy.
5. **Wire actor grants and policy.** Extend the trusted composition in [`r7_unified_candidate.py`](../fortis_approvals/r7_unified_candidate.py): read operations go into `actor_read_operations`; action operations go into `actor_operations`; policy entries are registered in the trusted `policies` map. Use `ALLOW`, `ASK` or `DENY` per actor/service/operation (and narrower target rules where needed). The module name is a retained historical name, not a promise that this is the final architecture.
6. **Connect ingress and the client.** Add only explicit typed routes/dispatch and matching client methods. Current machine ingress exposes `POST /v1/reads`, `POST /v1/actions` and `GET /v1/requests/{requestId}`; it is not a general proxy. The shared Repo transport is [`clients/gateway_transport.py`](../fortis_approvals/clients/gateway_transport.py); provider clients live under `integrations/<provider>/repo_client/`. GitHub adapter plumbing is attached only through [`integrations/github/registration.py`](../fortis_approvals/integrations/github/registration.py), which does not configure actor grants or policies.
7. **Test the security boundary.** Add tests for schema rejection, unknown operations, actor grants, target scopes, default DENY, ALLOW execution, ASK/PENDING, Reject with no dispatch, approval-bound execution, stale previews, credential redaction and upstream response validation. Use mocked/offline transports for normal tests; reserve live mutation for a separately approved owner-run E2E.
8. **Review deployment separately.** Update the image source allowlist, secret provisioning and deployment artifacts only through the approved release procedure. Editing this development checkout does not change the active Gateway image or container.

### Code ownership map

| Concern | Current source of truth |
|---|---|
| Closed operation names and request schemas | [`repo_action_contract.py`](../fortis_approvals/repo_action_contract.py) |
| Actor grants, adapter wiring and current policy map | [`r7_unified_candidate.py`](../fortis_approvals/r7_unified_candidate.py) |
| Default-DENY policy lookup, durable request lifecycle and execution | [`core.py`](../fortis_approvals/core.py) |
| Authenticated typed machine ingress | [`repo_ingress.py`](../fortis_approvals/repo_ingress.py) |
| Existing Sonar read/write adapters | [`sonar_read.py`](../fortis_approvals/sonar_read.py) and [`sonar.py`](../fortis_approvals/sonar.py) |
| Current Repo-side Sonar client | [`repo_sonar_tools.py`](../fortis_approvals/repo_sonar_tools.py) |
| Contract/Core/ingress regression tests | `fortis_approvals/tests/test_repo_action_contract.py`, `test_core.py`, `test_repo_ingress.py`, `test_r7_unified_candidate.py` |

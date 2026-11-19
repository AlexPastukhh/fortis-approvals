# Owner provider inventory — Phase 1 merged source (2026-11-19)

**Status (2026-11-20):** merged source in [PR #147](https://github.com/AlexPastukhh/fortis-approvals/pull/147); **not thereby built, deployed, enabled or accepted in the owner browser**. The broader [P1 program](BACKLOG-IMPROVEMENTS.md#api-onboarding-program) remains open.

## Endpoint and trust boundary

`GET /v1/owner/provider-inventory` exists **only on `IncidentOwnerPortal`** (not Repo/machine ingress), after exact trusted Host, empty query and forwarded/authorization-header checks, and valid owner session cookie. No owner mutations, policy writes, credential provisioning, new scopes or WebAuthn shortcuts are exposed. Response is `no-store`, with the Portal baseline CSP and security headers. All cells in Dashboard use `textContent`, not HTML interpretation.

Result fields: `schemaVersion`, `coverage`, `policyVersion`, `providers[]`, `operations[]`. `coverage=LOADED_GATEWAY_RUNTIME_ONLY`: native adapter names and configured policy entries, plus **loaded** extension provider definitions and configured grants. Native operations absent from policy map, packages not loaded into the process and external API readiness are **not** enumerated. Unknown method versions, effect kind and effective policy for wildcard/actor-wide native rules are explicitly `null`/`unknown`/`UNKNOWN`. The inventory does not invoke policy callbacks or extension handlers.

Extension rows show operation version/kind, exact actor+target, configured and effective policy, handler readiness, and an aggregate credential readiness status. **Never** return credential aliases, secret values, cryptographic generations, raw config or provider tokens. `upstreamStatus=UNVERIFIED` does not assert that remote API works; `active` means the handler is installed in this Gateway process, not remotely healthy.

The UI tab **API и политики** is read-only, with filter and explicit coverage label. A reload reads current in-process policy; there are no editing controls or privileged POST routes.

## Still required before P1 acceptance

- Full native packaged method/operation version registry and nonloaded/disabled extension inventory (source/runtime identity bounded).
- Unambiguous effective actor+target+environment precedence, native predicate inspection that does not invoke predicates, and policy digest/revision readback.
- Owner-only versioned policy store, diff/preview, separate **fresh** strong WebAuthn for each exact mutation, CSRF/origin/session checks, optimistic concurrency, audit, revoke and rollback.
- Negative/auth/CSRF/stale/cross-actor tests and verified build/CI/owner release, with runtime installed source/image attestation; no change to existing authorization implied by these READs.

## Offline verification

`python3 -B -m unittest fortis_approvals.tests.test_owner_inventory fortis_approvals.tests.test_owner_shell_portal`

`python3 -B scripts/update-source-manifests.py --check` (after updating generated manifests).

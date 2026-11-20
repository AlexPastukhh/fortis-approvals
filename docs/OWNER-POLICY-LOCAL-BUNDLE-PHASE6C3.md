# Phase 6C.3 — single-process guarded Core/Owner/Client composition

**2026-11-20: SOURCE-ONLY / NOT A DEPLOYABLE RUNTIME FACTORY / NO HOST CHANGES.** PR #170 merged the opt-in owner WSGI DENY bridge. This phase closes two source integration gaps without opening any live route or claiming that all installed workers use local policy enforcement.

## Correct Core type for owner incidents

The opt-in `LocalDenyCore` now inherits `IncidentCore` instead of plain `Core`. This preserves the original release-pinned `core.py`, `owner_auth.py`, `owner_portal.py`, `gateway.py` and `runtime.py` byte-for-byte. A policy-aware owner portal inherits incident readback and closure routes that need the `IncidentCore` API. All existing local deny CAS and request version/fingerprint/dispatch gates remain unchanged. The default runtime continues to instantiate its old Core. This change does **not** register a runtime provider or alter installed policy.

## Source-only composition candidate

`extensions/owner_policy_local_bundle_phase6c3.py` provides `bind_source_only_local_policy_bundle`. It accepts **preconstructed trusted in-memory objects**: exact `LocalDenyCore`, same `OwnerWebAuthn`, a fixed client Host, and source/credential-generation digests from a future independently checked owner host. It constructs a plain `ClientGateway` and an opt-in `OwnerLocalDenyInventoryPortal` bound to the **same single Core object** and to `OwnerLocalDenyApply`. It constructs **no network listener, environment configuration, host credential, migration, Windows action, release request or new machine API**. Default `IncidentOwnerPortal` is unaffected.

`SourceOnlyLocalPolicyBundle.status()` enforces object identity in that one process and explicitly returns:
- `allInProcessEntrypointsBound: true` only when machine, owner and apply objects reference the exact same Core;
- `externalWorkersVerified: false`, `hostSourceAttested: false`, `hostCredentialGenerationAttested: false`, `rollbackProtected: false`, `runtimeIntegrated: false`, `canDeploy: false`.

These are not optimistic placeholders. **No in-memory factory can prove that other host processes, worker replicas, old images, migrations or restore paths use the guarded Core.** There is deliberately no assertion of whole-deployment coverage.

## Accurate owner inventory

The existing owner inventory is a read projection of configured policy and **does not know local SQLite denials**. For example, after a local exact ASK-to-DENY change, the old inventory might still say ASK. The opt-in `OwnerLocalDenyInventoryPortal` intercepts owner-only GET `/v1/owner/provider-inventory` to read the exact Core-local denials under the same trusted DB and overlay `effectivePolicy: DENY`, `localDenialApplied: true`, current local revision, and the limited-coverage/rollback flags. It never invokes policy predicates or provider effects; it only projects verified exact literal rows. If a stored local DENY does not match one known exact ASK/ALLOW configuration, it **fails closed** instead of silently omitting the restriction. Host/session checks remain identical to IncidentOwnerPortal. New owner WebAuthn begin/finish/readback routes still come from Phase 6C.2.

## Negative tests and remaining STOP

The test bundle demonstrates client submission, owner incident read, owner inventory before/after a local WebAuthn-synthetic DENY, old pending approval invalidation, restart with guarded Core, exact Host/cookie enforcement, identity drift and source-only reporting. It also **proves plain legacy `Core` on the same DB still ignores local DENY** — this is not a deployment-safe revocation mechanism yet.

**Remaining gates before any production enablement:** live installed-source and credential-generation attestation; all worker/process construction and ingress selection pinned to LocalDenyCore and verified independently; owner network isolation, migrations/restore checks, real WebAuthn E2E, current owner UI, in-flight `DISPATCHED/UNCERTAIN` handling, and separately owner-approved release. Independent monotonic/immutable history remains deferred per owner decision, so backup/old-binary rollback can restore grants; do not claim anti-rollback or permanent revocation.

This is testable source composition, not a runtime factory approval, release, permission change or a new authorization for AI.

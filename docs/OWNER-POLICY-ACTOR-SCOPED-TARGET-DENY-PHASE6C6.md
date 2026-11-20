# Phase 6C.6 — exact target DENY inherited from actor policy

**2026-11-20: SOURCE ONLY / NOT DEPLOYED.** The owner deferred the independent immutable/monotonic audit service for the limited MVP. Old image and SQLite backup rollback risks remain real. No release or policy activation is authorized.

## Why this matters

The original owner-only local DENY editor accepted only an already configured exact (actor, provider, operation, target) literal ASK or ALLOW. Native R7 Sonar normally configures (actor, sonarcloud, accept_issue) as actor-scoped ASK, so no real issue target was previously editable through this exact-only editor.

The new optional candidate field expectedConfiguredScope: actor explicitly selects one narrow case: **DENY one exact target inherited from a configured actor-scoped literal ASK/ALLOW**. The target must be concrete and syntactically valid. The original exact-only candidate format without this field remains unchanged. No actor-wide rule, other issue, global fallback or callable policy is edited. No DENY removal, ASK restore, ALLOW grant or PowerShell bypass is possible.

## Source and proof binding

At fresh begin and again after owner WebAuthn UV under the same-Core-SQLite IMMEDIATE lock, validate: active actor and adapter, exact source parent policy ASK/ALLOW, absence of ANY overriding exact configured rule (including DENY/callable), correct expected policy revision/version, and no existing local DENY. Any drift fails closed.

The complete actor-scope tag, exact target, purpose, immutable UUID, owner/source/credential-generation descriptor and 90-second expiry are bound into a separate one-time owner WebAuthn challenge. Legacy review proof does not authorize apply. CAS inserts the same target-exact local DENY row, increments the single Core revision and appends a local audit row in one transaction. No upstream adapter side effect is invoked.

The opt-in owner-only inventory creates an **additional exact row** for the restricted target with configuredSourceScope: actor, effectivePolicy: DENY and localDenialApplied: true. It keeps the actor-scoped source policy row unchanged; other targets inherit ASK/ALLOW. A missing/callable/inconsistent parent or exact shadowing yields DENY rather than hiding any stored restriction. There is no independent anti-rollback receipt.

## Acceptance / remaining STOP

Offline tests cover unaffected targets, exact override, global/callable refusal, stale revision, duplicate/consumed WebAuthn proof, concurrent CAS and mismatched audit inventory. The native R7 actor-scoped Sonar ASK test uses a mock transport and proves a single issue target is denied while another is unaffected. Real FIDO2 VirtualKey tests with valid UV and wrong origin are registered for exact-head GitHub Source CI; the local Repo image lacks fido2.

No live runtime factory, installed worker check, owner-host attestation, secure migration, Dashboard Save/Apply, Windows operation or Docker release is implemented here. Default r7_unified_server still does not enable the local policy editor. Existing old workers can ignore local DENY; the startup fence cannot stop them. Owner-controlled end-to-end release and backup/restore acceptance remain OPEN.

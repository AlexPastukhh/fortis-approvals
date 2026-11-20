# Phase 6B.4 — read-only owner recovery evidence classification

**2026-11-20: SOURCE CANDIDATE, NOT DEPLOYED, NO RECOVERY EXECUTION OR POLICY APPLY.** Earlier Phase 6A–6B.3 are merged source only. Owner-host monotonic checkpoint service, protected provisioning and live admission fencing remain absent.

## Purpose

A signed prepared-event witness and external latest quote may provide evidence about an inert policy change. Neither proves that a request never caused external effects; neither authorizes clearing a PREPARED barrier. This phase adds `OwnerPolicyRecoveryInspectorCandidate`, an offline/read-only classifier requiring the exact Phase 6B.1 store, 6B.2 witness and 6B.3 monotonic quote verifier. No owner HTTP, Core or machine route imports it.

All results have `disposition=HOLD_OWNER_REVIEW`, `canApply=false`, `canRecoverAutomatically=false`, `canResumeDispatch=false`, `policyCommitConfirmed=false`, `inFlightRequestsReconciled=false` and `activePolicyChanged=false`. Not even a fully verified PREPARED record changes an active rule.

## Fail-closed classifier

| Evidence | Code | Automatic effect |
| --- | --- | --- |
| SQLite baseline, policy version or hash invalid | `PHASE6B4_LOCAL_STORE_UNVERIFIABLE` | NONE |
| Locally READY, but no independent anti-rollback claim | `PHASE6B4_NOT_PREPARED` | NONE |
| Request UUID or audit head differs from one PREPARED | `PHASE6B4_REQUEST_OR_HEAD_MISMATCH` | NONE |
| Signed owner witness missing, damaged or wrong | `PHASE6B4_WITNESS_UNVERIFIABLE` | NONE |
| Latest quote unreachable, stale, forged or mismatched | `PHASE6B4_EXTERNAL_CHECKPOINT_UNVERIFIABLE` | NONE |
| SQLite, local witness and external latest agree on PREPARED | `PHASE6B4_ATTESTED_PREPARED_STILL_BLOCKED` | NONE |

The algorithm verifies local SQLite first, local signed witness second, external fresh nonce-bound latest checkpoint third. A failure at an earlier stage never queries a later source. Missing ACK or remote outage does not establish non-execution, and a replay of an earlier signed checkpoint never authorizes recovery. Bad data yields only stable denial classes, never secrets or mutation authority.

## Required future owner-operated recovery

Freeze new policy admissions and preserve original UUID/readback. Never blindly retry `DISPATCHED` or `UNCERTAIN` actions. Verify installed source/credential identity, protected DB, external monotonic checkpoint and worker claims outside the AI's shared Repo volume. Missing or contradictory evidence requires HOLD and owner investigation; no manual SQLite clearing, backup restore that resurrects grants, or source fallback to ALLOW.

A future recovery/apply transition requires protected **monotonic authority actually deployed and non-rollbackable**, atomic CAS/fencing across processes and independent audit, fresh purpose-specific owner UV WebAuthn, in-flight state handling and independently verified live readback. The current in-memory quote fixture is **not** such an authority. This source candidate adds neither active commit nor owner UI Save/Apply, migration, rollback or runtime release.

## Verification

11 security tests cover READY, missing witness, missing/timeout latest checkpoint, stale signed quote, wrong request/head, corrupted DB/witness, lost-ACK same-request readback, preserved original baseline and absence of mutating methods. Source CI must cover it. **Phase 6B stays OPEN** pending real monotonic service and atomic commit/recovery; Phase 6C–6F remain OPEN. Do not release or activate policy on the basis of this PR.

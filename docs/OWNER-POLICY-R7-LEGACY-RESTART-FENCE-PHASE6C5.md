# Phase 6C.5 — R7 legacy restart fence when local policy state exists

**Status (2026-11-20): SOURCE-ONLY, NOT RELEASED OR ACTIVATED.** Owner deferred the separate independent monotonic/immutable journal for the local-deny MVP. This is one narrow safeguard against falling back to unguarded policy after restart; it neither detects backup rollback nor demonstrates all worker coverage.

## Problem and remedy

The opt-in R7 builder from Phase 6C.4 can create a `LocalDenyCore` that enforces exact local `DENY` overlays and exposes an owner-only WebAuthn apply workflow. By default the same builder and production `r7_unified_server` select ordinary `IncidentCore`, which **ignores** those local SQLite denial tables. Thus a later restart without opt-in could silently resurrect configured `ASK`/`ALLOW`.

This stage adds the read-only `refuse_legacy_core_with_local_policy(root)` preflight to the **default** path of `build_r7_unified_candidate`. After the existing `_fresh_r7_state` private-root validation and **before** constructing Sonar receipts, OwnerWebAuthn, Core, or machine broker, it inspects only the already-existing `approvals.sqlite` using SQLite `mode=ro`. Missing DB is allowed without creating a replacement. An existing ordinary DB with no local owner-policy schema may continue the original default. A schema name beginning with `owner_local_` — including a partial schema, an initialized but empty DENY table, or a fully populated owner policy — immediately denies default restart with `R7_LEGACY_CORE_LOCAL_DENY_BYPASS_FORBIDDEN`.

Corrupt/unreadable DB, symlink, directory in place of DB, or an owner-mismatched file fails closed as `R7_LOCAL_POLICY_DB_UNVERIFIABLE`; the preflight never repairs, replaces, clears, truncates, copies, migrates, signs, commits or activates a database. The exact opt-in guarded R7 path remains handled by the existing local-schema integrity checks; this new helper does not grant permissions or add an API. The current default R7 server does **not** construct or pass the opt-in selector.

## Limits and release STOP

This check applies only to **new builders using this exact source version**. It **cannot** intercept an older already-running Core, an older installed image that does not contain this check, an independent worker with its own state, or a restorer that rolls back the entire DB and image together. It is not external worker census, source-image attestation, credential identity proof, persistent revocation guarantee, independent audit, an atomic cross-host fence or protection against malicious backups. Existing in-flight `DISPATCHED`/`UNCERTAIN` remote effects must never be blindly retried.

The actual owner-host rollout is blocked until owner-controlled exact image attestation, all worker/ingress/restore path inventory and negative live tests, local-schema migration checks, actual R7 actor/target grant compatibility, owner WebAuthn UV apply E2E, and explicit acceptance of no independent anti-rollback. No extra service or audit-history system is introduced in this source stage. No Docker, Windows, release, owner approval, policy change or data migration has been performed.

## Verification

Offline tests cover: pristine state not creating a DB; established legacy DB preserving default behavior; opt-in DB with zero or populated DENYs blocking restart; opt-in guarded restart preserving revision; partial local schema detection; corrupt DB, symlink and directory refusing fallback; unrelated DB tables not triggering false denial; and absence of recovery/mutation helpers. The full source CI must rerun R7/TLS/FIDO2/owner incident regression tests at the exact PR commit. Release-storage pinned Core/WebAuthn/Gateway files remain unchanged.

# Phase 6C.8 — offline worker/SQLite inventory consistency classifier

**2026-11-20 — UNWIRED SOURCE ONLY. NOT owner-host attestation, runtime integration, authorization or release.** Phase 6C.7's subprocess tests are merged (PR #178). A worker on a different SQLite file or old Core can bypass local DENY. This stage provides a strict **comparison contract for independently supplied owner-host observations**, not a process collector or proof of live completeness.

## Closed owner-supplied observation contract

`extensions/owner_policy_worker_census_phase6c8.py` defines the pure `assess_owner_worker_census(expected, observations)` classifier. The expected structure includes: version 1, an observation timestamp and bounded maximum age, the role set (including owner HTTP and machine ingress), a list of expected PIDs with process-start ticks and role assignments, source SHA-256, credential-generation SHA-256, actor grants SHA-256, exact policy version and revision, the expected absolute SQLite path plus device/inode, and an explicit owner-supplied process-enumeration-complete flag.

Each observed process must have a closed record with PID/start ticks/roles, exact type `LocalDenyCore`, the same source/credential/grant digest, policyVersion/revision, SQLite path/device/inode and observation time. Multiple replicas may share a role; duplicate or unknown PID, wrong role, missing declared PID, stale/future samples, legacy Core, a different mounted DB, unexpected revision or identity all produce a blocking mismatch. Invalid schema, wildcard/unknown role, invalid hashes, unsafe state paths or numeric type confusion are refused.

A fully consistent supplied inventory returns `consistentDeclaredSamples=true`, **not** `ownerHostAttested=true`. The response always has `canDeploy=false`, `canApplyPolicy=false`, `rollbackProtected=false`, `runtimeIntegrated=false`, `ownerHostAttested=false`, `processEnumerationIndependentlyVerified=false`. Consistency of fields **cannot establish that the owner actually enumerated every process** or that the samples were made by a trusted owner-local collector; an attacker or test fixture can produce self-consistent false input. The classifier offers no signing, lease, runtime authority, source verification or active policy mutation.

## Remaining owner-host STOPs

Before any real owner policy apply, an independently trusted owner-controlled host procedure must obtain a **complete current process/container census** including machine ingress, owner listener, native/extension workers, prior images and alternate launch paths, resolve actual image binary/source digests and credential generation, inspect exact protected SQLite mounts and storage identity **in each namespace**, and prove the reported process start identities. Path/device/inode comparisons are local-platform observations, not universal cross-host storage identifiers. Separate backup/restore, volume switch and old-image tests remain mandatory.

A real owner-controlled release must also ensure the standard `r7_unified_server` selects the guarded Core for every worker and verify negative live requests, in-flight `PENDING/APPROVED/DISPATCHED/UNCERTAIN` behavior, owner passkey and operational recovery. This PR does not run host commands, change Docker/server/Windows, add a Dashboard button, or grant owner-apply privileges. The independent immutable/monotonic history service remains deferred by owner choice; SQLite backup rollback still reintroduces ASK. No release eligibility is claimed.

## Tests

`test_owner_policy_worker_census_phase6c8.py` checks consistent yet non-authorizing source data, replicated roles, missing/unknown/duplicate process, role/pid-start mismatch, legacy Core, split DB identity, source/credential/grant drift, revision mismatch, stale/future samples, unconfirmed enumeration, schema type confusion, invalid database path and absence of any apply credential or deploy result. Tests construct data only; they are **not host or cryptographic attestation**. Exact-head Source CI, source manifest and independent review remain required before merging source.

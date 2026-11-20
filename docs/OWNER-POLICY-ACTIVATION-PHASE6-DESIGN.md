# Phase 6 — active policy authority and owner-only atomic activation

**Status (2026-11-20): design candidate, NOT an active implementation or production approval.** Phase 1–5 source remains preview/review-only; the existing Phase 5 browser bridge is disabled without a trusted inactive ledger. Existing Gateway effective policy is still authoritative until separately reviewed migration, CI and owner-controlled release.

## Boundary and threat model

Machine actors and a compromised shared Repo workspace must never gain owner-only HTTP routes, credential/grant mutation, active policy DB access, or the ability to use their own proposal as approval. The owner UI accepts only an exact existing actor + provider + operation + target/environment rule; it cannot specify executable predicates, storage paths, providers, credentials, or grant identities. All unknown and unconfigured operations fail closed to DENY.

The current native Core policies have exact, actor-level and global precedence and can contain trusted callable predicates. ExtensionRuntime has separate rules and credential grants. Inventory and preview do NOT constitute runtime authority. Never make the inactive PolicyDraftLedger an active policy overlay by assignment. First establish an attested baseline and prove equivalence between actual Core/extension evaluation and the planned single active authority for each admitted exact rule. Conflicts, callables, wildcards, nonloaded providers or unresolved method versions stop migration.

## Protected active store (gate 6A/6B)

- Active storage belongs on an owner-controlled protected host path, not the shared Repo volume. Enforce owner/permission checks, no symlink/hardlink use, schema/version checks, backups, startup integrity and crash-safe restore. Unknown state must DENY or prevent startup, never revert silently to permissive defaults.
- Exact keys, immutable baseline digest, installed source/config digest, policyVersion, credential-generation digest, effective actor grants, committed revision and active audit head are required. Audit must be independently anchored/signed outside editable database state: Phase 3 plain SHA-256 chain is not anti-tamper proof.
- Multi-process Gateway workers must share one real transaction/fencing epoch for policy activation and admission. In-memory locks and browser preview hashes are insufficient. Atomic CAS must verify exact old rule, expected revision and source/grant/credential pins under the commit lock.
- Durable audit and active-state transition must be crash-consistent. If an external audit anchor cannot atomically commit with the policy DB, write an explicit durable PREPARED barrier blocking admissions until independently anchored receipt confirmation. Lost ACK must lead to readback, not repeat of unknown effect.
- No automatic migration from inactive drafts. A backup restore must not revive revoked credentials or older grants without independently verified owner recovery.

## Owner-only change (gate 6C/6D)

1. Owner Host, Origin, CSRF and authenticated session are mandatory. A preview is informational and does not authorize apply.
2. Apply/begin creates a fresh single-use UV-required FIDO2 challenge with purpose APPLY_ACTIVE_POLICY_CHANGE_V1. Bind exact actor/provider/operation/target/environment, literal old/new DENY/ASK/ALLOW, request UUID, owner session, source and credential digests, baseline, active revision, audit head, affected grants and short expiry (at most 90 seconds).
3. Apply/finish consumes challenge exactly once and verifies origin, RP ID, signature, active credential, counter, UV and exact descriptor. Login, previous ASK approval and Phase 4/5 draft-review proof are NOT valid apply proofs or bearer authorization tokens.
4. Under active policy commit lock revalidate all bound data and active identity, in-flight requests and Windows prerequisites; atomically advance revision/rule with durable receipt. Re-read exact effective state after commit. Any drift, missing audit anchor, concurrency race or recovery uncertainty => no permissions gain.
5. Rollback is a distinct new owner-authorized policy transition with fresh strong proof, CAS and audit. It is not a request to repeat or undo external provider effects.

## Dispatch and PowerShell

PENDING and APPROVED requests affected by a policy change must be rechecked against their frozen policy identity and become STALE/denied rather than silently receiving broader rights. DISPATCHED, UNCERTAIN and CLAIMED may have effects; preserve records, never replay, reconcile or close them implicitly. Revocation blocks new dispatch and records unresolved possible effects. All caches, owner inventory and Core pre-dispatch must agree on committed version or fail closed.

For powershell.execute the present ASK-only protocol V1 remains mandatory. No outer ALLOW until the separate Windows Executor Dynamic ASK evaluator and exact-command V2 signed proof are verified. Aggregate DENY > ASK > ALLOW, with one Core pending approval when both layers ASK; outer ALLOW never bypasses Windows evaluation.

## Ordered acceptance gates

| Gate | Exit criteria | Status |
| --- | --- | --- |
| 6A — exact authority | Native/extension scope precedence, trust migration, callable/grant rejection and source/credential pins | OPEN |
| 6B — active storage | Owner host protection, multi-process CAS, audited transaction and crash/restore tests | OPEN |
| 6C — Core integration | Same revision at submit, owner decision and dispatch; in-flight/worker fail-closed tests | OPEN |
| 6D — strong apply | New one-use apply-specific owner UV WebAuthn, atomic commit and readback | OPEN |
| 6E — Dashboard | Exact rule edit/save only after 6A–6D, no machine route or broad PowerShell ALLOW | OPEN |
| 6F — delivery | Source CI, owner UI merge, separate owner-controlled release, live and negative acceptance | OPEN |

Negative tests before any active capability: wrong actor/target/method/grant, unknown/wildcard/callable policies, invalid source or credential generation, stale revision/preview, UV false, wrong RP/origin/session/CSRF, replay/expiry, concurrent processes, tampered DB/audit, crash at each commit boundary, lost ACK, revoke/restore, PENDING/APPROVED/DISPATCHED/UNCERTAIN/CLAIMED, V1 PowerShell ALLOW bypass and machine-origin owner route attempts. Virtual FIDO2 crypto tests require CI; fake crypto tests are only state-machine tests.

**STOP:** No active policy store activation, production migration, owner apply route, Save button, ASK proposals or release on the strength of this document alone. Implement and independently review these gates before any permissions change.

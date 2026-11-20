# Owner policy Phase 6B.2 — independent PREPARED audit witness

**Status (2026-11-20): SOURCE CANDIDATE ONLY; NO POLICY APPLY OR PRODUCTION HOST CONFIGURATION.** Phase 6A and 6B.1 were merged in PR #160 and PR #161 respectively. This is an *additional* fail-closed witness, not an operational active-policy authority. Phase 6B overall is still **OPEN**.

## Trust boundary and mechanism

`OwnerPolicyAuditWitnessCandidate` (`extensions/owner_policy_audit_witness_phase6b2.py`) is never imported by Core/Owner Portal, is not a machine API, and cannot write an active policy. It requires a trusted `ProtectedActivePolicyStoreCandidate`, a separate owner-private witness directory (not the same parent as the SQLite DB and not a shared Repo mount), and a 32–128-byte owner-injected **HMAC signing key**. The key is never written to SQLite, the audit file, a Git repository, or a machine request. This prototype's byte-key interface is for isolated source tests; a real owner release must supply signer/key protection and host filesystem isolation from a separately reviewed owner-only trust domain.

The trusted caller must first prepare one exact change in the inert SQLite store. `attest_prepared(request_id, audit_head)` checks `PREPARED`, global revision 0, exact request UUID, event hash, baseline/source/credential-generation digests and policyVersion. It canonically serializes a `PHASE6B_PREPARED_WITNESS_V1` payload, authenticates it with domain-separated HMAC-SHA256 and writes a **create-exclusive, owner-private 0600** witness file. A second different writer cannot replace an existing signed witness. Same-request readback verifies exact content and returns `alreadyWitnessed=true`. The file and parent directory are fsynced; an interrupted/partial file remains a fail-closed blocker, not an opportunity for silent overwrite.

`verify(request_id, audit_head)` independently verifies signature, canonical schema and exact current trusted store snapshot. No receipt grants policy application: returns `canApply=false` and `activePolicyChanged=false`. SQLite remains `PREPARED`, effective active rules and revision remain frozen, and any other pending action remains blocked.

## Proof and explicit non-claims

Negative tests reconstruct a *different but internally self-consistent* SQLite journal with recomputed SHA-256 event and metadata hashes. The original SQLite self-verification accepts this forged chain, but the witness denies it because the external signed head no longer agrees. Wrong key, changed witness, missing/incomplete file, different UUID/head, unsafe owner path, symlink/hardlink, stale store, replay and restart are denied or readback-only.

This witness **does not** defend against complete replay of an earlier legitimate SQLite database and signed witness together, owner signer-key compromise, malicious owner-host administrator, theft of signer memory, malicious code running in the owner trust domain, credential revocation, or arbitrary rollback of filesystem snapshots. For true anti-rollback require a separately protected monotonic trusted counter or equivalent external append-only/remote attestation, verified per commit and recovery. The witness directory being distinct is necessary but does not by itself establish a separate security principal. Its key must not be provided by the AI, browser request or the shared Repo filesystem.

The witness is also **not** a complete atomic external-audit/active-DB commit protocol: there is intentionally **no active commit method**, no policyStore CAS revision advance, no signed WebAuthn apply challenge, no independent Core admission fence, no migration/rollback, and no owner Dashboard Save/Apply button. A crash between DB PREPARED and witness fsync means STOP until independently reviewed owner recovery; never automatically clear PREPARED or retry an external effect. No action can silently transition out of PREPARED.

## Acceptance and next step

Offline test command: `python3 -B -m unittest fortis_approvals.tests.test_owner_policy_audit_witness_phase6b2 -v` (10 negative/positive tests), plus Phase 6A and 6B.1. Included in `scripts/test-source.sh`, source manifests and Gateway image impact. CI must pass at exact PR SHA; source merge means **not deployed**.

**Next gate:** hardened independent owner signer/monotonic audit authority, protected owner host provisioning, transactional fencing + checked recovery across storage/audit/process restarts, and explicit independent review before any true active commit. Phase 6C integration, 6D apply-specific fresh UV-required FIDO2, 6E Owner Dashboard and 6F owner-controlled release remain OPEN. The Phase 6 design STOP rule continues to apply.

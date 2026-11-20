# Phase 6B.3 — external monotonic checkpoint fence (SOURCE CONTRACT)

**Status (2026-11-20): SOURCE CANDIDATE ONLY; NOT INSTALLED, NOT ANTI-ROLLBACK IN PRODUCTION, NO ACTIVE POLICY APPLY.** Phase 6A (#160), 6B.1 (#161) and 6B.2 (#162) are source-merged. This component does not satisfy the remaining Phase 6B trust/provider/recovery gates, and does not authorize owner-host deployment or policy activation.

## Problem and trust boundary

A signed HMAC file in a separate directory proves integrity against an attacker without the owner witness key, but **cannot** detect a complete rollback of both SQLite and the witness file to an earlier valid snapshot. A second local key, a second SQLite database, a mutable file counter, a signed timestamp without freshness or a browser-supplied monotonic value are not independent evidence.

Production requires a **separately owner-controlled, non-rollbackable latest checkpoint authority** with a protected monotonic epoch, immutable installation identity and independent durable storage. This authority must not be controlled by AI, provider input, the shared Repo workspace, the Gateway image/DB backup domain or untrusted owner HTTP payload. Its ability to refuse rollback, rotate keys, survive owner-host/worker restarts and detect clone/backup restoration must be proved by an owner-operated integration test and release review.

## This PR: strictly verifying, never advancing state

`fortis_approvals/extensions/owner_policy_monotonic_fence_phase6b3.py` defines `MonotonicPolicyFenceCandidate` with explicitly injected trusted `ProtectedActivePolicyStoreCandidate`, matching `OwnerPolicyAuditWitnessCandidate`, owner installation digest, fresh quote callback and owner-only HMAC verification key. The **callback is not an authority** merely because it is callable: only a genuinely isolated, non-rollbackable implementation with latest-state guarantees can be trusted in a later owner-controlled integration.

`verify_prepared(request_id, audit_head)` first checks current SQLite + signed local witness and its permanent PREPARED barrier. It generates a fresh unpredictable 256-bit nonce, requests an authoritative **latest** quote, rejects missing/unknown/oversized schema and checks its canonical HMAC-SHA256 signature, exact nonce, installation identity, epoch >= 1, event hash, request UUID, PREPARED, audit sequence/revision, baseline and installed source/credential/version pins. It rechecks local state after the quote. Missing/unreachable authority, replayed old signed quote, source rotation, independent newer checkpoint, local concurrency or tampering fails closed.

All successful responses still return `canApply:false`, `activePolicyChanged:false`, `runtimeIntegration:NOT_CONNECTED`. There is no method to apply/commit/rollback policy, clear PREPARED, advance the external epoch or construct a production authority. This readback cannot fence a future separate Core commit by itself; a final design needs **transactional admission/commit fencing** against races after the last check, including crash recovery and owner-only issuance.

## Cryptographic limits

The current quote verifier uses owner-injected HMAC test keys because the minimal Repo image does not include a reviewed asymmetric signature verification library. A production deployment must avoid spreading a signing-capable MAC key to an untrusted Gateway or browser; an owner-only isolate or independently reviewed asymmetric signature scheme with verifier-only key may be appropriate. Test-only `TestOnlyLatestAuthority` is ephemeral in-memory and **not** a model of durable/non-rollbackable storage. No cryptographic claim about TPM/HSM or OS ACLs is made by the unit tests.

The remote latest quote must attest the **current** epoch under its own monotonic transaction, not return cached token or accept a chosen epoch from the client. The oracle must reject diverging writes and resist snapshots from a malicious same-host DB administrator. One can detect rollback only when an independent trusted record has already advanced. Atomicity of external advance relative to SQLite commit remains a separate design gate: an advance that succeeds followed by a lost reply requires readback and frozen recovery, never a second blind write or silent ALLOW.

## Test and remaining gates

10 negative/positive tests cover exact match, missing/timeout authority, old nonce replay, independently newer head vs old internally consistent DB+witness, wrong key/actor/epoch/install/source/credential pins, damaged local witness, readback race and malformed quote; no active rules are changed. Registered in mandatory source suite.

**OPEN:** owner-installed monotonic authority and trust roots; independently verified loss/restore/credential rotation; crash-safe transaction across SQLite, monotonic authority and audit; multi-process Core fencing and in-flight ASK semantics; fresh apply-only UV-required FIDO2; owner-only Dashboard Save/Apply; owner-controlled release and live negative acceptance. Until these are complete, **STOP** before any permission mutation or privileged host change.

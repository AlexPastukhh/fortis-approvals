# Phase 6B.1 — protected active-policy store PREPARED barrier (source candidate)

**Status (2026-11-20): SOURCE-ONLY / PARTIAL 6B. NOT DEPLOYED, NOT CONNECTED, NOT AN ACTIVE POLICY EDITOR.** This PR must not be used to install an active store, open an apply endpoint, create an owner ledger, or authorize machine actor privileges. Phase 6A is merged as PR #160, but owner-controlled runtime release is independent.

## Implemented boundary

`fortis_approvals/extensions/owner_policy_active_store_phase6b.py` contains `ProtectedActivePolicyStoreCandidate`. Its constructor requires an explicitly supplied private absolute host path and a trusted `ExactPolicyBaseline` from Phase 6A; it never reads production configuration, discovers a baseline, touches credentials or imports runtime adapters.

The standalone SQLite file uses a protected parent, `0600` owner-owned single-link file, no symlink/ancestor-alias path, no Repo shared mount, `synchronous=FULL` and `BEGIN IMMEDIATE` for CAS. It stores the complete initial literal exact-policy baseline, installed source/config pin, credential-generation pin and policyVersion; any drift or malformed store prevents reopening.

`prepare_change` validates a strict existing exact-policy transition, expected old policy, UUID, global revision, source/credential/version pins and audit head under an exclusive SQLite transaction. It writes one canonical `PHASE6B_PREPARED_INERT` audit event plus pending descriptor, and closes the gate to `PREPARED`. The policy rows and active revision **never change**. Any new request while PREPARED is denied; an identical UUID and descriptor returns only readback (`alreadyPrepared=true`), with no new write. SQLite's cross-process write lock is used for competing prepares.

`snapshot()` verifies exact source binding, all baseline rows, canonical event hash, event sequence and durable pending state. It returns `canApply=false`, `runtimeIntegration=NOT_CONNECTED`, `externalAnchorVerified=false`. Reopening retains the barrier. There is **no** `commit`, `apply`, `activate`, `rollback` or emergency clearing method; no Core/Owner Portal/machine route invokes this component. This is a deliberately one-directional crash/recovery primitive, not the final active authority.

## Trust and correctness limits

- A local unkeyed audit hash is **not** an independently anchored, tamper-resistant audit. An actor able to rewrite the full DB can forge the chain. Do not infer the installed source/credential identity from caller-supplied digest text alone.
- While PREPARED, the source candidate is **stuck safe**. External independent audit anchoring, a durable commit/anchor protocol, restart/backup recovery and owner-authorized resolution are not implemented; direct DB edits and deletion are not permitted solutions.
- No WebAuthn apply challenge, owner policy change permission, credential rotation handling, release-time migration, admission fencing against live Core, or stateful invalidation of PENDING/APPROVED/UNCERTAIN/CLAIMED exists. Phase 6C–6F remain OPEN.
- Only pure source/offline tests were run; there is no owner-host Windows filesystem acceptance, production image/storage provisioning or effective permission readback. The protected directory test does not replace owner-operated ACL/mount checks.
- A new Gateway image containing this module would still leave the existing runtime policy unchanged because nothing imports or mounts it. Image/source merge must never be represented as activation.

## Verification and next gate

`python3 -B -m unittest fortis_approvals.tests.test_owner_policy_active_store_phase6b -v` tests private file boundaries, baseline/revision pins, strict coordinates, no silent PowerShell ALLOW, lost response idempotent readback, concurrent independent SQLite connections and processes, durable restart barrier, event/policy tampering and read-only status.

The next code gate is **6B.2: externally anchored audit + independently reviewed transaction/recovery design and multi-process admission fencing**, before any method that can commit an effective rule. After that: Phase 6C Core integration, Phase 6D fresh apply-specific strong UV WebAuthn, Phase 6E Dashboard Save/Apply, Phase 6F owner-controlled release and independent live verification. No production migration/host operations authorized by this document.

# Owner WebAuthn policy-change review — phase 4 source candidate

**Status:** source-only PR candidate (2026-11-19), not merged/deployed or exposed in owner web UI. **No policy activation** is enabled by this phase. The pinned immutable `owner_auth.py` remains unchanged; review ceremony is a separate trusted adapter in `extensions/owner_policy_change_challenge.py`.

## Exact contract

`OwnerPolicyChangeReview(owner_auth).begin_policy_change_review(session, csrf, change, ledger)` and `.finish_policy_change_review(session, csrf, ceremony, response, change, ledger)` are **trusted host-callable Python methods**, not WSGI routes. The owner must have an existing WebAuthn login session with matching CSRF. Every change triggers a fresh FIDO2 `authenticate_begin(..., user_verification=REQUIRED)` via the existing owner authenticator; `authenticate_complete` checks signature, RP ID, origin, user-verification flag, credential counter, active enrolled credential and session. This deliberately **does not** accept the existing session-only decision permit or a normal request-approval assertion.

The strict change object pins:

- `purpose=REVIEW_INACTIVE_POLICY_DRAFT_V1`, fresh canonical `requestId`, exact `actor/provider/operation/target` and old/new `DENY/ASK/ALLOW` (not equal).
- `expectedRevision`, `expectedAuditHash`, `baselineDigest`, `sourceDigest`, `credentialGenerationDigest`, `policyVersion`, bounded `reasonCode`, and `expiresAt` no more than 120 seconds ahead.
- All pins and the exact old rule must match the **independently verified, inactive** `PolicyDraftLedger.snapshot()` *before* beginning and *both before and after* cryptographic verification. The canonical descriptor SHA-256 is bound to the WebAuthn challenge along with a fresh nonce, RP ID, origin, and one owner session. An incorrectly scoped/mismatched, stale or expired attempt is denied.

The in-memory ceremony is consumed once (including on invalid change). Sessions and pending ceremonies are dropped on restart or credential revocation. No durable acceptance token is created. The returned `OWNER_POLICY_DRAFT_REVIEW_ONLY` result includes `canApply=false`, `policyActivated=false` and `authorizationToken=null`. **This is not an authorization for any later policy commit or runtime apply; future apply must initiate its own fresh exact strong WebAuthn and atomic active-policy CAS.** Machine ingress, actor permissions, dynamic PowerShell policy, extension source and current Core policies do not change.

## Tests and boundaries

- `test_owner_policy_change_challenge.py`: portable isolated state-machine tests (fake crypto, explicitly *not* proof of a WebAuthn signature); exact binding, changed revision, wrong actor/target, expiry, session, CSRF, replay, revocation/restart and race after proof.
- `test_owner_portal.py` extended with actual test-only P-256 VirtualKey/Fido2 assertions for verified owner login, fresh strong policy challenge, real signature/UV/origin and stale/replay failures. **Must run in source CI**, where `fido2`/`cryptography` are installed; the minimal Fortis Repo container lacks them.
- Source manifest `--check`, existing owner/session/inventory/preview/ledger regression tests and curated-image import smoke.

## Deferred before live policy edits

Implement owner-origin-only authenticated/CSRF-checked browser ceremony workflow and UI, persist a versioned trusted owner policy store with independently anchored audit, atomic live Core/ExtensionRuntime policy activation/rollback and startup readback, invalidate all pending requests/revoked credentials, check source/credential rotation and concurrency again under the commit lock, and separately validate Windows Dynamic ASK/ALLOW/DENY. **No new live ALLOW from this PR**.

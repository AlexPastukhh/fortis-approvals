# P1 phase 5 — owner WebAuthn review browser bridge (source only)

**Status:** source PR candidate, not yet merged, not installed; **no policy apply**.

## Enabling boundary

The default production `IncidentOwnerPortal(core, authenticator, ...)` has **no review ledger** and exposes `GET /v1/owner/policy/review/capabilities` only as `{configured:false, canApply:false, ...}` to a logged-in owner. Its POST review routes return `403 OWNER_POLICY_REVIEW_NOT_CONFIGURED`. There is **no automatic baseline discovery, ledger DB creation, configuration flag, owner permission upgrade, or executable policy overlay**. Source-only tests instantiate `IncidentOwnerPortal(..., policy_review_ledger=trusted_prebound_PolicyDraftLedger)` explicitly. No live deployment, secret provisioning, or Windows release is included.

Trusted host configuration is deferred: a protected root/owner-controlled ledger path and independently verified, exact baseline/source/policyVersion/credential-generation pins must be established outside the shared Repo AI workspace before any review route can be enabled. `read_only_banner` disables POST review even if a ledger is passed. `OwnerWebAuthn`, immutable release storage, legacy `OwnerPortal`, machine ingress and PowerShell execution contracts are unchanged.

## Owner HTTP-only behavior

- `GET /v1/owner/policy/review/capabilities`: requires owner login, exact Host, no forwarded/Authorization headers, no query string. Returns opt-in status (`configured`, `requiresStrongWebAuthn`) and **`canApply=false`**. Does not expose ledger rows or secrets.
- `POST /v1/owner/policy/review/begin`: owner login **and exact Origin+CSRF**; body strictly `{candidate: {provider,operation,actor,target,expectedConfiguredPolicy,desiredPolicy,expectedPolicyVersion}}`. Re-runs the existing exact owner inventory preview. Denies unknown/conditional/global/actor-wide scopes, noop, stale policy versions and absent or drifted draft baseline. Creates a new `requestId` + 90-second descriptor binding exact `oldPolicy/newPolicy`, pinned baseline/source/credential-generation and global revision/audit hash, then calls the separate phase-4 strong FIDO2 review adapter. Returns **only a browser assertion challenge and inert change descriptor**, no apply permission.
- `POST /v1/owner/policy/review/finish`: same host/origin/session/CSRF guards; body strictly `{ceremonyId, response, change}`. Consumes a one-use challenge even on wrong change, verifies **fresh** WebAuthn assertion with user verification required and checks ledger state before and after credential verification. Re-evaluates live exact policy preview after proof. Returns only informational `{verified:true,kind:OWNER_POLICY_DRAFT_REVIEW_ONLY,canApply:false,policyActivated:false,authorizationToken:null}` on success. Stale ledger/version returns 409; invalid/replayed proof returns 403.
- No machine-side `policy/review`, no reusable grant token, no route to `apply`, no `stage_draft`, no persistent review receipt. Owner FIDO2 credential counter may be advanced by a verified strong assertion in existing owner credential storage, but **draft ledger, Core policy, pending requests and remote providers are not written**. A later active-policy change must have a **new, distinct** strong ceremony and atomic active-store CAS.

## Browser behavior

`Dashboard > API и политики > Показать последствия` still performs read-only preview and displays real risk. The new `Подтвердить просмотр через WebAuthn (без применения)` button remains **disabled** unless an authenticated opt-in status explicitly says configured and a changed exact rule has passed preview. It uses existing browser `navigator.credentials.get()` challenge handling. Selecting another rule, changing desired policy, loading new inventory or signing out clears preview approval state. Output explicitly states no rules changed and the browser never shows an apply button.

## Tests

- `test_owner_policy_review_http.py`: 8 portable server-boundary tests using **fake crypto** (not proof of signature) for owner-only host/origin/CSRF, disabled-by-default, legacy route absence, exact rule, stale/unknown grants, no-op, one-use, session-only rejection, unchanged Core/SQLite.
- `test_owner_policy_review_http_crypto.py`: **real virtual P-256 FIDO2** cryptographic tests in CI for login + reviewer session, RP/origin/UV, tampering, replay and post-auth live state drift. Minimal Fortis Repo image lacks `fido2/cryptography`; CI is authoritative.
- `scripts/test-source.sh`, `scripts/update-source-manifests.py --check`, `scripts/check-release-storage-source.py`, curated image smoke and Owner Portal regressions. Do not merge on failing CI.

## Still missing before owner policy editor can go live

Trusted owner-host ledger provisioning/migration, durable and independently anchored audit, versioned **active** policy source, atomic apply/rollback, owner fresh apply-specific WebAuthn, restart/readback and pending-request invalidation, Windows command policy gate, and separate owner-approved image/Windows release.

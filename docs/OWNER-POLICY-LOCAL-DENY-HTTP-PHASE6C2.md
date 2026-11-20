# Phase 6C.2 — opt-in owner-only HTTP bridge for local DENY (SOURCE ONLY)

**2026-11-20: SOURCE REVIEW CANDIDATE; NO LIVE RUNTIME INTEGRATION, OWNER HOST ENABLEMENT, MIGRATION OR DEPLOYMENT.** Phase 6C.0 / 6C.1 were merged in PR #168 / #169. The owner has deferred the separate independent immutable/monotonic audit history for this reduced MVP; a restored SQLite backup or an older executable can still resurrect grants.

## What this adds

`fortis_approvals/extensions/owner_policy_local_deny_http_phase6c2.py` introduces **`OwnerLocalDenyPortal`**, an independent subclass of existing `IncidentOwnerPortal`. The current running/default portal constructor, default Gateway WSGI routing, machine/client API and original release-pinned `core.py`, `owner_auth.py`, `owner_portal.py` **remain untouched**. Merely including this class in a Gateway image does not expose an endpoint. A trusted owner-only host factory must deliberately instantiate it and inject an `OwnerLocalDenyApply` matching the **same** `LocalDenyCore` and `OwnerWebAuthn` instances. Absent injection the begin/finish/readback endpoints reject requests.

The new optional owner routes, on the isolated portal instance only, are:

| Verb | Route | Effect |
| --- | --- | --- |
| GET | `/v1/owner/policy/local-deny/capabilities` | Authenticated owner-only, no secrets or grants; reports availability and DENY-only scope |
| POST | `/v1/owner/policy/local-deny/begin` | Exact `{candidate}`, fresh apply-specific REQUIRED-UV FIDO2 challenge (no DB policy mutation) |
| POST | `/v1/owner/policy/local-deny/finish` | Exact `{ceremonyId,change,response}`, consumes the one-use strong proof; the Phase 6C.1 adapter can atomically insert a local exact DENY, CAS revision and local audit in the same Core SQLite |
| POST | `/v1/owner/policy/local-deny/readback` | Exact `{requestId}`, owner session+CSRF readback of the original immutable UUID only, no reapply/retry |

All POST routes require exact owner Host, no forwarded/Authorization host override, no URL query, same Origin, strictly decoded bounded JSON and explicit WebAuthn owner cookie+CSRF. GET capabilities requires a valid owner session; the response uses baseline no-store/CSP/anti-framing headers. Request shape mismatches deny; no route takes a file path, grants, signer material, alternate owner identity, remote host, PowerShell command or provider parameters outside the exact policy candidate. `read_only_banner` refuses mutations. Existing owner WebAuthn enrollment, decisions, incidents, draft review and machine routes remain delegated unchanged.

The only active transition exposed by this **source class when instantiated** is configured exact `ASK` or `ALLOW` to a more restrictive `DENY`. No rollback/restore, permission escalation, wildcard/callable grant, default ALLOW, machine write route or generic policy update exists. Current Core-side request version checks and dispatch fencing apply only when **every** ingress/worker is bound to `LocalDenyCore`. An unmodified plain `Core` operating on that DB ignores the new local DENY overlay. This is a **release-blocking** gap, not solved by this PR.

## Trust and release boundaries

`OwnerLocalDenyApply` still accepts source/credential digests from its trusted constructor; this is **not** a validated installed-image attestation. Actual runtime use requires independent binding to the known source SHA, credential generation and correct instance identity, plus checked local schema migration from prior opt-in stores (6C.1 added `owner_local_policy_events`). No HTTP/runtime factory, Docker container, Windows Executor, owner Dashboard Save/Apply, provider inventory effect parity or any production gate is changed here.

The owner must separately approve a release accepting risk of restoring older versions/backups without external history, prove all workers use one guarded Core and that an old worker cannot bypass a revocation, test restart/rollback/in-flight `PENDING/APPROVED/DISPATCHED/UNCERTAIN` semantics, validate owner-only listener/network access, and perform independent live negative permission tests. No automatic retry following a lost `finish` response; owner readback by original UUID is the only permitted diagnostic path.

## Tests / CI

`test_owner_policy_local_deny_http_phase6c2.py` runs offline negative/positive WSGI behavior using the explicitly **synthetic** WebAuthn fixture: default IncidentOwnerPortal has no routes, opt-in type binding, Host/Origin/CSRF/cookie/forwarded-header checks, read-only/not-configured, body schema/duplicate JSON/method restrictions, stale revision (HTTP 409), one-use deny and readback, and no adapter side effect. That fixture is NOT a cryptographic proof.

`test_owner_policy_local_deny_http_crypto.py` runs the same HTTP route with real virtual P-256 WebAuthn enrollment/login and fresh UV-required apply assertion in the crypto-capable Source CI. It checks valid signature+origin, negative UV/crossOrigin/other owner session, purpose mismatch, stale revision and old challenge reuse. Minimal Repo Docker image lacks `fido2` / `cryptography`; **exact PR-head source CI and independent security review are mandatory before owner merge**.

**STOP before actual deployment:** source merger does not install this class or change active permissions. The remaining 6C/6E owner runtime factory, trust attestation, Dashboard UI and 6F release/readback are separate owner-controlled work.

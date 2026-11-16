# Gateway → Windows ASK-only PowerShell V1 — source integration

**Status: 2026-11-17 source candidate only.** This repo task is not an installed Gateway image, enabled route, issued credential, owner-approved release or Windows machine cutover. Windows owner-only Executor and its prior TLS/config/receipt DB continue unchanged until a separate guarded installation.

## Behaviour

Fortis Repo uses a typed, machine-authenticated Gateway client. The execution operation submits a fresh UUID, fixed named Windows target, and the full exact PowerShell script. Gateway Core produces **PENDING/ASK for every admitted command**; there are no V1 command allowlist/editor/automatic ALLOW branches. Owner Portal displays the full command, actor/target, digest and warning about non-admin execution without a sandbox. It requires **strong WebAuthn** (not session-only approval). Owner Reject means no Windows dispatch. After a verified owner decision, Gateway Core records DISPATCHED, signs a short-lived command-bound machine proof and uses only the distinct Windows machine API with separate mTLS/Bearer. The Executor verifies proof and durably reserves the current SQLite receipt before any effect. Original UUID results are READ, never implicit retry.

The proof is HMAC-SHA256 with a dedicated 32+ byte owner-controlled key that is present only in protected Gateway/Windows copies, not the Repo AI client. Claims include fixed audience, actor/target, UUID, exact command SHA-256, approved Core fingerprint and expiry. This is a trusted-Gateway signing design, not an autonomous capability granted to the machine caller. Key lifecycle, rotation, protected Windows/Container distribution, mTLS identity and negative tests require security review before activation.

## New source components

- fortis_approvals/powershell_machine.py — fixed HTTPS transport, owner-private credential validation, Core-bound ASK-only adapter and proof issuance. No machine route is active on import.
- fortis_approvals/powershell_owner_mount.py — strict owner-private fixed mount reader; absent mount means **disabled**. Expected mount path: /run/fortis-machine-powershell. It must be a non-symlink directory owned by the service UID and mode 0700; its six files must be owner/service-UID-owned non-symlink regular files, mode 0600, hard-link count one.
- Exactly six mount filenames: profile.json, server-ca.pem, client-cert.pem, client-key.pem, bearer, proof-key. The profile must contain exactly version=1, enabled=true, mode=ASK_ONLY, actor (must match already authenticated Repo actor), target, sourceSha256 (accepted Windows Executor SHA), executorIdentity. No policy/ALLOW flag, URL, port, arbitrary machine route, secret value or command is selected by AI.
- NativeIngress typed machine endpoints: POST /v1/powershell/submit, /v1/powershell/result, /v1/powershell/capabilities. The last two cannot execute. Malformed input, other actor, unknown target or missing adapter fail closed.
- workflow/powershell_client.py — Repo-side typed facade. No Windows credentials, direct HTTP, owner-cookies, automatic retry or fallback to owner-local API.
- runtime composition is deliberately **opt-in**. Owner mount + native registered Gateway actor/target are prerequisites; no change to the existing owner-only browser PowerShell API.

## Conditions before owner release

1. Owner reviews/merges the contract PR #119 and both Executor and Gateway implementation PRs after exact-head Source CI/Release Impact; source merge alone is not live deployment.
2. Independently review symmetric proof key and dedicated machine bearer handling; generate/copy secrets only via owner-private channels. No secret, generated key, cert or machine grant belongs in Git, PR, ChatGPT output or Repo project files.
3. Windows: update clean approved standalone source, verify current historical receipt DB/TLS remain intact and no unresolved effect. Install protected new machine proof/bearer files under %LOCALAPPDATA%\Fortis\OwnerShell, ensure NTFS ACL restrictive. Update the one registered Script Center process start, not a second listener.
4. Gateway: owner-provision protected fixed mount and deploy image with explicit ASK-only composition. Confirm original Repo machine actor and Windows instance/target binding. No credential sharing with Repo AI tools.
5. Live acceptance: denied request, missing proof, wrong identity/host/bearer, modified command, reject, expired/replay, lost ACK/UNCERTAIN/restart; fresh Get-Date from Repo produces PENDING → WebAuthn → exactly one Windows execution → bound receipt; prior owner-only UUID remains visible only through owner API.
6. Rollback uses the **same CURRENT receipt DB** with preserved historical and machine UUIDs. Never restore an older DB, retry uncertain effects or run two listeners on 10443.

**V2+ only:** owner-editable command restrictions and optional ASK/ALLOW for narrowly reviewable actions. V1's default for every execution is ASK, including diagnostics.
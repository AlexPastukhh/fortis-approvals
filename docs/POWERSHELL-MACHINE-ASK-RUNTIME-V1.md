# Gateway → Windows ASK-only PowerShell V1 — source integration

**Status: 2026-11-17 source candidate only.** This repo task is not an installed Gateway image, enabled route, issued credential, owner-approved release or Windows machine cutover. Windows owner-only Executor and its prior TLS/config/receipt DB continue unchanged until a separate guarded installation.

## Behaviour

Fortis Repo uses a typed, machine-authenticated Gateway client. The execution operation submits a fresh UUID, fixed named Windows target, and the full exact PowerShell script. Gateway Core produces **PENDING/ASK for every admitted command**; there are no V1 command allowlist/editor/automatic ALLOW branches. Owner Portal displays the full command, actor/target, digest and warning about non-admin execution without a sandbox. It requires **strong WebAuthn** (not session-only approval). Owner Reject means no Windows dispatch. After a verified owner decision, Gateway Core records DISPATCHED, signs a short-lived command-bound machine proof and uses only the distinct Windows machine API with separate mTLS/Bearer. The Executor verifies proof and durably reserves the current SQLite receipt before any effect. Original UUID results are READ, never implicit retry.

The proof is HMAC-SHA256 with a dedicated 32+ byte owner-controlled key that is present only in protected Gateway/Windows copies, not the Repo AI client. Claims include fixed audience, actor/target, UUID, exact command SHA-256, approved Core fingerprint and expiry. This is a trusted-Gateway signing design, not an autonomous capability granted to the machine caller. Key lifecycle, rotation, protected Windows/Container distribution, mTLS identity and negative tests require security review before activation.

## New source components

- fortis_approvals/powershell_machine.py — fixed HTTPS transport, owner-private credential validation, Core-bound ASK-only adapter and proof issuance. No machine route is active on import.
- fortis_approvals/powershell_owner_mount.py — strict owner-private fixed mount reader; absent mount means **disabled**. Expected mount path: /run/fortis-machine-powershell. It must be a non-symlink directory owned by the service UID and mode 0700; its six files must be owner/service-UID-owned non-symlink regular files, mode 0600, hard-link count one.
- Exactly six mount filenames: profile.json, server-ca.pem, client-cert.pem, client-key.pem, bearer, proof-key. The profile contains exactly version=1, enabled=true, mode=ASK_ONLY, actor (matched to the authenticated Repo actor), target (fixed windows-owner), executorGitSha (accepted **40-hex Git commit** of Windows Executor), executorIdentity (fixed source label). Legacy sourceSha256, arbitrary 64-hex digests and other executor identities are rejected. No policy/ALLOW flag, URL, port, arbitrary machine route, secret value or command is selected by AI.

### Reviewed Windows source and identity pin — still not live attestation

The accepted standalone Windows Executor Git main is pinned to
`3a455fd34c9b442e3480729b377680a895c5399c` (40 lowercase hex).
Both the runtime mount reader and ASK adapter reject any other value in
`profile.json.executorGitSha`. This is a reviewed **source constraint**,
not a SHA-256 of a Git SHA string or proof that an already-running Windows
process loaded that checkout. Changing the accepted Executor commit needs
a separately reviewed Gateway source update.

`profile.json.executorIdentity` is fixed to `windows-owner-nonadmin-v1`.
It is a trusted configuration **role label**, not an authenticated SID,
process fingerprint or evidence that the live Executor has that identity.
A different label fails closed; a matching label alone establishes nothing
about the installed Windows service. The fixed role and Git pin are bound
into the owner ASK preview; the contract digest changes to invalidate
pre-change previews.

Before first activation the owner must **independently** confirm on Windows:
clean reviewed Executor `main` at this exact SHA, the actual running
non-admin Windows user/process identity, only the single approved listener
on 127.0.0.1:10443, the current original SQLite receipt DB and the
accepted Script Center source/launcher configuration. Verify TLS client
identity and negative machine proof cases after guarded rollout. Neither
this source assertion nor a successful TLS handshake is a live process
attestation. Do not put a Windows SID, credential, certificate private key
or receipt in a PR, Repo files, logs or chat.
- NativeIngress typed machine endpoints: POST /v1/powershell/submit, /v1/powershell/result, /v1/powershell/capabilities. The last two cannot execute. Malformed input, other actor, unknown target or missing adapter fail closed.
- workflow/powershell_client.py — Repo-side typed facade. No Windows credentials, direct HTTP, owner-cookies, automatic retry or fallback to owner-local API.
- runtime composition is deliberately **opt-in**. Owner mount + native registered Gateway actor/target are prerequisites; no change to the existing owner-only browser PowerShell API.

## Gateway owner-managed first mount (source-only controller proposal)

For an accepted Gateway owner-controller containing this change, first
activation uses one already owner-provisioned Docker named volume
`fortis-r7-machine-powershell`, mounted read-only at the **fixed**
`/run/fortis-machine-powershell`. The six files must pass the existing
runtime validation (UID 10001, directory 0700, each file 0600/no symlinks,
exact actor, ASK_ONLY, accepted Executor source, valid dedicated TLS,
bearer and 32+-byte proof key). The owner provisions credentials only
through private host channels; this source does **not** generate them.

The controller's explicit `-EnableMachinePowerShell` is accepted **only**
for the manual exact-SHA, quiescence-attested immutable-image
`Check -Build` and bound `Apply -Image ... -CheckedImageRecord ...`
flow. First opt-in is forbidden with `-Auto`. A network-disabled,
read-only UID-10001 image preflight validates all six files and stores
only their domain-separated SHA256 digest and the fixed volume identity
in the protected Check/Complete records. All later releases re-attest
the **same** volume digest before stop and in container admission.
Unknown host paths, mismatched volume identities, altered material,
missing private files, wrong actor or unexpected mounts fail closed.
The controller never creates a volume, prints secrets or runs Windows.

This is an implementation of the special owner-opt-in boundary, **not**
a new release procedure: use [UC-GW-005](use-cases/releases.md#uc-gw-005)
and [Primary runbook](PRIMARY-GATEWAY-OPERATIONS.md), with
[UC-GW-006](use-cases/recovery.md#uc-gw-006) for uncertain Apply and
[UC-GW-004](use-cases/credential-lifecycle.md#uc-gw-004) for secrets.
Do not perform owner provisioning or live Apply solely because this
source PR merges. Confirm the existing Windows single-listener opt-in,
same receipt DB and negative tests in a separate owner-controlled window.

## Conditions before owner release

1. Owner reviews/merges the contract PR #119 and both Executor and Gateway implementation PRs after exact-head Source CI/Release Impact; source merge alone is not live deployment.
2. Independently review symmetric proof key and dedicated machine bearer handling; generate/copy secrets only via owner-private channels. No secret, generated key, cert or machine grant belongs in Git, PR, ChatGPT output or Repo project files.
3. Windows: update clean approved standalone source, verify current historical receipt DB/TLS remain intact and no unresolved effect. Install protected new machine proof/bearer files under %LOCALAPPDATA%\Fortis\OwnerShell, ensure NTFS ACL restrictive. Update the one registered Script Center process start, not a second listener.
4. Gateway: owner-provision protected fixed mount and deploy image with explicit ASK-only composition. Confirm original Repo machine actor and Windows instance/target binding. No credential sharing with Repo AI tools.
5. Live acceptance: denied request, missing proof, wrong identity/host/bearer, modified command, reject, expired/replay, lost ACK/UNCERTAIN/restart; fresh Get-Date from Repo produces PENDING → WebAuthn → exactly one Windows execution → bound receipt; prior owner-only UUID remains visible only through owner API.
6. Rollback uses the **same CURRENT receipt DB** with preserved historical and machine UUIDs. Never restore an older DB, retry uncertain effects or run two listeners on 10443.

**V2+ only:** owner-editable command restrictions and optional ASK/ALLOW for narrowly reviewable actions. V1's default for every execution is ASK, including diagnostics.
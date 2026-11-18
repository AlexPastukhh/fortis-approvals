# Fortis Repo → Gateway → Windows PowerShell — ASK-only V1 contract

**Status:** PS-AI-V1-02 CONTRACT UPDATE CANDIDATE (2026-11-17).
**Implementation evidence:** Gateway and Windows source integrations exist in
accepted repositories, but the *installed Gateway* still returns HTTP 404 for
`POST /v1/powershell/capabilities`. Source inclusion is not live enablement.
**Decision of owner:** for the first machine version, **every admitted PowerShell
command from the AI requires an individual owner ASK**. No editable allow/deny
command rules, AST policy, or configurable bypass of ASK in V1. Those are
separate later V2 tasks. This source change does **not** activate a machine
API, grant credentials, launch Windows, alter TLS/config or migrate receipt DB.

Canonical requirements: [unified PowerShell plan](BACKLOG-IMPROVEMENTS.md#powershell-plan).
Owners: `fortis-approvals` for Core/Gateway/WebAuthn and Repo client;
`fortis-powershell-executor` for Windows machine dispatch/proof verification.
The existing owner-only PowerShell browser flow stays operational and separate.

## 1. Baseline already reported

- The owner previously confirmed standalone Windows Executor source at
  `3a455fd34c9b442e3480729b377680a895c5399c`. The Windows
  Script Center source-only update is confirmed clean at accepted main
  `750d2fc0d7411d2072c41cf68fb12b5e9d87e935`.
  Neither observation proves the running Python process changed versions.
- Owner reported running process tree `powershell.exe → py.exe → python.exe`,
  a visible `OWNER_SHELL_MTLS_READY` owner-only banner and a successful
  `Test-NetConnection 127.0.0.1:10443` TCP handshake. Windows listener
  enumeration via `netstat`/`Get-NetTCPConnection` was inconsistent; a
  successful handshake does not independently establish mTLS/API acceptance
  or the listener PID. Do not restart or start a second listener as a test.
- The protected owner-only Script Center config exists; the separate
  `machine-script-center.json` opt-in does not exist. Historical read-only
  receipt evidence was 1 EXECUTED and 0 DISPATCHED/UNCERTAIN; that inventory
  has **not been freshly re-verified**. The existing TLS paths, current
  SQLite receipt DB and owner-only process must remain unchanged until an
  independently reviewed, owner-controlled cutover.

This is **owner-only baseline evidence**, not machine execution acceptance.

## 2. Minimal V1 behaviour

1. A machine actor with a real TLS machine identity and explicitly granted
   fixed Windows target submits the **full exact** PowerShell command. A new
   Core request is **PENDING/ASK**, never ALLOW or immediate dispatch, even for
   `Get-Date`. Unknown actor, target or malformed/empty/NUL/over-8192-byte
   input is DENY. The V1 *does not attempt* to classify dangerous scripts.
2. The owner sees the full command with its SHA-256, exact UUID, authenticated
   actor, Windows target, interpreter/version, non-admin execution identity,
   working directory, output/timeout limits and explicit warning: **arbitrary
   PowerShell with this Windows user's rights, no sandbox or security verdict**.
   If preview is truncated or cannot be shown completely, fail closed.
3. The existing Owner Portal/WebAuthn owner decision must bind the exact
   Core fingerprint (actor + UUID + immutable command + target +
   interpreter/instance + version of this fixed ASK-only contract).
   Reject/no decision/expired/revoked/stale fingerprint = **no Windows effect**.
4. Only after that Core approval may Gateway issue a non-forgeable,
   short-lived, one-shot **machine dispatch proof** for this particular
   command and target. Windows verifies it before durable reserve and before
   spawning PowerShell. mTLS, a bearer and UUID are **not** a substitute.
5. No AI-selected URL, port, bearer, cert/key, script file/args, arbitrary
   process identity, DB path, working directory, owner status, proof or
   authorization mode. All come from installed trusted Gateway/Windows source.
6. No generic effect retry, new UUID workaround or force-reconcile on
   timeout/lost ACK/UNCERTAIN. Query the **original** UUID/readback. Preserve
   one Windows runner, same existing TLS/config and SAME CURRENT SQLite DB.
7. Existing `POST /owner-shell/v1/execute` remains strictly owner-only;
   NEVER expose it directly as a machine proxy. New authenticated Windows
   route is separately versioned and denies missing/invalid Core proof.
8. Scoped `status`, `result` and `capabilities` **READ** may be allowed
   without ASK only if they cannot execute, mutate or retry a command.

This V1 permits **arbitrary** PowerShell text after each explicit owner ASK,
subject only to the existing interpreter and transport ceilings. ASK is not
automatic risk assessment; the owner is deciding whether to run the exact
script under an ordinary Windows account.

## Accepted Executor source pin and owner-runtime verification

The ASK preview uses **`executorGitSha`** for the reviewed 40-character
Windows Executor Git commit `3a455fd34c9b442e3480729b377680a895c5399c`,
not the earlier ambiguous 64-character `sourceSha256`. The runtime adapter
and private mount reject other SHA values; the offline preview validates the
same pin. The accepted fixed `executorIdentity` is
`windows-owner-nonadmin-v1`. This is an owner-reviewable **role label**,
not a unique Windows user, process PID/SID or live-runtime authentication.
The changed contract digest invalidates any earlier ASK preview.

The source checks cannot prove which Python code the running Windows
listener loaded. Before a first protected Gateway release, the owner must
verify the installed Windows Executor checkout/source, non-admin identity,
single listener, original current receipt DB and Script Center launch path
separately, and conduct the cryptographic mTLS/proof/Reject/replay negative
tests. A correct profile and handshake never substitute for that
host-side evidence. Source upgrades require re-review of the Git pin; no
arbitrary 64-character string, placeholder identity or automatic enabling
is a valid workaround.

## 3. Closed typed request schema — offline helper and accepted source

| Logical operation | Body | Semantics |
| --- | --- | --- |
| `powershell.submit.v1` | exactly `{requestId,target,command}` | Valid syntax + trusted machine grant → Core PENDING/ASK |
| `powershell.status.v1` | exact existing UUID | Scoped Core read, no dispatch |
| `powershell.result.v1` | exact existing UUID | Scoped original-UUID receipt read, no retry |

The offline `scripts/powershell_machine_contract.py` enforces body shape,
canonical UUID4/7, fixed target registry, UTF-8 limit and NUL rejection.
It constructs a proposed immutable preview. **The offline helper does not
authenticate the caller, grant ASK, sign a dispatch proof or execute a
command.** The separate accepted Gateway source already defines typed
`POST /v1/powershell/{submit,result,capabilities}` endpoints in
`fortis_approvals/workflow/ingress.py` and the Windows source separately
defines `/machine-shell/v1/execute` and result readback. Those source
routes are not present in the currently deployed Gateway (404 on the
capabilities route).

The trusted preview binds `contractVersion` and `contractDigest` for the
**fixed ASK-only V1 contract**, NOT an owner-editable command policy. It also
binds actor, UUID, target, exact command/hash, Windows source/identity,
interpreter profile, working directory and limits. Altering any of those after
review must invalidate the Core request. No GUI to edit these fields in V1.

## 4. Implemented source proof and remaining release review

The accepted V1 source chooses **HMAC-SHA256**, not an asymmetric
signature. The dedicated owner-provisioned **shared secret must exist in
protected copies on BOTH Gateway and Windows Executor** to issue and
verify the MAC. It must never be available to Repo AI, a public repository,
logs or the owner-only bearer. Loss of secrecy on either endpoint
compromises the ability to authenticate machine dispatch proofs; confirm
credential custody, file ACLs, rotation and failure modes before release.

The Gateway's `MachinePowerShellAdapter._approved_row` re-reads the
existing trusted Core record and requires `DISPATCHED`, an actual
`approve` decision, an owner identity, the exact stored request,
unchanged ASK-only preview and the matching actor/policy **before**
`issue_proof` can sign it. The MAC covers the fixed audience, actor,
target, original UUID, Core fingerprint, exact command SHA-256,
issue/expiry times and nonce. The Core fingerprint indirectly binds
the reviewed preview's contract digest, identity and limits; these
are **not all separate fields in the HMAC claims**. Windows validates
the proof and reserves the original UUID in the same SQLite DB before
the command effect, with additive machine binding records.

This is **accepted source, not verified live installation**. Before
activating a Windows machine route, independently verify the Core
fingerprint-to-preview binding, actual WebAuthn approval path,
dual-endpoint secret protection, proof replay/expiry handling,
same-DB durability, wrong-instance denial, negative tests and
lost-ACK/UNCERTAIN behavior. Never accept `approved=true`, a generic
Bearer+UUID, an AI-supplied proof or the legacy owner-only route as
an equivalent authorization.

## 5. Shared DB, replay and failure handling

The single installed Windows `shell_receipts` SQLite database, TLS, protected
config and owner launcher stay in place. Historical UUID receipts must remain readable. The accepted Windows
source implements an additive `shell_machine_bindings` side table in the
**SAME CURRENT DB**, not a replacement or parallel DB. It requires an
owner-controlled pre-release check against the installed historical
database before activation. Before effects: reserve the original UUID
durably. Different command/target/proof under the same UUID conflicts.
Concurrent dispatch, restart or lost acknowledgement never cause double
execution. UNCERTAIN/DISPATCHED blocks further effects until reviewed
recovery. Nonzero exit may still have had side effects. No rollback to an
older DB snapshot that forgets UUIDs. Never log secrets or unbounded command
text/outputs to public CI or GitHub.

## 6. Offline and live acceptance

| Check | Expected V1 result |
| --- | --- |
| No machine grant, wrong actor/target, extra params | DENY, no Core dispatch |
| Any syntactically admitted command (including potentially dangerous) | PENDING/ASK, no effect until actual owner WebAuthn |
| Owner Reject, expiry, revocation, modified command/target/identity | No effect; STALE/REJECTED |
| Forged/expired/replayed/missing/wrong-audience proof | Windows DENY even with mTLS/bearer |
| Same UUID/different script, concurrent requests, timeout, ACK loss | Conflict/UNKNOWN, no duplicate effect |
| Original owner-only Portal, historical receipt/restart | Existing functionality and exact DB preserved |
| Live Get-Date from Repo | ASK → owner WebAuthn → exactly one Windows execution → bound result |
| Strict ASK-only policy | No shortcut or ALLOW for execution; reads may be non-ASK |

The standalone Windows Executor, Gateway source adapter and opt-in Script
Center changes were accepted separately. This contract PR still requires
fresh exact-head source CI and an owner merge. A separate guarded Gateway
image deployment, protected mount and controlled single-listener Windows
opt-in remain **unperformed**. Live negative/rollback tests remain open.

## 7. Later phases (NOT V1)

**V2:** owner settings for command/argument restrictions, versions and
audit; deterministic reviewed PowerShell AST evaluator and limits; default
DENY for unknown forms once restrictions are enabled. After a separate security
review, owners may optionally configure which *narrowly constrained* requests
can be ALLOW instead of ASK. Safe defaults remain ASK; unbounded arbitrary
PowerShell cannot silently become ALLOW. Owner UI, policy writes, stale-rule
handling, restrictions and ALLOW/ASK routing are future work, not hidden V1
prerequisites.

This contract-only PR does not itself enable, deploy or invoke any machine route.

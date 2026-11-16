# Fortis Repo → Gateway → Windows PowerShell — ASK-only V1 contract

**Status:** PS-AI-V1-02 SOURCE REVIEW CANDIDATE (2026-11-17).
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

- Standalone Windows Executor clone at `6bdda41cbc8a3edc79818a8b3c716cdefc7797ed`
  and Script Center at `a40ac4b031b44915f7aea4f09cf131d37fb6d429`,
  clean and synced to locally fetched origin/main.
- Old Mirror process tree stopped; new standalone py/python tree reported on
  `127.0.0.1:10443`. Preflight and mTLS-ready banner appeared and loopback
  TCP handshake succeeded. Windows listener enumeration via netstat/.NET
  was inconsistent, so the listener's PID still needs independent verification.
- Same server TLS material, protected Script Center config and CURRENT Windows
  receipt DB. Read-only DB counts: 1 EXECUTED, 0 DISPATCHED/UNCERTAIN.
  Owner Portal read back historical state EXECUTED. New exitCode/digest comparison,
  negative tests, controlled restart and full rollback acceptance remain open.

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

## 3. Closed typed request schema — offline proposal

| Logical operation | Body | Semantics |
| --- | --- | --- |
| `powershell.submit.v1` | exactly `{requestId,target,command}` | Valid syntax + trusted machine grant → Core PENDING/ASK |
| `powershell.status.v1` | exact existing UUID | Scoped Core read, no dispatch |
| `powershell.result.v1` | exact existing UUID | Scoped original-UUID receipt read, no retry |

HTTP paths, Windows machine route and transport are **not** implemented yet.
The offline `scripts/powershell_machine_contract.py` enforces body shape,
canonical UUID4/7, fixed target registry, UTF-8 limit and NUL rejection.
It constructs the immutable preview. **It does not grant ASK, parse policy,
authenticate the caller, sign a dispatch proof or execute a command.**

The trusted preview binds `contractVersion` and `contractDigest` for the
**fixed ASK-only V1 contract**, NOT an owner-editable command policy. It also
binds actor, UUID, target, exact command/hash, Windows source/identity,
interpreter profile, working directory and limits. Altering any of those after
review must invalidate the Core request. No GUI to edit these fields in V1.

## 4. Required separate Windows dispatch proof review

Candidate only: use a dedicated signed, short-lived machine capability
issued by Gateway *after* Core confirms WebAuthn-approved ASK (never from
the AI payload). Bind audience, issuer/key ID, target/Windows instance,
actor, requestId/Core fingerprint, command SHA-256, immutable ASK-only
contract version/digest, identity, limits, expiry and replay ID.
Do not send the signing key to Repo or Windows. Windows validates signature,
time/audience/target/full command/proof ID and a durable once-only reservation.

Current `Core.execute` calls `adapter.apply(payload)` after writing
DISPATCHED. This payload alone contains no owner approval evidence.
**STOP:** the implementation must add a reviewed Core-owned dispatch context
(fingerprint + frozen preview + actual approval decision) or equivalent,
unforgeable on the machine route. Never accept `approved=true`, generic
Bearer+UUID, an AI-supplied signature, or the existing owner transport as proof.
Choose exact protocol, key custody/rotation and replay storage before activation.

## 5. Shared DB, replay and failure handling

The single installed Windows `shell_receipts` SQLite database, TLS, protected
config and owner launcher stay in place. Historical UUID receipts remain
readable. A new machine route needs a reviewed **additive transactionally bound**
actor/target/contract/proof record (possibly side table in the SAME DB), not
a replacement or parallel DB. Before effects: reserve the original UUID
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

Full source CI, exact-head PR/owner merge, Windows changes and Gateway release
require **separate** later gates. Owner-side managed release and negative tests
are not part of this contract artifact.

## 7. Later phases (NOT V1)

**V2:** owner settings for command/argument restrictions, versions and
audit; deterministic reviewed PowerShell AST evaluator and limits; default
DENY for unknown forms once restrictions are enabled. After a separate security
review, owners may optionally configure which *narrowly constrained* requests
can be ALLOW instead of ASK. Safe defaults remain ASK; unbounded arbitrary
PowerShell cannot silently become ALLOW. Owner UI, policy writes, stale-rule
handling, restrictions and ALLOW/ASK routing are future work, not hidden V1
prerequisites.

No executable machine route or source publication is included at this stage.

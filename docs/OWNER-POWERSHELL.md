# Owner Portal PowerShell — optional owner-local command execution

**Status (2026-11-10): owner-reported live V1 opt-in and first `Get-Date` execution,
with additional security/recovery acceptance pending.** The installed Gateway
was activated via guarded `Check/Apply/Backup/Promote`, not a manual Docker
configuration; exact image, protected release evidence and remaining acceptance
are recorded in [current state](guides/FORTIS-APPROVALS-SECURE-DEVELOPMENT.md),
[dated owner evidence](../fortis_approvals/evidence/OWNER-SHELL-RELEASE-AND-GET-DATE-20261110.md)
and the [single backlog](BACKLOG-IMPROVEMENTS.md). The optional PowerShell tab
belongs to the existing Owner Portal; Pending/History and machine API remain
separate. **Do not infer full security acceptance from one successful command.**

## Отдельный Owner Portal и действующий machine ASK

Описанный далее `/v1/owner/powershell/*` — **owner-local baseline**, не
машинный API. Windows machine route уже активирован в **ASK-only V1**:
проверенные Get-Date/Reject E2E датированы 2026-11-18, дополнительные
security/restart negatives остаются открытыми. Старый вывод HTTP 404
относился к состоянию **2026-11-17**, до активации, а не к текущему Gateway.
Технический baseline — [Machine ASK V1](POWERSHELL-MACHINE-ASK-CONTRACT-V1.md).

Актуальная цель — [Gateway backlog: внешний метод + Dynamic ASK](BACKLOG-IMPROVEMENTS.md#powershell-plan).
Внешний owner dashboard определяет DENY/ASK/ALLOW по методу; только
Executor дополнительно решает DENY/ASK/ALLOW для **точной команды**. Это
не включено в текущий V1 и не меняет owner-local маршрут. Windows правила,
настройки и security tests описаны только в
[Executor backlog](https://github.com/AlexPastukhh/fortis-powershell-executor/blob/main/docs/BACKLOG-IMPROVEMENTS.md#executor-dynamic-ask).

## Interaction

After WebAuthn sign-in, select **PowerShell**, paste up to 8 KiB of PowerShell
text, then click **Выполнить команду**. This is one noninteractive Windows
PowerShell 5.1 invocation, not a persistent PTY or interactive REPL. Exit code,
bounded stdout/stderr, SHA256 and a request UUID are displayed in the tab.
The **Анализировать** and **Мнение ИИ** controls are disabled placeholders;
**no Analyzer nor second model reviews the script currently**. In particular,
PowerShell execution in this version has **no automatic security verdict**.

## Trust boundaries

The optional `OwnerShellPortal` wrapper intercepts PowerShell routes while the
release-pinned `owner_portal.py` and `runtime.py` remain byte-identical to
storage/WebAuthn baseline. The Owner Portal accepts
`POST /v1/owner/powershell/execute` only from an
existing WebAuthn owner session, with matching Host, exact Origin and CSRF.
Schema is exactly `{command,requestId}`. The browser cannot choose the Windows
host, network endpoint, credentials, PowerShell arguments or process identity.
The machine/AI Gateway ingress does not expose this operation.

The Gateway server calls a **separate** Windows executor over **mutual TLS**
with a dedicated, protected bearer token. The Windows executable belongs to
`docke-windows-mirror/mirror_api/owner_shell.py` and is started only by an
explicit reviewed `Start-OwnerPowerShellExecutor.ps1`. No existing Browser
Mirror launch activates it. Windows will reject requests without the client
certificate and bearer. A request UUID is stored durably before execution;
a repeat does not execute again. Unknown or timed-out results remain blocked
until the operator investigates. There is **no automatic retry**.

**Important:** the command is arbitrary PowerShell under the account running
the Windows executor. There is no sandbox or risk analysis. It can read files,
contact the network and create subprocesses. A dedicated
least-privilege Windows identity with minimal file/network access is the
recommended isolation target, **not** an accomplished V1 prerequisite. Compromise of the
Portal's client key **and** bearer can allow arbitrary commands on Windows.
Browser extensions that have access to this page may see commands and output.
For V1, the owner chose the existing Windows user **without elevation**;
this permits access to that user's ordinary files, applications and network
credentials. The owner **deferred** offline issuer CA backup/isolation and
removal of Windows-staged Gateway client credentials. These protections must
not be marked complete. Windows server key and bearer are readable by the
Executor identity by design; this does not isolate them from a compromised
same-user process. Until hardening, do not run untrusted or unrelated scripts,
and never paste secrets, admin scripts or recovery materials. The remaining
work is tracked only in the [backlog](BACKLOG-IMPROVEMENTS.md).

## Explicit opt-in release configuration

The optional runtime configuration is enabled only through the reviewed
owner-managed release controller, with private mTLS material and a verified
Windows bind/identity. No caller-supplied URL, credential file or manual
`docker -e` is permitted. The trusted release configuration uses
`FORTIS_OWNER_SHELL_CONFIG`. This env var contains JSON with exactly:

```json
{
  "port": 10443,
  "serverCA": "/trusted/path/to/windows-ca.pem",
  "clientCert": "/trusted/path/to/portal-client.pem",
  "clientKey": "/trusted/path/to/portal-client.key",
  "secretFile": "/trusted/path/to/owner-shell-secret"
}
```

These are **example path shapes**, not live files or credentials. All paths
must refer to private files outside Git; the secret must be 32–256 printable
ASCII characters and be accessible only to the Gateway service identity
(no group/world permissions on the client key or secret). The Windows server cert must
verify for `host.docker.internal`. The fixed Gateway destination is
`https://host.docker.internal:<port>` with no proxies/redirects/insecure
verification. The certificate and key must be independently reviewed.

If the variable is absent, the portal tab is visible but execution is
**disabled** and the owner sees `Windows Executor пока не подключён`.
The Analyzer/second-AI buttons remain disabled regardless of configuration.

## Trusted release opt-in (accepted mechanism)

The `Manage-Integrations.ps1` owner controller accepts `-EnableOwnerShell`
**only together with** `-Action Check` or `-Action Apply`, `-Build` and an
explicit approved exact `-SourceSha`. It does **not** accept caller-supplied
arbitrary Windows URL, port or credential paths. The sole trusted configuration
is `port=10443` and the four paths under the existing read-only
`/run/fortis-secrets/owner-shell/` mount (`server-ca.pem`, `client.pem`,
`client.key`, `secret.txt`). The five-key JSON is pinned to the protected
release record's `ownerShell` boolean. Missing or mismatched configuration
is rejected by the full container admission helper; future approved releases
retain an already-enabled `ownerShell` flag unless separate reviewed disable
semantics are implemented.

Before any release stop, the controller checks the private directory and
files under UID 10001 using an isolated read-only/no-network image helper,
including mode/ownership, certificate parsing and bearer format. A staged
container verifies an authenticated read-only `GET /owner-shell/v1/capabilities`
from Windows before owner activation, never running commands. A failed probe
must not silently enable the release. No manual Docker environment editing
is permitted. Real Check/Apply/Backup/Promote must still satisfy UC-GW-005
and exact preserved native `UNCERTAIN` and `CLAIMED` worker scopes.

The current owner deviation on CA/staging hygiene is recorded above and in the
single backlog; it does **not** establish Windows user isolation. The public tab
offers no Analyzer verdict and is not a sandbox.

## Acceptance

For full security acceptance verify denied unauthenticated owner API POST,
incorrect Origin/CSRF, same-UUID replay, mismatched command/UUID, timeout,
connection loss, and durable receipts after a controlled Executor restart.
Owner already completed one successful `Get-Date` execution, while prior
mTLS/Bearer negative preflights and the newer browser result are separate
pieces of evidence. These remaining tests need a safe owner-controlled
procedure; **do not replay the original effect to test an unknown outcome**.
A passing source CI is not host/WebAuthn acceptance. See the dated evidence
and the open PS-V1-10 backlog gates.

Future Analyzer should be reusable across commands and other Owner Portal
requests, but is deliberately out of scope. Sending arbitrary PowerShell to
Analyzer/AI does not automatically constitute permission to execute.

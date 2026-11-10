# Owner Portal PowerShell — optional owner-local command execution

**Status: source-only, not installed or connected to Windows.** This adds a
PowerShell tab to the existing Owner Portal (`http://localhost:19203` in the
accepted environment). Existing Pending/History and machine API remain separate.

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
contact the network and create subprocesses. The owner must use a dedicated
non-admin Windows account with minimal files/network access. Compromise of the
Portal's client key **and** bearer can allow arbitrary commands on Windows.
Browser extensions that have access to this page may see commands and output.
For V1, the owner has chosen to run the Executor as the existing Windows user
**without elevation**; a separate low-privilege user is a later hardening option,
not a code prerequisite. This permits access to that user's ordinary files,
applications and network credentials. Before activation, keep private CA keys
offline and remove staged Gateway client credentials from this user's accessible
profile after verified transfer into Docker. Windows server key and bearer remain
readable by the Executor identity by design; this is not isolation from a
compromised same-user process. Do not paste secrets, admin scripts, recovery
material or credentials.

## Explicit opt-in release configuration

The production image is **not** modified by this PR. The accepted release
operator must independently provision private configuration and mutual TLS
certificates for the Windows executor, review Windows bind/firewall/identity
and explicitly configure `FORTIS_OWNER_SHELL_CONFIG` in trusted Gateway
composition. This env var contains JSON with exactly:

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

## Acceptance

Before any live execution, on a disposable non-admin Windows identity: verify
failed no-client-cert/mismatched-CA/bearer attempts, denied unauthenticated
owner browser POST, CSRF, replay with same/mismatched UUID, timeout and loss
of connection, and output. Use `Get-Date` as a controlled first command.
A passing GitHub source CI is not Windows host or TLS acceptance.

Future Analyzer should be reusable across commands and other Owner Portal
requests, but is deliberately out of scope. Sending arbitrary PowerShell to
Analyzer/AI does not automatically constitute permission to execute.

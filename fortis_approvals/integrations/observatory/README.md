# Observatory API provider for Fortis Approvals

Status: **SOURCE CANDIDATE — not installed, not activated, no credential provisioned**.

Owner: `fortis-approvals`, extension framework `fortis_approvals/extensions/`.
Use cases: [UC-GW-002](../../../docs/use-cases/integrations.md#uc-gw-002),
[UC-GW-004](../../../docs/use-cases/credential-lifecycle.md#uc-gw-004),
[UC-GW-005](../../../docs/use-cases/releases.md#uc-gw-005).
The consumer uses the existing
`fortis_approvals.extensions.client.default_client()`: no new machine
auth, approval queue or client protocol.

## First source version

Two **read-only** operations are available to trusted policy configuration:

| Service / operation | Target | Params | Result |
|---|---|---|---|
| `observatory.health` | `service` | `{}` | Exactly `ok`, `service`, `mode` |
| `observatory.list_sessions` | `registry` | `{}` | `ok`; authorized session identifiers only |

Response projection excludes titles, messages, raw event bodies, debug fields and
unknown keys. All other operation names fail closed.

Proposed **public** config (not active; exact operation/target actor scope is
owner-reviewed before installation):

```json
{
  "schemaVersion": 1,
  "providers": {
    "observatory": {
      "credentials": { "api": "observatory-api" },
      "operations": {
        "health": { "policy": "ALLOW", "targets": ["service"] },
        "list_sessions": { "policy": "ALLOW", "targets": ["registry"] }
      }
    }
  }
}
```

Credential value is **not** a field of this config. The owner first registers
a dedicated `fortis-approvals` API client in the Observatory Gateway with
read-only access and a new service credential. Then the owner provisions its
secret into Fortis Approvals' existing named credential volume using
`Manage-Integrations.ps1 -Action Credential -CredentialName observatory-api`
(after verifying current Primary, pending requests and admission records).
Never reuse the Windows owner key, Repo's shared-workspace token or GitHub
tokens. The key must never be written to Docker Repos/Workfiles, Git, chat or
an AI-accessible process command line.

## Non-standard transport and deployment gate

The installed Observatory V1 API has historically listened on
`host.docker.internal:18756` over plain HTTP, with a Host allowlist that
requires `Host: fortis-observatory-api:18756`. The shared extensions
`JSONAPI` **rejects** HTTP and non-443 origins. This provider uses a
**fixed, narrow** transport in `transport.py`, with no custom caller origin,
method, Host, headers, redirects, proxy, cookie or raw upstream errors. It does
not weaken the shared HTTPS transport or open an arbitrary URL relay.

**This is not production transport acceptance.** A bearer on plain HTTP has
no transport-layer confidentiality; infrastructure/network access and the
trusted service path must be explicitly reviewed. The route from the
**Approvals container** to `18756` has not been established. A previous Repo
check on 2026-11-10 returned `ConnectionRefused`; an old successful Repo
check does not establish Approvals connectivity. Prefer reviewed
TLS/private-bridge transport before enabling credentialed production traffic.
Keep the provider config absent until the service credential, network
and runtime protections are accepted.

This version intentionally does **not** enable event/message writes. Stage
receipt format, idempotency/reconciliation behavior, supported chat scope
(including future chats), and actual current Observatory API source must be
confirmed before implementing `ASK` write operations. `staged_only`
means queued, not delivered or archived. No endpoint grants Notifier
or Windows Viewer/Send control.

## Tests and release

```sh
PYTHONPATH=.:fortis_approvals/tests PYTHONDONTWRITEBYTECODE=1 \
  python3 -m unittest -q fortis_approvals.integrations.observatory.tests.test_definition
```

Tests use a local mock server and fake test credential. No Observatory request
is made; no real bearer is read. Follow the Fortis main/source manifest suite,
GitHub PR/CI, owner merge and UC-GW-005 release; validate live extension catalog
and a real authorized read only after the release and owner-managed credential
admission. The source being in `main` alone will not activate this provider.

Do not clone or overwrite the existing Windows Observatory code or
`fortis-observatory-repo-v1` archive as part of this provider's release.

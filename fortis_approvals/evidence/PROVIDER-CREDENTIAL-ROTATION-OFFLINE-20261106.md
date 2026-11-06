# Existing-provider credential rotation — source evidence, 2026-11-06

## SOURCE-VERIFIED

The permanent controller accepts `Credential -Service github|sonarcloud -Rotate`.
The new owner-only stdlib helper is passed from reviewed Windows source to an
existing image over stdin/code arguments; it is not a Gateway image dependency.
No runtime/provider policy, legacy Repo credential helper or pending HTTP-202
client worktree is changed.

- Current protected review record/admission, production baseline and token-volume
  consumers determine targets. GitHub selects review; shared Sonar selects review
  and production. Unknown active consumer/writer blocks rotation.
- Core is read-only checked before/after stop; unsettled work blocks replacement.
  Expired unexecuted PENDING/APPROVED cannot execute in Core and do not block.
- A fixed owner-only authentication GET runs inside review before stop, with
  the new token on confidential stdin. False/invalid responses, redirects and
  transport errors fail before replacement; public project reads alone are not
  treated as proof of authentication. The helper has no caller-selected URL.
- Atomic replacement checks private file metadata/generation. Previous token bytes
  are not read/copied; the new value exists only in secure prompt/process memory,
  confidential stdin and the original credential volume, not argv/env/record.
- Same-container restart reloads cached tokens; closed Gateway reads verify the
  selected integration. No provider mutation is a probe. Failures retain records;
  interrupted attempts restore only matching container identities/configuration.

## Offline validation

17 deterministic tests PASS: GitHub/shared-Sonar target planning, stopped/unknown
consumers and bind aliases, wrong scopes/mounts, real atomic temp-file replacement,
stale generation, symlink/owner/mode denial, failed-write cleanup, no old-token
reads, real SQLite read-only idle checks across services, expiry/unknown states,
and redacted CLI errors. The tests use fake tokens and temporary files/databases;
they do not emulate Docker/PowerShell or claim host lifecycle acceptance.

Supported source suite: 411 PASS, exit 0. The final helper with authentication
preflight then passed all 17 focused tests. Manifests/Markdown/whitespace and
Gateway syntax are checked before commit; source CI checks the final PR head.

## MANUAL-PENDING

Windows PowerShell 5.1 parsing/execution, Docker volume/lifecycle checks, crash
recovery and actual token authorization/readback require the owner command in the
[runbook](../../docs/CREDENTIAL-ROTATION.md). No live token was read, replaced or
revoked by this source task; no live container was restarted. Readback cannot prove
upstream write permissions. Old retained state/approvals are not silently migrated.

## Documentation/use-case review

UC-CONT-009/010/011 routes were followed to scaffold/config/client/credential/
activation owners. The contract now states HTTPS/443, JSON/auth limits and a
common client example; the old manual template is explicitly historical.
The rotation entry is in the active documentation map, not historical references.
The container registry still has 18 stable cases; it links technical owners and
separates source readiness from owner/live acceptance. Root navigation clarifies
that admitted native GitHub uses Gateway; the legacy helper section is not its
publication path. These are navigation/source checks, not a new-provider live test.

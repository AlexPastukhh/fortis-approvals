# Primary Gateway cutover — owner Windows evidence and live Repo readback (2026-11-07)

## Evidence provenance

The Windows Docker commands and output in this document were supplied by the
owner in the 2026-11-07 operator session, **not** executed from the Linux Repo
connector. Repo-side TLS/GitHub/Sonar checks were executed from the actual
`fortis-repo-test` environment after the host changes. Values are retained for
reconciliation; this Markdown file is not a substitute for protected owner
release/backup records.

## Accepted source and correction

- PR #19, `task/primary-gateway-20261107`: accepted release controller,
  Primary client defaults and owner backup/promotion workflow; source CI PASS.
- PR #20, `task/primary-backup-diagnostic-20261107`: bounded, redacted Docker
  clone stderr for exit 125; source CI PASS.
- PR #21, `task/primary-backup-mount-fix-20261107`: fixes missing second
  `--mount` before the target volume and validates mount pairs; source CI PASS.
- Owner approved all three merges in Gateway. GitHub, Docker and Windows `main`
  for the host action were verified at `fab6f0101f849eb1343ad0b6365ee0bcb0034f24`;
  Windows `main` was clean before the successful Backup and Promote.
- Earlier two Backup attempts failed with `PILOT_PRIVATE_PROCESS_FAILED:125`
  before PR #21. The original failed backup volumes were **not** deleted;
  their presence does not demonstrate valid recovery copies.

## Host deployment — owner-confirmed

| Check | Evidence/result |
| --- | --- |
| `Manage-Integrations.ps1 -Action SelfTest` | `FORTIS_INTEGRATIONS_SELFTEST_PASS` |
| `-Action Backup` after PR #21 | `FORTIS_PRIMARY_BACKUP_PASS fortis-gateway-backup-e0137b2c8c7e4dc6a6e79a072d4ca74c` |
| `-Action Promote` | `FORTIS_PRIMARY_PROMOTED` |
| Protected release records | Owner-retirement preflight read `primary.json` and `primary-backup.json`, checked Complete identity/image/volume: `RETIRE_PREFLIGHT_PASS`. Original historical records retained. |
| Container ID / name | Same pre-existing `043d3497b2d1…`, renamed to `/fortis-gateway` |
| Image | `sha256:238ea3a43225eec4b714a0cf23c70559434c56a8b03f44b865ede40c70ca8242` |
| Health/restart | `running`, `healthy`, `unless-stopped` |
| Ports | `19103/tcp -> 127.0.0.1:19203`; `19104/tcp -> 127.0.0.1:19204` |
| Owner Portal/WebAuthn | Owner reported working after promotion and Docker Desktop restart |
| Docker Desktop restart | Owner reported `AUTOSTART_PASS` for `fortis-gateway` and `fortis-repo-test`, both with `restart=unless-stopped` |
| Legacy retirement | `RETIRE_PREFLIGHT_PASS`, `LEGACY_RETIRED_PASS`, `PRIMARY_STILL_HEALTHY_PASS` |
| Retained Legacy ID/name | `0852c39c9e5d…` / `fortis-approvals-gateway`; `exited`, `restart=no` |
| Retained Legacy image | `sha256:e751f6ca0cfe6ce290cf580de2f243071ee1f3e681baa8827c6cea41a16fa402` |

**Owner state paths** (Windows, access-controlled):
`%LOCALAPPDATA%\Fortis\GatewayReleases\primary.json` and
`primary-backup.json`, each referring to a protected record. Retain the
original `current.json`, the immutable release record and all token/state
volumes. The named backup is a **same-Docker-host** copy, not an off-host
recovery guarantee. No volumes, images or containers were deleted as part of
retirement; Legacy's original Compose file is not a live launcher.

## Live Repo verification after Legacy stopped

A fresh Repo probe used the normal machine-authenticated TLS client endpoint
`https://host.docker.internal:19204` (not the Legacy 19104 endpoint):

- Sonar `sonar.get_quality_gate` — **OK**, coverage `CURRENT_DEFAULT_BRANCH`;
  Sonar `sonar.list_issues` — PASS. This does not bind analysis to an exact PR/SHA.
- GitHub `get_repository`, `list_branches`, `list_pull_requests`,
  `list_workflow_runs` — PASS via Gateway.
- Native `/v1/workspace/capabilities` — PASS, 10 advertised operations.
- Gateway status of approved PR #21 request
  `32c07244-eb86-45d5-ab8c-eeb3a0f6e6bf` — `EXECUTED`.
- TLS public certificate exists; the limited machine-grant file is present
  with mode `0600` and matches the Repo client UID. No grant or token contents
  were read into documentation.

**Not demonstrated in this post-cutover probe:** a fresh end-to-end matrix of
all policy cases (`ALLOW/ASK/DENY`) or a post-retirement WebAuthn decision on a
new ASK request. Historic approved request readback and owner login do not
prove those additional cases. Third-party clients' use of Legacy 19104 has not
been exhaustively inventoried; only the Fortis Repo default was verified.

## Preservation and recovery boundary

- Current normal route is `fortis-gateway` / `19203` Owner / `19204` TLS
  machine API; `fortis-repo-test` is a separate native worker with
  `restart=unless-stopped`. Never silently fall back to Legacy 19104.
- Retain `fortis-gateway-backup-e0137b2c8c7e4dc6a6e79a072d4ca74c`,
  the protected hash-bound records, the old Legacy container/image/state and
  historical M3/bootstrap artifacts. Do **not** use the two failed backup
  volumes as verified restore points or delete them without a separate review.
- On a Primary failure, first preserve the failed runtime and reconcile the
  protected release records, container ID, image, mounts, writer exclusivity
  and receipt; use the reviewed owner restore/return contract. Never overwrite
  a live state volume, invent a new release pointer or start two writers for
  the same state. Restarting Legacy by itself is **not** a full GitHub/native
  rollback and must be a separately authorized, identity-checked decision.
- A merged GitHub PR and already-executed owner/provider effects are not
  reverted by restoring a volume. Reconcile request IDs and external effects
  before any replay; preserve the WebAuthn/owner credential material.

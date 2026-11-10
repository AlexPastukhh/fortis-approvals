# Owner Shell V1 — owner-reported release and first Windows execution (2026-11-10)

**Evidence type:** OWNER-REPORTED Windows PowerShell 5.1 output and Owner Portal result provided by the owner in chat, with separate **LIVE-VERIFIED** authenticated Repo machine readback where indicated. This is a dated acceptance record, not an instruction to rerun release commands or a replacement for protected Windows release records.

## Production release PS-V1-09

- Accepted source: PR #53 / `9481699faaa297d8ec1fb45b4f14be50ae17406f`. Owner ran `Manage-Integrations.ps1 -Action Check -Build -EnableOwnerShell` with exact source and preserved scopes: `RELEASE_INCIDENT_SCOPE=PASS`, `PUBLIC_CONFIG_UNCHANGED=PASS`, `status=READY`, `PS_V1_09_CHECK_BUILD_COMPLETE`. At the time the provider catalog was empty (`operations: []`), so this does not establish a new external provider.
- Owner attested workers quiescent before `Apply`. The guarded `-Action Apply -Build -EnableOwnerShell` reached `FORTIS_INTEGRATIONS_STEP_VERIFY_STAGED_OWNER_SHELL_MTLS`, `FORTIS_INTEGRATIONS_STEP_ACTIVATE` and `FORTIS_INTEGRATIONS_ACTIVATED`, followed by `PS_V1_09_APPLY_COMMAND_COMPLETED`.
- Protected Complete record: `%LOCALAPPDATA%\Fortis\GatewayReleases\fa449e3ee689466a818c1e730dc3787f\record.json`; image ID `sha256:03b258618e515988aaee17362889329c9b26d128012f13e62b733b99a3d5a273`; public configuration digest `d11136fe8de06d944bfe243c7eb7fe81d3d96fdda96cc901b27eb9ed426f5155`. Controller reported `active=true`, `previousRetained=true`, `productionUnchanged=true` and `providerMutationAcceptance=PENDING_OR_NOT_APPLICABLE` (not an external provider write acceptance).
- Owner Backup returned `FORTIS_PRIMARY_BACKUP_PASS fortis-gateway-backup-4920ada96279425e8d45b4a9eed15d0a` and `PS_V1_09_BACKUP_READBACK=PASS`; owner Promote returned `FORTIS_PRIMARY_PROMOTED` and `PS_V1_09_PROMOTE_READBACK=PASS`. The readback guarded identity, health, name and `unless-stopped` restart policy. These outputs establish successful owner-managed release; they do **not** replace a fresh Windows Docker inspect after later changes or prove reboot recovery.
- Protected incident scope for this release: `UNCERTAIN` UUIDs `cf5f963d-d550-4149-8ca0-1f6cd7622276`, `f7e7b116-9666-4a35-b871-9d54682d2b30`, `ef7c2a2d-d8bb-57c1-a1aa-f111e0610b57`; existing `CLAIMED` worker `2df32a24-efb1-4dac-97f6-3b66147d8944`, whose Core request is `CLOSED_UNCONFIRMED`. **No replay, reset, manual SQLite change or invented receipt.** Future release must derive the current exact scope from protected records and live reads, not reuse this historical list blindly.

## First Owner Portal execution PS-V1-10 (partial acceptance)

Owner submitted **`Get-Date`** from the WebAuthn-authorized PowerShell tab and reported:

| Field | Observed value |
| --- | --- |
| Request ID | `349937f9-d7b6-436d-9a9a-773b9164970e` |
| State | `EXECUTED` |
| Command SHA256 | `c1d9af5ecced5022dd0e037ef3d6e96a33b43dea902d1c05c894b7b33cb3c798` |
| Exit code | `0` |
| Stdout | `10 ноября 2026 г. 14:11:01` (displayed Windows-local value; timezone not separately established) |
| Stderr | PowerShell 5.1 `#< CLIXML` progress record with `Completed` and mojibake in progress text |

The output demonstrates one real successful Windows command and visible receipt/UUID. The owner reported **no additional per-command confirmation prompt** after an already-authorized Portal session. This alone neither proves an auth bypass nor confirms server-side negative session/Origin/CSRF enforcement. The CLIXML progress block is an output presentation defect to separate from genuine command errors; do not silently discard all stderr.

**Acceptance still open:** unauthorized session/Origin/CSRF negative POSTs, same UUID replay and changed-command UUID conflict, lost acknowledgement/timeout, receipt persistence after controlled Executor restart, and remediation of CLIXML display/encoding. Do not repeat the original effect to manufacture evidence. Detailed contract: [`docs/OWNER-POWERSHELL.md`](../../docs/OWNER-POWERSHELL.md); open work: [single backlog](../../docs/BACKLOG-IMPROVEMENTS.md).

## Independent machine readbacks and evidence limits

- After owner Apply, Repo TLS authenticated Gateway calls, typed GitHub read and read-only incident inventory confirmed three original `UNCERTAIN` and the one preserved `CLAIMED`; later Repo calls after Promote confirmed the machine ingress still worked. Source SHA / Docker host container identity after later PRs were **not independently re-inspected on Windows**.
- On 2026-11-10 a subsequent authenticated Repo read returned `incidentInventory.readOnly=true`, three `UNCERTAIN` IDs and `workerActivity.readOnly=true` with read-only `activity()` functioning. Worker heartbeat observation is **not quiescence proof**. Source/owner rollout provenance for any post-PS-V1-09 image update is not available in this evidence, so do not assert the latest active image digest based on these API calls alone.
- The owner deliberately deferred offline issuer CA key backup/isolation and cleanup of Windows-staged Gateway key/bearer for the functional V1. Untrusted scripts should not be run under that Windows identity. A non-admin account and mTLS are not a sandbox.

**Historical provenance boundary:** snapshot values above describe what was confirmed during this sequence. The current source of truth for future host changes is the protected release record plus fresh owner host checks, not an old pinned SHA or this Markdown file.

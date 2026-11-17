# OWNAPI-GW-01 — Observatory Docker HTTPS Gateway integration (SOURCE ONLY)

**Version:** 2026-11-17 source candidate, not installed / not approved for R5/R6.
**Scope:** exactly two Gateway READ/ALLOW operations, `observatory.health` (target `service`) and `observatory.list_sessions` (target `registry`). Full Observatory authorized staging API remains upstream-only and is not exposed through Gateway.

## Transport and source contracts

- Fixed origin `https://fortis-observatory-api:443` via Python `http.client.HTTPSConnection`; strict DNS SAN and CA via `/run/fortis-secrets/observatory-read/ca.pem` owner-read-only volume path. No system default CA, no proxy, redirect, HTTP/18756 fallback, caller URL or POST route.
- Trust material is **owner-provisioned** only. Do not commit the key, CA private key, tokens or runtime configs. The only upstream bearer in Gateway is a future distinct `observatory-read` vault alias tied to `read:metadata` and exact owner-approved chat allowlist. The existing Windows principal and previously retired Repo client are not changed.
- Source-only manifest `docs/templates/own-api/observatory-read.source.json` validates with existing `scripts/check-own-api-manifest.py`. `sourceSha=null` deliberately means upstream Observatory source is **not yet pinned to accepted merged main**; `readyToDeploy=false` until accepted Observatory HEAD, reviewed digest, owner CA and network release.

## Restricted network candidate (not created)

- Candidate fixed network `fortis-observatory-gw-net`, Docker `bridge`, `internal:true`, `attachable:false`, network labels `io.fortis.owner=fortis-approvals`, `io.fortis.purpose=observatory-gateway-v1`. Exact network ID pinned at Check and revalidated pre-stop/pre-attach; endpoint names/IDs closed in `github_pilot_helpers.admit_gateway_networks`.
- Observatory is a **single** running container attached **only** to that private Docker network, original Compose project `fortis-observatory-api`/service `api`, UID 1000, read-only rootfs, cap-drop ALL, **no host published ports**. Its single HTTPS server binds 443 in its isolated network; do not reuse multi-homed wildcard bind. R5 separate owner approval required before this state exists.
- Gateway retains required native egress network `fortis-gateway-egress` (not plain `bridge` in the new network mode), and joins the Observatory network **only via** protected owner-controlled `Manage-Integrations.ps1 -EnableObservatoryNetwork` Check and separately owner-approved Apply. If Action Core network is already installed, preserve it; the exact allowed sets are {egress, observatory}, {egress, actioncore}, {egress, actioncore, observatory}. Any other names, extra endpoints, changed IDs or unapproved downgrade are STOP.
- Controller verifies owner/labels, exact image/compose identity and no host publishing, stores pinned IDs in protected release records and checked image binding, creates candidate before stopping/starting, attaches only an exact missing pinned endpoint while still never-started, preserves Return/rollback and validates final endpoints. No manual `docker network connect`.
- Staged read-only acceptance: direct HTTPS/443 with pinned CA and expected **401 without Bearer** (proves TLS route + authentication), followed by TCP/18756 refusal from private DNS and `host.docker.internal`. Existing owner-specified Gateway `probe` must separately test authenticated two READs; neither a 401 nor synthetic tests prove scoped live responses.
- **PowerShell 5.1 runtime owner selftest and production host preflight NOT RUN.** Source static/offline tests do not validate Windows Docker CLI behavior or grant owner approval.

## Owner-only dependencies and release order

1. Owner accepts R1 network/TLS/SAN/key mounts, one Observatory-only Docker interface, no Windows-host route and independent isolated backup restore. Do not deploy if indirect clients need old networks, if another RW writer remains or if old image/restore is unproven.
2. Observatory upstream HTTPS/443 code PR/CI/owner GitHub UI merge, immutable image build/verified synthetic full-API test, protected R5 cutover. Original HTTP/18756 must be discontinued **at R5 only**, no side-channel listener.
3. Finalize upstream manifest `sourceSha` against accepted Observatory source and keep the same pin in owner release records; create new separate `read:metadata` credential and CA trust in owner vault only after owner R2 approval.
4. Gateway source PR/CI and owner merge; separate protected Gateway Check with exact source/record, global unresolved and claimed worker inventory under UC-GW-009, owner quiescence and independently verified backup. Owner-only Apply/Backup/Promote, never API-invoked by Repo AI.
5. R7 live `observatory.health`/`observatory.list_sessions`, TLS negatives, no old port/host route, audit and R8 handoff.

**Source candidate only:** No Docker network, volume, image, credential, port, GitHub merge or Gateway Apply was changed by source tests. HTTP/18756 production remains unchanged until separate R5 owner approval.

# Fortis live Sonar E2E evidence — 2026-11-04

> **STATUS: LIVE EVIDENCE SNAPSHOT.** No Sonar token, machine grant, private key, WebAuthn proof, owner DB row or private receipt is included.

## Environment and scope

- Caller: Fortis Repo process execution in the active connected Repo container.
- Client: `fortis_approvals.repo_sonar_tools` and `fortis_approvals.sonar_review_scenario`; no direct Sonar credential was used by Repo.
- Fixed Gateway endpoint: `https://host.docker.internal:19104`; the client requires TLS 1.3 and uses the read-only client certificate/grant mount at `/run/fortis-client`.
- Organization: `alexpastukhh`.
- Pinned project: `AlexPastukhh_obs-planning-docs`.
- The owner started a Gateway container after the earlier TCP connection-refused result. The typed client then completed live reads and actions through the Gateway.
- Exact post-start Docker container name, Compose project/service labels, image ID and attached server volumes were **not re-inspected** after startup. The live endpoint proves the service path, not the exact Docker resource identity.

## Live READ — 2026-11-04

- Visible pinned projects: 1.
- Sonar Issues: 275 total; page 1 returned 100; `hasMore=true`.
- Quality Gate: `OK`.
- Scope: `CURRENT_DEFAULT_BRANCH`.
- PR/SHA binding: `NOT_VERIFIED_D2`.
- Exact issue reads succeeded for both test targets below.

The issue listing is a live first-page result, not a cross-page point-in-time snapshot. It does not establish a PR/commit SHA binding.
## Live Reject path

Request `2b3580dc-6a88-4f44-a1e6-9a7097c84b0c` was created through the typed `sonar.propose_accept_issue` flow for Issue `AaGC4d9TJxEkuf26a_ZX`.

- Issue before decision: `OPEN`, `MAJOR`, rule `javascript:S5869`, `repository-catalog-service.js:27`.
- The owner confirmed that the request appeared in Owner Portal and selected Reject.
- A subsequent typed Fortis status read returned `REJECTED`.
- A separate exact Sonar GET returned the same Issue as `OPEN`.
- No packet trace was captured. The implementation's Reject path is no-dispatch; the unchanged Sonar readback is the observed external result.

## Live Approve path

Request `2db54607-f0c3-4f43-9597-f73f54ea46af` was created through the same typed flow for Issue `AaGC4d9TJxEkuf26a_ZY`.

- Issue before decision: `OPEN`, `MAJOR`, rule `javascript:S7721`, `repository-catalog-service.js:30`.
- The owner confirmed the exact request through the Owner Portal WebAuthn flow.
- A subsequent typed Fortis status read returned `EXECUTED`.
- An independent exact Sonar GET returned status `ACCEPTED`.
- Sonar `updateDate`: `2026-11-04T03:53:16+0000`.

## What this proves

- Live typed Repo-to-Gateway authentication and Sonar READ work for the pinned project.
- ASK creates a real, visible owner request and returns `PENDING`.
- Owner Reject reaches `REJECTED`; the exact Sonar Issue remains `OPEN`.
- Owner WebAuthn Approve reaches `EXECUTED`; the exact Sonar Issue becomes `ACCEPTED`.
`ACCEPTED` is a Sonar Issue status transition. It does not fix source code or prove the reported code smell has been corrected.

## Evidence limits and operational impact

- This is live single-actor / single-project acceptance for the currently implemented typed operations, not multi-agent or full production acceptance.
- The scenario reads the latest available Sonar analysis; it does not trigger GitHub Actions or a new Sonar analysis.
- The result does not establish PR/commit SHA binding (`NOT_VERIFIED_D2`).
- No packet capture was taken; request-state and exact Sonar readback are the recorded evidence.
- The successful endpoint proves the Fortis Approvals Gateway service path is active after the owner started a container. A fresh Windows `docker inspect` is still required to reconcile the exact active container name, Compose labels, image and server-volume attachments against the earlier host inventory.
- This evidence does not authorize Docker renaming, volume migration, credential rotation, backup/restore changes or deployment changes.

## Stage impact

- The functional Approval acceptance gate for the current single-actor Sonar pilot is **PASS** for READ, ASK, Reject and WebAuthn Approve.
- Do not repeat GO-1 provisioning, GO-2 owner enrollment or GO-3 Repo client mount/recreate.
- Keep the resource rename as a later, separately approved stage. Its remaining work is runtime identity/inventory reconciliation, dependency search, image/volume mapping, data-preserving migration and rollback.
- Multi-agent isolation, new scan dispatch, PR/SHA binding, backup/restore and production supply-chain hardening remain open roadmap items.

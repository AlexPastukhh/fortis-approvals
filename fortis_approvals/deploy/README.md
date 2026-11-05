# Fortis deployment artifacts — current index

> **СТАТУС: ДЕЙСТВУЮЩИЙ УКАЗАТЕЛЬ.** Fortis Approvals Gateway is deployed and live E2E has been exercised. R7/P1/P2 remain historical implementation/deployment identifiers in dated evidence and artifact names. This directory contains both current references and historical scripts.

## Current runtime

- Current runtime: one Fortis Approvals Gateway container with Owner Portal, machine ingress, Core and typed Sonar adapter.
- Deployed image ID (exact artifact identity): `sha256:e751f6ca0cfe6ce290cf580de2f243071ee1f3e681baa8827c6cea41a16fa402` (Windows build/audit and deployment/health owner-reported; live Repo→Gateway→Sonar E2E independently exercised).
- Existing GO-1 provisioning, GO-2 Gateway startup/owner enrollment and GO-3 Repo read-only client mount are complete. Do not rerun them.
- No additional volume is needed for the current single-actor pilot.
- **Latest live acceptance: PASS (2026-11-04).** Fresh typed READ, ASK, owner Reject (`REJECTED`, Sonar Issue remained `OPEN`) and owner WebAuthn Approve (`EXECUTED`, independent Sonar GET returned `ACCEPTED`) are recorded in [`FORTIS-SONAR-LIVE-E2E-20261104.md`](../evidence/FORTIS-SONAR-LIVE-E2E-20261104.md). The endpoint is live after owner startup; exact post-start Docker container/project/image/volume identity still needs a fresh host inspect.

## Current evidence and design references

- `compose-r7-p2-20261103.yaml` — preserved dated runtime configuration reference for the deployed artifact; filename is retained for provenance, not as a proposed naming convention or routine command.
- `compose-fortis-approvals-dryrun.yaml` — **SUPERSEDED HISTORICAL CANDIDATE; DO NOT DEPLOY.** It proposes a new Compose project/service and new volume names, which are out of scope for the owner's minimal in-place rename. Retained only as historical evidence; never use it with `up`, `create`, `start` or `down`.
- `Dockerfile-R7-Unified-Read-Ask-Candidate` is the Dockerfile named and SHA-256-pinned by `Build-R7-Windows-ImageOnly-p2-20261103.ps1` for the supplied historical image-only build. The top-level `Dockerfile` is a different older `fortis_approvals.server` / port-18990 image recipe; it is **not** the build file named by the deployed-artifact build script.
- `Dockerfile-Gateway-Modularized-Candidate` packages the modularized image now built and running only in the isolated owner-reviewed test instance. Production still uses the preserved older image; see the dated review evidence for exact image/snapshot IDs. It packages the migrated Sonar provider plus the GitHub Gateway adapter code, but does not register GitHub, add actor grants/policy, or mount a GitHub token. It is validated by `tests/test_modularized_candidate_manifest.py`; it is not a deployment instruction or release GO.
- `Audit-R7-P2-Windows-ImageOffline-20261103.ps1` and `Build-R7-Windows-ImageOnly-p2-20261103.ps1` — historical build/audit scripts for the already built image; rerun only after a new source package/image is intentionally prepared.
- `R7-P2-WEBAUTHN-EXECUTE-SOURCE-REVIEW-20261102.md` — archived source review, superseded by live evidence.
- Current operational status and limits: `../../docs/guides/FORTIS-APPROVALS-SECURE-DEVELOPMENT.md`.
- Live request/readback evidence: [`FORTIS-SONAR-LIVE-E2E-20261104.md`](../evidence/FORTIS-SONAR-LIVE-E2E-20261104.md) is the latest owner Reject + Approve acceptance; [`FORTIS-SONAR-LIVE-GET-AFTER-MODULARIZATION-20261105.md`](../evidence/FORTIS-SONAR-LIVE-GET-AFTER-MODULARIZATION-20261105.md) confirms the migrated Repo client still performs a live GET; [`FORTIS-SONAR-LIVE-E2E-20261103.md`](../evidence/FORTIS-SONAR-LIVE-E2E-20261103.md) preserves the prior evidence snapshot.

## Historical only — do not use as current deployment instructions

G2, G4, R4, R5, A3, old R7 P1/v2 candidates, old provisioning/preflight/cutover/rollback scripts and their dated runbooks are retained for provenance. They are not parallel production services and must not be started, reprovisioned or rolled back as part of ordinary Sonar work.

Old cutover/provisioning docs and source reviews are byte-preserved in `../archive/20261103-pre-live-doc-cleanup/`. Dated handoffs under `docs/handoffs/` are immutable history; their next-step text is superseded by the single active backlog in the Fortis Container repository's `docs/FUTURE-IMPROVEMENTS.md`.

## Runtime map (reference only)

| Container role | Volumes | Exposure |
| --- | --- | --- |
| Fortis Approvals Gateway (preserved Compose service `fortis`; old generated name owner-reported as `fortis-r7-p1-fortis-1`) | `fortis-r7-state` → `/state` RW; `fortis-r7-identity` → `/run/r7-identity` RO; `fortis-r7-grant` → `/run/r7-grant` RO; `fortis-r7-sonar-token` → `/run/r7-sonar-token` RO | `127.0.0.1:19103` Owner Portal; `127.0.0.1:19104` TLS machine ingress |
| Fortis Repo (`fortis-repo-test`) | `fortis-r7-client` → `/run/fortis-client` RO; `fortis-repo-workspace` → `/workspace/files`, `/workspace/repo`, `/workspace/repos` RW | Calls Fortis Approvals Gateway through `https://host.docker.internal:19104`; never receives Sonar token |

The Repo client sends typed envelopes to `/v1/reads` and `/v1/actions`; Fortis Approvals Gateway itself performs the allowlisted Sonar GETs. Only the owner portal can complete WebAuthn decisions. Do not infer live Docker identifiers from the preserved Compose reference alone: `compose-r7-p2-20261103.yaml` records the supplied deployed-artifact configuration, while `compose.yaml`, `compose-r7-unified-read-ask.yaml` and older candidates are historical.

For the source-level flow and state machine, use [`fortis_approvals/README.md`](../README.md).

## Planned GitHub credential isolation — not deployed

The GitHub integration is not yet registered, and the active Gateway has no GitHub upstream credential. The target is a separate external Docker volume named `fortis-github-token`, mounted read-only at `/run/github-token`; a Fine-grained PAT would be read from `/run/github-token/token`. The volume has not been created, populated or attached.

Do not edit or deploy the preserved `compose-r7-p2-20261103.yaml` merely to add this mount. It is a dated artifact reference, not confirmed as the maintained live Compose source. First identify the actual active Compose source and build a reviewed release candidate. Keep the existing Sonar, state, identity and machine-grant volumes unchanged. See [GitHub onboarding plan](../../docs/INTEGRATION-MODULARIZATION-AND-GITHUB-ONBOARDING-PLAN.md).

## Isolated modularized review candidate (2026-11-05)

The modularized image is being validated beside Production, not cut over. Use only these dated review artifacts:

- `Build-Modularized-Review-Origin-20261105.ps1` — image-only build from a clean review worktree or a checksum-verified owner-review source snapshot; starts no containers and changes no volumes. Snapshot builds record the base commit and exact snapshot SHA-256 without claiming the edits are committed.
- `Restore-R7-State-Backup-To-ModularizedReview-20261105.ps1` — verifies the protected R7 backup and restores it into the new external volume `fortis-r7-state-review-20261105`. Its Python helper `restore_review_state.py` validates actual counts against the pinned backup manifest and checks all credential/invitation rows and unchanged history bytes. Permission changes occur before ownership is transferred. It changes only the cloned `owner.sqlite` origin from `http://localhost:19103` to `http://localhost:19203`; RP ID remains `localhost`, and the production backup is mounted read-only.
- `compose-modularized-review-20261105.yaml` is a reference; `Start-Modularized-Review-20261105.ps1` creates, inspects and starts the candidate on loopback ports 19203/19204, with the restored review-state volume RW and the existing identity, grant and Sonar-token volumes RO.
- `Test-Modularized-Review-Sonar-GET-20261105.ps1` — sends one typed, read-only Quality Gate request from the existing Repo container to the review machine ingress on 19204; it does not perform a Sonar mutation.

The candidate image listens internally on 19103/19104. Its configured public Owner Origin and machine Host must match the host-published review ports; otherwise the Owner Portal rejects browser Host/Origin checks. Production remains on 19103/19104 with its original state volume. Do not remove, rename, stop or replace Production as part of this review sequence. The review Compose file is not a production deployment file.

The restored owner credential is expected to remain usable because the RP ID stays `localhost`; test login in a separate InPrivate browser window to avoid the localhost cookie being shared between ports. Do not enroll another credential unless login with the restored credential has been tested and a separate device is intentionally being added.

This review sequence does not activate GitHub: the GitHub adapter remains unregistered and no GitHub token volume is mounted. It also does not authorize a live Sonar mutation. Validate portal login/history and safe READ/ASK/Reject paths first; any Sonar Approve test must be separately authorized against an explicitly selected issue.

### Image-only preflight before restore

`Run-Modularized-Review-ImageOnly-20261105.ps1` first tests the existing image
`sha256:a2fd23c3def0609ed254cd796f40fb51cc4a5a103f0486bb0052d44d76b23267`,
builds the review Origin image, and tests the new image. Each image must pass
`pip check`, server import preflight, a synthetic offline Sonar GET and GitHub
imports with GitHub still unregistered. Smoke containers have no network,
ports, state or credential mounts, and are removed after execution.
The wrapper verifies Production image/health/container ID/start time before
and after. It never restores state or starts the review Gateway.

For a Windows source snapshot, `review-source.json` is generated by the
packaging step outside Git. Every packaged source file is hashed, and the
build validates the exact file set before building. This is a one-off
review artifact, not an update to a Windows Git clone or a production release.

### Pinned restore after the image-only result

The restore script uses tested image ID
`sha256:a6d3cbc645903fc3a36698868790ea1e191d73d1e9d5c01f7cecc97697c56e84`
and snapshot label
`3a0d8f99f11a2f27dd1467593e1ac37ce452a183c19c7abf685643e1727b6d14`.
It verifies owner/SYSTEM/Administrators ACLs on the backup directory and six
files without changing ACLs. `verify_review_state.py` is a second read-only
check executed as the Gateway UID/GID, with only the new volume mounted RO.
Both Python helpers must accompany the restore script. The final restore
marker is emitted only after this verification and Production/backup rechecks.
This step does not start or publish the candidate Gateway.

### Pinned start after verified restore

`Start-Modularized-Review-20261105.ps1` now uses explicit Docker create,
inspect/admission, then start by container ID. It does not use Compose up.
The dated review Compose file is a reference, not the current start entrypoint.
No existing container is overwritten or recreated. Startup requires the exact
restored-state receipt in `review-state-receipt-20261105.json` and a repeated
read-only state check as 10001:10001 before the Gateway starts.

The seven-file start/read bundle must include the Start script, Sonar GET
script, state verifier, runtime admission helper, recorded state receipt,
Repo GET Python helper and built-snapshot Repo source hashes. It checks the
Owner root page, then one typed Sonar GET at 19204; it does not enroll a key,
create ASK requests, make owner decisions or mutate Sonar. Physical WebAuthn
login and History viewing remain owner browser checks in a separate session.

The r2 start/read preflight reports exact Docker host TCP port bindings and
container states instead of treating any `docker ps --filter publish` hit as
proof of a live conflict. Active/uncertain containers and Windows listeners
block; created/exited containers are left untouched and merely reported.
Do not repeat restore because of the r1 port-preflight failure.

`Release-Smoke-Ports-And-Start-Review-20261105.ps1` is the follow-up entrypoint
for the owner-observed active r3 smoke port blocker. It inspects and admits
only that exact isolated test instance before stopping its container ID.
It retains the old container and all named volumes, rechecks Production, then
calls the pinned review launcher. Unknown image/state/mount/host configuration
or automatic removal causes STOP before changes. No other container is stopped.

The owner then showed r3 has the shell mkdir entrypoint and only three
credential mounts. The current release/start r2 handles that observed case:
it requires exact ID/image/command and /state tmpfs, then proves all seven
state counts are zero with `probe_smoke_state.py` before stopping. Nonempty
or uncertain state is left running for a separate protected backup. This
supersedes the r1 assumption that r3 uses a persistent named test-state volume.
Only a confirmed empty tmpfs may be discarded; all named volumes are retained.
The bundle must also include `smoke_tmpfs_contract.py` and `probe_smoke_state.py`.

The r2 probe proved r3 is nonempty (one request and event), so it was not stopped.
Use `Backup-R3-Locked-And-Start-Review-20261105.ps1` for this observed case.
It creates a separate protected Windows R3 backup, holding SQLite read locks
until the verified backup is durable and the exact r3 container is stopped.
The SQLite exporter `snapshot_smoke_locked.py` must never be run with inherited
console stdout: its private archive frame is captured by the .NET controller.
`verify_smoke_backup.py` verifies the Windows copy read-only. No private state
is copied into Repo/Git or mixed into the restored six-request review volume.
Exporter termination after the intentional container stop is expected; earlier
backup failures release locks and preserve the running r3. All named volumes
and the stopped old container are retained. Production cutover is not performed.

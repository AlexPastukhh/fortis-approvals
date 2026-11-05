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
- `Dockerfile-Gateway-Modularized-Candidate` is a new **source-only, not built, not approved and not deployed** candidate. It packages the migrated Sonar provider plus the GitHub Gateway adapter code, but does not register GitHub, add actor grants/policy, or mount a GitHub token. It is validated by `tests/test_modularized_candidate_manifest.py`; it is not a deployment instruction or release GO.
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

- `Build-Modularized-Review-Origin-20261105.ps1` — image-only build from the clean review worktree; starts no containers and changes no volumes.
- `Restore-R7-State-Backup-To-ModularizedReview-20261105.ps1` — verifies the protected R7 backup and restores it into the new external volume `fortis-r7-state-review-20261105`. It changes only the cloned `owner.sqlite` origin from `http://localhost:19103` to `http://localhost:19203`; RP ID remains `localhost`, and the production backup is mounted read-only.
- `compose-modularized-review-20261105.yaml` and `Start-Modularized-Review-20261105.ps1` — run the candidate on loopback ports 19203/19204, with the restored review-state volume RW and the existing identity, grant and Sonar-token volumes RO.
- `Test-Modularized-Review-Sonar-GET-20261105.ps1` — sends one typed, read-only Quality Gate request from the existing Repo container to the review machine ingress on 19204; it does not perform a Sonar mutation.

The candidate image listens internally on 19103/19104. Its configured public Owner Origin and machine Host must match the host-published review ports; otherwise the Owner Portal rejects browser Host/Origin checks. Production remains on 19103/19104 with its original state volume. Do not remove, rename, stop or replace Production as part of this review sequence. The review Compose file is not a production deployment file.

The restored owner credential is expected to remain usable because the RP ID stays `localhost`; test login in a separate InPrivate browser window to avoid the localhost cookie being shared between ports. Do not enroll another credential unless login with the restored credential has been tested and a separate device is intentionally being added.

This review sequence does not activate GitHub: the GitHub adapter remains unregistered and no GitHub token volume is mounted. It also does not authorize a live Sonar mutation. Validate portal login/history and safe READ/ASK/Reject paths first; any Sonar Approve test must be separately authorized against an explicitly selected issue.

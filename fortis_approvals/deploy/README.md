# Fortis deployment artifacts — index

[Current state](../../docs/guides/FORTIS-APPROVALS-SECURE-DEVELOPMENT.md) owns
instance/image/endpoint facts. The accepted Sonar + GitHub/native runtime on
19203/19204 is the active **`fortis-gateway` Primary**, promoted in place,
healthy and `unless-stopped` after owner-confirmed Docker Desktop restart.
The Sonar-only `fortis-approvals-gateway` on former 19103/19104 is stopped
(`restart=no`) and retained, not deleted. Physical promotion and autostart are
controlled by [Primary operations](../../docs/PRIMARY-GATEWAY-OPERATIONS.md)
and supported by [live evidence](../evidence/FORTIS-PRIMARY-CUTOVER-LIVE-20261107.md).
Do not infer any *future* promotion solely from merged source.
[Live evidence](../evidence/FORTIS-NATIVE-GIT-LIVE-20261106.md) records owner
bootstrap, CI/merge/main/cleanup results and verification limits.

## Accepted pilot entrypoints

| Artifact | Purpose |
| --- | --- |
| `Run-GitHub-FilePR-E2E.ps1 -ScenarioKind Native` | Accepted native startup, retained-M3 admission and return; exact source and protected owner record required |
| `Run-GitHub-FilePR-E2E.ps1 -ScenarioKind CIRead` | Retained M3 CI-read startup/return path |
| `Run-GitHub-FilePR-E2E.ps1` | Earlier M2 file/PR startup/return path |
| `Run-GitHub-Pilot-E2E.ps1` | Earlier M1 branch approval pilot |
| `Dockerfile-Gateway-Modularized-Candidate` | Modularized runtime with native Git support; trusted opt-in config enables GitHub; defaults leave it disabled |

These are deployment/return references, not instructions to rerun completed
provisioning. The native owner record still pins the protected bootstrap
source worktree/SHA. Preserve it, retained M3 and all dependent volumes. New
source commits do not change the image or that record. Client/worker commands,
policy and bootstrap/return conditions are in the [native contract](../../docs/NATIVE-WORKTREE-GATEWAY-2026-11-06.md).

The isolated instance has a separate GitHub credential, RO mounted at
`/run/github-token/token`; exact run-specific volume identity is in the protected
record. The retained Legacy Sonar-only container is not GitHub-enabled; the active
Primary is. Never replace the Primary token with the legacy Repo helper credential or add mounts to a historical Compose file incidentally.
[Provider boundary](../integrations/github/README.md).

## Production references and deferred release

- `compose-r7-p2-20261103.yaml` is a dated configuration reference. The owner
  renamed the same running container to `fortis-approvals-gateway`; Compose
  project/service labels remain `fortis-r7-p1` / `fortis`. Do not infer a
  maintained launch file or exact current host configuration from this alone.
- `Dockerfile-R7-Unified-Read-Ask-Candidate` is the hash-pinned build recipe used
  by `Build-R7-Windows-ImageOnly-p2-20261103.ps1`. The top-level `Dockerfile`
  is an older server/port recipe, not the deployed-artifact recipe.
- [Production release contract](../../docs/MODULARIZED-RELEASE-EXECUTION-CONTRACT-2026-11-05.md)
  remains a deferred proposal. Its earlier pinned image/profile is not the
  accepted native review or a current release GO. Exact inputs, executable
  rollout/backup/rollback and owner decision must be reviewed separately.
- `compose-fortis-approvals-dryrun.yaml` is a superseded migration proposal.
  It must not be used with `up`, `create`, `start` or `down`.

## Historical review and provisioning

[Review preflight evidence](../evidence/FORTIS-REVIEW-PREFLIGHT-20261105.md)
records the earlier 2026-11-05 image/state preparation. Later M1–M3/native
instances supersede its running review identity, not its historical evidence.

| Artifact group | Historical role |
| --- | --- |
| `Build-Modularized-Review-Origin-20261105.ps1`, `Run-Modularized-Review-ImageOnly-20261105.ps1` | Image-only build and network-disabled smoke |
| `Restore-R7-State-Backup-To-ModularizedReview-20261105.ps1`, `restore_review_state.py`, `verify_review_state.py` | Protected backup admission, separate state restore and byte/count/ACL verification |
| `Start-Modularized-Review-20261105.ps1`, `review_runtime_contract.py`, `compose-modularized-review-20261105.yaml` | Initial isolated create/inspect/start; Compose is a reference, not the current native launcher |
| `Test-Modularized-Review-Sonar-GET-20261105.ps1`, `review_repo_get.py` | Read-only migrated-client Sonar probe |
| `Backup-R3-Locked-And-Start-Review-20261105.ps1`, smoke snapshot/verify helpers | Protected preservation of the nonempty earlier R3 tmpfs before stopping that exact instance |
| G2/G4/R4/R5/A3, old P1/v2 and GO-1/GO-2/GO-3 scripts | Completed laboratory/provisioning/cutover work, not routine commands |

Old source reviews and runbooks are preserved in
`../archive/20261103-pre-live-doc-cleanup/`. Do not recreate volumes, enroll a
new owner credential, stop Production or replay a historical cutover as part
of ordinary source work. Deployment/return authorization belongs to the exact
reviewed record and target, not merely to the existence of a script.
Remaining work is in the [follow-up plan](../../docs/FOLLOW-UP-PLAN.md).

## New operation onboarding

`Manage-Integrations.ps1` is the permanent owner controller for the extension
framework: Apply/Check/Credential/Return and `Backup`/`Promote` for Primary
(`Primary-Gateway.ps1`). `Backup` makes a verified stopped-state clone;
`Promote` changes only the active container's name/restart policy and writes a
separate protected `primary.json`, leaving historical release records intact.
After future Apply, repeat Backup/Promote to restore the permanent name. Inputs, token handling and supported
state profile are defined once in the [extension contract](../../docs/INTEGRATION-EXTENSIONS.md).
The base controller is accepted with an empty catalog; current deployment and
limits are in [current state](../../docs/guides/FORTIS-APPROVALS-SECURE-DEVELOPMENT.md).
For existing GitHub/Sonar token replacement use the same entrypoint with
`-Action Credential -Service github|sonarcloud -Rotate`; the
[rotation runbook](../../docs/CREDENTIAL-ROTATION.md) owns steps, shared Sonar
effects, recovery and the pending Windows acceptance.

# Fortis deployment artifacts — index

[Current state](../../docs/guides/FORTIS-APPROVALS-SECURE-DEVELOPMENT.md) owns the
latest confirmed image/source/endpoint facts. Normal work uses the active
`fortis-gateway` Primary on 19203/19204; retained Sonar-only Legacy is not its
fallback. Routine releases use `Manage-Integrations.ps1` and
[Primary operations](../../docs/PRIMARY-GATEWAY-OPERATIONS.md), not a replay of
M1–M3 provisioning. Source merge does not deploy an image. Initial cutover and
reboot evidence is dated; exact runtime IDs always come from protected records
and live owner readback.

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

The Primary uses a separate Gateway-held GitHub credential, RO mounted at
`/run/github-token/token`; exact run-specific volume identity is in the protected
record. The retained Legacy Sonar-only container is not GitHub-enabled; the active
Primary is. Never replace the Primary token with the legacy Repo helper credential or add mounts to a historical Compose file incidentally.
[Provider boundary](../integrations/github/README.md).

<a id="production-references-and-deferred-release"></a>

## Historical deployment references

- `compose-r7-p2-20261103.yaml` is a dated configuration reference. The owner
  renamed the same running container to `fortis-approvals-gateway`; Compose
  project/service labels remain `fortis-r7-p1` / `fortis`. Do not infer a
  maintained launch file or exact current host configuration from this alone.
- `Dockerfile-R7-Unified-Read-Ask-Candidate` is the hash-pinned build recipe used
  by `Build-R7-Windows-ImageOnly-p2-20261103.ps1`. The top-level `Dockerfile`
  is an older server/port recipe, not the deployed-artifact recipe.
- [Historical Production release proposal](../../docs/MODULARIZED-RELEASE-EXECUTION-CONTRACT-2026-11-05.md)
  is superseded for routine releases by the permanent controller. Its old
  pinned image/profile is not a current release input or an additional backlog.
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
Remaining work is in the [follow-up plan](../../docs/BACKLOG-IMPROVEMENTS.md).

## AI incident details and simple owner close — established 2026-11-09

This feature predates the subsequent 2026-11-10 Owner Shell release. The latest
owner-confirmed source/image identity is recorded **only** in the
[current state](../../docs/guides/FORTIS-APPROVALS-SECURE-DEVELOPMENT.md), not
as a hardcoded historical pin in this operational index.
Authenticated Repo `WorkflowClient.details(UUID)` provides actor-owned
Core request, params/reason/preview, paginated audit, worker summary
(no claim token) and durable receipt if present. Live machine read was
confirmed for six historical `UNCERTAIN`. Investigation of actual Git
and GitHub effect still requires independent authorized read-only evidence.

Owner Portal `Закрыть заявку` uses the existing WebAuthn **login** session
and CSRF and records `CLOSED_UNCONFIRMED` with owner audit only.
It does **not** require a second WebAuthn ceremony, backup ID, explanation,
or `worker=FAILED`, and does not assert execution/nonexecution or modify
the original worker job. Browser click acceptance was not independently
established by the machine read. Current use case:
[UC-GW-009](../../docs/use-cases/incidents.md#uc-gw-009).

## Historical UNCERTAIN / CLAIMED protected migration — installed guard

For a new source/image release the controller still requires owner-scoped
`-PreserveUncertainRequests` with the current exact set of `UNCERTAIN`.
Orphaned native `CLAIMED` jobs can be byte-preserved only under an explicit
`-PreserveClaimedJobs` UUID with `-Build -SourceSha <approved SHA>` and
`-ConfirmWorkerQuiescent`; the switch is an owner attestation, not a
proof of worker inactivity. After owner administrative closure,
`CLOSED_UNCONFIRMED` + immutable closure audit permits preserving the
same explicitly scoped `CLAIMED` UUID without reopening its Core request.
No claim, receipt or provider effect is fabricated or executed.

`Backup` and `Promote` inherit the protected scope and need fresh worker-idle
attestation where a claim survives. This is a release guard, **not** a
requirement to launch backup when clicking `Закрыть заявку`.
Protected Primary release/rollback/worker procedures:
[owner runbook](../../docs/PRIMARY-GATEWAY-OPERATIONS.md).

## Native GitHub Actions analysis source candidate

GitHub CI analysis READ operations join the normal native profile on the next
reviewed image release; they do not require `FORTIS_ANALYSIS_REVIEW_CONFIG` or
a Sonar project. The default CI controls remain DENY. Only an owner-reviewed
release may pass `-CiControlRepositories 'rd-graphs'` together with
`-Build -SourceSha <exact-accepted-main-SHA> -Action Apply` to enable ASK for
the exact selected repository. The protected record binds the flag to public
container environment and all admission/recovery checks. No manual `docker -e`
or protected record editing. Normal UC-GW-005 Check/Apply/Backup/Promote and
live readback are required; source merge is not deployment.

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
effects and recovery; pending acceptance is tracked only in the backlog.

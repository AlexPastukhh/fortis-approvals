# Modularized Gateway cutover review — 2026-11-05

Status: preparation only. No Production stop, replacement, state change or
cutover is authorized by this document. The current owner instruction is to
leave Production unchanged. Use the [review evidence](../fortis_approvals/evidence/FORTIS-REVIEW-PREFLIGHT-20261105.md)
for full validation records and backup hashes.

## Verified candidate and current Production

| Item | Production | Isolated review |
| --- | --- | --- |
| Container | fortis-approvals-gateway | fortis-gateway-modularized-review-20261105 |
| Image ID | sha256:e751f6ca0cfe6ce290cf580de2f243071ee1f3e681baa8827c6cea41a16fa402 | sha256:a6d3cbc645903fc3a36698868790ea1e191d73d1e9d5c01f7cecc97697c56e84 |
| Published ports | 127.0.0.1:19103 / 19104 | 127.0.0.1:19203 / 19204 |
| State volume | fortis-r7-state | fortis-r7-state-review-20261105 |
| Owner Origin | http://localhost:19103 | http://localhost:19203 |
| RP ID | localhost | localhost |
| Credentials | Existing Production credential | Preserved copy; owner login verified |

The identity, machine grant and Sonar-token volumes are the existing three
volumes, mounted RO. The candidate source snapshot is
`3a0d8f99f11a2f27dd1467593e1ac37ce452a183c19c7abf685643e1727b6d14`,
based on commit `7963581eeae50f583df5c9f4caab46df5071b72a`.
Follow-up source commits include operational tooling/evidence; they must not
be falsely claimed as the image's build revision. Runtime Python source
hashes used by the review client match the built snapshot.

## Acceptance already exercised

- 282 supported offline tests passed; source manifests/whitespace checks pass.
- Image pip check, installed-module imports, synthetic Sonar READ and disabled
  GitHub adapter imports passed on the pinned image.
- The preserved Production backup passed hashes, all three SQLite integrity
  checks, owner binding, credential preservation and all seven ACL checks.
- Restore into the separate review volume passed hashes/modes/UID/GID and an
  independent read-only verifier as 10001:10001.
- The owner logged in with the existing WebAuthn device and confirmed the six
  restored History entries (3 EXECUTED and 3 REJECTED).
- Review GET through 19204 returned Quality Gate OK. One additional reject-only
  review ASK became REJECTED after the owner decision; exact Sonar GET still
  returned OPEN. Its ID is `4202bc09-dc0e-4fb3-b1ab-018d8c999d0d`.
- The old r3 smoke's distinct PENDING request/event is safely archived in its
  separate protected Windows backup. Its stopped container and named volumes
  are retained. That test request is not mixed into Production/review history.

## Limits requiring a release decision

A live new-image Approve-to-Sonar-write was not performed. Its code path has
offline coverage and prior Production E2E evidence, not a new live mutation
receipt. A live mutation test requires an explicitly selected Issue and
separate owner authorization; it is not a prerequisite to invent silently.

GitHub code is present but not registered in the running Gateway; no GitHub
provider token volume, actor grants or policies were added. Ordinary source
Git publication does not activate that integration. Remote CI/branch protection
must be checked separately from the local test result and successful push.

## Required read-only pre-cutover inventory

Before drafting an executable cutover, collect a fresh host profile of both
containers and identify the maintained Production launch/Compose source.
Include exact image/container IDs, command/entrypoint, public configuration,
ports, volume drivers/options, user, rootfs, capabilities, security options,
resource limits, restart/health policy and network. Do not print secret values
or use the dated Compose reference as proof of the actual launch source.
Check every user of fortis-r7-state; an unexpected writer is a STOP condition.
Check source PR/CI review according to the canonical Docker/GitHub/Windows
workflow. Do not switch the primary clone or overwrite prepared changes.

## Proposed controlled sequence after separate owner GO

1. Produce and verify an exact replacement configuration from that fresh host
   profile. Preserve the Production name, endpoints and four original volumes;
   use the pinned candidate image. Keep Owner Origin 19103 and RP ID localhost.
   Never promote the review owner.sqlite (Origin 19203, test login/counter) or
   review test requests into Production. No new credential enrollment.
2. Schedule the maintenance window. Quiesce writes and create a fresh final
   Production backup with SHA-256 manifest, three SQLite integrity checks,
   all request/event/receipt counts and owner/credential checks. The older
   verified backup is retained, not overwritten. A hot journal, changing
   source or unknown binding is STOP, not a reason to read immutable SQLite
   while ignoring recovery data. Review the exact backup/restore procedure.
3. Retain the old Production image and container configuration for rollback.
   Stop only its verified container ID. Do not remove any volume, and never
   run old/new Gateways concurrently with the same RW Production state.
4. Create the replacement using the reviewed configuration; inspect image,
   mounts and security before starting. A different endpoint, credential
   write mount or unreviewed volume mapping is STOP. Start only after this
   exact configuration and final backup have been approved.
5. Verify health, owner login with the existing device, history and receipts,
   Repo TLS READ at 19104, and fresh Production baseline. Re-enabling live
   owner-approved Sonar mutations is a separate post-cutover acceptance step.

## Rollback contract to make concrete before GO

Rollback image is the retained exact Production image e751f6ca…; it uses the
same original Origin/RP ID, identity, grant and Sonar-token volumes. Pin its
retained container/configuration and the new final backup in the executable
runbook before approval. Define failure/time limits and service routing.

If replacement health, binding, credentials, data counts or ingress fail,
stop only the replacement. Preserve its state/evidence. Use the retained old
configuration only after checking database compatibility; do not guess that
all startup/schema effects are reversible. If restoration is required, retain
both the pre-cutover and failed-state backups and review an exact restore
mapping. Do not overwrite or delete state blindly, and do not discard any
post-cutover requests. No force push, reset, new credential, token migration
or automatic cleanup is part of rollback.

There is intentionally no executable Production lifecycle command here:
actual launch provenance, final backup procedure and exact rollback mapping
remain required inputs to the final owner-reviewed release artifact.

## Source publication and next metadata inventory

Draft PR: https://github.com/AlexPastukhh/fortis-approvals/pull/1, targeting main.
Source CI run 42056460790 succeeded for
`2198f9abcbac7d0d62e2830a38158f4158c021ac`: 282 tests in 27 suites,
compilation, source manifests and commit whitespace. Main was observed without
branch protection or required checks; no protection settings were changed.
CI success does not constitute source-review approval, merge or release GO.

`fortis_approvals/deploy/Audit-Modularized-Cutover-ReadOnly-20261105.ps1`
is the next owner-run Windows metadata inventory. It reads Docker inspect
metadata only, inventories all containers using the Production state mount
(including overlapping bind paths), and reports Compose source labels.
An optional exact `-ProductionLaunchFile` path can be hashed without printing
file contents. A path reported by Compose alone does not establish that it is
the maintained deployment source.

Only allowlisted public environment values and recognized Gateway/health
commands are printed. Unknown command values, all other environment values,
volume-driver option values and log option values are omitted. A nonempty
unknown driver configuration needs separate review before release preparation.
The script reports mounts/security/resources/network/restart/health parameters
and re-inspects the selected containers to detect profile changes. It fails
if their public profiles changed or another active state writer is detected.
This is an observation script; its completion marker does not admit cutover.

No Docker exec, state probe, SQLite access, credential access, backup, lock,
container lifecycle operation, Compose operation or upstream call is included.
The read-only inventory does not require a production maintenance window.
Windows PowerShell parsing and actual host observations remain pending the
owner-run step; Fortis Repo has neither Docker CLI nor Engine socket access.

## Metadata inventory follow-up

The owner supplied a complete metadata inventory with the completion marker
and exit code 0. The selected containers were healthy, their public profiles
were stable, and the mount-based scan found no additional Production state
user. Detailed host observations remain in the owner-provided local report.

A PowerShell projection bug affected the volume option fields: null properties
were emitted as a one-element array containing null. The empty-options result
therefore did not establish actual volume driver configuration. The old
hasHostBinds field also described legacy bind specification entries, which
can reference named volumes; actual mount types require a separate count.
The command allowlist omitted Docker's known CMD-SHELL health form.

The corrected audit has an offline -SelfTest path covering null/empty/nonempty
options, withheld unknown command values, safe health commands and the
named-volume versus host-bind distinction. Source CI parses both audit
scripts and runs these regression fixtures in Windows PowerShell without
Docker or upstream access.

The narrow Confirm-Modularized-Cutover-Metadata-20261105.ps1 follow-up reads
volume metadata and the recognized health command, and accepts an explicit
owner-selected ProductionLaunchFile path for SHA-256 comparison with the Git
historical Compose file. Matching bytes still do not select a maintained
future deployment source or authorize any lifecycle operation. Actual host
follow-up results remain pending. Final backup, exact replacement and
rollback mapping, and separate release approval remain required.

## Narrow host follow-up completed

The owner-supplied follow-up completed with exit code 0,
FORTIS_CUTOVER_METADATA_FOLLOWUP_PASS and all 12 PowerShell self-checks.
The five inspected local volumes have empty driver options. Both containers
remain healthy with zero actual host bind mounts, and their public profiles
were stable. Both exact health command forms were recognized. The identified
historical Compose file bytes match Git by SHA-256. Detailed host observations
remain outside Git.

The [release execution contract](MODULARIZED-RELEASE-EXECUTION-CONTRACT-2026-11-05.md)
and versioned Production profile now spell out replacement settings, final
backup requirements, retention names and conditional rollback mapping. A
source-equivalence gate verifies the limited persistence-related differences
against the immutable extraction. It does not prove actual image hashes or
live database schemas. Executable lifecycle tooling and final host gates
remain separate subsequent work; this is a source-review checkpoint, not
Production GO.

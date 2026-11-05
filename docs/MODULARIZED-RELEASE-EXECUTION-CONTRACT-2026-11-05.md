# Modularized release execution contract — 2026-11-05

> **Priority update — 2026-11-06:** retain this contract for later Production
> rollout. First complete the minimal isolated GitHub E2E described in the
> [current onboarding plan](INTEGRATION-MODULARIZATION-AND-GITHUB-ONBOARDING-PLAN.md).
> Implementing this Production executor is not a prerequisite for the pilot.

Status: source-review proposal. This document and the JSON profile describe
an exact intended release, but contain no lifecycle executor and grant no
Production GO. Source PR review/merge precedes Windows source import; a
separately reviewed executable release packet and owner GO precede lifecycle
actions. Do not execute the historical R7 cutover scripts for this release.

## Confirmed preparation

The owner-supplied narrow follow-up completed with exit 0,
FORTIS_AUDIT_PROJECTION_SELFTEST_PASS cases=12 and
FORTIS_CUTOVER_METADATA_FOLLOWUP_PASS. Five related volumes have local driver
and empty options. Actual host-bind counts are zero. Production uses a CMD
health check and review the equivalent known CMD-SHELL form. Their selected
public profiles were stable and healthy. The launch file reported by
Production labels hashes to the historical Git Compose file, SHA-256
1405dbc21642e6f3a056d75cb35624943fd028adf69432d22b412d33f28f1b69.
Full host observations remain outside Git.

## Intended maintained source and replacement

The proposed normative replacement input is
[modularized-production-profile.json](../fortis_approvals/deploy/modularized-production-profile.json)
in the standalone source repository. Owner review and the eventual merged
source SHA must pin that file before a Windows release packet is built.
The existing historical Compose file remains rollback provenance. The new
profile must not be passed to a historical Compose up/recreate procedure.

| Setting | Intended replacement |
| --- | --- |
| Name | fortis-approvals-gateway |
| Image | sha256:a6d3cbc645903fc3a36698868790ea1e191d73d1e9d5c01f7cecc97697c56e84 |
| Runtime source snapshot | 3a0d8f99f11a2f27dd1467593e1ac37ce452a183c19c7abf685643e1727b6d14 |
| Owner / machine endpoints | http://localhost:19103 / host.docker.internal:19104 |
| RP ID / UID:GID | localhost / 10001:10001 |
| State | fortis-r7-state at /state RW |
| Credentials | Original identity, grant and Sonar-token volumes RO |
| Network | Existing fortis-r7-p1_default; preserve fortis and fortis-r7-p1-fortis-1 aliases |
| Rootfs / capabilities | RO; drop ALL; no-new-privileges; init enabled |
| Resource settings | PIDs 100; no configured memory or CPU limit; shm 64 MiB |
| Temporary filesystem | /tmp:size=16m,mode=1777 |
| Restart policy | no, retry count 0 |
| Command / directory | python -m fortis_approvals.r7_unified_server / /opt/fortis |
| Health | Exact module health command; 20s interval, 5s timeout, 3 retries, 20s start period |

The three explicit environment values remain the current Sonar region,
organization and project. Production endpoint defaults stay 19103/19104.
No review Origin, review state or review memory limit is imported. No new
credential enrollment, GitHub provider activation or token migration occurs.

## Persistence compatibility gate

[scripts/check-release-storage-source.py](../scripts/check-release-storage-source.py)
verifies six persisted-state-related source files against the immutable
extraction manifest and the pinned candidate hashes. Candidate hashes must
also match the existing built-snapshot runtime hash receipt. Owner auth, owner portal,
Gateway and runtime are byte-identical. The only allowed core change is the
GitHub-specific payload-size limit; Sonar implementation differs only in two
relative import paths. Reversing those explicit changes must reconstruct the
exact immutable baseline hashes. No storage SQL, credential format, receipt
format or owner decision implementation changes are accepted by this gate.

This establishes source equivalence, not actual old/new image equivalence or
live data compatibility. The final host release preflight must hash those six
files inside the actual previous and replacement images against
[the source hash descriptor](../fortis_approvals/deploy/release-storage-source-hashes.json).
The old Sonar path and new provider path are distinct. A mismatch blocks the
release before stopping Production. Record schema fingerprints for all three
actual databases in the final backup; compare them again after startup and
before any rollback. Keep the previous image locally available.

## Exact release phases to implement and review

1. Verify the merged source SHA, profile hash, image ID and image snapshot
   label. Inspect the currently named Production container and save its exact
   full ID as OldId in an owner-protected Windows release record. Recheck its
   configuration against the profile and the last accepted host observations.
   Recheck all users of original state, volume drivers/options, network,
   endpoint reservations, image source hashes and existing credential mounts.
   Rollback/failed-container names below must be unused. Unknown drift stops
   preparation without adopting, stopping or overwriting anything.
2. Establish an owner-controlled maintenance window: no new ASK submissions,
   owner decisions or browser logins until post-start data verification.
   Create a unique R7-final-pre-modularized backup below LocalAppData Fortis
   Backups. Apply and verify an ACL allowing only owner, SYSTEM and local
   Administrators before writing private bytes. Do not overwrite older backups.
3. In OldId as 10001:10001, a Production-specific snapshot exporter must acquire
   and retain SQLite read transactions for approvals, owner and receipt DBs.
   Require DELETE journals, no WAL/SHM/hot journal, expected file modes/owners,
   marker and Production owner binding. SQLite backup plus integrity, full
   logical hashes, schema fingerprints, credential/invitation preservation and
   all fresh counts must pass. Counts are dynamic, not assumed to remain six.
   A read-only lock is not an exactly-once upstream execution barrier: any
   queued or executing owner operation must finish before taking the snapshot.
4. Stream the snapshot privately to the protected Windows directory, with no
   database bytes in a console, transcript, Repo or Git. Verify the exact ZIP
   file set, sizes, SHA-256 and manifest, ACLs and independent SQLite/logical
   verification from a RO backup mount. The manifest must identify OldId and
   the Production image, using a distinct Production format; the R3 exporter
   constants and R3 verifier cannot be reused unchanged. Require a live source
   read-lock acknowledgement with at least 60s remaining on a 300s lease.
   On any error release locks and retain the running old container.
5. After separate release GO, and only after verified backup plus reinspection
   of OldId/configuration/single writer, stop only OldId with a 20s timeout.
   Confirm exited, retain the container and image, and rename OldId to
   fortis-approvals-gateway-before-modularized. The snapshot exporter exits
   with that container; this termination must be separately recorded.
6. Create the replacement from the pinned profile with pull disabled. Use
   docker create, inspect/admit, then docker start, rather than unreviewed
   Compose adoption or replacement. Original state is the sole RW state mount;
   all three credential mounts remain RO. No old/new concurrent writer is
   permitted. Save NewId durably before starting; inspect exact image, mounts,
   network/aliases, ports, identity, security, resources, environment and health
   policy in created state. Preserve every failed container for inspection.
7. After start, allow at most 100s for healthy, stopping at early exit/unhealthy.
   Before browser use, compare logical contents, schema fingerprints, binding,
   permissions and counts to the final backup through a RO probe. Production
   may be receiving traffic once ports are published, so the maintenance
   instruction remains in force until these checks finish. Then verify Owner
   HTTP and typed Repo TLS Sonar GET at the Production endpoints. This does
   not create ASK or perform a Sonar write. Any failure enters the rollback
   admission process below; the executor must not infer that health alone
   proves data preservation.
8. The owner signs in with the existing device at 19103 and checks History
   against fresh final-backup counts. This changes the WebAuthn counter in the
   ordinary compatible format; never restore an older counter over it. Record
   source/image/profile/backup/NewId, test results and retained OldId. Leave
   all old backup, review and R3 artifacts intact. Live Approve-to-Sonar-write
   and GitHub activation remain separately authorized acceptance work.

## Rollback mapping and failure limits

| Object | Mapping |
| --- | --- |
| Previous service | Retained OldId, image sha256:e751f6ca0cfe6ce290cf580de2f243071ee1f3e681baa8827c6cea41a16fa402 |
| Previous retained name | fortis-approvals-gateway-before-modularized |
| Replacement to preserve after failure | NewId renamed to fortis-approvals-gateway-modularized-failed |
| Returned service name | fortis-approvals-gateway |
| State on compatible rollback | Same original fortis-r7-state, including new requests/receipts/counters |
| Credentials and endpoints | Same original three RO volumes, Origin/RP ID and 19103/19104 |
| Backup restore | No automatic overwrite or restore of original state |

If failure occurs before old stop, release locks and retain Production. If it
occurs after old stop but before replacement start, preserve any created new
container, prove no new writer ran and data still matches final backup, and
admit restart of OldId. After the replacement has run, stop only NewId, prove
no other writer, and preserve a separate failed-state snapshot before rollback.
Verify original image source hashes, all three schema fingerprints and data
integrity plus owner binding against the final backup contract. Only the
source-compatible same-volume rollback may rename OldId back and start it;
this preserves post-cutover state instead of replaying an older snapshot.

A journal, schema/source mismatch, corrupt data, unknown writer or ambiguous
container identity blocks automatic rollback. Preserve both final and failed
state; do not use immutable SQLite to bypass a hot journal. The reviewed
operator must resolve recovery separately. This can extend downtime: the
profile is not a promise that every failure can be automatically recovered.
Restoring into any new volume or replacing live state requires an additional
exact restore mapping and owner approval. Recheck old health/Owner/TLS GET
after an admitted restart. Never remove volumes or discard post-cutover data.

## Remaining authorization boundary

This packet is sufficient to review the intended profile and lifecycle/data
contract, and is source-only. The executable Production backup/controller,
actual image hash preflight, rollback admission and Windows host execution
remain to be implemented/validated after the source review checkpoint. No
Production release GO should be requested from this document alone.

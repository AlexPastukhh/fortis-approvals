# Registry Functional V1 — non-Production E1.3 owner pilot procedure

Status: **SOURCE-ONLY PROCEDURE / NOT HOST APPROVAL / NO DEPLOYMENT**.
This document is the operational procedure for the **separate** `fortis-registry-pilot`
build target. The **only normative E0–E5 roadmap** remains
[`fortis-container/docs/BACKLOG-IMPROVEMENTS.md`](https://github.com/AlexPastukhh/fortis-container/blob/main/docs/BACKLOG-IMPROVEMENTS.md).
The [hardened checkpoint/witness runbook](https://github.com/AlexPastukhh/fortis-container/blob/main/docs/RELEASE-REGISTRY-P5-OWNER-RUNTIME-RUNBOOK.md)
concerns **HARDENED_REGISTRY_GO**, not this limited, non-authoritative
`FUNCTIONAL_V1_GO` pilot. Do not introduce a second owner authorization system.

## Preconditions before any owner-managed host effect

1. Confirm exact owner-merged Approvals source SHA, green Source/Release Impact
   CI, reviewed `release/targets.yaml` and approved non-Production image build;
   no merge or AI chat request is host GO. Apply any Gateway image changes
   only through the existing [UC-GW-005](use-cases/releases.md#uc-gw-005)
   owner Check/Apply/Backup/Promote gates; do not update the live Primary
   or Windows controller as a side effect of this pilot.
2. Owner records the selected host and **real** namespaces, Docker Engine
   control, mapping of UID/GID (including userns/rootless), read-only mounts,
   backup/restore ownership, current process PID view and source/image hashes.
   Neither Repo/AI nor the Registry process may access the Docker socket,
   host root, the Gateway owner state, publisher credentials, or private backup.
3. Owner allocates **different non-root** Registry/reader/Repo UID and GID,
   checks real group memberships and collision-free mapped host identities,
   and provisions the Registry schema-3 SQLite database in its exclusive
   `0700` directory with a `0600` file. Database initial creation and any
   seed/restore are **separate owner-reviewed effects**; the listener refuses
   to initialize or migrate a missing DB. Never attach hardened schema-2.

## Owner schema-3 bootstrap core (source-only; no Docker host provisioning)

The separately packaged
`fortis_approvals.registry.owner_functional_v1_bootstrap` provides three
**independently invoked** actions in a reviewed, one-shot Registry image:
`--action Preview`, `--action Provision --expected-spec-sha256 <sha256>`,
and `--action Verify --expected-spec-sha256 <sha256>`.
**Provision is a separate owner-approved host write**, not a consequence of
Preview, source tests, PR merge or image build; the other two actions do not
install a process, grant or Gateway mount. The Python entrypoint is only the
schema-3 SQLite/config core. The separately reviewed Windows
`fortis_approvals/deploy/Registry-Owner-Bootstrap.ps1` **source candidate**
provides a narrow owner-only CLI to invoke this core. It is not a Docker
volume creation/chown tool. The separate owner volume controller is now
source-merged; its actual operation remains separately GO-gated. A [source-only private-volume plan and future provisioner contract](RELEASE-REGISTRY-OWNER-VOLUMES.md) now fixes candidate names, Linux ownership and fail-closed requirements, but **no executable host preparer or owner GO is granted by this document**. Host setup remains UNKNOWN until UC-CONT-021/022/025,
independent real UID/GID mappings and actual owner host evidence are completed.
Never run either bootstrap entrypoint directly in the existing Gateway or Repo
containers.

Owner independently reviews an exact canonical JSON `spec.json` at
`/run/fortis-registry-bootstrap/spec.json` (private `0700` directory,
`0600` file, Registry UID/GID), with *exact* fields `schemaVersion=1`,
`instanceId` (UUID), `scope` (the complete owner-provenanced P5 scope),
`registryUid`, `registryGid`, `readerUid`, `readerGid`. A digest returned by
Preview is **not** independent owner provenance; before Provision the owner
must verify spec provenance, target host/mounts and exact SHA256. Registry UID
must match the actual non-root Linux process; reader UID/GID must differ.
The helper never chooses enrollment/instance/baseline/digest identities.

The fixed intended paths are `/run/fortis-registry-state/registry.sqlite`,
`/run/fortis-registry-runtime/profile.json` and
`/run/fortis-registry-read/reader.sock`. Owner provisioning must first create
**separate** state/config directories owned by Registry UID/GID at `0700`,
and a socket directory owned by Registry UID and **reader GID** at `02710`.
On Provision the helper requires an empty config directory, no existing
SQLite, runtime config or socket, and uses `FunctionalV1CandidateJournal.initialize()`
with non-overwriting `0600` SQLite creation, then creates one canonical `0600`
Registry config. It does not bind a socket or launch the Registry service.
On incomplete or ambiguous Provision it retains partial files for owner
investigation: **STOP**, never automatically retry, delete or reinitialize.
Verify checks exact config and schema-3 genesis via an inactive SQLite
read-only transaction; it is **not** SQLite backup, inactive restore,
independent identity attestation or host acceptance. Remaining owner steps
are the independent SQLite backup/restore, runtime/socket ownership, live
pidfd+boot+inode proof, true Repo `EACCES/EPERM`, sealed nonce/profile and
manual UC-GW-005 release.

## Windows owner bootstrap launcher (source candidate; manual per action)

`Registry-Owner-Bootstrap.ps1` supports **`-Action Plan`** (no Docker or Git
calls), and individually invoked **`Preview`**, **`Provision`** and **`Verify`**
on Windows PowerShell 5.1. None is an authorization to execute the next action.
`Preview` and `Verify` are isolated ephemeral Docker runs with **read-only
existing** state/config/socket mounts; `Provision` is a distinct, owner-GO-only
one-shot with `-ConfirmProvision`, where only state/config volumes are RW.
An unknown/partial Provision result is **STOP, no retry and no cleanup**.
These actions are not implemented by the Registry listener itself.

Before any Docker action the script requires the clean Windows
`%USERPROFILE%\Repos\fortis-approvals` **main**, exact 40-hex owner-reviewed
`-SourceSha`, the exact local Linux/AMD64 image ID with `Config.User=20002:20002`,
owner-reviewed full 64-hex `-ExpectedSpecSha256`, and three exact **existing**
`local` Docker volumes. State/config names must be
`fortis-registry-state-e13b-<owner suffix>` and
`fortis-registry-config-e13b-<owner suffix>`; socket name is fixed
`fortis-registry-read`. No attached running or stopped container is permitted
on any of the three volumes during these inactive bootstrap actions. Source
SHA and image ID are separately pinned inputs: a matching local image UID
**does not independently attest the image's source provenance**. The owner must
review the exact build provenance before any run. The old image ID
`sha256:597152e7160930682a98f676f093243a5b18ebf70c3724bdbae98de21bb1402b`
pre-dates the accepted Python bootstrap module and must **not** be reused.

The owner supplies an independently verified, canonical single-line ASCII
`spec.json` with `instanceId`, complete scope and exact Registry/reader IDs.
The script verifies its byte SHA256 **before** Docker; it is passed by stdin
(not argv or an uncontrolled Windows bind mount) and written as `0600` within
an ephemeral private tmpfs owned by Registry UID `20002`. The isolated image
then invokes the existing `owner_functional_v1_bootstrap.run()` contract.
It has network disabled, read-only root, all capabilities dropped, NNP,
seccomp, memory/PID limits and no Docker socket. It never creates volumes,
changes ownership, prepares a listener, seals a Gateway profile, changes
running containers or requests grants. The owner must **separately prepare**
correct `0700` private volume roots and `02710` socket directory with real
mapped identities *before* Preview/Provision; no such method is implicitly
approved by this source addition. `Verify` checks inactive genesis and owner
config; it is not the independent SQLite backup/inactive restore or live
Registry/Gateway/Repo denial gate. No `Provision` is authorized by this PR.

Owner Windows PowerShell 5.1 `-Action Plan` is an additional manual source
check; Linux static/unit checks cannot prove PowerShell runtime, Docker mount
semantics or host security. Source merge requires owner Mirror import and
separate image-only build before any host action.

## Consolidated owner pilot bootstrap (after independently verified volume roots)

`python -B scripts/registry_owner_pilot_bootstrap.py` is the manual Windows
owner entrypoint for the **already prepared/inspected/cleaned E1.3b pilot**.
It is source-only and is not an installed controller, image input or new
permission. See `--help` for the exact inputs; Python 3.11+ and the existing
Windows PowerShell 5.1 are required (no third-party Python dependencies).
The owner chooses an existing private, encrypted-at-rest backup directory,
separate from the repo and evidence directory. Check actual ACLs, storage and
key custody; a path, Windows file hash or this script does not attest them.
No off-host/disaster-recovery claim is made.

Use the **newly accepted exact clean Windows main SHA** independently checked
against remote main through the established Gateway/Mirror workflow. The
script automatically hashes the raw Git catalog, uses the existing exact P5
CI policy profile, and stops on catalog drift. It is deliberately pinned to
the current three-volume pilot's owner review and archived Prepare/Inspect
receipts (operation `dfba6213-f83f-42ca-a136-d269289dcc09`); no other volume
adoption or automatic recovery. The original source image SHA is independent
of the newer owner script source SHA. Existing Registry image is reused.

The owner supplies actual component/resource/dependency choices (interactive,
or `--mapping` JSON with `bindings` and `components` as in the existing
component-binding contract) and the review-to-merge/clock tolerance limits.
The catalog includes production targets; mapping them does **not** deploy or
grant them. UUIDs are fresh, canonical source/binding/policy/baseline/spec
files and byte digests are computed automatically. The owner sees the full
proposal and selects the exact **pilot scope**, not production enrollment.
`pilot-acceptance.json` is an immutable scope decision made in this owner-run
session, explicitly `enrollmentAccepted=false`, not WebAuthn or evidence of
live enrollment. E2 must independently accept the same retained scope/decision
and prove forward-only coverage from its exact baseline; if that cannot be
accepted, STOP for separately reviewed migration/re-enrollment with retained
history. Never rewrite genesis/digests or claim an authoritative enrollment
from this pilot file.

One invocation, three bounded owner confirmations (no extra chat turns):

1. `PILOT PREVIEW`: save canonical scope/spec/evidence locally and call the
   existing read-only launcher Preview. No Registry data write.
2. `PILOT PROVISION`: recheck exact source/image/peer/volume metadata and
   independent empty-root device/inode using the existing exact RO inspector
   payload, then call the existing launcher with `-ConfirmProvision` once.
3. `PILOT BACKUP RESTORE`: verify inactive genesis and config using a separate
   zero-capability helper with **RO** state/config/socket mounts. Read only
   exact private regular files and reject any WAL/SHM, extra entry or socket;
   copy the inactive genesis DB into private tmpfs before opening SQLite.
   SQLite's `mode=ro` on a RO WAL filesystem without SHM may fail, so do not
   weaken the mount to RW to make Verify pass. Invoke the existing
   `create_inactive_local_backup` on the staged private copy using exact
   accepted `recovery_snapshot.py` bytes; capture DB/manifest/config and recheck
   the original source bytes. Save files exclusively in the owner-selected
   backup directory, hash/re-read them, then independently materialize these
   retained bytes into a second isolated container with **no live mounts**,
   invoke the existing `verify_inactive_local_backup` and check schema-3
   genesis/checkpoint/config. No replacement of the original DB. This
   independent inactive restore supersedes the standalone Verify invocation
   for this exact genesis workflow; the original launcher remains unchanged.
   The helper is genesis-only (2 MB DB bound), not a general live backup job.

All Docker invocations use the reviewed existing image, no network, rootfs RO,
non-root 20002:20002, no capabilities, NNP, bounded memory/PIDs, and no host
binds, daemon socket, secrets or arbitrary code/path input. The exact source
backup helper, recovery module and RO root inspector are executed without a
new image build; the recovery module bytes are independently SHA256-pinned
against the clean source. No effect occurs through Repo AI. Retain the
private `pilot-bootstrap` session directory and backup files on failure;
STOP on a missing/changed pin, native failure, timeout or uncertain state;
no auto-retry, overwrite, volume removal, rollback or restart. The owner must
maintain the exclusive Docker change window during every phase; the metadata
checks are not an atomic lock. Native failure diagnostics are private.

Expected final marker: `PILOT_SCHEMA3_GENESIS_BACKUP_RESTORE_PASS`, with exact
instance/scope/spec/backup/file digests and explicit false host acceptance,
enrollment, admission, listener start and adversarial rollback protection.
Only this entire result, not individual source/CI/Preview markers, advances
bootstrap/restore. Runtime start, real peer/Repo denial, nonce seal, existing
UC-GW-005 and live Owner Portal remain a later integration stage.

## Source/runtime wiring to inspect

- Gateway source: `fortis_approvals/r7_unified_server.py` loads
  `r7_registry_reader_mount.py` only at the **fixed**
  `/run/r7-registry-reader`. A missing mount disables this path; an installed
  Registry extension without a bound reader, or a reader without the
  image-owned Registry extension, is a **startup STOP**. The mount must be a
  *separately verified*, owner-installed, dedicated **read-only bind mount**
  (exact `/proc/self/mountinfo` and `statvfs` checks), owned by the Gateway
  reader UID, with root directory `0700`, **one** regular `profile.json`
  file `0600`, no symlinks and no unexpected entries. It is **not** selected
  from an environment variable, Repo params, an integration call, or AI.
- Gateway reader profile is strict canonical JSON **schemaVersion=2** with
  `enabled=true`, `purpose="registry-candidate-read-v1"`, `releaseNonce`,
  `gatewaySourceDigest`, `instanceId`, `scopeDigest`, `socketPath`,
  `registryUid`, `registryGid`, `registryPidfdInode`, `registryKernelBootId`,
  `readerUid`, `readerGid`, `socketDevice`, `socketInode`. The Registry process
  may be in a separate PID namespace: `SO_PEERCRED` **PID=0** is permissible
  only when independent owner kernel pidfd/boot/UID/GID/socket pins match;
  PID alone is not the identity. A synthetic inode or Registry-reported
  identity is not independent proof. No shared PID namespace is required.
- Registry source: `Dockerfile-Registry-Read-Candidate` executes only
  `fortis_approvals.registry.local_candidate_read_service --owner-config
  /run/fortis-registry-runtime/profile.json` as the separately selected
  non-root Registry UID/GID. The Registry owner config is an exact one-file
  `0700` directory plus `0600` canonical `profile.json` with keys
  `schemaVersion=1`, `instanceId`, `scope`, `registryStatePath`,
  `socketPath`, `readerUid`, `readerGid`. The Registry source never
  provisions credentials or exposes an HTTP/TCP listener. Do not enable
  container networking or additional write-capable operations.
- **Unprivileged Unix socket handoff:** owner provisions a socket directory
  owned by the Registry UID and the reader GID, Linux mode **`02710`**
  (`setgid` + owner `rwx` + group `x`). Linux must inherit that reader GID
  when the Registry non-root process binds its new socket. The source then
  checks the inherited group and sets the socket to `0660`, **without**
  `chown` or `CAP_CHOWN`. Verify exactly the same socket `device:inode`
  and permissions from both process mount views; no symlink, stale socket,
  directory under Registry DB, or Repo-accessible bind is allowed.
- **PID namespace acceptance is mandatory:** use real kernel
  `SO_PEERPIDFD` together with `SO_PEERCRED` UID/GID, the independently
  owner-opened live pidfd inode and the pinned kernel boot ID; confirm process
  liveness and same socket device/inode across mount views. Separate Docker PID
  namespaces may yield `SO_PEERCRED pid=0`; this is **not** permission to omit
  peer authentication or accept a self-reported Registry PID. Kernel rejection,
  stale pidfd, changed boot, mapped UID/GID mismatch or socket replacement:
  STOP. Do not broaden capabilities or switch to shared host PID namespace.

## Owner pre-seal source digest and release/rollback order (E1.3b candidate)

1. After **owner merge**, exact-SHA CI and guarded Windows source update,
   review the clean Windows `main` and full 40-character `SourceSha`. The
   source-only controller action `-Action RegistrySourceDigest -Build
   -SourceSha <reviewed-main-sha>` builds a Gateway image using the existing
   owner source/archive mechanism and performs **network-none, no-mount,
   no-secret offline readback** of the actual installed Python/static manifest.
   Review the returned `schema`, `sourceSha`, immutable `imageId` and
   `gatewaySourceDigest`; the digest is **not** Git SHA, image ID or
   `MODULARIZED-SOURCE-MANIFEST.sha256`. The build creates a local Docker image,
   not a running service; do not issue this owner command without separate GO.
2. Before sealing a new Registry profile, independently cross-check the owner
   source SHA/image revision and this readback against the accepted source.
   Seal exactly the returned `gatewaySourceDigest`, a fresh UUIDv4 release
   nonce and all independently measured live Registry/reader/socket pins into
   an owner-managed per-nonce profile volume. Do not let the Registry process,
   Repo, AI or Gateway generate/rewrite the owner seal. Review actual UID/GID,
   mount source/RO, writer inventory and owner volume persistence.
3. The existing **manual** `Check -Build -EnableRegistryMount
   -RegistryReleaseNonce <same-uuid> -RegistryExpectedSourceDigest <readback>
   -SourceSha <reviewed-main-sha>` (with other required reviewed arguments)
   rebuilds exact accepted source, recomputes the installed digest, checks the
   sealed profile and live peer, then saves a protected binding to the **actual
   Check image ID**, source SHA, nonce, both volumes and both digests. The
   pre-seal build and protected Check build can have distinct image IDs;
   their common source SHA and installed digest must match. `Apply` uses the
   protected `CheckedImageRecord`, **without Build**, and repeats these checks
   with the same reviewed expected digest and nonce; no implicit `-Auto`.
4. Retain **all** prior image IDs, state volumes, profile volumes, nonces,
   protected Check/attempt records, backup and original UUID scopes. The
   controller checks every retained owner release/check record for nonce
   reuse, not only the immediately previous release. Never delete the old
   profile during the new release. Any unavailable/inconsistent history is
   STOP, not proof of nonce freshness. A missing `record.json` in a retained
   protected image-check/release directory, malformed historical identity or
   directory reparse point must STOP before Check/Apply; never delete the
   directory or rewrite the protected original to make a nonce appear fresh.
   The controller's PowerShell 5.1 SelfTest exercises malformed/reused nonce
   cases without Docker effects, but does not prove real owner history.
   Verify no unauthorized RW writer; `Check` or CI does not prove persistent
   host retention.
5. For `Return`, the existing protected original attempt is the only recovery
   authority. Controller re-admits the old image, protected state and old
   profile/live pidfd/boot/socket **before stopping** the current candidate,
   then rechecks after stop. If old Registry peer/profile is stale or the
   socket has been rebound, STOP; an owner must review recovery, not reseal
   automatically or blindly replay `Apply`. Preserve the original UNCERTAIN
   protected attempt. Follow UC-GW-006; missing previous image is not a
   routine exemption (UC-GW-013 requires independent owner review).

These are **source candidate instructions**, not passed Windows SelfTest or
host evidence. The owner must still prove actual image/UID/GID provenance,
mounts/RO and writers, Repo EACCES/EPERM, schema-3 SQLite backup/inactive
restore, exact Check/Apply/Backup/Promote and host acceptance.

## Required independent evidence for accepting E1.3

Owner must record: exact source/image digests; real distinct effective and
mapped host UIDs/GIDs and supplementary groups; actual mount namespace,
PID namespaces, live `SO_PEERPIDFD` and owner-pinned boot/inode,
`SO_PEERCRED` UID/GID, socket mode/device/inode; OS-enforced Repo denial on both
private socket and SQLite with `EACCES`/`EPERM` (**not** ENOENT or a mocked
same-UID test); no Docker socket/host-admin/secrets; startup refuses
unbound/wrong nonce/source digest/peer/replaced inode; restart readback of an
existing original UUID without reinitialization or WRITE; and consistent
**owner-controlled**, privately retained SQLite backup plus an **inactive**
restore verification. The full live Repo → Gateway `/v1/integrations/*` route,
real browser Owner Portal and human passkey/revocation belong to E1.4.

All Registry output at E1.3 is **`SOURCE_ONLY_CANDIDATE_READ`** with
`admissionAllowed=false`, `writeEnabled=false`, `liveRegistryAvailable=false`.
The local event digest is **not independent rollback protection**; no
collector authentication, desired authority, actual/deployment verification,
checkpoint/witness, unattended CD, or `FUNCTIONAL_V1_GO` is implied.

**No host provision, image build, grants or release happens by running
source tests or merging this file.** After E1.3 the single normative roadmap
must be re-checked for E1.4–E5 and corrected if real host observations change
prerequisites.

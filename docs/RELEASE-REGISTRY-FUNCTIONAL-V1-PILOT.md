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

### Functional V1 final cutover

For the live Functional V1 planner, supply `--cutover-plan` with the owner-selected
`releaseNonce` (UUIDv4), exact `registryImageId`, `gatewayImageId`,
`gatewaySourceDigest` from RegistrySourceDigest, and `validatorRevision`
(the reviewed Container commit). Build both runtime images from the accepted
Windows main first. Keep remote main unchanged until cutover acceptance or
STOP and prove forward coverage; never silently reset the baseline. The
`GO CUTOVER BOUNDARY PREVIEW` confirmation selects the conditional permanent
accounting boundary, not evidence of successful live activation. The existing
old Registry image is used only for the reviewed genesis/bootstrap helpers.

After successful backup/restore this mode additionally writes the bound
schema-2 `functional.json` and an exclusive private 32-byte `planner.key`.
Do not print, upload or pass the key as an argument. The legacy scope-only
mode cannot start Functional V1 writes. The owner must still start and inspect
the exact Registry runtime, verify Repo access denial, seal the new reader
profile, and complete the protected Gateway Check/Apply and live readback.
First capture refuses an unaccounted main advance. The owner retains the real
release acceptance separately from the conditional boundary decision.

Registry Check may reuse the exact prebuilt Gateway image with
`-Action Check -EnableRegistryMount -Image <sha256:id> -SourceSha <commit>`,
the same reviewed nonce, expected source digest, configuration and preservation
arguments. No second build is needed. Check binds the actual sealed profile and
source receipt; Apply still requires its checked-image record. Apply initializes
the collector only inside the exclusively cloned candidate state, or verifies
retained collector pins on later releases. Source state remains unchanged.
Existing policy authority and recorded decisions must match the exact recognized
predecessor; unrecognized authority drift stops rather than rewriting history.

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


### Recover the paused pilot after Approvals #253

Only the original pilot is eligible. Its bootstrap scope, instance,
enrollment, baseline, validator revision, backup and original sealed
configuration remain the historical record. Approvals #253 affects the
Windows controller. The recovery PR affects the Gateway and Registry images,
and the catalog's conservative GitHub source glob flags the Publisher image
for separate delivery. Both merges precede the first capture. Their disposition is
`OWNER_REVIEWED_PRE_CAPTURE_GAP`, with exact merge and head SHA and declared
impact. No pre-merge artifact, Core decision, Desired or installed status
is attributed to either merge.

1. Use the typed Gateway to confirm both merged PR identities, exact-head CI,
   and that GitHub main is the recovery merge. Keep Approvals main at that
   merge until the next open PR is captured. Update the clean Windows clone
   via the existing Mirror flow and run PS5.1 SelfTest. Build the two pinned
   images from this one source SHA. Use `RegistrySourceDigest -Build` once for
   Gateway and save its JSON readback privately. Use the existing Registry
   image build with its candidate Dockerfile and immutable source label.
2. From accepted Windows main, run
   `python -B scripts/registry_owner_cutover_recovery.py --session-dir <original-pilot-bootstrap> --backup-dir <original-backup-root> --gateway-readback <private-json> --registry-image-id <full-image-id> --pull-request <recovery-PR-number> --pull-request-head <exact-PR-head>`.
   Review the two merge identities, scope, backing files and exact image
   pins in the owner's session. Confirm only the creation of
   `functional-cutover-recovery.json`. It retains all original bindings and
   reads the existing private planner key locally without output.
3. With a single Registry writer and the verified genesis checkpoint, switch
   the pilot listener to the new exact image on its existing volumes. Retain
   the previous container, image, profile and backup. Keep Repo isolated.
   Verify the existing scope/checkpoint and the new live peer and socket
   identities. Seal a fresh nonce-specific read profile from the recovered
   config and the original key. Run protected prebuilt Check, separately
   approved Apply of that checked image, live readback, Backup and Promote.
   Use the protected original attempt for Gateway Return. A previous reader
   profile does not authorize a newly rebound socket.
4. The first subsequent pre-merge capture verifies the pinned two-merge
   first-parent chain and byte-identical catalog. The first authenticated
   owner ASK ingestion keeps that exact gap in its journal entry and
   receipt alongside the genuine next merge. The cursor changes only with
   that transaction. Later capture and ingest use the normal live cursor and
   ordinary per-merge evidence. Unexpected main, catalog or checkpoint
   state stops the procedure.

### Extend the paused pilot after Approvals #255

Use the accepted cutover above with `--post-255` after verifying the Registry
genesis, both empty Gateway journals and the retained original backup on
Windows. The new private file `functional-cutover-post-255.json` is created
only after separate owner confirmation. Preparation pins the previous recovery
configuration and requires new source-bound images and release nonce.

Review exact merge and head SHAs, CI and impact for #255 and this recovery
PR. The new disposition `OWNER_REVIEWED_POST_255_CAPTURE_GAP` records #253,
#254, #255 and precisely one recovery merge. #255 changes the Gateway backup
helper. The recovery PR affects Gateway and Registry, with the same catalog
Publisher classification as the original recovery. A different first-parent
chain, tree or catalog stops preparation. Future capture starts at the
recovery tip. The first genuine ingestion retains the explicit gap without
creating Desired records or owner decisions for those four merges.

Operational status and remaining steps are in the
[Fortis Release Planning backlog](https://github.com/AlexPastukhh/fortis-container/blob/main/docs/BACKLOG-IMPROVEMENTS.md).
Use the existing protected Check, Apply, Backup and Promote sequence after
the owner reviews and activates the new binding.

### Protected Gateway handover after the Registry peer changes

The retained #254 Gateway cannot cold-start with its original dead socket
peer. Use the #254 image, its unchanged functional config and planner key,
and a new nonce-specific seal for the new live Registry peer. Keep the old
Gateway and reader volume. The reserve must be a never-started, owner-created
container with the original source state volume, unchanged command, security,
network, published ports and runtime environment except nonce. Use
`fortis-github-pilot-<reserve nonce without hyphens>` for its name and
`io.fortis.review-update=<reserve nonce without hyphens>` for its label.
Only the Registry reader volume changes. Stop on drift in the source record,
image, input scopes, secret mounts, peer or source-state receipt.

Prepare the new release configuration with `--post-256`, the exact merged
head and two source-pinned images. The original #256 config is retained.
Before Check, verify the final Registry seal and the protected candidate on
an isolated clone with no ingress and a closed release gate. Owner reviews
the exact current uncertainty/claim scope and confirms an empty APPROVED
scope. Use manual prebuilt `Check` and its exact `Apply` with both
`-RegistryReturnContainerId` and `-RegistryReturnNonce`, in addition to
the ordinary Registry options. Keep the existing exclusive host window and
worker quiescence through activation. Apply explicitly confirms
`APPLY REGISTRY HANDOVER`.

For a failure before candidate activation, the controller's protected
attempt can return to the reserve using the retained source volume after
rechecking both the seal and the exact source receipt. It will stop before
changing the reserve if the candidate has an activation marker. If Return
is interrupted, use the original protected attempt; its
`ReturningRegistrySource` phase blocks resuming the new candidate.
After candidate activation, use the ordinary protected Backup and Promote
flow. The normative status lives in the
[Fortis Release Planning backlog](https://github.com/AlexPastukhh/fortis-container/blob/main/docs/BACKLOG-IMPROVEMENTS.md).

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

### Functional local-candidate source integration

The existing owner Portal now has an opt-in Registry panel. Under a separately
reviewed v3 reader mount, the owner can create an exact-head review ASK, merge
in GitHub after original WebAuthn approval, retain the original merge evidence,
and create one `registry.ingest_merged` ASK. The internal planner computes the
plan from that evidence and the pinned baseline/binding/policy using the existing
native GitHub backend and exact shared validator revision. It sends a bounded,
canonical authenticated request over the same private AF_UNIX endpoint. The
separate Registry process alone owns the schema-3 SQLite write; the existing
extension READ methods remain candidate-only. No Repo/publisher grant, GitHub
credential in Registry, deployment, or generic SQL/evidence input is added.

The local planner capability uses a separate owner-provisioned 32-byte random
key on the two private configuration mounts (never in source, logs or Repo).
HMAC binds the exact instance, scope, operation UUID, original evidence
reference and derived plan. It is not an independent owner signature or
anti-rollback witness. The current READ-only command/profile remains supported;
the writer needs the explicit owner-reviewed `--functional-planner-key-digest`
launch option and an exact read-only runtime config mount. Gateway profile v3
adds the SHA256 of the canonical `functional.json` and private `planner.key`;
the existing reviewed mount digest covers these pins. Collector journals and
private bare object stores require a separate, exclusive owner initialization
(`python -m fortis_approvals.integrations.github.gateway.functional_review_runtime
--initialize-collector-instance UUID` in the reviewed Gateway image). Startup
never creates or resets these stores. An interrupted pin advance is STOP;
Registry lost ACK reconciles the same original UUID through Core, not another
ingest. Process/mount/source and any existing policy-authority transition
remain subject to the actual protected owner Check/Apply procedure.

Source-only tests exercise real local Unix/SQLite and the original Core ASK
pipeline with a synthetic provider/test verifier. They do not prove cross-UID
host isolation, authentic GitHub merges, actual passkeys, or enrollment
acceptance. Select the final baseline only at the reviewed cutover; the
earlier pilot-only acceptance record is not an accepted Functional V1
enrollment. All candidate admission/deployment/rollback claims remain false.


### Managed Registry and Primary startup

The managed functional pilot uses the same Docker `unless-stopped` lifecycle
as Primary. Adopt it once during a protected release window. The Gateway's
owner-sealed reader profile v4 keeps the same v3 fields and binding material
except `registryKernelBootId`, `registryPidfdInode`, `socketDevice` and
`socketInode`. Those four fields are forbidden in v4. Keep the exact
candidate release nonce, installed-source digest, instance, scope, UID/GID,
canonical functional config and planner key pins. The owner places the
canonical profile and those same private files on the standard read-only
reader volume. The protected Check/Apply procedure still pins the full
profile digest. Generate no new enrollment, journals or policy grants.

In the reviewed non-Production window, retain the old listener and its
verified backup, then stop the old writer and disable its automatic restart.
Use the existing Windows owner bootstrap launcher once with
`-Action StartManaged -ConfirmManagedStart`, the exact source SHA and new
Registry image ID, the existing state/config/socket volumes and the
protected planner key's **digest** in `-PlannerKeySha256`. Read back the
same state, image and private mounts. The launcher records the exact new
container ID. It does not confirm a successful listener or authorize
Gateway promotion. Keep the ordinary protected Check, Apply, Backup and
Promote sequence. When the retained Gateway needs a v3 reserve during the
first migration, use its ordinary owner-reviewed peer observation with
`--managed-startup` and retain the original reserve/release records.

The managed listener holds an exclusive lock on the private socket
directory. It removes a dead socket only after checking its identity and
confirming that a connection is refused. It leaves live endpoints and
unexpected files intact. Gateway proves the listener on each connection
with the live kernel UID/GID and pidfd plus a fresh, instance- and
scope-bound challenge under the existing protected key. The proof and the
planner request use separate HMAC contexts. A v4 Gateway authenticates the
peer before it sends even a READ frame, with no legacy fallback. The same
listener accepts the existing v3 wire format for a pinned reserve and
requires the existing planner MAC for every ingest.

After Docker Desktop restarts, Docker starts both admitted containers.
Registry opens the existing journal and recovers its endpoint. Primary
serves only after authenticating Registry. The profile and the protected
release digest stay byte-identical across ordinary restarts. Verify
independent Registry restart and a real Docker Desktop cold restart on
the owner host, with both containers healthy, the same scope and cursor,
the active gate, typed Repo readback and working owner rollback. This
section describes the source candidate pending that acceptance.

#### First managed release after the uncaptured #269 merge

Use the exact Approvals #270 HEAD only after it includes the #269 merge
and all checks pass. Merge #270 with a GitHub merge commit. The recovery
check requires previous main as first parent, the reviewed #270 HEAD as
second parent and the merge tree to equal that HEAD. Keep the release
catalog, Registry instance and existing capture and collector journals.

Use the owner-only cutover preparation mode --post-269 with PR 270, its
exact merged PR HEAD and the pinned image readback for the clean Windows
main. Supply --active-268-config with an owner-private, byte-exact copy of
functional.json from the active #268 reader seal, and retain the original
functional-cutover-post-267.json. The helper verifies the archived #268
configuration, its active release variant and the exact #268, #269 and
#270 merge lineage before sealing the successor. It records #269 and the
release as an explicitly reviewed gap. It creates no pre-merge review or
ingest receipt for either PR.

Keep the #268 protected release and cold-recovery evidence. Use the
single-writer managed Registry migration and the ordinary protected
Check/Apply with the exact #268 return reserve described above. Its
legacy reader still pins the current Registry peer for this handover.
Use the v4 reader profile for the new release. After Backup and Promote,
test a real cold Docker Desktop restart and Repo readback on the same
Registry instance. Test the first normal Registry review and ingestion
with a subsequent open PR after that restart check.

If the first #270 handover stopped at the PowerShell 5.1 mount filter
before switching the Registry listener, retain the #270 configuration,
image IDs and reader volume as preparation evidence. The follow-up #271
merge commit carries the parser correction and extends the reviewed gap by
that single merge. Run --post-270 with the exact #271 HEAD, both #271 images
and the byte-exact configuration of the still-active #268 Gateway.
Use the fresh #271 nonce and v4 seal. The #268 reserve and single-writer
handover are still required.

### Post-271 authority-source recovery (source candidate, not deployment)

The #271 managed listener and v4 seal passed owner readback; the #268 v3
return reserve was created but never started. The isolated Gateway rehearsal
then exited with `OWNER_POLICY_AUTHORITY_UPGRADE_REVIEW_REQUIRED` after
cloning state and retaining the collector, before protected Check. Retain
all existing release records, images, volumes, failed rehearsal evidence
and original genesis backup. The active Gateway remains #268.

The historical Registry provider digest for #254/#259/#262/#265/#268 is
`1298c276fa8d1863ed9c272b428086fc039eea3935ca9cd42424b421337a6f7a`;
#270/#271 use
`3e15015c5eb975c3747066451556de7aa60a8293b412d60541272ca86b1779e8`.
The trusted authority predecessor must reconstruct both the exact old
functional config digest and provider digest. No new grants, policy rules,
SQL edits or relaxation of the historical authority hash check.
The #270/#271 candidates did not activate authority on the primary state,
so they are retained preparation evidence, not additional predecessors.

The recovery PR must extend the exact #253–#271 prefix by one owner-reviewed
merge; do not merge the unrelated #272 before this recovery. Use the exact
merged recovery HEAD and unchanged catalog. Build both new images (the
Registry journal must accept the 20-entry gap). Owner-only
`registry_owner_cutover_recovery.py --post-271` additionally verifies the
retained byte-exact #271 configuration and the active #268 predecessor.
It writes a fresh recovery config only after its distinct owner GO; no
container action is authorized by this config preparation.

After fresh exact census and exclusive host/worker quiescence, create a
fresh v4 seal, retain and stop the current managed #271 listener under the
single-writer handover contract, and start the new source/image-pinned
managed listener against the unchanged Registry genesis. Create a new
never-started #268 v3 reserve for that peer (retain the old reserve);
verify both live profiles. Preserve Machine PowerShell and Publisher
mount/digest bindings and the exact reviewed preservation scope. Repeat
isolated rehearsal, then protected Check and receipt equality, separate
Apply, Backup and Promote. No Core activity between successful Check and
Apply. The cold restart and E2–E5 acceptance remain open. The source PR
does not prove Windows installation or any successful live release.

### Post-285 exact continuity recovery (source candidate)

Owner readback 2026-11-26: installed #273, original schema-3 instance
`08ef25a7-defb-4c7a-ac83-26ba8f994fc0`, revision zero, unchanged
genesis/cursor, empty Capture/Collector, verified v4 seal, seven authority
epochs at policy revision 8. These are non-atomic owner observations, not
quiescence or recovery admission. #273 remains live.

The separately agreed recovery scope is a single exact 31-merge interval:
original 20, exact #274/#275/#276/#277/#278/#281/#282/#283/#284/#285,
and this necessary successor merge. #274/#275 have empty impact (CI only);
other rows carry source-derived impact, not reconstructed pre-merge owner
attestations. Retain the explicit gap in the first genuine ingestion receipt;
no Desired or installed record arises from the gap itself. The Registry
journal pins the entire known prefix independently of Gateway Git verification.
Old interval formats and grants remain unchanged.

`registry_owner_cutover_recovery.py --post-285 --active-268-config ...
--active-273-config ...` uses the existing retained originals, backup,
exact-main Git/image verification and distinct owner GO. The active #273
canonical configuration must match SHA256
`65d98082fb0c2f736aa40b72a60ad8d5eebc4e2ca4154d930e385a98faf99e74`.
The exact sixth prior functional digest uses the managed provider source,
not the pre-managed source of the five older epochs. Preserve all rules,
events, original Registry/Collector instances and recovery resources.

After exact-head CI and owner merge, synchronize Docker/Windows main,
check disk budget, original backup and quiescence. Build the two pinned
images once for the admitted recovery, retain source/return protections,
verify the same genesis, fresh v4 seal, peer and preserved collector state.
Use protected Check, isolated rehearsal as required, separate Apply, live
acceptance, Backup, Promote and separately eligible retention decisions.
Measure the necessary release using existing FORTIS_RELEASE_TIMING markers.
No automatic cleanup, unrelated merge, reset, or publisher activation.
E2 requires real pre-merge review and original ingestion receipt; E3–E5
remain open. Source tests and merge alone are not runtime acceptance.

### Registry / Composite successor — source-only W1 checkpoint (2026-11-27)

This is the first source increment after #286, not an admitted API or a
delivery. The semantic v1 input contract is in
`integrations/registry_contracts/semantic_contract.py`: closed typed ordinary/group
and read inputs, explicit source/catalog/state revision and observation
references, bounded arrays/pagination, canonical detached values. Existing
candidate READ contracts are unchanged. Unknown actual source is explicit
for UNKNOWN initial/external observations; owner reports cannot assert
VERIFIED/DEPLOYED. The domain writer still needs to enforce authority,
causality, coverage, evidence and CAS.

`extensions/composite_contract.py` contains source-owned versioned
definition metadata and deterministic group expansion. Group begin/report
bind the complete parent payload, exact child inputs and definition digest
to stable planned step IDs. Merge-and-register metadata is present but its
expansion deliberately refuses execution until reviewed output binding,
capture/collector and transition contracts exist. No policy values are
hardcoded; merge has a separate protected owner gate. No methods are
registered, no policy choices or child authority granted, no journal
migration or dispatch implemented by this increment. Shared Registry DTO
module is included in the Registry image recipe and catalog inputs; Gateway
already packages the relevant provider/extension trees.

Focused source and old Core/Registry/reader-mount regression suites:
113 tests PASS locally (including nine new test methods and their
negative subcases); diff whitespace check PASS. Full catalog validator
could not run in available Python environments (PyYAML missing); exact-head
CI and source publication have not run. Source-only work may continue;
complete W1 transition/authority and compatible schema/action work, and
the reviewed #286 preservation and transition evidence gates, before
any source merge. No live policy, Registry/Gateway release or installation
is implied. Current #286 remains operationally accepted with semantic and
rollback evidence partial.

### W1.2 — successor transition and preservation scaffolding (source only)

The shared contracts now live in `integrations/registry_contracts/` (no
`extension.py`, no provider registration). The existing Registry provider
package digest remains exactly the reviewed managed predecessor; do not
replace historical digest constants to make source tests pass. When the
new contracts are actually connected to the provider, its reviewed successor
authority and source binding must cover the real changed implementation and
shared dependencies. Both shared modules and the Registry-local preservation
module are included in the Registry recipe and catalog.

`transition_contract.py` validates the closed #286 transition manifest,
existing Capture and Collector checkpoint formats, old-state binding and
exact two-parent merged source, pinned manifest and new catalog/evidence
digests. Its match result is not authenticated owner evidence or GO.
`registry/transition_preservation.py` reuses strict legacy schema-3 replay
and compares original SQL values, receipts, genesis and cursor; verified
on isolated SQLite clones with preserved original receipts and negative
schema/tamper cases. `extensions/transition_authority.py` uses existing
policy replay on a caller-owned read-only transaction and compares preserved
Core requests/events, old policy events/rules/legacy digest and exact epoch
prefix plus one new authority epoch. Tested with the existing synthetic
reviewed authority upgrade, not with a new Registry grant or live owner
proof. A future complete protected migration must also verify all actual
schemas, state files, independent source evidence and the exact successor
authority. These helpers are not a migration runner, live diagnostic route,
or full-state inspection replacement.

Final focused regression suite (new semantic, transition and authority
tests plus existing Core, Registry READ/journals, R7 mount and owner policy):
148 tests PASS. Existing catalog validator still blocked by missing PyYAML
in the checked test environments; no live image, CI, merge or policy
changes. W1.2 scaffolding done; schema/authority integration and actual
v3-to-v4 migration remain tied to W2/W3 and the mandatory pre-publication
proof. Next W1.3 compatible central catalog schema and public action.

### W2.1 — Core-owned composite journal (source-only checkpoint)

`extensions/composite_journal.py` adds an explicit version-1 companion
schema to the existing Core transaction domain: composite_meta,
composite_instances, and append-only composite_step_events. No implicit
startup migration, old table change, provider registration or new route.
Migration on an isolated/staged copy requires existing protected
preservation and schema proof; in-flight parent work prevents installation.
Bind the exact existing parent fingerprint, definition, complete expansion
and authority digest from its immutable preview. Replay the bounded
ordered child-event chain, derive PLANNED/DISPATCHED/CONFIRMED/UNKNOWN/
BLOCKED, bind original step ID and receipt digest, reject invalid ordering,
duplicate dispatch, corrupt schema/history, parent success without complete
children or STALE after a possible effect. UNKNOWN/BLOCKED prevents
further dispatch in the original parent even after original readback.
Receipt digest is recorded by trusted verified provider binding in future
executor, not independently authenticated by journal. Hash chain is local
integrity, not adversarial rollback protection.

The caller owns BEGIN IMMEDIATE and must commit dispatch before any effect;
the journal itself is not execution authority, does not acquire provider
credentials or perform effects. Actual policy, live scope, hard floor,
expiry, maintenance and receipt verification, execution ownership and
recovery are W2.2+; no automatic continuation after process restart.
The source-only test adapter uses actual existing Core lifecycle on temp
databases. Sixteen new tests PASS (including concurrency, committed marker
restart, rollback, partial/unknown, preserved prior requests/events and
schema, no premature success). Final focused combined suite 164 PASS.
Legacy Core and provider source unchanged. Existing protected helper
schema guards are not relaxed; actual migration/controller compatibility
and independently reviewed successor authority are still required.
Gateway image already includes extensions tree. No publication or live
migration.

### W2.2 — opt-in Core composite executor (source-only checkpoint)

`extensions/composite_executor.py` adds GroupAdapter and CompositeCoreMixin.
The mixin uses the pinned Core submit/owner decision/dispatch lifecycle;
the parent journal binding is atomic with its initial audit event. Only
the two source-defined Registry group operations are intercepted. Ordinary
operations delegate unchanged. No production composition or routes yet.
A scoped one-use execution context admits only the winning Core dispatch;
the executor checks the current actor, parent policy/version/expiry and
all exact child contextual admission/generation bindings before each
durable step marker, and rechecks immediately before the effect. Trusted
child binding must supply admission, dispatch, original receipt lookup and
evidence verification, not general ExtensionAdapter.apply or caller
code. Independent hard ASK/DENY and missing context are vetoes; standalone
ordinary ASK is not globally changed. Actual owner policy authority,
contextual enrollment and real provider bindings remain W2.3/W3.

Dispatch commits its marker and releases the DB transaction before the
provider call. Verified receipt identity/digest is persisted. Post-marker
exceptions (including Stale) become UNCERTAIN, preserving confirmed
children. Recovery fences interrupted parent, reads only original receipts,
never runs unstarted children, and finalizes only if all are confirmed.
The current conservative lookup requires unchanged authorization; protected
accounting after expiry/revocation remains open. A single adapter-local
process lock serializes groups and excludes concurrent recovery. This is
not proof of cross-process exclusion, effect-time revocation or maintenance
atomicity: reviewed single writer, provider guards and W4 gate required.
Recovery after restart must use that boundary. Sequential group start
only in this executor; Registry-local atomic group contract still open.

Seventeen new executor tests with actual pinned Core and synthetic binding,
including ordinary delegation, context ASK vs ALLOW, hard vetoes, scope,
policy/expiry/revocation drift, commit-before-effect, receipt mismatch,
crash/partial/recovery and active execution race. Combined focused
regression 181 PASS. No real provider dispatch, owner proof, production
policy/configuration, schema migration or live installation. The existing
Core and Provider files remain unchanged. W2.3 exact reviewed successor
authority/schema compatibility is next; T2 publication blocker retained.

### W2.3a — exact context admission and companion preservation

`extensions/composite_authority.py` validates an independently pinned,
finite exact parent/child actor, operation, target, subject and definition
relation. It uses actual UnifiedPolicyCore policy replay and explicit
admitted literal coordinates, no actor/global fallback for contextual
execution. Existing owner editor changes remain effective; no policy
defaults are embedded in the executor. Context, provider readiness and
grant, generation, hard floor and current policy all independently matter.
A scoped ordinary child ASK can be admitted only through the reviewed
context. Actual provider guard still needs W3/W4 implementation. The
additive authority proposal checks pinned old/new digests, preserves old
baselines/choices and requires new coordinates initially DENY before
separate owner admission/settings. It is not an epoch installer.
Its narrow scope-addition contract is not yet a full #286 successor
reconstruction or a production R7 composition.

`extensions/composite_preservation.py` adds exact legacy schema/Core-row
pins, explicit checked additive installation on isolated copies, and
bounded read-only full companion replay/coverage/digests, original
parent receipt consistency and orphan rejection. This is supplementary
to the existing protected inspector, not a new permitted-growth
exception. No controller integration or production schema acceptance
claimed. Actual migration and compatible historical epoch reconstruction
remain open, including exact-type composition/editor bindings and the
real Registry provider source/dependency digest. Do not relax those
checks by passing an arbitrary subclass or replacing historical pins.

14 new tests PASS (7 authority + 7 preservation), including actual
existing synthetic owner policy editor DENY/ASK transitions and
scope mutation/fallback rejection. Combined focused regression 195 PASS.
Source-only, main #286 unchanged; no live schema/grants or publication.
W2.3a complete; W2.3b successor composition and preservation integration
next, then W3 real Registry domain/binding.

### W2.3b — opt-in Unified Policy successor and historical replay

Source-only: `extensions/composite_successor.py` combines the existing
UnifiedPolicyCore and CompositeCoreMixin. ReviewedHistory reconstructs
only the finite exact incumbent admissions accepted by the incumbent
resolver and independently pinned witness. The successor requires the
checked companion schema, explicit predecessor/successor pins and an
ordinary Registry delegate. Transition and restart are distinct:
transition verifies the old clone, uses the existing epoch installer,
and checks the exact appended epoch and preservation witness; restart
validates the current authority and history without appending an epoch.
Both replay the companion, check the exact prior policy event and epoch
prefix, and refuse serving on mismatch. The current mechanism supports
one narrow additive context successor; later authority evolution needs
its own reviewed contract. It does not reconstruct the actual #286
runtime from a guessed baseline or persist a new authority by itself.

The existing OwnerPolicyEditor accepts only the exact ready successor
type in addition to the existing exact type, not arbitrary subclasses.
Coordinate-only composite inventory shows configured/current policy and
UNKNOWN effective outcome where exact child parameters are missing;
explicit DENY remains DENY. The existing editor ceremony, policy engine
and original Core are reused. The read-only authority witness recognizes
the exact successor type. No existing R7 builder or protected controller
automatically selects this class. Actual Registry readiness, scoped
provider handler, release-specific historical reconstruction and trusted
source/manifest pins remain W3/W4/W5/T2, and the complete protected
state inspection/rollback proof remains necessary. Staged clone must
be discarded on failed transition; schema and authority installation
are separate verified stages, not distributed atomic migration.
History object reconstruction on real restart and durable independent
pin provisioning need actual reviewed controller composition; synthetic
restart uses the same reviewed history and freshly observed companion
pin in isolated fixtures only.

Eight new integration tests PASS with real UnifiedPolicyCore, existing
owner editor and synthetic provider/owner fixtures. Tests include
existing epoch and DENY preservation, new coordinates initially DENY,
owner-edited ASK/ALLOW context execution, child DENY veto, restart
without repeat effect/epoch, invalid mode/pin, old-clone drift and
historical prefix tamper. Expanded regression 235 PASS with existing
offline venv (cryptography 50.0.2, fido2 2.2.1), including original
R7 TLS/WebAuthn and legacy policy fence. No production credential or
network service used; R7 regression uses local fixtures. No live
migration, runtime grant or publication. W2 source substrate complete;
W3 Registry domain and real group binding next. Actual #286 cutover
and production composition remain blocked until T2 evidence and
reviewed controller/provider integration.

### W3.1a — additive Registry v4 release-event storage

Source-only: release_event_journal.py adds release_meta and release_events
in the same private SQLite DB and explicitly migrates an inactive verified
schema-3 clone, reusing original replay and exact legacy prefix witness.
Original four tables, identity, genesis, cursor and receipts are unchanged;
the v3 reader refuses the migrated schema. No automatic migration or
empty v4 bootstrap. Exact full schema and independently pinned legacy
witness and transition digest required. The transition digest is a binding,
not proof of the #286 delivery merge; sourceTransitionPending remains true
and legacy source append is disabled. The future trusted writer must
validate actual transition evidence before semantic admission.

Two typed local events (RELEASE_ATTEMPT_STARTED and OWNER_RESULT_RECORDED),
per-target revision CAS, separate global release snapshot revision, original
UUID/receipt recovery, bounded append-only digest chain and capacity checks.
Neither event implies a verified installation, release eligibility, an
effective protected hold, owner authorization or a verified source. This
increment does not enforce domain-level attempt matching, current catalog
or desired coverage; those must be enforced before connecting a real
writer. No installed setter or protected hold closure. No external
anchor; unknown commit/readback is read back by original operation ID,
not blind retry. Capacity provisional 512 events/8 MB; current source
limits retained, checkpoint exposes remaining event count. Additive module
included in Registry image recipe/catalog; existing entrypoint unchanged.

Eleven new tests PASS, combined relevant focused regression 164 PASS;
nonempty clone original receipt, v3 mismatch, separate target CAS and
concurrent write, changed UUID payload, capacity, malformed/corrupt
history, lost postcommit readback, legacy UUID collision, migration and
restart pin mismatch. Current Approvals v1 catalog validator PASS.
Next W3.1b domain-level release event validation/projection and distinct
protected evidence accounting contract. Actual transition source epoch,
controller proof and scope-bound runtime admission remain open.
No live migration, provider calls, policy changes, CI or publication.

### W3.1b–W3.3 — local Registry domain, semantic service and planner

Source-only integrated W3 checkpoint (2026-11-27). release_domain.py
replays the exact retained v3 records and v4 event chain against an
independently pinned, immutable reviewed-shape catalog/component profile.
It separates legacy candidate Desired, last accepted technical observation,
OwnerReported, and active owner windows. Target CAS and exact source/
catalog/attempt guards run in the same writer transaction as append.
Historical reports do not downgrade current state. Explicit rollback or
failed/unknown current reports preserve Desired and restore outstanding
actions where appropriate. Exact owner-reported completion can clear
manual actions but does not establish Installed or migration proof.
Mandatory begin, overlapping resources/global freeze, exact attempt
binding and own-hold closure are checked; unknown classification or
dependency compatibility prevents a candidate begin. Ordinary report
cannot clear a mandatory technical hold. A separate internal typed
technical observation/hold-close contract needs a trusted independent
verifier; current tests use synthetic evidence, not actual controller GO.
No generic verified setter, actual interlock, or technical effect.
The raw W3.1a storage API is not the semantic writer; it rejects protected
and profile-bound requests, and domain replay rejects unbound events.

SemanticRegistry provides all seven scoped local READ methods with
snapshot-bound pagination, original subject-scoped operation receipts,
active windows and aggregate candidate restrictions, plus ordinary begin/
report and compatible group begin using the same domain writer. The
maintenance status remains UNKNOWN for effective live restrictions;
candidate holds are separate. Missing visibility does not expose
hidden holds. Scope/provenance checks use trusted composition interfaces;
production authenticated principal and transport are not wired.

RegistryGroupBinding connects the actual opt-in Core executor to the
semantic service via a trusted transport interface. Compatible group
begin is one Registry-local transaction: all child DISPATCHED markers
commit together in Core, one group call, original receipt checks and
all CONFIRMED markers together. Ambiguous ACK means all UNKNOWN;
recover only after all original receipts match, never dispatch again.
Local rollback on conflict leaves zero new Registry events; the parent
remains UNCERTAIN conservatively until typed no-effect proof exists.
Group report uses the same ordinary report writer sequentially with
partial receipts. This is not distributed atomicity. Local integration
tests use actual Core and Registry databases, synthetic admission and
in-process transport; Gateway must not gain a Registry DB mount.

release_profile.py projects the existing resolved component bindings and
validated catalog v1/v2, with no second persistent graph. v1 maintenance
classification stays unknown; unresolved external dependencies and absent
build recipe/config pins remain unknown. Stateless release_planner.py
returns exact selected source, outstanding actions, UC/verification,
dependency ordering, conflict windows, per-check results, shared build
identity and visible affected-unselected targets. Source mismatch is
STALE, missing compatibility is UNKNOWN; no persisted Batch or deployment
authorization. Shared unbuilt artifact is BUILD_REQUIRED, not verified
identical artifact. Current sourceTransitionPending stays true: new source
epochs/Desired lineage and actual compatibility evidence remain W5/T2,
so no actual PLAN_READY/DEPLOYED assertion. Actual protected Installed,
drift/phase evidence and safe closure, interlock, independent source
transition, incident UNKNOWN overlay, authenticated owner/AI ingress and
production R7 composition remain W4–W6/T2. Bounds remain pilot limits
(512 events/8 MB, 256 KiB semantic response); no silent capacity expansion.

24 new tests in this increment (13 domain/service, 4 actual local group
binding, 7 catalog projection/planner); combined expanded suite 281 PASS,
including historical Registry and Core/R7 TLS/WebAuthn local fixtures.
Approvals catalog validator PASS; diff --check PASS. Registry recipe and
catalog include new local modules; existing listener entrypoint unchanged.
W3 local source block DONE, production integration OPEN. W4 protected
Maintenance/State Freeze controller and real evidence adapters next.
No live migration, provider admission, protected host action, CI or merge.

### W4 — local Maintenance/State Freeze substrate, controller proof OPEN

Source checkpoint 2026-11-27, no live admission. Shared
maintenance_contract.py defines a closed, exact instance/scope/attempt/
subject/source/restriction/generation-bound interlock sequence from NORMAL
through DRAINING, FROZEN_BEFORE_CHECK, CHECK_SEALED, APPLY_STOP,
STAGED_TARGET_FROZEN, BACKUP_FROZEN, PROMOTE_FROZEN and COMPLETION_PENDING;
failure/return stays RECOVERY_HOLD and cannot directly clear to NORMAL.
The read-only interlock reader requires a dedicated read-only owner mount,
root-owned directory/regular file, bounded bytes and independently supplied
latest digest. The proposed fixed mount /run/r7-maintenance is not installed;
no writer, credential, host command or provisioning route is added.
File/transition checks are not proof of actual Windows durability or of
independent latest-pin availability after restore. A caller cannot select
a mount via the API. Existing activation marker is separate.

MaintenanceGate synchronizes local mutation reservations and new effects
with the same Registry-local hold writer. Every decision rereads both
trusted views; stale/missing/mismatched observations fail closed, no
permissive TTL. A global candidate hold blocks immediately even before
controller DRAINING; scoped selectors union, unknown coordinate broad
blocks, unaffected exact coordinate may proceed. Existing admitted effect
settles, no new effect after fence. Begin receipt settlement retains
reservation; drain readiness waits for all tracked reservations. Ambiguous
hold write latches UNKNOWN locally and requires reviewed recovery; not a
durable unknown latch across process loss. Group begin uses one bounded
unit, same exact original receipts. A separate completion-only seam checks
the exact attempt/operation, independent verifier and hold closure readback;
ordinary traffic remains blocked until both controller NORMAL and Registry
agree. No timeout or direct recovery unlock.

MaintenanceCoreMixin is now included in the exact source-only
CompositeUnifiedCore (explicit gate required at reviewed install); existing
Core/R7 builder not replaced. Named mutating lifecycle methods guarded;
MaintenanceIngress conservatively reserves any non-passive classified
route for its entire response lifetime, including close-before-iteration.
Trusted classifiers must validate auth/scope first; only explicitly proved
passive reads may pass. Actual existing isolated Repo/owner HTTP lab and
Core byte comparison verify blocked writes, READ route, owner decision/
login and scoped status/session reads, without modifying protected files.
Not a proof covering every registered native/extension/owner route.
MaintenanceRegistryTransport wraps the local domain begin/group/report
boundary; Registry unfiltered hold snapshot is trusted internal candidate
evidence, not a public filtered Board or runtime permission.
No new Registry writer/mount in Gateway.

maintenance_seal.py binds the drain observation to independent exact
existing protected inspect_state receipt, companion digest, worker
attestation and pinned historical UNCERTAIN/CLAIMED sets. No PENDING/
APPROVED/DISPATCHED or unresolved composite accepted; no new allowed
growth. maintenance_evidence.py binds completion to original Apply/
Backup/Promote/final seal and independent fresh target readback projections,
exact artifact and target generation, not self-asserted host evidence.
Current proof accepts successful target completion only; Return/rollback,
actual artifact materialization, independently authenticated readers and
scope-bound protected accounting are OPEN. Existing protected helper and
growth guard unchanged.

Controller feasibility audit: existing Manage-Integrations.ps1 owner
ACL/lock, immutable per-nonce Registry mount, Check seal and Apply pre/post
stop exact source receipt, Resume-Target probe/activation, Primary-Gateway
Backup/Promote exact receipt and retained source remain authoritative.
Neither existing immutable activation volume nor old clone is a durable
current interlock. Proposed separate controller-owned latest record and
read-only Gateway observation still require actual host writer/ACL,
atomic update/fsync, independent latest-pin transport, generation/restart
and rollback rehearsal. No PowerShell runtime in this offline environment.
Do NOT patch protected state/skip existing probes or substitute a new
generic root route. Actual controller hook implementation and full
successor state inspector are still required; no changes to PowerShell.
Current gate blocks ordinary old PENDING/APPROVED decisions/cancellations
during drain; require pre-drain quiescence or implement separately reviewed
exact safe cancellation/settlement before seal. No blanket bypass.
Actual Core/worker/auth/collector/background coverage and effect-time
revocation, staged passive probe conversion, post-revocation evidence
accounting, durability across restore, Windows timing/availability and
protected completion are open gates, not claimed accepted.

21 new tests PASS (11 gate/domain, 9 Core/contract/ingress, 1 actual HTTP
fixture). Expanded combined 302 PASS, including original R7 TLS/WebAuthn
and legacy policy fences. Approvals catalog validator PASS; diff --check
PASS. Source packaging added shared contracts; existing entrypoint and
host configuration unchanged. W4 local source block DONE; controller
integration and protected feasibility PARTIAL/OPEN before publication.
Independent W5 source lineage/merge work can proceed; no live source
merge, activation, policy/schema/host operation. Actual #286 migration
and protected T2 proof remain blocking.

### W5 — source lineage, retained capture and Merge & Register local block

Source-only checkpoint 2026-11-27. Shared source_lineage_contract.py
defines exact proposal and observed merge identity, parent/head/tree/main,
body/catalog/impact/path/CI/profile/dependency pins and source revision.
The first v4 source event is a separate TRANSITION, not ordinary E2 or
a fabricated legacy capture/ASK. It binds the existing #286 transition
manifest, unchanged v3 witness, exact 31-entry historical gap (original
30-entry digest and exact #286 final row), and the actual successor
merge observation contract. Genesis cursor must equal the pinned old
baseline; nonempty legacy cursor must already be exactly #286. Other
legacy cursors STOP, not rebase. Independent old-state/gap/owner/CI/
source evidence verification remains required. Actual local main Git
objects for all 31 gap entries pass the existing verify_cutover_commits
check; this is not fresh live Registry, owner approval or remote main.

Registry source_event_journal.py adds a bounded source_events table in
the same as-yet-unpublished v4 schema. Exact first transition, subsequent
MERGE events same catalog/profile epoch and exact prior first-parent
cursor, separate source revision, original operation receipts, duplicate
PR/UUID and stale CAS rejection, local digest chain, release-event
anchor and combined snapshot revision/digest. Limits provisional
64 source events/4 MB, existing overall state bounds still apply.
Old v3 tables/receipts/genesis remain unchanged. No unrelated merge
advances Desired; relevant merge sets exact source record; owner-reported
coverage tracked per record/action, new work survives older attempt
report and previously reported actions are not resurrected by unrelated
new work. No migration proof from owner report, no installed setter.
One reviewed initial successor profile can change catalog with stable
subject/component/resources; subsequent catalog changes/remaps need
separate reviewed migration. Legacy untouched records retain provenance.
Source history/subject receipt lookup integrated into semantic read;
source preflight is passive internal binding. Planner retains UNKNOWN
for unverified source evidence. No live cursor or scope change.

MergeRegisterAdapter/Binding reuses exact Core parent, companion
journal, deterministic child IDs and existing owner decision lifecycle.
Mandatory parent ASK and merge child hard ASK preserved; one original
owner approval, separate contextual grants, no standalone child request.
MergeContextGrant adds exact repo/actor/parent/child coordinate relation
to existing ContextEnrollment/Policy Engine, existing editor shows
UNKNOWN effective without exact parameters. All new actual grants
remain uninstalled. Before effect, validate Registry source preflight
and exact provider proposal, commit first child DISPATCHED then retain
bounded raw PR body/catalog/changed paths/CI and projection digest in
new composite_merge_captures table, recheck current admission and
preview. Core schema/preservation witness includes original capture.
Verify postmerge two-parent/tree/main and original receipt/capture
digest; register child uses only the first verified receipt's output.
No-deployment still accounts source merge. Partial/ambiguous effect
UNCERTAIN, passive original receipt recovery only, no automatic second
effect/continuation. No actual provider or host credential used.

Local provider interface is NOT the completed production adapter:
actual independently authenticated successor CI/impact/projection
and Git/owner evidence readers, persisted upstream original merge
receipt, owner-created same-repo PR scope, release-specific transition
approval/pin provisioning, real Unix transport/effect gate and
source recovery after a confirmed merge with unstarted register
remain open. Existing native standalone merge and old P5 capture/
collector/planner contracts unchanged; do not invoke them to fake
new evidence. W6 discovery/dedup/owner ingress and production wiring
must use reviewed exact source and current scope; W4 controller/T2
still publication blockers. No external merge or protected migration.

21 new tests PASS (10 lineage, 11 merge/capture/authority), including
actual local Core and Registry SQLite with synthetic provider/owner
bindings, wrong gap, stale source cursor/preview, base race, wrong
tree, no-deployment, older attempt coverage, tampered capture, lost
ACK, revocation and no-repeat recovery. Expanded regression 323 PASS
(21.587s); actual local 31-gap Git objects PASS; Approvals v1 catalog
validation PASS; diff --check PASS; old main clean exact #286.
Source package/copy/impact updated; existing listeners unchanged.
W5 local source accounting and composite block DONE, real provider/
transition integration PARTIAL. Next W6 scoped transport, discovery,
Portal/API and integrated composition; resolve concrete W4/W5/T2
blockers before publication or admission.

### W6 — local semantic access, private transport, Portal

SemanticAccess, RegistrySingleAdapter and SemanticRepoBroker implement
opt-in typed AI/owner access on existing Core lifecycle, exact scoped
enrollment and default DENY. Owner principal is separate from bearer
authentication. READ ALLOW is passive; READ ASK uses original one-shot
approval/UUID and spent ledger. Existing owner session/CSRF/origin and
strong WebAuthn apply to semantic owner routes. No runtime grant added.

Discovery accepts independently validated bounded proposal snapshots,
checks native list PR ALLOW/grant before/after, deduplicates repo/PR/head
and does not recreate rejected/expired requests. Overlapping unresolved
Core effects project UNKNOWN/BLOCKED without fabricating Registry events.
Actual GitHub evidence reader and explicit same-head reproposal remain
open; local lock is not cross-process proof.

Private wire schema 2 binds frame MAC, instance/scope/generation,
request identity and response digest. Typed reads, writes, group begin,
internal hold/profile only. Separate semantic transport reuses managed
peer checks. No legacy fallback, raw proxy or automatic retry.
Legacy provider digest remains exact: initial regression from extending
candidate_gateway and placing a new file in the incumbent provider
directory was corrected by restoring old bytes and moving the semantic
transport to extensions/semantic_gateway.py. No historical pin changed.
Real listener provisioning, independent UID/GID/key/mount proof,
source register/preflight/lookup transport remain OPEN.

Actual static Portal adds capability-gated Registry board/active/history/
maintenance/plan, individual/group begin/report, distinct Installed
(last observation and validity), Desired and Owner Reported, exact
source report form, original UUID readback and no mock domain logic.
Composite Actions category uses same existing policy editor and provider
identities; V2/V3.2.4 presentation palette ported. Technical plan/history
JSON and final PR/detail visual parity need browser acceptance. Legacy
manual panel retained. No actual browser or PowerShell available.

16 new tests PASS (9 access, 2 enrollment, 5 wire), socketpair framing
with synthetic peer, lost response original receipt without retry.
Expanded regression 427 PASS (30.731s), node syntax and HTML IDs
110/semantic references 24 PASS, catalog validation and diff check PASS.
Main remains clean exact #286. No live merge, policy/grant, host or
migration. Local W6 DONE; actual production composition and browser
acceptance PARTIAL. Next integrated W4/W5/W6 and T2 closure: real reviewed
GitHub evidence/discovery/merge receipt, private source transport,
successor composition, protected controller/inspector and restore
proof. Publication blocked until gates satisfied.

### I1 — integration: source registration transport and native discovery

Shared merge expansion preserves the deterministic step identities and
definition digest. Private semantic wire v2 adds closed SOURCE_PREFLIGHT,
SOURCE_REGISTER and SOURCE_LOOKUP, default denied without separate source
admission. Preflight internal principal; registration/lookup actual parent
actor with exact persisted context. Original first-step receipt, capture
digest and proposal/observation bind the second step. Transport binding
rechecks the Core journal and maintenance gate. Registry independently
requires domain evidence verification. No generic transition writer,
public source API, shared DB mount or automatic retry.

NativeMergeDiscovery uses the existing native GitHubAdapter typed PR list
and exact read-only PR/main/tree/catalog/compare paths; explicitly scoped
evidence reads and branch enrollment, no author filter. Max 20 complete
open PRs, no forks or diverged base, draft excluded. Exact blob/hash and
path projection, reread before proposal; fail closed on changed/incomplete
inventory. Independent successor validator/CI/profile/Git object projector
is still required, not the historical P5 authority. Native merge executor
and durable upstream receipt, real source authorizer and protected peer
composition remain OPEN. Existing native provider source unchanged.

13 additional tests PASS (7 source transport, 6 native discovery),
including real isolated Core/Registry SQLite through socketpair framing,
synthetic provider/owner/independent authorization, lost registration ACK
with original receipt recovery, no-deployment cursor only, scope drift,
unverified evidence and incomplete discovery. Expanded regression 440 PASS
(31.287s), catalog and diff check PASS. Main clean exact #286.
I1 local block DONE, real integration PARTIAL. Next I2 independent
successor CI/impact/Git evidence projector and original upstream receipt,
then successor composition, protected controller/inspector and T2
old-state/restore rehearsal. No live merge, migration, grant or publication.

### I2 — successor evidence and original native receipt verification (local)

SuccessorImpact verifies exact independent Git commit/tree, unique merge
base equal to reviewed base, full changed/renamed paths, raw catalog/blob
and retained body/impact hashes. Runs the exact independently pinned
validator commit in a bounded isolated raw-blob data view, uses v1/v2
catalog schema selector and unchanged v1 Release Impact contract. PR code
is not imported/executed. Resolved component mapping and build pins must
reproduce the reviewed profile digest. External and PR dependency claims
without compatibility evidence are refused, not dropped.

SuccessorCI requires separately pinned successor workflow and current
rules-view digest, exact AnalysisGitHubAdapter workflow binding and
per-read scope guard. Reuses existing bounded native run/job/check
collectors for exact PR/base/head, latest attempt, workflow source hash,
complete exact jobs and GitHub Actions App witness; rereads latest
inventory and rules. SuccessorProjector independently checks raw Git
workflow blobs and binds the reviewed validator/profile/CI policy together
under an explicit composition digest; exact source revision and capture
material. NativeMergeDiscovery.review uses the same verifier at selected
PR review and rejects changed proposal. No assumed historical P5 policy,
no assertion of complete effective branch protection, no owner grant.
The actual approved successor policy, validator commit/action publication
and independently obtained object stores remain T2 requirements.

NativeMergeReceiptReader reads only the original receipt under the
deterministic first child ID in existing native receipt store, binds
retained capture and exact proposal, then reads actual-shaped merged PR,
main and two-parent commit, independently verifies raw Git objects/tree
and catalog, rereads remote observation and original receipt. Missing
original receipt returns no confirmation even if PR is merged; changed
main/body/parents deny. It does not create receipts or invoke merge.
Actual protected merge executor, precise persisted context binding of
this reader into MergeRegisterBinding, effect-time scope and native
base-race handling remain open. No automatic reconstruction, continuation,
or historical approval inference.

10 new tests PASS (5 impact/projector/receipt with real temporary Git
objects and actual v2 validator code from the Container task copied into
an isolated local fixture commit, 3 CI policy/join, 2 native CI collector
tests). Actual GitHub adapters use synthetic REST; original upstream
receipt in test is synthetic, no actual GitHub action. Exact fixture
path explicitly provided via FORTIS_SUCCESSOR_VALIDATOR_FIXTURE; without
it cross-repo tests skip rather than substitute a validator. New suite
10 PASS (11.540s) in validator venv; existing regression 440 PASS
(34.531s) in Approvals offline venv. These are separate runs, not a single
450-test execution. Catalog and diff check PASS, old native provider
directories unchanged, main clean #286. Existing Gateway packaging
covers extensions and requirements-owner already pins validator deps.
No actual build, CI, merge, live migration or policy change.
I2 local evidence/receipt readers DONE; native effect execution and
reviewed production composition PARTIAL. Next integrate guarded native
merge dispatch with original receipt and successor Core/transport, then
controller/inspector and T2 proof before publication.

### I3 — actor-bound pre-observation, discovery isolation and mandatory suites

Source-only increment after the plan audit. Merge preview now receives the
exact persisted/submit actor. CompositeCoreMixin performs merge external
observation before the Core writer reservation; MergeRegisterAdapter uses
a per-invocation ContextVar bound to canonical request, actor and policy
version. No public cache, no caller-selected actor, no Core source edit.
Inside Core prepare, current child authority and deterministic preview
are still checked; before the actual child effect, original capture and
fresh checks remain mandatory. Existing UUID replay does not repeat
external preview. Denied/stale preview is non-executable; policy drift
before insert/dispatch fails closed. Production admission guards must
remain bounded/local under Core's reservation; real native provider
dispatch and latency/drain measurement still OPEN.

Native discovery returns explicit bounded blocked summaries for known
individual eligibility failures (draft/base/CI/impact/dependency/diff),
without hiding independently valid PRs. Unknown errors, lost scope or
unstable/incomplete inventory still abort the scan. Validate complete
result before creating any proposals; recheck list authorization before
each proposal and returning results. Existing Portal displays blocked PR
links/reasons, no new PR tab, clears prior results on denial/session loss.
Same-head stale pending settlement, cross-actor dedup visibility,
explicit reproposal and external/partial recovery remain OPEN.

Registered all 23 previously omitted new Python test modules in
scripts/test-source.sh (187 mandatory named modules, existing integration
discovery retained); runner/list checks PASS. Existing Node mock tests
initially had four failures because theme and composite category helpers
were missing from their fixture harnesses. Updated fixtures and added
blocked discovery/denial and category coverage. No weakened old
assertions. P5 real-validator workflow still requires actual successor
immutable action pin and no-skip gate; optional cross-repo tests skip
without fixture, not an accepted production proof. Both source manifests
must be refreshed on coherent prepublication candidate, not on every edit.

Focused final tests 70 PASS (14.082s) including merge/core/transport/access/
discovery/runner; actual validator fixture 10 PASS (14.410s); existing and
new Node mock tests 16 PASS (0 skips). Separate runs, not full Source CI.
Python tests include independent SQLite write reservation during external
preview, exact actor, missing observation, policy drift before insert
and dispatch, original UUID replay, red/draft vs ready PR, revoked scope.
Shell/JS syntax and git diff check PASS. Historical Core and native
provider directories unchanged, local primary main clean #286. No
PowerShell or Chromium in current environment. Read existing protected
controller Write-Private/ACL and exclusive controller lock: reuse
candidate identified, actual atomic interlock/latest-pin mount and
successor inspector feasibility not proved; no controller code/host
operation. I3 PARTIAL: next protected native dispatch and original
receipt with reviewed actual composition, lifecycle and evidence
acquisition; I4/T2 and full prepublication checks remain OPEN.


### I3 — isolated exact merge and shared Desired

The source test runs Portal discovery, a signed WebAuthn owner decision,
the native adapter and its original child receipt store, independent Git
and impact verification, Registry journal replay and equal Portal/AI READ.
It installs the additive successor policy epoch with default DENY and applies
local scoped choices through the existing owner editor. It checks that a
post-effect base mismatch preserves the receipt and blocks Registry advancement
and that reopening returns the original successful result. GitHub is a synthetic
endpoint, the passkey is virtual, and the framed Registry link is local. This
exercise does not establish live admission, production readiness or browser
acceptance. R7's reviewed Python-only selector requires a staged Gateway/Registry
pair; the production server still needs protected input provisioning and a
compatible versioned Registry service entrypoint.

Source admission checks the event/byte budget and uses the retained capture to
serialize each repository revision before merge. Ambiguous capture remains
reserved. Portal refresh retires changed pending reviews. For rejected,
expired or stale reviews the owner can explicitly repropose the same HEAD
after a fresh check, then approve the new request with WebAuthn. Standalone
native merge uses its existing authorization and entrypoint. Source accounting preserves the
legacy candidate and source-transition provenance; a verified relevant merge
sets Desired with linked PR evidence, while Installed requires technical
proof. An isolated dependency plan orders its prerequisite, requires its
build when appropriate and permits the dependent begin only after exact
technical artifact and action coverage. There is no automatic deploy.

### I3 — real private peer and restart

One isolated E2 uses the actual Unix listener in a separate Registry
process, kernel pidfd peer checks, the managed challenge and exact
authenticated request/response frames. It compares Portal and AI Desired
after reopening Gateway and restarting Registry on the same socket.
The original merge receipt remains the only upstream effect. The R7
server factory rejects the wrong reader, failed peer proof and profile
drift before creating private state or opening listeners. Four focused
E2 and 85 regression cases passed. GitHub and the passkey are fixtures,
and the sandbox uses the same UID/GID for both local processes. The
packaged launcher's protected composition selection, separate host
identities and actual browser acceptance remain open.

### I3 — packaged Registry read startup

The existing Registry command accepts a versioned semantic read profile
from its fixed protected runtime mount. Startup verifies the original
legacy witness, accepted transition and profile digests, independent peer
and frame keys and exact read grants. It opens already accepted state
read-only and selects the existing semantic Unix service. The isolated
restart test loads this profile through that command and checks equal
Portal and AI Desired. It leaves the merge effect count unchanged.
The 106 focused tests and the separate restart test passed. The tests
substitute host mount and identity provisioning. Gateway launcher
selection, protected write verifiers and actual host acceptance are open.

### I3 — protected Gateway reader selection

The normal Gateway reader loader recognizes schema version 5 on its
existing fixed owner read-only mount. It seals the nonce, source, exact
Registry instance and scope, independent frame key, runtime generation
and semantic profile. Startup authenticates the Registry profile and
hold snapshot on the same managed Unix peer. The server requires the
reviewed successor binding for the exact selected transport before
creating private state or listeners.

The isolated E2 loads this mount for the merge and repeats the selection
after Registry restart. Portal and AI read the same Desired, with one
upstream merge. The test denies an incorrect frame-key digest, profile
drift and a missing reviewed binding. The 96 targeted tests and the
separate E2 passed locally. The lab substitutes host mount and UID/GID
provisioning. The ordinary Gateway command still needs to assemble the
reviewed successor from protected inputs. The Registry write profile
and deployment acceptance remain open.

### I3 — protected incumbent history replay

The successor Gateway profile also seals policy-history.json on its
existing read-only mount. The evidence contains the verified incumbent
authority witness and exact old policy-event and epoch prefixes. Before
serving, the candidate reconstructs old admissions using the same
compiled prior policy scopes and verifies the prefixes against the
staged database in a read-only transaction.

The isolated E2 uses this evidence at transition and reopens Gateway
with a fresh load of the same mount. The multi-epoch regression checks
replay after legitimate owner edits and refuses a changed historical
event. The 85 targeted tests and 10 impact/E2 cases passed locally in
separate runs. Remaining fixture inputs include the native guard and enrollment
assembly, the controller latest pin and the current companion receipt.
The packaged command still needs this composition before it can serve.
The protected Registry write path and deployment acceptance remain open.

### I3 — normal Gateway server composition

The ordinary R7 factory assembles the reviewed successor from the version
5 reader mount. The mount seals `successor.json`, which binds the exact
semantic and child grants, policy and companion receipts, controller
record, retained validator and CI policy. Discovery reads the current
Registry source revision over the authenticated private socket. Native
evidence uses the installed GitHub transport and retained Git objects.
The existing activation record fences Registry calls that could enqueue
an ASK before activation.

The isolated E2 opens both ordinary Gateway listeners with the real
candidate builder and Core. It denies an incorrect controller pin before
candidate construction, rejects digest drift, completes one approved
merge and observes the same Desired after Gateway and Registry restart.
GitHub, host mounts/UIDs, the controller's inputs and activation are
local fixtures. Gateway reopen uses a fresh matching companion receipt.
The 107 focused regressions and both isolated E2 scenarios passed. The
packaged Registry still needs its protected write verifier. The controller's
receipt delivery, retained source provisioning and deployment acceptance
remain open.

### I3 — packaged Registry merge accounting

The existing private Registry entrypoint selects source accounting only
on owner profile version 3. It opens the pre-migrated writable state,
checks the pinned controller record, holds a writer lock and admits one
exact owner principal, scope and Gateway policy authority. New accounting
requires NORMAL and a controller reservation. The read-only profile
remains separately available.

The writer verifies a canonical merged-PR observation under the separate
`/run/fortis-registry-source` read-only mount and uses independently retained
`source.git` and `validator.git` plus the pinned validator to recalculate
impact before appending. It reuses the existing authenticated Unix wire
and original-receipt lookup. The isolated scenario rejects missing and
changed evidence and verifies matching Desired after restarting both
services. Two end-to-end cases passed. The focused regression had
103 passes and one skip, and the release catalog validated. The tests use
fixtures for GitHub and evidence publication, controller input and host
mounts/identity. The normal release must still
deliver those inputs through the protected path, and live acceptance
remains open.

### I3 — ordinary source evidence delivery

The native Gateway backend now fetches exact Git bundles for scoped
main and task refs. After verifying the original merge receipt, GitHub
readback and raw Git parents and tree, Gateway atomically retains
one artifact per merge on the owner-provisioned evidence volume.
Registry independently imports that artifact and re-runs the pinned
impact validator. It mounts the same evidence volume read-only and
keeps its validator on its independent read-only source mount.

The authenticated startup/effect check binds the shared filesystem
identity and exact policy and controller pins. Existing proofs are
read back before a retry can return success, and conflicting bytes
cannot replace an original. The local E2 uses automatic proof
publication and reads the existing proof and original receipt after
restart. Both isolated E2 cases passed. The regression had 108
passes and five skips, and the release catalog validated. GitHub
network, host mounts/UIDs, activation and controller data are fixtures.

### I3 — protected startup and pre-stop check

The first Gateway handover uses the existing owner-approved release
nonce and a committed NORMAL controller publication for the exact
incumbent. Owner-managed Registry startup pins the candidate writer
profile and uses the pre-provisioned private socket, the read-only
evidence and validator volumes, bounded scratch, and read-only
controller records. Gateway uses the same evidence volume as writer.

Check authenticates the Registry peer, matches the storage identity and
controller record, and projects the expected companion receipt from a consistent
read-only snapshot in the isolated helper's private temporary storage.
The helper checks the SQLite page footprint against that storage's
available capacity. Apply
repeats and compares the receipt before writing the attempt pointer or
stopping the incumbent. The same memory copy must still match the
owner-pinned Core request/event history, policy revision/rules and exact
stored authority epochs after the schema addition. A pre-stop mismatch
leaves the incumbent in place. After stop, initialization repeats the
history comparison inside the companion transaction on the controlled
clone and rolls that transaction back on drift. Gateway startup still
replays the compiled authority and verifies the new epoch.

The owner launcher now has an explicit PrepareSuccessor action under
its existing independent provisioning confirmation. It uses the
accepted source and image, the exact successor profile digest, and
inactive state/config volumes named for the approved successor nonce.
It mounts only the pre-existing clone as writable and the owner
profile as read-only. The preparation container reserves the same
name as managed startup so the two cannot overlap. It verifies the
pinned v3 SQL prefix, applies the existing additive migration in a
transaction, and reopens the v4 clone to check the original prefix
again. The receipt reports pending transition accounting. An unclear
outcome requires readback before any further action, as for Provision.

For the approved cutover, the same PrepareSuccessor action takes an
independently reviewed transition evidence digest from the owner. The
existing read-only config volume supplies canonical transition-evidence.json
and the pinned transition-main.bundle. The separately pinned validator is
mounted read-only. The artifact carries the approved manifest, independently
obtained predecessor and gap observations, exact PR/body, retained head CI
and post-merge observation. Preparation matches the protected old-state and
profile pins, imports the bundle, verifies the #286 catalog and 31 original
first-parent merge/head pairs, checks the actual delivery parents/tree and
action/workflow pins, and re-runs the reviewed impact validator against the
CI evidence. The accepted Windows source SHA must be the observed merge.

The successful path appends the reviewed transition and replays the normal
Registry projection in the same SQLite transaction as the schema change.
Any incompatible profile or prefix rolls back both. Fresh readback returns
the original transition receipt and admits no deployment. The staged event
opens normal managed Registry startup. The ordinary merge registration
route cannot submit this first event. The protected owner review supplies
the authenticated predecessor, CI and approval facts. Local Git and CI
fixtures exercise their verification and persistence through the owner
launcher and normal writer startup. They establish no actual #286 runtime
readback or owner approval. Actual Windows Docker readback, approved profiles
and volumes, and the Gateway restart seal after new writes remain required.

The local clone preparation regression passed 85 tests. PowerShell 7
on Linux parsed the launcher, rejected missing provisioning confirmation
before Docker and ran Plan. The actual Windows PowerShell 5.1/Docker
path remains unverified.

### T4 — retained CI policy compatibility

Windows PrepareSuccessor recorded the exact #287 transition at source
revision one. The staged Registry peer started. The protected Gateway
Check stopped while loading the retained #286 P5 reference because two
workflow hashes changed in #287.

The schema-five Gateway mount admits the exact historical CI profile for
opening the sealed incumbent configuration and reconstructing existing
authority. The existing functional configuration, policy reference, scope,
and history pins still apply. New legacy review and ingest still require
the current P5 reference, and successor PR review uses its separately
sealed CI policy. The source fixture uses the #286 workflow hashes through
the successor mount and the protected companion preview.

For the corrective delivery, use the already prepared Registry state
volume with the original transition envelope and revision-one receipt.
Under a separate owner confirmation, detach the staged private Registry
from the volume before Accounting. Supply a read-only, canonically hashed
`delivery-repair-evidence.json` and a `delivery-repair-main.bundle` in
the protected config volume. `AccountDeliveryRepair -ConfirmProvision`
binds the accepted Windows main and image, the repaired runtime profile,
the exact preceding receipt, and the corrective PR body, tree and both
Git parents. It independently verifies Release Impact and the retained CI
policy, with exact successful GitHub Actions checks on the corrective
PR head. This one-time operation requires the same catalog, release
profile, CI workflow pins, rules and validator as the original transition.
The protected config retains the original transition evidence.

Read back both receipts. The original #287 event remains revision one
and the corrective merge becomes revision two. The existing v3 prefix
stays sealed and an exact retry returns the same repair receipt. The
ordinary runtime rejects this operation. After protected accounting,
start the isolated peer and obtain Check READY for the same source
before any Apply approval. Windows accounting, Check and Apply remain
open.

### T4 — same-profile restart and exact recovered Gateway admission

The first #288 Apply and independent Registry revision-two readback passed.
Backup committed a verified clone, but the original Gateway exited on
restart: the unchanged transition profile still required the predecessor
authority. The owner verified the exact current/backup receipt, rehearsed
reopen of a copy, and approved the same-image startup profile rebind.
The original container is healthy; the independent typed catalog and
GitHub main readback passed. #286 is retained and #288 is not promoted.

The source correction treats transition as permission for the first epoch,
not as an instruction to repeat it. The existing protected ReleaseGate
distinguishes activated and staged state. Only an inactive exact predecessor
with an approved transition can install the epoch. An exact successor
reopens through the existing policy replay and historical prefix checks.
The inactive snapshot and empty companion remain exactly pinned.
A nonempty active companion is checked through the existing schema,
parent coverage, journal replay, result and capture validation rather than
equality to its original static snapshot. This is local structural integrity,
not a new adversarial rollback proof. Check/Apply/State Freeze snapshot
verification is unchanged. No new state table, provider grant or effect
path is introduced.

The controller admits the changed profile only after its existing exact
image, runtime and Registry delivery/peer checks, for the observed #288
recovery alone. The three owner-protected original release, rehearsal and
rebind records are checked by exact SHA256 and bound runtime identity.
No source, Check/Apply, backup or primary pointer is rewritten. Any other
profile mismatch still fails closed.

Local tests reproduce both original failures and verify unchanged-profile
reopen before and after a Composite operation, no extra epoch or repeated
provider effect, active predecessor rejection, staged pin enforcement
and corrupt companion rejection. The existing private-Unix E2 fixture
uses the original profile bytes at reopen and passes. The exact rebind
controller fixture passes in PowerShell 7 with strict mode and no host
effects. Actual Windows 5.1 controller and corrected packaged image
delivery remain open. The first-transition controller contract does not
yet establish a general successor-to-successor release; the next release
must preserve the exact source-bound enrollment/authority, Registry
lineage, maintenance and protected volume bindings. Do not treat this
source checkpoint as delivery, promotion or live E2 acceptance.

The existing inactive AccountDeliveryRepair path also supports exactly one
additional corrective edge from the recorded #288 revision-two merge and
its exact event digest. Both original evidence envelopes are retained and
verified; the next envelope has separate material. No new event type,
table, normal product route or deployment authority is introduced. Exact
CI, Git ancestry, catalog/profile/rules and validator evidence remain
mandatory; no release operations may have occurred. The local fixture
verifies a third event, exact retry and negative predecessor/evidence cases.
No actual third event has been written.

The explicit successor composition v2 can retain only the verified #288
enrollment source digest with transition disabled, while the independent
outer seal pins the actual new image source. Both original enrollment
pins, compiled stored authority and historical replay must still match.
This preserves existing scope without an extra authority epoch. The
retained enrollment fixture rejects changed grants, source and transition.
The 62 registry regression cases and 3 final focused evidence cases passed
in separate runs. Windows launcher parser and early authorization guards
passed in PS7, not a Windows PS5.1 delivery test.

The ordinary controller still rejects a successor delivery with an existing
successor maintenance context and lacks the later protected handover phase
sequence. A bounded corrective T4 continuation with independently proved
State Freeze and the existing owner/protected release guarantees is a
proposal requiring separate review, not an available or authorized delivery
route. Otherwise complete ordinary I4 handover first. No publication or
merge until accounting, deployment and recovery feasibility are resolved.

The bounded corrective T4 preparation now has two complementary local
preservation proofs. The existing real Git/SQLite repair fixture accounts the
third event on a separate inactive copy; the original revision-two database
and configuration remain unchanged. The new actual R7 factory fixture
stages a copy with a fresh release nonce, synthetic new source digest and
retained enrollment. The compiled authority, policy choices, Core history
and empty companion are identical to the frozen source, with no new
authority epoch or provider effect. A new release seals the actual stopped
source companion, rather than reusing a pre-transition schema snapshot.
The fixture substitutes host mount identity, owner activation and GitHub;
it is not a packaged Windows delivery or combined lifecycle proof.

The historical prefix validator is reused for read-only inspection of the
already-migrated source. The controller accepts a distinct existingCompanion
witness only for the exact recovered #288 source and rechecks that witness
on the cloned state instead of performing another migration. The existing
collector must be retained. The prior first-transition preflight is unchanged.
The paired stop/activation/Return, current interlock anchor, private target
staging and primary promotion integration remain open; the ordinary
successor-maintenance denial is not removed. Local targeted checks passed,
including wrong authority rejection and the extracted PS7 strict-mode
preflight/recovery fixture. No Windows host effects or live third event.

The next local increment verifies the paired Registry checkpoints: exact
revision-two #288 and revision-three correction, unchanged first two
source events, scope, instance, catalog, legacy witness and profile.
No product release operations, installed or reported state is accepted.
This is readback evidence, not authority to switch the pair.

The existing owner bootstrap supports a bounded corrective preview on
the separate target volume with restart disabled and physically read-only
state. Only the internal PROFILE and HOLD_SNAPSHOT frames are admitted;
there is no mutable frame or journal admission. The closed WAL database
must have no sidecars, an exact WAL header and stable file identity
under the dedicated read-only mount. SQLite immutable reading is confined
to this preview; offline corrective accounting reads back the committed
receipt and allows SQLite to close/checkpoint its own WAL, without
manually removing sidecars. The focused real Git/SQLite fixture passed
with negative tests for wrong source, prefix, writable preview and pending
WAL. The 29 other wire/launcher/domain cases passed separately. The
Windows launcher parser/early boundary passed in PS7. Actual host mount,
paired controller Check/Apply/Return and primary promotion remain open.
The original protected NORMAL interlock is not reset or republished by
this code. No new runtime has been launched.

The bounded corrective Check binds the exact recovered #288 source and
original committed NORMAL publication without replacing the interlock.
The owner bootstrap can prepare the target writer as a never-started,
restart-disabled container before the non-writing preview starts.
The existing Check binds independent target image/profile pins, the
original Registry and both candidate container IDs, mount/holder
admission and both replayed checkpoints, rechecking before record seal.
No new product authority or writer is enabled by Check. The local
Git/SQLite/launcher checks passed 10/10, the extracted PS7 strict-mode
pair fixture and embedded Python syntax passed. The temporary source-only
Apply denial has been replaced by an exact checked-image/owner-GO path
after local paired switch and Return tests passed. This is not a Windows
READY receipt or accepted delivery.

The corrective attempt pins the original Check hash and both Registry
checkpoints before any stop. The existing Apply stops the original
Gateway first, then the original Registry, replays its frozen journal,
stops Preview, verifies the staged target and starts the exact dormant
writer. Frozen replay copies the main SQLite file and committed WAL into
private scratch while the source remains read-only, rebuilding SHM on
scratch. The actual managed schema-5 peer proof admits the restarted
listener with its sealed key and live kernel identity. The existing
staged Gateway activation and Return boundaries are retained.

Return requires absence of the activation marker, stops the target
Gateway and Registry before restoring the original Registry and Gateway,
and verifies the original journal. A malformed or active marker denies
Return. After activation, persist the activation evidence before enabling
the target Registry restart policy and publishing the current pointer.
Lost activation ACK or failed pointer publication is resolved by reading
the actual marker and exact attempt, not replaying activation or probes.
The local real Git/SQLite/WAL fixture, extracted PS7 strict-mode
switch/Return/Resume fixture, 24 related regressions and 18 mount-admission
tests passed in separate runs. Windows PS5.1, actual target material and
host switching, Backup/Promote and live E2 acceptance remain open. No live
effect or additional product authority was introduced.

The corrective material projection checks the exact recovered source seals
and matching authority, scope, instance, generation, interlock and key pins.
It preserves the enrollment and policy history while projecting the fresh
nonce, image source digest and distinct key digests. The packaged local
Gateway/private peer fixture passed with separate projected config roots.
The bounded Registry snapshot helper now also prepares a fresh inactive
clone using SQLite backup from a stable main/WAL copy; full replay must
match the original revision-two checkpoint. The real Git/SQLite fixture
passed, including refusal of a nonempty target and unchanged source bytes.
Related source regression (105 tests), R7/tooling regression (25 tests)
and extracted PS7 switch/Return/Resume fixture passed in separate runs.
The extended packaged Gateway/private Unix peer fixture also passed the
joined revision-two source / revision-three corrective clone / revision-four
ordinary Merge & Register path, including exact receipt preservation, shared
Desired and same-profile reopen without repeating the merge. Historical
receipts and provider/WebAuthn actions in that test are synthetic; the local
Git/validator and peer paths are exercised. Owner material preparation now
has a bounded Workfiles entrypoint template reusing the existing preparation,
Bootstrap and Check helpers; syntax and static package pins are checked, not
Windows execution. The actual accepted merge, image and repair evidence pins
are required to open that entrypoint. Exact postmerge source/CI evidence,
Windows mounts, Check/Apply, Backup and Promote remain pending. No new
authority epoch or live effects were introduced.

Publication boundary: the local Source CI Python runner completed
252/252 units, with 251 passing and one existing native cleanup test
timing out in its five-second owner HTTP call under parallel load.
The exact failed test passed in isolation without source changes.
The mandatory browser tests passed separately (18/18); the retained
public validator gate passed 9/9. This is coverage across separate
runs, not an all-green single CI run. Exact-head GitHub Source CI
and Release Impact remain mandatory before the owner merge.


### I3 — owner recovery after a merge

When GitHub has returned a verified receipt and Registry accounting has
never started, the original owner can authorize only that step with fresh
WebAuthn. The confirmation is bound to the exact receipt-backed payload.
The journal records dispatch before the effect. When a write may have
happened, recovery uses receipt readback and leaves missing proof blocked.

When a previously reviewed same-repository PR was merged directly in
GitHub, Portal retires the pending proposal and offers separate accounting.
The eligible merge must be the exact two-parent current successor of the
Registry source cursor, with the reviewed tree/body/catalog/impact and
fresh exact CI. A separate private owner admission and fresh WebAuthn
authorize an external merge record. The original proposal stays stale,
and the verified external merge provenance appears in Desired. The
accounting route performs GitHub reads. The test exercises both owner
routes with the real local Registry, compatible validator and a
synthetic GitHub endpoint, and compares the resulting Portal and AI
Desired. The focused suite passed 175 Python tests, the final focused
rerun passed three, and the Node UI suite passed 17. Protected service
admission, exact remote object acquisition and browser acceptance are
still open.

### I4 — release profile preview

The existing Registry Board and plan display the release-window and State
Freeze requirements, explicit operation pairs across providers, notes and
the restriction digest for each visible component. The same digest binds
the profile, resources and restrictions in the recorded hold. The owner
can inspect a profile before opening a release. Unclassified entries show
unconfirmed restrictions. The existing semantic reads supply the same
projection to Portal and AI. Focused regression passed 69 Python and 18
Node tests. Three focused E2 routes passed with the compatible validator.
The checkpoint below covers the local Check/Apply binding. Profile
editing, automatic enforcement for new mutations and actual browser
acceptance are open.

### I4 — checked maintenance profile binding

For a protected successor source, the existing checked-image record binds
the release subject, attempt, generation and exact restriction digest.
Check persists the original read-only freeze seal and source receipt.
Apply revalidates that original seal against the mounted CHECK_SEALED
record and its exact predecessor chain, plus fresh protected state
evidence. It rejects profile, phase or state drift. The selected path
stops before service stop until the protected APPLY_STOP publisher
exists. Focused regression passed 121 tests. PowerShell wiring was
checked in source, and the Windows/Docker lifecycle and protected
profile-context provisioning remain open.

### I4 — phase publication and readback

The owner controller records a protected Pending intent before the
single-volume write and marks it Committed only after exact readback.
The helper checks the predecessor, serializes writers, atomically
replaces the mounted record and flushes it. DRAINING can be recorded
with shared worker reservations still present. Later phases need the
exclusive drain lock. A lost acknowledgement is recovered by reading
the exact old or new record. A matching new record is left in place.
Check and Apply require the same committed protected phase and digest.
The 134 focused tests passed, including Linux lock contention and a
simulated failure after rename. The PowerShell recovery SelfTest, fixed
mount behavior and operational provisioning still need Windows proof.
The checked-image Check source path now calls this publisher after
admitting the running incumbent and verifying its single writer.
It reports MAINTENANCE_DRAINING until the matching drain evidence exists.
Once that evidence verifies, Check saves one receipt by attempt before
publishing FROZEN_BEFORE_CHECK and CHECK_SEALED. It verifies the mounted
phase and saved state before reporting READY. Retrying from an
interrupted or completed transition uses the same protected receipt
and exact phase readback. Apply also verifies that receipt and its
transition chain. The APPLY_STOP transition and the protected evidence
producer still need integration. Focused regression passed 135 tests.
The PowerShell Check-start and seal-resume SelfTests still need PS5.1
execution.

### I4 — Apply stop preparation

Apply reuses the original protected Check context and reconstructs the
read-only verification request from the saved Check and current committed
CHECK_SEALED. After verifying the mounted phase and exact frozen receipt,
it saves an APPLY_STOP intent bound to the source and Check records,
attempt, restrictions and target image. Exact readback makes the saved
intent reusable after interruption. The existing controller still keeps
the source running at this boundary. Target/Return pin handover and the
protected release recovery pointer must be wired before Apply can publish
the intent and stop the source. The 136 focused local tests passed,
including Linux APPLY_STOP exclusion while a worker is reserved.

### I4 — receiving a frozen Gateway handover

The staged target accepts its exact generation and STAGED_TARGET_FROZEN.
Return accepts the original generation and RECOVERY_HOLD. The reviewed
startup checks the mounted lock and independently supplied phase pin,
attempt and restrictions, along with the exact active freeze from the
authenticated Registry peer. The check runs before listeners open.
Mutable operation admission remains closed. An interlock mount without
reviewed startup composition is refused. The local regression suite
passed 161 tests and the three E2 merge/Desired scenarios passed
separately. Supplying the protected inputs and runtime mounts from the
Windows controller, proving staged preparation without unintended
effects and wiring source stop and Return remain open.

### I4 — cross-process drain feasibility

Keep the existing controller lock and ACL/Write-Private path for the host
latest record. The interlock directory must remain a dedicated stable
read-only mount, with separately pinned generation and latest record digest.
Gateway reservations use a shared Linux lock on its directory inode.
After publishing DRAINING and verifying the exact Registry hold, the
controller inspector must hold the exclusive lock on the same inode
through state inspection, companion inspection and validation of the final
seal. It returns that exact source receipt with the seal as one result.
The PowerShell wrapper compares returned digests with its input pins.
The 72 focused tests passed, including real Linux lock contention and
refusal of a changed interlock. Mount and ownership checks used fixtures.
The PowerShell wrapper and Docker Desktop mounts still need host proof.

In the applicable protected delivery checks, prove the same inode is
visible to every mutable participant, verify
read-only flags and actual UID/GID, and compare both protected state and
companion receipts. Hold an admitted mutation across DRAINING, verify that it
can settle and that new effects fail closed, then acquire exclusive drain
and compare the latest anchor again. The successor inspector reuses the
incumbent state receipt and pins the exact companion schema and witness.
Prove generation handover, protected completion and Return against the
same durable controller anchor through the required delivery checks. Unknown peer, worker state or proof leaves the
hold active. No Windows preflight or host action was executed for this
checkpoint. The successor inspector is source-wired to the existing state
helper with two read-only volume mounts. The protected writer, operational
Check hook, actual mount and full worker coverage remain release prerequisites.

The local Source CI runner completed 193 suites with zero failures and
20 skipped Python cases, followed by 16 passing Node tests. The compatible
successor validator fixture was tested in a separate run. Remote exact-head
CI and Windows checks remain delivery gates.

### I4 — exact image identity at protected completion

A source merge produces Desired before the image exists. The hold binds the
source and catalog at begin; its artifact digest can still be unknown.
Protected completion requires the controller receipt and the independent
target readback to identify the same exact image and the same source lineage.
An artifact already pinned by the hold must match both. The completion
projection carries the verified image and preserves the original attempt
across all phase transitions. Tests cover the missing and mismatched
artifact and changed source or catalog. The protected verifier, Registry
event wiring, dependency readback and host completion are still open.

### I4 — retained profiles and frozen companion witness

The paired profile projector also accepts an installed schema-2 successor
when the trusted caller supplies the exact incumbent Gateway source digest
and both independently verified profile digests. The new seal retains the
original enrollment source and the existing authority, context and
semantic pins. It binds the new image source and release nonce and
requires fresh peer and frame keys.

For a reviewed staged handoff, the existing read-only companion check
replays the stored authority and the entire companion against the exact
staged digest, including completed requests and receipts. The historical
path still requires an empty companion. The local tests exercise a second
profile projection and a nonempty companion with policy history.

A frozen Check can also ask the authenticated internal Registry peer for the
source cursor, source/snapshot revisions and event digest. The Registry
derives the hold digest from the same read-only replay. Check verifies it
against the protected handoff. Repository cursor and release Desired can
differ after an accounted no-deployment merge; the selected attempt source
continues to be verified through the hold. A delivery requiring a specific
cursor binds it in its protected controller receipt. When inspecting the
companion, Check re-reads the whole proof afterwards. Ordinary profile
reads keep their existing shape.
This proves the staged peer's accounted source and hold. Runtime
compatibility, live Installed and readiness to stop the incumbent require
their existing independent evidence. Host provisioning, protected begin and
ordinary phase publication remain open.

For an already installed successor, the same paired profile projector now
also has a frozen-target projection. It binds the independently supplied
STAGED_TARGET_FROZEN record and startup handoff to the incumbent instance,
scope and source generation, sets the same distinct target generation and
interlock pin on both profiles, and seals the fresh companion digest. The
original enrollment, authority, history pins and historical corrective
projection remain unchanged. The caller must independently verify the
controller record, hold snapshot, companion and exact source/image before
using this material. This is not a host writer or proof of a paired begin.
The focused fixture and existing gate regressions passed 15 tests, including
mixed instance/scope/generation and stale interlock refusal, and the previous
isolated revision 3-to-4 product flow. The projection is not yet invoked by
the Windows controller. A pre-stop Check must not pretend the target is
already in STAGED_TARGET_FROZEN; actual target admission and later restart
require the independently protected phase handover and latest-pin transport.

### Bounded #289 bootstrap source accounting (owner-approved development)

The installed #289 semantic enrollment cannot admit the delivery's production
subjects, and its installed writer/controller cannot perform a normal paired
begin. The two historical delivery repairs are exhausted. The owner accepted
source development of a distinct bootstrap migration, not live merge or host
GO. `BOOTSTRAP_MIGRATION` is restricted to the exact #289 source receipt and
revision 3, with no release events before its append. It is not a Composite
receipt or a deployment authorization. The retained authority, catalog and
profile pins are unchanged. Existing repair verification and the confined
SQLite clone helper are reused. The pre-merge review pins the whole proposal,
exact source prefix, authority and independently witnessed owner/backup/primary
references; separate post-merge evidence binds that review and exact Git edge,
CI, body, impact and bundle. The owner controller must authenticate those pins,
review ceremony, source/target identities and writer exclusion before invoking
the inactive-only account helper. Hash fields alone do not authenticate them.
The offline helper rereads the full committed journal and original receipts;
exact retry returns the original receipt, no live source register is admitted.
Local real Git/bundle + SQLite fixture and source-lineage regressions: 12 PASS,
43.377s. Owner proof/mounts are fixtures, not a host rehearsal. Protected host
entrypoint, paired begin, phase publication, completion and Return remain open.

### Protected paired begin (local domain and gate)

The narrow owner-controller pair is exactly Gateway production plus Registry
non-production in the reviewed repository, not a public group lifecycle.
The intent binds the current replay checkpoint, both exact Desired/CAS inputs,
prepared image digests, and two independent controller/compatibility evidence
references. The trusted verifier must authenticate and independently validate
those references; ordinary semantic operations cannot dispatch this event.
Two deterministic per-target events are appended in one SQLite transaction,
with contiguous replay and an exact shared pair digest. Only Gateway's
specific dependency on the Registry in the same pair can use this proof in
place of prior DEPLOYED. All other dependency, subject, scope and overlap
checks remain; unrelated holds refuse the pair. Begin never creates Installed
or pins Desired artifact from a staged image. Later technical observation must
match the exact prepared artifact and coverage. The gate accepts either its
original sole hold or the exact two-member pair, not a surviving member or
additional hold. Completion cannot clear the interlock while either paired
hold remains. 50 focused source/domain/journal/gate tests passed (12.405s),
including atomic rollback, original receipt recovery, cursor ahead of Desired,
frozen handoff/Return, stale proof, incorrect prepared artifact and conflicts.
The fixture verifier is synthetic; protected host evidence acquisition,
private writer composition, latest phase pin, pair completion and actual
controller delivery remain open. No policy enrollment is extended.

### Independent latest phase pin (local publisher and runtime composition)

The protected host publication record remains authoritative. Its current
phase/generation/sequence, interlock digest and exact frozen Registry digest
are projected on a second fixed, root-owned read-only mount, not in a release
rollback volume. The runtime cannot derive its own expected digest from the
interlock. Missing, Pending, stale, mixed or aliased mounts fail closed.
The publisher retains the existing shared reservation/publish locks; publish
first persists Pending projection, then the exact next interlock. Only after
the host independently persists Committed may it commit the projection.
Readback/recovery distinguishes previous/next and Pending/Committed, without
resetting the chain or blindly replaying. Static compatibility mode remains
restricted to its original phases. Schema-3 successor composition and matching
Registry writer opt into the current pin; initial staging still pins the exact
handoff, later restart requires current phase/hold and Gateway activation
marker, and Return requires the source generation. Ordinary effect policy is
unchanged. A subsequent projection preserves original enrollment/authority.
Local publisher/reader fixture 7 PASS, including a real rename/fsync fault and
old generation refusal; changed runtime composition 31 PASS (30.228s), including
existing packaged-peer E2 fixture, both profile readers, Backup/Promote phases,
activation and exact hold proof. Owner host mounts, authenticated bootstrap
seed, actual durable Windows publication and controller integration are not yet
proved. The old #289 static reader cannot return after its shared record is
advanced; the one-time bootstrap must retain the old interlock and introduce
the new operational interlock on a distinct stable volume, or prove an equally
safe compatible recovery path. No new generation may start merely because
its projected material exists.

### Host publication v2 and paired close (local source checkpoint)

The existing protected controller has a v2 publication branch that binds
the exact source record, previous/next phase and independent Registry pin.
It durably saves Pending, verifies the mounted result, durably saves
Committed and only then commits the projection. A retry resolves both
lost acknowledgements by exact readback. The helper allows only the two
fixed operational volume names for this mode, checks both volumes and
writer exclusion; the v1 publication branch remains unchanged. PS7 syntax
and isolated old/new publication selftests passed, including lost publish
and commit acknowledgements and changed-pin denial. 15 source regressions
passed. This does not prove Windows PS5.1, actual Docker mounts or host
provisioning. The v2 anchor seed, lifecycle callers and protected target
handoff remain to be composed.

Successful paired closure reuses the original exact pair intent and the
existing protected observation model. Two deterministic close events
are appended in one transaction only after both exact prepared artifacts
have accepted technical observations and all current action coverage is
verified. Ordinary individual close cannot close either paired hold.
Replay checks contiguity, pair identity, target CAS and exact accepted
evidence; second-append failure rolls back the pair. Identical readback
returns original receipts. Return or failed deployment is not successful
completion. The trusted controller verifier must still supply real
independent per-target evidence and phase authorization. 12 lineage tests
and 45 domain/journal/planner/gate regressions passed locally. In particular
the host must reconcile a changed Registry replay during observation/close
and a lost acknowledgement before NORMAL from independent evidence; a
restart at an earlier frozen digest cannot be treated as readiness.

### Bootstrap launcher, operational seed and v2 Check (source checkpoint)

The existing Windows owner Registry launcher now has a distinct
AccountBootstrapMigration action. It requires separately pinned review and
post-merge evidence, clean exact Windows main, the matching immutable Registry
image source, the existing owner GO, nonce-bound inactive state/config/source
volumes and no holders. It dispatches only the existing confined source
accounting helper and verifies the exact #289 predecessor, revision-4
receipt/checkpoint and explicit false host/deployment admission. It does not
prepare the clone, authenticate the owner review or start a service.

A bounded interlock seed helper copies the exact original retained NORMAL
record, verified against the independently pinned old read-only mount, onto
two distinct fresh operational mounts. It first writes Pending projection,
then the original record; only the independently durable owner host commit
permits committing the projection. Exact readback handles interrupted seed.
No general genesis, reset or rollback is supported, and the old record is
not modified. The host seed orchestration, writer exclusion and volume
provisioning still need to be wired.

The existing Check/Apply pre-stop path can consume a protected v2 context:
its independent Registry digest is forwarded to each Check publication,
and its sealed inspector mounts and checks both operational volumes under
the existing exclusive reservation, before and after the same inspection.
The v1 path is preserved. No new readiness claim or actual source stop.
43 focused tests and three isolated PS7 Check selftests passed; actual
Windows PS5.1, Docker mount identity, authenticated controller evidence and
staged lifecycle remain unproved.

### Host seed orchestration and completion recovery (source checkpoint)

The existing controller includes an internal seed orchestration function
(not a separately selectable action). It binds the exact accepted #289
release/primary records and original retained publication, requires the
old Gateway and Registry stopped with no automatic restart, preserves
the historical preview, reuses the all-holder alias guard and confines
the helper to the old RO mount and two fixed fresh operational mounts.
It persists and verifies host Pending before seed and host Committed
before projection commit; exact readback recovers both lost ACKs.
Ordinary v2 publication refuses a Pending seed. The isolated PS7
orchestration selftest passed; actual owner admission, physical stop,
mount creation and the normal controller caller remain open.

Protected completion recovery reuses the exact paired close request
projection and full journal replay. The read-only recovery witness requires
both original close receipts at the current tip, unchanged source
revision/cursor/profile, no holds, and both matching accepted observation
receipts. Later source or release events invalidate that witness.
The existing confined RO SQLite scratch replay handles the frozen DB/WAL
without mutating the source or invoking a writer. This is readback evidence,
not NORMAL authorization: the host must bind it to its independently
retained COMPLETION_PENDING intent and real post-promote proof. 52 local
lineage/domain/journal/controller regressions passed, including denial
before close, exact recovery after close and refusal after a new source
event. The operational path through protected writer, phase publication,
activation/Return and actual Windows proof is still incomplete.

### Publication predecessor recovery and integrated bootstrap clone

Before replacing a committed v2 phase intent, the controller now reconciles
that exact predecessor's mounted projection using its retained original
transition. An already committed readback fsyncs both directories and needs
no additional commit helper invocation. A lost ACK before the projection
commit is recovered before saving the next Pending intent. Apply's protected
pre-stop verification also reconciles its exact CHECK_SEALED phase; the
binding-only reader remains nonmutating. Old v1 behavior is unchanged.

AccountBootstrapMigration now composes the existing confined clone helper
with source accounting, rather than assuming an independently prepared
database. The owner launcher mounts only the exact accepted #289 state/config
volumes read-only, checks the known holder set, and retains the new nonce-bound
inactive target. The helper pins the original Registry profile, checks retained
instance, scope, profile, authority and grants, rejects aliasing, copies a
fresh target or verifies the incumbent prefix when recovering a prior copy.
The source is never altered. This is staging, not stopped-source proof: the
controller must independently verify exclusion and unchanged source after
actual stop. The initial #289 static runtime cannot participate in the new
operational DRAINING; its bounded cutover must retain a pre-effect owner
review/Check, prove physical freeze and then seal the frozen pair, rather
than fabricate a live drain or reuse the exhausted corrective exemption.
PS7 v1/v2 publication selftests and 44 focused source/real Git/SQLite
fixture tests passed; the first fixture reused a directory with WAL/SHM
sidecars and was corrected to use a separate fresh directory without
deleting sidecars. No live host proof, trusted pair writer, actual cutover,
post-Apply completion or Return is implied.

### Current phase delivery admission and physical bootstrap freeze

The v3 receiver's immutable staged handoff remains the startup pin for
STAGED_TARGET_FROZEN, not a forever-current Registry checkpoint. The
read-only delivery helper verifies the current independently pinned phase
and binds the authenticated PROFILE replay to the same hold snapshot.
Subsequent frozen phases and NORMAL, including later source-only merges,
are checked against current state. Already-running draining source
inspection is distinct from startup: DRAINING through APPLY_STOP can be
inspected read-only, but cannot admit a restart or new effect.

Use one protected host publication file
`maintenance-publication-v2.json` for the operational interlock chain,
outside both rollback and mounted projection volumes. No historical v1
file is fallback authority. The owner controller reads it against the exact
retained release record/source lineage and rechecks after the actual
packaged-image preflight. Compare current phase/Registry pin separately
from retained image/profile, companion, evidence device/inode and authority
pins. A completed later release must explicitly rebind this one anchor to
the new source record before a new ordinary attempt; rebinding and recovery
callers are not yet integrated. Old v1 immutable images receive their
original preflight arguments. The Gateway create/admit and staged collector
paths now select both fixed RO operational mounts only on verified v2
delivery and check the frozen peer before and after preparation.

Before any seed write the bounded #289 bootstrap now requires an exact
pre-effect Check SHA and durable attempt pointer, original source/pointer
and image binding, worker quiescence, full frozen Gateway receipt equality
and replay of the retained stopped Registry revision-3 checkpoint. It
rejects a changed Gateway receipt, Registry checkpoint or primary/backup
pointer before seeding, and rechecks the stopped source identities after
the full receipt. This does not create the pre-effect Check or authorize
the physical stop. The caller must persist the original Check references
before the first stop. The guarded private pair writer, bootstrap
pre-effect Check/stop orchestration, Registry receiver creation and
post-Apply Backup/Promote/completion/Return remain open; the mandatory
pre-stop deny is unchanged. 80 local regressions and isolated PS7
publication/runtime/frozen-proof fixtures passed. Real PS5.1, mount
identities and owner-host lifecycle have not been accepted.

### First bootstrap pre-effect Check and private paired begin

The one-time `Check -Bootstrap289` source path uses the existing manual
prebuilt-image Check and nonce, exact Gateway and Registry image IDs,
Registry profile SHA256, review SHA256 and independently collected
post-merge evidence SHA256. It is not ordinary live successor Check:
no DRAINING is claimed for static #289, no target listener starts, no
hold is opened and no deployment is authorized. It confirms the exact
retained source/pointers, running incumbent identities, original
revision-3 Registry replay, worker quiescence and inactive target volume
exclusion. The packaged Gateway probe validates both sealed profiles,
fresh distinct peer/frame keys, unchanged enrollment and retained
companion/authority on the read-only incumbent Core. The packaged
Registry probe replays the inactive revision-4 accounted clone, reads
the exact migration receipt and both verified Desired/CAS items, and
compares its private binding to the Gateway binding. Compatibility
includes both immutable artifact IDs. The previously accepted #289
Gateway backup receipt and Registry backup manifest/bytes are read back;
the final Check rechecks source/candidate and record pins without
re-reading the full backup a second time. The existing durable Check
record binds the result; report is `BOOTSTRAP_CHECKED_ONLY` with
`deploymentAuthorized=false`. A later fresh Check may not silently
reuse an already-seeded operational anchor.

The offline private paired writer reuses the actual protected
`ReleaseDomain.protected_begin_pair`, exact original Check inputs,
independent seeded NORMAL projection and exclusive stable-inode
reservation. It verifies source accounting, review/prefix, both Desired
items and exact compatibility digest; its fixed controller actor and
deterministic pair IDs make a lost ACK an exact two-receipt readback.
Neither Installed nor host admission is asserted. The original source
accounting guard still requires a pre-product journal; only the narrow
prefix replay is shared for paired begin recovery. No new RPC, service,
database or reusable repair authority is introduced.

These are source/local proofs, not authenticated owner GO or actual
Windows Check acceptance. The pre-effect Check is connected to the
existing controller; the stopped-source attempt/GO authentication and
private writer invocation must still be integrated with seed, final
profile projection, Registry receiver creation and protected Return
before enabling Apply. In particular a supplied owner-review proof
digest is a binding/reference, not proof by itself. Independent
technical observations, Backup/Promote/completion callers and anchor
rebind remain required. The explicit pre-stop gate stays closed.
Local SQLite paired begin and lost ACK, immutable backup readback,
packaged retained authority/E2 fixture, source and controller
regressions passed (see canonical plan for run details).

### Durable owner intent, private writer bridge and bootstrap phase plan

The first bootstrap controller needs an independently retained owner
pre-merge review, not only the review digest supplied with an inactive
clone. The Registry's checked replay now returns a digest of the complete
review object except its own `ownerReviewProofDigest` (canonical JSON,
SHA256), avoiding circular hashing. The internal owner bridge checks an
existing ACL-protected JSON record under the owner Fortis root using the
ordinary protected record reader. The exact four-field record has
`schema: fortis-registry-bootstrap-review-v1`,
`decision: APPROVE_BOOTSTRAP_MERGE`, `reviewContentDigest` and
`reviewedAt` (positive integer Unix seconds). Its exact file SHA256 is
the review's ownerReviewProofDigest. The record must be independently
created and retained before the actual reviewed merge; the local timestamp
alone is not independent proof of chronology. The owner additionally
confirms the exact Check hash interactively at Apply. No proof record is
fabricated from the post-merge Check.

The internal bridge consumes the original protected attempt and pointer
with the Check path/hash, owner review record path, stable owner GO,
sourceReceipt and exact checked image/profile/evidence. The GO pins the
attempt UUID, Check/source/compatibility/review/evidence/proof digests,
new generation and recorded time. The existing seed helper revalidates
actual stopped #289 and full frozen source equality. The private
networkless Registry writer mounts only its inactive state RW, runtime
config RO and the two independent operational mounts RO. It derives
canonical authorization from the retained GO and full frozen receipt,
replays the exact paired begin and saves its result through the existing
bounded, durable attempt serializer. The same intent recovers lost ACK;
a changed GO, review or result is not a new permitted begin. The old
Registry, Gateway and static interlock are not modified by the writer.

The writer's phase plan is tied to actual two original begin receipts,
the exact hold snapshot, owner intent and seeded NORMAL record. It uses
the existing transition validator and derives the same five planned
phases from DRAINING through STAGED_TARGET_FROZEN, with proof kind
BOOTSTRAP_PHYSICAL_FREEZE. These source phase names are a planned
offline publication chain after physical stop, not an attestation of
live DRAINING by #289. A lone surviving hold, changed generation or
changed seed is refused. Final handoff is a projection only; it is not
publication, startup, Installed, or deployment admission. The bootstrap
Gateway Check also uses the existing companion quiescence predicate:
pinned unresolved composite parents are not admissible.

These internal functions have local real SQLite and isolated PS7
fixture evidence, not actual Windows execution. The pre-merge proof
creation/admission before clone accounting, top-level Apply durable
attempt/stop and Return orchestration, phase publication with real
material/readback and final profiles/receiver provisioning remain open.
The existing pre-stop deny remains. No owner live GO, policy expansion
or new public operation.

### Prepared physical cutover and early Return (source/local)

Bootstrap Check now requires the existing independently protected review
record path in addition to the previously reviewed hashes, and binds it
into the immutable Check. Explicit checked-image Apply reaches the same
read-only source/compatibility/review checks, but still refuses before any
attempt or stop while the final receiver path is unavailable. No owner GO
is solicited for this incomplete delivery.

The internal Prepared driver uses the existing record and attempt pointer:
exact owner GO, fresh compatibility and original Check source receipt,
bounded durable save, pointer last, readback before the first effect. The
physical helper verifies the retained #289 primary and old Registry
identities; only those identities allow the transient disabled-restart
policy. Stop Gateway first, then Registry; read back actual state even if
a Docker command reports an error, never blindly repeat a satisfied effect.
The existing frozen Check then proves unchanged original Gateway receipt
and revision-3 Registry. The original source record and static interlock
are unchanged. The early Return is now dispatched by the existing Return
route for a bootstrap Prepared attempt; it excludes any new receiver or
activation marker, starts Registry first and verifies original checkpoint
and live peer, then restores Gateway and original restart policies.
A late Gateway receipt change denies freeze but does not require restoring
older bytes when no candidate receiver or activation exists. Return retains
the inactive clone, any paired holds and operational anchor; no cleanup,
closure or automatic reseed. A repeated already-Returned readback performs
no new effects. Later receiver Return still needs its separate exact
pre-activation/activation proof; early Return must not be used for it.

The private begin result can be independently recovered on an exact RO
journal replay instead of reissuing a writer after uncertain ACK. Existing
stable main/WAL copy is used if sidecars remain; no sidecar deletion or
immutable read of uncheckpointed bytes. The controller reads the same
original two events and phase plan; before publication it compares the
protected attempt's stored result. The first four planned phases are
published by the existing Pending/Committed publisher under the controller
lock. Re-entry reconciles the exact current prefix and publishes only the
missing suffix to APPLY_STOP. STAGED_TARGET_FROZEN is not published by this
helper, because final receiver material and mount proof are still needed.
No fictitious live DRAINING proof or Installed assertion.

Local PS7 extracted actual-function fixtures cover Prepared save/pointer
ordering, changed source/compatibility before effects, partial stop and
Return, lost Docker and writer ACK, already-returned readback, changed hold
readback, and Pending publication recovery. The existing Windows PS5.1
serializer, actual owner proof chronology, Docker host stop/start and
mount behavior are not proved by these fixtures. Full top-level Apply
invocation of the Prepared driver, final generation profiles/Registry
receiver creation and later Return/Backup/Promote/completion/anchor rebind
are still open. Integrate and remove redundant full freeze inspections
only when the connected protected controller path establishes the same
lock, identity and exclusion; do not reduce evidence merely for timing.

### Bootstrap final profile sealing — source/local checkpoint (2026-11-28)

After the protected paired begin and committed APPLY_STOP, the internal
Prepared driver now seals the final Registry and Gateway material. The
shared maintenance contract reconstructs the exact phase plan from the
original seed, authorization, pair and two begin receipts, and verifies the
committed host publication and exact predecessor. It projects the next
handoff without publishing STAGED_TARGET_FROZEN. The already reviewed
nonce, key pair, authority and retained profiles remain bound; only the
required final generation/handoff pins change. The pure hold/phase
validation is shared by both image packages, avoiding the previously
unavailable Gateway-only import in the Registry image.

For this bounded bootstrap, retain the preliminary config/evidence in
`fortis-registry-config-e13b-<id>-prepared` and
`fortis-r7-registry-reader-<id>-prepared`, separately from the standard
final config volumes. Check requires the independently prepared final
roots to be empty, private, correctly owned and pinned by device/inode.
The helpers read preliminary files and the frozen state read-only and
write only the corresponding final config root under the existing owner
lock. They check exact allowlists, file digests, mount/holder identity and
the current APPLY_STOP anchor; incomplete exact file prefixes can resume,
but unknown or changed files are refused. Each final seal is independently
read back RO before recording its digest and cross-profile binding in the
durable attempt. No additional key rotation, state database or service is
introduced. The existing original-volume provisioning procedure does not
automatically provision these two additional config/evidence roots;
actual owner preparation, ownership/mount proof and capacity admission
are still required. Retain the prepared roots on Return and during
recovery; no automatic deletion or reseed.

Local validation: 112 focused Python tests PASS, separate integrated
retained Gateway/Registry fixture PASS, seven extracted actual PS7
selftest groups PASS; isolated packaged-source import checks cover both
image layouts. These are not Docker image builds or Windows PS5.1/host
acceptance. The original host Review chronology remains unproved.
Actual receiver creation, durable receiver ID and independent readback,
publication of STAGED_TARGET_FROZEN, top-level Apply connection, later
Return/Backup/Promote, technical close and single-anchor NORMAL rebind
remain open. Apply still denies before the protected attempt/GO/stop;
the internal Prepared driver does not authorize an actual deployment.

Review correction: the two pre-effect Check invocations must mount the
respective standard final profile roots at /target, read-only and
volume-nocopy. The initial local sealing tests exercised the helpers,
but did not cover these actual Docker arguments. The missing mounts
are now connected and covered by the existing controller source test.
The runtime acceptance boundary is unchanged. For the next connected
cutover increment, create and inspect the dormant receiver before
publishing STAGED_TARGET_FROZEN, start only against the committed
generation/hold pin, then independently authenticate its peer and
checkpoint. Use the existing controller lifecycle and exact-ID recovery;
do not add another independently selectable deployment route.

### Connected bootstrap Apply / Resume / pre-activation Return (local checkpoint)

The existing Apply driver now consumes the durable Prepared transition,
rather than treating its internal helpers as a separate deployment. Before
any receiver effect Check requires the exact named volumes. The controller
records the deterministic nonce-bound Registry container intent, creates
it dormant with restart=no and an exact attempt label, inspects the full
image/command/UID/mount identity, and durably records the ID. A lost
create ACK can only reconcile the exact never-started container, not
another process or configuration. The existing latest-pin publisher then
commits STAGED_TARGET_FROZEN; only after both projections match does the
controller start the receiver. Its authenticated Gateway-side PROFILE
and hold/companion replay must match the original paired begin, source
checkpoint, final profile and generation. An existing sealed result
from this same continuous lock can be reused before create; a re-entry
without that result independently reads the sealed material again.

The verified delivery is saved in the Gateway runtime DTO before the
ordinary clone, collector and Gateway creation. The existing Resume
path verifies the receiver/phase, real activation marker and exact
candidate; a lost Gateway create ACK adopts only the never-started
exact run and records the ID before start. Activation ACK is checked
against the independent marker, not retried blindly. Persist activation
before restoring Registry restart policy and publishing current.json.
An already Complete record recovers only the missing pointer, never
replays activation. Before activation, Return checks the retained original
and actual marker, stops the exact new Gateway before its Registry, then
restores the original Registry before Gateway. A present/unknown marker
denies rollback; no clone, hold, evidence or anchor is deleted.

Local connected controller fixtures exercise create/start/publication ACK
loss, checkpoint/anchor rejection, failed probe and pre-activation Return,
activation ACK and current-pointer recovery. They run actual PowerShell
functions with simulated Docker effects, not Windows/Docker acceptance.
The public bootstrap Apply gate remains until Backup/Promote, protected
technical pair close and NORMAL/anchor rebind consume this same attempt
and phase proof. The ordinary successor Apply gate also remains; do not
substitute the one-time #289 bootstrap for the ordinary lifecycle.
A Prepared interruption before Gateway create uses the safe Return unless
the exact continuing pre-create boundary can be independently resumed.
No source/host publication or operational GO is implied.

### Connected bootstrap Backup / Promote / technical completion (local checkpoint)

The existing Backup and Promote entry points now consume the same protected
bootstrap attempt. Backup commits BACKUP_FROZEN, disables restart and stops
the new Gateway then Registry, clones the Gateway using the existing state
helper, and independently verifies a bounded local Registry state reserve.
Check additionally binds the empty owner-prepared
`fortis-registry-bootstrap-backup-<id>` volume by device/inode (UID/GID
20002, mode 0700, exact RO Check mount). It must be provisioned and its
capacity verified by the owner; retain it and the exact sealed config.
This is a pre-close recovery reserve, not a new general backup service or
independent host-loss recovery proof. The new pair restarts Registry-first
against the authenticated frozen checkpoint; the old pair remains retained.

Promote binds the immutable release and verified backup, saves the intended
primary transition before rename, independently reads the exact resulting
container identities, and writes the primary pointer. No rollback to the
old pair after activation. Completion binds fresh live health/peer
observations, exact protected Apply/Backup/Primary record hashes and
independently reread frozen state/reserve. Stop the new pair with restart
disabled before closing. Publish COMPLETION_PENDING first. The confined
Registry helper atomically records both technical observations and both
close events; readback of exact receipts is independently RO and is tried
before any possible write. A failure on the last write rolls back the
whole transaction. Only verified empty holds and the exact replayed
checkpoint can project NORMAL. Rebind the existing host anchor to the
current immutable release without resetting sequence or replacing the
operational volumes; commit NORMAL and start Registry, authenticate its
checkpoint, then start Gateway. Lost acknowledgements reconcile the
same durable intent; unused stale pre-pending observations are retained
and refreshed, not silently reused for a new write. An unresolved stale
pending write fails closed.

Local SQLite tests exercise the real reserve, proof projection, atomic
rollback and lost-close-ACK replay. The connected extracted PS7 fixture
runs actual Backup, Promote and completion functions against simulated
Docker effects and journal replies: reserve/rename/close/NORMAL ACK loss,
no duplicate clone or closure, exact restart ordering, and same-intent
re-entry. These are local source checks, not owner Windows PS5.1/Docker
acceptance, and do not establish host timings. Ordinary successor
convergence (including subsequent maintenance), exact pre-merge review
creation/admission, owner provisioning and real host acceptance remain
open. Both top-level Apply gates remain before any deployment effect.

### Re-audit corrections (2026-11-29)

Latest-pin receiver admission consumes the exact protected Check's existing
companion witness and the incumbent runtime's nonce-bound state volume.
The #288-only historical exception remains limited to its original path.
After committed NORMAL and exact primary/completion binding and live peer
admission, a later ordinary Gateway Backup no longer enters the original
bootstrap BACKUP_FROZEN attempt. It does not claim another paired Registry
reserve. An incomplete NORMAL restart remains a Promote recovery, not a
new backup.

For an expired COMPLETION_PENDING write, independently replay the stopped
Registry before any effect. Exact existing receipts recover the original
completion even after expiry; absence requires all four operation IDs
absent and the exact held checkpoint unchanged. Persist the original
no-effect witness and next RECOVERY_HOLD before publication. Only the same
held target generation, exact pair and already activated Gateway can
restart passively for fresh observations; retain the superseded proof.
The existing atomic close and NORMAL path then consumes the renewed
pending proof, not expired evidence. Partial/conflicting/unknown outcomes
do not renew, write or clear holds. No old-source rollback or new actor
authority. The two Apply gates remain pending ordinary successor
convergence and final source/host acceptance.

#### Ordinary successor begin — local controller checkpoint (2026-11-29)

The ordinary path must not use the bounded #289 repair or a second SQLite
writer. The manual prebuilt Check with exact `-SuccessorRegistryImage` and
`-SuccessorRegistryProfileSha256`, current latest-pin source, new nonce and
worker-quiescence confirmation independently checks prepared Gateway and
Registry material, retained authority, a stable RO Registry copy/replay,
both exact Desired records and live authenticated checkpoint. It returns
`SUCCESSOR_PAIR_PREFLIGHT_ONLY`, not READY, while ordinary Apply/Return
remain incomplete. No hold, owner GO, phase or attempt is created by that
public Check.

The internal controller producer saves the exact owner-confirmed intent
before publishing root-owned `begin.json` on the existing operational
anchor (no new volume). The private authenticated
`CONTROLLER_PAIRED_BEGIN` frame is internal-only and carries just the
intent digest and readback flag. It uses the existing Registry writer,
exclusive interlock reservation and atomic paired begin. The mount,
authority, source NORMAL and complete predecessor must match; stale
unapplied intent is denied. Exact receipts at the replay tip permit
idempotent recovery; the protected context is saved before the existing
DRAINING publisher. No public Registry mutation method or policy grant
was added. Local SQLite and strict PowerShell fixtures test the connected
begin/readback path, not owner host execution.

An expired unused intent is revoked on the same protected anchor under
the same exclusive reservation before decisive Registry readback. A
revoked intent cannot issue a new effect (even after clock rollback);
already committed receipts remain recoverable. Only authenticated absence
with a current checkpoint/hold snapshot matching a fresh candidate
permits an owner-confirmed replacement. The previous context and absence
readback are retained durably before replacement. The sole Registry
writer may recover its private listener at NORMAL with the exact original
pair and at the exact committed DRAINING phase; Gateway startup and new
source effects remain blocked. Durable DRAINING publication recovery
checks exact retained container identity even if a pending phase blocked
the peer's startup, before requiring live drain evidence.

The internal ordinary controller reads authenticated drain status and
produces the existing freeze payload under the existing exclusive
inspector. It binds the mounted owner intent, original paired receipts,
committed current phase, exact hold digest and prepared companion. The
state digest comes from the actual protected receipt. The worker digest
binds explicit owner quiescence confirmation and observed drain; it is
not an independently proven worker-quiescence claim. The payload is
persisted for the existing Check verifier. Local SQLite, phase-file and
PowerShell fixtures exercise expiry, replacement and begin ACK loss,
restart, busy drain and frozen payload; Docker effects remain simulated.

Remaining before effectful ordinary Check: connect the protected Check
record and phase transitions to staged Apply/Return and post-completion;
reuse the fresh inspector result within the continuous controller lock
where possible, without removing independent verification after phase
publication or re-entry. Recovery of a stopped/unhealthy Gateway is not
proved by Registry-only startup. Retain both Apply gates and current
read-only preflight until the full safe path is connected. Prepared
volume provisioning, actual pre-merge owner review and Windows/Docker
acceptance are still required.

### Ordinary frozen handover integration — local development checkpoint

The protected ordinary context now binds four distinct prepared final
roots, the original paired begin receipts, one frozen Check, its source
receipt and a durable Apply-stop intent. The common controller can use
the fresh inspector result under its existing lock, publish the checked
phases, then independently compare the stopped state at exact APPLY_STOP.
The ordinary state copy uses the same confined SQLite copy/replay primitive
as the backup path; final Registry/Gateway material uses the existing
profile binder and independent read-only seal. Historic bootstrap evidence
is retained, not issued again. A retained recorded ancestor may hold only
its exact canonical read-only operational mounts when exited with restart
disabled; no arbitrary holder or new global operational volume is allowed.

The local ordinary journal/phase-file fixture reaches STAGED_TARGET_FROZEN
and verifies the copied state by independent replay and retry. A separate
extension of the completed bootstrap journal fixture proves that the next
ordinary Registry material retains historical evidence and reseals without
another migration. Common controller code is wired for a protected
ordinary prepared attempt, stopped source, receiver and Resume, and the
post-activation branch uses the actual previous receiver and primary
record instead of the #289 special pins. These are source connections, not
a passing ordinary end-to-end Docker lifecycle. The ordinary Return branch
explicitly refuses the historical bootstrap return; the exact recovery
phase/readback and source restart still need integration and fault tests.
Both Apply barriers and read-only public ordinary Check remain. Neither
real owner review/GO, actual Windows PS5.1/Docker effects, nor deployment
admission is implied.

### Ordinary Return and Check re-entry — local development checkpoint

Ordinary Return now uses the common controller, original protected Check,
paired receipts and current phase. It excludes the inactive target, checks
the original stopped source by independent read-only replay, persists the
recovery intent and publishes source-generation RECOVERY_HOLD before
starting the original Registry and Gateway. Both holds remain; Return
does not declare successful completion or NORMAL. Exact retry recovers
lost publication/start acknowledgements without repeating a completed
effect. Changed source evidence or an activation marker fails closed.
The ordinary Check re-entry uses the durable original context rather than
a new NORMAL-only compatibility probe; a fresh intent requires proven
absence of the previous effect.

Local journal/phase-file and simulated controller fault tests PASS.
The packaged ordinary Gateway seal also preserves enrollment and authority
on the next generation; actual host effects remain untested. Still required:
composed ordinary successful Check/Apply/Backup/Promote/completion, recovery
of a stopped Gateway before Check, and exact owner pre-merge review and
volume provisioning. Public Check remains read-only, both Apply barriers
remain; no deployment admission or policy activation is implied.

### Stopped-source Check recovery and staged passive verification

The existing durable ordinary context permits readback of an already
committed paired begin after the Gateway stops. It does not permit a new
begin, revocation or replacement from a stopped source. After committed
DRAINING, retain the stopped Gateway with restart disabled and, if needed,
restore only the exact Registry listener to recover the existing drain
witness; verify both identities and the same publication before sealing.
This is not admission to restart the Gateway while its generation is held.
Manual paired Return requires the owner quiescence attestation, as does
the other protected recovery path.

The exact native GitHub list_branches ALLOW uses the existing typed GET
adapter and rechecks policy, grant and maintenance restrictions; ASK remains
reserved and cannot create approval rows during freeze. The authenticated
metadata catalog is passive. The shared staged controller uses an owner-local
technical probe for the reviewed Mirror get_repository on fortis-approvals,
not the audited extension call. It checks the sealed current target phase,
profile, inactive marker, effective ALLOW, credential readiness and restrictions,
uses the existing fixed GET handler, and independently rechecks the witness.
Other probe coordinates are not silently skipped or enabled. The actual owner
probe set still needs exact review before delivery.

Focused source and isolated fault tests PASS, not actual Windows/Docker
acceptance. The complete ordinary public Check/Apply/Backup/Promote/NORMAL
path remains open: specifically source admission and native preflight if the
Gateway is already stopped, and a connected successful lifecycle proof.
Public ordinary Check remains preflight-only; both Apply barriers remain.

### Ordinary lifecycle convergence (2026-11-29, candidate source)

The exact latest-pin ordinary Check now binds the protected source and the
native GitHub read witness before its existing explicit owner BEGIN, then
resumes the durable drain/freeze/Check record. Apply requires that exact
Check and separate owner APPLY. An already stopped held Gateway is not
restarted for native preflight: the original witness remains bound to the
same source/intent and the staged Gateway must pass the native read afresh
before activation. The retained owner probe JSON and requested probe JSON
must match the reviewed closed list before any new paired begin; unsupported
coordinates stop rather than silently drop checks. No new provider probe or
permission is introduced. Actual #289 evidence establishes Mirror TLS,
GitHub TLS and OwnerShell mTLS; the exact last Windows probe JSON is not
present in the retained local transcript.

The ordinary candidate follows the shared Prepared/stop/copy/seal/receiver/
Resume/Backup/Promote/completion path, with no second bootstrap migration.
After durable Prepared readback the controller reloads the JSON record to
preserve the ordinary dispatch discriminator. The journal fixture follows a
second release through the staged SQLite copy, reserve, close, independent
readback after lost ACK, and new-generation NORMAL, with the held old
journal unchanged. Strict PowerShell fixtures cover the ordinary Check
publication, stopped-source Apply, Prepared dispatch, state-copy/seal,
and post-lifecycle retry boundaries. These are local journal and simulated
controller proofs, not a single real Windows/Docker execution or installed
acceptance. The candidate exact ordinary source entrypoint is wired; the
historical/static maintenance Apply denial and #289 bootstrap Apply barrier
remain. No publication, owner installation, live policy change, or E2 GO
until the remaining exact pre-merge/provisioning proof and required gates.

### One bounded delivery from #289 (2026-11-29, source candidate)

The earlier unconditional #289 bootstrap Apply barrier is superseded at
source level. The ordinary lifecycle is unchanged; historical/static
maintenance without an exact successor still stops. Bootstrap requires
the exact protected Check and original owner review, and a distinct
`APPLY BOOTSTRAP <CheckHash>` confirmation before the persisted attempt
and physical source stop. Reuse the same protected pair controller,
receiver, Resume, Backup/Promote and completion; never a second migration.

Before the inactive clone is even copied, AccountBootstrapMigration now
authenticates the original owner ACL-protected review file, checks its
hash against the canonical review and requires reviewedAt < mergedAt.
The merge timestamp is independently observed by the owner from GitHub,
not a new trusted remote timestamp API; no proof is made from local clock
alone. The exact accepted Git parents, tree, body, CI and Registry prefix
remain mandatory and are independently replayed. A protected review is
created only for the actual open, reviewed, exact-head successful PR;
no fabricated review for the current uncommitted candidate.

The bounded owner preparation package is retained outside Git under
Workfiles/registry-bootstrap289-delivery-20261129. It uses existing
protected record writer and release lock, exact current #289 runtime
and backup pins, original source/profile/authority, existing native
typed READ, existing root and material writers, and AccountBootstrapMigration.
New nonce roots and two fixed latest-pin roots must be fresh, distinct,
unheld and independently inspected. Actual Windows/Docker execution,
owner PR/rules/merge timestamp, fresh capacity and exact retained probes
are still required. Local preparation tests do not establish host
acceptance, and no policy, publication, merge, or installation is authorized.

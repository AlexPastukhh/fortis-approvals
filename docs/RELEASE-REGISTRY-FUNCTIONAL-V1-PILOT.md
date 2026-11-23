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
- Gateway profile is strict canonical JSON **schemaVersion=2** with fields,
  `enabled=true`, `purpose="registry-candidate-read-v1"`,
  `releaseNonce` (one owner-reviewed UUID matching the current release),
  `gatewaySourceDigest` (the exact installed R7 source manifest digest),
  `instanceId`, `scopeDigest`, `socketPath`, `registryUid`, `registryGid`,
  `registryPidfdInode`, `registryKernelBootId`, `readerUid`, `readerGid`,
  `socketDevice`, `socketInode`. The legacy numeric `registryPid` field is
  **not accepted** in the owner R7 mount v2.
  Owner re-derives and checks **all** pins against running processes and the
  exact mounted endpoint. Do not copy illustrative numbers or override a
  failed pin merely to make a pilot appear healthy.
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
- **PID namespace acceptance is mandatory:** FORTIS_M owner's isolated
  sandbox confirmed distinct Docker PID namespaces yield `SO_PEERCRED pid=0`
  but support Linux `SO_PEERPIDFD` (optname `77`) with real kernel process
  identity, verified by independently opened pidfds from both processes.
  **Current v2 *source candidate* requires Linux 64-bit pidfs (kernel 6.9+),
  the real peer UID/GID from `SO_PEERCRED`, a live kernel pidfd, and exact
  pidfd inode + current `/proc/sys/kernel/random/boot_id` from the
  immutable owner-sealed Gateway mount. `pid=0` is acceptable **only** when
  the independent owner process pin and all other checks match**; it is not
  a fallback to UID/GID alone or to claimed process values. The Registry
  listener checks the Gateway's kernel UID/GID and live pidfd with its exact
  socket ACL without relying on a numeric cross-namespace PID. A pidfd
  obtained from the peer and compared to the peer's *own statement* is not
  owner admission. After a process exit, Registry restart/rebind or kernel
  reboot, stale boot/process/socket pins must STOP; the owner independently
  re-provisions the seal and uses the existing guarded release procedure.
  Keep separate PID namespaces; do NOT use `--pid=host`, `--pid=container:*`,
  process-identity fallbacks, or new capabilities.
- **Two separately owner-provisioned Registry volumes are necessary:** the
  Gateway needs a fixed readonly activation-profile volume at
  `/run/r7-registry-reader` **and a distinct readonly view** of the live Unix
  socket directory at `/run/fortis-registry-read`. The Registry service owns
  the only writable socket bind; its private schema-3 SQLite volume is never
  attached to Gateway or Repo. E1.3b source admission adds only a strictly
  paired, fixed-name, readonly volume check in `github_pilot_helpers.admit()`:
  `fortis-r7-registry-reader` and `fortis-registry-read`. The owner Windows
  Check/Apply controller **does not activate these two volumes yet**. This
  still needs an exact protected owner design, independent socket writer
  provenance and an explicit owner GO. Ordinary releases must remain unchanged.
- **Owner-side read-only process observation (source-only tool):** after the
  Registry pilot is separately approved and launched, the owner first
  confirms exact Docker container/image/namespace/source and service command
  via **independent Docker inspect/top**. Docker Engine host PID is **not**
  necessarily the numeric PID visible **inside the Registry container**;
  the owner must independently map/inspect `/proc` in that selected container
  before supplying its *container-local* Python listener PID, without asking
  the Registry listener to assert its own PID. The reviewed candidate image
  includes `fortis_approvals.registry.owner_candidate_pidfd_observation` as
  an **owner-invoked, one-shot** diagnostic: requires exact selected PID,
  real Registry UID/GID and reader GID, validates live process pidfd,
  `/proc` security/command, the 02710/0660 socket endpoint and its actual
  kernel `SO_PEERPIDFD` connection; checks stable PID start ticks, boot ID,
  process inode and socket inode. It reads no SQLite, sends no READ request,
  and creates no credentials/volumes/processes; its connection may be counted
  or rejected by the Registry listener. **Owner must review its invocation
  and compare its raw result against Docker Engine's independent container
  image/UID/namespace/mount readback.** The result intentionally reports
  `ownerAcceptanceVerified=false`, `profileSealed=false`,
  `releaseAdmitted=false` and cannot auto-create or authorize the v2 profile.
  Neither a same-UID test nor this tool alone proves the owner attestation.
- **`releaseNonce` requires an owner-reviewed Check/Apply design.** The
  current Windows controller creates a **fresh random release nonce** when
  preparing the runtime; the v2 Registry activation profile demands the
  *same* pre-sealed nonce at startup. Merely allowing two volumes is
  insufficient. A future protected Check/Apply source-cut must enforce an
  explicit owner-chosen nonce, exact checked-image binding, repeatable
  unchanged profile digest, fail-closed owner re-seal on Registry restart,
  and no new default `-Auto` activation. Until those gates pass, **STOP**.
- **The existing installed Gateway release controller does NOT automatically
  accept this new Registry mount.** Source `github_pilot_helpers.admit()`
  requires an empty `PidMode` and an exact mount allowlist; existing
  `Manage-Integrations.ps1` has no authorized Registry mount entry. Owner
  must independently approve the precise added **readonly Registry volume**
  and versioned protected Check/Apply/Backup/Promote source prior to building
  or releasing this image. A source/test PASS is not installation or GO.
- **Trusted process pin origin:** after starting an isolated owner-accepted
  Registry listener, an independently vetted owner-side Linux kernel
  observation must identify its exact process, current pidfs inode and boot
  UUID, correlate to reviewed Docker container/image UID/GID and socket
  device/inode, then seal the exact v2 Gateway mount **read-only** before
  Gateway startup. Do not source the pin from Registry JSON/response,
  untrusted Repo data or process self-report. The way Windows operator
  obtains this trusted kernel observation on Docker Desktop remains a
  separately reviewed host step; do not invent host namespace access.

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

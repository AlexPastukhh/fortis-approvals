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
- Gateway profile is strict canonical JSON with fields `schemaVersion=1`,
  `enabled=true`, `purpose="registry-candidate-read-v1"`,
  `releaseNonce` (one owner-reviewed UUID matching the current release),
  `gatewaySourceDigest` (the exact installed R7 source manifest digest),
  `instanceId`, `scopeDigest`, `socketPath`, `registryUid`, `registryGid`,
  `registryPid`, `readerUid`, `readerGid`, `socketDevice`, `socketInode`.
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
- **PID namespace acceptance is mandatory:** `SO_PEERCRED` in the Gateway
  reader's namespace must return the exact pinned Registry PID/UID/GID,
  including after restart/rebind. Separate Docker PID namespaces can yield
  a PID that is not the host PID (or not representable at all). Record the
  *observed peer identity in the Gateway namespace*. If it cannot be pinned
  without broadening host privileges or weakening the check, **STOP** and
  review topology; do not permit `pid=0`, compare to a fabricated PID, or
  silently switch to shared PID/host namespaces.

## Required independent evidence for accepting E1.3

Owner must record: exact source/image digests; real distinct effective and
mapped host UIDs/GIDs and supplementary groups; actual mount namespace,
PID, `SO_PEERCRED`, socket mode/device/inode; OS-enforced Repo denial on both
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

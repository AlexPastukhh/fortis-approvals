# Registry Functional V1 — owner private-volume provisioning contract (E1.3b)

**Status: SOURCE-ONLY EXECUTABLE CANDIDATE / NO HOST GO / NOT HOST ACCEPTED.**
This specifies the **next** separately reviewed owner-controlled host action. It
is not permission to create a Docker volume, chown, mount or start any container.
The **only normative E0–E5 progress table** stays in
[`fortis-container/docs/BACKLOG-IMPROVEMENTS.md`](https://github.com/AlexPastukhh/fortis-container/blob/main/docs/BACKLOG-IMPROVEMENTS.md).
The accepted [Registry Functional V1 pilot](RELEASE-REGISTRY-FUNCTIONAL-V1-PILOT.md)
and [bootstrap launcher](../fortis_approvals/deploy/Registry-Owner-Bootstrap.ps1)
require **preexisting** volumes. The new separate candidate below does not change that launcher or grant host authority. Use **UC-CONT-021, UC-CONT-022,
UC-CONT-025** before each proposed host effect; UNCERTAIN is STOP, not retry.

## Pure source plan (zero Docker operations)

`scripts.registry_owner_volume_contract.plan_private_volume_roots(owner_suffix)`
validates an independently **owner-selected** 8–32 character lowercase hex
suffix. It returns immutable expected roots, nothing else. It does not choose
instance ID, scope, release nonce, base provenance, Linux UID map or host.

| Separate existing/future local volume | Container mount destination | Root owner in Docker Linux VM | Octal mode |
| --- | --- | --- | --- |
| `fortis-registry-state-e13b-<owner_suffix>` | `/run/fortis-registry-state` | `20002:20002` | `0700` |
| `fortis-registry-config-e13b-<owner_suffix>` | `/run/fortis-registry-runtime` | `20002:20002` | `0700` |
| `fortis-registry-read` | `/run/fortis-registry-read` | `20002:10001` | `02710` (setgid + group traverse) |

The three mounts must be **distinct local volumes** and not an existing Gateway
state, Repo workspace, secret, token, GitHub, or host-root mount. The fixed
socket volume is **not** the per-release owner-sealed Gateway reader profile
volume. A `docker volume ls` name count of zero means *not yet present*, not
that a volume is created or securely owned. `volume-nocopy` is required.

## Before proposing any one-time owner GO (read-only inventory/review)

1. Select host and source SHA: Windows Docker context `desktop-linux`, Linux
   Engine, exact clean Approvals `main`, accepted image ID/source revision and
   provenance, reviewed release target; never silently rebuild or pull images.
2. Independently establish real Docker-VM rootless/userns mapping and mapped
   Registry UID `20002`, reader UID/GID `10001`, Repo `1000`, effective groups,
   and writer/mount conflicts, rather than relying on empty `UsernsMode`,
   configured `GroupAdd` or Windows ACL assumptions. Existing owner Windows
   `docker top` EUID/EGID and new-image isolated probe are only partial proof.
3. For **each** exact desired volume name, verify it is absent in `docker
   volume ls/inspect`, no stopped/running attachment or stale prior owner
   record, no conflicting active state, Compose/launcher ownership and no
   in-flight startup/change. If *any* name exists, **STOP**: do not adopt,
   chown, reuse, overwrite or delete it as part of provisioning.
4. Owner independently reviews an executable helper's **immutable source/image
   provenance** and the *complete* Docker command, exact three writable
   destinations, requested Linux credentials/capabilities (least privilege),
   limits, namespace, network=none, no Docker socket, no host root, no
   unrelated mounts or env secrets, no privilege escalation or post-exec
   cleanup. A privileged generic `alpine`/`busybox` chown helper, `docker
   exec` into Gateway/Repo, `docker run --privileged`, or Docker `--user 0`
   without a narrowly justified and pinned capability plan is **not approved**.
   Image ID alone is not independently verified upstream base provenance.
5. Review separate effect boundary: any **creation** of the 3 named empty
   volumes and **setting ownership/mode on their roots** are host writes and
   require a distinct exact-scoped **owner GO** after this plan is accepted.
   `Preview`, schema-3 `Provision`, backup and listener activation each require
   their own later approval and prerequisites. No source PR or Plan is a GO.

## Source-only Windows PowerShell 5.1 metadata preflight

`[scripts/registry_owner_volume_preflight.ps1](../scripts/registry_owner_volume_preflight.ps1)`
is a separate read-only preflight, not a volume preparer, independent of the existing
`Registry-Owner-Bootstrap.ps1`. Its `-Action Plan` requires no Docker or Git;
`-Action Inventory` performs **read-only** exact Windows clean-main SHA checks,
current Docker context and immutable Registry image/source-revision pins,
exact running Gateway/Repo container ID/image/user/health constraints, named
volume-name collision checks and stopped/running container mount metadata
scan. It prints only bounded output; neither raw `docker inspect` JSON nor
private environment values are displayed. No volume creation, `docker run`,
`docker exec`, `chown`, `Preview` or `Provision` is called.

The mount inventory explicitly tolerates Docker `bind`/`tmpfs` records
without `Name` (as seen on Windows PS5.1 with `Set-StrictMode`), but fails
closed if a `volume` lacks `Name` or if a `bind`/`volume` lacks `Source`.
An unknown or missing `Type` is STOP; optional property absence must never
silently override a volume name/source collision.

This script is **metadata-only**, not independent runtime permission attestation or authorization for host writes. Its
successful marker `E13B_OWNER_VOLUME_METADATA_READONLY_PASS` is followed by
`E13B_USERNS_GROUPS_OWNERSHIP_WRITER_FENCE_UNKNOWN_STOP_BEFORE_CREATE`:
not all in-flight Docker operations, rootless/userns translations, Linux
supplementary group memberships, volume root UID/GID/mode, Docker-VM/Windows ACL,
or future container writers can be inferred from Docker metadata. These limits remain even after the owner-reported Windows metadata PASS. The executable source candidates below are not proof that those gaps have been closed.
Before execution on Windows the script itself requires owner review, merge,
guarded source update and exact SHA pins. Static Linux tests are not a
PowerShell 5.1 runtime check.

## Required mutation semantics for a future reviewed owner-run helper

- **Fail closed before first write:** exact context, immutable SHA/image,
  independently validated principal mappings, local driver, all three names
  absent, original Gateway/Repo container IDs/images/health and mount writers
  preserved. Do not create scratch containers or anonymous volumes as an
  unreviewed side effect. No source/AI environment may access Windows Docker
  Engine, daemon socket, root or host private records.
- **Creation only under separate GO:** create only the three exact owner-chosen
  volumes, without Compose or renamed existing resources; no implicit
  Docker volume copy. Record each new actual volume name/driver/scope and
  creation result *immediately* before the next effect. There must be no
  possible write mount to live Gateway/Repo state, credentials or workspace.
- **Ownership setting under separate reviewed execution:** only the exact,
  provably fresh and **empty** volume roots may be set to `0700` owner
  `20002:20002` (state/config), `02710` owner `20002:10001` (socket).
  Never recursively change arbitrary content or use an unpinned helper image;
  never mask an unknown Windows/Docker-Linux-VM mapping with `chown` on a
  Windows bind path. Permission mode `02710` requires setgid, not just `0710`.
- **Independent verification before any bootstrap:** re-inspect every volume
  exact name, driver and scope, and independently read live Linux `stat`
  root UID/GID/mode, empty contents, device/inode, no aliases or symlinks;
  verify these via a **separately reviewed RO-only inspector** and the mapped
  identities seen by the actual relevant process mount view. Confirm no
  other container/owner writer or attachment and verify original Gateway/Repo
  unchanged. A `volume inspect` success or planner output alone is **not**
  root ownership evidence. Record immutable readback and owner witness.
- **Partial/ambiguous result:** **STOP** immediately on first nonzero or
  uncertain Docker effect; **no automatic cleanup**, no retry, no
  `docker volume rm`, no compensating `chown`, no blanket prune and no auto
  restart. Preserve named partial volumes for owner incident inspection
  under UC-CONT-022. An independent restore/backup is *not* established by
  this operation. Rollback/retention is a separate owner-approved incident
  procedure with an exact resource manifest.

## Separate executable source candidate: controller, preparer and inspector

- `scripts/registry_owner_volume_controller.ps1`: Windows PowerShell 5.1
  entrypoint; default `Plan` does not call Git or Docker. `Prepare` and
  `Inspect` are separate owner-only host-effect phases, each requiring its
  own explicit scoped confirmation (`-ConfirmHostEffects`) and independently
  reviewed owner record. It revalidates clean exact Windows `main`, the
  pinned Registry image **and its historical build-source SHA**, exact
  Gateway/Repo IDs/images/health, and the Docker Desktop Linux named-pipe
  context. No automatic import, build, pull, retry, restart or cleanup.
- `scripts/registry_owner_volume_prepare_roots.py`: fixed Linux roots only;
  all three mounts must be fresh empty local-volume roots (default `0:0`
  `0755`, no aliases or nested mounts) **before the first ownership change**.
  Open directory FDs with no symlink traversal. Check the actual VM uid/gid
  maps, real/effective/saved identities, supplementary groups, seccomp,
  no-new-privileges, root filesystem and mount flags; recheck a fresh root
  immediately before applying `fchown` then `fchmod`, `fsync` and `fstat`.
  UID `0`, primary GID `10001`, exact capability mask `0x9`: `CAP_CHOWN`
  and `CAP_FOWNER` only; GID `10001` permits setting the socket-root setgid
  bit without `CAP_FSETID`. No `CAP_DAC_OVERRIDE`, recursive operations,
  arbitrary path, file creation, compensating mutation or cleanup.
- `scripts/registry_owner_volume_inspect_roots.py`: separate read-only code
  and separate non-root container, `20002:20002`, **all capabilities zero**,
  exactly three RO named-volume mounts with `volume-nocopy`. Independently
  opens the roots, checks emptiness, exact owner/mode and device/inode,
  actual mount RO flags and confinement. The controller compares the
  independently measured device/inode with the preparer receipt; it does
  not treat a preparer PASS as independent verification.

Both helper payloads are exact SHA256-pinned source bytes passed as a bounded
base64 argument to the **existing, independently reviewed/pinned** Registry
Python image. The expression for decoding/executing the reviewed payload is
fixed; no shell, user-supplied code path or free-form Docker arguments.
Neither helper is copied into the Registry image or existing Windows owner
controller deployment target. No rebuild follows from this source change.

`Prepare` repeats the corrected metadata Inventory before the first host
write. Its expected `...UNKNOWN_STOP_BEFORE_CREATE` means Inventory cannot
prove the external prerequisites; it is **not** treated as authorization.
Only a separately reviewed external owner evidence record and separate GO can
admit the candidate. The controller creates only the three exact names with
local driver and a new owner operation UUID label, refuses existing names,
checks identity/options/attachments and distinct mountpoints. It uses
`docker container create` (not immediate start), inspects the exact actual
container configuration, mount names/source/targets/RW and nocopy, namespace,
limits, caps, image/payload and labels **before** starting by exact container
ID. Inherent Docker-generated system mounts are not owner-added volume
mounts; neither payload accesses them except read-only `/proc` evidence.
There is no host bind, Docker socket, host network/PID/IPC or other host
resource mount. The owner must independently exclude concurrent Engine
writers; the metadata snapshots and operation labels are **not an atomic
Docker writer fence**.

`Inspect` is a later, separately approved action because creating and starting
a read-only diagnostic container still changes Docker metadata. It validates
the retained exited-success preparer and exact payload, volume labels and
attachments, creates a distinct zero-capability helper, checks its RO mounts
before start, and validates its independently measured receipt. Both phases
check Gateway/Repo before/after. The `json-file` log policy is bounded; owner
must retain the logs/receipts, including any partial result. The helper
containers remain stopped/retained, including after success. Before any
bootstrap, separately approve exact-ID cleanup of **only** the two known
successful stopped helper containers (no volume removal); verify no remaining
attachments. Cleanup is not implemented here. No `--rm` or automatic retry.

### Independent owner record (not generated or approved by source CI)

Before either host-effect phase, the owner must independently establish and
review the mapped Linux-VM identities (including effective supplementary
reader/Repo groups and required non-conflicting active principals), actual
exclusive owner change window/absence of other writers and stale attachments,
and upstream provenance for the exact existing Registry image. If any of
these is unknown, **STOP**; do not invent evidence records/digests. The
controller requires a bounded JSON record, separately pinned by SHA256,
with exact fields:

- `schemaVersion` = 1; `decision` = `Prepare` or `Inspect` (distinct record
  per phase); `operationId` = same independently selected unique lowercase
  UUID for the two phases; `ownerSuffix` = reviewed suffix.
- `sourceSha`, `registryImageId`, `imageSourceSha`, `gatewayContainerId`,
  `gatewayImageId`, `repoContainerId`, `repoImageId`, `context` =
  `desktop-linux`, `dockerEndpoint` = `npipe:////./pipe/dockerDesktopLinuxEngine`.
- `hostIdentityEvidenceSha256`, `exclusiveWriterFenceEvidenceSha256`,
  `imageProvenanceEvidenceSha256`, `preparePayloadSha256`,
  `inspectPayloadSha256`: full lowercase digests of actual independently
  reviewed evidence/payload files. The controller also reads and checks the
  referenced evidence file bytes using `-HostIdentityEvidencePath`,
  `-ExclusiveWriterFenceEvidencePath`, `-ImageProvenanceEvidencePath`.
  These files stay in the owner's reviewed private evidence area (no tokens,
  private keys, protected state or raw sensitive logs). A hash verifies
  byte identity only; the script cannot verify the truth of the evidence or
  owner authority. Review and current exclusive window must be independently
  established before each GO, not inferred from a JSON field.

Do not run `Prepare` or `Inspect` from this document. Owner review and exact
source/image verification, PowerShell 5.1 fixture CI, independent actual host
evidence and a separate explicit GO must precede either effect. Expected
successful phase markers are `E13B_VOLUME_PREPARE_OWNER_READBACK_PASS_INSPECT_REQUIRED`
then `E13B_VOLUME_INSPECT_OWNER_READBACK_PASS`. Both are **not** bootstrap GO,
backup/restore, actual reader peer authorization or E1.3b host acceptance.

## Acceptance boundary

The source candidate now contains an executable bounded preparer and
independent read-only inspector; **HOST_NOT_ACCEPTED / VOLUMES_NOT_CREATED**
remains until real separately approved owner actions and independent readback.
Python offline tests simulate mutations rather than calling them; real Windows
PowerShell 5.1 CI parses the scripts and tests no-Docker configuration/receipt
fixtures. These checks are not live Docker runtime evidence. The already-built
Registry image remains unchanged. Preview, schema-3 Provision, backup and
independent restore, actual peer/Repo-denial proof, owner nonce seal and manual
UC-GW-005 remain separate later gates. E1.4–E5 stay blocked.

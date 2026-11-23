# Registry Functional V1 — owner private-volume provisioning contract (E1.3b)

**Status: SOURCE-ONLY CANDIDATE / NO HOST GO / NOT A PROVISIONER.**
This specifies the **next** separately reviewed owner-controlled host action. It
is not permission to create a Docker volume, chown, mount or start any container.
The **only normative E0–E5 progress table** stays in
[`fortis-container/docs/BACKLOG-IMPROVEMENTS.md`](https://github.com/AlexPastukhh/fortis-container/blob/main/docs/BACKLOG-IMPROVEMENTS.md).
The accepted [Registry Functional V1 pilot](RELEASE-REGISTRY-FUNCTIONAL-V1-PILOT.md)
and [bootstrap launcher](../fortis_approvals/deploy/Registry-Owner-Bootstrap.ps1)
require **preexisting** volumes. This document does not change that launcher or
publish an operational volume-creation tool. Use **UC-CONT-021, UC-CONT-022,
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

## Acceptance boundary and next implementation step

Until an independently reviewed executable owner-helper, host mapping evidence,
owner GO and **actual readback** all exist, record `VOLUME_PROVISIONER_DESIGN_ONLY`
/ `VOLUMES_NOT_CREATED` / `HOST_NOT_ACCEPTED`. Next source task should
implement and validate the bounded owner-run preparer and independently read-only
inspector against this contract, with Windows PowerShell 5.1 syntax/runtime
checks and source CI; **do not** insert volume creation into the existing
`Registry-Owner-Bootstrap.ps1` or treat its `Plan` as authorization. The source
planner contains no host operations and is not packaged into the existing
Registry image; that image's already-built runtime ID remains unchanged.

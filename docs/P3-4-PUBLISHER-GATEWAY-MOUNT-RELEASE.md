# P3.4 — protected Gateway mount for the Publisher principal

**SOURCE_CANDIDATE / DISABLED BY DEFAULT / NO OWNER CREDENTIALS.**
This is a source-only owner-reviewed extension of the existing Windows
PowerShell 5.1 Gateway Manage-Integrations.ps1 release procedure. It
enables one optional fixed publisher-principal mount; it does NOT provision
credentials, launch the Publisher runner or authorize GitHub label ASK.

## Exact trusted path and scope

Only one existing, independently owner-provisioned **local Docker named
volume** is allowed: fortis-r7-publisher-activation.

Its sole Gateway destination is /run/r7-publisher-activation, mounted
READONLY. No bind mount, user-selected host path, environment variable,
unscoped volume name, Docker socket or Repo/Workfiles mount is supported.

The volume root must contain exactly two files, owned by Gateway UID/GID
10001, directory mode 0700, regular single-link files mode 0600:

- profile.json: exact schemaVersion/actor/repository/policy revision/
  validator revision/registryDelegation required by the accepted
  publisher_owner_mount.load_owner_publisher_mount.
- grant: unique high-entropy machine credential for
  release-label-publisher-v1, never the Repo grant, provider PAT or
  owner key.

The owner must provision this volume OUTSIDE the shared Repo environment,
with no secrets in source, PR, Workfiles, CI artifacts, logs or chat.
This PR does not create a volume or invent policy and validator pins.

## Activation boundary

Manage-Integrations.ps1 adds the owner-only switch -EnablePublisherMount.
It is valid ONLY on manual, SHA-pinned Check -Build and the bound
Apply -CheckedImageRecord, with owner-attested quiescence.
It is rejected with -Auto, Return, Backup, Promote, Credential and
an unbound Apply. The existing owner procedure remains mandatory.

A network-disabled, read-only, UID-10001 Docker preflight verifies the
EXACT two private files and computes a SHA256 digest of their bytes. This
digest is bound to the protected checked-image record and new release
runtime record, not printed in public logs. Apply repeats the check and
refuses drift before the old Gateway is stopped. Container admission checks
the exact readonly volume mount AND independently checks this same digest.
The old protected records with no publisher fields remain DISABLED.

Once activated, future Check -Auto and Apply -Auto may preserve the same
already reviewed volume and digest. Auto can NEVER activate a previously
disabled publisher principal. Credential/policy rotation through a changed
live volume is rejected; it requires separate reviewed release planning.

## Required OWNER-ONLY gates (not executed by Repo AI)

1. Review exact accepted source, both CI checks and Windows PowerShell 5.1
   parse/SelfTest. Independently verify local docker volume provenance,
   UID/mode, readonly disposition, and absence of conflicting RW writers.
2. For first activation use a protected MANUAL Check -Build with exact
   accepted SourceSha, EnablePublisherMount, independently verified
   ConfirmWorkerQuiescent and the complete current scope of UNCERTAIN and
   CLAIMED jobs (plus PENDING/DISPATCHED/APPROVED gating), existing owner
   private config and probes. Never use Check -Auto for opt-in.
3. With separate owner GO, Apply the exact checked image record and SHA
   with EnablePublisherMount, same verified owner scope and no second Build.
   Do NOT repeat an ambiguous Apply; use the original protected attempt.
4. Read back Gateway and source/image IDs, then Backup and Promote through
   existing guarded procedures and independently inspect Docker mounts and
   healthy runtime. Probe the new machine principal with its OWN grant,
   verifying exact READ and ASK-only add/remove and DENY of other operations.
5. Separately attest the isolated one-shot runner image/container,
   Gateway-TLS-only egress and private validator/grant/journal. Only after
   fresh PR/CI/labels admission, run one owner-invoked preview and at most
   one ASK on still-open pilot PR #118. WebAuthn and original receipt
   verification are mandatory. No timer, webhook, direct GitHub egress or
   unattended release.

**Status: SOURCE ONLY — no live publisher grant or runtime installed.**

Normative docs: docs/use-cases/releases.md (UC-GW-005),
docs/PRIMARY-GATEWAY-OPERATIONS.md, docs/use-cases/incidents.md (UC-GW-009),
docs/P3-4-PUBLISHER-OWNER-STARTUP.md and
docs/P3-4-PUBLISHER-ISOLATED-RUNTIME.md.

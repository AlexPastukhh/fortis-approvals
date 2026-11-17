# P3.4 — owner-sealed startup composition (source candidate)

**Status: SOURCE_CANDIDATE / DEFAULT_DENY / NO DEPLOYMENT.** This change adds a
narrow optional **second** Gateway actor, not a daemon, scheduler, publisher
credential or production activation. Never treat a source merge, unit tests,
GitHub labels or Gateway image build as the owner's release approval.

## Trusted boundary

The existing `repo-sonar-read-proposal-actor` remains the original ingress
actor. `release-label-publisher-v1` may be added only by a *separate*
owner-private grant, **not** `actor_grants` (whose members inherit
Sonar/extension scopes). The trusted candidate builder creates:

- a distinct credential mapped only to the publisher principal;
- broker operations = exactly `github.add_pr_release_labels` and
  `github.remove_pr_release_label` (both **ASK**);
- broker READs = exactly the reviewed `PublisherProfile.READS`, with
  fixed `fortis-approvals` scope and explicit delegation of existing Repo
  task registration; no general GitHub inventory, CI control/logs or URL fetch;
- **no** Sonar, workspace edit/commit/push/claim, PR creation/merge,
  label-definition creation, owner/extension or cross-actor incident grants.

The existing `PublisherProfile.validate_composition` checks the complete
principal, broker and Core policy map and pre-dispatch guards; the original
Repo actor policy is not widened. The actual owner decision remains WebAuthn
against the immutable original ASK. The existing Intent Journal/receipt
contract is reused, never replaced.

## Source entrypoint and default-deny input

The Gateway process calls `load_owner_publisher_mount()` in
`r7_unified_server.main` **only** for real runtime startup (not import/health/
source preflight). The only production input is the **fixed** private location:

`/run/r7-publisher-activation/`

If this directory is absent, it returns `(None, None)` and the existing
Gateway starts with publisher **disabled**. There is **no** environment
activation switch, Repo/PR config lookup, credential fallback or automatic
file/credential generation.

For a *later owner-managed activation*, a separate trusted release must
read-only-mount a directory with **exactly** two files:

- `profile.json` — JSON object with **exactly** the fields
  `schemaVersion: 1`, `enabled: true`,
  `actor: "release-label-publisher-v1"`,
  `repository: "fortis-approvals"`, `revision` (64 lowercase hex characters
  for an explicitly owner-reviewed policy revision),
  `validatorRevision` (full reviewed public-action 40-hex commit),
  `registryDelegation: true`.
- `grant` — one unique, owner-provisioned **machine** credential for the
  publisher (32–256 allowed ASCII characters, optionally trailing LF).
  No GitHub PAT or owner session.

Both files must be owned by the non-root Gateway process UID, be regular
non-symlink files with mode **0600**, single hard link, and be mounted under a
non-symlink **0700** directory owned by the same UID. File inventory must be
exact; malformed, duplicate-key, incomplete, changed, oversized, extra or
insecure files **STOP startup**, rather than silently disable checks. The
owner must independently verify the actual container mounts and readonly
property; source validation cannot establish Docker isolation. Do not put
filled files, credentials or secrets in Fortis Repo, Workfiles, Git, chat or
CI artifacts.

A separate [protected P3.4 Gateway mount source candidate](P3-4-PUBLISHER-GATEWAY-MOUNT-RELEASE.md)
now proposes the fixed, optional owner-provisioned readonly Docker volume
fortis-r7-publisher-activation. The owner mount is NOT installed by a source
merge, and no credential/volume is created by that source change. First-time
activation requires manual reviewed Check/Apply with a protected binding,
then separate owner image release and live principal readback. Auto cannot
activate the previously disabled principal.

## Required pilot release gates

1. Owner accepts exact source HEAD, profile/validator pins, no broad grants and
   a reproducible image; a source merge is not a release.
2. Fresh clean Windows Mirror Pull, PowerShell 5.1 SelfTest, protected
   `Manage-Integrations.ps1 -Action Check -Auto`, and **separate owner GO**
   for Apply, Backup and Promote per [UC-GW-005](use-cases/releases.md#uc-gw-005).
   Preserve all existing `UNCERTAIN` requests and historical `CLAIMED`
   jobs. `quiescenceProven=false` remains STOP until independent owner proof.
   An ambiguous Apply must use original protected recovery record, not retry.
3. Independent live Gateway and owner-host READ confirm source/image identities
   and **publisher-grant** capabilities:
   `publisherProfile.enabled=true`, exact profile SHA256 and validator commit,
   `requestEvidence.scope=own-release-label-requests`,
   `crossActorDetails=false`, bounded head workflow reads, and only ASK label
   add/remove for the fixed repository. Negative foreign-actor/read/write
   admission is required; Repo capabilities alone are not this evidence.
4. Separately provision the **runner**, not a shared AI worker: non-root,
   read-only root filesystem, no Repo/Workfiles/Docker/owner mounts, fixed
   Gateway TLS-only egress, private data cache and existing Intent Journal;
   no direct GitHub egress. The separate [P3.4 one-shot image source](P3-4-PUBLISHER-ISOLATED-RUNTIME.md)
   defines an owner-review candidate but does not build, deploy or launch it.
5. Keep [pilot PR #118](https://github.com/AlexPastukhh/fortis-approvals/pull/118)
   **open** and non-draft. Revalidate its **latest** exact-head CI,
   stable PR/labels/base, registered task and one permitted managed delta
   before a one-shot `preview` or `request`. Owner WebAuthn decides one ASK;
   verify original receipt + independent label readback. No automatic
   replay, bulk replacement, merge, timer, webhook or deployment.

See [P3 owner decisions D1–D7](RELEASE-LABEL-PUBLISHER-P3-REVIEW.md),
[runner technical owner](../fortis_approvals/integrations/github/PUBLISHER-RUNNER.md),
[UC-GW-009](use-cases/incidents.md#uc-gw-009) and
[Primary release procedure](PRIMARY-GATEWAY-OPERATIONS.md).

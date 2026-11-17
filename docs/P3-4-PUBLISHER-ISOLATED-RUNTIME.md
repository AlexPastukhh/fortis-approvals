# P3.4 — isolated one-shot Release Label Publisher image

**SOURCE_CANDIDATE / NOT INSTALLED / MANUAL-PENDING.** This describes a
separate image for the accepted [P3.3 runner](../fortis_approvals/integrations/github/PUBLISHER-RUNNER.md)
and [P3.4 owner-sealed Gateway identity](P3-4-PUBLISHER-OWNER-STARTUP.md).
It does not install a service, create a credential, change the Primary,
issue an ASK, or implement an unattended trigger. Pilot PR #118 stays open.

## Image and authority

Recipe: `fortis_approvals/deploy/Dockerfile-P3-Release-Label-Publisher`.
One fixed `python3 -I -B -m ...release_label_publisher` entrypoint
accepts only the already-implemented `preview`, `request`, `inspect` modes
for an explicit PR/intent; no listening port, daemon, cron or worker claim.
The image packages the reviewed Python runtime subset in site-packages,
Git for read-only verified bundles, and CA roots. No code is copied from
the PR or the shared Fortis Repo worktree at execution time. Only the separately
reviewed *public action validator* may be mounted as trusted data/code.

The Dockerfile intentionally has **no default base**: its owner must supply
`PYTHON_BASE=python:3.11-slim@sha256:<exact reviewed digest>`. Reject unpinned
tags and verify the complete built image ID/source identity. The apt package
resolution is not reproducible merely by pinning the base: a future production
build needs an owner-reviewed immutable package source or an exact captured
dependency manifest. This PR supplies no built image and claims no Docker test.

## Owner-provisioned private paths — never in Git/Repo/Workfiles

- `/run/publisher/config.json`: owner-readonly strict JSON `RunnerConfig`;
  `enabled: true` is permitted **only after** live publisher-principal
  acceptance. It names an exact reviewed `validator_revision` and live
  `profile_sha256`. Safe default when not provisioned: no invocation.
- `/run/publisher/grant`: **unique** publisher machine credential, mode 0600,
  owned by the container UID. This is not the Repo grant, GitHub PAT, or owner
  WebAuthn key. `/run/publisher/gateway.crt`: reviewed Gateway TLS server CA
  certificate. No general host certificate stores or owner-session mounts.
- `/opt/fortis-validator`: separate **read-only** reviewed public-action Git
  checkout with exact pin and complete files; no source from the PR.
- `/var/cache/fortis-publisher`: private **writable**, non-symlink cache for
  verified Git bundles/source data. `/var/lib/fortis-publisher-intents`:
  separately writable private **existing** IntentJournal; preserve it across
  invocations. Distinct paths, UID 10002, permissions 0700, no shared Repo
  cache, host Docker socket or Gateway owner databases. Do not wipe the
  journal after an ambiguous operation.

All paths must be absolute, immutable-configured and checked against the
runner's strict `RunnerConfig` rules. The owner creates those files/mounts
outside AI-writable directories; the image never generates them.

## Owner-only runtime admission (no command in this PR runs Docker)

1. Accept the source/PR and exact image provenance. Review the fixed build
   argument and package supply-chain; inspect the image's copied files,
   non-root UID (10002), fixed entrypoint and absence of secrets.
2. First verify a **network-disabled** image import/CLI-help smoke in an
   owner-controlled disposable environment; this cannot prove Gateway egress.
3. For a real private invocation use Docker `--read-only`,
   `--cap-drop=ALL`, `--security-opt=no-new-privileges`,
   `--user=10002:10002`, restricted PID/CPU/RAM, no ports, no host PID/network,
   no privileged mode, and only the exact private paths above as mounts.
   Permit one fixed **Gateway TLS** destination using independently enforced
   egress policy; Docker network membership alone does **not** prohibit
   direct GitHub/internet egress. Prove both connectivity to Gateway and
   denial of direct GitHub/other destinations from the container.
4. Before `preview --pr 118` confirm Gateway has been released under
   protected UC-GW-005 Check/Apply/Backup/Promote, with original UNCERTAIN/
   CLAIMED preservation and independent quiescence attestation. Independently
   inspect the **publisher grant's** live capabilities, fixed repository,
   ASK-only label operations, exact profile/validator pins and own-receipt scope.
   Missing/disabled/foreign/broad capabilities => STOP.
5. Keep [pilot PR #118](https://github.com/AlexPastukhh/fortis-approvals/pull/118)
   open and non-draft. Read its *current* HEAD, body, labels, registration,
   both latest required exact-HEAD CI attempts and complete jobs.
   Run one `preview`; if and only if all gates pass, owner invokes a
   **single** `request` for the same PR. Review the immutable ASK in Owner
   Portal/WebAuthn. Use `inspect` with original intent/attempt IDs and
   independent current target readback. No replay of UNKNOWN, no automatic
   bulk labels, no PR merge and no deployment.
6. Run it only on owner demand; exit after one operation. A timer/webhook
   or an always-running listener is a **separate** unapproved future change.

For an owner-review illustration only, the command *shape* is:
```text
docker build --build-arg PYTHON_BASE=python:3.11-slim@sha256:<REVIEWED-DIGEST> -f fortis_approvals/deploy/Dockerfile-P3-Release-Label-Publisher -t <OWNER-REVIEWED-IMAGE> .
docker run --rm --read-only --cap-drop=ALL --security-opt=no-new-privileges --user 10002:10002 --network <OWNER-GATEWAY-ONLY-EGRESS> --pids-limit 64 --memory 768m --cpus 1 --mount <PRIVATE-READONLY-CONFIG+GRANT+CA> --mount <TRUSTED-READONLY-VALIDATOR> --mount <PRIVATE-RW-CACHE> --mount <PRIVATE-RW-EXISTING-INTENT-JOURNAL> <OWNER-REVIEWED-IMAGE> --config /run/publisher/config.json preview --pr 118
```
These placeholders deliberately block copy-paste execution. The owner must
independently verify actual mounts, image ID, network/firewall, health and
retained journal on the host; static Dockerfile checks are not isolation proof.

**STOP** on a missing image pin, uncertain release, active competing ASK,
invalid source/CI, unproven egress restriction, config/UID drift, missing
original receipt, or an already known executed effect. Preserve audit and
intent history; do not workaround by using the Repo grant or direct GitHub.

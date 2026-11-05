# Fortis Approvals

> **Owner-approved standalone source repository — 2026-11-03.** This repository is the canonical development source for Fortis Approvals Gateway. It is a verified extraction from `rd-graphs/fortis_approvals`. Git source is published to `AlexPastukhh/fortis-approvals`; the bootstrap source is on its own branch and modularized review work uses a separate task worktree. It is not the deployed runtime; R7 is retained only as a historical implementation identifier.

## Start here

- [AI-agent guide: Gateway role, policies and adding a service](docs/GATEWAY-AGENT-GUIDE.md)
- [Source map and operating status](fortis_approvals/README.md)
- [Current state](docs/guides/FORTIS-APPROVALS-SECURE-DEVELOPMENT.md)
- [Deployment artifact index](fortis_approvals/deploy/README.md)
- [Live Sonar E2E evidence](fortis_approvals/evidence/FORTIS-SONAR-LIVE-E2E-20261103.md)
- [Documentation map](docs/README.md)
- [Baseline offline test results — 245 tests](docs/TEST-RESULTS-2026-11-05.md)
- [Historical offline test results](docs/TEST-RESULTS-2026-11-03.md)
- [Source extraction audit](docs/audits/SOURCE-EXTRACTION-2026-11-03.md)
- [Integration modularization and GitHub onboarding plan](docs/INTEGRATION-MODULARIZATION-AND-GITHUB-ONBOARDING-PLAN.md)
- [Latest migrated Sonar GET evidence](fortis_approvals/evidence/FORTIS-SONAR-LIVE-GET-AFTER-MODULARIZATION-20261105.md)
- [Current isolated review evidence — image, restore, WebAuthn, live GET and offline tests](fortis_approvals/evidence/FORTIS-REVIEW-PREFLIGHT-20261105.md)
- [Original extraction SHA-256 manifest](docs/SOURCE-MANIFEST.sha256)
- [Current working-copy SHA-256 manifest](docs/CURRENT-SOURCE-MANIFEST.sha256)
- [Full modularized source manifest](docs/MODULARIZED-SOURCE-MANIFEST.sha256)
- [Manifest update and verification policy](docs/SOURCE-MANIFESTS.md)

## What this project contains

The Python package, tests, static assets, deployment references, live evidence and preserved historical artifacts from the original `fortis_approvals/` subtree.

The Python import root remains `fortis_approvals`, so the documented module entry points remain unchanged when commands are run from this repository root.

## Source provenance

Original source: `/workspace/repos/rd-graphs/fortis_approvals`

Extracted copy: `/workspace/repos/fortis-approvals/fortis_approvals`

The initial copy contained 196 non-generated files (1,721,755 bytes). Generated `__pycache__` directories and `.pyc` files were excluded. Every file matched the original SHA-256 manifest at extraction. Since then, this standalone copy has been modularized: SonarCloud now lives under `integrations/sonarcloud/`, a default-disabled GitHub integration has been added under `integrations/github/`, and GitHub repository/CI scaffolding has been prepared. The original extraction manifest remains immutable; `CURRENT-SOURCE-MANIFEST.sha256` tracks the same 196 baseline paths and `MODULARIZED-SOURCE-MANIFEST.sha256` tracks the full standalone tree. Regenerate/check them with `scripts/update-source-manifests.py`; see [manifest policy](docs/SOURCE-MANIFESTS.md). The original `rd-graphs` subtree was not moved, modified or deleted.

The current-state document was copied from `rd-graphs/docs/guides/FORTIS-APPROVALS-SECURE-DEVELOPMENT.md` and separately SHA-256 verified.

## Runtime boundary

This is a development/source copy only. Editing it does not change the active Fortis Approvals Gateway image or container. The owner-documented deployed image and existing volumes remain separate deployment artifacts; their exact historical identifiers are preserved in the deployment reference. Do not run provisioning, cutover, build, rollback or Compose scripts as part of ordinary source work.

## Isolated review status — 2026-11-05

Production remains on image `sha256:e751f6ca0cfe6ce290cf580de2f243071ee1f3e681baa8827c6cea41a16fa402`
and ports 19103/19104. The owner-tested modularized review image
`sha256:a6d3cbc645903fc3a36698868790ea1e191d73d1e9d5c01f7cecc97697c56e84`
runs beside it on 19203/19204 with separately restored state. Image smoke,
backup integrity/ACL/restore checks, 282 offline tests, a live Sonar GET and
owner login/History have been verified. The reject-only ASK/owner Reject check also passed, with the Issue remaining OPEN. No Production cutover or GitHub activation has
occurred. See the [review evidence](fortis_approvals/evidence/FORTIS-REVIEW-PREFLIGHT-20261105.md)
for exact source snapshot, backup hashes, limits and remaining gates.

## Git status

The primary clone `/workspace/repo/Repos/fortis-approvals` stays on `main`.
The verified modularized bootstrap was published as
`bootstrap/verified-source-2026-11-05` at `3355941`. Review work is isolated in
`/workspace/repo/Worktrees/fortis-approvals/candidate-origin-overrides-20261105`
on `candidate/test-origin-overrides-20261105`. Check current branch, staged
changes and remote refs before any write; publication of a source branch does
not deploy a Gateway or update a Windows clone. The original `rd-graphs`
subtree remains untouched.

## GitHub readiness

The repository scaffold includes `.github/workflows/source-ci.yml`, Dependabot, issue and pull-request templates, `CONTRIBUTING.md`, `SECURITY.md`, and `scripts/test-source.sh`. CI uses a read-only `GITHUB_TOKEN` permission set and runs only offline tests. The bootstrap source is already published. Branch-protection and Actions acceptance are not established by a successful push. The Gateway GitHub integration remains unregistered, with no GitHub token volume, grants or live policy; this is separate from the existing Repo Git credential helper.

## Safety

- Never copy machine grants, TLS private keys, Sonar tokens, owner WebAuthn state or runtime databases into this project.
- Keep deployment secrets in their dedicated runtime volumes.
- Live `review` commands can create real ASK requests; do not invoke them as an offline test.
- Run only targeted offline tests until a separate live test is explicitly requested.

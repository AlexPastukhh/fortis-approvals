# Extension framework — source acceptance 2026-11-06

Scope: `task/extensible-provider-registry-20261106`, based on Docker main
`2f88d92091e7d652ea0f33486fbeb38f2eaedd21`. No image build, live mutation, token
provisioning, volume change or Production action was performed by these checks.
Contract: [integration extensions](../../docs/INTEGRATION-EXTENSIONS.md).

## Offline checks

- Targeted extension/security/packaging/storage checks: **40 tests PASS**.
- Additional real TLS/R7 + cryptographic owner WebAuthn scenario: **1 test PASS**.
- Full supported offline suite: **395 tests PASS**, exit 0 (about 190 seconds),
  using `/workspace/repo/.rdg-webauthn-venv/bin/python` and `scripts/test-source.sh`.
- Python compileall, whitespace and regenerated source manifests: **PASS**.

The new tests cover ALLOW read/write; ASK read without pre-approval provider IO;
strong ASK write; Reject/Approve, stale preview and token generation; request-ID
conflict/replay; uncertain result with read-only receipt lookup; actor/target/
policy denial and revocation; secure vault permissions, symlinks and atomic CAS;
fixed HTTP routes, header auth, redirects, response bounds and safe errors;
secret output including JSON-escaped credentials; HTTP 202; staged mutation
blocking; native wrapper compatibility; real scaffold/discovery and disabled stub.
The TLS scenario reuses existing real server/owner crypto fixtures and a fake
provider. It proves source wiring, not upstream authorization or Windows behavior.

The packaging check executes imports/smoke from the Dockerfile's source COPY set
with the documented exclusion subset. It caught and fixed an overbroad ignore
that excluded the credential module; the module now uses `vault.py` so it also avoids
the existing credential-file Git/manifest exclusions. This is a source check, not a Docker build.

## Manual acceptance still required

This offline record covers controller source inspection. The Windows CI job is
configured to run the real PowerShell parser and non-Docker SelfTest (JSON array
handling and caller parameter forwarding); consult its exact-head run separately.
Windows PowerShell 5.1 host execution beyond that self-test,
NTFS ACL, Docker CLI/volumes, confidential prompt, pull/build continuation,
stop/clone/start, staged activation, interrupted resume and return (including a
stopped activated candidate) are **MANUAL-PENDING** on the actual owner host.
No local substitute host/Docker implementation was used to claim these passed.

A future provider also needs real scopes and operation readback/Reject/Approve/
replay acceptance. Catalog reports permissions as UNVERIFIED; file readiness is
not a permission test. No provider token or real provider is bundled as a demo.
Existing optional Sonar/CI operations remain outside this framework's activation.

The pending WorkflowClient HTTP 202 worktree and the bootstrap/M3 deployment
sources were not modified or included in this candidate.

## Owner-reported first installation failure

Windows main pulled merged source `48315a2ada6df40c6e300e8e7359e92316a7b9a2`.
Build, config, image smoke, Repo client, source admission and native state clone
passed per owner output. Attempt `6962bbdb800244138cd59a45df367f93` failed at
CREATE_STAGED with RELEASE_CONFIG_CHANGED; automatic Return hit the same check.
No activation was reported. Recovery and subsequent machine readback are recorded below.

Source defect: unparenthesized string concatenation inside a comma-separated
PowerShell array collapses the two extension env rows. The admission check
correctly rejected it, but Return incorrectly depended on identical admission.
A second occurrence affected argument forwarding. The fix constructs the two
rows explicitly, tests the real builder and malformed case in SelfTest, and
round-trips the actual Docker env file before stopping the source.

A recovery-only admission accepts that exact malformed pair only for a created,
never-started, unactivated candidate whose cloned state still matches the saved
receipt. Full image/ID/security/mount/legacy-env admission and source-state checks
remain required; Resume never uses this exception. No data/container/volume is
removed. Recovery was prepared in the existing isolated task worktree while the
Gateway was unavailable; no direct Git/helper/connector bypass was used. Source
publication uses the recovered Gateway.

Recovery package: `Workfiles/_fortis_windows_transfer_tmp/recover-review-6962-envfix-20261106/Recover-FortisReview.ps1`.
The package runs the real Windows parser/SelfTest before Return, verifies source
hashes, and targets only that protected attempt record. Owner output confirms
SELFTEST_PASS, RETURN_NEVER_STARTED_ENV_BUG, RETURNED_SOURCE and RECOVERY_PASS.
Package SHA-256: `aae67cb45dcb3103006f356927f183ce36a3781572b50800d615d06e5c11ee31`.
Recovery was executed with the frozen controller snapshot in that package; the
subsequent parameter-forwarding helper is checked by the PR Windows CI job.
Afterward AI readback through Gateway succeeded for native capabilities, GitHub
branches and Sonar quality gate (CURRENT_DEFAULT_BRANCH OK; PR/SHA binding remains
NOT_VERIFIED_D2). This proves the prior review is reachable again, not activation
of extensions. Retry installation and its new Docker env round-trip remain pending.
Targeted source packaging/storage checks after the controller fix: 10 PASS.

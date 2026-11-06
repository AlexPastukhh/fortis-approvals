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

`Manage-Integrations.ps1` was inspected as source only. Windows PowerShell 5.1,
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

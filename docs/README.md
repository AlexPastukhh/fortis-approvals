# Fortis Approvals documentation

Goal-based entry: `/workspace/repo/README.md` → the active container registry.
Every chat reads only its short introduction, without scanning the whole table, and reads UC-CONT-002 (Docker → GitHub → CI →
Windows/Mirror) and UC-CONT-003 (GitHub through typed Gateway client) in full;
other case details are task-dependent. This map indexes technical owners,
not a second container registry.

Each active topic has one owner document; entry points link to it rather than
repeat runtime snapshots or policy tables.

[Local Gateway Use Case index](use-cases/README.md) lists only accepted
application-specific scenarios; central cross-project rules stay in Fortis Container.

| Topic | Source of truth |
| --- | --- |
| Deployed instances, verified scope and limits | [Current state](guides/FORTIS-APPROVALS-SECURE-DEVELOPMENT.md) |
| New provider operations, policy, token provisioning and update controller | [Extension contract](INTEGRATION-EXTENSIONS.md) |
| Add/rotate tokens: existing GitHub/Sonar or named vault | [Credential rotation](CREDENTIAL-ROTATION.md) |
| Add another Owner Portal passkey | [UC-GW-008](use-cases/owner-passkey.md) · [Owner-only invitation script](../fortis_approvals/deploy/Invite-Primary-Owner.ps1) |
| AI use, trust boundaries and adding a service | [Gateway agent guide](GATEWAY-AGENT-GUIDE.md) |
| Optional analysis-review source operations (not deployed) | [Analysis review contract](ANALYSIS-REVIEW-CONTRACT.md) |
| Native Git/worktree operations, policy and command contract | [Native workflow](NATIVE-WORKTREE-GATEWAY-2026-11-06.md) |
| Upcoming work, acceptance gaps and priority P0 | [Single backlog](BACKLOG-IMPROVEMENTS.md) |
| Source modules and test entry points | [Package source map](../fortis_approvals/README.md) |
| Provider-specific implementation | [Integration catalog](../fortis_approvals/integrations/README.md) |
| Deployment scripts and retained return paths | [Deployment index](../fortis_approvals/deploy/README.md) |
| Completed onboarding milestones | [Onboarding record](INTEGRATION-MODULARIZATION-AND-GITHUB-ONBOARDING-PLAN.md) |

## Evidence and historical references

- [Owner Shell PS-V1-09 guarded release and PS-V1-10 first `Get-Date` — owner report, 2026-11-10](../fortis_approvals/evidence/OWNER-SHELL-RELEASE-AND-GET-DATE-20261110.md).

- [Primary Gateway promotion, recovery backup, Docker restart and Legacy retirement — 2026-11-07](../fortis_approvals/evidence/FORTIS-PRIMARY-CUTOVER-LIVE-20261107.md).
- [Native Git/worktree live cycle — 2026-11-06](../fortis_approvals/evidence/FORTIS-NATIVE-GIT-LIVE-20261106.md).
- [Multi-repo release, host-only workflow lessons and live write acceptance — 2026-11-07](MULTI-REPO-WORKFLOW-REVIEW-20261107.md).
- [Native offline acceptance — 342 tests](../fortis_approvals/evidence/FORTIS-NATIVE-GIT-OFFLINE-20261106.md).
- [M1 branch pilot](../fortis_approvals/evidence/FORTIS-GITHUB-PILOT-M1-20261106.md) and [M2 file/draft-PR pilot](../fortis_approvals/evidence/FORTIS-GITHUB-PILOT-M2-20261106.md).
- [Sonar READ / ASK / Reject / Approve — 2026-11-04](../fortis_approvals/evidence/FORTIS-SONAR-LIVE-E2E-20261104.md).
- [Migrated Sonar GET — 2026-11-05](../fortis_approvals/evidence/FORTIS-SONAR-LIVE-GET-AFTER-MODULARIZATION-20261105.md).
- [Earlier isolated review](../fortis_approvals/evidence/FORTIS-REVIEW-PREFLIGHT-20261105.md).
- [Earlier offline test reports](TEST-RESULTS-2026-11-05.md), [extraction tests](TEST-RESULTS-2026-11-03.md), [extraction audit](audits/SOURCE-EXTRACTION-2026-11-03.md).
- [Deferred Production release contract](MODULARIZED-RELEASE-EXECUTION-CONTRACT-2026-11-05.md).
- [Manifest policy](SOURCE-MANIFESTS.md): [immutable extraction](SOURCE-MANIFEST.sha256), [current baseline paths](CURRENT-SOURCE-MANIFEST.sha256), [full source tree](MODULARIZED-SOURCE-MANIFEST.sha256).

Dated evidence describes its own snapshot. Old handoffs and archived provisioning
instructions do not override the current-state or operation contract.

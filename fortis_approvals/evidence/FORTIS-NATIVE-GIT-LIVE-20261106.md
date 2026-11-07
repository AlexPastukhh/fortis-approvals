# Native Git/worktree live acceptance — 2026-11-06

Status: **PASS in the isolated review**, not a Production rollout or Windows
mirror acceptance. Evidence is the owner-supplied bootstrap output, durable
Gateway results and saved Repo-client run records. Documentation revalidation
read PR №11, merge/cleanup receipts and clean Docker main through Gateway again.
No GitHub connector or legacy Git credential helper was used for this native cycle.

## Runtime and baseline

- Repository: `AlexPastukhh/fortis-approvals`; one existing Repo machine actor.
- Owner bootstrap run: `bf089ec8547f4a0bbc95004f692e70bf`.
- Runtime source: `06791650ca86617e5c9f951439ef8cc53ec98847`.
- Owner-reported image: `sha256:e3ef9029a13284f5baadc7c1529c5d3b94a67fc9c045be1ed91950937c46c5f1`.
- Owner/machine endpoints: `http://localhost:19203` / `https://host.docker.internal:19204`.
- Windows bootstrap exited 0, reported 19 pilot and 27 FilePR self-test cases,
  network-disabled image smoke, retained M3/receipts, Sonar `OK`, unchanged
  Production baseline and `FORTIS_GITHUB_NATIVE_WORKTREE_READY`.
- READY had `liveNativeCycleVerified=false`; the two later cycles below provide
  live acceptance. The original Windows bootstrap record is not rewritten by
  these Repo-client runs.
- M3 had already accepted Gateway Source CI reads for PR №8 head
  `a2cb4a59bf2251cc05301a9da17e3a9fd02a19ee`, run `42101319273`, completed/success.

## Source publication cycle

Local task `gateway-worktree-native-git-20261106` was adopted and its existing
source commit published through Gateway with identical local/upstream SHA.
Completed-request replay did not publish again. Owner approved draft PR №10,
mark-ready and merge; Gateway checked Source CI for the exact head.

| Item | Result |
| --- | --- |
| Source/head SHA | `06791650ca86617e5c9f951439ef8cc53ec98847` |
| PR | [№10](https://github.com/AlexPastukhh/fortis-approvals/pull/10) |
| Source CI | `42137145997`, completed/success for that head |
| Merge SHA / Docker main | `9b6770531d856b2bae25350536516cd6f95a573b` |
| Post-merge read | Docker main clean; Sonar `OK` |

## New-task cycle

Task `native-e2e-bf089ec8` was created from that main through Gateway.
Typed edit/check/stage/commit produced two actual Git commits; first and
subsequent push preserved their SHA. Check used the fixed syntax profile,
not a full project test run. An attempted stage with an outdated digest was
denied; commit and push replay did not duplicate their effects.

| Item | Result |
| --- | --- |
| First commit | `bdb958303fac0bfe10583f93a94b89ef005e7bdf` |
| Final head | `16beefc5a4c32fcdc7e5d03f27e68bb2cd83343f` |
| PR | [№11](https://github.com/AlexPastukhh/fortis-approvals/pull/11), regular PR |
| Source CI | `42138518893`, completed/success for the final head |
| Merge / Docker main | `54d332a12a478cd4d01b6d43d634b307092498a4` |
| Cleanup | `EXECUTED`, `removed=true`; test worktree and its local branch removed |
| Final reads | Docker main clean; Sonar `OK` |

## Durable request references

| Cycle / operation | Request ID |
| --- | --- |
| Source push | `15e6ac30-69fd-422d-9f67-d4eafc8de6ac` |
| Source PR | `620d49b9-5b26-474d-80b7-f4fbd882110a` |
| Source ready | `5e326d6f-0223-4990-8de9-6d14d2734770` |
| Source merge | `4eb4c77f-b7a7-479e-8e32-16f0941541e4` |
| Source main update | `bd3413d1-ebbd-4ed9-9da2-db7a7ee12a79` |
| New task | `f6e80dc3-6c4e-4446-995d-08edbed04f56` |
| Commit 1 / 2 | `d06e2712-d50c-471a-827e-2a8227c8415d` / `3f0de801-2831-4b85-a57d-b00d707bf7c0` |
| Push 1 / 2 | `b100b63d-ce6c-410d-89c8-5df9fc376ea2` / `d81c401b-ae69-44d8-b5f8-8149df6574f5` |
| Stale stage | `d0aa5e45-1cc2-4efa-bf79-489cf401070d` |
| Test PR | `c0bc1019-c87d-4748-80d7-4fdecfdb26f7` |
| Test merge | `a03b0dce-d911-4693-bd76-f1fdbb26fb10` |
| Test main update | `cf035d21-7d88-4393-acb3-f34eb26056ac` |
| Cleanup | `38e53a51-50a5-41e5-9ace-eff95451bccf` |

Private operator records remain outside Git under
`Workfiles/fortis-native-git-live-20261106-bf089ec8/`: `record.json` and
`workspace-e2e.json` (final phase `NATIVE_WORKTREE_LIVE_E2E_PASS`). Only the
public identifiers and projected results needed for evidence are recorded here.

## Pending status observation and limits

During cleanup waiting/resume, `WorkflowClient.result` rejected HTTP 202 for
`PENDING` because it expected 200. The user reported approving earlier than
expected. Timing is an observation, not evidence that an early Approve is
invalid or that it caused a server failure. The client must accept the documented
pending response. Cleanup was reconciled using the same ID and completed once.

A one-line client change (`accept_202=True`) and TLS regression were prepared in
`task/native-client-pending-status-20261106`; the saved red test failed and green
test passed. At documentation revalidation these are uncommitted local changes,
not merged source or a new deployed image. Follow-up is tracked in the
[plan](../../docs/BACKLOG-IMPROVEMENTS.md).

The [offline evidence](FORTIS-NATIVE-GIT-OFFLINE-20261106.md) separately covers
binary/deletion/mode preservation, sensitive workflow history, rejection,
concurrency, sync and UNCERTAIN paths. Those cases are not all live GitHub tests.
Checks/status token permissions and workflow-file writes are not established
by successful Source CI reads or ordinary task pushes. Sonar default-branch
`OK` is not a PR/SHA analysis binding. Windows main, Mirror API, Production
cutover and removal of the shared legacy PAT/helper were not performed.
The protected bootstrap worktree remains required by the owner-run record.

# Fortis Approvals agent entrypoint

Each new chat: read `/workspace/repo/README.md` and `/workspace/repo/AGENTS.md`,
read the short introduction of the linked container registry without scanning its table, then **read UC-CONT-002 and
UC-CONT-003 in full** before working. UC-CONT-002 owns Docker → GitHub → exact-SHA
CI → approved merge → Docker main → Windows/Mirror; UC-CONT-003 owns typed
GitHub-client/Gateway-only authorization, including STOP for unregistered repos.
Read this repo README, the applicable [local Gateway UC](docs/use-cases/README.md) and relevant technical owner only for the chosen task.
For any Gateway image/controller release (including tasks from other chats),
add [UC-GW-005](docs/use-cases/releases.md#uc-gw-005) and its owner runbook.
Never treat source merge as Windows/runtime installation or copy dated
one-off release commands.
Do not duplicate shared cases, runtime snapshots or policy tables here.

The user authorizes creating needed ASK proposals within an assigned task without
first asking conversational permission. Submit using the typed Gateway client,
then identify the PENDING request in Owner Portal. Owner WebAuthn remains required
for its effect; do not fabricate approval or broaden the task/policy. Report any
actual outer tool-review rejection and do not bypass it.

After every completed task step, compare the authoritative plan with actual
receipts/tests and the remaining prerequisites; correct obsolete future steps
and report the current completed/open/blocked step table. Every PR must include
the corresponding plan/checkpoint update (in this repository's backlog or its
linked authoritative runbook), accurate at the intended merge boundary.
Separate source/test status from CI, merge, installation and live acceptance;
never mark a future owner-controlled gate as passed. Recheck at actual merge;
if evidence or the plan changes, update the relevant source checkpoint through
the normal reviewed PR workflow, not by editing protected runtime state.

Primary stays on main; use a registered linked task worktree. Preserve other tasks,
the pending HTTP-202 client fix, bootstrap source and retained deployment records.
Native Git publication/PR/CI/merge use Gateway, not the GitHub connector or legacy
credential helper. Effective ALLOW/ASK and exact scope come from the live contract.

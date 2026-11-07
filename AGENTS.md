# Fortis Approvals agent entrypoint

Each new chat: read `/workspace/repo/README.md` and `/workspace/repo/AGENTS.md`,
read the short introduction of the linked central registry (no full table scan), then **read UC-CONT-002 and
UC-CONT-003 in full** before working. UC-CONT-002 owns Docker → GitHub → exact-SHA
CI → approved merge → Docker main → Windows/Mirror; UC-CONT-003 owns typed
GitHub-client/Gateway-only authorization, including STOP for unregistered repos.
Choose only applicable cases in [local Gateway registry](docs/use-cases/README.md).
Read this repo README and relevant technical owner only for the chosen task.
Do not duplicate shared cases, runtime snapshots or policy tables here.

The user authorizes creating needed ASK proposals within an assigned task without
first asking conversational permission. Submit using the typed Gateway client,
then identify the PENDING request in Owner Portal. Owner WebAuthn remains required
for its effect; do not fabricate approval or broaden the task/policy. Report any
actual outer tool-review rejection and do not bypass it.

Primary stays on main; use a registered linked task worktree. Preserve other tasks,
the pending HTTP-202 client fix, bootstrap source and retained deployment records.
Native Git publication/PR/CI/merge use Gateway, not the GitHub connector or legacy
credential helper. Effective ALLOW/ASK and exact scope come from the live contract.

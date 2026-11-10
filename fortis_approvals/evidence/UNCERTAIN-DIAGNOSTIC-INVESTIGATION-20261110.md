# UNCERTAIN diagnostic investigation — 2026-11-10 (read-only evidence)

This report identifies **observable failure stages, not proven root causes**.
It does not authorize retry, reconciliation, claim reset, forced shutdown or
changes to existing requests, receipts or their SQLite records.

## What the accepted source currently loses

- Core.execute() marks DISPATCHED before invoking adapter.apply(), but catches
  generic Exception and saves only REMOTE_OUTCOME_UNCONFIRMED. No exception
  class/message survives in Core events for the historical requests.
- Worker.execute() marks the local journal DISPATCHED before its effect, then
  catches generic Exception and persists FAILED/error=UNCERTAIN. The original
  exception class and location are not in the durable worker journal.
- WorkflowClient._finish_claim() intentionally persists UNCERTAIN on unexpected
  worker exceptions, and refuses blind resubmission after a lost acknowledgement.
- GithubAdapter may have an upstream effect without an accepted receipt; a
  missing receipt is not evidence of no push.

The above is sufficient to explain why the **exact exception** cannot be
reconstructed from the existing records. It is not sufficient to attribute
the original effect as executed or not executed.

## Live actor-scoped evidence collected before code changes

| Request | Core / worker | Independent evidence | Interpretation |
| --- | --- | --- | --- |
| cf5f963d-d550-4149-8ca0-1f6cd7622276 (workspace.inspect, feed_and_search_and_bank_and_brain) | UNCERTAIN / no worker job; no receipt | Core audit: APPROVED -> DISPATCHED -> UNCERTAIN within about 2 seconds. | No durable worker job was observed. Exact exception and whether a worker began are unproven. |
| f7e7b116-9666-4a35-b871-9d54682d2b30 (workspace.update_main_from_pr, feed_and_search_and_bank_and_brain, PR #4) | UNCERTAIN / worker FAILED error UNCERTAIN; no receipt | Exact merge SHA 85a32ba... is an ancestor of later local main; a *different* UUID succeeded at main update. | Current Git matches intended merge. The original UUID's effect is still unconfirmed. |
| ef7c2a2d-d8bb-57c1-a1aa-f111e0610b57 (github.push_commits, fortis-approvals) | UNCERTAIN / no native job; no receipt | Exact local commit d37417e... exists; corresponding remote task branch and PR were not found at readback. | Absence at readback does not prove the branch was never created. |
| 2df32a24-efb1-4dac-97f6-3b66147d8944 (historical workspace.create_task) | CLOSED_UNCONFIRMED / worker CLAIMED; no receipt | Verified administrative closure only; claim survives. | Do not re-deliver the claim, synthesize a receipt, or infer no effect. |

The three active UNCERTAIN IDs and historical CLAIMED were subsequently
preserved across an owner-managed Windows image release; their unchanged states
were read back over the authenticated Gateway machine endpoint.

## Changes proposed in this single source PR

1. Authenticated POST /v1/workspace/list_uncertain reads only current requests
   belonging to the authenticated machine actor. Bounded pages contain safe,
   minimal metadata, total count and next offset. No owner routes or worker
   actions are used. Individual pages are consistent, but cross-page updates
   require quiescent revalidation for an exact release scope.
2. The existing details(UUID) now includes an evidence-stage diagnostic:
   WORKSPACE_JOB_NOT_FOUND, WORKER_FAILED_NO_RECEIPT,
   WORKER_CLAIMED_NO_FINISH, GITHUB_RECEIPT_NOT_FOUND, etc. It explicitly
   records rootCause=UNDETERMINED and originalEffect=UNCONFIRMED for historical
   unknowns. It exposes no new raw exception strings or claim tokens.
3. A capability marker lets Repo distinguish installed support from source-only
   changes. Tests cover cross-actor denial, bounded pagination, read-only
   behavior, invalid requests and safe stage classification.

## Remaining root-cause work (not silently claimed as resolved)

To establish future exact causes, a separately reviewed mechanism must retain
safe, typed error categories at the effect boundary (before/after enqueue,
claim, local Git command, upstream GitHub operation, receipt and acknowledgement)
without exposing tokens, paths or raw exception strings. Worker journal and Core
must still never auto-retry an uncertain effect. New instrumentation cannot
recover exceptions already discarded by older worker/Core versions.

**Boundary:** This report is a historical read-only investigation; source
changes are not active on the live Windows Primary until approved release.


## Additional actor-scoped readback — later 2026-11-10

After the PR #54 owner release, live `list_uncertain()` returned **four** current
actor-owned requests instead of the earlier three. New request:
`6c20c00c-124c-4781-9dbd-c7875e7932d9`, `github.push_commits`,
repository `feed_and_search_and_bank_and_brain`, task
`action-execution-modes-20261110`, target commit
`d62437ebbb6eb87ecad366b867285dcbe709757a`.

Read-only `details()` showed `APPROVED → DISPATCHED → ERROR_OBSERVED →
UNCERTAIN`; no native worker or receipt. The new bounded Core diagnostic
recorded `GITHUB_ADAPTER / RUNTIME_ERROR` and the 19-second
dispatch-to-uncertain interval. This identifies an exception **family and
boundary**, not the original exception message or root cause.
Local commit exists. A first-page GitHub branch/PR read did not show a
matching published task; that negative readback does **not** prove that the
original push never occurred. Original effect remains `UNCONFIRMED`.

The historical `CLAIMED` request
`2df32a24-efb1-4dac-97f6-3b66147d8944` remains
`CLOSED_UNCONFIRMED` with no heartbeat and no receipt. Activity has
`quiescenceProven=false`. No historical request was retried, reconciled,
closed, claimed, reset or modified during this investigation.

Future source diagnostics make evidence more specific, but requests affected
before the instrumentation retain unknown error details. UC-GW-009 now
defines the separate **proven non-execution → fresh typed request** route.

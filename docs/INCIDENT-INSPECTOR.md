# Read-only incident inspector (PR 2 source candidate)

This is the implementation contract for `WorkflowClient.incidents.inspect(request_id)`.
The machine credential and Gateway authorization are unchanged. PR 2 is
**not** production deployment or a recovery coordinator; feature exposure in
Docker source does not establish a matching Windows image.

## One read, with no mutation

```python
from fortis_approvals.workflow.client import default_client

report = default_client().incidents.inspect(existing_request_id)
# For offline Core-only triage: inspect(existing_request_id, github_reads=False)
print(report['assessment'], report['missingEvidence'], report['retryAuthorization'])
```

The inspector checks live `globalRequestInventory.crossActorDetails`, requests
`/v1/workspace/details` with bounded pages (at most 10,000 events), rejects
page/order/state drift, and checks a final snapshot. Each Core page is a
separate read: the final recheck narrows but does not create a global
transaction.

Core event IDs are global AUTOINCREMENT values across all requests. Other
requests may allocate IDs between a selected request's events; sparse positive
IDs are valid, including across pages. Coverage uses the stable per-request
event total, exact offset and expected page length, not consecutive IDs.
Duplicate, decreasing, nonpositive or non-integer IDs fail closed with
`AUDIT_SEQUENCE_INVALID`; incomplete or excess pages remain
`AUDIT_PAGE_INVALID`. Changed fingerprints, states, receipts or worker
snapshots still prevent a confirmed outcome. Inspection never retries effects.

The projection suppresses raw reason, params except whitelisted
identity, owner proof, worker claim token, bearer, full exception text and
provider payloads. Optional GitHub READ uses only existing typed methods:
bounded branch and PR listings, exact `get_pull_request` for merge/ready
state, the bounded Release Label context, or the visual-review Issue run marker. For create_branch, matching
remote branch name + exact source SHA is target-state evidence; for
merge/ready, matching PR number + head SHA + state is target-state evidence.
Neither is proof of which UUID effected the change.
A discovered remote object is **not** attributed to the original request UUID.

`worker` includes observed CLAIMED/heartbeat timestamps when the deployed
Gateway supports the additive fields; missing or stale timestamps prove
neither effect absence nor worker quiescence. `visualReview` is a safe summary
of an existing durable run reservation/partial upload. Provider pagination,
denials and failed reads become explicit `missingEvidence`, never proof
of nonexecution. No direct network Git, GitHub token or new read route.

## Outcome and compatibility

- `CONFIRMED_EXECUTED`: Core has durable `EXECUTED` and an exact, original-UUID-bound
  native worker or GitHub receipt whose result matches the Core record.
  This is persisted Gateway/adapter confirmation, **not** a claim that the
  current remote branch/PR still has the same state.
- `CONFIRMED_NOT_EXECUTED`: `CANCELLED_BEFORE_DISPATCH` has the required
  audit event, no dispatch, no worker and no receipt, with complete evidence.
- `UNCONFIRMED`: all other cases, including `DISPATCHED`, `UNCERTAIN`,
  `CLOSED_UNCONFIRMED`, incomplete pages, mismatched/missing receipts, remote
  object absent or ambiguous. A live matching remote task HEAD is reported
  separately as `TARGET_STATE_CONFIRMED_ATTRIBUTION_UNKNOWN` in
  `outcomeAssessment`, never as original UUID execution or retry permission.
  Durable Issue-number/upload-count evidence may instead classify a partial
  visual effect; no duplicate Issue is attempted.

Schema v2 is an additive client-side projection with observed-at time,
source-specific `evidenceScope`, sanitized `origin/phase/code`, and explicit
`missingEvidence`; existing `details()` and `list_requests()` keep their
original response shape. A Gateway without
global cross-actor READ fails closed rather than falling back to an
actor-scoped inventory. No new Core DB migration.

`retryAuthorization` is always `NONE`. This API never calls `submit`,
`claim`, `finish`, `resume`, `reconcile`, owner routes or GitHub writes.
Even proven nonexecution requires separate fresh authorization and the
applicable UC-CONT-003/UC-GW-009 process. The proposed fast path and worker
fencing belong to separately reviewed PR 2b/3, **not** PR 2.

## Release Label reconciliation (P2 source)

For `add_pr_release_labels` / `remove_pr_release_label`, the additive
`releaseLabelReconciliation.state` separates a durable original effect from
its independently observed current projection:

- `CONFIRMED_APPLIED`: complete stable Core audit, original-UUID-bound GitHub
  receipt, matching Core result, and two consistent typed
  `get_pr_release_label_context` reads agree on exact HEAD/base/body and the
  complete receipt label set. A final Core recheck must also agree.
- `CONFIRMED_NOT_APPLIED`: proven `CANCELLED_BEFORE_DISPATCH`, no dispatch,
  worker or receipt, and stable current HEAD/base/body/labels matching the
  original preconditions. An absent label or `NOT_FOUND` alone is insufficient.
- `UNKNOWN_STOP`: all other cases, including changed fingerprints, concurrent
  labels, incomplete evidence, unavailable/disabled reads or a closed PR for
  which the existing open-PR-only context READ is unavailable. The separate
  original Core execution assessment remains available; a failed projection
  read never erases known execution and never authorizes another WRITE.

Both the intent coordinator and inspector validate the receipt's full label
set against `expectedLabelsSha256` and the permitted delta, including the
boolean `changed` flag. With at most five additions, at most 32 prior label
sets are possible; one removal has two. This accepts already-present adds and
no-op removals while rejecting unrelated label loss/addition or duplicates.
No second journal or provider authority is introduced. Provider output exposes
only bounded identifiers, hashes/counts and comparisons, not label names/body.

`retryAuthorization` stays `NONE`, including on confirmed nonexecution.
Repeated reads narrow observation races; they do not create a GitHub PR-HEAD
CAS, a global transaction, publisher automation or deployment evidence.

## Verification

Run focused tests `test_pr2_incident_inspector.py` and
`test_machine_uncertain_inventory.py` and `test_release_label_recovery.py`, then mandatory
`bash scripts/test-source.sh` with the declared owner dependencies installed.
Tests cover cross-actor secrecy, exact cancel/dispatch boundary, worker claim,
205-event pagination, changed pages, provider target-state without attribution,
old-Gateway fail-closed and zero mutation routes. Runtime acceptance,
source-image pinning and deployment need a distinct owner-approved release.

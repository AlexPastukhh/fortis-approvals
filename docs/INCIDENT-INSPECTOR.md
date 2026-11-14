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
page/sequence/state drift, and checks a final snapshot. Each Core page is a
separate read: the final recheck narrows but does not create a global
transaction. The projection suppresses raw reason, params except whitelisted
identity, owner proof, worker claim token, bearer, full exception text and
provider payloads. Optional GitHub READ uses only existing typed methods:
bounded branch and PR listings or the visual-review Issue run marker.
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

## Verification

Run focused tests `test_pr2_incident_inspector.py` and
`test_machine_uncertain_inventory.py`, then mandatory
`bash scripts/test-source.sh` with the declared owner dependencies installed.
Tests cover cross-actor secrecy, exact cancel/dispatch boundary, worker claim,
205-event pagination, changed pages, provider target-state without attribution,
old-Gateway fail-closed and zero mutation routes. Runtime acceptance,
source-image pinning and deployment need a distinct owner-approved release.

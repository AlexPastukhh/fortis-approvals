# Worker error categories and activity — 2026-11-10 source candidate

## Safety intent

Provide future-case diagnostic *evidence*, not a remote-effect verdict, not
claim recovery and not a release quiescence certificate. No existing
UNCERTAIN or CLAIMED record is repaired, retried, marked done or removed.
The installed live Primary from PR #52 remains unchanged by this source PR.

## Implemented candidate

- The existing persistence-pinned `core.py` remains byte-identical. Native
  Workspace and GitHub adapter wrappers append an `ERROR_OBSERVED` audit
  event with a whitelisted exception category and fixed adapter stage before
  Core records UNCERTAIN. `failure=REMOTE_OUTCOME_UNCONFIRMED` remains.
- Repo worker retains `UNCERTAIN:<CODE>` in its existing local journal after
  `DISPATCHED` when the effect throws, no raw exception message. A safe
  read-only `failure_code()` binds that row to request ID + payload digest;
  a missing/mismatched journal gives `UNKNOWN`.
- The native Gateway job table has additive nullable columns
  (`claimed_at`, `heartbeat_at`, `diagnostic`). Existing seven-column records
  migrate without rewriting job states, claims, payloads or receipts. The
  same `jobs` table is retained for existing controller admission rules.
- The original claim token can submit best-effort heartbeat while the
  worker executes; the Gateway checks machine grant, actor, request UUID,
  service and original token, and requires `state=CLAIMED`. Heartbeat only
  updates the observation timestamp: **not** lease renewal, re-claim, retry,
  cancellation, or executor liveness proof.
- A machine actor can read only its own `QUEUED`/`CLAIMED` inventory through
  `/v1/workspace/activity`; page size 1–100, offset ≤1,000,000. `quiescenceProven`
  is always false. Missing telemetry on historical claims is explicitly
  `NO_HEARTBEAT_UNCONFIRMED`; stale telemetry is also unconfirmed.
- A version-gated client enables heartbeats and the diagnostic field only
  when the **live** Gateway advertises `workerActivity` and
  `workerDiagnostics` markers. A new Repo checkout speaking to the older
  Primary keeps the exact four-field finish schema and sends no heartbeat.
- An optional, strictly allowlisted `{stage,code}` accompanies only new
  `finish(error='UNCERTAIN')`. The old four-field finish remains admitted;
  `details(UUID)` includes the new worker diagnostic when available.
  No raw secrets, payloads, claim tokens, traceback or original exceptions
  appear in inventory or diagnostic codes.

## Limits and release gate

A live actor can crash, hang or lose network after an earlier heartbeat.
A heartbeat can be received just before a worker crashes. An executor may be
running without ever delivering a heartbeat. Therefore **neither positive
nor negative activity telemetry proves quiescence or effect completion**.
The owner must still independently attest worker quiescence and preserve all
exact active UNCERTAIN and historical CLAIMED IDs in every release.
Never treat absence of `/activity` rows as permission to restart a claim.

Expected release requires a separate approved image and tests verifying
TLS actor boundaries, legacy 7-column migration, no replay, no raw exception
leakage and protected backup admission; source/PR is not deployment.

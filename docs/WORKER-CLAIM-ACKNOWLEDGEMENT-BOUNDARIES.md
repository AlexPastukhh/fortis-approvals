# Native worker claim and acknowledgement failure boundaries

This documents the Repo-side worker transport regression, **not** the root
cause of any historical incident or a new Gateway deployment.

1. Gateway `Store.claim` persists `CLAIMED` before handing a job to Repo.
   `Worker.execute` opens its local SQLite journal only after that point.
   A caught exception at the intervening boundary formerly escaped the
   Repo `WorkflowClient` and skipped `/v1/workspace/finish`, leaving `CLAIMED`.
2. `WorkflowClient.command` and `.resume` now share one guarded worker-call
   path. An ordinary Python `Exception` in the worker is reported as
   `result=null, error=UNCERTAIN` under the **original claim**, never as a
   proven non-effect. Core still records `REMOTE_OUTCOME_UNCONFIRMED`.
   Exception messages are not transmitted to Gateway and no worker retry runs.
3. If `/finish` itself has an uncertain acknowledgement, the client does not
   retry it or the worker blindly. Owner/AI uses `details(uuid)` and distinct
   Git/journal evidence; `result(reconcile=True)` may recover a **durable**
   existing receipt but cannot establish an unrecorded effect.
4. Gateway `Store.claim` returns the execution token/payload **only for the
   first `QUEUED → CLAIMED` transition**. A later request for an already
   `CLAIMED` job returns only `{state: CLAIMED}`; no authorization to replay
   a possibly unjournaled effect or expose the previous claimant's token.
   Original worker may still call `/finish` with its initial claim. Concurrency
   is serialized by the SQLite transaction; later actors cannot acquire a
   second executable claim. This does not auto-reset historical claims.
5. A process crash, `BaseException` or Gateway/network outage can still leave
   `CLAIMED`, with or without a local journal. There is no automatic lease
   reaper, claim reset, synthetic receipt, or assumption of absence of effect.

Offline TLS/fixture tests in `test_native_worker_exception.py` cover exceptions
before a local journal, a possible partial effect, a lost `/finish` response,
and `resume`. Historical UUID `2df32a24-efb1-4dac-97f6-3b66147d8944`
remains `CLOSED_UNCONFIRMED` with a preserved `CLAIMED` job and must not be
retried or administratively mutated by this client fix.

The `WorkflowClient` exception-to-`UNCERTAIN` fix came from PR #48 and affects
Repo-side Python source only. The subsequent single-delivery claim guard changes
**Gateway `Store.claim` server source**; after owner merge and exact-SHA CI,
its activation requires a **separate Windows Gateway image release**, with
protected `CLAIMED` preservation and owner quiescence proof. Do not infer
that merging a PR activates server behavior on the current image.

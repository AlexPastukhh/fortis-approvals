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
4. A process crash, `BaseException` or Gateway/network outage can still leave
   `CLAIMED`, with or without a local journal. There is no automatic lease
   reaper, claim reset, synthetic receipt, or assumption of absence of effect.

Offline TLS/fixture tests in `test_native_worker_exception.py` cover exceptions
before a local journal, a possible partial effect, a lost `/finish` response,
and `resume`. Historical UUID `2df32a24-efb1-4dac-97f6-3b66147d8944`
remains `CLOSED_UNCONFIRMED` with a preserved `CLAIMED` job and must not be
retried or administratively mutated by this client fix.

This change affects **Repo-side Python client source only**. An accepted PR
must be brought into the clean Repo `main`; it does not on its own require a
Windows Gateway image release. Any future change to Gateway `Store.claim`,
Core, ingress or deployed worker policy requires separate release acceptance.

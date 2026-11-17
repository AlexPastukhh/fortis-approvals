# P3.3 — trusted Release Label Publisher (accepted source, disabled)

**Status:** P3.3 SOURCE_ACCEPTED (owner PR #115), disabled unless explicitly enabled by
owner-reviewed configuration and a separate P3.4 release. No service, scheduler,
identity, grant, credential, image or runtime activation is installed here.
The [accepted P3 project](../../../docs/RELEASE-LABEL-PUBLISHER-P3-REVIEW.md)
owns D1–D7. The [release roadmap](https://github.com/AlexPastukhh/fortis-container/blob/main/docs/BACKLOG-IMPROVEMENTS.md)
owns the sequence; [UC-GW-011](../../../docs/use-cases/integrations.md#uc-gw-011)
owns typed Label effects. This file is the P3.3 technical source owner.

## Source boundary

- `publisher_source.py` obtains **two** Gateway `/v1/git/fetch` bundles:
  independently observed `main` and the registered open task PR's exact HEAD.
  It validates repository/ref/SHA, bundle digest, complete Git object graph,
  ancestry of PR base within current main, and full merge-base history.
- A fresh owner-private data view reads raw regular Git blobs through bounded
  `cat-file --batch`. No PR checkout, archive attributes, hooks, filters,
  submodule recursion, code import or script execution. PR-controlled contents
  are **data only**. Limits: 24 MiB per bundle; 5,000 files; 16 MiB/file;
  48 MiB/view; 100,000 objects and 256 MiB Git object data.
- `publisher_validator.py` checks the exact public-action Git HEAD pin and
  content of **every** file in its separately supplied trusted code root.
  Modified, extra, ignored and symlinked files/directories stop execution.
  Only that reviewed code root runs `ci_entry.run` and
  `label_admission_v1.plan_labels` under isolated Python, scrubbed Git/Python
  environment, process-group timeout and memory/CPU/file-size limits.
  There is no private second Release Impact classifier.
- `release_label_publisher.py` is an owner-invoked one-shot CLI. Its live
  scoped capability/profile checks require exact actor, repository, revision,
  ASK-only label operations, registered-task delegation and no broad Repo
  workspace/WRITE grants. The same shared CI admission verifies both latest
  exact-HEAD Source CI and Fortis Release Impact attempts and **all** jobs.
  Each pass uses at most 18 typed CI RPCs / 60 seconds; admission is read twice.
  Gateway separately rechecks approved CI evidence before a label WRITE.

## Configuration and invocation

`RunnerConfig.load` takes a private absolute-path JSON file containing **all**
fields: `validator_root`, `validator_revision` (full reviewed 40-hex pin),
`profile_sha256` (64-hex live profile pin), `cache_root`, `intent_root`,
`endpoint` (HTTPS Gateway origin), `grant_path`, `certificate_path`,
`owner`, and `enabled`. The owner must supply and review these values;
there is no fallback credential, environment activation switch, or automatic
provisioning. Code, cache and intent roots must be distinct, absolute,
non-symlink paths. `enabled=false` is the safe default in source; merely
merging this file does not enable the runner. Never commit a filled-in
owner config, grant or private certificate.

Owner-only **after P3.4 admission** (these are command shapes, not instructions
to activate in the shared Fortis Repo):
```sh
python3 -B -m fortis_approvals.integrations.github.release_label_publisher --config /private/publisher.json preview --pr 123
python3 -B -m fortis_approvals.integrations.github.release_label_publisher --config /private/publisher.json request --pr 123
python3 -B -m fortis_approvals.integrations.github.release_label_publisher --config /private/publisher.json inspect --intent-id UUID
python3 -B -m fortis_approvals.integrations.github.release_label_publisher --config /private/publisher.json inspect --pr 123
```

## Effects and evidence

A fresh preview computes a deterministic admission hash from exact source,
PR context, profile/validator, CI evidence and one bounded label delta. Poll
timestamps and binary bundle encoding do not change its identity. Missing
managed definitions produce `BLOCKED_MISSING_LABELS`; no delta gives
`NO_CHANGES`. Otherwise remove **one** sorted stale managed label first,
or add at most **five** sorted managed labels. Human labels and
`release:review-required` are preserved; sticky review may be added, never
removed. No bulk replacement, automatic repair or deployment is performed.

`request` reuses `IntentClient.github_action` and its **existing** private
`IntentJournal`. Optional `callerEvidence` in that journal is non-authorizing
metadata bound to the admission hash; it creates no second journal, approval
system or Core table. The Gateway issues the actual ASK; owner WebAuthn
decides the immutable preview. An existing PENDING, APPROVED or DISPATCHED
request prevents a competing publisher/Repo label operation.

`inspect` is **READ-only**: it reads the original attempt IDs, own Core
details and receipt plus an independent current target-label readback.
It reports original receipt verification separately from current source/CI
admission. A later CI failure, stale source, missing receipt READ or disabled
admission never erases a known `EXECUTED` effect. Unknown outcomes remain
unconfirmed; no replacement ASK, reconcile, retry or rollback is triggered.
For recovery follow [UC-GW-009](../../../docs/use-cases/incidents.md#uc-gw-009)
and the existing [native intent contract](../../../docs/NATIVE-WORKTREE-GATEWAY-2026-11-06.md).

## Source checks and remaining gate

Offline tests: `python -B -m unittest discover -s fortis_approvals/integrations/github/tests -p 'test_publisher_*.py' -v`.
For a **local, separately verified** public-action checkout, set
`FORTIS_TEST_VALIDATOR_ROOT` to that path; this harness variable is **not**
a production configuration feature. With no second checkout the cross-repo
integration tests intentionally skip, while pin, authority and real-Git
tests run offline. Run full `scripts/test-source.sh`, source manifest
verification and exact-head CI before source acceptance.

**P3.4 MANUAL-PENDING:** [Owner-sealed Gateway startup source](../../../docs/P3-4-PUBLISHER-OWNER-STARTUP.md)
and [separate disabled one-shot image candidate](../../../docs/P3-4-PUBLISHER-ISOLATED-RUNTIME.md)
adds source-only, default-deny second-principal composition. Owner-controlled immutable/readonly code and config,
separate isolated worker, non-Repo credentials and grants, exact reviewed pins,
network/isolation verification, live capabilities and a controlled owner ASK
with original receipt and independent readback. Do not run an owner pilot from
Fortis Repo or treat source CI as installation evidence.

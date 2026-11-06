# Analysis review source acceptance — 2026-11-06

Status: **offline source candidate; not deployed or live-provider accepted**.

Base: main `7d50f5ea3345ccfc2b422b1e6160a4958328e7bd`.
Task: `task/sonar-ci-analysis-operations-20261106`, canonical linked worktree
under `Worktrees/fortis-approvals/`. Main, the separate pending-HTTP-202 task,
bootstrap source worktree, retained M3 and other repositories were not changed.

The [operation contract](../../docs/ANALYSIS-REVIEW-CONTRACT.md) owns schemas,
activation, policies and correlation limits. This file owns validation only.

## Checks

- **PASS:** 22 targeted domain/security tests, including every new provider
  operation, actual loopback TLS 1.3 and virtual-owner WebAuthn, Reject/Approve,
  machine-owner route separation, stable UUID replay, stale previews and
  uncertain POSTs with no repeat.
- **PASS:** exact run/attempt/job/artifact/SHA/project/workflow validation,
  denied foreign projects/forks/attempts, PR metadata mismatch, branch-vs-PR
  report evidence labels, missing-metric handling and complete-page markers.
- **PASS:** bounded download host/redirect checks, no bearer/cookie forwarding
  to storage, token-pattern redaction, ZIP bounds/traversal, artifact digest
  mismatch and duplicate/non-finite JSON rejection.
- **PASS:** default candidate retains four legacy Sonar read grants; review
  configuration refuses Production endpoints. A CI-only additional repository
  does not gain native Git actions.
- **PASS:** release/storage source equivalence gate. The historical
  `gateway/sonar.py` remains byte-identical to the base; the optional transport
  is a separate module. Release hashes/checker were not weakened or retargeted.
- **PASS:** full supported suite, 364 tests in 34 groups (342 existing + 22 new).
  Final targeted checks cover the subsequent credential-redaction and R5 legacy-grant safeguards.
- **PASS:** regenerated current source manifests and check-only verification; whitespace and documentation links checked.

Commands run from the task root:

```sh
PYTHON=/workspace/repo/.rdg-webauthn-venv/bin/python bash scripts/test-source.sh
/workspace/repo/.rdg-webauthn-venv/bin/python -B -m unittest discover \
  -s fortis_approvals/tests -p test_analysis_review.py -v
python3 -B scripts/update-source-manifests.py
python3 -B scripts/update-source-manifests.py --check
git diff --check
```

The existing dependency environment has the pinned requirements-owner versions.
No new dependencies were installed in the shared Repo runtime. Test provider
transports are offline fixtures; no live Sonar/GitHub mutation or scan was run.
The image-copy import test is source packaging validation, not a Docker build.

## Manual acceptance still needed

A separately reviewed image/package/configuration must first be deployed to
isolated review. Keep the native bootstrap worktree and retained M3/volumes.
Do not reuse a deployment record with different source path/SHA.

The owner must verify the exact repo/project/workflow ID/path binding, token
scope and provider permissions. GitHub needs Actions read for run/job/artifact
inspection, applicable Checks read for check details, and Actions write only
if CI controls are enabled. Sonar task detail may require Execute Analysis;
issue triage additionally needs the applicable issue-management permission.
No permission was probed or widened by these source tests.

Then verify actual CI manifest production, exact run/attempt/SHA readback,
current provider response shapes, storage download hosts and errors, pending
and failed analyses, branch/PR correlation limits, and one reviewed Reject /
Approve / readback for each mutation family. Approval is not scan completion.

There is no claim of historical PR finding snapshots or cryptographic proof
of scanned bytes. Sonar triage may change a gate after an analysis. Windows
Mirror, Production rollout, credential migration, Owner Portal latency,
the separate HTTP 202 fix and the remaining follow-up plan are outside this change.

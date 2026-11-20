# Fortis Release Registry P5 — Gateway post-merge evidence envelope

**SOURCE-ONLY CANDIDATE / NOT REGISTERED / NOT LIVE.**
Contract owner: `fortis-approvals` per UC-GW-003. Product authority remains the
[Fortis Release Planning Contract](https://github.com/AlexPastukhh/fortis-container/blob/main/docs/RELEASE-PLANNING-CONTRACT.md)
and the accepted [P5 evidence readiness/gap specification](https://github.com/AlexPastukhh/fortis-container/blob/main/docs/RELEASE-REGISTRY-P5-POST-MERGE-EVIDENCE.md).
No new route, Core operation, actor grant, policy, token, volume, Registry WRITE,
Windows controller step, production image activation or GitHub Deployments POST
is delivered here.

## What this proposal adds now

`fortis_approvals/integrations/github/post_merge_registry_envelope.py`
provides **pure offline structural validation** for a proposed v1 envelope.
`inspect_candidate()` checks exact keys, finite/bounded lists, SHA formats,
repo and catalog binding, reviewed-body cutoff **claims**, exact-head CI
result **claims**, changed-path coverage **claims**, ordered PRs, dependency
claims, canonical hashing and rejection of forged installed/authorization
fields. A successful parse returns `SOURCE_CANDIDATE_ONLY` with
`evidenceVerified=false`, `admissionAllowed=false` and
`deploymentAllowed=false` **without exception**. It does not read GitHub,
verify protected signatures, run scripts or write to any Registry store.

A digest from this pure function establishes only identity of **caller-supplied
bytes**, not their GitHub origin, protected review cutoff, policy or owner
approval. A `sourceRef`, `actor`, `ancestryRef`, `complete=true`, `captureRef`
or `reviewCutoffRef` string is **not a credential or provenance receipt**.
The current `github.get_pr_release_impact_evidence` is restricted to an open,
non-draft, unmerged task PR, not a historical merged snapshot. Calling it for
an already merged PR and retrying a scope/precondition `403` cannot fill the
gap. The existing `get_pull_request`, check-run and bounded commit projections
likewise cannot reconstruct immutable complete historical release evidence.

## Proposed future typed operation (NOT implemented)

**Tentative name:** `github.get_post_merge_registry_evidence` (READ only).
This name does **not** appear in the closed `GITHUB_READ_OPERATIONS`, transport
router, Repo client, native ingress allowlist or capability catalog; its use
remains DENY. Approval of this document is **not** approval of that method,
its token scope or deployment. Independently review the actual operation
schema and principal/grants/route in a separate change under UC-GW-003.

A future collector would need a **trusted** snapshot identity bound to:

| Source | Required evidence (not mere strings/booleans) |
| --- | --- |
| Authentication | Independently verified collector principal, exact repo/actor scope and protected source/receipt identity; never credentials in Repo or PR. |
| Merge | Exact PR number/head, verified merge SHA and timestamp, selected merged `main` source SHA, actual ancestry, bounded complete pagination. |
| Review cutoff | Immutable or independently preserved reviewed PR body/Release Impact bytes, exact head and pre-merge cutoff; detect edits after the accepted cutoff. |
| Changed files | Complete exact-head path inventory with rename semantics, immutable digest and zero gaps; fail on unknown or unmapped paths. |
| Catalog | Exact enrolled `release/targets.yaml` content at pinned commit with blob/content digest and reviewed target-to-component/resource bindings. |
| CI | Required check policy digest, exact head/run ID/attempt and accepted success, no ambiguous reruns or partial pages. |
| Dependencies | Complete PR/repo/target dependencies pinned to source versions, cycle/unknown evidence rejection. |
| Durability | Source proof bundle/integrity checkpoint and retention/recovery model capable of supporting exact idempotency/CAS on future Registry WRITE. |

**No synthetic historical body:** if original PR text at accepted review cutoff
was not preserved, a current PR body is insufficient. The correct outcome is
`EVIDENCE_INCOMPLETE` until an explicitly owner-reviewed alternative trusted
attestation exists. A commit subject alone never proves its parentage. An
absent collector or a 403/timeout cannot mean an empty release batch.

## Component restrictions and release windows

P5 canonical desired records are **target/environment** identities, not a
repo-wide mutex. The separate component restriction layer records only
actual constraints by component, shared resource and operation. A missing
constraint means `NO_REGISTRY_RESTRICTION`, **not `ALLOWED`**. During Gateway
Check/Apply, backup or uncertainty, the original protected controller and
owner UCs retain authority even if Gateway itself is temporarily unavailable;
the Registry cannot infer quiescence or clear restrictions from missing data.
Independent source-only work need not be frozen by a whole-repo release label.

## Route/actor and failure gates for a future PR

Before any live endpoint, the owner must approve an explicit repository
allowlist, separate bounded authenticated READ principal, fail-closed route
verb/path/suffix, upstream GitHub token privilege, request/response limits,
body retention/redaction, exact catalog version, CI policy and protected audit.
Add negative tests for wrong actor/repo/head/base, stale selected `main`,
non-merged/draft, fork, missing reviewed-body cutoff, truncated paths/checks,
wrong run attempt, catalog drift, dependency cycle, replay and provider
403/429/5xx. READ access never confers WRITE, Registry admission or a
right to stop/restart Gateway.

**Activation ladder:** `SOURCE_READY` → `PR_MERGED` → separately approved
Gateway image release (UC-GW-005) → live capability and exact-scope READ
acceptance → separately reviewed Registry ingestion/owner audit. GitHub
Deployments P4 READ is already complete; no P4 re-release is required.
For P6 `REPORTED_COMPLETE`, a future owner statement is **not** independently
verified installed state and must never clear Gateway release constraints.

## Offline source checks

Run `PYTHONDONTWRITEBYTECODE=1 python3 -B -m unittest
fortis_approvals.integrations.github.tests.test_post_merge_registry_envelope`.
The test fixture is **not** a live GitHub readback: fake complete provenance,
wrong SHA, missing catalog/CI/path coverage, ambiguous attempts, identity
spoofing and unknown route all fail closed or remain unverified. The existing
CI suite and source manifests are required before publication. No credentials,
Production, Windows, Docker or Registry data files are created by these tests.

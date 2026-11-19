# P3 — Trusted Release Label Publisher: security/owner review

**Owner live acceptance (2026-11-19):** A separate isolated, owner-invoked P3.4 Publisher completed one `preview → request → WebAuthn → original receipt` cycle for [PR #118](https://github.com/AlexPastukhh/fortis-approvals/pull/118). Original request `ed0dce76-8402-4230-941e-a89b5639460d` is `EXECUTED`; UUID-bound receipt and independent `release:no-deployment` GitHub readback passed. This acceptance covers **one addition only**, not unattended automation, a removal E2E, CD Queue, merge or deployment. Exact evidence: [current state](guides/FORTIS-APPROVALS-SECURE-DEVELOPMENT.md). The initial source-only statements below describe the historical design stage, not the latest runtime status. Never replay the original request.

**Status: DESIGN_ACCEPTED ([owner PR #104](https://github.com/AlexPastukhh/fortis-approvals/pull/104));
P3.2 SOURCE_ACCEPTED ([owner PR #107](https://github.com/AlexPastukhh/fortis-approvals/pull/107));
P3.3 SOURCE_ACCEPTED ([owner PR #115](https://github.com/AlexPastukhh/fortis-approvals/pull/115));
P3.4 owner one-shot E2E PASS, 2026-11-19.** D1–D7 remain the accepted direction.
The source below does not provision a principal, grant, credential, worker,
timer or runtime. Source acceptance and owner activation remain separate
steps. P3 **manual pilot** is DONE; unattended operation is not accepted.

The [current roadmap](https://github.com/AlexPastukhh/fortis-container/blob/main/docs/BACKLOG-IMPROVEMENTS.md)
owns sequence and status. Classification/catalog semantics stay with the
[Release Planning Contract](https://github.com/AlexPastukhh/fortis-container/blob/main/docs/RELEASE-PLANNING-CONTRACT.md)
and its one public executable validator. [UC-GW-011](use-cases/integrations.md#uc-gw-011)
owns typed labels; [UC-GW-003](use-cases/integrations.md#uc-gw-003) owns new
client/server scope, [UC-GW-009](use-cases/incidents.md#uc-gw-009) continuation,
and [UC-GW-005](use-cases/releases.md#uc-gw-005) activation.
GitHub Deployments/CD Queue remain P4–P6; GitHub Projects is excluded by the roadmap.

<a id="p32-source-candidate--disabled-by-default"></a>

## P3.2 source candidate — disabled by default

The implementation stays in this Gateway package. The original review baseline
below records the gaps that motivated it; it is not the current source feature list.

- [Publisher profile](../fortis_approvals/integrations/github/publisher_profile.py)
  reserves actor `release-label-publisher-v1` and repo `fortis-approvals`.
  `PublisherProfile()` is disabled. Enabling requires reviewed policy/validator
  revisions, explicit read-only registry delegation, and separately owner-composed
  authentication, exact broker grants and ASK/ALLOW policy. `owner_policy_map()`
  returns a blueprint; registration/binding installs deny guards, never grants.
  No environment switch, credential loader or provisioning command was added.
- [Typed contract](../fortis_approvals/integrations/github/contract.py) and
  [client](../fortis_approvals/integrations/github/repo_client/client.py) add
  `list_head_workflow_runs(headSha,page,perPage)`: fixed `pull_request` event,
  page size 20, at most 5 pages/100 runs, explicit complete-page provenance.
  This operation is excluded from legacy automatic read grants and defaults DENY.
- [Shared CI admission](../fortis_approvals/integrations/github/release_label_ci.py)
  binds both reviewed workflow IDs/paths, active workflow definitions and their
  exact-HEAD blob SHA-256, latest run/attempt, same-repo PR provenance and all
  successful jobs. A final head inventory detects a later attempt. The additional
  CI budget is 18 fixed provider GETs and 20 seconds checked before/after each;
  an already in-flight GET retains the existing transport timeout. UC-GW-011's
  existing bounded PR/label reads remain separate. There is no public HTTP loopback,
  repository-history scan or second Release Impact classifier.
- [Native adapter](../fortis_approvals/workflow/adapters.py) applies this gate to
  opted-in repo PR-label routes, including legacy callers. Definitions remain a
  separate owner ASK outside the publisher grant. All three label routes share
  one active-request guard, including repository case aliases. `prepare` reads
  existing Core requests while unchanged `Core.submit/execute` hold their existing
  `BEGIN IMMEDIATE`; competing admissions are serialized. No extra intent table
  or journal is introduced. The adapter reads the actual immutable DISPATCHED Core
  row and rechecks its approved preview, owner decision, expiry, current ASK policy,
  initiating grant and profile immediately before the provider WRITE. Caller
  preview/approval fields cannot substitute for that row. Base Core bytes stay pinned.
- [Native ingress](../fortis_approvals/workflow/ingress.py) limits this principal
  to capabilities, own label result/details/positive receipt reconciliation and
  guarded source bundles. Fetch requires an exact SHA and fixed repo/main or an
  existing Repo-owned task with a ready open same-repo PR. It cannot create/adopt
  registrations, claim workers, inspect other actors or reach global inventory.
- [Scoped evidence contract](../fortis_approvals/integrations/github/publisher_evidence.py)
  advertises `requestEvidence.version=1`, `scope=own-release-label-requests`,
  `crossActorDetails=false`. Existing AI global read-only investigation is preserved.
  [WorkflowClient](../fortis_approvals/workflow/client.py)'s explicit
  `for_release_label_publisher(gateway=..., intent_root=...)` uses the supplied
  owner-private transport/journal and no Repo worker or credential fallback.
  The existing coordinator/inspector supports this mode. Original own receipts
  stay readable after future admission is disabled; known execution is preserved
  when independent current-state READ fails.

[Offline security tests](../fortis_approvals/integrations/github/tests/test_release_label_publisher.py)
cover cross-actor/restart/concurrent admission, post-approval CI/profile/policy/
credential races, foreign request denial, source fetch scope, read limits and
original-UUID receipt recovery. They do not establish live machine admission,
worker isolation, actual owner WebAuthn or deployment.
The public action's existing owner-ASK helper remains the legacy Repo path and
fails closed for this scoped principal. P3.3 must wire the reviewed validator,
source acquisition and one-shot entrypoint to the versioned client/CI contract;
P3.4 owns provisioning and the live controlled pilot. No publisher is started here.

## P3.3 trusted runner — original source stage, later owner activation

[Technical owner and one-shot CLI](../fortis_approvals/integrations/github/PUBLISHER-RUNNER.md)
cover exact-SHA Gateway bundles, data-only raw Git blobs, pinned public
validator, bounded double CI admission, one minimal label operation, and
read-only original receipt/target evidence. The private existing IntentJournal
stores optional non-authorizing admission evidence. Source tests include
real pinned public action integration; the runner has **not** been provisioned
or activated, and CI passing is not a live publisher demonstration.
P3.4 isolation, grant issuance and owner pilot were **MANUAL-PENDING at source acceptance**;
they were subsequently performed and verified by the owner on 2026-11-19. No scheduler, GitHub Projects or CD steps are started.

## P3.4 trusted startup — source opt-in, accepted one-shot pilot

[Owner-sealed startup composition](P3-4-PUBLISHER-OWNER-STARTUP.md) introduces
one fixed read-only private mount for a second machine credential and exact
reviewed profile/validator pins. Missing mount means disabled. The owner-only
profile is explicitly excluded from inherited Sonar/extension grants; it is
limited to fixed-repository GitHub READ and add/remove ASK. No grant, mount,
credential, worker, timer or active runtime is deployed by this source change.
[PR #118](https://github.com/AlexPastukhh/fortis-approvals/pull/118) stays open
for the completed owner pilot. The separate protected Windows Gateway release,
private runner isolation and owner WebAuthn pilot passed within the narrow
2026-11-19 evidence scope. Do not repeat them to check status.

## P3.1 verified baseline and gaps

Read-only preflight used clean Docker/GitHub main at:

- approvals `c52736aec5861c67b7ce2b2a58304a821cf8e413`;
- public action `6627da85cab34dec75333676ec6215de8e0130ff`;
- container `f671821df2810e3b8a3b913b4da016a542196e55`.

Live capabilities through the existing Repo principal report label writes
`ASK`, `unknownEffect=STOP`, `automaticPublisher=NOT_ACTIVE`, and registered
open same-repository task PR scope. This does not establish a publisher grant
or a second-principal live acceptance.

| Current source evidence | Consequence for P3 |
| --- | --- |
| [Native runtime install](../fortis_approvals/workflow/runtime.py) gives the configured Repo actor broad native operations | A publisher must have its own narrow composition; copying this profile is unsuitable |
| [Native ingress](../fortis_approvals/workflow/ingress.py) scopes capabilities/fetch/result to that Repo actor; [task store](../fortis_approvals/workflow/store.py) keys registration by actor | New principal access and read-only delegation to existing registrations require explicit source support |
| [IntentClient](../fortis_approvals/workflow/intents.py) and [inspector](../fortis_approvals/workflow/incident_read.py) currently require global cross-actor detail capability | A truthful own-request evidence mode is needed; do not fake `crossActorDetails=true` or create another journal |
| [Git bundle transfer](../fortis_approvals/workflow/git_backend.py) already fetches fixed main/task refs through Gateway, with expected SHA and bundle digest | Reuse this mechanism under narrow publisher authorization; it is not currently available to a new actor |
| [Label snapshot](../fortis_approvals/integrations/github/gateway/adapter.py) binds HEAD/base/body/labels, but [native label prepare](../fortis_approvals/workflow/adapters.py) does not add CI evidence | CI can change while ASK waits. A publisher preflight alone does not protect the approval-to-dispatch interval |
| [Shared CI collector](https://github.com/AlexPastukhh/fortis-release-impact-action/blob/6627da85cab34dec75333676ec6215de8e0130ff/tools/release/gateway_snapshot_v1.py) bounds full history to 25×20 runs and jobs to 100 | Preserve incomplete-read STOP. Add bounded head-scoped CI collection before putting dispatch checks on this path; do not scan unbounded repository history under a Core write lock |
| [Owner-ASK admission](https://github.com/AlexPastukhh/fortis-release-impact-action/blob/6627da85cab34dec75333676ec6215de8e0130ff/tools/release/owner_ask_label_v1.py) requires inactive publisher and the three-command legacy capability | A versioned publisher capability/client path must be reviewed; the current helper cannot simply be switched on |

These are source observations, not claims that the proposed profile or methods
are installed. The shared Fortis Repo workspace is AI-writable; it is not the
trust boundary for privileged publisher code, configuration or credentials.

## Recommended decisions for this first scope

| Decision | Proposal to accept |
| --- | --- |
| D1 — principal | Dedicated logical role `release-label-publisher-v1`, issued/revoked by owner-controlled composition; no borrowed Repo actor or GitHub token |
| D2 — repository | First pilot only `fortis-approvals`; an exact server-enforced repository policy before provider READ or WRITE. Token-wide dynamic discovery does not widen it |
| D3 — worker | Separate owner-managed worker outside the AI Repo container/workspace; immutable reviewed code/config, private data cache and private existing IntentJournal |
| D4 — trigger | Initially owner-invoked one-shot processing of one selected PR and at most one bounded label operation. No timer/webhook installation in this scope; unattended triggering requires its own accepted activation |
| D5 — effect | `ASK` for existing add/remove only; Owner Portal/WebAuthn for the actual effect. No ALLOW switch in the proposed pilot |
| D6 — admission | Independent exact-HEAD recomputation plus both latest complete CI gates, repeated at Gateway admission/dispatch with the approved preview binding |
| D7 — continuation | Reuse P2 intent/receipt/readback machinery. Existing active label requests block replacements; unknown outcomes follow UC-GW-009 rather than replay or automatic rollback |

The generic validator remains in the public action. Gateway owns principal,
policy, typed transport and CI admission; the trusted runner belongs in the
GitHub provider package of this repository. Neither layer maintains a second
Release Impact classifier. Baseline source SHAs above are review references,
not activation pins: the later owner release must bind the actual accepted
implementation, validator and policy revisions, never `@main` from a request.
This proposal does not change the existing CI callers' action SHA.

## Principal, data and credential boundaries

The following is a proposed grant scope, not current capability output.
Authorization is enforced at Gateway before upstream access; client-side
checks are additional guards. Role/actor/policy cannot come from PR data.

| Surface | Proposed publisher scope |
| --- | --- |
| GitHub READ | Exact pilot repo: branch/PR metadata, bounded release-impact body/context, repository/PR labels, run metadata and complete exact-attempt jobs; closed query types only |
| Source objects | Existing Gateway bundle transfer, main and a registered task ref at independently observed expected SHAs; no arbitrary URL/refspec/path |
| Evidence | Its own label-request status/details/result, with an explicitly scoped capability. Positive original-receipt reconciliation only under the existing protected rules |
| Label WRITE | `add_pr_release_labels` / `remove_pr_release_label`, ASK, existing definitions and UC-GW-011 bounds; no full replacement of labels |
| Everything else | DENY: workspace edit/commit/push/cleanup/claim, PR create/merge/update, CI controls/logs/artifacts, owner routes, secrets/credentials, definitions creation and deployment operations |

A publisher may not adopt another actor's intent, request result or worker
claim. Keep existing AI global read-only investigation semantics intact while
giving this non-AI service only scoped own-request evidence. Shared client
changes must distinguish those modes without misreporting inventory completeness.

The Gateway must resolve an open registered task using the configured Repo
registration owner and an owner-reviewed delegation rule. The publisher cannot
register/adopt/close tasks or supply a registry owner in its payload. A closed,
unregistered, forked, draft, wrong-owner or non-main PR stays outside scope.

GitHub credentials stay in Gateway. The worker receives only its separate
machine authentication, inaccessible from Repo/PR/CI, via owner provisioning.
Use a separate owner-managed container with a read-only root filesystem and
non-root process; only its private data cache and journal are writable.
Do not mount Fortis Repo/Workfiles, a Docker/host-control socket or owner state;
do not grant host PID/network modes, Windows Executor or Owner Shell access.
Permit the fixed Gateway TLS destination, not direct GitHub egress. The owner
must independently verify actual UID, mounts, network and secret delivery
before activation; source checks do not establish those properties.
Source checkout and label metadata never convey owner session, WebAuthn or
approval authority. No such credential or isolation was provisioned here.

## Trusted inputs and source acquisition

The reviewed profile binds repository, required workflows/jobs, validator code,
policy revision and registry delegation. Configuration is not discovered from
PR files, artifacts, logs, an arbitrary URL or caller-selected Python modules.

Initial CI identities from reviewed approvals main:

| Required workflow | ID and path | Required jobs |
| --- | --- | --- |
| Source CI | `408327525`, `.github/workflows/source-ci.yml` | `offline-tests`, `audit-projections` |
| Fortis Release Impact | `414303977`, `.github/workflows/release-impact.yml` | `release-impact` |

Workflow blob SHA-256 at the baseline source:

- Source CI: `f5a5ae93f28673bc9c981ba5702565ba91f115f1fe52d60aca3324a0fbd9fab1`.
- Release Impact: `e141908e8aeadf41088e7998842f72dea52ea4332346a5e3bd084e7de7d65218`.

For the initial profile, a PR changing either required workflow definition
requires explicit review/profile update and blocks automated ASK admission,
even if its jobs have familiar names. This is a publisher admission restriction,
not a new label or classification rule. An API run summary alone does not prove
trusted executed code or authorize publication.

Obtain authenticated PR/CI metadata and two Git bundles only through Gateway.
One bundle binds the observed current main, the other the registered task HEAD.
Verify repository/ref/SHA/digest, full history and reachability of the PR base
from the verified main history; an old PR base must not be mistaken for the
current main ref tip. Missing objects, shallow history, ref drift or partial
inventories stop admission.

Build a fresh data-only view at the exact PR HEAD in the private cache, with
fixed trusted Git commands and hooks, external filters/helpers, replace refs,
submodule recursion and inherited configuration disabled. Execute no PR script,
workflow, build, dependency installer, artifact or hook. PR body/catalog/source
are bounded data for the pinned validator. Use the full verified merge-base
diff, not a supplied subset. No shared Repo checkout or PR artifact is a
substitute for this acquisition path.

## One run and the approval boundary

1. Verify the enabled owner-reviewed publisher profile, exact code/config pins
   and supported scoped capabilities. Missing scope means STOP; no fallback to
   the broad Repo grant or direct GitHub access. Before activation only preview
   development/source tests are available, not a live publisher command.
2. Read the selected PR, acquire the data-only source above, and reuse the shared
   snapshot/admission/projection functions. Re-read both required workflows,
   their latest runs/attempts and all jobs, plus current HEAD/base/body/labels.
   Missing, stale, queued, skipped, failed or partial evidence stops admission.
3. Compute only the minimal managed delta. Preserve human labels and the sticky
   review flag. Missing definitions stop this run; their creation is a separate
   owner-controlled ASK outside the publisher grant. No delta means no request.
   Remove one stale managed label before adding a replacement projection;
   each later operation requires a new fresh plan. Do not enqueue a whole batch.
4. Select one bounded operation. Bind an admission revision to source/body/
   label fingerprints, delta, trusted profile/validator and CI identities.
   Identical admitted input resumes the same logical intent; polling timestamps
   do not create new intents. Persist through the existing IntentJournal before
   submit and retain all attempt IDs and the actual pending owner request ID.
5. Enforce an active-request guard at the Gateway admission transaction using
   existing durable Core requests. Initially at most one PENDING/APPROVED/
   DISPATCHED label request per pilot repository, across actors, including
   existing label routes. A client-only lock is insufficient. Return a bounded
   conflict and do not replace, cancel, approve or adopt a competing request.
6. Create one ASK through the existing typed add/remove route. The trusted
   repository-specific CI gate must contribute canonical evidence to Core's
   immutable preview and run again immediately before a provider WRITE.
   Compare with the actual approved Core snapshot obtained through trusted
   server context, never an `approved=true` field from the caller. Changed CI,
   policy, workflow definition, HEAD/body or label fingerprints means stale/STOP
   before WRITE. The Gate applies to the opted-in repo's label routes, including
   legacy callers; otherwise another route could bypass the same guard.
7. Owner WebAuthn authorizes the exact preview. Gateway performs its bounded
   label effect and existing whole-set/HEAD readback and stores the original
   receipt. Publisher then reads that receipt and independently checks current
   PR/labels and current CI. A failed later READ or changed CI must preserve a
   known EXECUTED effect while marking current admission/projection unconfirmed;
   it cannot invent nonexecution or silently undo labels.

Head-scoped CI lookup and a bounded dispatch read budget are implementation
gates, not existing public methods. Reuse the one shared CI-admission logic
through a narrow trusted read interface; do not loop back through public HTTP
or scan full repository history while holding Core's write transaction.
The implementation must show where approved CI evidence is compared at the
last pre-WRITE check; checking it only when the ASK was created is insufficient.

A CI rerun or changed profile while an ASK waits does not silently produce a
replacement ASK. Respect the existing active request until owner decision,
expiry or verified terminal state; then recompute admission for any new intent.
A real DENY stays a stop. UNKNOWN/CLOSED_UNCONFIRMED does not by itself prove
absence or permanently prohibit a new safe intent: use UC-GW-009 with concrete
operation guards and fresh authorization. Never replay the old UUID.

`EXECUTED` with unavailable receipt verification is read-only continuation.
A matching label set without an attributable receipt is only observed target
state. A race can remain between GitHub reads and labels WRITE because no
atomic PR-SHA/labels CAS is available; ambiguous results remain UNKNOWN/STOP.
Neither a label receipt nor any CI result is deployment evidence.

## Source slices and activation gates

| Slice | Concrete deliverable and required acceptance |
| --- | --- |
| P3.1 — this project | D1–D7 accepted by owner PR #104; implementation/activation gates remain separate |
| P3.2 — Gateway/client source | Separate publisher profile, truthful own-evidence capabilities/client compatibility, fixed-repo policy, registry delegation, scoped bundle access, bounded head CI lookup, preview/pre-WRITE CI binding and cross-actor active-request guard. Client/schema/server together under UC-GW-003; profile disabled/default DENY |
| P3.3 — trusted runner source | Owner-private data-only cache and existing coordinator, pinned single validator/config, one-shot preview/request entrypoints and deterministic minimal deltas; no timer or credential bootstrap side effect |
| P3.4 — owner release/pilot | Accepted exact source pins, owner-managed isolation/credential/policy admission, UC-GW-005 release if server/image changes, then fresh capabilities and a controlled ASK/readback pilot on a fresh registered open PR |

P3.2/P3.3 can be reviewed as source before any activation, but all gates must
hold together for the pilot. The runtime release must preserve unrelated
PENDING/APPROVED/DISPATCHED/CLAIMED/UNCERTAIN and protected recovery records.
Do not reuse closed P1 PR #76 or merge a PR merely to run the pilot.
Timer/webhook selection and enabling are a later owner-reviewed activation,
not something installed by source merge or inferred from CI success.

Before implementation acceptance, prove at least:

| Case | Required result |
| --- | --- |
| Wrong actor/repo, forged role/policy, missing profile, unrelated native/owner route | Denied before provider access; no broad-grant fallback; existing AI scopes unchanged |
| Missing registration/delegation, closed task, wrong ref/SHA, shallow/poisoned data view | No ASK, arbitrary fetch or PR-code execution |
| Newer failed/in-progress CI, incomplete/duplicate jobs, changed required workflow file | No admission; no old green attempt substituted |
| CI/profile changes while PENDING, after approval or just before provider WRITE | Fresh server gate rejects/stales the request; no stale mutation or forged preview binding |
| Concurrent publisher/Repo label attempts and restarts | At most one active request in the pilot scope; same existing intent/journal, no duplicated approval |
| Lost ACK, late/missing/foreign receipt, known EXECUTED with failed READ | Preserve all original IDs and known effect; bounded native continuation or UNKNOWN, never blind WRITE |
| Action classes, multiple targets/shared units, stale labels and human/review labels | One shared projection; minimal bounded changes, preserved labels and no deployment claim |
| Revocation/profile update/read limits/provider race and post-effect CI drift | Fail closed, retain evidence and existing effects; no automatic approval, cancellation, rollback or hidden retry |

Run the supported source/manifest checks in the owning repositories and require
exact-head CI. A fixture cannot establish a second principal's live access,
worker isolation, WebAuthn, runtime deployment or real provider behavior.
Those remain MANUAL-PENDING until the later owner-managed pilot records them.

For rollback, disable future trigger/admission first and preserve intent and
Core history. Pending owner requests are handled by the existing owner process;
revocation/profile changes must prevent later dispatch. No automatic bulk
label removal, Core database cleanup or replay is part of this project.

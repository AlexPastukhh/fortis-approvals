# P3 — Trusted Release Label Publisher: security/owner review

**Status: DESIGN_REVIEW_CANDIDATE, 2026-11-16.** This is the concrete P3
proposal for owner review after P1 live acceptance and P2 source acceptance.
It does not provision a principal, grant, credential, worker, timer or runtime.
Merging it accepts a design direction; implementation and activation have the
separate gates below. P3 is not DONE.

The [current roadmap](https://github.com/AlexPastukhh/fortis-container/blob/main/docs/BACKLOG-IMPROVEMENTS.md)
owns sequence and status. Classification/catalog semantics stay with the
[Release Planning Contract](https://github.com/AlexPastukhh/fortis-container/blob/main/docs/RELEASE-PLANNING-CONTRACT.md)
and its one public executable validator. [UC-GW-011](use-cases/integrations.md#uc-gw-011)
owns typed labels; [UC-GW-003](use-cases/integrations.md#uc-gw-003) owns new
client/server scope, [UC-GW-009](use-cases/incidents.md#uc-gw-009) continuation,
and [UC-GW-005](use-cases/releases.md#uc-gw-005) activation.
GitHub Deployments/CD Queue remain P4–P6; GitHub Projects is excluded by the roadmap.

## Verified baseline and the actual gaps

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
| P3.1 — this project | Owner review of D1–D7 and the scoped first-pilot boundary; DESIGN_REVIEW_CANDIDATE only |
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

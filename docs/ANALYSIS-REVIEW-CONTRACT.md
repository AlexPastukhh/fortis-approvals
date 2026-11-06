# Analysis review — source operation contract

Status: **SOURCE CANDIDATE, not deployed or live-provider accepted**.
This document owns the optional Sonar/GitHub analysis profile, schemas and
correlation limits. The [current-state document](guides/FORTIS-APPROVALS-SECURE-DEVELOPMENT.md)
owns deployed scope. The [native contract](NATIVE-WORKTREE-GATEWAY-2026-11-06.md)
still owns ordinary Git/worktree operations. This profile does not replace it.

## Activation and policy

All new operations remain DENY unless trusted composition explicitly receives
an `AnalysisReviewConfig`. Adapter registration alone never grants access.
The runtime reads the non-secret `FORTIS_ANALYSIS_REVIEW_CONFIG` JSON; it must
not be supplied by the machine caller. Unknown/duplicate keys and partial
configuration fail closed. This profile requires isolated review endpoints
19203/19204 and pinned Sonar project keys. It refuses Production endpoints.

Example configuration (workflow ID is an example, not a discovered live ID):

```json
{
  "owner": "AlexPastukhh",
  "sonarMutations": false,
  "bindings": {
    "obs-planning-docs": {
      "projectKey": "AlexPastukhh_obs-planning-docs",
      "workflows": {"12345": ".github/workflows/sonarqube.yml"},
      "allowCiControl": false
    }
  }
}
```

New reads are ALLOW for the configured actor and allowed provider scope.
New Sonar actions are ASK only when `sonarMutations=true`; CI controls are ASK
only for a repository with `allowCiControl=true`. Owner WebAuthn is mandatory.
Existing legacy Sonar reads/accept and native task-push policies are preserved.
The CI router can admit additional exact repositories without granting them
native Git operations. Token permissions and scope must independently permit
each operation; this source does not provision or widen credentials.

## Sonar reads

All targets in this table are the pinned **project key**, not an arbitrary
organization, issue URL or provider endpoint. Every response contains
`operation, projectKey, context, data` with a closed data projection.

`context` is exactly one of `{}` (default branch),
`{"branch":"task/example"}`, `{"pullRequest":"123"}`.
A branch and PR selector cannot be combined.

| Operation | Exact params |
| --- | --- |
| list_project_branches | `{}` |
| list_project_pull_requests | `{}` |
| list_analyses | `context, page, pageSize`; branch/default only; PR history is unavailable in this V1 API |
| get_analysis_task | `taskId`; returned task must belong to the pinned project |
| get_quality_gate_details | `context, analysisId`, optional `taskId`; non-null analysisId requires empty context |
| search_issues | `context, page, pageSize, filters` |
| get_issue_details | `context, issueKey` |
| get_issue_history | `context, issueKey` |
| get_rule | `ruleKey`, optional `contextKey` |
| get_measures | `context, metricKeys` |
| list_file_measures | `context, metricKeys, page, pageSize` |
| get_duplications | `context, componentKey`; component must belong to the project |
| list_security_hotspots | `page, pageSize`; default context compatibility only |
| get_security_hotspot | `hotspotKey`; returned project/component are checked |

For analysis-ID gate reads, prove membership using the supplied successful
project task with the same analysis ID. Without taskId, the adapter searches
at most 1,000 entries of the pinned project's default-branch history and denies
unverified membership. Use taskId for PR and non-default branch analyses.
There is no arbitrary cross-project analysis-ID lookup.

Issue filters are restricted to `issueStatuses, impactSeverities,
impactSoftwareQualities, rules, types, newCodeOnly`; list-valued filters contain
1–20 validated entries. Pages contain at most 100 entries, with a 10,000-result
window and explicit hasMore/nextPage. A page is never claimed to be a frozen
cross-page snapshot. Metric keys come from the closed allowlist in
`integrations/sonarcloud/analysis_contract.py` (coverage, duplication, size,
complexity, ratings, issues and compatibility hotspot review metrics).

Issue details retain validated text ranges, bounded secondary flows, impacts,
effort, tags, assignee, comments and available transitions. Provider HTML in
rule descriptions/comments is returned as plain text; comment Markdown is retained
as text when the provider supplies it. History omits provider
user/email objects. Unknown provider fields and scannerContext are not exposed.
Missing metric values remain null/NO_VALUE, with missingMetrics separately
reported. Quality Gate preserves ignoredConditions and comparator/thresholds.

The upstream V1 routes remain fixed in the provider's analysis contract.
Quality Gate V1 is deprecated; no unverified V2 replacement is invented.
Hotspot reads are explicitly deprecated compatibility. New hotspot mutations,
arbitrary metrics, source downloads and generic provider requests are absent.

## Sonar actions

Targets are single issue keys. All require projectKey, a stable request UUID,
reason and owner approval. The broker obtains the issue digest; the caller
cannot supply a trusted digest, transition, version, policy or approval.

| Operation | Additional input | Effect |
| --- | --- | --- |
| accept_issue | optional comment through the new client | Existing acceptance; the new client defaults comment to reason |
| mark_false_positive | optional comment | falsepositive transition |
| reopen_issue | optional comment | reopen transition |
| confirm_issue | optional comment | confirm transition, preserving gate impact |
| add_issue_comment | required comment | Append one reviewed comment |
| assign_issue | required assignee; empty string unassigns | Change assignment |
| set_issue_tags | required tags, at most 20 | Replace the exact tag set, including an explicitly empty set |

Comments are bounded to 2,000 UTF-8 bytes. Status-transition comments default
to the reviewed reason; assignment/tag operations do not accept a comment; use add_issue_comment separately.
The full before state, intended change and comment are frozen in the preview.
Before dispatch the issue and available transition are read again. A changed
preview is STALE. A confirmed provider response/readback yields a durable receipt.
A lost POST/readback is UNCERTAIN; no blind retry. A replay of the same UUID and
intent returns its prior state; changing the intent with that UUID is rejected.
Sonar has no atomic compare-and-swap endpoint, so the residual remote-writer
race remains explicit.

Accept/false-positive are triage decisions, not code fixes. Changing gates,
profiles, exclusions, baseline, permissions or deleting analyses is outside
this profile.

## GitHub reads and CI controls

Targets are configured repository names under the trusted owner. Workflow
reads additionally verify the exact allowed workflow ID and workflow path.

| Read operation | Exact params |
| --- | --- |
| get_workflow_run | runId, attempt |
| list_workflow_jobs | runId, attempt, page, perPage |
| get_job_log | runId, attempt, jobId, offsetLines, maxLines |
| get_check_run | checkRunId, expectedHeadSha |
| list_check_annotations | checkRunId, expectedHeadSha, page, perPage |
| list_run_artifacts | runId, attempt, page, perPage |
| get_analysis_manifest | runId, attempt, artifactId |

Jobs must belong to that exact run, attempt and SHA. Check reads expose app
identity plus summary/text/annotations; a check name alone is never accepted
as evidence of Sonar identity. Artifact listings may include other attempts:
only the fixed-name artifact and its strict manifest establish attempt metadata.

| ASK operation | Exact params |
| --- | --- |
| rerun_failed_jobs | runId, attempt, expectedHeadSha |
| rerun_job | runId, attempt, jobId, expectedHeadSha |
| cancel_analysis_run | runId, attempt, expectedHeadSha |
| dispatch_analysis_workflow | workflowId, ref, expectedHeadSha |

Rerun targets must be completed failed/cancelled/timed-out runs/jobs.
Cancel requires an active run. Controls reject forks and stale attempts.
Dispatch permits main/task refs, empty inputs, an active configured workflow,
and freezes the exact ref and workflow blob SHA. Provider dispatch has no
atomic ref CAS. The receipt says PROVIDER_ACCEPTED_NOT_COMPLETED; a successful
enqueue is not a successful analysis. Existing generic rerun/dispatch/approve
operations are not granted by this profile.

Logs are downloaded up to 2 MiB; returned pages have at most 500 lines/64 KiB.
Oversized downloads/pages fail explicitly. Redaction removes the active GitHub
token, Authorization header lines and known GitHub/Sonar token patterns; it is
best effort, not proof that an arbitrary build log contains no other secrets.
Download URLs never reach the client. The initial fixed GitHub route may return
one redirect to narrowly allowed GitHub Azure storage account hosts; the second
request has no provider bearer/cookies and cannot redirect again. Unknown
storage hosts fail closed and need reviewed source changes.

Manifest ZIPs are bounded to 64 KiB and exactly one analysis-manifest.json
entry with at most 16 KiB expanded data. Encrypted/extra/traversal entries,
duplicate JSON keys, unknown fields, mismatched artifact digest (when supplied),
expired artifacts and wrong run/SHA/attempt/project are rejected.

## Correlation manifest and composed report

The source helper:

```sh
python3 -B -m fortis_approvals.integrations.sonarcloud.repo_client.manifest --help
```

reads public GitHub CI identifiers and report-task.txt's ceTaskId. It records
repository, workflow ID/path, run ID/attempt, project/context, PR head SHA,
actual checkout SHA and the explicitly supplied scanner revision. It never
reads SONAR_TOKEN or scannerContext and refuses output overwrite.

A trusted reviewed workflow must upload only analysis-manifest.json with the
artifact name `fortis-sonar-analysis-RUNID-ATTEMPT`. The workflow must configure
the scanner revision consistently with its manifest and preserve the real
checkout SHA; PR head and merge checkout SHA can differ. Do not interpolate
untrusted PR/branch text into shell commands. This change does not edit any
repository's live workflow or install secrets. Actual workflow IDs and provider
permissions still need owner verification.

`AnalysisReviewClient.get_ci_analysis_report` composes existing typed READs;
it is not a new unauthenticated server route. It returns task processing state,
the gate for that task's analysis ID, current issue/measure pages and explicit
freshness/coverage limitations.

- A CI artifact is CI_RECORDED_NOT_SONAR_VERIFIED.
- Branch history can establish SONAR_REVISION_MATCH_CI_RECORDED for the same
  analysis ID/revision. Latest context is rechecked after reading findings.
- PR number/head must match the run's PR metadata. PR head and actual checkout
  remain separate. This V1 path does not prove a historical PR revision binding;
  the report retains CI_METADATA_ONLY and UNKNOWN context freshness.
- Current issues/measures are always labelled CURRENT_CONTEXT_NOT_HISTORICAL_NOT_ATOMIC.
  The report returns the first 100 open/confirmed issues and declares whether
  more pages remain; the caller can continue through search_issues.
- An analysis-bound gate is not immutable: later triage can change quality state.
  A pending/failed task is not presented as a passed gate.
- Workflow IDs, timestamps and Sonar OK alone do not prove scanned-byte identity.

## Repo client usage

Use the approved source worktree after deploying this profile, not the current
older review image:

```sh
printf '%s' '{"context":{"pullRequest":"123"},"issueKey":"ISSUE_KEY"}' |
  python3 -B -m fortis_approvals.clients.analysis_review sonar get_issue_details --target PROJECT_KEY

printf '%s' '{"runId":9,"attempt":2,"jobId":5,"offsetLines":0,"maxLines":100}' |
  python3 -B -m fortis_approvals.clients.analysis_review github get_job_log --target REPO

printf '%s' '{"run_id":9,"attempt":2,"artifact_id":4,"expected_head_sha":"FULL_SHA"}' |
  python3 -B -m fortis_approvals.clients.analysis_review report get_ci_analysis_report --target REPO
```

Mutation CLI commands additionally require --request-id UUID and --reason.
PENDING means wait for the owner, not resubmit with a new UUID. Poll the existing
authenticated request-status operation. This feature does not merge the separate
WorkflowClient HTTP 202 fix.

## Validation and release boundary

[Offline evidence](../fortis_approvals/evidence/FORTIS-ANALYSIS-REVIEW-OFFLINE-20261106.md)
owns checks and limitations. Source packaging includes the new modules but
does not build or replace a Gateway image. Live credentials/permissions,
download hosts, real response shapes, CI metadata production, PR binding and
owner-approved provider mutation acceptance remain MANUAL-PENDING.

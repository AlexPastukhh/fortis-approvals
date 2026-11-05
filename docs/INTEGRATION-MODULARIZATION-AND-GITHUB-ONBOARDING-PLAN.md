# GitHub onboarding plan — minimal live E2E first

> **Priority revised by owner — 2026-11-06.** Prove the smallest real
> Repo -> Gateway -> GitHub -> owner decision -> execution -> readback path,
> then expand only where an actual workflow needs it. Production rollout is
> after pilot acceptance. The existing release/rollback contract is retained
> as later work; finishing its executor is not a prerequisite for this pilot.

## Goal and current baseline

The goal is practical AI access to GitHub through the shared Fortis Gateway,
with provider credentials confined to Gateway and ALLOW/ASK/DENY enforced by
Core. Use one machine ingress, Core, Owner Portal and approval queue. An
external ChatGPT GitHub connector or the legacy Git CLI credential helper
cannot substitute for the pilot's Repo -> Gateway path.

Source PR #1 is merged; the approved source baseline is bc8d92d. Review already
proved the existing owner credential, restored history, Sonar GET and an ASK
rejection. Baseline CI passed 287 Python tests and 12 Windows checks. GitHub
contracts, fixed-origin transport, adapter, receipts, Repo client and explicit
registration helper exist. Live composition remains Sonar-only: registration,
actor grants, policies and a separate provider credential are still needed.

Reuse this evidence unless a relevant input changes. The current production
Gateway and all its state remain outside the pilot. Preserve the accepted
review container/state as a return path; do not repeat the earlier Production
backup, restore or broad host inventory to start GitHub E2E.

## First acceptance target: READ + ASK/Reject + ASK/Approve/create_branch

Use one owner-selected test repository, one frozen base commit SHA and a
Gateway-enforced pilot branch prefix such as fortis-e2e/. The test repository
must not deploy on pilot branch creation. Reuse the existing typed
create_branch operation: proving approval and a real ref creation does not
require implementing file writes, PRs or workflow controls first.

| Pilot capability | Policy | Scope |
| --- | --- | --- |
| get_repository, list_branches | ALLOW | Exactly the selected repository |
| create_branch | ASK + strong owner WebAuthn | Selected repository, protected base branches excluded, enforced pilot prefix |
| Every other GitHub operation | DENY / no actor grant | Includes push_files, PR merge and workflow controls |

The proposed first credential uses the existing secure token-file loader:
a separate fine-grained pilot credential, selected-repository Metadata read
and Contents read/write. Pull requests, Actions, Checks, commit statuses and
Workflows permissions are not requested for this first scenario. Use an
existing compatible owner-controlled credential only if it already meets
these boundaries; build GitHub App minting infrastructure later if needed.
Token permissions are broader than a branch operation, so Gateway repository,
branch and operation scope remains mandatory. Never copy the Repo helper PAT.

Owner inputs before live execution: exact test repository, credential provision
through hidden owner-only input, and approval of the isolated pilot startup
and two test proposals. Source implementation can proceed with explicit
configuration without waiting for the secret or inventing a repository.

## Delivery sequence

1. **Finish the thin runtime connection in one task branch.** Opt in to
   GitHub only through trusted pilot configuration; default remains disabled.
   Reuse the existing adapter, transport, Repo client and receipt store. Add
   the explicit repository/branch scope, actor operation grants and Core
   policies. Include create_branch in OwnerPortal strong operations; the
   machine ingress must have no owner approval route. Preserve Sonar behavior.
   No new Core, portal, generic proxy or credential mechanism.
2. **Prepare one pilot image and one owner-run package.** Source goes through
   one PR and CI. The package combines configuration/image/source validation,
   credential provisioning, isolated startup, rollback of the pilot only,
   scenario execution and a redacted result. Reuse existing owner Origin,
   TLS/machine grant and portal. Before changing review, stop only the admitted
   review ID and clone its persistent state into a fresh pilot volume through
   a RO source mount. Preserve owner rows, counters, Origin, history and file
   ownership; verify the copy. Retain the original container/volume unchanged.
   Reuse 19203/19204 after their known holder is stopped. A pilot failure stops
   only the pilot and returns to the retained review. Production is not touched.
3. **Run the complete first scenario.** Perform a typed Repo read; freeze the
   base SHA. Persist stable run/request IDs and distinct reject/approve branch
   names before submitting anything. First submit create_branch for owner
   rejection; wait for REJECTED and verify that branch remains absent through
   typed Repo readback. Then submit the approval case; owner WebAuthn approves
   its exact repository, branch and SHA. Await EXECUTED, verify its receipt and
   independently read the resulting GitHub branch/SHA through the Repo client.
   Owner input is the credential setup and browser decisions, not serial
   debugging commands or a new package for each checkpoint.
4. **Reconcile and report.** Resume interrupted runs using the saved IDs and
   status/readback. Never generate a new proposal merely because a response
   was lost. Verify a replay of the completed request returns the recorded
   outcome without another mutation. An ambiguous provider outcome stops for
   reconciliation; do not promise exactly-once behavior across an unrecorded
   upstream result. Retain the test branch and evidence; branch deletion is
   not implemented and cleanup is not automatic.

Package construction and offline validation are agent work. The target is one
owner-run package, with built-in checkpoints/resume for unavoidable owner
credential and WebAuthn actions. A failed gate is fixed narrowly; it does not
restart all accepted preparation or justify another general audit.

## First E2E acceptance — all are required

- Reads and proposals originate in the actual Repo client over the authenticated
  TLS ingress to the pilot Gateway. The pilot's provider token is mounted only
  in Gateway, RO at /run/github-token/token, UID 10001, mode 0600, with no
  symlink. It is absent from Repo, source, arguments, environment and logs.
- Default-disabled startup and missing operation grants/policies stay DENY;
  the only enabled mutation is create_branch in the selected repository/prefix.
  Out-of-scope requests fail before upstream mutation.
- Owner Reject produces REJECTED; independent readback shows no reject branch.
- Owner strong WebAuthn approval executes the exact approved proposal, produces
  EXECUTED with a durable receipt, and the approved branch has the frozen SHA.
- Saved IDs support resume; replay of the completed request does not duplicate
  the action. Ambiguous outcomes are visible and reconciled, not hidden.
- An ordinary Sonar GET still works through the changed pilot composition.
  Existing credential/history preservation is checked during state copy;
  a fresh enrollment or another full manual history audit is unnecessary.
- Evidence identifies source/image/config/run/request IDs and observed results,
  with no credential material. Failure retains the old review and its state.

This accepts the approval-to-branch E2E only. It does not claim file/PR/Actions
coverage, Production deployment or removal of the legacy direct Git access.

## Expand after the first E2E, according to need

| Next slice | Add only when needed | Acceptance |
| --- | --- | --- |
| Working branch edits | push_files | Bounded UTF-8 commit, expected-head checks, approved change and readback |
| Pull request workflow | create_pull_request, then separately merge policy | Exact refs/head, owner policy and observed PR result |
| CI visibility/control | Required Actions/Checks/status reads; selected controls later | Explicit operation, token permission and branch/ref scope |
| Workflow-file edits | Dedicated update_workflow_file | Separate permission and ASK policy; never implicit in ordinary push |
| Permanent deployment | Existing release/backup/rollback work | Reviewed executable packet, fresh backup and separate Production GO |
| Close legacy bypass | Replace and retire shared Repo credential | All actually required workflows proven before credential removal |

The current typed push_files API is not general Git smart-HTTP: binary files,
large artifacts and arbitrary packfile pushes are outside its scope. Do not
retire the existing Git helper until the replacement covers the owner's real
required workflows. That known legacy access is separate from the pilot's
Gateway-only provider credential; pilot success does not mean all bypasses
have already been closed.

## Work discipline

- Keep plan and implementation in the same task branch; open one substantive
  PR when the minimal runtime, package and tests are ready. No plan-only PR.
- Run targeted local tests for changed runtime/policy/provisioning paths, then
  the existing full source CI and Windows parsing/projection checks for the
  complete candidate. A documentation edit does not need another runtime test.
- Fix relevant failures and rerun affected checks. Reuse unchanged accepted
  image/state/owner evidence; validate new or changed inputs in package preflight.
- Use one short scenario/result/resume interface. Ask only for decisions or
  confidential owner input that is actually missing. Do not split independent
  agent work into owner-run scripts.
- Keep correctness gates: fail-closed policy, owner-bound approval, credential
  isolation, idempotency/reconciliation, state preservation and live readback.
  Reduce scope and handoffs rather than removing these gates.

## Source locations

- Shared TLS/machine transport: fortis_approvals/clients/gateway_transport.py.
- GitHub schemas, adapter, transport, registration and Repo client:
  fortis_approvals/integrations/github/.
- Shared composition: r7_unified_candidate.py and r7_unified_server.py.
- Existing review evidence: fortis_approvals/evidence/FORTIS-REVIEW-PREFLIGHT-20261105.md.
- Deferred Production contract: MODULARIZED-RELEASE-EXECUTION-CONTRACT-2026-11-05.md.

## Source implementation checkpoint — live acceptance pending

The task branch now contains the opt-in runtime/prefix scope, shared actor
policy wiring, strong owner approval, typed resumable scenario, private
provision/clone/admission helpers and one Start/Resume/Rollback entrypoint.
Targeted tests include real TLS and cryptographic WebAuthn with fake upstreams,
state preservation, unsafe deployment denial and lost-response resume. These
are implementation checks; no live GitHub call, token provisioning, pilot
startup or owner decision has been performed by this source work. Run the
existing source CI and Windows parser/private-pipe self-test on the complete
candidate, then review/merge the single pilot PR before the owner-run package.

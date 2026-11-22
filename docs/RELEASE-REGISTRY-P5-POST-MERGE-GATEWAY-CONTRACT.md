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

## P5 claimed-byte bindings (source-only follow-up)

`fortis_approvals/integrations/github/post_merge_proof_bindings.py::bind_claimed_material`
adds a **pure, no-I/O** layer that compares supplied raw PR-body/catalog
bytes and canonical-JSON path, component-map, dependency and CI-policy
structures against the SHA-256 fields of the source-only envelope. This is
an improvement over format-only 64-character digest checks, but **not**
provider authentication. Its only success is
`SOURCE_BYTES_MATCH_UNTRUSTED` with `evidenceVerified=false`,
`admissionAllowed=false`, `deploymentAllowed=false`. It does not call the
Gateway or GitHub, open files or write a Registry record.

The bundle has exact fields `catalogText`, `componentMap`,
`dependencyEdges` and ordered `pullRequests`. A PR material entry supplies
`number`, `reviewedBodyText`, ordered `changedPathRecords` and
`ciRequiredPolicy`. Material lists must match the envelope's full PR count
and identifiers. In this **candidate encoding**:

- A text SHA-256 uses its exact UTF-8 bytes, with no implicit trimming or
  newline normalization. `catalog.contentSha256` and
  `reviewedBody.bodySha256` are bound this way. The separate
  `catalog.blobSha256` is **not** verified: validating real Git blobs at the
  pinned object database remains a trusted-collector task.
- For JSON arrays and mappings, compute SHA-256 of UTF-8 JSON with sorted
  object keys, `ensure_ascii=False`, no NaN, separators `(',', ':')` and no
  extra newline. This applies to `componentMapSha256`,
  `dependencyClosure.digest`, `changedPaths.sha256` and `ci.policySha256`.
- The bounded Release Impact value is exactly one fenced `yaml` block between
  the accepted `<!-- fortis-release-impact:start -->` and
  `<!-- fortis-release-impact:end -->` markers. `releaseImpactSha256` binds
  the exact UTF-8 YAML substring **excluding the single delimiter newline**
  immediately before the closing fence. Matching syntax/hash is not the
  accepted semantic Release Impact validation: independently run the pinned
  shared validator against complete trusted changed paths and exact HEAD.
- Path records are sorted by `path`, `status`, `previousPath` and carry all
  three keys; rename entries have different `previousPath` and `path`.
  Canonical POSIX relative paths allow `.github` and `.dockerignore`, but
  forbid traversal, `.git` internals, absolute/Windows paths, CR/LF and NUL.
  The source-only set of changed paths cannot attest its own completeness.
- `ciRequiredPolicy` is exactly `{'requiredChecks': [sorted unique names]}`.
  Exact-byte hash agreement is not proof those checks were **required** by
  GitHub branch rules when the PR merged, or that `runId` and `attempt`
  genuinely came from the provider. A second self-consistent forged JSON
  fixture can still produce matching hashes.
- Component-map entries bind ordered target IDs to claimed component and
  shared-resource IDs. Digest agreement does **not** prove catalog parsing,
  active component topology, installed version or a release mutex.

The material is bounded (2 MiB total; 250 KiB catalog, 50 KiB each PR body),
missing/duplicated/unsorted records and unknown fields fail closed. It
returns only aggregate digests/counts and does not echo body or path bytes.
Even perfect matches require separately protected immutable review-cutoff
capture, Git commit/ancestry checks, trusted CI policy and a reviewed exact
actor/operation grant **before** authoritative Registry admission.

## Offline Git merge graph checking (source-only follow-up)

`fortis_approvals/integrations/github/post_merge_git_lineage.py::check_claimed_first_parent`
can independently check the **internal consistency of caller-supplied Git
commit objects**, not their provider origin. This adds a different proof
surface to the prior byte/digest binder:

- Input is the same untrusted v1 evidence envelope and a bounded array of
  `{ "sha": "40-char-lowercase-hex", "rawHex": "lowercase-hex-Git-commit-bytes" }`
  objects. These are **raw uncompressed Git commit payload bytes**, not the
  zlib object store representation or generic JSON commit metadata. The
  candidate verifier recomputes the legacy Git SHA-1 object ID over
  `b"commit " + decimal_byte_length + b"\0" + raw_commit_bytes`.
- Each object must carry a `tree` header, ordered `parent` headers, author,
  committer and the standard header/message separator; malformed or
  duplicate object identities stop. Signed commits with multiline `gpgsig`
  headers are parsed as *unverified bytes*, **not cryptographically verified
  signatures**. This source-only v1 handles 40-hex-character SHA-1 objects,
  not 64-character Git SHA-256 repositories or replace/graft refs.
- The claimed selected `main` SHA must be represented by such an object. A
  bounded **first-parent chain** from this SHA must reach each claimed PR
  merge SHA. The merge object must have **exactly two parents**, with the
  second parent exactly the claimed PR HEAD SHA, and the HEAD object must
  itself be present and hash-consistent. This reflects the accepted ordinary
  GitHub merge-commit flow; squash/rebase, octopus merge and missing ancestry
  nodes STOP for separate review. It does not require traversing all of
  Git history or accept a commit subject as evidence of parentage.
- All supplied objects must be relevant to that first-parent route or to
  the claimed PR head objects; duplicate, missing, truncated, inconsistent
  or unrelated object material fails closed. The result includes only the
  number of first-parent **edges between selected main and oldest matched
  merge** (zero when selected main is the only merge), matched merge SHA
  sequence and a normalized material digest; it does not echo full commit bytes.

**Limitation is fundamental:** an attacker can supply a self-consistent Git
SHA-1 object graph, and legacy SHA-1 has known collision limits. This module
neither authenticates GitHub's selected main ref nor verifies owner merge,
immutable reviewed PR body, required CI policy, catalog tree/blob content,
protected collector identity or live installation. It always returns
`SOURCE_GIT_DAG_MATCH_UNTRUSTED`, `evidenceVerified=false`,
`admissionAllowed=false`, and `deploymentAllowed=false` after a match. No
policy, route, network operation, local Git command or Registry WRITE is
added. Later trusted source collection must bind an authenticated, complete
provider ref and capture to these hash-bound objects, with independent
owner-reviewed proof and SHA-1 transition considerations.

Offline unit fixtures cover valid single/multiple PR first-parent chains,
changed SHA/object content, forged second parent, omitted/extra objects,
unsupported merge method, malformed headers, signed-header continuation
and no-authority results. One read-only check against locally available
Git commit objects for merged PR #174 and #175 produced a two-node
first-parent match (2026-11-20); local object presence is **not** a remote
GitHub identity or permission attestation.

## Provider-backed partial observation (source-only pilot)

`fortis_approvals/integrations/github/gateway/post_merge_reader.py` adds an
internal `observe_post_merge()` function, **not registered in machine ingress**.
It accepts a Gateway-owner-composed adapter and exact PR number, head SHA,
merge SHA and selected main SHA. The pilot has a fixed repository
`fortis-approvals`, additionally checked against the adapter allowlist. The
caller cannot choose an upstream host, path, ref name, token or actor. The
function uses only the existing pinned GitHub GET transport routes:

- `branches/main` at beginning and end; mismatch is stale.
- `pulls/N` at beginning and end: closed, merged, non-draft, same-repo
  task branch into main, exact head and merge SHA, provider merge timestamp.
  The mutable current body is neither retained nor treated as historical
  reviewed bytes. The reported base SHA is observation metadata, not proof
  of the first parent at merge time.
- `git/commits/SHA`: bounded (64 nodes) first-parent walk to the exact
  ordinary two-parent merge, exact second parent and independently read
  head metadata. Missing/mismatched nodes, duplicate/self-parent, unsupported
  merge method and limit exhaustion fail closed. These are provider JSON
  projections, not raw hash-recomputed commit objects.
- `contents/release/targets.yaml?ref=SELECTED_MAIN_SHA`: fixed file,
  bounded UTF-8 base64, exact size, recomputed Git SHA-1 blob ID and raw
  SHA-256. The provider's pinned contents projection is not an independent
  tree-path proof, parsed catalog or component binding. No raw catalog or
  body is echoed. No alternate URL or route is introduced.

Re-reading PR and main detects observed drift, not an atomic snapshot or
all possible races. Upstream failures (including 403) propagate, never
converted into an empty successful batch. The result is always
`PARTIAL_PROVIDER_OBSERVATION` with all authority flags false; it does **not**
produce the complete trusted envelope. No live provider call was made by
this source test suite. The internal reader has no externally callable
operation, authentication composition or persistence. Only an approved
future server composition may call it with the actual pinned transport.

### Proposed owner-controlled collector scope and capture protocol

Propose a dedicated `release-registry-collector-v1` principal, separate
from Repo AI and the label publisher. Initial exact repository scope is
`fortis-approvals` only. Future machine operation, if separately accepted,
is `github.get_post_merge_registry_evidence` READ with exact PR/HEAD/merge/
main parameters; all other operations and repositories remain DENY. No
credential generation, policy map, route, grant, or activation is added now.
The collector must not borrow the publisher's open-PR-only grant.

A complete collector must have two distinct stages: (1) pre-merge retained
reviewed body/impact, exact head, paths, catalog and CI rule/attempt evidence
in a protected owner-controlled append-only capture; (2) post-merge readback
bound to the same immutable capture and exact merged outcome. A review-cutoff
record must be bound to an explicit trusted review attestation, not merely a
snapshot time, current PR body or caller label. If capture is unavailable for
an older PR, report `EVIDENCE_INCOMPLETE`; do not reconstruct the cutoff.
Choose a protected durable location, access rules, retention and independent
checkpoint/restore acceptance before implementation of that capture. Only
then can all proof classes be linked to canonical Registry admission, which
remains a separate WRITE contract. Existing component restrictions and
owner/Gateway release gates remain independent.

## Private pre-merge body observation journal (source-only reference)

`gateway/review_capture.py::ReviewCaptureStore` retains the exact UTF-8
body of an open non-draft same-repository task PR, scoped to the existing
`fortis-approvals` pilot. The trusted server composition (not implemented)
would inject the owner-configured adapter and a private persistent path.
The method accepts only an operation UUID, expected journal revision, PR
number, exact head and expected body SHA-256. It reuses
`_release_impact_pr_evidence` twice through the existing GET transport and
rejects mismatching body hashes, identities or observed drift. No caller
body, reviewer label, credential, URL, or claimed approval is accepted.

**Placement proposal, not owner acceptance:** separate dedicated volume
under the future collector's service UID; private directory mode 0700,
regular database mode 0600, no shared Repo/AI/publisher access, no symlink or
hardlink to another data file. No default path or runtime provisioning is
introduced. Owner must independently approve the volume, UID, filesystem
trust, at-rest protection, limits, retention and backup lifecycle before
activation. Raw PR body may contain sensitive text and stays internal;
external receipts are metadata only. Mode checks do not protect against a
privileged filesystem actor or an attacker controlling the private directory.

The reference uses explicit exclusive initialization, schema version,
SQLite FULL durability with rollback journal, bounded 1000-record history
and transactional CAS under BEGIN IMMEDIATE. Same UUID+fingerprint returns
the original receipt even when the PR is now closed; differing fingerprint
conflicts. New UUID with stale revision stops. Multiple observations of
one PR/head may exist, without rewriting earlier captures. Network I/O
occurs outside the write transaction; the revision is rechecked before
append. The operation and observation form one immutable row with a
SHA-256 event chain. Missing DB is not recreated. Readback checks row
integrity and the chain; a separately retained exact head checkpoint is
required for internal raw material retrieval. A test restores a consistent
SQLite backup to a new inactive file and compares the original checkpoint
and operation receipt. No production backup, restore, migration, deletion,
retention job or checkpoint authority is currently implemented.

The receipt is **PRE_MERGE_OBSERVATION_RETAINED** with
`reviewAttested=false`, `evidenceVerified=false`, `admissionAllowed=false`
and `deploymentAllowed=false`. Capture time is local time after the reads,
not the GitHub review or merge timestamp. Two matching reads do not make an
atomic snapshot or guarantee the body remained unchanged until merge.
A hash chain cannot independently prevent full-history rewrite or rollback;
the checkpoint must be protected externally. Tests use a temporary DB and
fake provider, not live GitHub or a real owner approval.

Remaining: bind exact retained material to a separately authenticated owner
review decision and protected checkpoint; capture full changed paths, CI
policy/attempts, catalog, validate Release Impact and dependencies, and bind
to provider-confirmed merge. Older PRs without trusted retained review
evidence remain EVIDENCE_INCOMPLETE. The new source neither registers an
ingress operation nor grants permissions, authenticates a caller, writes
canonical Registry state or performs a release.

## Owner-bound review decision (source-only Core integration)

`gateway/review_attestation.py` adds an unregistered candidate Core adapter
for `release-review.attest_capture` and an exact-scope ASK predicate for
`release-registry-collector-v1` and the fixed `fortis-approvals` pilot.
It uses the existing Core approval fingerprint and audit protocol rather
than trusting an owner flag, chat message, or caller-supplied receipt.
No active policy map, gateway composition, capability or route is changed.

Future trusted server composition must inject the protected capture store,
owner-configured provider, **independent checkpoint reader** and actual Core
with its trusted owner verifier. The request's checkpoint is a precondition
only. Prepare binds the exact capture UUID, event digest, HEAD, body digest,
PR number and anchored revision/digest, as well as retained PR base and
branch. The same exact body must still be observed from an open, same-repo
PR. Core's fingerprint covers actor, full request, policy version and
immutable preview. Core rechecks the preview after owner approval; apply
and confirm re-read these material bindings. No GitHub write or extra
capture journal write is performed. Drift stops, and no separate effect
receipt is invented when Core's outcome is uncertain.

Internal readback reads the protected Core record and audit, not a DTO
provided by the client. It requires the exact original fingerprint,
EXECUTED state, approved decision by the configured owner, ASK at submission,
and matching PENDING/APPROVED/DISPATCHED/EXECUTED events with the approval
proof digest. ALLOW without an owner decision, rejection, pending, stale,
uncertain, changed policy/preview or mismatching audit cannot attest.
The result is OWNER_CAPTURE_DECISION_BOUND for that precise **body-review
decision**, including its timestamp. It is not GitHub merge approval and
does not prove that the body remained unchanged between review and merge.
historicalMergeCutoffVerified, evidenceVerified, admissionAllowed, and
deploymentAllowed are always false.

The current Core owner portal/credential modes are unchanged. A future
owner-only UI must allow the actual retained body/Impact to be inspected
before the explicit decision, enforce the accepted owner proof mode, and
keep raw material out of AI-facing previews. An audit proof digest alone
does not establish which proof mode was used or that the user saw the body.
Independent protected checkpoint and Core audit retention are deployment
prerequisites; the source-only readback does not authenticate an arbitrary
Core instance. Automated tests instantiate actual Core with an isolated
temporary DB, fake provider, test-only verifier and fixture checkpoint;
they do not exercise real owner WebAuthn or a production decision.

Next integrate the exact decision with complete changed paths, historical
CI rule/attempts, catalog/Impact validation and post-merge observations.
The final trusted capture/merge binding, protected placement, rollout and
authorized Registry ingestion remain separate owner-reviewed work.

## Bounded pre-merge path and pinned workflow observations (source-only)

`gateway/path_ci_observation.py` adds an internal fixed-pilot reader for
an open non-draft same-repository PR and exact HEAD, current base and body
SHA-256. It uses only existing Gateway GET transport routes, no new actor
grant or externally callable operation. The initial and final main ref and
PR observations must match. It does not retrieve a merged PR's mutable
body as historical evidence.

The exact SHA compare endpoint is read twice with page 1 and per_page 1
(the provider's changed-file list is on the first page). The reader requires
the provider's base identity, merge-base identity, ahead count, and
agreement with the PR changed_files counter. It rejects 300 or more
files because GitHub compare caps the file list there; malformed, unsafe,
duplicate, overlapping or unsupported path records also stop. The result
contains deterministic normalized path records and their digest, plus both
old and new paths for renames. These are bounded provider observations,
not independent raw Git diff/tree proofs. Count agreement alone does not
prove a provider inventory is complete or a PR's impact is valid.

The existing release-label CI collection is factored into the shared
`collect_workflow_evidence` helper (no profile or authority). The publisher
wrapper retains its original enabled-profile gate and return shape. The
P5 reader uses an independently composed adapter with the existing
approved workflow identity bindings, not publisher credentials. The shared
collector reads complete head-scoped run pages and exact selected attempts,
pinned workflow source hashes, job identity and status, and rechecks the
selected attempts. The same Source CI and Release Impact workflow pins
apply; unknown or changed workflows stop.

Current main branch rules are read and rechecked via the existing pinned
rules read. The bounded result records required status contexts with their
integration IDs and a digest of the returned rules. Empty, oversized,
ambiguous and unsupported required workflow/deployment rules stop. This is
not full historical effective branch protection (classic protections,
bypass and other rule classes are not established), nor a proof that a
workflow job satisfies a required context/App. These two observations must
not be conflated. No lookup of mutable current rules can reconstruct the
historical policy at merge time. Read counts and time are bounded; observed
drift or upstream failure stops. The result deliberately leaves
historicalPolicyVerified, requiredPolicySatisfied, reviewAttested,
evidenceVerified, admissionAllowed and deploymentAllowed false.

Remaining: persist the complete material and bind it to the independently
protected owner review decision and post-merge evidence; prove historical
effective CI policy and exact required-check/attempt binding; validate
catalog, impact and dependencies. No live storage or provider call was made
by the source tests. No change in deployed permissions or authority.

## Integrated review bundle and merge observation (source only)

The new internal `gateway/premerge_bundle.py` joins the previously separate
source components. `ReviewCaptureStore.capture_bundle` requires exact
operation ID, expected revision, open PR number, HEAD, current base and
body digest. It retains exact body bytes, the path/CI observation (including
rename paths, pinned workflow attempts/jobs, observed rule context/App
IDs and rule digest), and the exact UTF-8 catalog at PR HEAD, with
verified provider blob ID and SHA-256. The impact annotation is extracted
with the existing strict delimiter parser and hashed. This does **not**
parse or validate its YAML semantics. The catalog is read twice; the
existing bounded path/CI reader and outer body reads must agree.
The journal atomically appends that material and its bundle digest using
the existing revision CAS and event hash chain. A 240,000-byte material
bound and 32,000,000-byte total serialized journal payload bound limit
storage. No production DB is created. Existing body-only rows remain
readable and retain their original receipt shape and fingerprint; the
new kind and base are included in the new request fingerprint. A body-only
operation ID cannot be reused as a bundle operation.

An additional unregistered `release-review.attest_bundle` candidate uses
the same Core ASK mechanism. It requires the exact bundle digest in the
immutable preview and re-observes the bundle before accepting a match.
A body-only capture cannot satisfy the bundle operation, and an integrated
capture cannot silently take the old body-only path. Owner decision readback
binds the original capture event and bundle digest to the Core fingerprint,
and records the original execution time. No raw body or catalog is exposed
in the receipt. As before, a future protected owner-only UI must actually
show the retained material, enforce the approved proof mode, and rely on
an independently protected checkpoint and audit.

`observe_reviewed_merge` composes trusted-server reads of the original
EXECUTED ASK record, an anchored capture, and the existing exact merged PR
reader. This conservative pilot requires the merge first parent to be the
reviewed base, the exact reviewed HEAD/branch, the selected main catalog
to have the same blob ID and SHA-256 as the retained PR HEAD catalog, and
Core execution strictly before the observed merge timestamp. If the base
or catalog changed, no continuity is claimed. It rechecks the checkpoint
and decision after collection; it does not retrieve a mutable post-merge
body as review evidence. The result is REVIEWED_BUNDLE_MERGE_OBSERVED,
not a canonical evidence envelope. Cross-system time ordering is an
observation under trusted clock assumptions, not an independent cutoff proof.

Historical policy, required-policy satisfaction, historical merge cutoff,
evidence verification, Registry admission and deployment are all false.
In particular the observed branch rules are not complete historical effective
protection, exact required check-to-App binding is missing, the reviewed
PR diff does not independently attest the actual merge tree diff, catalog
and impact semantics/component/dependency closure still require validation,
and historical body continuity at merge time is not established.
Protected composition/owner review UI, checkpoint/backup retention, final
Registry API and live E2E remain separate. Source tests use isolated private
SQLite files, synthetic provider observations and a test-only Core verifier.
No new provider transport route, ingress, grant, owner proof mode, live
policy, persistent production path, or deployment is activated.

## Retained Release Impact validation against exact Git data (source only)

`gateway/retained_impact.py::RetainedImpactValidator` reads a retained
bundle from the private capture journal under an independently supplied
checkpoint. The server composition must provide the trusted local source
Git object repository, trusted validator Git object repository, explicit
validator revision and private temporary state root. These are not machine
request fields. For this pilot the shared implementation is
`fortis-container/tools/release/validate.py` with its two v1 schemas;
the normative comparison reference is container commit
`f763ea53169c2151df4a3212524221404b9aa990`. The executable validator is
the separately reviewed public `fortis-release-impact-action` at
`8c9abefdfbe4699aae97b9363a2a66c596680e62` (the existing Release Impact
CI action pin). Raw Git bytes of validate.py, requirements.txt and both
v1 schemas match the container reference exactly. The deployment owner must
separately accept the actual code/dependency pin and protected object stores.

The adapter checks exact base and HEAD commits, the unique Git merge base
and an independent bounded NUL-separated name/status diff including
rename identities. It requires exact agreement with retained provider
records (ambiguous/differently detected renames fail closed). Both old
and new rename paths are supplied to the shared validator. It reuses
`publisher_source.materialize` to read regular raw Git blobs from the
validator pin and exact source HEAD into fresh separate private directories.
The bytes of the source catalog must match the retained text, Git blob ID
and SHA-256. Neither dirty checkout contents nor PR Python modules are
imported; the isolated subprocess imports only the pinned validator code
and trusted installed dependencies, with a minimal environment, bounded
input/output, CPU/memory/file limits and timeout. This is not an OS sandbox
or protection against a compromised trusted local object store/interpreter.

The fixed shim invokes the existing YAML parser, catalog schema and
filesystem semantics, Impact marker parser, schema and changed-path
classification. It rejects unknown actions, missing local target refs
and direct self PR dependency, and returns declared/affected targets,
direct dependency requirements and the reachable same-catalog dependency
graph, not proof of complete release closure. It binds the result to
the validator revision, capture event, bundle, exact base/HEAD, catalog,
changed records and impact hashes; checkpoint drift stops. No raw body or
catalog is returned. `RETAINED_IMPACT_VALIDATED` is a partial validation
observation: dependency closure, historical policy, evidence verification,
admission and deployment flags remain false. The result is not yet
persisted in an owner-attested complete merge envelope. The actual merge
tree and historical CI/owner-cutoff proofs still need integration.

Tests use real temporary Git objects, private journal, fake provider and a
pinned protocol validator double; negative tests cover wrong paths/catalog,
checkpoint and pin and opaque subprocess failure. The real shared validator tests require
`FORTIS_TEST_RELEASE_VALIDATOR_ROOT` pointing to a trusted checkout of the
exact public action pin and its installed pinned requirements
(PyYAML 6.0.2, jsonschema 4.23.0). The existing offline security suite
can still skip these cross-repo tests when that fixture is not supplied;
a skipped real integration is not semantic acceptance.

### Required P5 semantic acceptance gate (source CI only)

`.github/workflows/p5-retained-impact.yml` adds a separate source CI job
`p5-retained-impact`. It checks out exact PR HEAD (or push/dispatch SHA)
and the fixed public action revision into separate sibling directories,
with read-only contents permission and no persisted checkout
credentials or extra secrets. It checks both revisions and requirements
hash before installing the existing pinned validator requirements in CI.
The script `scripts/test-p5-retained-impact.py` checks the public revision
and installed dependency versions, then executes six named retained-impact real-validator
cases: valid exact-source Impact, false no-deployment, unknown local
dependency, duplicate YAML mapping key, reachable transitive local
dependency graph, and unresolved external requirement. Any missing dependency,
mismatched pin, error, skipped case or incomplete run exits nonzero.
The gate is an explicit owner merge/activation acceptance requirement,
not a claim that GitHub branch protection has already been changed.
It is deliberately separate from the existing Source CI and Release
Impact workflows whose bytes/IDs are pinned by the publisher; those
pins, publisher policy and current required checks are unchanged.
The new workflow/job identity still needs owner-reviewed inclusion in
any future trusted historical P5 CI policy. Source CI does not authorize
a live release. No active route, Gateway fetch, grant, runtime package
installation, policy or Registry write is introduced.

## P5 policy-bound pre-merge bundle v2 (source-only)

The accepted PR #189 has four successful exact-HEAD CI checks, including
the real public validator semantic gate. An authorized point read of its
P5 workflow run 44862545365 / attempt 1 and check 136718935198 established
workflow ID 425664934 and GitHub Actions App ID 15368. That run returned
an empty PR association array after merge; no historical PR association
is reconstructed from job URLs or from the merge itself.

The internal `gateway/p5_ci_binding.py` adds a fixed candidate P5 policy
covering all three immutable workflow source hashes/IDs and their four
jobs (including `p5-retained-impact`), with the reviewed Actions App ID
and slug. Server-selected policy-bound capture uses the shared attempt
reader with the additional exact PR base SHA binding and refuses an
empty/mismatching PR association. The publisher still calls its original
two-workflow wrapper with its original bounds and behavior; P5 has a
separate 32-GET/30-second budget inside the bounded path/CI reader.
No caller-supplied policy, workflow list, repository or App ID is accepted
through a route. There is no new externally callable operation or grant.

The P5 branch-rule observation must contain only supported required
contexts and either the pinned App or an unbound App requirement; the
P5 candidate independently requires the pinned App for all four jobs.
Two bounded latest check-run and combined commit-status observations
must agree. Each required check must have the same job ID as the exact
selected attempt, HEAD, name, successful conclusion, pinned App and
exact provider job URL; duplicate/missing/mismatched checks and same-name
legacy commit statuses stop. Completion times are retained and selection
is rechecked. At the merge observation, completion must precede the
original Core execution and not postdate capture. These are cross-system
observations, not a proof of synchronized clocks or merge-time protections.

`capture_bundle(..., policy_bound=True)` is an internal source mode,
appending the distinct body-path-ci-catalog-v2 fingerprint and schema
version 2 with the policy digest, rules digest and exact check witnesses
inside the retained bundle. The same Core ASK decision binds the bundle
digest, and prepare re-observes the stored mode; check drift stops.
Body-only and schema-v1 captures remain readable with their old identity,
and cannot reuse an operation ID as a v2 capture. Merge observation
includes the retained policy/binding digests for v2. Neither mode is
an admission-ready evidence envelope; a future collector must require
v2 or a separately accepted successor, never silently fall back to v1.

The candidate policy is source-reviewed only, NOT asserted as owner-
accepted historical effective branch protection. Classic protection,
bypass, policy lifecycle, independent protected checkpoint/audit, and
body/CI continuity at the precise merge cutoff remain unresolved.
`candidateChecksMatched` means only this fixed candidate matched the
observed jobs/checks. historicalPolicyVerified, requiredPolicySatisfied,
evidenceVerified, admissionAllowed and deploymentAllowed remain false.
Do not widen the Repo actor's `list_head_workflow_runs` grant: P5 uses
the existing internal provider reader, and eventual separate owner-
composed collector scope requires its own acceptance. Source tests use
a synthetic provider and actual temporary journal/Core; no live capture,
production storage, branch-protection change or deployment occurred.

## Reachable dependency graph from retained catalog (source-only)

The existing isolated RetainedImpactValidator shim now traverses
validated `dependsOn` edges starting from every declared deployment
target and every explicit local Impact target dependency. Explicit
Impact target requirements remain separate roots, not invented per-target
edges. The existing direct targetDependencies and pullRequestDependencies
outputs remain available. The graph includes declared roots, explicit
targets, reached local target IDs, local dependency IDs, catalog edges,
unresolved external targets and unresolved PR requirements. It stops on
unknown local target, cycle, or a 256-edge / 200-local-node bound; unrelated
catalog nodes are not traversed for this release. The shared validator
still checks structural/catalog semantics first.

The observation binds the graph and deterministic local dependency
edges to the exact retained catalog HEAD, SHA-256 and outer capture
event/bundle digest, never inventing a selected-main or other-repository
source version. Local edge records have canonical repository, target
and exact PR HEAD sourceSha, and are explicitly provisional: selected
main/tree/component binding and multi-PR attribution remain separate
requirements. The dependency observation has its own SHA-256 under the
outer observation digest. External repository names and PR numbers
are unresolved requirements until authenticated enrolled source
selection, reviewed merge evidence, catalog continuity and recursive
cross-repository closure are established. Missing cross-repository
proof must not be interpreted as empty dependencies.

Even when there are no unresolved external/PR requirements,
dependencyClosureVerified, evidenceVerified, historicalPolicyVerified,
admissionAllowed and deploymentAllowed stay false. This is not a
complete evidence envelope or queue write. No new route, token grant,
fetch, mutable checkout trust or runtime change is introduced.

Protocol tests cover transitive reachability, an unreachable catalog
branch, cycle, missing transitive local target and unresolved PR ref.
The separate real-validator CI runner also executes positive transitive
and external-requirement cases without skips; workflow bytes and the
publisher/P5 CI source pins are unchanged.

## Selected-main local source binding (single exact tip merge, source-only)

`gateway/selected_main_binding.py::observe_selected_main` composes
existing owner-Core-reviewed v2 capture, provider merge observation,
and RetainedImpactValidator under one independently read checkpoint.
It does not accept request-supplied observation DTOs. Trusted deployment
composition must supply the actual protected Core/store/provider,
validator pin, dependency runtime and server Git object repository.

This conservative pilot only accepts selected main equal to the
reviewed merge SHA, with the retained base as the unique Git merge base.
It recomputes SHA-1 of raw base/head/merge commit objects using the
existing commit parser, compares provider head/merge parent and tree
projections, requires exact two-parent merge [base, head] and identical
complete root tree IDs for head and merge. It independently reads raw
HEAD workflow blobs and matches the fixed retained policy hashes.
The existing retained validator materializes HEAD raw regular blobs and
checks catalog bytes, exact paths and impact semantics. Equal tree
identity permits transferring the local dependency source versions
from PR HEAD to that exact selected-main SHA. No later main commit,
diverged base, modified merge tree, old bundle schema, policy pin drift
or mismatching provider projection is silently accepted.

The result contains the bound owner/merge and retained-impact
observations and their hashes, raw-commit-binding digest, selected
tree SHA, local selected-main dependencies and explicit unresolved
external target/PR requirements. The independent checkpoint and
reviewed merge observation are read again after the validation.
This does not claim complete multi-PR attribution, raw tree storage
protection, complete dependency closure or owner component/environment
bindings. No fabricated source versions or full envelope coverage:
historicalPolicyVerified, historicalMergeCutoffVerified,
dependencyClosureVerified, componentBindingsVerified, evidenceVerified,
admissionAllowed and deploymentAllowed all remain false. No new live
route, scope, credentials, protected storage or Registry write.

Seven source cases use actual temporary Git commits, actual private
capture journal and Core ASK, synthetic provider and validator protocol
double. They cover exact tip composition, unresolved external
requirements, tree/projection/workflow mismatch, older bundle rejection
and later main rejection. The separate pinned semantic runner adds
a seventh mandatory real-validator case for this composition (six
existing retained Impact cases plus this case), with no skips allowed.
Workflow bytes and the existing publisher/P5 workflow pins are unchanged.

## Collector snapshot and independently witnessed candidate receipt

`gateway/collector_snapshot.py` retains the real internal
`observe_selected_main` output, not an externally supplied evidence DTO.
The host-composed dependencies remain the actual Core, review capture
store, provider, validator, checkpoint reader and configured owner.
The separate source-only journal requires explicit exclusive creation in
a private 0700 directory with 0600 DB and sidecars, an independently
provisioned instance UUID and exact genesis checkpoint. It does not
auto-create a missing database, choose a production path or provision an
anchor. Its bounded SQLite journal (128 entries, 32 MB aggregate snapshot
bytes, 2 MB per snapshot) has schema version, immutable evidence IDs and
request fingerprints including expected revision, original Core request ID
and exact selected-main SHA. It checks canonical source bytes, selected
source and owner/capture/bundle binding, digest, ordered event chain and
independent checkpoint on each read. The candidate receipt includes
the exact evidence digest and preceding/resulting instance checkpoint.
No credential, arbitrary source location, owner assertion, positive
authority flags or raw mutable PR text is accepted from a request.

Retaining a new evidence ID requires the current external checkpoint
to equal the local head; collect outside the write transaction, recheck
both checkpoints and CAS, append atomically. The returned local result
is `LOCAL_EVIDENCE_PENDING_ANCHOR`, not an authoritative receipt.
The store does not advance the external anchor. A future independent
owner-controlled CAS must advance exactly that checkpoint. Until the
independent reader returns the matching head, snapshot and receipt reads
and new appends stop, including reads of old rows. Exact retain replay
recovers the local pending receipt after lost ACK/restart without
recollecting the PR; changed fingerprint/revision conflicts. A matching
external checkpoint permits anchored historical receipt/readback; replay
then returns `ANCHORED_CANDIDATE_EVIDENCE_RETAINED` with the same original
identity/digests. An unmatched checkpoint is not silently repaired or
initialized from the DB. Source tests use an independent synthetic witness,
not installed durable anchor authority or authenticated transport.

The existing Registry boundary can receive the journal's read method as
a trusted composition dependency. This still returns only
BLOCKED_EVIDENCE_GAP even for an anchored snapshot. The new receipt is a
**collector candidate evidence receipt**, not a Registry ingestion
operation receipt, verified evidence or admission. No Registry state,
external anchor writer, protected runtime, transport, credentials or
permission changes. Independent live capture/anchor authority, historical
policy/cutoff, baseline/lineage and component/environment bindings,
complete dependency provenance and production durability/backup remain
gates. The journal is not the future canonical Registry database.

## Forward-only lineage from the enrollment source (source candidate)

The owner-accepted [forward-only baseline decision in container PR #42](https://github.com/AlexPastukhh/fortis-container/blob/d870a8ba0d22c348813cf74bc719385f2e1f08a9/docs/RELEASE-REGISTRY-P5-DESIGN.md#forward-only-enrollment-baseline-owner-decision-2026-11-21)
requires no reconstruction of pre-enrollment PR history.
`gateway/forward_lineage.py::observe_forward_lineage` is an internal,
source-only coverage verifier. Host composition pins a baseline digest
independently of an immutable baseline-reference reader. The reference
has exact schemaVersion 1, enrollmentId, canonical repository,
baselineSha, catalogSha256, acceptanceReceiptDigest and bindingDigest.
These last two digests are references, NOT verified acceptance or
component provenance. No baseline SHA is selected/provisioned by code.
Production bootstrap and external anchor remain separate gates.

The verifier re-reads the exact scoped provider main before/after,
checks raw SHA-1 baseline commit and catalog bytes, then walks at most
64 first-parent merges back to baseline, without traversing its parents.
It reads the original candidate snapshots/receipts by ID through a
new bounded atomic `CollectorSnapshotStore.anchored_batch` read under
one matching independent checkpoint. Require an exact one-to-one set
of retained merge/PR/owner identities with no duplicate or unused
evidence, verify raw commit objects, exact parent/base and head/tree
projections, original commit-binding and snapshot digests and ordered
collector revisions. No recollection of a historical mutable PR body.
Missing prior tip capture, direct/squash/rebase commit, wrong first
parent, incomplete/extra evidence, drift or unresolved dependency stops.
This conservative slice also blocks any catalog byte change pending
component/catalog continuity proof. Zero new merges at the exact
baseline yields a zero-row *coverage observation*, not an empty
authoritative release queue or admitted no-deployment operation.

The observation binds the baseline digest/tree, selected main, catalog,
collector checkpoint and exact oldest-first merge/receipt sequence.
The batch, baseline and main are re-read before returning. The result
FORWARD_SOURCE_COVERAGE_MATCH_CANDIDATE is not a protected cursor or
canonical envelope. All acceptance, coverage, policy/cutoff, dependency,
component, evidence, admission and deployment verification flags remain
false. No cursor advancement, initial desired record, actual-state
assertion, historical backfill, grant or live ingress.

Eleven source tests cover actual temporary Git commits and the existing
Core/retained collector/SQLite fixture, with synthetic provider/validator
and independent witness. The two-merge case uses real Git objects and a
synthetic second retained receipt to exercise exact range matching and
missing-middle rejection, not two live captures. Real protected baseline
acceptance and full multi-PR semantic attribution remain prerequisites.

## Registry-specific review/policy binding (source candidate)

The owner-accepted [container PR #43](https://github.com/AlexPastukhh/fortis-container/blob/3a404cd61df842641a68ed508dd4177ea0267bef/docs/RELEASE-REGISTRY-P5-DESIGN.md#registry-specific-review-cutoff-and-ci-policy-proposed-alternative-2026-11-21)
permits a separately protected Registry-specific review policy rather than
claiming a reconstruction of historical GitHub merge protection. Existing
GitHub rules, four required candidate jobs and manual owner merge remain
unchanged. This increment is an unregistered candidate implementation,
not that protected policy lifecycle or live admission.

`registry_review_policy.py` adds a host-composed exact immutable policy
reference reader with a separate fixed digest. Schema 1, canonical
repository, enrollment UUID, baseline SHA, first policy revision 1,
zero previousDigest, acceptanceReceiptDigest, effectiveAt (UTC epoch
seconds), maxReviewToMergeSeconds (1–86400), clockToleranceSeconds
(0–60), and exact full existing four-job profile are required. The bounds
are source guards, not owner-selected live clock/interval settings.
Later policy revisions, transitions and mismatched pins stop.
AcceptanceReceiptDigest is a reference, not verified owner enrollment
authority. No default policy is enrolled or selected.

The separate `RegistryPolicyReviewAdapter` reuses the existing Core ASK
bundle operation only in an offline composition. It requires v2 retained
material, exact policy profile and capture at/after policy effectiveAt.
It binds enrollment, baseline, policy revision, profile digest,
reference digest and acceptance receipt digest in the **Core preview**
before the owner approves. Existing Core fingerprint, prepare/apply/
confirm exact preview rechecks are used. Neither request JSON nor
post-merge code may attach a new policy to an old receipt. The legacy
adapter is unchanged; receipts missing this binding cannot pass the
new observer. Independent protected policy and Core/owner ceremony
acceptance, exact scope and transport remain prerequisites.

`observe_registry_review` reuses the actual selected-main composition
and original owner decision, checks the Core preview fingerprint and
policy binding, re-reads original capture under checkpoint and requires
check completion <= capture < owner approval <= execution < merge,
merge no later than composed clock plus tolerance, and bounded
approval-to-merge interval. It independently rereads the merged PR's
exact identity/body as a drift check (not as release planning input),
latest attempt inventory, original run/job IDs and check/App witnesses.
Post-merge empty PR association is permitted only after the original
pre-merge association was bound by the reviewed v2 bundle; a conflicting
nonempty association stops. A later rerun or changed body/check/job
fails closed. The shared exact check witness helper is factored from
the existing P5 source collector without weakening pre-merge checks.
Readback is bounded (existing P5CIReader budget), current main, policy,
capture checkpoint and original Core decision rechecked before return.
This is current consistency, not an atomic provider history proof.

Result REGISTRY_REVIEW_POLICY_MATCH_CANDIDATE binds the original
policy/cutoff, owner/bundle/capture identities, selected-main observation
digest and CI binding digest. Registry-specific verification flags,
historical provider verification flags and all admission/deployment flags
remain false. Its retention in the candidate journal is described below; it is not
consumed by a canonical admission gate. Full protected enrollment/
policy acceptance, trusted clock/owner audit, independently durable
review-policy retention and forward-range binding/component evidence
must be integrated and tested before enabling that alternative.
Eleven tests use actual temporary Git/Core and retained capture with
synthetic provider, verifier, policy reference and clock. No new routes,
credentials, workflow bytes, policy grants or production state.

## Retained Registry review policy and forward source pairing

The policy-bound collector mode composes the selected-main observation
and Registry-specific review-policy candidate **once**, from the same
original Core/capture/merge identities. The journal stores both in one
immutable schemaVersion 2 snapshot, with the complete exact policy
reference and canonical snapshot digest. The request fingerprint additionally
binds policyReferenceDigest, so a legacy schema 1 operation cannot be replayed
as a policy-bound operation, or vice versa. Existing schema 1 rows/receipts
remain readable unchanged. This is a versioned payload extension in the
same private collector database, not a migration to a second journal.
The policy reader and pin are host composition inputs, not public request
parameters. A fresh append requires the independently read pinned policy;
the initial observation and policy are rechecked before commit. Original
operation replay does not recollect mutable PR/CI evidence or rewrite bytes.

The journal revalidates the complete policy reference, exact review
projection schema, false verification flags, review digest, original
owner request/fingerprint, bundle/capture/checkpoint, timestamps, selected
main digest and retained CI binding on every read of the paired snapshot.
Its receipt adds policyReferenceDigest and registryReviewDigest. The
existing append CAS, immutable identity, independent-head readback and
pending-anchor failure rules are unchanged. No paired snapshot, batch
or original receipt is readable before its matching independent checkpoint.
A locally matching journal does not prove that the witness is protected.

Forward lineage has an explicit policy-bound source mode. It independently
pins policy, checks repository/enrollment/baseline/acceptance reference
against the baseline, and requires every retained snapshot in the range
to have the same exact policy and paired receipt digests. The range
projection binds these review digests to each original merge; no mixing
of legacy rows or downgrade of policy-bound rows in legacy mode. Legacy
mode remains a source compatibility check only. No new verified flags,
policy transitions, baseline advancement or canonical admission. The
offline Registry boundary accepts a paired snapshot only as a blocked
candidate; it checks the outer identities/digests and adds an explicit
protected review-policy acceptance gap. No new READ/WRITE grants,
storage provisioning, protected authority, route or effective policy
change is implied. All historical and Registry verification flags remain
false. Component/environment binding, trusted clock/enrollment/witness
acceptance, authoritative storage and recovery still need integration.

Eight tests exercise actual fixture Git/Core, retained v2 capture, SQLite
and synthetic independent witness, replay after restart, selection pairing,
policy fingerprint, baseline/enrollment mismatch, false authority flags,
tampering and fail-closed drift. The paired range and blocked preview use
the same original anchored candidate snapshot. No live evidence collected.

## Component/environment binding candidate

`gateway/component_bindings.py` composes the policy-bound forward range
with a host-pinned mapping reference independently read against the
baseline's bindingDigest. Schema version 1 has exact repository,
enrollmentId, baselineSha, catalogSha256, bindings and components fields.
The mapping is not inferred from PR text, target names, request parameters
or the current filesystem. It has one selected catalog environment and
one distinct deployment component per catalog target in this pilot.
Bindings are sorted by targetId and each contains targetId, environment,
componentId. Components are sorted by id, with a nonempty sorted unique
resources set and sorted unique requires component IDs, compatible with
the existing restriction evaluator's component graph vocabulary. Shared
resource IDs deliberately may appear on multiple components. Unknown or
unused components, cycles, missing catalog target/dependency bindings,
duplicate identities and external catalog dependencies stop. All targets
are covered, not only the current affected subset. Extra owner-declared
component dependencies must still resolve and be acyclic. No implicit
selection of all catalog environments or construction of physical IDs
from target names.

The selected-main raw catalog and exact pinned shared validator source
are materialized from Git as private data views using the existing
bounded blob reader; the source checkout and PR code are not executed.
An isolated subprocess invokes the shared schema/semantic validator,
not a new YAML parser. The raw catalog hash must match the baseline, and
the validated deployment procedure, environment, build unit and
verification requirements are preserved in the mapping projection. The
policy-bound forward observer must match repository, baseline/policy
digest, exact selected tree and catalog; the binding, baseline, policy,
journal checkpoint and main are rechecked before return. Catalog
remapping, policy transitions and missing source coverage still block.

The current source catalog has exactly the following deployment targets
and declared environments (not a live resource inventory):

| Target | Catalog environment | Deployment kind |
| --- | --- | --- |
| fortis-gateway | production | owner-controlled |
| gateway-owner-controller | windows-owner | windows-source |
| release-label-publisher | production | owner-controlled |

Actual resource IDs, shared-state identity, dependency topology and
selected environment are owner-reviewed enrollment material; no concrete
live component map or enrollment SHA is provisioned by this code.
The result COMPONENT_ENVIRONMENT_MATCH_CANDIDATE includes the complete
mapping, raw catalog digest, parsed catalog projection digest, validator
revision, policy/lineage/baseline/binding digest and collector checkpoint.
componentBindingsVerified, resourceTopologyVerified,
baselineAcceptanceVerified, evidenceVerified, admissionAllowed and
deploymentAllowed remain false. No active restriction, permission,
actual state, canonical desired record or cursor update is inferred.
This is not yet a combined authoritative admission envelope or a
persisted canonical plan. The protected enrollment and resource
attestation are still necessary before a mapping may create records.

Eight offline tests exercise actual Git/Core/collector fixture and
synthetic policy/anchor/validator, including dependency/resource graph,
mapping drift, and exact raw catalog semantics at the protocol boundary.
A ninth real shared-validator test is mandatory in the existing
p5-retained-impact semantic gate (now eight real cases in total), without
changing any workflow byte pin. No deployment or route is implemented.

## Combined initial-range plan candidate (source only)

`gateway/admission_plan.py::observe_initial_plan` composes the existing
policy-bound lineage and component mapping from one observation. It
reads the same anchored batch again and binds every original evidence
digest, receipt, selected merge, policy/review digest and collector
checkpoint. It does not accept an arbitrary candidate plan or caller
completeness flags, environments, sources or actions. The previous
component observer's public source projection is unchanged. Catalog
bytes are still validated by the pinned shared validator. The mapping,
lineage, catalog projection, baseline/policy references, journal batch
and selected main are bound/rechecked before returning.

For each covered merge, take the retained validator's declared actions
and affected-target consistency, rejecting unknown actions. Recompute the
reachable catalog dependency graph with explicit target requirements;
compare exact retained root, edge and local source bindings, reject
external/PR dependencies, unknown targets, cycles or incomplete graph.
Requirements bind the selected full tree's SHA and mapped environment;
they are **source requirements**, not verified installed versions,
execution ordering or implicit additional deployment actions. Preserve
per-merge attribution in mergeAudit. Aggregate declared actions by
target across the complete initial range, with original contributing
evidence IDs, not an inference from the last PR alone.

The internal candidate plan separates stable subject SHA256 of
canonical repository/targetId/environment from immutable record SHA256
of canonical identity adding desiredSourceSha, catalogCommitSha and
catalogSha256. The first catalog pin is the enrolled baseline commit
with exactly unchanged raw catalog bytes throughout the range; it is
not a claim to have located the last catalog-edit commit. Each candidate
preserves component/resources, direct component dependencies,
deployment procedure, build unit, verification and required actions.
Artifact starts NOT_BUILT with null digest; actual=null,
planningState=PLANNED_UNVERIFIED, evidenceVerified=false.
Candidates are not canonical stored records, an admitted queue or a
public read response. The internal range classifications EMPTY_RANGE,
NO_DEPLOYMENT_CANDIDATE and DEPLOYMENT_CANDIDATE distinguish zero new
merges from a complete source candidate with no actions. Even the
no-deployment candidate cannot be admitted based on this observation.

Result INITIAL_RANGE_PLAN_CANDIDATE binds baseline/binding/policy,
selected main, catalog, lineage, component observation and exact
collector checkpoint and plan digest. Admission, deployment and
evidence flags remain false. The protected enrollment/resource
attestation, authenticated collector/trusted clock and protected
canonical state/recovery remain mandatory. This increment supports
only the complete first range after baseline; subsequent ingestion
must obtain an independently witnessed Registry cursor and plan only
the new suffix, not re-enqueue an action from every previous merge.
No cursor parameter, advance, supersession, writer, new routes or
production effects are implemented here. Six tests cover real fixture
Git/Core/collector/mapping composition, deterministic IDs and
dependencies, missing evidence, checkpoint drift and synthetic negative
projection/no-deployment protocol cases. Source fixtures do not prove
admission or a real deployment.

## Suffix planning from Registry cursor (source candidate only)

After the first accepted **candidate** range, `observe_suffix_plan`
requires the actual Registry journal's bound `checkpoint` reader,
not a request-provided SHA, arbitrary closure, proxy or asserted
completion flag. Schema 1/2 checkpoint-backed journal readers remain
supported. With the functional V1 source addition, the **exact**
`FunctionalV1CandidateJournal.checkpoint` bound method (SQLite schema 3)
is also accepted. Its `LOCAL_SOURCE_CANDIDATE_HEAD` is strictly checked
for the expected `LOCAL_EVENT_CHAIN_ONLY` marker, false admission and
deployment flags, immutable enrollment/scope, positive revision, local
event digest and source SHA. Only for *existing candidate plan schema*
is its `localCheckpoint` projected into the `registryCursorCheckpoint`
field; that does **not** make it an independent checkpoint/witness.
The full local event chain is replayed on read, and the owner method
is re-read after source composition. The selected `main` is independently
re-read as for initial planning. A forged dictionary/wrapper is denied.
This step is **not** owner enrollment or trusted runtime admission.

The suffix walk checks every first-parent merge between the Registry
candidate cursor and the selected main, without re-reading or including
earlier PRs. Each new merge needs its own independently witnessed
policy-bound collector receipt, raw Git commit/head/tree match and
unchanged pinned catalog. Missing first-parent nodes, unreviewed
commits, duplicate or unused evidence, unknown dependencies and
provider/main/checkpoint drift block. The source-pinned component map,
original impact actions, local dependency graph and catalog validator
are reused; only new suffix actions and evidence IDs are aggregated.
Record ID keeps the full *new* selected SHA and catalog, so the new
candidate has a distinct identity. The result
`SUFFIX_RANGE_PLAN_CANDIDATE` also binds startCursorSha and the exact
Registry cursor checkpoint. A final journal checkpoint reread blocks
changes after lineage composition. Empty suffix is not re-enqueued.

No arbitrary start SHA, cursor reset, retrospective backfill or automatic
policy/catalog transition is permitted. The original immutable
enrollment baseline is unchanged. Initial plan rejects any cursor
override; suffix planning requires the exact journal reader.
The *historical schema 1* supports only an initial transaction. The
separately reviewed schema 2 and **local-only schema 3** support
candidate initial and suffix CAS/supersession; source tests now exercise
a real first Git-fixture plan followed by a second synthetic retained
merge through schema 3 and a persisted latest desired projection.
This **still** does not establish original collector authentication,
an authoritative Registry queue, installed actual, `DEPLOYED`,
unattended CD, or permission to turn on a Registry WRITE. Before
`FUNCTIONAL_V1_GO`, require trusted collector/owner composition,
first cutover, grants, host isolation, backup/restore and non-Production
E2E. False `evidenceVerified`, `admissionAllowed` and
`deploymentAllowed` are preserved; later hardening requires
independent checkpoint/witness, not a local hash.

Seven source tests include a real first fixture Core/Git/collector
and matching Registry initial transaction, then a real second Git
merge with a *synthetic* second policy-bound retained receipt. This
exercises the suffix protocol, no duplicate earlier actions, stable
new record identities, missing middle merge and cross-enrollment
cursor rejection, and cursor checkpoint drift. It is not proof of two
live owner-reviewed merges or a production protected anchor.

## Registry preview/receipt boundary (separate source module)

The [closed Registry source-only boundary](RELEASE-REGISTRY-P5-TYPED-BOUNDARY.md)
consumes the present selected-main observation by exact reference/digest;
it returns only blocked preview and explicit unavailable storage errors.
It does not promote this collector result to trusted admission, expose
a live route or create any canonical desired records.

## Source-only Git planner → Registry schema 3 composition (2026-11-23)

The exact initial/suffix planning source and schema-3 local desired journal
are now connected by the opt-in
`fortis_approvals.registry.functional_v1_journal.OfflineSourceRangeComposition`.
In a single **offline** call, fixed host-supplied Git/Core/policy/catalog
readers compute the candidate through the existing
`observe_initial_plan` / `observe_suffix_plan` (exact bound
schema-3 local cursor); the composer seals a deterministic
per-operation local evidence reference and passes the recomputed
candidate to the existing SQLite revision-CAS writer. It rechecks the
local head both before committing and inside the transaction. The
caller cannot provide a plan, desired records, issuer, source
classification, installed version or a changed file path on ingest.
Only original operation lookup and bounded candidate READ are exposed
as source-only methods.

Tests cover a real Git/Core/retained-plan fixture, a synthetic second
merge, two persistent desired versions and immutable supersession,
missing/forged evidence references, incorrect main SHA/scope, concurrent
source-plan drift, lost post-COMMIT ACK and exact-UUID recovery.
`UNKNOWN_OUTCOME` is not a committed/admitted success; the original
operation must be looked up, never blindly replayed. **No source-only
issuer label/digest is authenticated collector provenance**: local
`evidenceVerified`, `admissionAllowed` and
`deploymentAllowed` remain false, and no Gateway route or grant is
registered. This is a combined *source implementation + contract* cut,
not the promised full `FUNCTIONAL_V1_GO`.

Before the first authorized non-Production P5 pilot, still required:
authenticated original collector/Core evidence and owner approval
cutover, independently placed single-writer Registry runtime,
bounded existing-Gateway typed methods with scoped actors, robust
backup/restore/unknown-result testing and live negative E2E. P6
manual outcome, P7 Board and P8 manual batch must be implemented
before the complete functional user journey can be accepted.
Checkpoint/witness hardening remains a separate gate. The authoritative
cross-repository milestone ordering is the
[single container roadmap](https://github.com/AlexPastukhh/fortis-container/blob/main/docs/BACKLOG-IMPROVEMENTS.md#fortis-release-planning--cd-queue);
its stale completion references require an eventual *container*
repository edit, which this single *approvals* PR cannot perform.

## Exact persisted collector source pin for inactive schema-3 composition (2026-11-23)

The existing `OfflineSourceRangeComposition` has been narrowed:
`journal` **must** be an actual
`gateway/collector_snapshot.py::CollectorSnapshotStore`, plus an
explicit **host-composed** `expected_collector_checkpoint` with the
same instance ID and a positive revision. The composer captures the
store's original bound `anchored_batch` method at construction
and checks its full SQLite journal replay against the pinned head
before, during and immediately before schema-3 append. A compatible
JSON object, fake journal wrapper or later replacement of the public
instance method cannot manufacture accepted source evidence. The
range planner continues to verify original reference IDs, owner
request binding, retained policy/CI/catalog/dependencies, first-parent
Git tree/lineage and a consistent source checkpoint.

The prior positive synthetic cross-store suffix test is **revoked**:
a fabricated second receipt injected into `anchored_batch` fails
because it is absent from the original journal. The new
`test_registry_original_two_merges.py` instead executes two distinct
pre-merge capture and **test Core-approved** owner requests using
the actual `ReviewCaptureStore`, `Core`, Git commit objects,
`CollectorSnapshotStore.retain` and Registry schema-3 CAS methods.
After the first initial plan/commit it advances the original
collector with a different PR/owner audit, explicitly pins the
new collector checkpoint and commits a suffix with immutable
supersession. Missing second evidence, resubmitting old evidence
and unavailable original Core readback fail closed. No caller-made
collector receipt or monkeypatched `anchored_batch` is used.
The GitHub source is a **fixture** and Core's verifier is a **test**
owner. Authenticated live post-merge provider identity, original
real owner authorization and non-Production runtime E2E remain
requirements for the P5 pilot; this is not their substitute.

This is not authentication of GitHub, owner, process, time or source
anchor. The expected checkpoint is an offline host **input**; the
legacy collector's independent checkpoint reader is synthetic in
tests and still requires separate runtime acceptance. Every result
remains `evidenceVerified=false`, `admissionAllowed=false`,
`deploymentAllowed=false`; `collectorProvenanceVerified=false`
is explicitly returned. No new live Registry WRITE, Gateway grant,
enrollment, container runtime or production operation is activated.

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

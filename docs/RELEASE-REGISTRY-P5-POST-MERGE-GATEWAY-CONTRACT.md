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

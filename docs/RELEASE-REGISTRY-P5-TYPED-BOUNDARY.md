# P5 Registry typed preview / receipt boundary — source only

Status: **OFFLINE SOURCE CANDIDATE — NOT LIVE**. The read-only accepted-peer
checkpoint adapter landed in merged PR [#211](https://github.com/AlexPastukhh/fortis-approvals/pull/211);
no Registry runtime/API/ingest or protected checkpoint/witness is activated.
The existing Gateway Core/Owner Portal (including source mode
`OWNER_ALL_METHODS_V1`, merged PR [#216](https://github.com/AlexPastukhh/fortis-approvals/pull/216))
owns `DENY/ASK/ALLOW` and owner WebAuthn. Registry integration must register
**exact typed planner/reader operations and grants** there, not create another
owner policy authority. The protected checkpoint store/service is an independent
integrity/recovery boundary, not the owner decision API. Actual installed
owner-policy mode and Registry grants must be verified separately; existing
machine capabilities do not advertise Registry operations. Remaining tasks and
ordering belong only to [the central P5 roadmap](https://github.com/AlexPastukhh/fortis-container/blob/main/docs/BACKLOG-IMPROVEMENTS.md#fortis-release-planning--cd-queue).

Authority: the owner-merged [concrete D1–D7 source design in fortis-container
PR #41](https://github.com/AlexPastukhh/fortis-container/blob/6bf24812d5d32c5afd17e65afcdf8efbec9afd0c/docs/RELEASE-REGISTRY-P5-DESIGN.md#21-concrete-first-pilot-decision-proposal-2026-11-21).
This implements its first source increment, not acceptance of the remaining
operational/evidence gates. Existing [Gateway source evidence
contract](RELEASE-REGISTRY-P5-POST-MERGE-GATEWAY-CONTRACT.md) remains the
owner of upstream collection details. No change to the current Gateway or
Publisher routes, grants, credentials, images or owner release procedure.

## Gateway source-only READ registration (current task candidate)

The shared closed method/query/projection contract lives at
`fortis_approvals/integrations/registry/read_contract.py`; the existing
`RepoIntentBroker` accepts its five `registry` READ names only through
normal `validate_read_query`, exact `fortis-approvals` target, canonical
repository and explicitly provisioned actor READ grants. These source schemas
**do not** install an adapter, register an actor, populate owner policy,
or enable an R7 route by themselves. Source-only
`registry/boundary.py::GatewayRegistryReadCandidate` can be composed by
trusted test/host code with an independent, fixed reader identity and
`RegistryBoundary` only; current R7 builder **does not compose it**.

The normal Gateway Core and Owner Portal keep ownership of
`DENY/ASK/ALLOW`; existing one-use native READ ASK applies if installed and
configured, with no second WebAuthn or policy store. Registry reads recheck
actor/grant/policy before and after the adapter call. Only
`SOURCE_ONLY` capabilities and `BLOCKED_EVIDENCE_GAP` preview can be
returned. `get_record`, `list_records`, `get_operation` still return
`STORAGE_UNAVAILABLE`; `ingest_merged` and any deploy/advance routes
remain outside Broker READ/WRITE grants. No empty queue, owner proof or
live enrollment is fabricated.

The lightweight shared contract is packaged as an image **input** to
Gateway and the separate Publisher source image (because they import the
shared Repo Broker); no Registry DB, collector, checkpoint or reader
credentials are copied into either image. A later PR with this Gateway
input has real build-target Release Impact even though the new Registry
**runtime** remains uninstalled; it must not claim `no-deployment`.
Current work and host/recovery gates remain solely in the
[central P5 roadmap](https://github.com/AlexPastukhh/fortis-container/blob/main/docs/BACKLOG-IMPROVEMENTS.md#fortis-release-planning--cd-queue).

## One-shot accepted checkpoint.get responder — source only

`registry/owner_peer_boundary.py::respond_accepted_checkpoint_get` is the
bounded **sending** counterpart to `read_accepted_checkpoint`. It accepts
one pre-accepted filesystem Unix stream connection and the exact private
`OfflineCheckpointCAS` reader. No process, listener, socket bind, new owner
authority, grant, checkpoint writer or monotonic witness is created.
The responder explicitly requires EOF after the single canonical request
**before touching the owner ledger**; appended data, pipelining, missing
half-close, unknown operation and `checkpoint.original` are refused on this
route. `checkpoint.advance` remains denied for every peer. It reuses the
original kernel `SO_PEERCRED` and owner profile/inode/instance/scope
checks, validates the exact checkpoint projection and sends precisely one
bounded canonical UTF-8 JSON line. All authorization/acceptance/admission
claims remain false. Failure sends **no success or synthetic error frame**;
the host caller owns the accepted connection and must close it.

Positive exchange tests use one same-UID Linux test host and **only**
simulate the role classification at the source seam, while the real
kernel peer credential is still read. One pinned-client ↔ responder
integration test also simulates Registry EUID/GID at the caller-side
identity check. Real same-UID access must be refused **without ledger READ**.
These tests do **not** demonstrate separately provisioned principals,
protected host transport, a true external witness or authorization to
activate the Registry. The protected listener/process and cross-UID host
tests require later owner-reviewed implementation. Source milestones and
remaining gates are tracked only in the
[central CD Queue roadmap](https://github.com/AlexPastukhh/fortis-container/blob/main/docs/BACKLOG-IMPROVEMENTS.md#fortis-release-planning--cd-queue).

## Source-only pinned owner checkpoint READ client

`owner_peer_boundary.read_pinned_checkpoint()` is the **outbound Registry
reader** counterpart of the existing accepted-peer
`read_accepted_checkpoint()` source adapter. It performs exactly one
`checkpoint.get` using canonical bounded newline-framed JSON over Linux
filesystem `AF_UNIX/SOCK_STREAM` — no arbitrary URL, path, actor, token,
operator command, checkpoint advance or enrollment. A separately provisioned
pinned profile binds instance UUID, scope digest, expected Registry UID/GID,
owner UID/GID, socket path, directory/socket modes and socket device/inode.
The client reads the server kernel `SO_PEERCRED` (before and after the
exchange), rechecks the filesystem socket and pinned profile after the
exchange, requires EOF after the one response, and rejects malformed,
duplicate-key, noncanonical, oversized, extra-field or replayed/wrong-request
responses. A successful response must match the original UUID, operation,
instance/scope and exact bounded checkpoint shape, with all
`protectedAuthorityVerified`, `ownerAcceptanceVerified`,
`dispatchAllowed` and `admissionAllowed` flags **false**.

This is **not** a service or a live Registry connection. It creates no
listener, owner SQLite handle, witness, credentials, grants, owner policy or
checkpoint mutation. The separate source-only
`respond_accepted_checkpoint_get()` now emits a single fixed READ candidate
frame on an **already accepted** connection. It is **not** a listening
service or independently protected host process; host-side listener and
runtime lifecycle remain unimplemented. Positive socket tests
run under one real test UID and simulate the Registry EUID/GID **only in the
client identity check**. They do not prove kernel cross-UID isolation or
authorize runtime acceptance. The source client may ultimately supply a
readback claim to `observe_inactive_registry_startup`, but that startup
result still must be `INACTIVE_UNVERIFIED`, even if all local reads match.
Owner actions remain authorized by existing Gateway/Owner Portal; checkpoint
transport is only an integrity/readback boundary. The deployment/evidence
gates and sequence remain in the [single CD Queue
roadmap](https://github.com/AlexPastukhh/fortis-container/blob/main/docs/BACKLOG-IMPROVEMENTS.md#fortis-release-planning--cd-queue).

## Inactive Registry startup readback (source only, P5 next cut)

`RegistryStateJournalV2._read_only_db()` now opens an **existing** fixed-scope
SQLite v2 database with `mode=ro`, `PRAGMA query_only=ON`, a deferred READ
transaction, the shared exact schema/scope validator and complete local
event/record/supersession replay checks. It does not initialize a missing
database, migrate schemas, append a record, or call `BEGIN IMMEDIATE`.

`recovery_reconcile.observe_inactive_registry_startup` composes only that
Registry-side reader and **two externally supplied READ callbacks** for
the owner checkpoint and independent witness claims. It binds exact
instance/scope/revision/eventDigest, rejects missing, malformed, divergent,
corrupt, or changing inputs and reads all three observations twice. It does
**not** open an owner ledger from the Registry principal, call a checkpoint
CAS, trust caller-provided paths or invoke a collector. It always returns
`INACTIVE_UNVERIFIED` with all live READ, WRITE, admission, activation,
host-isolation, owner-acceptance and protected-witness flags **false**.
Matching fixture claims (including genesis) are **not** proof that two storage
domains cannot be rolled back together.

This is an inactive *source integration seam*, **not** a deployable
Registry service, protected witness transport or launch readiness. No
socket bind/listener, container or owner image, registered Gateway
adapter/grant/policy, WebAuthn ceremony, installation or enrollment exists
from this change. Dedicated principal, protected checkpoint transport and
independent witness acceptance remain requirements of **later hardened**
anti-rollback operation under the
[host runbook](https://github.com/AlexPastukhh/fortis-container/blob/main/docs/RELEASE-REGISTRY-P5-OWNER-RUNTIME-RUNBOOK.md),
not a prerequisite for the separately reviewed limited functional V1.
The authoritative outstanding work sequence remains **only** in the
[central CD Queue roadmap](https://github.com/AlexPastukhh/fortis-container/blob/main/docs/BACKLOG-IMPROVEMENTS.md#fortis-release-planning--cd-queue).

## Offline v2 desired-record page — functional P5 READ source cut (2026-11-23)

`RegistryStateJournalV2.list_desired_candidates(limit, cursor=None)` reads
the **existing** SQLite v2 journal through `mode=ro`, `query_only=ON`
and a deferred transaction. It replays all immutable operations, local
records and supersession edges before deriving the active
`repository / target / environment` desired records. It does not use
`BEGIN IMMEDIATE`, write to SQLite, initialize a missing database, invoke
an evidence collector, update installed state or create a receipt.

The bounded `INACTIVE_DESIRED_CANDIDATE_PAGE` result exposes
`snapshotRevision`, `snapshotDigest`, `candidateSourceSha`, exact
active record IDs, desired source/catalog, deployment procedure/actions and
an optional deterministic cursor. A cursor is bound to the local snapshot
and last active record ID; malformed, mismatched or stale cursors fail
closed. This hash-based cursor is **not** a secret, signature or
authorization token; it protects pagination consistency, not against
a malicious client fabricating a matching public hash.
No-deployment advances the observed source cursor without inventing
a desired record. Superseded records stay in immutable history but only
the latest target version appears on the candidate page. The response
is capped at 8192 bytes; oversized responses are an error, not truncated
or silently accepted as complete.

**No authorization or availability is implied.** Even an empty page is
an inactive *candidate observation*, **not** proof that the live release
queue is empty. Every page has `evidenceVerified=false`,
`admissionAllowed=false`, `deploymentVerified=false`,
`writeEnabled=false` and `actual=null` for each record.
No `REPORTED_COMPLETE` event, `DEPLOYED` claim, target readback,
Gateway `registry.list_records` registration or owner grant is
created. The currently merged offline SQLite v2 still **requires an
injected owner checkpoint reader** and must not be made authoritative by
fake `verified=true` flags or a synthetic witness.

Under the [revised single P5–P8 roadmap](https://github.com/AlexPastukhh/fortis-container/blob/main/docs/BACKLOG-IMPROVEMENTS.md#fortis-release-planning--cd-queue),
the future `FUNCTIONAL_V1_GO` needs a separately reviewed owner-provisioned
persistent Registry, independently trusted collector, local append-only
event/receipt continuity, backups, Gateway grants and non-Production E2E.
Independent owner checkpoint transport and monotonic witness move to
the separate `HARDENED_REGISTRY_GO`, which must be satisfied before
asserting rollback resistance. This source cut changes **neither** gate.

## Functional P5 V1 local desired journal candidate — schema 3 (2026-11-23)

The owner-approved product direction in the
[single P5–P8 roadmap](https://github.com/AlexPastukhh/fortis-container/blob/main/docs/BACKLOG-IMPROVEMENTS.md#fortis-release-planning--cd-queue)
separates a **limited functional** Registry from **later anti-rollback
hardening**. As a source-only implementation step,
`registry/functional_v1_journal.py::FunctionalV1CandidateJournal`
offers a **separately versioned SQLite schema 3** for locally retained
desired *candidates*. It is **not a migration of checkpoint-backed
schema 2** and does not modify schema 2's accepted invariants or
`RegistryStateJournalV2` methods.

- Private parent directory `0700`, exclusive existing-file creation,
  database `0600`, exact schema/version/scope, WAL, `synchronous=FULL`,
  append-only operation rows/desired records/supersession links. No
  public path selector or automatic data migration.
- `append_range` requires exact typed planner operation/evidence UUID,
  digest, expected revision, and an independently injected offline
  `plan_reader`. It revalidates full stored source-plan chain/merge
  continuity and candidate target IDs, local event digest chain, schema,
  record lineage and supersession. Initial and suffix ranges are
  distinguished, no-deployment ranges preserve cursor without inventing
  a release row. SQLite `BEGIN IMMEDIATE` protects a **single
  transaction** with revision CAS. Original-operation replay returns
  the same receipt; changed fingerprint conflicts. Unknown commit
  receipt is `UNKNOWN_OUTCOME`, not permission to blindly retry.
- `operation`, `checkpoint` (explicitly **local checkpoint only**)
  and bounded `list_desired_candidates` provide an offline readback
  of accepted *candidate* rows. The last desired record per
  target/environment is projected, previous versions remain in history.
  Pagination cursors are tied to local revision/digest; a public
  hash is not authorization. The page size is capped at 100 entries
  and 8192 bytes. No runtime actual, installed version, owner report
  or deployment claim exists in this schema.
- Every output says `integrityModel=LOCAL_EVENT_CHAIN_ONLY`.
  `evidenceVerified`, `admissionAllowed`, `deploymentAllowed`
  and `deploymentVerified` (where applicable) remain **false**.
  An empty local candidate list must **not** be exposed as an
  authoritative empty live Release Queue.
- **Functional forward planning source integration:** the existing
  `forward_lineage._registry_cursor` now accepts only schema 3's
  *exact bound* `FunctionalV1CandidateJournal.checkpoint` method in
  addition to existing schema 1/2 checkpoint readers. It rejects
  wrapper functions, incompatible scope, a zero-revision cursor,
  false evidence/authority markers and invalid local checkpoint
  layout. The local head is normalized **only** into the source
  suffix-plan's `registryCursorCheckpoint` field. It is **not** an
  independent witness and grants no new actor/method permission.
  Offline test exercises original Git-fixture initial evidence,
  a second retained-merge fixture, source planner, two schema 3
  append-range CAS receipts, supersession and read-only latest
  desired pagination. No live collector or Registry service exists.

**Threat boundary:** local event hashes detect ordinary corruption
without allowing routine API edits, but do **not** detect an adversary
rolling back the entire SQLite DB/WAL/backup domain. No outside
checkpoint, trusted collector identity, original Core/Owner Portal
acceptance, protected host runtime, accepted first enrollment or
registry WRITE grants are present. The callback supplying a plan is
**not authenticated by this class**. Future `FUNCTIONAL_V1_GO`
requires explicitly reviewing that composition: owner-controlled
single-writer placement, trusted original post-merge collector and
cutover, restricted Gateway methods/actors, WAL-safe backup/restore,
unknown-outcome recovery and non-Production E2E. Source-only schema 3
cannot be installed automatically just because its tests pass.
`HARDENED_REGISTRY_GO` subsequently adds independently protected
checkpoint/witness and cross-principal tests; it is not silently
replaced by the local event hash.

This module is under `release/targets.yaml:noDeploymentPaths` until
a separately reviewed Registry target/catalog/image is introduced.
It is **not** imported into either currently deployed Gateway/Repo
service, so it cannot publish a live queue or write to Production.

## Functional P5 offline source composition and execution-order clarification (2026-11-23)

**Status: source candidate after owner-merged PR #224 (v2 READ), #225
(local schema 3), #226 (schema 3 suffix cursor). None is a Registry
runtime launch, authenticated collector admission or `FUNCTIONAL_V1_GO`.**
`FunctionalV1CandidateJournal` now also owns
`OfflineSourceRangeComposition` in the **same explicitly
`noDeploymentPaths` module**. This opt-in source class composes the
existing exact initial/suffix planner from fixed host-supplied
GitHub/Core/journal, baseline, policy and component-binding readers
and stores its *computed* plan through the schema-3 CAS writer.
The caller cannot submit arbitrary plan/desired DTOs, change the
issuer or choose a database path during an operation. Inputs are
bounded to original local operation UUID, expected revision, selected
main SHA and evidence-reference UUIDs, all rechecked by P5 source
planning.

The wrapper derives a deterministic per-operation **local** evidence
reference from `instanceId + operationId`. This is not an authenticated
collector identity, original owner receipt, signed capture or trusted
clock; source dependencies remain untrusted until a separately accepted
runtime composition. The local-head snapshot is rechecked after
planning, before the SQLite CAS (which rechecks again transactionally).
On a COMMIT/readback ambiguity, the **top-level result is
`UNKNOWN_OUTCOME`**, requiring a separate exact original
`operation(operation_id)` lookup. Calling `compose_and_append` again
after the revision changes is stale and not an automatic retry.
`candidate_page` remains `LOCAL_DESIRED_CANDIDATE_PAGE`, never an
authoritative empty live queue. All output flags continue to be false:
`evidenceVerified`, `admissionAllowed`, `deploymentAllowed`,
`writeEnabled`. There is no `REPORTED_COMPLETE`, `verifiedInstalled`
or `DEPLOYED` admission here.

**Proposed execution-order clarification for the existing single roadmap**
(subject to owner review, not a second authoritative roadmap):
functional P5 pilot must first join *original authenticated*
collector/owner acceptance, private Registry single-writer deployment
and backup/recovery, exact Gateway actor grants and forward-only
enrollment in an independently authorized non-Production E2E. Build
P6 owner report, P7 Board and P8 manual batch after the restricted P5
pilot, then run **complete P5–P8 user-journey E2E before final
`FUNCTIONAL_V1_GO`**. This resolves the prior shorthand that placed
full-functional E2E before P6/P7/P8. `HARDENED_REGISTRY_GO` and its
independent checkpoint/witness are later, not hidden P5 prerequisites.
There is no grant or deployment approval implied by this source PR.

**Cross-repository roadmap synchronization needed:** the actual *single*
roadmap is in `fortis-container/docs/BACKLOG-IMPROVEMENTS.md`, a
different Git repository. It still describes the completed #46 source
cut as next and lists Approvals milestones only through #223; its
P5–P8 E2E ordering and older D6/v2 references should be reconciled
with this accepted source status. A GitHub PR to `fortis-approvals`
cannot modify `fortis-container` and must not silently create an
alternate canonical roadmap. The above is the **explicit next
implementation acceptance contract** in this PR, while the original
central roadmap edit remains an independent repository action and
will not be performed by bypassing the PR workflow.

## Functional V1 schema 3 inactive WAL-safe backup — source cut (2026-11-23)

`registry/recovery_snapshot.py` now provides
`create_inactive_local_backup(store,directory,backup_id)` and
`verify_inactive_local_backup(directory,backup_id,instance_id,scope,plan_reader)`
for **exact** `FunctionalV1CandidateJournal` SQLite schema 3.
These are separate from the existing schema-2 owner-checkpoint-backed
backup APIs and do **not** inject or simulate a trusted anchor.
The one-writer P5 source remains inactive and is not packaged into
the running Gateway image.

Only a host-selected, separate, absolute private `0700` directory is
accepted; existing/symlink output paths are refused and files are
created exclusively `0600`. Capture uses SQLite's **online backup
API** with a bounded progress deadline, not a raw filesystem copy
of a database with live WAL pages. Before capture, the full local
operation/event/record/supersession chain is replayed and the local
head/cursor/counts are pinned. After capture, both source and inactive
copy are replayed, matched exactly and reread to detect changed
source; the `0600` database bytes are hashed and bounded. A canonical
size-limited manifest records `instanceId`, exact scope digest,
local checkpoint, cursor, event/record counts, file size/digest and
`integrityModel=LOCAL_EVENT_CHAIN_ONLY`; both files and the parent
directory are fsynced before success. The verifier validates the
snapshot again without changing any active state or writing a
replacement DB. No automatic restore, backup rotation or migration
is added.

**What this proves:** private snapshot **local consistency and
byte integrity** under the supplied manifest, schema 3 identity,
and replayable immutable history. It handles concurrent normal
append changes by failing closed rather than declaring a mismatched
snapshot current. Tests include initial and suffix, no-deployment,
changed source, corrupt DB, modified manifest, schema-v2 confusion,
permissions, wrong scope/instance and source state advancing while
copying. An **older but internally consistent backup remains readable**
even after new merges.

**What this explicitly does NOT prove:** backup authenticity against
the owner of the backup directory, an externally monotonic current
version or protection from coordinated replacement/rollback of both
the SQLite DB and its manifest. `rollbackProtected=false`,
`restoreAllowed=false`, `admissionAllowed=false`,
`deploymentAllowed=false` on every successful readback. There is
no unattended recovery or switchover. Host ACL/encryption, offline
restore into a fresh instance, backup lifecycle, trusted collector
admission, Gateway actors and non-Production E2E still need separate
owner review before limited `FUNCTIONAL_V1_GO`. Later
`HARDENED_REGISTRY_GO` requires an independently protected
checkpoint/witness; this backup cannot substitute for it.

## P5 original collector journal pin at source composition (2026-11-23)

`OfflineSourceRangeComposition` now **requires** the exact
`CollectorSnapshotStore` (not a caller-supplied `anchored_batch`
function, proxy or self-consistent dictionary) plus an explicit
`expected_collector_checkpoint` pinned by host composition.
The pin has the actual collector instance UUID, **positive**
revision and original event digest. It is compared to the full
replayed, SQLite-backed `CollectorSnapshotStore.anchored_batch`
result on construction and on every range. The bound original
method is captured once in a private adapter: later monkey-patching
`journal.anchored_batch` cannot inject fabricated evidence.
An expected head change, missing original retained evidence,
source SQLite tampering, mismatched checkpoint or changed
collector anchor is a **DENY/STALE** condition, never an
implicit no-deployment or empty desired projection.

Before/after the Git/Core planning pass, the adapter checks the
same original collector head. The sealed Registry `plan_reader`
rechecks it again just before schema-3's transactional CAS.
Original operation lookup after uncertain commit **does not**
re-read or replay provider effects. The candidate response
includes `collectorCheckpointCandidate` for exact diagnostic
binding and `collectorProvenanceVerified=false`. The Registry
local event chain still reports `LOCAL_EVENT_CHAIN_ONLY`.

The prior synthetic test that monkey-patched an invented second
collector receipt and observed successful desired supersession is
**correctly rejected**. A follow-up P5 source regression now covers
**two genuinely persisted test-fixture original collector receipts**:
two distinct pre-merge `ReviewCaptureStore.capture_bundle` operations,
two independent `Core` ASK/approved/executed owner-audit rows, two
real `CollectorSnapshotStore.retain` transactions with checkpoint
advancement, actual Git commit/tree objects and first-parent merges,
then initial/suffix planning and two SQLite schema-3 CAS commits with
immutable supersession. A new owner-composed collector head pin is
required for the second transaction; the first pin fails closed.
No `anchored_batch` or owner-decision JSON is forged by the test.
Separate negative cases deny missing original second evidence, replay
of the earlier merge as new suffix evidence, and unavailable original
Core readback (zero collector/desired changes).

**This is an offline E2E with an emulated GitHub provider, pinned
synthetic Release Impact validator and Core test owner verifier,
NOT a live owner-accepted non-Production release.** Real trusted
provider/source-host identity, real owner acceptance, live Registry
deployment, original operation credentials and grants remain
outstanding. Earlier tests also deny fake journal providers,
malformed/mismatched host pins, unauthenticated method replacement,
changed original anchor and tampered source DB.

**Threat boundary:** Python class identity and an expected
collector head bind which *source API* we read; they do **not**
establish the actual identity of the OS process, original Core
owner approval, trusted time, GitHub authenticity, effective CI
policy, or protected journal anchor. The current collector
reader still requires its own externally injected checkpoint
reader; the test one is synthetic. An attacker who controls the
host composition and its pin can create self-consistent false
data. Neither `FUNCTIONAL_V1_GO` nor `HARDENED_REGISTRY_GO`
is granted. The separate limited Registry schema 3 still does
**not** require an independently protected monotonic witness;
trust in any future collector must be accepted by owner-reviewed
runtime/grants/evidence, not inferred from this source test.

No new Gateway operation, protected owner listener, live Registry
WRITE, enrollment, Docker/Windows/Production action or unattended
CD is installed by this change.

## First executable private Registry candidate READ process (2026-11-23)

**P5 implementation status: runnable in an isolated test subprocess,
NOT installed/non-Production accepted, NOT a live Registry API.** The new
`registry/local_candidate_read_service.py` implements a bounded Linux
AF_UNIX foreground **candidate READ** process against an already existing,
exact-schema SQLite **3** `FunctionalV1CandidateJournal`. This is the
first process/transport composition for the functional-V1 storage path.
It is separate from the unfinished *owner-side checkpoint* listener;
no protected checkpoint/Witness/GO role is assumed or touched.

**Startup/ownership.** A separately provisioned non-root Registry identity
must own a private `0700` config directory with one exact `0600`
canonical JSON config. Fields are *exactly* `schemaVersion=1`,
`instanceId`, `scope`, `registryStatePath`, `socketPath`,
`readerUid`, `readerGid`. A trusted supervisor may invoke
`python3 -B -m fortis_approvals.registry.local_candidate_read_service
--owner-config <owner-provisioned-file>`; no config, credential or
path is accepted over the socket. The DB must **already exist**, be
`0600` in an owner-private `0700` directory and replay its complete
schema-3 event history on startup. Neither process startup nor read
requests initialize/migrate a DB, create an enrollment, fetch source
evidence or invoke any writer. Its separate socket directory must be
owner-controlled `0710`, with a `0660` socket and fixed configured
reader group; a preexisting/symlink socket is a STOP, **never unlinked
or replaced automatically**. The listener has **no TCP/HTTP endpoint**
or Docker socket dependency. Host provisioning remains owner-only.

**Network protocol / identity.** A request is one canonical UTF-8 JSON
line of at most 4096 bytes, then client write-half-close. Duplicate keys,
additional bytes, multiple frames, noncanonical JSON, absent EOF,
oversize requests or unknown fields abort without a response.
Every request has only `schemaVersion=1`, `operation`,
`instanceId`, `scopeDigest`, `requestId`, and exact `params`.
The exact closed operation set is
`candidate.capabilities` / `candidate.head` /
`candidate.list_desired` (limit 1–100, revision-bound cursor) /
`candidate.original_operation` (original UUID).
The server reads **real kernel `SO_PEERCRED`** for each accepted
connection and requires the host-configured reader UID/GID. Client
actor/credential/path/scope override is not a valid field. It checks
the private socket inode/modes and local head before and after every
read; a concurrent write or socket replacement blocks output. It
never returns a caller-supplied empty queue or `NOT_FOUND` for an
unavailable/corrupt DB. Failed requests close with no success DTO.

The only wire result is `SOURCE_ONLY_CANDIDATE_READ` with a bounded
`data` holding the source journal's **explicitly local** result.
`authenticatedCollectorAvailable=false`, `admissionAllowed=false`,
`writeEnabled=false`, `deploymentAllowed=false`,
`runtimeActivationAllowed=false`, `rollbackProtected=false`.
`candidate.list_desired` is **NOT** `registry.list_records` and
does not claim authoritative production queue or installed identity.
`registry.ingest_merged`, `report_manual_complete`,
`verify_actual`, `deploy`, any SQL and Gateway grants remain denied.

**Acceptance evidence/remaining work.** Mandatory tests execute
real filesystem AF_UNIX requests, multiple accepted connections
and a **separate running Python process** against a previously written
schema-3 journal. They reject forged actors/WRITE, wrong peer UID,
malformed/pipelined/noncanonical frames, missing client EOF,
world-readable config, loose socket ACL, existing socket replacement,
missing SQLite and changed head during output. Same-UID test fixtures
**do not prove distinct-principal isolation**; this process runs under
the test runner's account and no privileged host is modified.
Owner must separately choose a collision-free dedicated Registry UID,
reader UID/GID, private encrypted volume/backup, accepted source image,
effective socket grants and process namespaces, and verify **real
cross-UID** EACCES/EPERM and denied write/mount access before pilot.
The runtime still has no authenticated collector, protected owner
enrollment, source admission, live typed Gateway `registry.*` READ
binding, or admission WRITE. The existing Gateway READ DTO only permits
SOURCE_ONLY/blocked results and must **not** be silently widened by
this service. `FUNCTIONAL_V1_GO` and `HARDENED_REGISTRY_GO`
are not granted. A source merge is not host installation.

## Functional V1: owner-run real cross-principal host access probe (2026-11-23)

**SOURCE-ONLY verification tooling; NO host installation / enrollment /
live GO.** To follow the executable candidate READ service cut (#231),
`scripts/probe-functional-v1-registry-access.py` can be invoked by an
independently authorized host operator under each **already-existing,
distinct** Linux `reader` and `repo` process UID. It is a read-only
kernel/filesystem/AF_UNIX observation tool, **not** a UID allocator,
privilege switch, Docker controller, owner approval API or Registry
write client. It cannot provision its own host or impersonate principals.

**Preconditions (owner-only, no AI rollout):** the owner has independently
reviewed and pinned the exact script/Registry binary SHA and source
version, selected a non-Production host, and provisioned/inspected distinct
owner, Registry, reader and Repo UIDs; distinct Registry/reader/Repo GIDs;
a private Registry schema-3 SQLite in a Registry-owned `0700` directory,
file `0600`, and a *separate* Registry-owned `0710` socket directory
with a `0660` listener assigned to the reader group. The accepted
Registry **candidate** reader is running under the Registry UID and the
owner independently verified its PID, actual UID/GID, socket device/inode,
mounts, groups and relevant kernel restrictions. A fictional process, a
stale/unbound socket, same-UID fixture or a fake "readback" is NOT
acceptable. This limited Functional V1 preflight **does not require**
installing a protected checkpoint or independent witness.

Owner constructs a **canonical UTF-8** JSON profile from those *actual*
post-bind facts (not values chosen by Repo/AI), with EXACT fields:
`schemaVersion=1`, `format=functional-v1-host-access-profile-v1`,
`ownerUid`, `registryUid`, `registryGid`, `readerUid`,
`readerGid`, `repoUid`, `repoGid`, `serverPid`,
`socketDev`, `socketInode`, `instanceId`, `scopeDigest`,
`registryStatePath`, `socketPath`. Publish a pinned SHA256 digest of
the canonical profile, and the owner-owned immutable-to-the-peers
`0444` file under an owner-owned `0755` directory. Profile contains
**no token, credential or original owner receipt**. A SHA256 digest of a
caller-editable file is NOT owner authenticity; the host operator must
independently verify the file and the invoking principals.

Under the **real reader UID**, execute this command from the
owner-reviewed, **non-Repo-writable** accepted source copy (paths are
illustrative command placeholders, not prescribed host paths):

```sh
PYTHONPATH=<owner-pinned-source-root> python3 -B <owner-pinned-source-root>/scripts/probe-functional-v1-registry-access.py --role reader --profile <owner-published-absolute-profile-path> --expected-sha256 <owner-pinned-profile-sha256>
```

Run the same command in a **separate real Repo UID** process with
`--role repo`. The tool does **not** switch UIDs. A valid role must have
matching real/effective/saved Linux IDs, zero permitted/bounding/effective/
ambient capabilities, `NoNewPrivs=1`, `Seccomp=2`, no forbidden
supplemental DB/socket groups, and must be distinct from Registry and
owner. The UID identities are read from the real running process, not
from a request actor claim.

Both roles attempt OS `open` on the Registry DB parent (directory),
DB read-only FD, and DB read-write FD. **No DB data is read or written**;
no directory/file is created or unlinked. Each must fail with actual
kernel `EACCES` or `EPERM`: `ENOENT`, `EROFS`, `ELOOP`,
`ENOTDIR`, `ECONNREFUSED` or an unexpectedly successful open are
**STOP**, not denial evidence. The reader must additionally inspect the
exact `0710/0660` listener inode and receive a bounded original
`SOURCE_ONLY_CANDIDATE_READ` `candidate.head` over AF_UNIX. The kernel
server `SO_PEERCRED` must equal the owner-pinned PID/Registry UID/GID;
its exact instance/scope/revision and all false authority fields are
checked. Repo must fail the **real socket connect** with `EACCES` or
`EPERM` without receiving a valid Registry response. An inaccessible
parent might yield `EACCES` even if a socket does not exist; that is
**not proof of a live denied listener without the separate original
reader PASS and owner host inspection**.

Each execution emits only
`SOURCE_ONLY_CROSS_UID_ACCESS_OBSERVATION` with the pinned profile
digest, actual process identity, kernel denials and bounded socket
evidence. `originalHostVerified=false`,
`ownerAcceptanceVerified=false`, `collectorAuthenticated=false`,
`liveRegistryAvailable=false`, `admissionAllowed=false`,
`deploymentAllowed=false`, `runtimeActivationAllowed=false`,
`rollbackProtected=false` are always explicit. The owner must compare
the **two original process observations and the same pinned profile**
against an independent host inspection after running the probe,
including mount namespace, UID mapping, backup/restart and writer
identity. No programmatic GO, Gateway grant or automatic promotion is
performed.

**Evidence limit:** these source tests run under one unprivileged UID
(`uid=1000` in the current Repo environment); user namespaces are
blocked (`EPERM`). Tests exercise the actual Unix socket, actual
`SO_PEERCRED`, permission-denial classification, strict profile and
fail-closed same-UID behavior, but **cannot** assert the real
cross-principal host acceptance condition here. A real owner-managed
non-Production host execution under two separately provisioned UIDs
remains outstanding. Even successful host probes do **not** establish
authentic GitHub/Core collector, owner enrollment, a working Gateway
`registry.ingest_merged`, protected rollback witness or
`FUNCTIONAL_V1_GO`. The next vertical integration must provide
bounded collector admission and a separately reviewed Gateway API
before live Registry desired can be authoritative.

## Registry candidate READ through existing Gateway Core/Broker and Unix transport (2026-11-23)

**Implementation source accepted only after PR review, not installed or
granted.** The P5 candidate reader from #231 can now be addressed through
the **existing authenticated** `RepoIntentBroker` and `RepoIngress`
`/v1/reads` contract, using new
`fortis_approvals/integrations/registry/candidate_gateway.py`.
The adapter does not install itself into the running R7 Gateway.
It requires a trusted host to supply an **already bound** exact private
socket path, Registry instance UUID/scope digest, server PID/UID/GID,
reader UID/GID and current socket device/inode. Runtime requests cannot
select any of these, a credential, actor, filesystem path or SQL.

The separate **candidate-only** typed operations are:
`registry.candidate_head` with `{repository}`,
`registry.candidate_list_desired` with
`{repository,limit,cursor}`, and
`registry.candidate_original_operation` with
`{repository,operationId}`. Existing Core actor/grant/policy checks
run **before** any AF_UNIX connection and again before returning data;
revocation, DENY, unapproved ASK, scope mismatch, stale socket inode,
wrong kernel server `SO_PEERCRED` PID/UID/GID, request/response
mismatch, invalid canonical framing, oversize data or unavailable DB
must STOP. The adapter invokes the source process's exact
`candidate.head`/`candidate.list_desired`/
`candidate.original_operation`, never a Registry WRITE.

The Gateway response is strictly
`SOURCE_ONLY_CANDIDATE_READ` with source `LOCAL_EVENT_CHAIN_ONLY`
and explicit `authenticatedCollectorAvailable=false`,
`admissionAllowed=false`, `deploymentAllowed=false`,
`writeEnabled=false`, `liveRegistryAvailable=false`,
`rollbackProtected=false`. Page records are bounded, validated
against exact identity/source SHA, canonical SHA256 record ID,
approved required actions, `PLANNED_UNVERIFIED` and
`actual=null`. The original operation response includes only
the exact request UUID, local checkpoint, source SHA, record IDs,
supersession links and a local receipt digest; it does not expose
raw Core/owner credentials or assert an authorized release.
A missing local original operation is **DENY**, not canonical
`NOT_FOUND`. The live `registry.list_records`,
`registry.get_record`, `registry.get_operation`,
`registry.ingest_merged` and `registry.report_manual_complete`
remain closed. No candidate DTO is valid as a live Registry record
or verified installed actual. Existing `registry.capabilities`
continues to indicate `SOURCE_ONLY` with zero live operations.

**Security and activation constraints:** this integration adds
new **potential** typed read method names to packaged Gateway source,
but does **not** register an R7 read adapter, owner policy, machine
principal or grant, nor change the Registry host/service image or
Production state. Source regression runs real WSGI → Core/Broker →
AF_UNIX → local SQLite under one UID, deliberately mocks
cross-principal identity checking solely to exercise protocol;
the real-host source acceptance probe from #232 must run under
distinct verified UIDs before any non-Production rollout.
Full original collector authentication, policy/owner acceptance,
bounded source-only-to-authoritative admission, isolated writer,
first forward-only enrollment and original UUID recovery across
live processes still require separate review. Modifying a packaged
Gateway input creates a **release impact obligation for
`fortis-gateway`**, not approval to build/replace an image.

**E1 reader identity guard (source-only):** the existing Gateway-to-Unix
candidate adapter now verifies real/effective/saved UID/GID, supplementary
groups (excluding the Registry group), complete `/proc/self/status`
identity, zero capabilities, `NoNewPrivs=1`, `Seccomp=2` and no tracer
before/after socket reads. Missing or changed evidence is a DENY, not
an empty queue. Unit tests use synthetic `/proc` data, so they do not
establish real cross-UID isolation. The existing owner-run host probe and
separate E1 host/ACL/image/grant review remain required; neither Registry
WRITE nor an authoritative queue is enabled.

**E1 existing R7 + Repo READ composition (source-only):**
`build_r7_unified_candidate(..., registry_candidate_reader=...)` accepts
only the preconstructed exact `GatewayRegistryUnixCandidateRead` class and
checks its invoking identity before wiring that existing adapter into the
existing Core/Broker `/v1/reads` route. The normal `r7_unified_server` passes
no such input. There is **no** automatic actor, grant, ALLOW/ASK policy,
capability advertisement, Registry socket creation or image activation.
The Repo-side `integrations/registry/repo_client.py::RegistryCandidateClient`
uses the existing authenticated Gateway transport with fixed target/repository
and exposes only `head`, bounded `list_desired` and original local UUID READ.
It rejects ASK/PENDING, malformed/forged replies and unavailable storage,
never converting them to empty records or installed actual. A real R7 WSGI
→ Core/Broker → AF_UNIX → schema-3 regression uses **test-only** grant/policy
and same-UID mocks; neither a live machine grant nor host cross-UID proof.
E1 still requires separately owner-reviewed non-Production host, installed
source/image, real distinct principals, pinned mount/socket state, permissions,
backup/restart and actual denied Repo access. E2 trusted original collector,
first enrollment and authorized `ingest_merged` remain unavailable.

**E1 Repo→Gateway live READ observation (source-only):**
`RegistryCandidateClient.observe_e1_candidate` and
`scripts/probe-functional-v1-registry-gateway-read.py` use only the existing
authenticated Gateway `/v1/reads` methods; the owner supplies a previously
pinned selected-main SHA and *original* local operation UUID. The bounded
head → original UUID → full candidate page(s) → head readback requires matching
instance/scope, revision/event digest/source cursor and matching nonempty
record IDs. Missing grant/socket/DB, absent UUID, source mismatch, incomplete
pages and concurrent changes STOP, never return an authoritative empty queue.
Only a sanitized `SOURCE_ONLY_E1_GATEWAY_READ_OBSERVED` diagnostic is emitted;
all approval/WRITE/host-proof fields remain false. This does **not** replace
the independent host cross-principal denial probe, owner review or E2
authenticated collector/ingestion; source-only tests are not host acceptance.

## Closed candidate contract

Separate module `fortis_approvals.registry.boundary` is not packaged into
either existing runtime. It provides an in-process offline dispatch test
boundary, not HTTP ingress or an advertised live capability. The existing
synthetic Core authenticator can be injected for tests; production identity,
transport, credential provisioning and broker review remain future steps.
Only the exact canonical repository `AlexPastukhh/fortis-approvals` is
accepted, and only the proposed planner/reader identities after injected
authentication. No Repo, Publisher or collector credential gains access.
The actor is never a payload field. No storage, provider token or path is
selected by requests.

Requests are UTF-8 JSON bytes, maximum 4096 bytes, exactly
`operation` and `params`. Duplicate names, nonfinite numbers, malformed
JSON, unknown/extra fields and unsupported operations are rejected.
All operations require the canonical `repository` parameter.

| Operation | Additional exact params | Source-only behavior |
| --- | --- | --- |
| `registry.capabilities` | none | SOURCE_ONLY, no live operations, no writer or store |
| `registry.preview_merged` | evidenceId, evidenceDigest | inspect current referenced source candidate; always blocked |
| `registry.get_operation` | operationId | STORAGE_UNAVAILABLE; never fabricate a receipt |
| `registry.get_record` | recordId | STORAGE_UNAVAILABLE |
| `registry.list_records` | limit, cursor | STORAGE_UNAVAILABLE; never return an empty queue |
| `registry.ingest_merged` | operationId, evidenceId, evidenceDigest, expectedRevision | schema defined; planner WRITE_DISABLED, reader DENIED |

Canonical UUIDs are used for operation and evidence IDs; digests/record IDs
are lower-case 64-hex; revision is a nonnegative signed-64-bit integer.
List limit is 1–100; cursor is null or bounded opaque URL-safe text
(encoding/authentication and pagination implementation are deferred).
No route for deploy, installed-state verification, manual complete,
arbitrary queries or GitHub operations. In particular a valid WRITE schema
does not authorize execution.

## Preview and evidence identity

A source-only owner-composed evidence-reader function receives an evidence
ID; the request cannot supply a snapshot, actor, target, environment,
selected SHA, policy flags, action list or path. The response must be the
bounded (2 MB canonical UTF-8 JSON) exact wrapper:
`{schemaVersion:1, issuer, repository, evidenceId, result}`, with issuer
`release-registry-collector-v1`. Its exact SHA-256 must match the request.
The result is the existing `SELECTED_MAIN_LOCAL_SOURCE_BOUND` observation
including its digest, retained Impact digest and false authority flags.
Only this present source observation format is supported. A matching wrapper
or issuer label/digest is not authentication of a protected collector.

Preview returns `BLOCKED_EVIDENCE_GAP`, `SOURCE_CANDIDATE_ONLY`, exact
reference and observed source identity/classification, fixed missing proof
codes and distinct unresolved target/PR dependency codes. It never returns
records, record count, actual, an admitted no-deployment decision or a
write receipt. Even a no-deployment observation cannot be admitted with
the current gaps. Correct-looking positive flags are rejected, not promoted.
Reader failure/unavailability is explicit `REGISTRY_EVIDENCE_UNAVAILABLE`;
the source checks identity, digest and actor active status again before
returning preview. No original PR body or raw evidence snapshot is exposed
by the projection.

The authenticated immutable snapshot reader, owner-reviewed baseline/full
lineage, historical merge cutoff/effective CI policy, exact enrolled
dependency closure, component/environment binding, and protected
collector/Registry recovery remain prerequisites. They cannot be
implemented by making the current flags configurable.

The source-only [collector candidate journal](RELEASE-REGISTRY-P5-POST-MERGE-GATEWAY-CONTRACT.md#collector-snapshot-and-independently-witnessed-candidate-receipt)
can be composed as the evidence reader; unconfirmed checkpoints refuse
reads, including after restart. A matching external checkpoint only
binds the original candidate bytes. It does not clear any of the fixed
admission gaps, and the collector receipt is not a Registry receipt.

## Original receipt boundary (no writer yet)

The closed lookup key is authenticated principal + exact repository +
operationId. The actual store and visibility policy must be composed
server-side in a later reviewed increment; a caller cannot pick a receipt
actor, anchor, or stored path. Until then every well-formed authorized
lookup fails with REGISTRY_STORAGE_UNAVAILABLE. In particular unavailable
storage is not NOT_FOUND, an empty queue, or successful reconciliation.

Future store contract: original immutable operation fingerprint binds
authenticated actor, exact repository, evidence ID/digest and expected
revision; transaction-bound receipt binds prior and resulting revision,
outcome and original evidence reference. Successful authoritative readback
requires independently confirmed instance/schema/checkpoint and exact
operation visibility. A local stored receipt alone is not proof of
external anchor advancement. Missing, inconsistent or unconfirmed
receipt/anchor remains UNKNOWN_OUTCOME or a storage/evidence error.
An exact replay can return the original receipt only after those checks;
different fingerprint under same UUID conflicts. The production receipt
DTO, visibility, CAS, durable writer and two-system fault recovery require
their own review and tests; this source creates none of them.

## Source checks and delivery

`python3 -B -m unittest discover -s fortis_approvals/tests -p test_registry_boundary.py -q`
exercises closed schema, exact scope/actor, role spoofing, disabled WRITE,
strict JSON and pagination bounds, evidence identity/digest, unsupported
positive claims, source unavailability, revocation, dependency gaps and
receipt/storage unavailability. The integration test consumes actual
temporary Git/Core selected-main composition output (synthetic provider
and validator protocol double) and still returns blocked. The new test
is mandatory in the existing Source CI test entrypoint, without changing
any pinned workflow bytes.

The two Registry module files are explicitly classified as offline
non-runtime sources in the existing catalog. Changing the catalog itself
conservatively affects all existing targets under the shared Release
Impact validator. No Registry build target/image is yet defined; its
future independent runtime and catalog enrollment require a separate
review, and these classification entries are not a blanket future
Registry source exemption. No live API, database, grants or deploy.


### Policy-bound source snapshot compatibility

The collector's schemaVersion 2 wrapper adds the exact immutable
registryPolicy reference and registryReview candidate to the original
selected-main result. Preview verifies wrapper/source identities,
selected-main observation digest, policy reference digest and all false
review flags. It still returns BLOCKED_EVIDENCE_GAP, now including
PROTECTED_REGISTRY_REVIEW_POLICY_ACCEPTANCE; it never claims actual
policy acceptance or successful intake. Full paired retention and
forward-range consistency are checked in the owner-composed collector,
not by trusting a caller-supplied DTO. SchemaVersion 1 remains supported
as a legacy blocked source candidate.

### Initial Registry transaction mechanics (source only)

The Registry-owned `state_journal.py::RegistryStateJournal` implements
the initial-range SQLite transaction from PR #200. This is the owning
state schema v1, not the earlier Container fixture journal or another
collector journal. **No admission or live dispatch is enabled.**
Only the initial nonempty merge range can be recorded; subsequent
suffixes and supersession require a further reviewed schema extension.

The host composes an explicit private database path, immutable enrolled
scope (repository, enrollment ID, baseline SHA and digest, catalog,
binding and policy digests), independent anchor reader, and a plan
reader by evidence ID. A distinct combined-plan wrapper has exactly
schemaVersion=1, issuer, repository, evidenceId and plan; its digest
binds all bytes. This is an internal candidate protocol, NOT the
existing per-merge collector snapshot, not an installed plan receipt
provider, and not authenticated transport. The proposed planner
identity is a host parameter, not a credential or public actor selector.

Explicit initialization requires an externally supplied genesis checkpoint
binding instance and scope; no existing DB is replaced or missing DB
automatically created. The private 0700 directory, 0600 regular single-link
files/sidecars, WAL, FULL synchronous, foreign keys, bounded busy timeout
and exact schema are checked. BEGIN IMMEDIATE serializes operation, original
fingerprint, retained candidate plan, original receipt and candidate records.
The event digest binds instance, scope, revision, operation fingerprint,
evidence digest and previous digest. Every read recomputes the retained
plan/receipt/event bindings and exact record projection. The candidate
cursor is derived from the immutable receipt, not a mutable main pointer.
Only deployment candidates create candidate records; a nonempty
no-deployment candidate retains its audit with zero records.
An empty range cannot advance this cursor.

Exact operation replay returns the original receipt only when an
independent matching head is observed; a changed fingerprint conflicts.
CAS mismatch, competing commits, scope mismatch, incomplete candidate
or unsupported suffix block. Locally committed data without a matching
anchor returns UNKNOWN_OUTCOME; candidate cursor reads are blocked.
An original-operation read can expose only the exact pending checkpoint
identities, not a committed receipt. Anchor/readback failure after commit
or an ambiguous local COMMIT is UNKNOWN_OUTCOME with the operation ID;
resolve that same operation, never blindly reapply. The state journal
has **no anchor writer**. The test witness is synthetic; an actual
protected monotonic external anchor, exact CAS advancement, recovery
authority and backup/restore still require implementation and owner
acceptance. A rolled-back witness is not proof of a new transaction.
There is no live queue, authoritative absence assertion, artifact build,
release operation, route or permission change. All candidate verification
and admission flags remain false.

Mandatory source tests cover original replay, pending read blocking,
scope/actor/identity checks, invalid actual state, no-deployment audit,
missing DB, tampering, atomic rollback, commit/readback ambiguity and
competing writers. The admission-plan fixture also exercises the real
composed source candidate through this SQLite transaction with a
synthetic independent witness. The existing typed dispatch remains
WRITE-disabled and disconnected from the state journal.


### Explicit Registry schema v2 candidate for suffixes and supersession

`registry/state_journal_v2.py::RegistryStateJournalV2` is a separate,
explicitly initialized Registry-owned SQLite **schema version 2**.
It does not migrate or reopen a schema-v1 database, and the existing
schema-v1 class and original receipts are not rewritten. This is an
offline-only candidate that must be reviewed **before** a real enrollment
chooses its production schema. Any existing v1 installation would need
a separately approved, verified migration/backup/restore procedure.
The genesis hash is domain-separated (`registry-state-v2`) from v1.
The external checkpoint wire shape remains version 1 for the current
bounded source observer; this is not a claim that a live external anchor
already exists.

The journal has a single owner-provisioned private database with
operations, immutable record payloads, and separate supersessions
edges. Every initial or suffix operation uses the host-selected
planner identity, operation UUID, retained plan evidence UUID/digest
and expected revision. The caller supplies **no** cursor SHA, desired
records, component list, supersession selection, or stored actual value.
All plan bytes come from the separate host-composed evidence reader,
are strictly compared to the immutable enrollment/policy/catalog
scope and revalidated under the original envelope. First append must
be `INITIAL_RANGE_PLAN_CANDIDATE` from baseline; later append must
be `SUFFIX_RANGE_PLAN_CANDIDATE` whose startCursorSha equals the
previous immutable candidate cursor and whose
registryCursorCheckpoint equals the entire previous local checkpoint.
No empty range, duplicate merge, owner request, PR number or evidence
ID is accepted across operations. The collector's own checkpoint
must advance on the same collector instance. Any catalog/policy
transition remains unsupported.

Each candidate record is identified by the planner's original
subject SHA256 and version SHA256. Repeated subject IDs receive new
immutable version records; the journal stores a separate
`fromRecordId → toRecordId` edge only when the same subject has a
previous version. Former record rows and original receipt bytes are
never edited. A no-deployment suffix may advance the candidate cursor
with a retained nonempty merge audit but creates no record or
supersession. A later deployment of that subject supersedes its last
stored version, not a fabricated no-deployment record. The graph is
validated by replay of every original operation and all stored record/
edge rows on read; tampering or missing rows fails closed. Old receipts
remain retrievable by their exact operation ID after subsequent
operations.

Transaction revision, event hash chain, full original request/evidence,
immutable receipt, record payloads and supersession edges commit
atomically under one bounded BEGIN IMMEDIATE CAS transaction. The
source schema has a conservative 64-operation, 512-record and
16 MB bound, with exact schema check, WAL/FULL, private file checks,
and full independent checkpoint re-read. Pending local commits return
`UNKNOWN_OUTCOME` with original checkpoint identities and do not
permit another append or a candidate cursor read; recovery compares
the same original operation without resubmitting changed evidence.
An ambiguous SQLite commit also returns `UNKNOWN_OUTCOME`.
The journal does not implement or write the separate owner-protected
checkpoint: tests inject a synthetic in-memory witness. Backup/restore,
independent anchor CAS, full migration policy and live owner ceremony
are still required.

The existing `observe_suffix_plan` accepts only the exact bound
checkpoint method of the schema-v1 **or schema-v2** journal. A caller
closure remains forbidden. It rechecks state scope and checkpoint
before returning its candidate; it cannot advance the cursor. These
records are never represented as installed state:
`actual=null`, `PLANNED_UNVERIFIED`, `evidenceVerified=false`,
`admissionAllowed=false`, `deploymentAllowed=false`. No typed
live ingress, public reader, service principal or deployment action
is added. First-range schema v1 remains an isolated compatibility
source path, not an silently upgraded production database.

Offline source tests include three-version supersession chain,
no-deployment suffix followed by deployment, new subject without
supersession, duplicate/replayed evidence, different collector
instance/revision, exact witness rollback and pending recovery,
corrupted local links/records, competing writers, failed transaction
rollback, and rejection of schema v1 without migration. Integration
also feeds a real Core/Git first plan and a second real Git merge
with *synthetic* second owner/collector evidence into the v2 journal.
No two live owner-approved merges or protected anchor is claimed.


### Inactive SQLite backup and recovery readback (source candidate)

`registry/recovery_snapshot.py` offers two host-composed offline
functions for **Registry schema v2 only**:
`create_verified_backup(store, directory, backup_id)` and
`verify_inactive_backup(directory, backup_id, instance_id, scope,
anchor_reader, plan_reader)`. They do not run in an active service,
write to the external integrity anchor, rotate backups, or replace an
active database. The host chooses a preexisting separate absolute
0700 directory, and an owner-provided independent checkpoint reader
and original evidence reader. Backup ID is a UUID. No caller can
choose SQL, a source SQLite filename, a different enrollment or a
new cursor. The source store must be exactly
`RegistryStateJournalV2`; no schema v1 migration or auto-create
of the source is performed.

A backup starts only when the source candidate cursor read agrees
with the independently read anchor. The SQLite online backup API
copies a consistent database snapshot into a new 0600 file with
exclusive create, **not** a raw copy of a WAL DB file. The copy is
opened as a separate inactive v2 instance and its full original
operation chain, immutable receipts, records and supersession edges
are checked against the same independently supplied checkpoint.
The source, copied state and witness are compared again before a
durable manifest is created. The manifest is a canonical JSON file
containing exact schema/instance/scope digest, backup UUID, checkpoint,
candidate cursor, SQLite byte length/SHA-256 and operation/record/
supersession row counts. The destination file and manifest are fsynced;
an additional verification reads and hashes the copied bytes, checks
all canonical manifest fields, replays the independent journal
integrity verification and performs another witness readback.
No successful receipt is emitted before this. The backup verification
result deliberately states `INACTIVE_BACKUP_MATCH_CANDIDATE`,
`restoreAllowed=false` and `admissionAllowed=false`.

Any missing/corrupted manifest, wrong SQL schema, private-path
permission/symlink failure, rollback of the witness, changing source
checkpoint during backup, or inconsistent table/event/supersession
state blocks. A failure may leave an incomplete private destination:
never interpret a backup file without a verified manifest as a usable
restore point; no cleanup or reuse of the original backup UUID is
automatic. The snapshot is not an authenticated or encrypted remote
backup, and a shared UID/disk cannot prove an independent protection
boundary. The supplied witness may be an in-memory test fake;
the real owner-protected external monotonic checkpoint and the
backup host, encryption, retention and recovery operator are
still unverified. SHA-256 alone is not backup authority.

Only **readback of an inactive backup** is implemented. There is no
restore command, active-DB swap, last-known-good fallback, rebuild
from GitHub, acceptance of a stale checkpoint, or auto-migration.
An actual restore must be separately owner-reviewed, independently
verified against a protected checkpoint in an inactive new instance,
and must not reset a newer operation chain. Candidate retention
policy is daily consistent snapshots (30 daily copies) and
pre-change snapshots with owner-approved retirement; scheduling,
cleanup, separate encrypted backup placement and retention evidence
remain future runtime work. Source tests exercise empty and
two-transaction backup, unchanged original source, same original
receipts, failed pending state, changed copy/digest/manifest,
permission/symlink and scope/instance mismatch, witness rollback
and concurrent source advancement. They do not simulate a live
owner-protected checkpoint service or actual production recovery.


### Offline checkpoint CAS candidate — owner-side source protocol

`registry/checkpoint_cas.py::OfflineCheckpointCAS` implements a
**separately initialized, local owner-side source candidate** for
checkpoint compare-and-swap. It is *not* a deployed protected anchor.
The class has no authenticated transport, owner WebAuthn authorization,
service principal, signed enrollment ceremony or privilege separation;
its tests run under the same Docker UID. The mere presence of a second
SQLite database or a digest does not establish an independent trust
boundary. This module is explicitly excluded from the existing images
by the exact `noDeploymentPaths` catalog rule. A production owner
checkpoint must reside under a dedicated identity and storage boundary
that the Registry writer and Repo AI cannot mutate, with separately
reviewed peer authentication and policy. Do not install this module as
an unrestricted service endpoint.

Only an owner-provisioned, preexisting 0700 directory may contain this
explicitly created 0600 WAL/FULL checkpoint database. Genesis comes
from the **v2 Registry state genesis**, with an owner-selected instance,
exact enrollment scope, pinned nonempty original enrollment receipt
digest and fixed registered Registry-journal path. No missing anchor
is reconstructed from the Registry database, and no existing anchor
is overwritten or migrated. Owner enrollment acceptance and the
real protected source identity/volume remain separate owner gates.
Current source path pinning models an exact local owner configuration;
a future separate-service protocol must bind the authenticated peer
and source instance rather than accept arbitrary remote paths.

The owner-side `advance` call takes only the original operation UUID,
the exact prior and proposed checkpoints and a host-bound original
Registry v2 operation reader. It accepts **only**
`RegistryStateJournalV2.operation` from the configured journal whose
`anchor_reader` is exactly this checkpoint reader, with the same
instance, scope and a different directory. The reader MUST show the
original `UNKNOWN_OUTCOME` with exactly these two checkpoints and the
same operation ID, or (for idempotent recovery) the original already
anchored receipt with identical identities. A missing, unregistered,
forged or altered operation cannot advance the anchor. No plan DTO,
provider token, arbitrary SQL, caller-chosen source path or caller
"verified" flag is accepted at this method boundary. This source
binding is NOT a substitute for live inter-service authentication.

Under SQLite `BEGIN IMMEDIATE`, the owner ledger checks its entire
immutable checkpoint/operation chain, compares the original current
checkpoint and appends one exact transition `revision+1`. Its
stored receipt binds the enrollment receipt digest, original operation
ID, previous/next checkpoint, pending readback digest and owner-ledger
event hash. Reuse of the same operation ID with different data
conflicts. Two concurrent exact requests yield one stored transition
and the same receipt after original readback. Original receipts remain
queryable after later transitions; read-only retry handles a race
between Registry's two anchor reads without replaying CAS. A lost
acknowledgement is resolved by reading the original owner operation;
an uncertain commit must **not** be submitted under another ID.
Every read validates schema, permissions, monotonic revision and
full persisted chain, but this does not prove tamper resistance
against the authority's host/UID or an unprotected backup copy.

After CAS, the original Registry operation must read back
`ANCHORED_CANDIDATE_TRANSACTION` with the same checkpoint pair;
otherwise the owner-side outcome is **not** announced as confirmed
by this protocol. The external result is still named
`CHECKPOINT_CAS_CANDIDATE`, with
`protectedAnchorVerified=false` and
`admissionAllowed=false`. The current Registry Writer still only
stores **candidates** and never exposes installed state. A protected
monotonic witness, separate credentials/network/storage, owner enrollment
sign-off, backup/restore and end-to-end failure/restart tests are
required before live admission. No runtime route, authority grant,
checkpoint service activation or Production change is in this PR.

Fifteen focused offline tests bind the actual Registry v2
`UNKNOWN_OUTCOME` to the distinct checkpoint ledger and exercise
first/suffix CAS, immutable original receipts, concurrent identical
calls, a late idempotent replay after another revision, restart,
wrong enrollment/source path, missing or forged pending operation,
modified ledger, private-path permissions, and a rolled-back witness.
They use local temporary SQLite databases with a synthetic owner
boundary — not an actual separate UID or trusted anchor service.


### Read-only owner/Registry checkpoint reconciliation candidate

`registry/recovery_reconcile.py::reconcile_inactive` implements an
**offline-only, read-only** recovery preflight across the exact v2
Registry journal, its registered owner-side
`OfflineCheckpointCAS` ledger and an optional exact inactive SQLite
backup. It accepts concrete locally composed object instances, not a
caller-supplied checkpoint, arbitrary SQL or public actor flag. It
requires the same scope, instance, v2 genesis, registered Registry path
and the exact bound owner-checkpoint reader; another instance or
anonymous callable is refused. This checks the *source protocol*, NOT
a privilege boundary. Both modules remain under the same test UID,
not under a separately provisioned owner or service identity.

The preflight independently replays the full immutable Registry
request/evidence/receipt/record/supersession history and the complete
owner checkpoint ledger, then cross-matches **every** owner operation
against the Registry receipt and the original pending transition.
It re-reads both journals before returning and stops on any change
or divergence. If they exactly agree, it reports
`MATCHED_LOCAL_CANDIDATES`, together with the source candidate cursor
and owner/Registry checkpoint. This is not a protected-authority
assertion, not a release queue and not a permission to write.

If Registry is ahead by exactly one locally committed operation,
the result is `UNRESOLVED_LOCAL_COMMIT_OR_OWNER_ROLLBACK` with the
original operation ID and checkpoint pair but **no candidate cursor**.
This is deliberately NOT named "safe to advance": without an
independently protected monotonic witness, an interrupted commit and
a rolled-back owner ledger can be indistinguishable. No automatic
owner CAS, rollback, retry, witness reseeding, blank rebuild or active
restore is possible from this API. An owner-ledger advance ahead of
Registry, a larger gap, conflicting original receipts, missing
operations, corrupted ledgers or changing checkpoint produces STOP
via a strict error.

An optional backup requires a complete backup directory plus UUID.
It is checked only when both live local journals match; the existing
inactive backup verifier checks the copied bytes, full original
Registry history, exact scope, independent owner checkpoint and
candidate cursor. A backup even one revision behind is **not**
accepted as a current recovery point. The backup file is never
copied into the active instance. A missing backup does not silently
become a verified backup; the observation records `backup=null`.
The result `REGISTRY_RECOVERY_READBACK_CANDIDATE` and its digest
always retain false `protectedCheckpointVerified`,
`enrollmentVerified`, `backupRestorable`, `restoreAllowed`,
`admissionAllowed` and `deploymentAllowed`. No owner security
claim follows from a matching local hash chain.

The private SQLite path guards also tolerate the narrow race where
SQLite unlinks an optional WAL/SHM sidecar between the existence check
and `lstat`; any newly appearing sidecar is rechecked, while symlinks,
bad permissions and unexpected file types remain denied. This fixes
an observed concurrent source test failure and is not a relaxation of
the private database/parent permissions policy.

A host-owner protected monotonic witness with separately verified
access controls, authenticated origin and enrollment acceptance
remains a prerequisite. Even this preflight cannot detect rollback
of **both** local copies without external protected retention.
Real restore switchover, backup lifecycle, runtime and E2E are
still unimplemented and require owner approval. Fourteen dedicated
offline tests cover genesis, first and second operations, inactive
backup readback, old backup rejection, pending and rolled-back
witness ambiguity, larger gaps, wrong source binding, storage
tampering, race detection and no-write replay. No deployment or
service route is added.


### Owner checkpoint Unix peer boundary — source-only preflight

`registry/owner_peer_boundary.py::observe_accepted_peer` adds an
**offline-only Linux AF_UNIX/SOCK_STREAM peer-envelope candidate**.
It creates NO listening socket, process, container, route, credential,
privilege grant or Registry WRITE binding. A future owner-run local
service would need to provision a filesystem socket at a separately
accepted absolute path, verify actual protected hosting and connect
a closed transport dispatch only after owner acceptance. This code
intentionally never calls `OfflineCheckpointCAS`, never returns the
protected checkpoint and always reports `dispatchAllowed=false`,
`protectedAuthorityVerified=false`,
`ownerAcceptanceVerified=false` and `admissionAllowed=false`.

The exact immutable owner profile is required through a host-supplied
reader plus an expected SHA-256 of canonical JSON. It fixes Linux
AF_UNIX/SOCK_STREAM with kernel SO_PEERCRED, one instance UUID,
scope digest, enrollment receipt digest, socket path and separately
specified non-root authority, registry and owner-operator UID/GID
identities. All three UIDs must differ. The source guard validates
the *current process* UID/GID as the owner-service identity, the
exact server-side accepted socket path, its existing non-symlink
socket type/UID/GID/0660 permissions and its existing parent
directory type/UID/GID/0710 permissions. The socket path and profile
are rechecked after request framing; a replacement inode/profile
invalidates the read. SO_PEERCRED is read directly from the accepted
kernel Unix socket, not from a `uid`, `role` or `actor` field in
the message. The requested exact operation and scope are validated
under a bounded single canonical UTF-8 JSON-line frame. Unknown,
noncanonical, duplicate-key, oversized, trailing and pipelined frames
are denied. No TCP listener, abstract Unix socket, free-form SQL,
path selector or arbitrary caller profile is supported.

The only recognised envelope operations in this **source guard**
are `checkpoint.get` (registry-reader or owner-operator UID/GID)
and `checkpoint.original` (owner-operator UID/GID only).
`checkpoint.advance` is closed **even to the owner-operator peer**:
OS UID/GID is a transport authentication signal, not a WebAuthn owner
decision or a protected acceptance receipt. The previously implemented
offline `OfflineCheckpointCAS.advance` is not exposed through this
transport candidate; no bridge is enabled. A future implementation
must obtain a separately attributable owner WebAuthn ceremony,
authenticate the actual peer and source Registry process under
independently verified UID/user-namespace/mount topology, and verify
the original pending Registry operation before permitting any CAS.
No caller assertion, claimed profile digest or local matching ledger
promotes `protectedAnchorVerified` or admission.

The source profile assumes a host-provisioned writable Unix socket
group and real cross-UID processes, but it does NOT provision the
group memberships, runtime namespaces or secure host directories.
The currently shared source-development UID and Docker test topology
cannot demonstrate isolation from Repo/AI or from the Gateway.
The tests assert Linux actual SO_PEERCRED denies a same-UID peer;
positive role cases are explicitly **synthetic credentials** at the
pure classifier test seam, not a cross-UID live service test.
The future owner's live negative test must show that the Registry
process cannot modify the external owner DB/anchor, that the
owner-specific operator is separately authenticated/approved, that
Repo/Gateway/publisher identities cannot perform checkpoint CAS,
and that the protected witness cannot be rewound with the local DB.
Fail closed when these protections cannot be demonstrated.

The new module is explicitly added to the pilot release catalog
`noDeploymentPaths`: source review does not alter active image inputs
or provision an owner checkpoint container. Eleven offline tests
cover role spoofing, denied owner CAS, malformed frames, scope/profile
pinning, Unix-vs-TCP rejection, invalid socket permissions, real
same-UID peer denial and source-only false authority flags.


### Source-only Linux owner/Registry placement observation

`registry/owner_runtime_isolation.py::observe_host_isolation` reads a
**pinned Linux host layout candidate** and the previous pinned
`owner_peer_boundary` profile. It is an offline preflight for owner
review, not a container deployment, accepted enrollment, protected
checkpoint or live Registry authentication layer. No local process,
volume, socket or credential is created, changed or restarted.
This source file is explicitly in the catalog's
`noDeploymentPaths`; no runtime image adds the module.

The owner-selected layout pins its exact canonical JSON digest,
Registry instance/scope, matching peer profile digest, Linux boot UUID,
three distinct current PIDs (owner checkpoint, Registry writer and Repo
observer), both expected state database absolute paths and the Repo
UID/GID. It is checked against the separately pinned Unix peer
profile, including unique non-root authority/Registry/operator UIDs
and the exact enrollment receipt digest. Profiles are **host
preconditions**, not user-submitted credentials. A matching hash does
not prove that a person or trusted owner signed the profile.

The code reads `/proc/PID/stat` (process start ticks, checked twice),
`/proc/PID/status` (all four real/effective/saved/filesystem UID/GID
values, supplementary groups, all five capability sets, NoNewPrivs,
seccomp and TracerPid), `/proc/PID/ns/mnt`, and
`/proc/PID/cgroup`. The boot UUID is checked before and after the
observation. It requires separate non-root process credentials, zero
inheritable/permitted/effective/bounding/ambient capabilities, zero
tracer PID, `NoNewPrivs=1`, `Seccomp=2`, and different mount
namespaces and cgroup readings for owner, Registry and Repo. Registry
and Repo must not join the owner state GID. PID/start-tick and all
process observations must remain unchanged through the second read;
any restart/reuse/drift is STOP, never an enrollment fallback.

For the owner and Registry SQLite paths, the observer refuses
symlinks in every existing ancestor, requires existing private 0700
directories and 0600 single-link regular files with the expected
respective UID/GID, and requires their parent/file device IDs to
agree within each state volume but differ across owner/Registry
volumes. The existing Unix socket's strict owner/group/type/0710
parent/0660 socket guard is reused and its inode rechecked. Directory
or file creation, chmod/chown, backup restoration, encryption setup
and socket binding are deliberately out of scope. Separate device
IDs alone do **not** establish encrypted storage, authenticated
inter-service transport or independence from privileged host actors.

The returned
`OWNER_RUNTIME_ISOLATION_OBSERVATION_CANDIDATE` binds the pinned
layout/profile, process start ticks, observed namespace/cgroup and
filesystem inode/device evidence in a deterministic digest. It always
returns `protectedAnchorVerified=false`,
`enrollmentVerified=false`, `hostStorageVerified=false`,
`ownerAcceptanceVerified=false`,
`runtimeActivationAllowed=false` and
`admissionAllowed=false`. A synthetic positive assessment is
not evidence of real cross-UID containers or a protected checkpoint.

**Before live P5 owner acceptance**, an independent operator must
first provision and verify the real owner/service/Registry/Repo
identities and distinct host volumes, separate backup protection and
encryption, process/image and seccomp policies, service-owned
authentication, the owner WebAuthn ceremony and a monotonic
out-of-writer checkpoint that cannot be reset by Repo/Gateway.
Run actual cross-principal negative tests: Repo, Gateway, Publisher
and Registry cannot write the owner checkpoint DB; unrelated callers
cannot read or advance the owner service; only the owner-scoped,
separately authorized operation can perform CAS after exact original
pending receipt reconciliation. Verify fail-closed restart, crash,
backup and restore on a non-active instance. These checks are NOT
satisfied by the source unit tests or current shared Docker UID.

Sixteen offline tests include synthetic distinct role observations
(with authority flags still false), exact profile/boot pinning,
missing/changed process capabilities or namespaces, shared state
devices, symlink state, real local `/proc` parsing, process/boot
races and explicit rejection of source-worker self-attestation.
They do not exercise a provisioned owner runtime. No P5 live GO or
source-only merge is allowed to imply one.


### Owner storage cross-principal denial preflight — P5 source candidate

`registry/owner_storage_denial.py::observe_storage_denial` adds a
host-invoked, **source-only** negative access test for the independently
provisioned Registry writer and Repo observer Linux identities. It does
not launch subprocesses, change UID/GID, provision credentials or create
a checkpoint service. The caller must run it **in the actual host
process under that role's effective, real and registered UID/GID**,
with the pinned Linux PID, boot ID, scope and owner/Registry
runtime-layout profile from the previous offline modules. The code
validates its own `/proc/PID` state twice: all four UID/GID values,
supplementary groups, all five capability sets cleared, seccomp 2,
NoNewPrivs 1, tracer PID 0, actual process start ticks, namespace
and cgroup. Any privilege or profile drift is STOP.

It attempts exactly three OS open checks against the pre-registered
**owner checkpoint** SQLite state path: open the owner state parent
directory read-only, open the existing SQLite file read-only, and open
the file `O_RDWR` **without reading or writing any contents**.
The attempts use `O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK`, never
`O_CREAT`, `O_TRUNC`, `unlink`, `chmod`, `chown` or SQLite.
An opened descriptor is immediately closed and the observation fails
`REGISTRY_DENIAL_STORAGE_ACCESSIBLE`. Only kernel errors
`EACCES` or `EPERM` count as denial. `ENOENT`,
`ENOTDIR`, `ELOOP`, `EROFS`, `EISDIR` and any other
error are **not** proof of an inaccessible but healthy protected
owner store. A missing DB, symlink, wrong namespace or unprovisioned
path cannot masquerade as a successful access-control test. The probe
does not test network/service CAS policy, hard-link alternatives,
out-of-band host/backup access, elevated host administrators or
independent owner approval.

A second source-only function,
`compose_storage_denial_review(registry_observation,repo_observation,
...)`, requires both distinct-role candidate observations,
checks their canonical original digests, exact pinned enrollment/
instance/scope/boot/layout identity, denied operation set, unchanged
safe-failure flags and separate process PID, mount namespace and
cgroup. It is only a **structural review package**. Any actor with
source access can fabricate a matching JSON digest; no signed
trusted observer, original process attestation, challenge nonce,
WebAuthn verification or independent monotonic witness is supplied
by these source functions. The package always retains
`protectedAnchorVerified=false`, `hostIdentityVerified=false`,
`ownerAcceptanceVerified=false`, `enrollmentVerified=false`
and `admissionAllowed=false`. It never promotes the earlier
`OWNER_RUNTIME_ISOLATION_OBSERVATION_CANDIDATE`.

Before the first protected enrollment, an independently
authenticated **host owner** must actually run and retain the
original role-specific probes on the real provisioned UID/GID
principals, pin their process identity and verify that their
evidence was not substituted by Repo/AI. The host owner must also
prove protected owner checkpoint monotonicity, owner-only CAS
authorization, negative API access for Gateway/Publisher and
attested encrypted independent backup/restore, then perform a
separately authorized WebAuthn enrollment ceremony. Matching source
JSON alone never opens Registry WRITE.

The new module is explicitly excluded from current image inputs by
`release/targets.yaml::noDeploymentPaths`. The local tests use
synthetic separate principal observations and real non-mutating OS
open checks on disposable files; they do NOT claim any live cross-UID
owner volume has been provisioned. Negative tests cover accessible
files, missing/symlink paths, permission-vs-other error codes, exact
read/readwrite attempts, role spoofing, missing or replayed evidence,
scope and process drift and false admission flags.


### First protected enrollment exact-cutover preflight (offline candidate)

`registry/enrollment_cutover.py::inspect_first_enrollment` introduces
a **strictly source-only** preflight for the first enrolled
`AlexPastukhh/fortis-approvals` main SHA. It combines existing
candidate-only v2 Registry state, the separately provisioned local
owner checkpoint CAS ledger, an immutable baseline reference, a
current-main READ and the previously reviewed host isolation and
Registry/Repo denied-access observations. This is **not** a WebAuthn
ceremony, an authenticated host observation, an actual cutover
or a protected enrollment receipt. No host processes or DB
files are provisioned; no CAS, branch update, registry WRITE,
restore, credential activation or release is performed.

The exact baseline reader supplies only the original closed reference
(`schemaVersion, repository, enrollmentId, baselineSha,
catalogSha256, acceptanceReceiptDigest, bindingDigest`).
Its canonical hash must match the independently configured
Registry `baselineDigest`. The instance/scope, catalog raw SHA,
component binding digest, enrollment ID, baseline SHA and
owner checkpoint's enrollment receipt digest are bound to the
same original values. The reference is **not** automatically
accepted merely because it has a matching digest.

The current-main reader must return exactly `{repository, branch:
"main", sha}` for the selected immutable baseline SHA on both
reads. If main advances before or during the first cutover preflight,
STOP; do not silently rebaseline or skip intermediate PRs. The source
does not reconstruct pre-baseline PR history. The actual live
source read must eventually be authenticated and independently
pinned by the owner; the injected test reader is not a real GitHub
receipt.

The exact local `RegistryStateJournalV2` and its bound
`OfflineCheckpointCAS` must match the instance, enrolled scope,
original registered Registry journal path and exact owner checkpoint
reader. Both complete immutable journals are verified and **must
be at initial revision 0/genesis with no operations**, and the
candidate cursor must equal the baseline SHA. A preexisting,
pending, partially advanced or rolled-back history is STOP:
the first-enrollment constructor cannot be used to wipe, reseed,
reuse or supersede an already existing Registry enrollment.
Subsequent recovery requires a separate protected procedure.

The owner-peer profile and Linux runtime layout are validated by
their exact pinned digests and matched to both concrete DB paths,
instance, scope and pinned acceptance receipt digest. The supplied
host isolation candidate is re-assessed for correct process UID/GID,
all capability sets, distinct mounts/cgroups, private state ownership,
socket inode and false authority flags. Registry and Repo denied-access
candidate observations are checked against their exact pinned identity,
matching process start ticks, original role, scope and the three
required `EACCES/EPERM` outcomes. Altered or missing observations,
an accessible owner file, cross-role evidence substitution, a changed
peer/layout pin or an inconsistent kernel-process snapshot block.
The module rechecks both local immutable journals and the source/
profile references before returning.

An untrusted caller with Repo access can fabricate these host
observation JSON values, matching SHA-256, baseline/current-main
READs or even a local owner checkpoint SQLite file. Thus **even a
complete matching offline preflight cannot authenticate the original
host or confer owner approval**. The result is always
`FIRST_ENROLLMENT_CUTOVER_PREFLIGHT_CANDIDATE`, with
`originalHostEvidenceAuthenticated=false`,
`ownerAcceptanceVerified=false`,
`protectedCheckpointVerified=false`,
`runtimeActivated=false`, `enrollmentAllowed=false`,
`registryWriteAllowed=false` and `admissionAllowed=false`.

Before a real first enrollment the owner must establish and
independently verify the protected runtime/principals/volumes, collect
and attest original host evidence, authenticate source/main and
evidence retention, validate encrypted backup and recovery,
accept the immutable baseline and component/target policy, authorize
the exact owner operation through a separate WebAuthn ceremony
and verify the protected monotonic checkpoint on the **real** host.
An unchanged main SHA or complete post-baseline merge coverage
is mandatory at the moment of actual activation. These steps are
not performed by this module, by CI or by merging the PR.

Thirteen new offline negative and source-composition tests cover
genesis, exact main and acceptance/binding identity, pending and
already anchored data, unexpected local state, altered host process,
wrong owner/Registry path, changed owner/Repo denial observations,
reader drift and no-write readback. They do not constitute a real
separate-principal host E2E test.

### Accepted-peer fixed owner checkpoint READ adapter — source-only increment

`registry/owner_peer_boundary.py::read_accepted_checkpoint` is a
bounded **READ-only source adapter**, not a listener or an active
service. It accepts an already connected filesystem Unix stream
socket and reuses `observe_accepted_peer` to validate pinned host
profile, kernel SO_PEERCRED, exact instance/scope/enrollment, socket
inode and framing. It requires the exact `OfflineCheckpointCAS`
instance configured independently of caller data, and rechecks the
socket/profile/ledger binding after reading the ledger.

Only `checkpoint.get` (registry-reader or owner-operator) and
`checkpoint.original` (owner-operator only, exact operation UUID)
can return fixed checkpoint/original-receipt projections. Unknown
operations, forged actor/UID/path fields and `checkpoint.advance`
remain **DENY**. It does not bind/listen or send on a socket, create
host accounts, mount storage, alter the checkpoint, or accept an owner
decision. The response explicitly keeps `dispatchAllowed=false`,
`protectedAuthorityVerified=false`, `ownerAcceptanceVerified=false`
and `admissionAllowed=false`: successful candidate READ does **not**
mean a protected authority or trusted external monotonic witness.

Focused source tests verify real same-UID kernel denial and bounded
SQLite readback, missing/original operation, wrong role/ledger/pin,
changed socket permissions and closed mutation. Positive role tests
use an explicitly **injected observation seam**; they do not prove
cross-UID host isolation. No Registry runtime or WebAuthn ceremony
is activated. The next separate source/host work must establish an
owner-provisioned listener/process, authenticated owner acceptance,
independent non-rollback witness and negative multi-principal E2E,
without exposing `advance` by merely changing a flag.

## E1.3b kernel peer process identity candidate (2026-11-23; SOURCE-ONLY)

This addendum does not supersede historical numeric-PID `SO_PEERCRED`
diagnostic source described above. Owner-reported FORTIS_M sandbox proved
`SO_PEERCRED pid=0` between independent Docker PID namespaces while Linux
`SO_PEERPIDFD` returned a matching process inode from both sides and
signaled process exit. The new owner-fixed R7 profile **schema 2** selects
only a kernel pidfd inode and boot UUID verified against a **separately
owner-measured** Registry process, plus exact UID/GID, source/release nonce,
instance/scope and Unix socket device/inode. Numeric registry PID is not a
valid owner R7 profile v2. The existing Gateway candidate reader retains a
numeric-PID constructor for old offline tests only; it cannot be enabled by
this owner mount. The Registry listener separately checks a live kernel
pidfd, reader UID/GID and 02710/0660 socket access; cross-namespace PID=0
never grants access without those checks. Kernel 6.9+, 64-bit and explicit
SO_PEERPIDFD support are required; no compatibility fallback is allowed.

The source-only experiment and owner-reported test do **not** establish that
an owner verified and sealed the service process identity, or that a source
controller is installed. The current owner Check/Apply controller must still
explicitly review the added immutable Registry mount allowlist under
UC-GW-005. Until that, `E1.3b HOST_NOT_ACCEPTED`, `E1.4 NOT_LIVE` and
no machine grant or Registry WRITE. Future E2–E5 remain separately gated in
the **single** Registry roadmap, not here.

### E1.3b owner observation + two-volume admission source follow-up

The source-only, one-shot `registry/owner_candidate_pidfd_observation.py`
correlates a separately owner-selected Registry service PID (local to the
Registry namespace after independent Docker inspect/top and host↔namespace
PID reconciliation) with the kernel `SO_PEERPIDFD` of the **actual Unix socket**.
It validates `/proc` process security and fixed socket modes and inode, but
**never** treats output as an owner signature or automatically enrolls a
Registry. The exact two Gateway READONLY volume destinations are
`/run/r7-registry-reader` and `/run/fortis-registry-read` from fixed
named volumes, NOT the private Registry SQLite volume. `github_pilot_helpers`
now has source-only admission coverage of the exact pair, rejecting RW/bind,
unknown source/destination and shared/host PID namespace. The installed
Windows owner controller does not yet create this pair; no release is allowed.

**Non-obvious Check/Apply blocker:** protected owner Gateway release creates a
fresh random `releaseNonce` when constructing a new runtime. The owner-sealed
Registry v2 profile pins that nonce before R7 can start. Implementing a
protected **owner-chosen nonce** in the exact checked-image binding, and a
preflight of unmodified sealed profile bytes at both Check and Apply, requires
separate security review. Never replace nonce matching with a wildcard or
auto-rotate a seal using Registry-provided values. E1.3b remains STOP.

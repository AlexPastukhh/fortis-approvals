# P5 Registry typed preview / receipt boundary — source only

Status: **OFFLINE SOURCE CANDIDATE — NOT LIVE**.

Authority: the owner-merged [concrete D1–D7 source design in fortis-container
PR #41](https://github.com/AlexPastukhh/fortis-container/blob/6bf24812d5d32c5afd17e65afcdf8efbec9afd0c/docs/RELEASE-REGISTRY-P5-DESIGN.md#21-concrete-first-pilot-decision-proposal-2026-11-21).
This implements its first source increment, not acceptance of the remaining
operational/evidence gates. Existing [Gateway source evidence
contract](RELEASE-REGISTRY-P5-POST-MERGE-GATEWAY-CONTRACT.md) remains the
owner of upstream collection details. No change to the current Gateway or
Publisher routes, grants, credentials, images or owner release procedure.

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

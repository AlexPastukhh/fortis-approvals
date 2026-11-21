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

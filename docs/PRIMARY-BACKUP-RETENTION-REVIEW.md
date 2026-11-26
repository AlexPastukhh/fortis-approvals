# Primary Gateway backup retention — minimal policy proposal

Status: SOURCE REVIEW / NOT ACTIVE. This is a backup-volume lifecycle
proposal, not a new disaster-recovery system. Existing owner operations
and UC-GW-005/006/007/009/013 and UC-CONT-022 remain authoritative.
The dated inventory and decisions live in the container maintenance
handoff; no second inventory or retention database is needed.

## Retain operational dependencies

- Current Primary backup, bound by the protected backup pointer and exact
  source record path/hash, container, image, state volume and receipt.
- Previous Primary's verified backup(s), with the same identity binding.
  Until the existing emergency Promote contract changes, retain every
  matching record's volume; it verifies all such records.
- Additional exact dependencies of an active Check, unresolved release,
  incident hold or Registry/recovery reserve. Unknown or ambiguous
  provenance stays held. Keep source state, images, containers, protected
  pointers, Registry genesis and credentials outside this proposal.

This is a two-generation operational objective, not a hard limit of two
volumes. A new backup may coexist with both protected generations until
successful Promote and owner readback. No cleanup within Check/Apply/
Backup/Promote, after an incomplete release, or on inferred orphan status.

## Reuse existing checks

Backup already uses the stopped single-writer source, `Receipt`,
`State-Helper` clone, `Same-Json`, protected records and restart/readback.
Promote rechecks the backup's exact identity and receipt. Use those checks
and existing ACL admission, rather than another validator or record format.
The receipt describes a particular snapshot; it need not equal a later
live state. That difference matters if the owner intends to restore it,
not when assessing the historical snapshot's integrity.

Return before activation is the existing recovery path. After activation,
a previous image may not support the latest state; restoring older state
may lose later requests/receipts and cannot reverse GitHub effects.
Follow UC-GW-006 for recovery review. Do not invent a general rollback,
automatic replay or a new Restore action for retention.

The added test copies a synthetic backup into an empty isolated directory
after the source has changed, using only `clone_state` and `inspect_state`.
It proves the tested snapshot round-trip and preserves the newer source.
It does not prove runtime compatibility, production RESTORE_TESTED,
off-host recovery or authorization for any physical operation.

## Actual lifecycle constraint

`Assert-Emergency-Promote-Rescue` in Primary-Gateway.ps1 enumerates
primary-backup-* directories (limit 128), reads protected records, matches
the prior source path/hash and verifies every matching volume. A matching
record is not disposable just because a different backup has equal bytes.
An unrelated older source is not selected by that check; nevertheless,
its directory counts toward the scan limit. Do not loosen verification,
change historical records/pointers or treat missing volumes as success.

For future bounded retention, settle historical record lifetime explicitly
against this consumer and existing reference evidence. The current Check
binding hashes the backup pointer; it is not a permanent binding of the
exact historical backup record in the completed emergency release.
Changing that contract is not required for this source review, and would
need separate evidence and tests. The existing inventory of 18 volumes
does not establish the exact number of backup-record directories.

## Lifecycle decision (source review)

| Consumer | Actual dependency |
| --- | --- |
| Backup | Exact current source, stopped single writer, verified clone; publishes the new protected backup pointer |
| Ordinary Promote | Exact current backup pointer and bound record/receipt; retained predecessor runtime |
| Checked Apply | Exact checked binding, including current/Primary/attempt/backup pointer hashes |
| Emergency Check/Apply | Current source's verified backup and exact rescue evidence |
| Emergency Promote | Current backup plus every matching prior-source backup; original rescue evidence |
| Return / Registry handover | Original attempt and exact retained runtime/reserve; do not infer a backup from its age |
| Incident closure | Owner-attested backup identity in audit; retain pending separate disposition |

`Save-Checked-Image` records Ready and `auto-check.json` selects a record;
the controller does not remove that selection on successful Promote.
A historical Ready file alone is not proof of an outstanding Check.
Determine whether its exact binding is still applicable, and treat
ambiguity as a hold. No attempt may be replayed or modified for retention.

For the present scope retain protected records unchanged, do not expand
the emergency exception, and do not implement a new record store.
The previously audited older-source candidates are distinct from the
protected sources; the existing verifier does not select them merely
because they are historical records. This does not approve any removal.
A sustainable record-count policy remains open: verify the actual
directory count before deciding whether a controller change is needed.
Do not confuse the count of volumes with the count of records or increase
the scan limit without a reviewed reason.

## Next evidence, without another general audit

The earlier owner recovery handoff (2026-11-19) recorded metadata
provenance PASS but not an executed isolated restore. Its prepared
exercise pins a historical image and cannot serve as current acceptance.
Reuse the existing verification approach only under current owner-reviewed
identity and scope; do not create a second recovery tool. The 2026-11-26
backup receipt audit adds integrity evidence, not runtime recovery proof.

Owner PowerShell readback 2026-11-26: 36 immediate primary-backup-*
directories against the existing emergency Promote cap of 128 (92
additional directories before reaching the cap). No immediate cap issue;
do not modify the controller for this reason. Directory count is not
volume count or proof of recoverability. Retain the existing scan bound
and protected evidence. Recheck count during future maintenance rather
than invent a new record store.

Owner-reported bounded assurance exercise 2026-11-26: V2 isolated copy
of the exact current #273 Primary backup passed using its pinned image's
inspect_state/clone_state helpers. Source receipt, restored receipt and
Primary pointer/runtime readback PASS; production mutations NONE.
Host free 12.40 GiB before, 12.31 GiB after. V1 stopped before copying
because its old 128 KiB record bound was incompatible with actual
137772-byte current and 162437-byte backup records. V2 matches the
controller's 1 MiB UTF-8 release record budget. No live state mount or
Gateway stop. This confirms offline recovery of the tested snapshot,
not a running restored service, post-activation rollback, independent
off-host recovery, or authorization for maintenance. The previous
Primary and other reserves remain protected, not independently tested.

## Supported scope and remaining limitation

Use the existing owner release and maintenance contracts
(UC-GW-005/006 and UC-CONT-021/022/023); do not add another report parser,
receipt validator, database or release action. A saved report already
contains counts and observed reference statuses. Its aggregate summary
does not supply fresh evidence or an operational retention decision.

This source candidate records the recovery assurance and protection
policy and adds a snapshot round-trip regression in the existing suite.
It does not bound physical volume or record growth. An effectful
retention implementation is not available in this scope; do not mark
that work complete or bypass the maintenance authorization boundary.
Keep the physical lifecycle open while independently useful source
verification and release performance work proceed.

## Remaining decision

The dated handoff identifies 12 older-source candidates (~17.685 GB)
with no current operational references or holders found in the checked
scope, but a reference to an earlier inventory/evidence plan. A historical
inventory reference is not by itself a recovery dependency. Preserve that
evidence; do not equate it to an active hold or infer approval to retire
a backup. The prior report returned ready=0, and no candidate was retired.

Review actual operational references and recovery assurance under
UC-CONT-022 before any separate owner-authorized maintenance.
Revalidate relevant identities, receipts, holds and release state at that
boundary; use prior inventory as evidence, not as current authorization.
Do not require a general post-activation rollback implementation or
a restore drill for every historical candidate as a new policy.
No effect phase is implemented or authorized here. No production backups,
volumes, records, runtime or Windows configuration have changed.

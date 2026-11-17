# Protected Gateway release: audited append-only UNCERTAIN growth

**SOURCE CANDIDATE in PR #128; NOT YET INSTALLED ON WINDOWS.** This is
one reusable mode of the permanent owner controller, not an additional release
script or a bypass of Gateway authorization. Use [UC-GW-005](use-cases/releases.md#uc-gw-005)
to decide whether to release and [the primary owner runbook](PRIMARY-GATEWAY-OPERATIONS.md#lightweight-owner-release-path-pr4b)
for the exact Windows procedure.

## Standard interface and defaults

After acceptance and owner installation of this source, the normal interactive
Windows PowerShell 5.1 sequence is unchanged:

  Manage-Integrations.ps1 -Action SelfTest
  Manage-Integrations.ps1 -Action Check -Auto
  # Separate owner review/GO and fresh quiescence proof
  Manage-Integrations.ps1 -Action Apply -Auto
  # Live owner/machine verification before Backup/Promote
  Manage-Integrations.ps1 -Action Backup -Auto
  Manage-Integrations.ps1 -Action Promote -Auto

The controller internally enables safe audited UNCERTAIN growth on BOTH
Check -Auto and Apply -Auto; the owner does NOT pass the manual flag.
The -Auto argument validator deliberately rejects any explicit
-AllowUncertainGrowth and all manual preservation scopes. The checked-image
artifact and its immutable original source receipt/witness are required on
Apply. An older check artifact without a sealed witness is rejected: run a
new Check, never guess or modify the record. Only fresh UNCERTAIN entries
may be added; an old UNCERTAIN cannot be removed or silently reclassified.

For owner-reviewed manual exceptions, the EXISTING Check -Build -SourceSha
and the bound Apply -CheckedImageRecord -Image -SourceSha may both specify
-AllowUncertainGrowth, alongside exact approved/claimed scopes and separate
owner attestation. Omitting the flag on manual Check/Apply retains the
prior strict equality rule. -Auto cannot first enable a Publisher mount,
owner-shell integration or unrelated API grants.

## Single invariant implemented by the reusable helper

At Check, the offline read-only non-networked image helper captures an exact
full state receipt, the current bounded UNCERTAIN IDs and a protected digest
of the existing Core SQL rows/events plus the complete SQLite schema. At
Apply, including after stopping the original source, it accepts only fresh
UNCERTAIN request IDs with their own audited final UNCERTAIN status.
The previous request/event rows, all other state files, native worker data,
provider receipts, owner config, image/source identity and approved/claimed
scopes must remain unchanged.

It NEVER closes, retries, executes or resolves an UNCERTAIN; it admits no
unreviewed APPROVED, PENDING or DISPATCHED request or new CLAIMED worker.
The total unknown-ID bound (20) still applies. Any incomplete inventory,
changed old SQL row/event, altered schema, changed non-Core state file,
missing rollback image or unconfirmed quiescence is a STOP. New UNKNOWN
accompanied by changes to a provider receipt or native worker journal is
NOT permitted in this narrow initial implementation.

The final snapshot is checked again after the source is stopped; its
complete exact set is frozen into the candidate's owner-protected record,
copied byte-for-byte and compared with the source. The original Check
artifact is never rewritten, and the original Gateway remains available
for guarded return if a later step fails.

## Ownership, routing and status

Implementation owners (single code path, no second coordinator):
- Windows release controller: fortis_approvals/deploy/Manage-Integrations.ps1
- Reusable read-only verifier/clone: fortis_approvals/deploy/github_pilot_helpers.py
- Tests: fortis_approvals/tests/test_release_uncertain_growth.py,
  test_release_auto_owner.py and test_release_uncertain_growth_source.py.

UC-GW-005 owns the release decision; UC-GW-006 owns return after an
ambiguous attempt; UC-GW-009 owns UNCERTAIN investigation; UC-CONT-002/003
own Docker-to-GitHub/CI/Windows delivery and authorized GitHub operations.
The common cross-project workflow is deliberately NOT duplicated here.

Merge/CI alone do not install this source. Owner-controlled Windows Mirror
source acceptance, Windows PowerShell 5.1 SelfTest, actual Docker/image
admission, independent quiescence evidence, protected Check/Apply, Backup,
Promote and host readback remain mandatory.

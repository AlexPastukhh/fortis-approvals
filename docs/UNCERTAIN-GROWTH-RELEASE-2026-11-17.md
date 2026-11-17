# Manual protected release: append-only UNCERTAIN drift

**SOURCE CANDIDATE; NOT INSTALLED.**

The owner may explicitly allow *newly appended* UNCERTAIN requests to be
preserved between exact-image Check and Apply without rebuilding repeatedly.
This does not remove, dismiss, close, reconcile or retry any historical item.

## Admission and owner authority

The mode is disabled by default. First use requires manual, exact-SHA
Check with Build and AllowUncertainGrowth; owner-confirmed worker quiescence,
private config/probes and exact separate approved/claimed scopes remain
mandatory. Then run manual Apply with the same checked-image record, image
ID, SHA and AllowUncertainGrowth flag. Auto is NOT permitted for initial
or later opt-in with this flag.

At Check, the offline, read-only, network-disabled helper takes the full
exact state receipt and seals an immutable Core SQL prefix witness in the
owner-protected checked-image record. No new credentials or permissions.

At Apply, the helper validates the sealed witness before each receipt and
again after stopping the source. It admits only fresh request IDs added
after the witness with final state UNCERTAIN and matching appended audit
records. All earlier requests and events must remain unchanged.
## What remains an immediate STOP

Any changed/deleted old Core row or event, new PENDING/APPROVED/DISPATCHED,
new or changed CLAIMED job, any changed non-Core state file (including
GitHub/Sonar receipts and native worker journal), missing previous image,
changed approved/claimed scope, incomplete state evidence or unknown source
ownership remains a hard STOP. The current cap of 20 UNCERTAIN IDs
continues to apply.

Not every new UNCERTAIN can be admitted: a new uncertain request that
also changed a native worker journal or provider receipt is deliberately
not considered append-only. This is a narrow mitigation, not a blanket
skip for all concurrent Gateway activity.

After the original Gateway has stopped, the updated complete unknown
scope is stored in the new candidate's protected runtime record,
then clone_state must prove byte-for-byte equality and source immutability.
The original immutable Check record is never changed or reauthorized.
No wildcard is permitted in ordinary inspect/clone.

## Release workflow and status

Use existing owner-controlled Check -> separately approved Apply ->
live readback -> Backup -> Promote -> independent Docker inspect.
Windows PowerShell 5.1 parse/SelfTest and production-host checks remain
mandatory before any real use. The Publisher mount/grant/isolated runner
and live PR #118 pilot have separate owner gates.

This change is only source for review and has not built an image or
changed the running Gateway. See UC-GW-005, UC-GW-009 and
PRIMARY-GATEWAY-OPERATIONS.md.

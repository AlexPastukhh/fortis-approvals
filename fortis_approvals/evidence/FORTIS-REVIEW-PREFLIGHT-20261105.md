# Modularized review preparation — 2026-11-05

## Host observations supplied by owner

Read-only audit timestamp: 2026-11-05T13:11:46Z. The pasted JSON ends during
the final ACL entry, so it is not a complete machine-readable receipt.

- Production `fortis-approvals-gateway` is running/healthy, image
  `sha256:e751f6ca0cfe6ce290cf580de2f243071ee1f3e681baa8827c6cea41a16fa402`.
  Loopback ports are 19103/19104. State is `fortis-r7-state` RW; identity,
  grant and Sonar-token volumes are RO. User is 10001:10001; rootfs is RO.
- Existing modularized image is
  `sha256:a2fd23c3def0609ed254cd796f40fb51cc4a5a103f0486bb0052d44d76b23267`,
  revision `3355941a4c7836beac32bc27a0730a7a0e0a45ec`.
- Old clone `fortis-gateway-state-clone-20261105` is exited/unhealthy.
  Its state volume remains present; database contents have not been inspected.
- New review container, review-origin image and review-state volume are absent.
- Backup manifest SHA-256 matches the handoff pin
  `0b783913f0465ab9fb8fc098953ae0b74070cc6f8e854845258390486f7078dd`.
  All four marker/database file hashes match the manifest.
- Manifest records 3 EXECUTED + 3 REJECTED requests, 18 events, 3 Sonar
  receipts, 1 total/active credential and 1 invitation. It records integrity
  `ok` for the three databases and owner binding PASS. This audit did not
  rerun SQLite integrity or inspect credential material.
- Complete visible ACL entries for the directory, manifest, marker,
  approvals.sqlite and owner.sqlite are protected from inheritance and grant
  FullControl only to the owner, SYSTEM and Administrators. The receipts ACL
  is truncated; a blanket ACL PASS is not claimed.

## Source changes and validation

Worktree: `/workspace/repo/Worktrees/fortis-approvals/candidate-origin-overrides-20261105`.
Base commit: `7963581eeae50f583df5c9f4caab46df5071b72a`. These follow-up edits
are an uncommitted review snapshot, not published GitHub source.

The earlier TLS tests connected to an ephemeral local listener while the
server expected the production Host. They now keep the advertised Host
consistent with that server. A separate real TLS test proves that review
Host 19204 is accepted and production Host 19104 is rejected by the review
composition. Host enforcement was not relaxed.

Restore verifies the pinned manifest and actual database counts, then copies
into an empty target and changes only its Owner Origin. All credential and
invitation rows remain equal, and approvals/receipts bytes remain equal to
the backup. chmod occurs before chown; the isolated helper retains CHOWN and
DAC_OVERRIDE but does not require FOWNER. No existing volume is adopted or
removed. Failure leaves the new target for inspection.

Validation in the existing WebAuthn test venv: 259 offline tests passed,
including 7 restore tests. A synthetic existing credential logs in at Origin
19203 after migration and is rejected at the old Origin. This is not proof
that the owner's physical authenticator has logged in to the candidate.
The installed-module packaging test also executes the image smoke against an
isolated copy of exactly the Dockerfile COPY allowlist. Source manifests and
whitespace checks are verified separately.

## Next host step: image only

Run `Run-Modularized-Review-ImageOnly-20261105.ps1` from the SHA-256-verified
source snapshot. It tests the existing image, builds the Origin candidate,
tests that image and validates alternate endpoint configuration. Check
native exit codes; expected final marker is
`FORTIS_REVIEW_IMAGE_ONLY_CHECKS_PASS`. No helper mounts runtime state or
credentials, exposes ports, restores backup or starts the Gateway.

Windows PowerShell parsing, actual image pip/import/offline smoke results,
restore with real ownership/capabilities, browser Origin, physical WebAuthn
login, review history and review live Sonar GET remain pending host evidence.
Production cutover is not authorized by this snapshot.

## Owner-supplied image-only result

The owner supplied the completed image-only wrapper output in this session:

- New image: `sha256:a6d3cbc645903fc3a36698868790ea1e191d73d1e9d5c01f7cecc97697c56e84`.
- Source snapshot: `3a0d8f99f11a2f27dd1467593e1ac37ce452a183c19c7abf685643e1727b6d14`.
- Base commit: `7963581eeae50f583df5c9f4caab46df5071b72a`.
- New image pip check: no broken requirements. The pip cache warning concerns
  an unwritable home cache; pip disabled the cache and the check succeeded.
- Server import preflight, offline synthetic Sonar GET, GitHub imports,
  GitHub-unregistered check and alternate endpoint configuration passed.
- Final wrapper marker `FORTIS_REVIEW_IMAGE_ONLY_CHECKS_PASS` was emitted.
  The wrapper runs the old image checks first; their individual output is not
  in the excerpt, while completion of that sequence is reported by the wrapper.
- Production container ID and start time were unchanged. No runtime state or
  credential volumes were mounted by the smoke checks; no Gateway was started
  and no state was restored.

These are owner-supplied host results, not direct Docker Engine inspection
from Fortis Repo. The full transcript remains on the owner's Windows machine.

## Next host step: restore and verify only

`Restore-R7-State-Backup-To-ModularizedReview-20261105.ps1` now pins the tested
image ID and source snapshot. Before creating the new review-state volume,
it checks Production, image metadata, all seven backup ACLs (by SID), the
pinned manifest and backup file hashes. It does not repair ACLs. Allow entries
must be limited to the current owner, SYSTEM and local Administrators.

The root helper mounts only the new review-state volume RW and backup RO.
A second helper runs as 10001:10001 with all capabilities dropped and the
new volume RO; it mounts neither backup nor credentials. It verifies the
restored hashes, database integrity, counts, binding, UID/GID and modes.
The source backup and Production container baseline are rechecked afterward.
Any error stops the sequence, retaining a newly created volume for inspection.
Existing clone volumes are never mounted, removed or reused.

Nine targeted synthetic restore/verifier tests pass. Actual Windows ACL,
Linux capabilities/ownership and real-data restore still require this host
step. Expected final marker: `FORTIS_R7_REVIEW_STATE_VOLUME_READY`.
Gateway startup, published review ports and physical WebAuthn login remain
separate subsequent checks; this restore script does not start the Gateway.

## Owner-supplied restore and runtime-UID verification

The owner supplied the complete restore output for the three-file restore
bundle SHA-256 `bfee217b108d534845ddcaa8fc804fe12bdde3133f1951e0ebc2d9e53e5ab092`.

- All seven backup ACL paths passed the SID-based check.
- Manifest and backup bytes stayed unchanged; Production container baseline
  and the older clone volume stayed unchanged.
- The new `fortis-r7-state-review-20261105` contains 6 requests (3 EXECUTED,
  3 REJECTED), 18 events, 3 receipts, 1 active credential.
- Origin is `http://localhost:19203`; RP ID is `localhost`. All credential
  and invitation rows were preserved by the root restore helper.
- Review owner.sqlite SHA-256 is
  `497a6985fb3af7338f4260beac97739ead8cbfe94a724914372421efbf7027cd`.
  Approvals and receipt database hashes match the original backup.
- The independent helper ran as UID/GID 10001:10001 with the new volume RO:
  all hashes, permissions, counts and integrity of all three databases passed.
- Final marker `FORTIS_R7_REVIEW_STATE_VOLUME_READY` was emitted. No review
  Gateway was started and no ports were published by the restore sequence.

## Prepared start and safe read step

The revised Start script uses `docker create` with the tested immutable image
ID. It inspects/admit-checks the created container before `docker start`,
using `review_runtime_contract.py`. It never invokes Compose up/down and does
not reuse or replace an existing candidate. A failed new container remains for
inspection. The dated Compose file is only a reference configuration.

Before creation it checks the restored state against the owner-supplied
receipt as UID 10001 with the state volume RO. Admission checks require only
the review state RW, the three credentials RO, exact localhost endpoints,
loopback ports 19203/19204, dropped capabilities, RO rootfs and resource bounds.
Admission runs again after the container reaches healthy. The Owner root
page is then checked with Host localhost:19203 (not a WebAuthn Origin test).

The typed Repo client then makes one Sonar Quality Gate GET through 19204,
after verifying 55 runtime Python files against the built snapshot. Production
container identity, start time, image, mounts, ports and health are checked
before and after. No ASK, owner decision or Sonar mutation is created.
The live call and the startup still need the owner's host execution result.

267 offline tests passed in the existing test venv, including four admission
checks with rejected unsafe inspect mutations and two mocked Repo GET checks.
These are source tests; they are not evidence of a live review GET or physical
WebAuthn login. The latter must use the existing credential at port 19203
in a separate InPrivate browser session, without a new enrollment.

## First start attempt stopped at port preflight

The owner ran start/read bundle r1 (archive SHA-256
`40c68b940a8ef1bbe04c13a74819dcfdb76ce7096ef20c4eb326d00b6d71b66a`).
It stopped with `REVIEW_PORT_RESERVED_BY_DOCKER_CONTAINER:19203` before the
state probe, docker create, or docker start. This script therefore made no
review container/state changes. The owner did not supply the matching Docker
container name or inspect data, so actual port ownership is not established.
No owner browser login, review history or live review GET is proven yet.

The r2 preflight replaces the publish-filter-only gate with read-only inspect
of every container's exact HostConfig.PortBindings and status. Matching TCP
host ports are logged with names and states. Running/restarting/paused or
unknown states block; configured ports on created/exited containers are
reported without starting, stopping or deleting those containers. A separate
Windows active-TCP-listener check still blocks occupied ports and prints the
endpoints. This does not bypass a live port conflict.

Nine admission/port tests and four candidate packaging tests passed after
this change. Coverage includes an internal-port match with a different host
port, stopped configurations, active states, UDP separation and Production
ports 19103/19104. Actual host ownership still requires the r2 output.
The new artifact does not restore or rebuild anything; it keeps the already
verified review-state volume and immutable image pin.

## Second start attempt identified the active blocker

Owner-supplied r2 output identifies running
`fortis-gateway-candidate-smoke-r3-20261105` with loopback host ports
19203/19204 mapped to internal 19103/19104. An older
`fortis-gateway-candidate-smoke-20261105` is exited with the same configured
ports. The running r3 instance is a real conflict; the start preflight
correctly stopped before state probing or review creation.

The follow-up release/start entrypoint admits stopping only that exact r3
name and inspected container ID, with a known candidate image and standard
Gateway command/user. Its state must be a separately named dated test volume;
Production state and the verified review volume are forbidden. Its three
known credential volumes must be RO. Host bind/device/PID access and automatic
container removal are denied. Volume driver/options and Mountpoint are checked
to avoid accepting a named alias to another state directory.

If admitted, the operator-run script stops that ID without removing anything,
checks the retained container and each volume identity, rechecks Production,
and invokes the previously prepared review start/read sequence. Unknown
configuration causes an observation-only stop. No automatic cleanup, state
restore, rebuild or Production cutover is performed. The old smoke state must
remain available for later inspection; its history is not presumed empty.

Eleven targeted admission/port tests pass, including rejection of Production
and review state, unknown images, writable credentials and automatic removal.
The actual r3 image/mounts and stop/start outcome still require host evidence.

## Observed r3 shell entrypoint and missing persistent state mount

Owner ran release/start r1 (archive SHA-256
`f15fc5e78c4a64214383bcd71fecf0f4edcb5be5fd36f5c081ff237df6949a30`).
It failed admission before any stop or start with SMOKE_BLOCKER_PROCESS_UNKNOWN.

The public inspect identifies exact r3 container
`d35f999783872ed11225b52fffee534f93777dcd757b326044aa2521dc7bd1f3`,
image `sha256:a2fd23c3def0609ed254cd796f40fb51cc4a5a103f0486bb0052d44d76b23267`,
user 10001:10001, RO rootfs, not privileged, no automatic removal, running/healthy.
It has only the three known credential volumes RO; no state volume is shown.
Its observed command is shell `mkdir -m 700 /state/private && exec python -m
fortis_approvals.r7_unified_server`. HostConfig.Tmpfs was omitted by r1, so
state persistence and counts were not proven. Do not assume empty state.

Release/start r2 now includes HostConfig.Tmpfs and uses a separate admission
helper for this exact observed ID/image/shell command. It requires /state to
be tmpfs with no extra state volume or host mounts. It executes only a
read-only SQLite count/integrity probe inside r3, with no credential-row output.
Unknown files, journals, schemas, binding, identity, permissions or changes
during the read stop the sequence. Requests, events, event sequence rows,
receipts, credentials (total/active) and invitations must all be zero before
r3 can be stopped. Any nonzero count leaves it running pending a separate
protected backup. The already restored review state is never re-restored.

If admitted, only the exact r3 container ID is stopped. Its confirmed empty
volatile state disappears; the stopped container and its three named credential
volumes are retained. Then the same pinned review start/read sequence runs.
Four synthetic tmpfs/probe tests and four candidate packaging checks passed.
Actual tmpfs configuration, empty-state proof and subsequent stop/start still
require owner host evidence; no success is claimed from these source tests.

## r3 is not empty; protected snapshot is required before stopping

Owner-supplied release/start r2 output confirmed /state is a 64 MiB tmpfs
owned by 10001:10001, and /tmp is a separate 16 MiB tmpfs. The read-only probe
passed integrity/stable-read checks and found: 1 request, 1 event, 1 event
sequence row, 0 receipts, 0 total/active credentials and 0 invitations. Owner
Origin is still 19103. The empty-state guard correctly stopped with
R3_STATE_NOT_PROVEN_EMPTY_DO_NOT_STOP. No container was stopped or created.
The state of the single request was not printed and must not be presumed.

The next entrypoint `Backup-R3-Locked-And-Start-Review-20261105.ps1` preserves
that separate test history before freeing the ports. It creates a new
owner/SYSTEM/Administrators-only Windows directory under LocalAppData Fortis
Backups, named R3-pre-stop-20261105-<unique GUID>. It never modifies the pinned
Production backup or the six-request restored review volume.

An exporter executed only in the exact inspected r3 ID acquires and retains
read transactions on all three DELETE-journal SQLite databases. It creates
SQLite backup snapshots and verifies full logical-content hashes against the
locked source, plus integrity and source counts. The snapshots, marker and
manifest are streamed privately through redirected Docker exec stdout to a
flushed Windows snapshot.zip. No database bytes go to the console, transcript,
Fortis Repo filesystem or Git. The new backup's ACL, ZIP/file hashes, logical
hashes, binding and counts are independently checked through a RO bind mount.

Only after backup verification and a live lock-lease acknowledgement with at
least 60 seconds remaining can the script stop the exact r3 ID (20-second
stop timeout). The snapshot helper then terminates with the container; a
nonzero exporter exit at that point is expected and separately labelled.
On earlier backup/verification failure it releases locks and leaves r3
running; the partial protected backup is retained for diagnosis. A lock lease
also expires after five minutes if the controller is lost. The existing
container and three named credential volumes remain present after a stop.

Then the established review launcher runs; the extra smoke request stays in
its own protected backup and is not merged into the six Production-derived
review requests. Cutover and live Sonar mutation remain outside this step.

282 offline tests passed, including the cross-process private-frame protocol,
write blocking during snapshot/verification, release on command, preservation
of requests/credentials/invitations/receipts, and rejection of tampered copies.
Windows .NET process/ACL execution, actual r3 snapshot and review startup/GET
are still pending owner host evidence.

## Owner-confirmed protected r3 backup, review startup and live GET

Owner supplied the completed backup/start transcript for artifact SHA-256
`4c34688ee3e244a9cc85d877cf12b5c6d04e922cc54d9ed2c75c1cfecc7cddd1`.

The r3 backup was created at
`C:\Users\alexa\AppData\Local\Fortis\Backups\R3-pre-stop-20261105-97af97ad8622446e9a926c5005b9e8e0`.
Archive SHA-256:
`434c3a2c54d2d041ca2c9fe7d8ece4458e4c245e183fb1fa4f17fb672cf1b509`.
Manifest SHA-256:
`7a6be58006592db45130dd55eaa34ea8153f5a4e74a35edef29b2293fd698637`.
The independent backup verification passed all three integrity checks and
full logical-content hashes. Its separate history contains 1 PENDING request,
1 event, 0 receipts, 0 credentials and 0 invitations; Origin remains 19103.
The exporter acknowledged its source read locks before the exact r3 ID was
stopped. Exporter exit 137 was expected after the container stop. The old
container and all named credential volumes were retained. Do not delete or
overwrite this backup or confuse it with the six-request Production backup.

Review container name: `fortis-gateway-modularized-review-20261105`.
Container ID: `dd90f5a3d2fcda35d02339cc154f027c67f60d12033bec573809f00834757109`.
Image ID: `sha256:a6d3cbc645903fc3a36698868790ea1e191d73d1e9d5c01f7cecc97697c56e84`.
State volume: `fortis-r7-state-review-20261105` RW. The three credential
volumes are RO. Prestart verification as 10001:10001 passed hashes,
permissions, all database integrity checks, 6 requests (3 EXECUTED + 3
REJECTED), 18 events, 3 receipts and 1 active preserved WebAuthn credential.
Owner Origin is 19203 and RP ID localhost.

Admission of both created and running/healthy configurations passed. The
Owner root page returned HTTP 200 at localhost:19203. This proves Host routing,
not physical WebAuthn login or browser Origin acceptance of a signed assertion.

The live typed Sonar quality-gate read through
`https://host.docker.internal:19204` returned OK. Request ID:
`bfa00c23-c792-49e3-b550-f012d28247d8`. No Sonar write was performed.
Final markers FORTIS_REVIEW_START_AND_READ_CHECKS_PASS and
FORTIS_SMOKE_RELEASE_AND_REVIEW_START_PASS were emitted. Production container
baseline remained unchanged; cutover was not performed.

Remaining gates: owner's physical WebAuthn login at 19203, browser History
review and further authorized Gateway functional checks; then finalize Git
source review/commit/push and a separately approved cutover plan with final
backup and rollback. GitHub remains unregistered with no Gateway token volume.
No scripts should be rerun merely to reproduce this already confirmed startup.

## Owner browser login and restored History confirmed

The owner reported successful login (message: вошел) after being directed to
the isolated 19203 portal using the existing WebAuthn device. The attached
portal screenshot shows Вход подтверждён and six History entries: 3 EXECUTED
and 3 REJECTED. Its image does not include the browser address bar, so port
attribution is the owner's session context, not independently visible URL
proof. No new credential enrollment was requested or reported.

## Final review ASK/Reject functional check — pending owner decision

Direct Repo typed client on 19204 successfully listed issues, request
`466eb348-e28d-4f7d-ab3b-2b71f175f356`. Issue
`AaGC4d9TJxEkuf26a_ZX` is OPEN and was selected for a reject-only check.
A fresh exact Issue GET confirmed OPEN before submission. One ASK request was
created in the review Core, not Production:
`4202bc09-dc0e-4fb3-b1ab-018d8c999d0d`, state PENDING.
Its explicit reason requests only REJECT and says Sonar execution is outside
this test. No live Sonar mutation is authorized. The stable request ID was
written to `review-reject-test-20261105.json` before submission; do not create
a duplicate on retry. After owner rejection, re-read this request and the
Issue to prove REJECTED and OPEN. The six restored History records are kept;
this new review-only record will make seven after rejection.

Fresh Git remote read showed only main at e7baf76 and bootstrap at 3355941;
primary main is clean, and the candidate task worktree remains on its own
branch with the prepared changes. The candidate branch is not yet published.

## Reject-only check completed

The owner reported rejecting the review-only request. A direct typed Repo
status read through 19204 returned REJECTED for
`4202bc09-dc0e-4fb3-b1ab-018d8c999d0d`. A subsequent exact Issue GET returned
OPEN for `AaGC4d9TJxEkuf26a_ZX`, readback request
`51b8208e-da0c-4f77-8907-653972a25d50`. The public evidence record is
`review-reject-test-20261105.json`. No live Approve or Sonar mutation was
requested. The six restored history records remain separate from this one
new review test record (expected History: 3 EXECUTED + 4 REJECTED).

The review acceptance now covers image imports/pip/offline smoke, verified
backup/restore/ACL/UID permissions, existing owner credential login, restored
History, live typed Sonar READ, ASK creation and owner Reject with machine
status/readback. Live Approve-to-Sonar-write on the new image was not tested;
its execution path has offline coverage and prior Production evidence only.
GitHub remains source-present/default-disabled. These boundaries must be
preserved in any release decision; this is not a Production cutover GO.

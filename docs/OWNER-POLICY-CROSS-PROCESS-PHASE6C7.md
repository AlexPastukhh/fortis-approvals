# Phase 6C.7 — shared SQLite multi-process test evidence and rollback STOP

**2026-11-20: SOURCE-ONLY OFFLINE TEST HARNESS, NOT HOST ATTESTATION, NOT A RELEASE.** Phase 6C.6 is owner-merged source in PR #176. The owner explicitly deferred the independent monotonic/immutable history service for the local DENY-only MVP. This test stage does not reintroduce that service or claim that restore/rollback is protected.

## What the independent process tests cover

`fortis_approvals/tests/test_owner_policy_cross_process_phase6c7.py` uses Python `spawn` to construct genuinely independent `LocalDenyCore` instances, each with its own SQLite connection and in-process state. A parent owner-side test fixture performs a target-exact DENY on one shared Core SQLite database through the Phase 6C.6 WebAuthn **synthetic** source-only state machine. The child processes are not the actual owner host, do not use a real provider credential or network, and do not perform production policy changes.

1. Two processes instantiated **before** the owner change and pointing at the **same** SQLite path observe the new policy revision, reject the exact target, and retain ASK for an unrelated target.
2. An ASK request PENDING in the other process before the DENY cannot be approved using the old revision. An already APPROVED request becomes STALE instead of DISPATCHED. No provider effect is performed.
3. A child holding SQLite `BEGIN IMMEDIATE` prevents the owner's local CAS commit from completing until the lock releases. This demonstrates synchronization across separate processes sharing the same **local SQLite file**, not distributed host fencing.
4. Changing the policy metadata gate to PREPARED makes an **already-running** other process refuse both read evaluation and new submissions. Restoring READY in the test resumes the previous configured ASK.
5. Terminating a separate process while its write transaction contains an **uncommitted** DENY+revision increment rolls the partial update back; the parent still sees unchanged ASK and no local events. This is an offline fault-injection fixture, not owner recovery.
6. **Counterexample: split database paths.** If two processes use separate SQLite files, a DENY in one does not protect the other. It can still submit ASK requests. Therefore a list of all installed worker processes and their exact shared state/volume identities is mandatory before rollout.
7. **Counterexample: restored old database.** Replacing the protected file with an offline copy taken before the change restores revision 0 and ASK, and removes the local audit entry. The current same-DB revision mechanism cannot detect this: a separate independent anti-rollback witness was explicitly deferred by the owner. An owner-accepted backup/restore and old-image risk plan is a hard release STOP.
8. **Counterexample: unguarded legacy Core.** A directly instantiated plain Core on the same DB still ignores local DENY. Phase 6C.5 prevents only new legacy *R7 builder* launches with matching source; it cannot terminate a previously running plain Core or detect one under an old binary.

## Trust and release boundary

All tests are **synthetic** and do not use a real passkey. The existing real VirtualKey FIDO2/UV/RP tests from prior phases remain required in exact-head GitHub Source CI. No test result here proves that the owner-host deployment has only one shared SQLite, that every worker uses the expected source/image/credential generation, that the host has no old running process, or that a backup cannot restore a former permission. A different Docker volume, a prior image, a cross-host copy and a process that does not use this Core remain unaddressed.

For any production activation the owner must independently inventory the running containers, process classes, image digests, exact state mounts and all machine ingress/worker paths; verify quiescence and safe in-flight PENDING/APPROVED/DISPATCHED/UNCERTAIN/CLAIMED handling; test restore/cutover under owner control and explicitly accept the lack of anti-rollback; and then separately authorize a release with negative live probes. **None of that host inspection or activation is performed in this PR.** No dashboard Save/Apply button, runtime selector, Dockerfile, Windows Executor, permanent policy service, owner credential, grant or live SQLite volume changes are made.

Source CI and checked source manifests do not substitute for these owner-only controls. This test harness is evidence of **limited local process behavior and remaining failure modes**, not clearance to remove any STOP.

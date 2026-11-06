# Native Git/worktree offline acceptance — 2026-11-06

Source candidate only. No native GitHub live PASS, new container build/start, Production lifecycle change, connector call or legacy Git credential helper publication is claimed.

## Verified

- Full scripts/test-source.sh: 340 tests, 33 suites, exit 0.
- Additional final sync_task regression: 1 test, exit 0. This covers ordinary upstream-main synchronization through Gateway bundles and fail-closed handling of configured external merge drivers.
- Final uncertain-resume regression: no new local effect after UNCERTAIN, receipt reconciliation only.
- Final complete native suite rerun: all 13 cases passed after the claim-state and uncertain-resume guards.
- Total final source test cases: 342. The native file contains 13 cases (11 in the full run, final sync and uncertain-resume cases separately).
- Real local Git repositories and bare upstream fixture, actual HTTP/TLS Gateway, shared Core and cryptographic WebAuthn ceremonies: fetch/create/edit/stage/commit/native push/PR/ready/CI gate/merge/main fast-forward/approved cleanup.
- Exact local/upstream commit SHA; binary contents, deletions and executable mode preserved; old configured credential-helper sentinel never ran.
- Ordinary push ALLOW, sensitive workflow-history push ASK, UV required, rejection preserves upstream; reverted intermediate workflow change still requires ASK.
- Wrong remote SHA, concurrent remote update, divergent history and main/ref spoof blocked. Ambiguous publication is UNCERTAIN, repeated UUID does not repeat the push. Local repeated commit UUID creates one commit.
- Fake/unregistered worktree and stale workspace digest blocked; failed CI cannot create a merge proposal.
- Fixed mark-ready GraphQL transport route/body/result validation, default native opt-in and required workflow configuration, and exact native deployment admission tested.
- PowerShell 7 parser passed for all deploy scripts on Linux.
- Platform-independent FilePR/CI/native admission and return self-tests: 27 cases, exit 0 under PowerShell 7 on Linux, including retained-M3 return and replay. This does not replace PowerShell 5.1/NTFS checks.
- git diff --check clean. Source manifests refreshed and checked before packaging.

## Reproducibility

Private transient dependency cache/venv in Workfiles uses exact requirements-owner.txt dependency versions, official PyPI wheel hashes verified before extraction. It is not packaged as source.

Operator-local logs (not committed or packaged):
- Workfiles/fortis-native-git-regression-20261106-r2.log
- Workfiles/fortis-native-git-sync-20261106-r1.log
- Workfiles/fortis-native-git-final-20261106-r1.log

Full regression initially exposed an isolated image-copy test dependency-environment issue; it was rerun with the actual pinned venv and passed. Native tests exposed an ASK worker-wait bug, which was fixed and passed in the full sequence. No test was disabled.

## Remaining owner/live checks

The owner bootstrap package runs PowerShell 5.1 self-tests before lifecycle changes, builds the exact packaged source image, runs its network-disabled smoke, preserves M3 and verifies ordinary Sonar/Production baseline. Its READY marker explicitly has liveNativeCycleVerified=false.

After readiness, all source publication and live acceptance requests must use the new Gateway. Source GitHub CI and the owner-reviewed PR/merge are still required; local upstream fixtures do not substitute for them. See docs/NATIVE-WORKTREE-GATEWAY-2026-11-06.md for policy, commands, bootstrap exception and limits.

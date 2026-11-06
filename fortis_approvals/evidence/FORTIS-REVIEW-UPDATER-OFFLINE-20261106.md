# Windows review updater — evidence, 2026-11-06

SOURCE-VERIFIED: bounded owner-run entrypoint
[`Update-NativeReview.ps1`](../deploy/Update-NativeReview.ps1), based on the
accepted pilot state clone, runtime admission and private Windows record
helpers. The state helper now adds an explicit native profile while retaining
strict legacy behavior. Protected historical worktrees/records are unchanged.
New arrays are explicitly enumerated at the `ConvertFrom-Json` boundary for PowerShell 5.1.

Targeted offline checks after the native-state correction: 37 tests passed
(6 updater config/embedded-code/package checks, 7 real native-layout preservation
and denial regressions, 14 legacy state/admission/scenario regressions and
10 image/storage source gates). They cover exact
config owner/project, malformed/duplicate/extra fields and workflow paths,
stopped state cloning and rejection, preservation, admitted mounts/security
and unhealthy-return admission. They do not simulate Docker or Windows.

OWNER-REPORTED: the image identified in [current state](../../docs/guides/FORTIS-APPROVALS-SECURE-DEVELOPMENT.md)
passed the owner's network-disabled smoke, including analysis-review imports.
The first attempt with `python -I` omitted `/opt/fortis` from `sys.path` and
failed `ModuleNotFoundError`; the corrected stdin prefix passed all markers.
The updater includes that prefix and uses base64 code transport, not native
quoting of multiline Python/JSON.

OWNER-REPORTED first attempt: standalone source `03730380129694eb5a71051ad4f12122c2b0e5c1`,
file SHA256 `f2e8e54b5b855bf2d2d01cf69f0e3ffc2bd260981f5dbbd8cb1ff2fb31f27dc6`.
PowerShell reached stopped-state inspection, then failed with
`PILOT_SOURCE_UNKNOWN_FILES_OR_JOURNAL` and printed
`FORTIS_REVIEW_UPDATE_RETURNED_PREVIOUS`. The original 30 checks covered legacy
state; they missed the native directory created by runtime initialization.
No new image update PASS was reported.

SOURCE-VERIFIED cause: the legacy helper admitted only the marker and four
SQLite files, while native runtime always creates `native-git`. Its `Store`,
Git backend and runner source are identical between the pinned bootstrap and
image source commits. New tests use those actual constructors, reproduce the
old rejection and verify exact preservation of native DB/tasks/jobs/artifacts.
Transient auth/quarantine state, journals, unfinished jobs, corrupted or missing
artifacts, permissions and links remain denied before target creation.

LIVE-VERIFIED after owner-reported return: authenticated native capabilities
respond at the isolated machine ingress and Sonar `get_quality_gate` returns
`OK`. This proves those reads respond, not a host image/health inventory.

MANUAL-PENDING: corrected native clone/start/health/readback/return on Windows.
The retry uses a new protected record, verifies the old attempt safely returned
without created resources, and preserves/hash-binds the old record. No Windows
Docker lifecycle action was performed from Fortis Repo. PowerShell is unavailable
here; the corrected script still runs actual owner-side local selftests before
Docker and no Windows execution PASS is inferred from the offline suite.

SOURCE-VERIFIED: the standalone bundle is reproducible from a clean source
commit. It embeds exact Python asset bytes and selected unchanged pilot
functions, with no external source-file reads. Its offline packaging test
checks deterministic output, embedded assets and entrypoint preservation.

UNKNOWN / NOT VERIFIED: new provider scopes, actual obs-planning-docs workflow
binding, CI manifest, Sonar analysis/SHA binding and live mutation semantics.
The updater reports these separately from image readiness and keeps opt-in
absent unless the owner supplies an explicit public config. It does not alter
Production or the separate pending HTTP 202 client task.

[Runbook](../../docs/guides/WINDOWS-REVIEW-UPDATE.md) owns usage and failure
semantics; [analysis contract](../../docs/ANALYSIS-REVIEW-CONTRACT.md) owns
operation/policy/binding semantics. This evidence records no live cutover PASS.

# Windows review updater — evidence, 2026-11-06

SOURCE-VERIFIED: bounded owner-run entrypoint
[`Update-NativeReview.ps1`](../deploy/Update-NativeReview.ps1), based on the
accepted pilot state clone, runtime admission and private Windows record
helpers. Those historical helper sources are unchanged. New arrays are
explicitly enumerated at the `ConvertFrom-Json` boundary for PowerShell 5.1.

Targeted offline checks: 30 tests passed (6 updater config/embedded-code/package
checks, 14 state/admission/scenario regressions and 10 image/storage source gates). They cover exact
config owner/project, malformed/duplicate/extra fields and workflow paths,
stopped state cloning and rejection, preservation, admitted mounts/security
and unhealthy-return admission. They do not simulate Docker or Windows.

OWNER-REPORTED: the image identified in [current state](../../docs/guides/FORTIS-APPROVALS-SECURE-DEVELOPMENT.md)
passed the owner's network-disabled smoke, including analysis-review imports.
The first attempt with `python -I` omitted `/opt/fortis` from `sys.path` and
failed `ModuleNotFoundError`; the corrected stdin prefix passed all markers.
The updater includes that prefix and uses base64 code transport, not native
quoting of multiline Python/JSON.

MANUAL-PENDING: parsing/execution under actual Windows PowerShell 5.1, ACL and
subprocess selftest, fresh image/container admission, stop/clone/create/start,
health/readback and failure return. No Windows Docker lifecycle action was
performed from Fortis Repo. The script runs local selftests before Docker. PowerShell is unavailable in
this Repo environment; no claim of Windows parsing/execution is made.

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

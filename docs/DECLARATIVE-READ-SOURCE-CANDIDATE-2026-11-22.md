# Declarative READ for Fortis integrations — source candidate (2026-11-22)

**Status:** task source-only, not merged, installed or enabled. Historical
`fortis-gateway` container and owner state are unchanged. This document records
an architectural trial and review boundaries, **not** a live new provider.

## Purpose

Reduce repetitive programming and source-file edits for new provider methods
while keeping the **existing** image-owned provider discovery, Core approvals,
Owner Policy, vault, closed transport and ordinary source PR/CI → image release.
No dynamic runtime provider loading, hot update or rebuild avoidance goal.

`No-code / Low-code / Custom` are optional **metadata describing the actual
implementation** at API, provider or method granularity; they are not runtime
modes, approval policies or different onboarding workflows. Automated source
preparation + a manually added **narrow** component belong to the same workflow.

## First source component

`fortis_approvals/extensions/declarative_read.py` exports
`compile_read_provider(service, api, specs, *, postchecks=None, context_checks=None)`.

- The **trusted source** supplies a finite Python data definition, **not** a
  user-uploaded URL/JSON/OpenAPI document. It compiles bounded schema validators,
  a closed response projection and generic READ execution into standard
  `Operation` callables. A `Provider` holds the existing trusted `api` transport.
- The accepted transport must already own its `routes` with fixed GET/readonly
  definitions. Any unregistered or mutating route, unknown descriptor member,
  target outside the finite allowlist, path placeholder mismatch, unused caller
  parameter or secret-bearing public parameter fails closed.
- Supported schema shapes: exact objects, arrays (up to 256 items), nullable,
  text (explicit character vs UTF-8 byte counts, printable policy and a finite
  set of structured character formats), integers (including finite allowlists),
  boolean and literal. Projection selects named fields and maps bounded arrays
  with explicit output names; it never echoes arbitrary response fields.
- Generic operation checks include equality between the request target and
  a result field, uniqueness of entries, limited offset/limit/revision paging,
  and the existing Core output-size bound (up to 64 KiB).
- Source-owned **result postchecks** (`postchecks={name: fn(value)}`) run on
  execution **and** every `Operation.result(value)` validation/confirmation;
  they may reject but not modify the result or return a replacement.
  Separate context-dependent checks (`context_checks={name:
  fn(target, params, value)}`) are **execution-only**: they cannot be treated
  as result/receipt validations without the original persisted request context.
  Unknown hook names are rejected. Any changed/renamed method must preserve
  matching trusted hook or fail compile. Custom transports remain source-owned.
- Source definitions carry an optional `Operation.allowed_targets` envelope.
  The existing ExtensionRuntime checks configured target subsets before
  publishing a ready/ALLOW catalog row. Legacy handwritten Operation objects
  retain their previous contract (empty envelope means not compiler-bound).
- Invalid canonical decimal target bindings, unhashable unique fields,
  incomplete param object schemas and incompatible paging types fail **at
  compile time**; they do not reach upstream execution. Generic uniqueness is
  enforced during `Operation.result` revalidation as well as `execute`.
  Target-bound identity, pagination offsets and context-dependent hooks still
  require persisted request data; `Operation.result(data)` alone cannot prove
  those cross-request constraints.

- Credentials, actor grants, owner policy, image activation, release and rollback
  remain in existing Fortis mechanisms. There is no machine API to install
  definitions or mint grants, no new credential source, no production network
  effect and no new owner approval bypass.

## Reasonable preflight selection, before editing provider source

The task candidate also has
`fortis_approvals/extensions/source_strategy.py`:
`advise_onboarding(reviewed_evidence, source_description=None, effort=None)`.
It **does not automatically infer** API semantics from a URL, and it does not
execute HTTP. Its starting facts must be reviewed: transport characteristics,
HTTP verb and effect category, JSON/non-JSON response, whether the method
contract exists, and the need for special checks or a custom Operation.
Unknown facts or unreviewed effects return `REVIEW_REQUIRED`, not a guess.

For reviewed GET/READ methods the assessor performs a **real source-only
compiler preflight** and compares feasible implementation techniques using
transparent, editable effort-point *proxies* (not measured business costs).
A simple method usually prefers a compiled operation; if its contract is
missing, drafting and reviewing a descriptor can be more economical than
writing the whole handler. For a narrow special business invariant, a trusted
result/context check may be cheaper; otherwise a fully handwritten Operation
is available in the **same Provider, approvals and source-release process**.
No-code/Low-code/Custom remain **descriptive metadata only** and never choose
permissions, transports, runtimes or separate onboarding routes.

`next_source_attempt(plan, operation, source_failure)` keeps the original
assessment digest and source decision history when an attempted source
implementation fails a **verified source-only** capability or regression test.
A reviewed *additive* invariant can try one trusted postcheck before a fully
handwritten method. A broader contract mismatch skips the check and tries a
handwritten operation. Security/trust denial, unknown WRITE effects and
unverified facts always STOP; the assessor never replays an API request,
Core worker effect, deployment or owner decision to try a different technique.

One read-only command for source review:

```sh
PYTHONPATH=. python3 -B -m fortis_approvals.extensions.source_strategy \
  --evidence /path/to/reviewed-api-evidence.json \
  --source-description /path/to/reviewed-source-description.json
```

The source generator CLI **requires reviewed evidence for `--apply`**. While
mandatory manual hooks/operations cannot yet be independently enforced by a
persistent, generated installation contract, the CLI deliberately refuses
`MANUAL_REQUIRED` cases (`SOURCE_ASSESSMENT_MANUAL_REQUIRED`) instead of
creating a falsely-ready provider. It can still print a read-only plan; manual
source pieces and mixed providers are proved by isolated generator tests.
Future work must add safe incomplete source preparation, the exact manual
artifact/review gate, and resume in the same task before enabling end-to-end
partial automation. A `SOURCE_PREFLIGHT_READY` assessment is **not** a release
or owner-grant permission; standard CI, image rebuild and real acceptance
remain required.

## OpenAPI intake as an untrusted, read-only source draft (Phase 10)

`fortis_approvals/extensions/openapi_intake.py` adds a deliberately bounded
OpenAPI **3.0.x/3.1.x JSON** adapter. This is **not** a generic OpenAPI interpreter,
YAML parser, API client, provider installation service or deployment path.
Its public `inspect_openapi(openapi_json_or_dict, provider)` never opens a URL,
installs a provider or uses the document's `servers` addresses; it returns
`OPENAPI_SOURCE_DRAFT` with `reviewed: false`, the input `specSha256`, per-method
reason codes, next actions and an **incomplete** source template with
`origin: null`, `targets: []` and no credential. No runnable method is created
by the inspection step. This is a review artifact, not a trusted API contract.
For a compilable path parameter, the operation row also records its normalized
`pathTargetSchema`.

Supported automatic *draft conversion* is GET/HTTP 200/application-json,
exact bounded object fields, source projection of required fields only,
nullable scalar fields, arrays with an explicit `maxItems <= 256`, integer and
boolean values, strings with explicit max length, a single path target and
simple scalar query parameters. Reusable local `#/components/schemas/Name` and
`#/components/parameters/Name` references are resolved with cycle/depth
limits. Path binding supports string length bounds and integers with inclusive
bounds, integer-only enums, and `int32`/`int64` formats. Integer path targets
must be canonical decimal strings supported by the Fortis target identifier
grammar. A path pattern, unsupported format, or union requires review. A
non-null scalar `const` or integer-only enum excludes null even if the declared
type admits it. A `const` combined with other assertions requires review.
Unsupported compositions/constraints, external refs, non-standard serialization,
headers/cookies, non-JSON or non-200 responses, missing bounds and **any**
non-GET verb return specific `REVIEW_REQUIRED` reasons. `POST`/
WRITE is never quietly generated as a read method; ambiguous source response
contracts are not fixed by switching to manually-written code. Unlisted fields
in upstream objects are **projected out**, not passed through to caller results.

The read-only local command writes no source files:

```sh
PYTHONPATH=. python3 -B -m fortis_approvals.extensions.openapi_intake \
  --spec /path/to/local-openapi.json --provider study_records
```

After independent source/fixture/security review, the caller may explicitly
use `bind_source_draft(plan, reviewed_https_origin, targets_by_method,
selected=[...])` to produce a **still unreviewed** source candidate. The
binding reuses the Fortis schema validator and generator/compiler without HTTP.
Every explicit path target must pass the preserved schema before the bound
allowlist becomes the generated operation's target scope. Re-inspect older
drafts that lack a path schema before binding them. If any operation is
unsupported, select methods explicitly. `excludedMethods` lists every omission.
`excludedMethodDetails` records the operation name, verb, path, diagnostic codes
and whether it was unsupported or explicitly skipped. Origin, target, auth,
policy and owner permissions are never inferred or granted. To progress, separately supply independently
reviewed method facts to the existing `advise_onboarding()` and use one
`source_onboarding.begin()` task; the trusted test callback, PR/CI, image and
Owner release remain separate gates. No optional flag or source checksum grants
independent review automatically.

OpenAPI 3.2, YAML source text, polymorphic schemas, unbounded collections,
complex OAuth transports, response bodies with optional-only fields and
actual upstream behavior verification remain outside this subset. The scope is
intentionally narrower than OpenAPI as a whole. The importer and generated
source must not be used to estimate the percentage of third-party APIs that
can be onboarded without hand-written code until tested against independently
sourced real API documents and verified response fixtures.

## Source onboarding checkpoint and manual pause/resume (offline candidate)

`fortis_approvals/extensions/source_onboarding.py` introduces one source-only
workflow across all implementation techniques:

- `begin(session_directory, reviewed_evidence, source_description)` uses the
  existing strategy preflight, saves a digest-bound checkpoint and creates an
  **incomplete draft outside `fortis_approvals/integrations`**, including the
  source-owned definition, generated package and separate manual files. An
  incomplete provider is never available to the runtime discovery scanner.
- `inspect(session_directory)` reads the persisted checkpoint and rejects
  modified generated files. `REVIEW_REQUIRED`, `SOURCE_READY`,
  `MANUAL_REQUIRED`, `SOURCE_VERIFIED` and `SOURCE_PREPARED` are internal source
  progress statuses, **not** policy modes or extra release paths.
- `fallback(session_directory, evidence, description, method, source_failure)`
  uses the existing *source-only* bounded fallback decision in the **same**
  persisted task. It retains manual bytes; for fully handwritten fallback it
  removes the compiled operation with that name from the staged source,
  avoiding duplicate/contradictory runtime `Operation`s. Security failures
  stop rather than trigger a weaker implementation.
- `resume(session_directory, reviewer=trusted_source_verifier)` requires a
  **trusted, in-process source-test/reviewer callback**. It binds the returned
  operation set to the original assessed methods, checks typed manual
  requirements, and records hashes of the unchanged generated and manually
  edited source. It is NOT a signed owner grant: a caller-controlled Boolean
  or an untrusted reviewer callback is not an authorization mechanism.
- `prepare_source(session_directory, source_root, original_description)`
  requires exact source/evidence identity, unchanged reviewed file bytes and
  the registered Git task-worktree fence. Only then are the generated and
  reviewed manual bytes copied to a normal image-packaged source directory.
  Existing manual files that would be silently overwritten cause STOP.
  This **does not** create PR, promote an image, install an API, grant scopes or
  issue Gateway network requests.

Isolated regressions cover fully automatic READ, a mixed method with a hand
result check, fully manual READ, late fallback through all three techniques,
restart/inspect from persisted JSON, changed manual/generated source, edited
input descriptions, extra unreviewed manual methods and denied WRITE/unknown
semantics. Source drafts and recovery snapshots are not production state; the source
reviewer fingerprint and current hard-exit tests are not a replacement for
independent PR CI, authenticated owner approval or race-free durable recovery. A missing/unfinished
source descriptor remains a **review STOP**, not a silently accepted stub.

### Phase 9: source-bound review record and draft interruption recovery

The offline checkpoint now records **source-test provenance** on successful
`resume`: the reviewed stage-file snapshot, assessment/source/requirement and
operation digests, and the source-path, function name and SHA-256 of the
in-process reviewer Python module. The reviewer must come from a Python file
under this Fortis source checkout. `prepare_source` checks these references
again, so a changed test module or reviewed source blocks copying the draft.
This is reproducible evidence **only**, not a signed independent PR CI receipt,
Owner WebAuthn authorization or a permission to activate the provider. The
caller-supplied verifier can still lie about tests if it is not independently
trusted and executed under normal source-review controls.

`begin()` now writes a `STAGING` checkpoint **before** writing the first
generated file. Every draft file is written via an atomic file replace. If a
process exits between files or before updating the final checkpoint, repeating
`begin()` with the **same source and evidence** completes only known generated
files and preserves any existing manual edits. Unexpected files or altered
generated bytes STOP instead of being deleted.

`fallback()` uses an immutable **versioned draft directory**: first clone the
active source draft and prepare the new generated files privately, then
atomically switch the active version in `checkpoint.json`. Any hard crash
before the switch keeps the old draft valid; an abandoned, hidden incomplete
version remains available for explicit inspection rather than being removed
without permission. `stage_path(session_dir)` resolves the current editable
manual source location; hard-code neither `staged_provider/` nor an older
version directory after a fallback. A lost-reply repeat of the same source
fallback returns the saved decision rather than making another downgrade; an
intentional fresh attempt of the same failure classification requires
`advance_again=True` after independent verification.

A source session inside `fortis_approvals/integrations/` is rejected. Source
preparation after a verified checkpoint still goes through the registered
Git task-worktree fence and the ordinary source package generator; the
runtime/owner image and grants are untouched. The source test suite includes
hard exits **before file rename, after partial begin, before final begin
checkpoint, during fallback, and after fallback checkpoint switch**.

This is not a crash-proof distributed state machine: byte-level disk/power
loss, fsync of every parent directory, adversarial same-UID filesystem races,
stale/hypothetically forged checkpoint JSON, review callback authorization,
and safe cleanup of abandoned version directories still require independent
review. The source-level evidence record is not cryptographic proof of who
approved the manual code. Do not claim this proof without the real PR+CI and
Owner release path.

## Source-workspace safety and failure recovery (source candidate only)

`fortis_approvals/extensions/source_workspace.py` owns source filesystem
planning and staged application. The generator uses a single validated source
spec to render and preflight the package before applying (rather than
recompiling it several times). Both `source_plan` and `apply_source_package`
return **the same pre-change file diff**, with `appliedFiles` in the mutation
receipt. New/generated packages retain `manual.py` and `tests/test_manual.py`;
these follow the provider CI discovery pattern `test_*.py`. An intentional
failing manual test was independently observed by the actual unittest loader.

Public source `apply` requires a **Git-registered linked task worktree**
whose git-common-dir matches the trusted package source and whose branch is
`refs/heads/task/*`. A directory without Git or a separate fake `task/*`
checkout is rejected. Unit fixtures explicitly patch this external gate only
inside their isolated test process; the CLI has no fixture bypass.

Confinement checks forbid symbolic links in the source package, ancestors
inside the worktree and generated/manual files. A cross-process lock serializes
cooperating source updates of the same provider. Update first stages an entire
provider directory preserving all manual files, writes a journal with old/new
manifest hashes, then performs two same-filesystem renames. A sudden stop
between renames **can briefly leave the provider path absent**. The next
`apply` validates the journal and returns the original provider before
reapplying; if the new source is already committed, it finalizes the journal
without rewriting it. An unrecognized or modified transaction **STOPs**.
`source_plan` is always read-only and refuses to mutate pending transactions.

Tests inject an exception between renames **and** kill a separate process at
both interruption boundaries. They also exercise symlink ancestors, fake Git
worktrees, manual-code retention, exact apply receipts, source revalidation
counts and deterministic source-only preview. A further adversarial test
modifies a generated file **after** an interrupted commit while the previous
source remains backed up; recovery now checks actual generated-file hashes
before removing the backup and STOPS without deleting it on a mismatch. These
tests demonstrate recovery of known failures, **not** complete resistance to
hostile concurrent directory replacement/TOCTOU, host crashes without fsync'd
directory metadata, disk-full at every byte boundary or the owner's rollout. Stronger dirfd/no-follow
handling, durable fsync on the stage/metadata, and owner review remain required
before an unattended deployment workflow.

`source_strategy.py` now treats an unregistered route/invalid descriptor as a
**source contract correction** (`REVIEW_REQUIRED`), not as a reason to spend
extra effort on handwritten code. Only explicit unsupported shape/format
features can trigger a safe source-only fallback. `reviewed=true` in an input
file remains **self-asserted evidence**, not independently signed owner review;
image release and policy approval are still separate.

## Real source contracts used as oracles

No real provider has been migrated yet. The test
`fortis_approvals/tests/test_declarative_read.py` compiles an equivalent
source-owned method definition and runs positive/negative cases **against the
unchanged existing source handlers**:

| Original provider | Methods | Required behavior preserved in offline comparison |
| --- | --- | --- |
| Action Core | `read_action` | Target only `3`/`4`, exact six result fields, integer ID equality, no control characters in name, codepoint-count length, category format, YAML with newline, size bound |
| Observatory | `health` | Target `service`, literal service/mode and `ok is True`, strip internal upstream fields |
| Observatory | `list_sessions` | Target `registry`, projection of `reporting_session_id` to `session_id`, optional session ID, finite format, uniqueness, 200-row ceiling, no output of private metadata |

Transport objects are reused via the existing provider imports, not replaced
with a new generic HTTP client. The original Action Core and Observatory
per-service pinned CA, TLS/SAN, Bearer, no-redirect, strict response handling
and target-granted Core layer remain **independent**. Observatory's legacy
HTTP/18756 path is not enabled, reconnected or approved by this work.

A test-only extra `listing` method exercises pagination, query filtering and
revision checks without a new specialized handler. A test-only postcheck shows
manual checks can narrow behavior without altering generated READ code.

Four adversarial gaps found by an independent review were closed in the task
branch: invalid decimal targets, unhashable uniqueness keys, context-free result
postcheck revalidation and catalog readiness for disallowed targets.
`test_declarative_read.py` runs these new regressions.

## Explicit limitations, prerequisites and STOP

1. **Source-only generator added to this task branch, not production.**
   `fortis_approvals/extensions/source_generator.py` supports deterministic
   `source_plan` (read-only), `apply_source_package` (explicit source-worktree
   mutation) and `build_generated_provider` (image-owned provider import).
   Generate normal `extension.py`, `definition.py`, baseline tests and contract
   documentation; preserve the human-written `manual.py` and its tests on
   regeneration. Detect hand-edited generated files and STOP instead of
   overwriting them. Explicit `transport=manual` leaves trust/CA/auth to a
   source-reviewed component, while `manual_operations()` can supply additional
   or entirely custom operations in the **same** Provider and runtime. Full
   manual `methods=[]` is possible but cannot activate until a valid
   hand-written Operation exists. Existing unmanaged provider folders are
   never overwritten automatically.
   The generator is **not** an OpenAPI reader and does not generate owner scopes,
   credentials, Windows settings, PRs or live Gateway installation. No real
   providers have been migrated. Only source CI/prototypes are available.
2. **The compiler is source-trusted, not an interpreter of arbitrary remote
   input.** Production-ready descriptor ingestion needs adversarial parsing,
   complexity/fuzz tests, source-review procedure and version migration. No
   network-loaded descriptors, arbitrary regex, expressions, eval or imports.
3. **WRITE is not supported.** POST/PATCH/DELETE effects require independent
   precondition/preview, stable request identity, upstream idempotency or
   readback, effect receipt, uncertainty/replay prevention and trusted transport
   semantics. Generic GET does not confer WRITE permissions.
4. **Complex provider rules may require source hooks.** Mirror v2 actor-bound
   proof, worker receipt, expected SHA, in-flight approvals and cross-source
   consistency must not be collapsed into generic mapping/typing or bypassed.
   A developer can supply a reviewed custom validation/transport at the exact
   unsupported step, then continue the single common process.
5. **No live compatibility is inferred.** Passing mocked tests, unit tests or
   source CI proves no Windows/Docker TLS/CA, no owner vault provisioning,
   no Gateway READ from the real network namespace and no protected
   Check/Apply/Backup/Promote. The existing `UC-GW-002/003/004/005/009/012`
   and `UC-CONT-002/003` still control any real deployment.

## OpenHolidays source pilot

The original linked task worktree now contains a source-only package at
`fortis_approvals/integrations/open_holidays_pilot`. The only operation is
`public_holidays`, a GET for the fixed target `de` in the 2026 calendar year,
with no caller parameters or upstream credential. The source-owned transport
binds the four vendor query fields, verifies HTTPS and the JSON response
framing, caps bytes and wraps the upstream list. The existing compiler
projects the two date fields and the nationwide flag. The source-owned date
check validates the receipt and enforces the same range used in the request.

The recorded Docker response contained 20 entries. Compiled and typed
handwritten variants matched on the complete recording. A separate isolated
Fortis Core executed the prepared transport against the same vendor endpoint
and returned the matching projection. Tests exercise denied routing, malformed
and truncated responses, and invalid or out-of-range dates.

The same staged onboarding session advanced through `SOURCE_VERIFIED` and
`SOURCE_PREPARED`. The source-test receipt binds the reviewed files and the
test verifier in `fortis_approvals/tests/review_staged_openholidays.py`.
Activation requires separate Gateway configuration, source PR/CI and the
ordinary owner release. The pilot evidence covers one fixed query.

## Acceptance for a future PR

- Assess reviewed API/method evidence **before** source changes; record
  feasibility, cost assumptions, supported technique, fallback reasons and
  explicit `REVIEW_REQUIRED`/`MANUAL_REQUIRED` steps. Do not downgrade a
  security failure by choosing custom code or replay any uncertain effect.
- Compile source-owned real method specs with original transports, compare
  acceptance/denial to unchanged providers and preserve their negative tests.
- Ensure normal `scripts/test-source.sh` runs the compiler, strategy,
  generator and workspace fault-injection tests and dynamically discovers
  `test_manual.py` in generated providers.
- Refresh source manifests and verify the strict release/source checks.
- Audit compiler schema and projection with hostile values; explicit STOP for
  non-GET, unknown scopes, custom transport without owner review, unstable
  grants, invalid response or incompatible hook.
- Preserve ordinary source PR/CI, owner merge, verified Gateway image release
  and independent live readback. No direct modification of production.

## Next phase after security review

Source package generation is now prototyped **in the task branch** for
independent new providers. Baseline source tests include mixed declarative +
manual operations and manual transport, deterministic change preview,
protected manually owned files, mismatched manual transport routes and the
existing `discover()`/`ExtensionRuntime` contract. It is **not** production-ready
for arbitrary user-supplied descriptions.

Next: pilot the bounded OpenAPI importer against independent API contracts and
verified response fixtures. Exercise a new provider and adding a method to an
**existing manually authored provider** while preserving its extension.py.
Compare the shared compiler with ordinary typed Python implementation for
manual effort and maintenance. Track concurrent tampering protection and
journal durability in the source-workspace review. Research WRITE effects
separately. Use ordinary source PR and verified image rebuild; never hot-install
or implicitly create owner grants.

# Owner policy editor V2 — source candidate

Status: **explicit R7 source opt-in implemented; not deployed or live accepted**.
The existing SONAR_ACCEPT_ISSUE_V1 release is unchanged. V2 is selected only by
the owner-reviewed full release config with `"ownerPolicyEditor":"UNIFIED_V2"`
instead of the V1 key. The modes are mutually exclusive, and a valid release
nonce and existing activation gate are required. No live grant, provider
credential, Windows executor or production database is changed by this source.

## Common authority and UI

One trusted PolicyAdmission describes the choices for already admitted literal
actor/method and exact actor/method/target coordinates. A method rule is scoped
to an actor; configured exact policies, exact V2 overrides and legacy exact DENY
remain exceptions. No global wildcard, invented actor, unregistered operation,
or conversion of a conditional predicate to an unconditional permission.
A denied actor-wide baseline may not be widened by this candidate. A trusted
exact grant may be admitted only by separate source composition review.

UnifiedPolicyCore uses the existing Core SQLite transaction domain, and adds
three owner_local_policy_v2_* tables. Existing V1 tables and events remain
untouched. V2 binds the baseline and admission map, verifies event sequence and
effective projection, and retains the V1 digest. A V1 runtime rejects the
additional tables; the ordinary R7 legacy fence rejects local-policy state.
Old binaries/snapshots and external rollback remain a separate unresolved risk.

Any transition requires a fresh owner session/CSRF and one-time UV WebAuthn
assertion binding the exact candidate, revision, authority, source, credentials
and expiry. Commit rechecks inside BEGIN IMMEDIATE, then writes a rule and
event atomically. No external provider operation is executed by the editor.
The global policyVersion revision stales prior pending/approved decisions;
a DISPATCHED request anywhere blocks the change. UNCERTAIN history is preserved.
A lost finish response requires exact UUID readback, not auto-retry.

The V2 UI uses a two-pane policy workbench: independently scrolling,
provider-grouped operation choices and a visible editor alongside the selected
rule. Filtering to editable rows is optional and defaults on; read-only rows,
conditional policies and unknown effective target values stay inspectable on
request. The panel explains server-admitted choices (including why an ASK-only
operation cannot be made ALLOW) and distinguishes permanent owner policy edits
from per-request machine ASK approval.

An enabled V2 inventory and separately verified owner-only capability are both
required. Server-supplied editablePolicies constrains the selector. Owner chooses
method or exact target, reviews old/new policy, exceptions, risk and request
counts, then explicitly invokes WebAuthn. The UI change does not expand any
operation's policy admission. V1 remains compatible and the V2 panel stays hidden
unless a live V2 capability is verified.

## Real R7 admission and limitations

The R7 factory derives one admission map after all trusted adapters and grants
are installed. All edits use the same Core, HTTP portal and SQLite transaction
domain. Unregistered/disabled rows, callable policies, publisher-only guards
and unreviewed configured DENY grants are not turned into editable grants.

| Registered operation | Permitted values |
| --- | --- |
| Native synchronous READ | DENY / ALLOW |
| Sonar mutation, PowerShell execute, mandatory ASK GitHub controls | DENY / ASK |
| Ordinary native PR creation, scoped visual publication/revision, literal Workspace operations | DENY / ASK / ALLOW |
| Configured extension READ or existing ALLOW write without signing | DENY / ASK / ALLOW |
| Signed Mirror WRITE or other existing ASK extension WRITE | DENY / ASK |
| Conditional push/cleanup, publisher profile, unadmitted scope | Fixed existing contract |

Native READ-ASK needs a separate deferred result protocol. PowerShell ALLOW
requires Windows Executor authorization changes; do not bypass that proof.
Technical Git transfer/status paths are separate from editable Core methods.
A method-level actor rule is a default; exact exceptions remain in force.
No new credential, provider scope, project/repository, actor or target grant
is created. Provider-specific independent guards continue to apply.
An already admitted synchronous READ may finish; a policy change cannot undo
an already dispatched or unknown effect. A global DISPATCHED row blocks edits.

The authority digest includes trusted project/repository/actor/provider and
executor scope as well as the literal rows and ceilings. Scope drift fails
closed at restart and requires a separately reviewed migration.
Runtime ceremonies bind the loaded grant/Sonar/GitHub identity, mounted
machine-shell identity, extension vault generations and active owner keys.
Owner counters are not treated as key-generation changes.

## Release validation

The state helper understands V1, V2 and preserved V1+V2 tables; validates
schema, legacy digest, sequence, event descriptors and current projection;
returns a bound V2 receipt. Full first-event authority replay is enforced by
the live Core. Clone and backup preserve exact bytes; append-only UNCERTAIN
growth cannot legitimize policy changes. A new V2 startup initializes its
tables only on the cloned candidate; the retained source is untouched.
Do not restore an old binary or pre-policy snapshot after a confirmed change:
independent external rollback prevention remains out of scope.

First opt-in uses UC-GW-005 owner-controlled Check/Apply, Backup and Promote,
not inherited Auto. Preserve current full config and approved preservation
scopes; replace only the explicit editor mode. Validate the exact installed
image with IMAGE_OWNER_POLICY_V2_OPT_IN_PASS and staged owner write refusal.
Review probes when a policy change blocks an existing READ probe. Never
silently loosen the policy just to get a release through.

## Evidence and remaining live acceptance

Offline tests exercise all six transitions, actor/target precedence,
Core dispatch, real R7/RepoIntentBroker READ and Sonar mutation denial,
ExtensionRuntime ASK/ALLOW, configuration opt-in, gate, credential rotation,
restart, V1 preservation, V2 receipt/growth clone, stale revision, tampered
descriptor, owner HTTP/CSRF/Origin and lost-response readback. The mandatory
image smoke builds the native GitHub/Workspace/Sonar V2 composition. Browser
tests cover provider grouping, choices and two-step confirmation. Real virtual
FIDO2 tests run in Source CI. Still require exact merged CI, Windows checked
image release and owner-only live acceptance; no current production change.

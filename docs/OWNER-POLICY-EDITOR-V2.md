# Owner policy editor V2 — source candidate

> **Историческая спецификация V2, не текущий статус production.** Последующий owner-reported релиз `UNIFIED_V2 + OWNER_LABELS_V1` был активирован, а PR #214 с исправлением интерфейса merged source; завершение Backup/Promote того релиза требуется подтвердить по защищённой Windows записи. Полное управление DENY/ASK/ALLOW для *каждого* метода пока разрабатывается: см. [план 2026-11-21](OWNER-ALL-METHOD-POLICY-PLAN-2026-11-21.md) и [текущий handoff](OWNER-ALL-METHOD-POLICY-HANDOFF-2026-11-21.md). Перечисленные ниже ASK-only потолки описывают **старую модель admission** и не являются новым продуктовым требованием.


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

## Owner-managed release-label ALLOW — separate source candidate

A new, **not installed** review flag `ownerPolicyAuthorityUpgrade:
"OWNER_LABELS_V1"` is valid only alongside `ownerPolicyEditor:"UNIFIED_V2"`.
It expands the source admission for the existing Repo actor's three typed
release-label writes from DENY/ASK to DENY/ASK/ALLOW. The currently running
owner policy is unchanged until another owner-approved checked image release
and a separate WebAuthn policy change. This is not a default permission,
nor a publisher credential or privilege for new actors/targets.

The V2 authority digest already binds its admitted value set. The candidate
explicitly verifies the *previous exact* digest and permits a one-time
transactional authority upgrade only while V2 revision is zero and its rule
and event tables are empty. Existing V1 DENY audit history is retained.
Any prior V2 edit, changed project/actor/provider scope, unrecognized digest
or rollback of a once-upgraded database fails closed. The release controller
must preserve the state and separately admit the reviewed upgrade before
production deployment. Do not manually edit policy SQLite tables.

Persistent ALLOW changes only the owner-approval requirement for the ordinary
typed Repo actor, after an explicit strong WebAuthn policy edit. The existing
pre-dispatch Core CAS/receipt checks, registered task PR restrictions, managed
label namespace, exact head/base/body/complete-label digests, publisher CI
admission when applicable and pre-effect GitHub revalidation remain active.
An independent readback is still required; UNKNOWN is never retried blindly.
The dedicated `release-label-publisher-v1` actor retains its distinct ASK
owner authorization and cannot borrow the ordinary actor's policy.

The user-level distinction is: **WebAuthn authorizes an ongoing policy
change; ASK authorizes one machine request**. Neither creates a new provider
scope. Other native controls, Sonar writes, PowerShell, signed Mirror, callable
policies and synchronous READ-ASK remain separately gated. Do not advertise
unconditional DENY/ASK/ALLOW for those until their inner enforcement contracts
and tests explicitly support it.


## Subsequent owner-all-methods authority V3 (source-only candidate)

This section describes a **separate** reviewed release opt-in,
`"ownerPolicyAuthorityUpgrade": "OWNER_ALL_METHODS_V1"`, only with
`"ownerPolicyEditor": "UNIFIED_V2"`. It does not alter the installed Gateway
or automatically grant any method. The previous label-only opt-in remains
accepted for its original authority digest and migration lineage.

For **all already registered, actor-granted Core methods** (including
synchronous native GitHub/Sonar READ and provider action, Sonar WRITE,
PowerShell, trusted extensions and signed Mirror operations), the Owner Portal
accepts the three **outer** policy settings `DENY / ASK / ALLOW`. The option
list is derived from trusted registration, existing actor grants and scoped
provider operations, **not a ceiling keyed to operation name**. Owner edits
require the existing fresh UV-required WebAuthn ceremony, exact revision,
credential, and source-generation binding. Unknown methods, unregistered
actors/targets and absent provider credentials receive no new grant.

At execution, independent checks still apply. The effective policy is the
most restrictive of owner outer policy, a trusted conditional callback,
and trusted adapter **inner** policy: `DENY > ASK > ALLOW`.
Windows PowerShell V1 remains ASK for independent executor command proof;
signed extension writes and the separate release-label publisher actor
continue to require their independent ASK. The UI must distinguish outer
policy from effective policy at a *specific target*. ALLOW never means
unrestricted shell, provider credential, URL, repo, or raw HTTP access.

Native synchronous READ ASK uses a one-use Core owner request:
the first typed GET creates a durable PENDING request with **no provider read**;
after owner WebAuthn approval the client may send the exact same UUID and
parameters **once**, consuming an append-only protected receipt *before*
contacting the provider. A different UUID, actor, target or params cannot reuse
that consent. The provider's result is not automatically retried after a
lost response. Existing unrestricted read clients still return normal
`data`; a pending consent is explicitly returned as `state: PENDING`.

New candidate authority is not silently installed on prior V2 state:
the owner-reviewed release names its exact previous authority digest;
the Core verifies every persisted historic event and writes a transactionally
bound monotone authority epoch. Past UV events, V1 local DENY history,
rule projection and revision remain byte-for-byte unchanged. Any unknown
epoch chain, missing grant, altered scope, digest mismatch or active
PENDING/APPROVED/DISPATCHED Core request **stops migration**.
Unresolved UNCERTAIN effects retain their normal protected preservation
requirements. Rollback to an old image against newly migrated state fails
closed. No operator should edit SQLite tables to force compatibility.

The operator source/CI checks and real image smoke are not proof of production
activation; each first owner-controlled V3 release needs protected Check,
full-state clone/readback, Apply, Owner Portal acceptance, Backup and Promote.
After release the owner may separately choose a new policy. The source
candidate must not be advertised as deployed until this is completed.

## Reviewed successor inventory correction (source candidate, 2026-11-28)

The actual #289 owner screenshot showed missing Registry semantic methods even
with the editable-only filter disabled. The legacy extension and reviewed
successor share the Registry service name: the extension inventory enumerated
only its packaged candidate READs. The V2 projection now includes missing
exact coordinates from the already verified semantic/context enrollment,
using the existing admitted baseline and policy snapshot. Existing extension
rows and exact actor/target distinctions are retained; contextual child rows
identify their parent Composite, and do not claim independent effect readiness.
No new admission, grant, handler, credential, policy event or state schema.

The independent Policy filter matches the displayed current/configured policy
(ALLOW, ASK, DENY, CONDITIONAL, UNKNOWN) together with provider, search and
editable-only filters. It does not change policy or perform a bulk edit.
Focused Python regression passed 24 cases, including actual owner HTTP
inventory with the packaged Registry extension and successor, exact row
uniqueness, existing DENY, policy edit/readback and isolated revision 3→4
product flow. UI fixtures cover filtering and contextual display.
A focused follow-up models three exact owner policy edits (merge_and_register
ASK, GitHub merge_pull_request ASK and list_pull_requests ALLOW) before the
separate staged copy. The compiled authority, policy revision, full Core and
policy history and inventory values remain identical across reopening, then
only the remaining fixture policies are edited before the ordinary product
flow. PASS in 24.887s. The prior fixture assumed no owner edits before copying;
this is not a readback of the owner's actual policy state.
The real GitHub/host effects remain fixtures; source delivery and live Portal
acceptance are not established. Do not merge this Gateway change outside
an approved source-lineage and maintenance handover, or use it to bypass the
first E2 scope. The #290 Registry-only PR is still unmerged.

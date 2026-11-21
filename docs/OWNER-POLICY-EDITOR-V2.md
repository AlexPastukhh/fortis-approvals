# Owner policy editor V2 — source candidate

Status: **not selected by the R7 runtime, not a released editor**. The existing
explicit SONAR_ACCEPT_ISSUE_V1 release is unchanged. No live grant, provider
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

The UI offers provider selection and filtered rule counts. An enabled V2
inventory and separately verified owner-only capability are both required.
Server-supplied editablePolicies constrains the selector. Owner chooses method
or exact target, reviews old/new policy, exceptions, risk and request counts,
then explicitly invokes WebAuthn. V1 remains compatible and the V2 panel stays
hidden for current releases.

## Runtime integration admission still required

Do not simply change the research configuration or copy the engine into a
running container. Current RepoIngress native READ requires ALLOW and has a
synchronous response contract; ASK needs a separate reviewed request flow.
The native Sonar write broker currently requires ASK; publisher role,
release-label operations, Mirror signed dispatch and the Windows machine
PowerShell executor have additional independent authorization requirements.
Callable Git push and cleanup policies preserve domain-specific guarantees.
A real R7 integration must derive choices from registered ready handlers,
actual broker/actor/target scopes and explicit provider ceilings, and test each
admitted transition at the real ingress and dispatch boundary. Do not convert
an unsupported transition into a misleading editable option or bypass an
executor's mandatory owner proof.

Before production opt-in, adapt and verify the protected controller's state
receipt/clone/backup/growth validation for the V2 schema and preserve V1 evidence.
Bind the actual installed source, all admitted credential generations and owner
key generation; verify single active writer, release gate and exact packaged
image smoke, not only source imports. No deployment is permitted by this
source candidate; do not use it as a live authorization or rollback guarantee.

## Evidence

Offline synthetic adapter tests cover all six transitions, actor and exact
scope precedence, actual Core admission/dispatch, restart, V1 audit preservation,
authority drift, stale revision, tampered descriptor, owner HTTP/CSRF/Origin
boundary and lost-response readback. Browser tests cover provider grouping,
server-approved choices, two-step confirmation and no finish replay.
Real virtual FIDO2 test is included in the existing cryptographic Source CI
lane. Installed-package imports are included in the exact Dockerfile COPY test.

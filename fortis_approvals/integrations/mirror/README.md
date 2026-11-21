# Mirror Gateway provider — READ-only source candidate

The retained get_repository v1 READ is unchanged. P3 adds eight version 2 READ definitions, disabled unless explicitly granted in reviewed
configuration. No Gateway ASK Pull or history WRITE is registered. Bound lookup never adopts Browser receipts. A source package,
green tests or published PR is not a Windows or Gateway deployment.

The fixed TLS transport is HTTPS/443 to host.docker.internal, using a
Gateway-owned named Bearer secret (future alias mirror-link). **Mirror-only CA
trust** is read from the fixed public PEM
/run/fortis-secrets/mirror-read/ca.pem in the already existing Gateway
read-only secrets mount. The CA must be independently reviewed and staged by
the Windows owner only after shared-vault coordination. This is not a new mount,
a token, or permission to modify the shared volume here. Missing/invalid CA
fails closed (MIRROR_CA_UNAVAILABLE); TLS keeps hostname verification and
CERT_REQUIRED, without proxy/redirect or system CA fallback. No private
Mirror CA key or Windows TLS server key ever belongs inside the Gateway. The Windows
GatewayHandler must be separately enabled with a trusted server certificate
and a Windows exact-repo allowlist. No browser cookie or OwnerShell port 10443
is used. Credential and vault compatibility are owned by the other flow:
do not provision a secret, change shared mounts or activate a provider yet.

The retained v1 Windows GET calls inventory(remote=False): it reads registered Docker
worktrees and Windows primary Git state but NEVER checks GitHub main/CI or
fetches Windows refs. The provider returns a bounded projection with the
Windows observation checkedAt and the explicit GitHub verification NOT_CHECKED.
All raw origins, local paths, filenames, private status and actions are omitted.
A returned Windows error/unknown remains UNKNOWN, never a claim of clean main.

Example proposed public config, not ready for deployment:
{"schemaVersion":1,"providers":{"mirror":{"credentials":{"link":"mirror-link"},"operations":{"get_repository":{"policy":"ALLOW","targets":["fortis-approvals"]}}}}}

**Historical observation, not current runtime status:** owner-run Windows preflight 2026-11-11 found Mirror source main clean
at 747ffaa8830a1bcbc12838ada0b5dccbd9b1e08e, but no listener on host
ports 443/8765/10443; the executable identity, TLS cert and live API remain
unverified. Owner-readback is not equivalent to LIVE_READ_VERIFIED.

The abandoned untracked mirror-provider-20261107 remains preserved. Its
pull_main relied on a Gateway github.merge_pull_request receipt, which
does not exist when the owner merges in GitHub UI. WRITE is DEFERRED pending
reviewed owner merge proof, CI, ASK, Windows preconditions, durable receipt
and negative acceptance. Never activate old WRITE from this task.

Canonical contracts: docs/INTEGRATION-EXTENSIONS.md; Gateway UC-GW-002;
docke-windows-mirror/docs/API-FIRST.md and UC-MIR-005.

The Windows Mirror raw `docker.worktrees` is the complete registered Git worktree inventory and includes its `docker.primary` exactly once. The Gateway READ projection checks that the primary entry matches the separate raw primary object and omits only that verified entry from the projected ordinary worktrees; missing, mismatched or duplicate primaries fail closed. This does not authorize Mirror or Gateway WRITE, change TLS/credentials, or deploy a runtime.

### v1 inventory capacity and reviewed authority compatibility

The 2026-11-21 release attempt returned safely before activation: a live
Mirror response contained 130 inventory entries (including its primary),
while both the retained and staged Gateway rejected over 128.
The staged authority migration itself preserved revision 2 and recorded
the authority epoch. The failed read was UNCERTAIN on the retained staged
copy, not on the active source volume.

The source fix raises the finite v1 inventory ceiling to 256. Exactly one
verified primary is still required; every ordinary worktree is projected.
The existing 256 KiB HTTPS response and 64 KiB projected result limits
remain independent. Oversize/invalid results fail closed, never truncate.
READ v2 pagination remains the long-term separately reviewed path.
No increase authorizes writes, new credentials or worktree cleanup.

Because provider source identity participates in the owner authority digest,
the trusted R7 builder recognizes only the exact old/new Mirror source
digest pair for the owner-reviewed OWNER_ALL_METHODS_V1 upgrade from
OWNER_LABELS_V1. It reconstructs the previous scope by substituting only
the old source digest; all other grants, baseline, configuration and scope
must reproduce the stored authority digest. Historical UV events and epoch
records are not rewritten. Other source/scope changes still require
separate reviewed migration; no generic database-supplied override.
Source tests do not establish production installation.


## P3 bounded READ v2 source

Normative source scope and owner activation gates:
[Mirror READ-V2](https://github.com/AlexPastukhh/docke-windows-mirror/blob/main/docs/READ-V2.md),
[closed catalog/schemas](https://github.com/AlexPastukhh/docke-windows-mirror/tree/main/docs/unified-api),
and [UC-GW-012](../../../docs/use-cases/own-api.md). The provider uses the same
Mirror-only pinned CA/HTTPS/443 transport and dedicated READ credential. Its
new routes are GET-only; public config, credentials, grants and runtime are
unchanged. Existing configs that grant v1 do not grant any v2 operation.

read_v2.py reuses the shared strict review_schema helpers; no generic schema
engine or second onboarding pipeline is added. Upstream wire remains bounded
at 256 KiB and shared audited results at 64 KiB. The public wire fixtures are
copied byte-for-byte from Mirror docs/unified-api/read-v2-fixtures.json and
validated by both projects. Changes must keep that copy identical.

The source-owned proposed named target mirror-pilot resolves only to
fortis-approvals. It never expands to GitHub token scope or discovered clones.
Internal inventory/scope_digest query fields are generated by trusted provider
code; callers cannot supply them. Windows must configure exactly the same
membership; both layers fail closed on mismatch. Further inventories require
reviewed source/config changes on both sides, not a wildcard grant.

Repository/worktree/action reads do not contact GitHub. Only the explicit
get_github_status_v2 uses bounded Windows owner gh reads through shared Core;
no READ fetches Git refs. Required checks remain NOT_VERIFIED. Capabilities
report source support; effective actor policy remains in the Gateway catalog.
P3b supplies durable principal-bound preview/lookup. The Windows factory requires
an explicit reviewed generation and safe Core ledger; it has no production machine
binding writer until P4 signed atomic reservation. History WRITE and Pull remain
DENY. Do not expose or retroactively bind old Browser receipts.

For a future release reuse the existing own-API manifest/linter, Doctor and
Acceptance tools from UC-GW-012. Do not enable the v2 factory, change occupied
443, provision keys/credentials or rebuild Gateway as part of source delivery.
A fresh live READ from the Gateway namespace and negative TLS/scope/write
probes remain separate owner-controlled acceptance.


P3b trusted_identity derives actor from Core's persisted authenticated request
in execute/reconcile and validates request operation/target/params. No public
actor field or generic framework change is added. Internal preview GET carries
principal/original READ UUID and a hash of trusted definition, admitted Core
policy version and READ credential generation. Lookup carries the authenticated principal and exact effect UUID.
The READ bearer authenticates Gateway assertions; it does not independently prove
human approval. READ never signs, consumes ASK or creates an effect binding.
Preview lookup callback reuses the original UUID after uncertain transport;
Windows returns its frozen stored metadata and never silently renews TTL.

Windows metadata shares the existing Core ledger and preflight. Lookup is a
strict stored-result projection after durable ownership/payload checks, without
Git readback/reconciliation. Missing or foreign/Browser UUIDs are indistinguishable;
NOT_FOUND and unfinished receipts remain UNKNOWN. See the canonical READ-V2 runbook
for capacity, generation rotation and owner-controlled activation gates.

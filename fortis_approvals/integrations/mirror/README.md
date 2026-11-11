# Mirror Gateway provider — READ-only source candidate

This provider has ONE operation: get_repository (read; proposed ALLOW with
exact allowed repo IDs). No Gateway ASK Pull is registered. A source package,
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

The Windows GET calls inventory(remote=False): it reads registered Docker
worktrees and Windows primary Git state but NEVER checks GitHub main/CI or
fetches Windows refs. The provider returns a bounded projection with the
Windows observation checkedAt and the explicit GitHub verification NOT_CHECKED.
All raw origins, local paths, filenames, private status and actions are omitted.
A returned Windows error/unknown remains UNKNOWN, never a claim of clean main.

Example proposed public config, not ready for deployment:
{"schemaVersion":1,"providers":{"mirror":{"credentials":{"link":"mirror-link"},"operations":{"get_repository":{"policy":"ALLOW","targets":["fortis-approvals"]}}}}}

Accepted owner-run Windows preflight 2026-11-11 found Mirror source main clean
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

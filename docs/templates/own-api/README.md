# Own API onboarding toolkit — source-only

Canonical procedure: [UC-GW-012](../../use-cases/own-api.md).
General extension package creation remains
[UC-GW-002](../../use-cases/integrations.md#uc-gw-002).

This toolkit consists of a local public JSON manifest, a **read-only**
standard-library linter, an evidence template and an owner handoff template.
It is NOT a Docker installer, a credential or CA provisioning tool, a network
probe, or a proof that the upstream service is installed.

In a registered task worktree:

~~~sh
python3 -B scripts/check-own-api-manifest.py --manifest "$PWD/docs/templates/own-api/mirror-read.example.json"
python3 -B scripts/check-own-api-manifest.py --manifest "$PWD/docs/templates/own-api/second-api-docker.fixture.json"
~~~

Both fixtures must produce SOURCE_MANIFEST_VALID with
liveVerified=false and readyToDeploy=false.

The Mirror example records the reviewed *source* of the WIN-HTTPS READ pilot;
its SHA is historical and needs fresh review before release. The second
example is a deliberately fictional DOCKER-HTTPS metricsprobe service,
documented in [the tabletop exercise](second-api-tabletop.md),
with sourceSha=null. It validates offline planning, **not** a running
service, DNS connectivity, pinned cert or a ready Gateway provider.

The manifest holds public inputs only: source pin, HTTPS hostname:443,
public CA *path* (not certificate/private key), vault *alias* (not secret),
strict GET routes, explicit target allowlist and response-size bound.
The checker intentionally forbids unknown keys and READ→WRITE upgrades.

Actual provider code must still fix its URL/routes, project closed
request and result schemas, and reject malformed upstream replies.
The tool does not inspect installed code, live trusted policy or actor
grants. The reviewer/owner must separately test: TLS SAN/expiry and
CA provenance; upstream Bearer 401/403, Host/route/POST rejection;
network isolation; vault owner/permissions and minimum privilege;
native Gateway regressions; exact Core state and isolated recovery;
live typed Gateway call and independent negative readbacks.

For DOCKER-HTTPS, an owner-released upstream container must expose
verified HTTPS on port 443 on a deliberately accepted gateway-visible
network. Loopback, plaintext HTTP, guessed DNS, wildcard target scope
and trust fallback do not qualify.

Owner Shell remains a separate privileged owner-only contract, not a
generic owned-API extension. Any future ASK/WRITE operation needs its
own narrowly reviewed preview, admission, effect receipt and
uncertainty/replay safety: this V1 linter is deliberately READ-only.

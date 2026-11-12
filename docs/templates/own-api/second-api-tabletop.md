# Second own API: independent-profile tabletop exercise (offline)

## Setup

The deliberately fictional service **metricsprobe** has a single fixed,
read-only API operation with target "service". No host, Docker network,
CA key/certificate, token, service principal or source repository exists.
Do NOT attempt to start it or send an HTTP request. This scenario tests
whether an agent can reuse the own-API steps without copying Mirror privileges.

Source-only manifest: [second-api-docker.fixture.json](second-api-docker.fixture.json).
Compare it to [mirror-read.example.json](mirror-read.example.json).

## Rehearsal procedure

1. Record a new upstream owner and repository; since this is a fixture,
   sourceSha=null and sourcePinned=false must appear in the result. STOP
   before any release until there is a real accepted source SHA.
2. Select DOCKER-HTTPS. The hypothetical service DNS metricsprobe:443
   requires an independently verified shared Docker network and cert SAN.
   It MUST NOT reuse Windows host.docker.internal, Mirror CA or Mirror token.
3. Verify that API source would implement GET /v1/status and forbid POST,
   redirect, wildcard targets and arbitrary path/query parameters. No
   implementation is present here, so these gates are PENDING.
4. Describe the least privileged upstream account metricsprobe-reader and
   a separate Gateway vault alias metricsprobe-link. Do not create them.
5. Run the exact static linter from the task worktree for this fixture;
   expected status SOURCE_MANIFEST_VALID, transportProfile DOCKER-HTTPS,
   sourcePinned=false, liveVerified=false, readyToDeploy=false.
6. Run the 20 negative/positive unittest cases; they must reject HTTP, port
   18756, hostname mismatch, network mismatch, public CA fallback, secret
   fields, POST/ASK/WRITE, wildcard target and path traversal.
7. Fill [evidence.template.md](evidence.template.md) with every host/release/
   live check left PENDING. Give [handoff.template.md](handoff.template.md)
   to the next owner/chat. Its next authorized operation is to establish
   actual upstream source, HTTPS/443 and rollback in a separate task, NOT
   call Gateway Apply.

## Observed source-only result

The local source rehearsal ran both Mirror WIN-HTTPS and metricsprobe
DOCKER-HTTPS manifests; both returned SOURCE_MANIFEST_VALID but
liveVerified=false and readyToDeploy=false. The metricsprobe fixture remains
un-pinned; the 20-unit-test static suite passed. No API was deployed.

- Actual Gateway Mirror source exists, but Mirror live catalog/READ
  still require separately accepted owner release and old-image recovery.
- No fake "metricsprobe" service/Gateway operation has been created.
- This is a successful *offline tabletop* / transport-profile
  differentiation, not an independent second-chat reproduction, installed
  API, HTTPS handshake, vault readiness, or LIVE_API_VERIFIED.
- Final milestone OWN_API_ONBOARDING_REPRODUCIBLE_VERIFIED remains PENDING
  until independent owner review and documented second-party reproduction.

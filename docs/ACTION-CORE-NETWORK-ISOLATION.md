# Action Core READ — owner-controlled network isolation

**Status: source-only candidate; NO Windows Firewall, Docker, Gateway or
PostgreSQL changes executed by this task.** This is a UC-GW-012 admission
prerequisite, not live READ acceptance or a new release controller.

## Boundary and provenance

The existing feedbrain HTTP/8000 API is intentionally unauthenticated.
Read-only Windows probes on 2026-11-17 reached it from the Gateway by both
host.docker.internal:8000 and the direct API container IP. Docker/Windows
NAT collapsed those connections and Windows localhost to the same API peer;
a post-NAT source-IP ACL cannot distinguish them.

| Network | Driver / owner | Members in the accepted design |
| --- | --- | --- |
| feedbrain_default | Existing Compose bridge | Local HTTP API, workers, PostgreSQL |
| fortis-actioncore-db | Internal bridge, Action Core owner | PostgreSQL, native HTTPS ingress |
| fortis-actioncore-net | Internal bridge, Action Core owner | Native HTTPS ingress, Fortis Gateway |
| fortis-gateway-egress | Non-internal bridge, Fortis owner | Fortis Gateway, approved outbound path |

Action Core [Compose network PR #19](https://github.com/AlexPastukhh/feed_and_search_and_bank_and_brain/pull/19)
is a separate source candidate, not a deployed configuration. Only the
Fortis owner release controller attaches the staged Gateway to
fortis-actioncore-net; **never manually run docker network connect**.
The Gateway must not join either feedbrain_default or fortis-actioncore-db.

## Read-only Check and fail-closed Apply

The **existing** Windows PowerShell 5.1 Manage-Integrations.ps1 controller
accepts explicit -EnableActionCoreNetwork only for approved-image Check/Apply
with a pinned merged source SHA. It is DENY for Auto, credential, return,
backup and promotion flags; rollback itself reads the protected attempt
record and does not require the flag. A checked image record binds the flag
and both exact 64-hex Docker network IDs. An existing networked source
cannot silently downgrade to the default Docker bridge.

Check reads, but never creates or changes, these owner-side prerequisites:
- Running Docker Desktop backend processes from the single reviewed
  C:\Program Files\Docker\Docker\resources\com.docker.backend.exe path.
- An **enabled outbound Block** Windows Defender Firewall rule named
  Fortis-DockerBackend-Block-TCP8000 in ActiveStore, with program set to
  that exact binary, TCP remote port 8000, and any local port, addresses,
  interface, service and profile. All three firewall profiles must be on.
- Distinct existing local Docker bridge IDs, correct internal flags and
  owner/purpose labels for both fortis-gateway-egress and fortis-actioncore-net.
- A running Compose feedbrain-api-1 with project/service labels, direct
  feedbrain_default IPv4, no unreviewed container IPv6 address, and
  Windows-only 127.0.0.1:8000 publication.
- Windows-local HTTP GET 127.0.0.1:8000/health/live returns 200.
- Public config includes only Action Core read_action (ALLOW, targets 3/4,
  vault alias action-core-read) for this upstream service.

The Windows firewall rule is **a separate owner mutation**, not installed
by this PR or automatically by the Gateway manager. It is broad for
Docker backend TCP/8000 egress, not just Action Core; assess other Docker
workloads before installing it. Its existence is not proof that Docker
Desktop applied the rule to all container-originated paths.

## Staged cutover and recovery

After UC-GW-009 global unresolved requests, claimed workers, independent
quiescence and protected old-image/restore admission, Apply repeats the
read-only boundary preflight **before** STOP_SOURCE. It persists the
reviewed network IDs in the same owner release record and creates the
new Gateway on fortis-gateway-egress, not the Docker default bridge.
It then uses a single controller-owned Docker network connect to attach
fortis-actioncore-net **before the candidate starts**.

The normal Guard admits exactly these two network names **and IDs**,
rejecting a missing, swapped or third endpoint. The legacy bridge remains
admitted only for the original source and review; no implicit expansion.
The sole partial-attachment exception is for a never-started, phase=Created
release candidate, and is permitted only to resume the same owner release
or return to the immutable old source. No partial topology can activate.

Before activation, the candidate itself executes read-only TCP connection
tests to both host.docker.internal:8000 and the actual reviewed local
API container IPv4:8000. **Any successful connection blocks activation.**
Windows localhost GET must remain healthy. DNS failures, mismatched
labels, network IDs, firewall rule, config, receipts or partial container
identity also stop release; the ordinary Return/attempt journal is preserved.
These tests are not equivalent to a live proof until performed on Windows.

## Upstream PostgreSQL admission before Primary Gateway release

Action Core Compose configuration is not proof that its Windows PostgreSQL,
API or native HTTPS upstream have been deployed. Its `db` service joins the
existing `feedbrain_default` and the new internal `fortis-actioncore-db`,
which may require **recreating the running PostgreSQL container**. That is
a separate upstream owner maintenance effect, not part of the Fortis Gateway
owner release and not authorized by a source merge or network Check.

**STOP Gateway Check/Apply** until the Action Core owner has separately:

1. Verified an application-scoped PostgreSQL backup with independent isolated
   restore, pinned original image and exact retained RW production PGDATA
   volume; retained private baseline runtime configuration and reviewed
   **operational rollback** to the prior DB network with a single writer.
   Neither a historical Compose file, an encrypted Docker-inspect snapshot,
   nor a successful logical restore proves an executable zero-loss rollback.
2. Enforced a coordinated **no-new-write** maintenance window for RSS/Action
   workers, scheduler, API write ingress and other DB clients; verified no
   in-flight jobs, external effects or transactions **after** admission was
   fenced. A single zero-count snapshot or worker SIGTERM is not quiescence.
   Approved any necessary API interruption separately.
3. Completed only the explicitly owner-approved, reviewed service-scoped
   PostgreSQL/network change **without** running Alembic migrations, doing
   blanket Compose service reconciliation or replacing PGDATA. Confirmed
   correct Compose-managed internal network IDs/labels, original default
   network retention, PostgreSQL health/data, Windows-local API live/ready
   endpoints, clients and workers reconnect, and owner restoration of
   admission after checks.
4. Provisioned the **separate** ingress bridge, upstream TLS/443 listener,
   reviewed SAN/CA and scoped verifier/credential, with direct HTTPS probe
   evidence. This must precede Gateway Check/Apply; never stage an HTTP/8000
   fallback, and never manually attach the Primary Gateway.

The Fortis owner independently assesses collateral Docker-backend-wide
TCP/8000 Firewall impact, obtains separate approval and verifies both
HTTP bypass negatives plus the Windows localhost positive check. Only the
Fortis owner release controller attaches the Gateway to ingress and admits
the exact pinned two-network topology; a pre-created egress bridge alone
does not prove this release-ready state.

The upstream recovery and quiescence contract is owned by the Action Core
`docs/GATEWAY-COMPOSE.md` runbook and UC-CONT-021/022. Existing
UC-GW-009 global unresolved/claimed work, previous immutable Gateway image,
protected state records, manual first `-EnableActionCoreNetwork` Check/Apply
and UC-GW-005/006/007 controls remain **separate**, mandatory STOP gates.

## Owner preparation and separate approvals

1. Obtain owner-approved upstream PR #19 and Gateway source PR; verify both
   owner-merged exact SHAs and clean Windows main before any release.
2. Back up the existing Windows firewall policy/owner state; confirm the
   backend binary and dependent Docker workloads. Owner may then install
   the narrowly scoped rule shown below **only after independent review**.
3. Provision fortis-gateway-egress as a labelled non-internal bridge and
   fortis-actioncore-net via the upstream reviewed Compose deployment.
   Network creation is owner provisioning; attaching the Gateway is
   exclusively a protected Manage-Integrations Apply operation.
4. Provision upstream TLS, SAN, owner pinned CA and Action Core scoped
   credential using the existing vault. Do not put bearer in source/env.
5. Perform Fortis Gateway owner SelfTest, Check -Build with the explicit
   network flag and the fresh UC-GW-009 preservation scope, then a separate
   owner-confirmed checked-image Apply, readback, Backup and Promote.
6. Verify TLS/Host/certificate negatives and one-shot READ Acceptance
   for Action IDs 3 and 4. WRITE remains a separate UC-GW-003 phase.

### Owner-only examples — NOT executed

First export the Windows firewall policy to an owner-protected backup
using netsh advfirewall export, and separately record the existing Docker
networks and running containers. In elevated Windows PowerShell, after
reviewing policy impact and verifying that the rule does not already exist:

    New-NetFirewallRule -Name 'Fortis-DockerBackend-Block-TCP8000' `
        -DisplayName 'Fortis Docker backend TCP 8000 egress block' `
        -Direction Outbound -Action Block -Enabled True -Profile Any `
        -Program 'C:\Program Files\Docker\Docker\resources\com.docker.backend.exe' `
        -Protocol TCP -RemotePort 8000

Owner-created egress network **only if absent**, following network
inventory and backup of the existing Docker configuration:

    docker network create --driver bridge `
        --label io.fortis.owner=fortis-approvals `
        --label io.fortis.purpose=gateway-egress-v1 fortis-gateway-egress

These example commands **change Windows/Docker state**. They are not
preflight instructions to execute automatically. Do not manually attach,
detach or reconnect a running Gateway; use the existing release controller.
Do not delete either network or firewall rule while any accepted release
depends on them. Rollback must use the protected release records and owner
review; removing the firewall rule restores Docker backend access to
TCP/8000 and may re-open the security bypass.

### Validation boundary

Pure-Python Guard tests and static source checks do not prove real Windows
PowerShell 5.1 parsing, Docker Desktop NAT, firewall effectiveness, lossless
state clone, live TLS/443 or safe rollout. The owner needs real host
SelfTest, Check, image/source readback, negative/positive probes and an
isolated recovery test. UC-GW-012 live Acceptance remains STOP until then.

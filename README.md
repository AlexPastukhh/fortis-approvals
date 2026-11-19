# Fortis Approvals

**Required first read for every new Fortis Repo chat:** open the active container
use-case registry through `/workspace/repo/README.md` (its first section links
straight to the registry); **read only the short registry introduction**,
without scanning the whole table, then **read these three UCs in full**:
**UC-CONT-002** (Docker → GitHub → CI → Windows/Mirror),
**UC-CONT-003** (GitHub only through the supported typed client + Fortis Gateway)
and **[UC-GW-009](docs/use-cases/incidents.md#uc-gw-009)**
(UNCERTAIN: full read-only investigation and owner-only close).
Other cases are selected as needed. The shared mandatory-reading rule
is owned by the container registry, not copied here.

Canonical source for the Fortis Approvals Gateway: typed service operations,
ALLOW/ASK/DENY policy, owner WebAuthn decisions and durable execution receipts.
Provider credentials remain in Gateway; Repo uses a separate machine grant.

## Documentation through use cases

The container registry owns cross-project Docker/Gateway/client/token/GitHub,
CI and Windows/Mirror goals; this repo owns technical contracts, deployed state
and evidence. Do not create a second shared registry. New application-specific
scenarios belong to their application repository. See [AGENTS.md](AGENTS.md)
for the agent entrypoint and scoped ASK-proposal authorization.

## Start here

| Need | Document |
| --- | --- |
| What is deployed and verified | [Current state](docs/guides/FORTIS-APPROVALS-SECURE-DEVELOPMENT.md) |
| AI usage and adding a service | [Gateway agent guide](docs/GATEWAY-AGENT-GUIDE.md) |
| Gateway-specific Use Cases accepted in main | [Local UC index](docs/use-cases/README.md) |
| Native worktree commands and policy | [Native Git/worktree workflow](docs/NATIVE-WORKTREE-GATEWAY-2026-11-06.md) |
| Completed live GitHub cycle | [Live evidence, 2026-11-06](fortis_approvals/evidence/FORTIS-NATIVE-GIT-LIVE-20261106.md) |
| Remaining work | [Follow-up plan](docs/BACKLOG-IMPROVEMENTS.md) |
| Code and deployment references | [Source map](fortis_approvals/README.md), [deployment index](fortis_approvals/deploy/README.md) |
| All documentation and provenance | [Documentation map](docs/README.md) |

## Development

Use a linked task worktree; the primary clone stays on `main`. Run commands
from the repository root. See [CONTRIBUTING.md](CONTRIBUTING.md) for dependencies,
offline checks and source manifests. The agreed cross-project directory and
Windows handoff rules belong to the [Mirror workflow](https://github.com/AlexPastukhh/docke-windows-mirror/blob/main/docs/WORKFLOW.md).

The standalone repository was extracted from `rd-graphs/fortis_approvals`;
the original subtree remains untouched. The [extraction audit](docs/audits/SOURCE-EXTRACTION-2026-11-03.md)
and [manifest policy](docs/SOURCE-MANIFESTS.md) preserve provenance.

Source changes do not deploy a Gateway image or update a Windows clone.
Never commit credentials, private keys, machine grants or runtime databases.
Historical provisioning/cutover scripts are not routine development commands.

## Optional Owner Portal PowerShell

The Owner Portal **PowerShell** tab uses a separately provisioned mTLS
Windows Executor. Owner-reported PS-V1-09 opt-in and the first real `Get-Date`
execution are accepted as **functional evidence**; full session/CSRF/receipt
safety acceptance is still open. Analyzer and second-AI controls remain disabled.
See [current state](docs/guides/FORTIS-APPROVALS-SECURE-DEVELOPMENT.md),
[Owner PowerShell contract](docs/OWNER-POWERSHELL.md) and the
[single backlog](docs/BACKLOG-IMPROVEMENTS.md#powershell-plan).

The machine route is already active in **ASK-only V1**; no automatic command
ALLOW or owner command-policy editor is installed. The [PowerShell plan](docs/BACKLOG-IMPROVEMENTS.md#powershell-plan)
defines the next architecture: an owner-editable **outer method policy**
(`DENY/ASK/ALLOW` for all Gateway providers) and an Executor-only **inner
Dynamic ASK** per command. Outer ALLOW never bypasses Windows evaluation.
The [Executor backlog](https://github.com/AlexPastukhh/fortis-powershell-executor/blob/main/docs/BACKLOG-IMPROVEMENTS.md#executor-dynamic-ask)
owns Windows rules and acceptance. Source changes alone enable neither layer.

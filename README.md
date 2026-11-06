# Fortis Approvals

Canonical source for the Fortis Approvals Gateway: typed service operations,
ALLOW/ASK/DENY policy, owner WebAuthn decisions and durable execution receipts.
Provider credentials remain in Gateway; Repo uses a separate machine grant.

## Start here

| Need | Document |
| --- | --- |
| What is deployed and verified | [Current state](docs/guides/FORTIS-APPROVALS-SECURE-DEVELOPMENT.md) |
| AI usage and adding a service | [Gateway agent guide](docs/GATEWAY-AGENT-GUIDE.md) |
| Native worktree commands and policy | [Native Git/worktree workflow](docs/NATIVE-WORKTREE-GATEWAY-2026-11-06.md) |
| Completed live GitHub cycle | [Live evidence, 2026-11-06](fortis_approvals/evidence/FORTIS-NATIVE-GIT-LIVE-20261106.md) |
| Remaining work | [Follow-up plan](docs/FOLLOW-UP-PLAN.md) |
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

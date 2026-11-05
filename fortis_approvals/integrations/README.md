# Provider integrations

This directory is the home for provider-specific contracts, Gateway adapters, Repo-side typed clients, tests, policy registration notes and deployment instructions.

| Integration | Status | Source of truth |
|---|---|---|
| [SonarCloud](sonarcloud/README.md) | Live; source migrated | Provider code lives in `gateway/` and `repo_client/`; root-level imports are compatibility shims |
| [GitHub](github/README.md) | Implemented in source; NOT registered or deployed | Typed contract, fixed-origin transport, Gateway adapter, registration helper and Repo client; no actor grants, policy or credential |
| [_integration_template](_integration_template/README.md) | Template | Copy for a new provider; never enables an integration |

Shared Core, Owner Portal, machine ingress, authentication and Gateway transport remain in shared package locations. Provider folders must not create duplicate authentication systems or owner approval queues.

An integration is enabled only when its adapter, strict typed contract, actor grant, policy, client operation, tests and deployment are all explicitly connected. A token or folder alone never enables access.

See [modularization and GitHub onboarding plan](../../docs/INTEGRATION-MODULARIZATION-AND-GITHUB-ONBOARDING-PLAN.md).

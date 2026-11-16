# Provider integrations

This directory is the home for provider-specific contracts, Gateway adapters, Repo-side typed clients, tests, policy registration notes and deployment instructions.

| Integration | Status | Source of truth |
|---|---|---|
| [SonarCloud](sonarcloud/README.md) | Live; source migrated | Provider code lives in `gateway/` and `repo_client/`; root-level imports are compatibility shims |
| [GitHub](github/README.md) | Opt-in native profile **live in Primary** `fortis-gateway`; not enabled in retained stopped Sonar-only Legacy | Provider schema/REST adapter/client here; native policy, Git bundles and worker under `../workflow/`. See the [native contract](../../docs/NATIVE-WORKTREE-GATEWAY-2026-11-06.md) and [current state](../../docs/guides/FORTIS-APPROVALS-SECURE-DEVELOPMENT.md) |
| [Observatory](observatory/README.md) | Read-only source candidate; **not configured or deployed** | Extension provider for fixed health/session reads; separate network and credential acceptance required |
| [Action Core](action_core/README.md) | Read-only source candidate; **not configured or deployed** | Fixed HTTPS Gateway READ for Actions 3/4; owner-provisioned CA, bearer and network isolation acceptance required |
| New provider packages | Scaffold | `python3 -m fortis_approvals.extensions.cli scaffold --source-root . --name <service>`; [contract](../../docs/INTEGRATION-EXTENSIONS.md) |
| [_integration_template](_integration_template/README.md) | Historical manual layout | Existing integrations only; new providers use the shared extension mechanism |

Shared Core, Owner Portal, machine ingress, authentication and Gateway transport remain in shared package locations. Provider folders must not create duplicate authentication systems or owner approval queues.

An integration is enabled only when its adapter, strict typed contract, actor grant, policy, client operation, tests and deployment are all explicitly connected. A token or folder alone never enables access.

See [modularization and GitHub onboarding plan](../../docs/INTEGRATION-MODULARIZATION-AND-GITHUB-ONBOARDING-PLAN.md).

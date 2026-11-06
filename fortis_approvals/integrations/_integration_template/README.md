> For new providers use the [shared extension scaffold and contract](../../../docs/INTEGRATION-EXTENSIONS.md). This older manual wiring template is retained for existing integrations.

# New provider integration template

**Status:** template only. Copy this folder to a provider-specific directory and replace every placeholder before implementation.

## Required contents

- `README.md`: purpose, status, trust boundary, credential location, provider scopes, operations, policies, client usage, testing, deployment and rollback.
- `contract.py`: exact typed operation names, target syntax, required fields, bounds and public response projection.
- `gateway/`: provider-specific adapters with fixed origins, methods and routes; no generic URL/method/body proxy.
- `repo_client/`: provider-specific typed client using shared Gateway transport; no provider credential.
- `tests/`: schema, actor grants, policy, response validation, redirects, size limits, redaction and approval lifecycle.
- `deployment/`: secret mount declaration, provisioning procedure, image manifest changes and owner-reviewed release steps.

## Enablement checklist

1. Select the minimum upstream credential scopes and resource allowlist.
2. Provision credentials only on the Gateway side.
3. Register typed contracts, adapters, actor grants and operation-level policies.
4. Keep READ and mutation paths separate.
5. Make unknown operations fail closed.
6. Pass offline tests and owner-reviewed live acceptance before deployment.

Do not create a new Core, machine authentication scheme, owner portal or approval queue for an individual provider.

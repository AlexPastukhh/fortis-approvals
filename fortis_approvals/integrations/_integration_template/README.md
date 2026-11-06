# New provider integration template

**Status:** template only. Copy this folder to a provider-specific directory and replace every placeholder before implementation.

For an existing integration, extend its package and use the
[change card](OPERATION-CHANGE.md); copying this entire folder is unnecessary.
The [shared workflow](../../../docs/OPERATION-ONBOARDING-WORKFLOW.md) owns the
stage order and release/feature completion criteria.

## Required contents

- `README.md`: purpose, status, trust boundary, credential location, provider scopes, operations, policies, client usage, testing, deployment and rollback.
- `contract.py`: exact typed operation names, target syntax, required fields, bounds and public response projection.
- `gateway/`: provider-specific adapters with fixed origins, methods and routes; no generic URL/method/body proxy.
- `repo_client/`: provider-specific typed client using shared Gateway transport; no provider credential.
- Registration/composition reference: how shared envelope validation, trusted intent construction, result projection/delivery, owner preview/strong approval, adapter and grants/policies are connected. A folder alone is not registration.
- `tests/`: schema, actor grants, policy, response validation, redirects, size limits, redaction and approval lifecycle; explicitly include the new provider in the supported test collection.
- `deployment/`: secret mount declaration, provisioning procedure, image manifest changes and owner-reviewed release steps.

## Enablement checklist

1. Select the minimum upstream credential scopes and resource allowlist.
2. Provision credentials only on the Gateway side.
3. Register typed contracts, adapters, actor grants and operation-level policies.
4. Keep READ and mutation paths separate.
5. Make unknown operations fail closed.
6. Prepare the complete activation config, scopes and live probes before owner release.
7. Pass offline checks, deploy/activate in the approved target, then perform owner-reviewed live acceptance. An image with disabled operations is not feature acceptance.

Do not create a new Core, machine authentication scheme, owner portal or approval queue for an individual provider.

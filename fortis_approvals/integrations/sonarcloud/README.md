# SonarCloud integration

**Status:** live in the deployed Gateway; source implementation has been moved into this provider package. Legacy root module names remain as import/CLI compatibility shims.

## Canonical implementation locations

- Gateway write adapter and Sonar HTTPS transport: `gateway/sonar.py`.
- Gateway read-only adapter: `gateway/read_adapter.py`.
- Bounded project inventory: `gateway/inventory.py`.
- Owner-only read probe and preflight: `gateway/probe.py`, `gateway/preflight.py`.
- Repo typed client: `repo_client/client.py`.
- Repo review/status workflow: `repo_client/workflows.py`.
- Sonar-specific operation schemas: `contract.py`.
- Shared machine transport: `../../clients/gateway_transport.py`.
- Shared envelope/broker and ingress: `../../repo_action_contract.py` and `../../repo_ingress.py`.

Compatibility modules at `fortis_approvals/sonar.py`, `sonar_read.py`, `sonar_inventory.py`, `sonar_probe.py`, `sonar_preflight.py`, `repo_sonar_tools.py` and `sonar_review_scenario.py` re-export the canonical modules. New code must import the canonical integration paths.

## Current operations

- READ / ALLOW: list projects, list issues, get issue, get quality gate.
- ACTION / ASK: propose `accept_issue`; only owner WebAuthn approval can execute the Sonar mutation.
- STATUS: the initiating machine actor can read its request state.

## Credential and trust boundary

The upstream Sonar token is Gateway-only at `/run/r7-sonar-token/token`, supplied through the existing separate read-only volume. Fortis Repo receives only its distinct machine ingress grant and Gateway public certificate. Do not move, rename or reprovision the live Sonar volume during this refactor.

The migration preserves current operation names, response projections, policy, request IDs and approval lifecycle. The live GET was repeated through the migrated Repo client and shared transport on 2026-11-05; `get_quality_gate` returned `OK` for `AlexPastukhh_obs-planning-docs` with `scope=CURRENT_DEFAULT_BRANCH` and `prShaBinding=NOT_VERIFIED_D2` ([evidence](../../evidence/FORTIS-SONAR-LIVE-GET-AFTER-MODULARIZATION-20261105.md)). That 2026-11-05 probe did not change the deployed image. The subsequent isolated native review includes the provider package and passed Sonar GET again; Production remains on its earlier image. Compatibility wrappers remain for callers. See [current state](../../../docs/guides/FORTIS-APPROVALS-SECURE-DEVELOPMENT.md).

The optional [analysis-review source contract](../../../docs/ANALYSIS-REVIEW-CONTRACT.md) adds scoped analysis/issues/rules/measures/history reads, compatibility hotspot reads and owner-approved issue edits. It requires explicit trusted configuration and a separate reviewed deployment; it does not change the accepted live scope above. Its composed report distinguishes CI metadata from Sonar revision evidence and current findings from historical analysis. ACCEPTED remains a triage decision, not a code fix.

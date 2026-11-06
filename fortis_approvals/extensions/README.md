# Shared operation extensions

The [extension contract](../../docs/INTEGRATION-EXTENSIONS.md) owns onboarding,
config, policies, credential handling, client usage and deployment. Provider code
belongs in `../integrations/<service>/extension.py`; this package owns shared code.

| Module | Responsibility |
| --- | --- |
| model.py | Trusted Provider/Operation definitions and selected source discovery |
| runtime.py | Strict config, actor/target policy, shared Core adapter and catalog |
| vault.py | Private named-volume IO, generation binding, atomic CAS rotation |
| http.py | Fixed-origin named JSON routes and Gateway-only authentication |
| ingress.py / client.py | Three closed machine routes and common Repo client |
| cli.py | Scaffold, config check, confidential owner provisioning and read probes |
| staging.py | Owner-controlled activation after release readback |

Default is disabled; reserved existing providers retain their contracts. Unit,
security and source packaging checks run in `scripts/test-source.sh`.

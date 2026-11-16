# Action Core — typed Gateway READ

Source candidate for UC-GW-012 DOCKER-HTTPS. This provider exposes one operation only:
`action_core.read_action` (`kind=read`) for exact targets `"3"` and `"4"`, with empty params.

## Fixed upstream contract

- Origin: `https://action-core-gw:443`; TLS name: `action-core-gw`.
- Route: `GET /gateway/v1/actions/{action_id}`; no query, body, suffix or redirect.
- Result: exactly `action_id`, `name`, `category`, `current_version_number`,
  `definition_yaml`, `schedule_active`; canonical JSON bounded to 65,536 bytes.
- The provider uses the existing `fortis_approvals.extensions.client.default_client()`
  and common catalog/call/result, ALLOW/DENY, actor, receipt and vault framework.
- The owner-provisioned public CA certificate is read from
  `/run/fortis-secrets/action-core-read/ca.pem`. The TLS server private key
  stays only in the upstream owner runtime.
- The existing Gateway vault alias is `action-core-read`; upstream principal is
  `action-core-gateway-reader`. The raw bearer is never stored in this repository.

## Public config shape

```json
{
  "schemaVersion": 1,
  "providers": {
    "action_core": {
      "credentials": {"read": "action-core-read"},
      "operations": {
        "read_action": {"policy": "ALLOW", "targets": ["3", "4"]}
      }
    }
  }
}
```

## Security and activation

This provider does not expose Action creation/version publication, schedules, runs,
run history, source/search APIs or External AI registration. It has no WRITE operation.
Public config/manifest is not proof of TLS, network isolation, vault readiness or runtime. The UC-GW-012 own-API manifest must pin the exact owner-merged Action Core main SHA; do not publish a placeholder or source-branch SHA.

Before owner release, prove from the real Gateway namespace: exact Docker network and DNS,
TLS SAN/CA/expiry, wrong CA/SAN/Host, no redirects or HTTP fallback, no route to the
unauthenticated local API on port 8000, and bearer 401/403. Use UC-GW-012 Doctor and
one-shot Acceptance; do not create a second client, vault, approval engine or controller.

# Extension framework activation — 2026-11-06

## Owner-reported Windows execution

After the env-controller repair, the owner pulled accepted main, reused the
already-built immutable image and ran Apply. Public-env preflight, state clone,
staged catalog verification and activation passed. Output:

- `FORTIS_INTEGRATIONS_ACTIVATED`, active=true.
- Image `sha256:bbbcda6a5ff86f8d58602f0dff61196d984d19ba15ccd0c39c903b30caf08cba`.
- Protected record `%LOCALAPPDATA%\Fortis\GatewayReleases\1fe554004e7c41ffb6be3405be9f4518\record.json`.
- Previous retained=true; Production unchanged=true.
- providerMutationAcceptance=PENDING_OR_NOT_APPLICABLE.

## AI live readback through Gateway

Using the Repo grant/TLS typed clients, without provider tokens, GitHub connector
or legacy helper:

- Extension catalog returned configuration digest
  `19632eb46e842ded25d4abf7fc1b41e586e7b536a0f414bbbf133adb69252271` and operations=[].
- Native capabilities and GitHub branch reads passed; main was `a1bb13415191cf4e22d295996a154864d3fb9af0`.
- Existing Sonar quality-gate read passed: CURRENT_DEFAULT_BRANCH OK,
  prShaBinding=NOT_VERIFIED_D2.
- Optional Sonar analysis `list_project_branches` was denied with HTTP 403.

This verifies extension wiring/catalog activation with empty provider config and
legacy regression reads. It does not verify a new provider/token, mutation, PR
analysis binding, or optional analysis profile. The image/host lifecycle and
Production-preservation statements above are owner-reported; no Docker Engine
inspection or Windows private-record copy was performed by AI.

Current state lives in the [state owner](../../docs/guides/FORTIS-APPROVALS-SECURE-DEVELOPMENT.md),
operation/activation contract in [extensions](../../docs/INTEGRATION-EXTENSIONS.md).
Earlier failure/recovery remains in [offline/recovery evidence](EXTENSIONS-OFFLINE-20261106.md).

# Scoped PR creation ALLOW — live acceptance, 2026-11-06

## Owner-reported deployment

The permanent `Manage-Integrations.ps1` Apply/Build/Pull path completed all steps
and emitted `FORTIS_INTEGRATIONS_ACTIVATED`:

- Source: `e48e59ae54b456a390a02a63551b8e4f2ea4a4fc` (PR #16).
- Image: `sha256:238ea3a43225eec4b714a0cf23c70559434c56a8b03f44b865ede40c70ca8242`.
- Protected record: `%LOCALAPPDATA%\Fortis\GatewayReleases\0a83fd2241944ad59c2e409a710c9484\record.json`.
- Configuration digest: `19632eb46e842ded25d4abf7fc1b41e586e7b536a0f414bbbf133adb69252271`.
- `active=true`, `previousRetained=true`, `productionUnchanged=true`.
- `providerMutationAcceptance=PENDING_OR_NOT_APPLICABLE`.

These host image/container facts come from the owner's output; Repo did not
inspect Docker or read the protected record. Previous records/state remain retained.

## Repo-to-Gateway readback

All requests used the existing typed client, machine grant and public certificate
against isolated review `https://host.docker.internal:19204`, not a GitHub connector
or the legacy Git credential helper.

- Capabilities: `allowGitHub=[push_commits, create_pull_request]`;
  `askGitHub=[mark_pr_ready, merge_pull_request, update_workflow_file]`;
  `sensitivePush=ASK`, `gitHubCredentialInRepo=false`.
- GitHub main read: `e48e59ae54b456a390a02a63551b8e4f2ea4a4fc`;
  Docker primary clean at the same SHA before this task.
- Extension catalog: same configuration digest as above, `operations=[]`.
- Existing Sonar `get_quality_gate`, request
  `9e359a70-a284-4e9c-99a9-7f0547cc07a1`: `OK`,
  `scope=CURRENT_DEFAULT_BRANCH`, `prShaBinding=NOT_VERIFIED_D2`.
- Registered documentation task creation, request
  `7e9a932a-7b65-47dc-b84f-f04ca5f89431`: `EXECUTED`.

## PR effect

Capabilities confirm policy installation. Actual PR creation acceptance will be
recorded here after publishing this documentation task through Gateway.

## Limits

The grant remains exact actor/configured repository, with registered task-to-main
checks; [native contract](../../docs/NATIVE-WORKTREE-GATEWAY-2026-11-06.md) owns
its conditions. This does not enable other repositories or change legacy pilots.
Other ASK policies and owner WebAuthn remain in effect.

No optional Sonar/CI analysis profile, new provider/token/effect, production
cutover or additional Windows Mirror behavior is accepted by these checks.
The existing default-branch Sonar gate does not prove analysis of a PR SHA.
Container documentation remains a local Git commit because its remote does not
exist; the Mirror documentation branch is published, without a claimed main merge.

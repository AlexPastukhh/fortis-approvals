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

An ordinary documentation PR, not a throwaway test, was created through the typed
GitHub client without a preliminary chat permission round or Owner Portal decision:

- Native task push: request `22ab5360-4e29-4c53-9b00-beaf79e9f424`, `EXECUTED`;
  readback preserved commit `b7acfaf328033ed2d41030b0730e83ad63bd1403`.
- PR creation: request `498ce727-d182-46c4-a398-77b911d564f5`, `EXECUTED`.
- GitHub readback: [PR #17](https://github.com/AlexPastukhh/fortis-approvals/pull/17),
  open, `draft=false`, head `task/pr-allow-live-evidence-20261106` at that exact
  commit, base `main` at the deployed source SHA.

This confirms the real create effect under ALLOW, beyond capability advertisement.
The receipt is added by a subsequent documentation commit on the same PR. CI for
that final head and owner-approved merge remain separate steps, not claims made
by the creation receipt. Source manifests, modified Markdown targets, whitespace,
Gateway syntax and the 18-case registry/workspace navigation checks passed.

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

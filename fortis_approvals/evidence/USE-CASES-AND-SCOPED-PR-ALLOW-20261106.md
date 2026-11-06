# Use cases, ASK submission and scoped PR ALLOW — 2026-11-06

## Ordered source work

1. Container registry and DRY navigation: 18 cases in local `fortis-container`
   commit `0ac39b85e12873987a8e2f82b7b9482bf1ea31a0`. Workspace README/AGENTS
   managed projections are installed and checked. Existing text/dirty primaries
   were preserved. The owner confirmed there is no remote repository yet.
2. Needed ASK proposals are submitted without preliminary conversational consent;
   Owner Portal still approves the effect. The rule is in workspace/repo AGENTS,
   the container case and Gateway/native guide. Documentation source commit
   `d9509e1100cf9397ed1d1bf603fe1c664892f179` precedes the policy implementation.
   Outer tool review is not disabled or bypassed.
3. Native PR ALLOW is only for the exact installed actor/configured repository.
   Generic ASK, other actors/repos and task/main checks remain. Capabilities read
   that rule from Core. This is a source change, not a deployed-policy claim.

Mirror branch `task/container-use-cases-20261106` was published/read back at
`5c1f1e1898fa95822f9a103de353e3cf71b12929` using its existing explicitly authorized
legacy Git helper, without reading credentials; this was not Gateway publication.
Its pre-existing Worktree convention text is included; dirty primary was retained.
No remote was created for Container, and no unrelated changes were committed.

## Validation

- Registry: 18 unique goals/how/completion sections and local references PASS.
- Workspace projection --check, modified Markdown targets and whitespace PASS.
- Native suite: 16 PASS, real Git/TLS/Core with offline upstream. Covers PR without
  owner session, draft, replay/conflict, lost response/no repeated POST, foreign
  repo/base/unregistered ref denial, unknown actor DENY, foreign-target ASK fallback,
  and unchanged ready/merge/workflow/cleanup ASK.
- Supported source suite: 398 PASS, exit 0. No live PR was created to test the
  new policy, no provider secrets or Docker/Windows substitute was used.
- Manifests and Gateway syntax are verified before commit.

## Live boundary at source validation

Existing review still advertises create_pull_request in askGitHub. A new accepted
Gateway image is required for ALLOW. Legacy pilot policies remain unchanged.
Extension activation evidence separately records empty catalog, native/GitHub/
legacy Sonar reads and optional analysis HTTP 403. New Sonar/CI operations and
new provider token/effect acceptance are not claimed.

## Subsequent deployment

The owner subsequently updated review. The resulting live capabilities and PR
creation effect are recorded separately in
[PR ALLOW live evidence](PR-CREATION-ALLOW-LIVE-20261106.md); the preceding section
retains the boundary observed during source validation.

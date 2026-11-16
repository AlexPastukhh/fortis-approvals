# P3.4 — controlled Release Label Publisher pilot input

**Source-only pilot fixture, not a release instruction or live acceptance.**
This deliberately inert documentation payload is for a fresh, registered
same-repository PR to `fortis-approvals/main`; only generated source manifests
may change in addition to this document.
It does not alter Gateway policy, install dependencies, create credentials,
modify runtime state or authorize a GitHub Label write.

## Intended owner-controlled observation

- Keep this PR **open and non-draft** while the owner separately verifies and
  activates the pinned P3.2/P3.3 trusted publisher through P3.4.
  Do not merge it merely to run the pilot.
- The one public exact-HEAD Release Impact validator should classify the
  changed documentation as `no-deployment`, with zero targets and a suggested
  `release:no-deployment` label. The two mandatory workflows are Source CI
  (`offline-tests`, `audit-projections`) and Fortis Release Impact
  (`release-impact`), all complete on the latest exact-HEAD attempts.
- The separately authenticated, owner-isolated publisher may **preview** this
  PR only after P3.4 admission. An actual `request` must create at most one
  existing typed `ASK` label operation and retain its original UUID and intent.
  The owner reviews the exact preview and decides through ordinary WebAuthn.
- After an approved effect, independently read back the same PR HEAD, the full
  label set, the original Core receipt and current CI. Preserve human labels,
  a manually set `release:review-required` flag, and all unrelated state.
  A known executed effect is not undone by a later failed READ.
- No owner decision, publisher principal, grant, worker, timer, network access,
  deployment receipt or runtime action is supplied by this repository file.
  `UNCERTAIN` is a STOP, not permission for a new write or duplicate ASK.

Use the accepted [P3 owner project](../RELEASE-LABEL-PUBLISHER-P3-REVIEW.md)
and the [publisher runner technical owner](../../fortis_approvals/integrations/github/PUBLISHER-RUNNER.md)
for the actual controls. This pilot input alone never proves P3.4 activation.

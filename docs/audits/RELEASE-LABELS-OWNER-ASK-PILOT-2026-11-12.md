# Release Labels owner-ASK pilot — documentation-only acceptance note

This note is a **controlled test fixture**, not a production installation
record and not an authorization to deploy, merge this PR, or automatically
modify GitHub labels.

## Purpose

Exercise the source-only Fortis Release Impact admission chain against a fresh
same-repository `task/* → main` PR based on the currently accepted Gateway
main. The intended candidate classification is **no-deployment**. A successful
pilot must independently verify the *latest attempts* and all completed jobs
for both **Source CI** and **Fortis Release Impact**, the exact PR HEAD/base,
full-history source diff and catalog, and the live GitHub label definitions.

The first mutation, if separately approved by the owner, should be a
**single** bounded Gateway `add_pr_release_labels` ASK for
`release:no-deployment`. An owner WebAuthn decision, a durable Gateway
receipt and a fresh GitHub PR/label readback are independent requirements.
This note supplies **no approval**, token, runner privilege or automatic job.

## Fail-closed checklist

- Do not merge the pilot PR merely to complete the label experiment; it must
  remain open while the exact-head label operation is reviewed.
- If either required workflow fails, is queued or rerun, STOP. A prior
  successful attempt does not override a later failure.
- If the PR HEAD, base, body, labels, registered task branch or relevant
  GitHub permissions change, re-evaluate from trusted reads, not CI artifacts.
- If the ASK is PENDING, wait for an explicit owner action in Owner Portal.
  If its outcome is unknown, inspect the **same request UUID** and receipt;
  never reissue the mutation with a new UUID.
- Keep all human labels and `release:review-required` untouched.
  `release:no-deployment` is only a planning classification, not a
  deployment or backup receipt.

This note and the automatically regenerated documentation source manifest
are the **only changed files** in the test PR. The Fortis Gateway image,
Windows controller and protected production release record are unchanged.

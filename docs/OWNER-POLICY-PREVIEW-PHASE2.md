# Owner Policy Preview — source-only Phase 2 (2026-11-19)

**Status:** isolated source PR candidate; not merged, built, installed or activated.

## Behavior

- Owner Session + exact Host/Origin/CSRF and no forwarded/Authorization header allows `POST /v1/owner/policy/preview` on the **Owner Portal origin only**. The same route is not on machine or provider ingress. Underlying Core/ExtensionRuntime authorization is **unchanged**.
- Request body pins `provider`, `operation`, `actor`, `target`, `expectedPolicyVersion`, `expectedConfiguredPolicy`, and `desiredPolicy` (strict object schema). Only **existing, active, exact actor+target grant rows** in owner inventory can be previewed. Wildcard/actor-wide, unconfigured, missing provider or callable/unknown-effective policies are denied.
- Output gives exact old/new configured/effective policy, deterministic **non-authorizing** preview fingerprint, risk, safe version/source digests, and counts of `PENDING`, `APPROVED`, `DISPATCHED`, `UNCERTAIN` requests for the exact actor/method/target as a point-in-time Core read. It never returns request payloads, credentials, tokens, raw vault aliases, endpoint secrets or evidence. Upstream is explicitly `UNVERIFIED`.
- `canApply=false` and `applyEnabled=false` for **all** previews, including no-op and DENY. No policy write, WebAuthn policy-change route, secret access, dispatch or new grant exists in this phase. A preview fingerprint is **not** an approval token and is not transferable to a later apply route.
- Native method kind/version is still often unknown; potentially effects are classified conservatively as HIGH. PowerShell policy preview is always CRITICAL and does not override Windows Dynamic ASK/ALLOW/DENY logic.
- The UI exposes a rule picker/desired value with a **preview-only** button. Results are rendered with `textContent`, never raw HTML. A fresh inventory READ clears a prior selection; no save button exists.

## Required next gates before policy mutation

A separate owner-only versioned policy store, durable audit, exact compare-and-swap against policy source/version and actor/target grant, source digest and credential generation pinning, strong fresh WebAuthn challenge **for the exact permission change**, race-safe recheck and rollback, restart/restore persistence with no implicit escalation, explicit owner release and negative concurrency/replay/revoke tests. Neither a session nor a preview grants apply authority. Upstream-effect methods continue to require their own ASK/approval at execution time; no PowerShell open-shell `ALLOW` until the Windows command-policy gate has passed separately.

## Tests

`python3 -B -m unittest discover -s fortis_approvals/tests -p test_owner_policy_preview.py -v`

Mandatory Source CI includes this test via `scripts/test-source.sh` and source manifests via `scripts/update-source-manifests.py`.

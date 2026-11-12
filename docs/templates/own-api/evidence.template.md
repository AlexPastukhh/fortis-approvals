# First-party API onboarding — evidence record template

Never write bearer credentials, TLS private keys, machine grants, raw Docker env,
protected record contents, or personal paths here. PENDING is NOT PASS.

| Gate | Result | Evidence reference / exact SHA or public hash | Actor / owner |
| --- | --- | --- | --- |
| Upstream owner source, tests and reviewed upstream release | PENDING | | |
| WIN-HTTPS or DOCKER-HTTPS reachable from actual Gateway network | PENDING | | |
| TLS hostname, owner-reviewed pinned CA, no redirect/fallback | PENDING | | |
| Scoped upstream principal; wrong/no bearer denied | PENDING | | |
| Owner vault alias READY; original Owner Shell unchanged | PENDING | | |
| Fixed Gateway provider/routes/closed request and result schema | PENDING | | |
| Wrong route/method/actor/target denied; size bounds | PENDING | | |
| Clean upstream and Gateway GitHub main, exact PR/merge SHAs and CI | PENDING | | |
| Global UNCERTAIN/CLAIMED/APPROVED and independent worker quiescence | PENDING | | |
| Previous Gateway image and isolated recovery evidence | PENDING | | |
| One-owner Gateway release Check/Apply and protected attempt | PENDING | | |
| Host running/healthy and native GitHub/Sonar/Owner Shell regression | PENDING | | |
| Typed Gateway catalog plus fresh ALLOW READ from actual upstream | PENDING | | |
| Wrong-scope negative tests and same UUID result/replay readback | PENDING | | |
| Backup/Promote, exact protected pointers and independent recovery | PENDING | | |

Public manifest path / SHA-256:
Upstream source SHA / Gateway merged SHA:
Approved operation and exact targets:
Credential alias only (never secret value):
Single owner release window / protected record reference:
Unresolved STOP conditions and responsible owners:

Outcome ladder (never skip): SOURCE_MANIFEST_VALID → SOURCE_READY →
PR_MERGED → IMAGE_ACTIVATED → LIVE_API_VERIFIED.
This template does not attest any stage. The static checker can validate only
the first stage and does not establish a trusted source or installed runtime.

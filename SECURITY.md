# Security policy

Fortis Approvals is a security-sensitive gateway. Please do not disclose
credentials, machine grants, WebAuthn material, runtime databases, private
keys, or live infrastructure details in public issues or pull requests.

## Reporting a vulnerability

Use GitHub's **private vulnerability reporting / Security Advisories** feature
for this repository. Do not create a public issue for an exploitable
vulnerability. If private reporting is not enabled, contact the repository
owner through the existing private project channel and include a safe
reproduction that contains no real secrets.

## Scope and expectations

- Do not test against live SonarCloud, GitHub, or production Gateway resources
  without explicit owner authorization.
- Do not submit real tokens, private keys, machine grants, cookies, or state
  databases in bug reports, logs, screenshots, or test fixtures.
- Security fixes must include offline regression tests and preserve the
  default-deny boundary.
- A provider token permission does not grant an AI actor permission to invoke
  an operation. Gateway registration, actor grants, policy, credentials, and
  deployment are separate owner-controlled decisions.

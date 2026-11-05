# GitHub pilot M1 — accepted 2026-11-06

Repository: AlexPastukhh/fortis-approvals.
Approved source: cd9af3ca6e43ec03134477beb2b284a837c67236.

The owner supplied the terminal result FORTIS_GITHUB_PILOT_LIVE_E2E_PASS.
The actual Repo client used the authenticated TLS Gateway ingress. Owner
Reject produced REJECTED and no branch; strong WebAuthn approval produced
EXECUTED and the exact frozen source SHA. The runner verified the durable
receipt and completed-request replay, Sonar returned OK, and the Production
baseline was unchanged. A separate Repo -> Gateway read confirmed the approved
branch SHA and the absence of the rejected branch.

This accepts approval-to-branch only. File/PR/CI coverage, Production rollout
and removal of legacy direct Git credentials remain subsequent work. Retain
M1 state, image, test branch and the operator receipt; no automatic cleanup.
No provider credential or private owner state is included in this evidence.

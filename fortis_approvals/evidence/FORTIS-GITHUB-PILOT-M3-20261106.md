# GitHub pilot M3 — accepted 2026-11-06

Runtime source: e8dd217e1279c5ec8e1ad6b4e2ff893d01aa5dbc.
Repository: AlexPastukhh/fortis-approvals; draft PR #8.
Selected head: a2cb4a59bf2251cc05301a9da17e3a9fd02a19ee.
Source CI: https://github.com/AlexPastukhh/fortis-approvals/actions/runs/42101319273.

The owner-run package reported FORTIS_GITHUB_CI_READ_LIVE_PASS, exit 0.
The actual Repo client read the exact workflow/run/event/branch/head through
the authenticated TLS Gateway ingress: completed, conclusion success,
ciPassed=true. An independent Repo -> Gateway call reproduced this result.
This accepts the Gateway read path, beyond the earlier connector observation.

M2 receipts were preserved and verified, Sonar returned OK, M2 remains retained
for return, and the Production baseline was unchanged. M3 performed no GitHub
mutation or new owner decision. Failed/pending CI reports remain distinguishable
from a successful read; a live PASS does not turn those reports into success.

The Source CI candidate passed 327 Python tests and 49 Windows checks before
source merge/package delivery. The limited pilot is accepted; merge, workflow
controls, Production rollout and retirement of legacy direct Git access remain
outside this result. Detailed operator metadata stays outside Git.

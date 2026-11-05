# GitHub pilot M2 — accepted 2026-11-06

Repository: AlexPastukhh/fortis-approvals.
Runtime source: cf0553d0690a693fcc3e11ac8d3685f61aefe86d.
Evidence commit: a2cb4a59bf2251cc05301a9da17e3a9fd02a19ee.
Draft PR: https://github.com/AlexPastukhh/fortis-approvals/pull/8.

The owner-run package reported FORTIS_GITHUB_FILE_PR_LIVE_E2E_PASS, exit 0.
One bounded UTF-8 file and one draft PR executed through the actual Repo
client, authenticated Gateway ingress, Core ASK and owner strong WebAuthn.
Both durable receipts and owner decisions were verified; completed request
replays passed; Sonar returned OK. Production baseline was unchanged and M1
was retained. A separate Repo -> Gateway read verified both EXECUTED statuses,
file digest, exact branch commit, and draft PR refs/head/base with main unchanged.

Source CI run https://github.com/AlexPastukhh/fortis-approvals/actions/runs/42101319273
passed for this test PR/head SHA. This CI observation used the GitHub connector;
CI visibility through Gateway is not yet accepted. The PR remains draft/open;
merge, workflow control, Production rollout and legacy credential retirement
are outside this result. Detailed operator metadata stays outside Git.

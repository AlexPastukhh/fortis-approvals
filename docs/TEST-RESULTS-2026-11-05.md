# Offline test results — 2026-11-05

**Result: PASS — 245 tests across 21 suites.**

Environment: Python 3.11.2 in the repository's pinned owner-runtime virtual environment.

Command:

```sh
PYTHON=/workspace/repo/.rdg-webauthn-venv/bin/python bash scripts/test-source.sh
```

| Suite | Tests | Result |
|---|---:|---|
| GitHub integration | 16 | PASS |
| SonarCloud package compatibility | 2 | PASS |
| Core lifecycle/policy | 28 | PASS |
| Gateway | 6 | PASS |
| Owner Portal | 18 | PASS |
| Owner Portal input | 7 | PASS |
| Runtime | 3 | PASS |
| Repo action contract | 12 | PASS |
| Repo ingress | 12 | PASS |
| Repo Sonar READ contract | 8 | PASS |
| Repo Sonar READ ingress | 14 | PASS |
| Repo Sonar tools | 12 | PASS |
| Sonar | 22 | PASS |
| Sonar inventory | 13 | PASS |
| Sonar preflight | 15 | PASS |
| Sonar probe | 8 | PASS |
| Sonar READ adapter | 15 | PASS |
| Sonar review scenario | 7 | PASS |
| R6 Repo→Sonar→Approvals TLS offline E2E | 4 | PASS |
| R7 unified candidate | 21 | PASS |
| Modularized candidate image COPY/import manifest | 2 | PASS |
| **Total** | **245** | **PASS** |

Additional checks:

- `python -B -m compileall -q fortis_approvals scripts/update-source-manifests.py` — PASS.
- `bash -n scripts/test-source.sh` — PASS.
- `python scripts/update-source-manifests.py --check` — PASS.
- `git diff --check` exited 0. The initial source tree is still untracked, so Git's diff check does not yet cover those files.
- Credential/runtime-artifact scan for `.env`, token, key, certificate, SQLite and database files — no matches.

The suite is offline. The R6 TLS test uses local test endpoints; it does not call GitHub or SonarCloud. Historical R4/R5 Windows image audit tests remain separate provenance checks because some require owner-held source archives outside this standalone repository.

These results validate the source tree and the candidate Dockerfile's exact COPY/import context. They do not represent a Docker image build, GitHub live test, Gateway deployment, token provisioning, policy grant or production acceptance.

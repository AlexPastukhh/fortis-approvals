#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
PYTHON="${PYTHON:-python3}"

"$PYTHON" -B -m unittest discover \
  -s fortis_approvals/integrations/github/tests -p 'test_*.py' -v
"$PYTHON" -B -m unittest discover \
  -s fortis_approvals/integrations/sonarcloud/tests -p 'test_*.py' -v

tests=(
  test_core.py
  test_gateway.py
  test_owner_portal.py
  test_owner_portal_input.py
  test_runtime.py
  test_repo_action_contract.py
  test_repo_ingress.py
  test_repo_sonar_read_contract.py
  test_repo_sonar_read_ingress.py
  test_repo_sonar_tools.py
  test_sonar.py
  test_sonar_inventory.py
  test_sonar_preflight.py
  test_sonar_probe.py
  test_sonar_read_adapter.py
  test_sonar_review_scenario.py
  test_r6_repo_sonar_read_to_approvals_tls_offline.py
  test_r7_unified_candidate.py
  test_modularized_candidate_manifest.py
)
for test in "${tests[@]}"; do
  echo "=== $test ==="
  "$PYTHON" -B -m unittest discover \
    -s fortis_approvals/tests -p "$test" -v
done

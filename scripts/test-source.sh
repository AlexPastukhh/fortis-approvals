#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
PYTHON="${PYTHON:-python3}"

# Every provider package participates; adding one never needs a CI script edit.
for provider_tests in fortis_approvals/integrations/*/tests; do
  if [[ -d "$provider_tests" ]]; then
    "$PYTHON" -B -m unittest discover -s "$provider_tests" -p 'test_*.py' -v
  fi
done

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
  test_github_pilot.py
  test_github_pilot_package.py
  test_github_file_pr.py
  test_github_ci_read.py
  test_native_workflow.py
  test_dynamic_github_repos.py
  test_dynamic_github_release_source.py
  test_analysis_review.py
  test_extensions.py
  test_extensions_http.py
  test_extensions_tooling.py
  test_provider_credentials.py
  test_extensions_tls.py
  test_r7_runtime_endpoints.py
  test_review_state_restore.py
  test_review_runtime_contract.py
  test_smoke_tmpfs.py
  test_smoke_locked_backup.py
  test_review_repo_get.py
  test_modularized_candidate_manifest.py
  test_release_storage_source.py
)
for test in "${tests[@]}"; do
  echo "=== $test ==="
  "$PYTHON" -B -m unittest discover \
    -s fortis_approvals/tests -p "$test" -v
done

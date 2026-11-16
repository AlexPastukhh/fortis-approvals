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
  test_owner_incident_ux.py
  test_orphaned_worker_claim_release.py
  test_visual_media_release.py
  test_owner_incident_portal.py
  test_machine_uncertain_inventory.py
  test_worker_observability.py
  test_owner_shell_portal.py
  test_owner_shell_release.py
  test_owner_shell_release_source.py
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
  test_visual_review.py
  test_visual_revisions.py
  test_native_workflow.py
  test_native_git_push_diagnostics.py
  test_git_transfer_efficiency.py
  test_native_pending_status.py
  test_native_worker_exception.py
  test_native_claim_single_delivery.py
  test_dynamic_github_repos.py
  test_native_github_ci.py
  test_dynamic_github_release_source.py
  test_release_bounded_record_source.py
  test_release_checked_image_source.py
  test_release_auto_owner.py
  test_release_emergency_image_source.py
  test_analysis_review.py
  test_extensions.py
  test_extensions_http.py
  test_extensions_tooling.py
  test_own_api_onboarding.py
  test_own_api_tools.py
  test_provider_credentials.py
  test_extensions_tls.py
  test_r7_runtime_endpoints.py
  test_review_state_restore.py
  test_review_runtime_contract.py
  test_smoke_tmpfs.py
  test_smoke_locked_backup.py
  test_review_repo_get.py
  test_modularized_candidate_manifest.py
  # PR1 diagnostics are part of mandatory source CI, not optional ad-hoc tests.
  test_pr1_git_push_audit_phase.py
  test_pr1b_github_read_errors.py
  test_pr1c_github_http_signals.py
  test_pr1d_create_pr_phases_precore.py
  test_pr1e_diagnostic_contract.py
  test_pr1f_closure.py
  test_pr1g_artifact_validation_phase.py
  test_pr1h_final_contract.py
  test_pr2_incident_inspector.py
  test_pr3_git_delivery.py
  test_automatic_read_retries.py
  test_command_intents.py
  test_intent_result_recovery.py
  test_release_label_recovery.py
  test_intent_target_efficiency.py
  test_delivery_intents.py
  test_intent_cli.py
  test_workspace_intents.py
  test_intent_native_integration.py
  test_release_storage_source.py
)
for test in "${tests[@]}"; do
  echo "=== $test ==="
  "$PYTHON" -B -m unittest discover \
    -s fortis_approvals/tests -p "$test" -v
done

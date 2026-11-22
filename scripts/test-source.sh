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
  test_owner_inventory.py
  test_owner_policy_preview.py
  test_owner_policy_draft_ledger.py
  test_owner_policy_change_challenge.py
  test_owner_policy_review_http.py
  test_owner_policy_review_http_crypto.py
  test_owner_policy_authority_phase6.py
  test_owner_policy_active_store_phase6b.py
  test_owner_policy_audit_witness_phase6b2.py
  test_owner_policy_monotonic_fence_phase6b3.py
  test_owner_policy_recovery_evidence_phase6b4.py
  test_owner_policy_local_core_phase6c.py
  test_owner_policy_engine_v2.py
  test_owner_read_ask_v3.py
  test_owner_all_method_sonar_v3.py
  test_owner_label_allow_guard.py
  test_owner_policy_local_deny_apply_phase6c1.py
  test_owner_policy_local_deny_apply_crypto.py
  test_owner_policy_local_deny_http_phase6c2.py
  test_owner_policy_local_deny_http_crypto.py
  test_owner_policy_local_bundle_phase6c3.py
  test_owner_policy_r7_optin_phase6c4.py
  test_owner_policy_legacy_fence_phase6c5.py
  test_owner_policy_actor_scoped_deny_phase6c6.py
  test_owner_policy_cross_process_phase6c7.py
  test_owner_policy_worker_census_phase6c8.py
  test_powershell_machine_gateway.py
  test_powershell_owner_mount.py
  test_machine_powershell_gateway_mount_release.py
  test_powershell_machine_client.py
  test_owner_shell_release.py
  test_owner_shell_release_source.py
  test_powershell_executor_extraction.py
  test_powershell_machine_contract.py
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
  test_action_core_network_guard.py
  test_action_core_network_release_source.py
  test_github_file_pr.py
  test_github_ci_read.py
  test_github_cd_queue_read.py
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
  test_p4_cd_owner_release.py
  test_release_bounded_record_source.py
  test_release_checked_image_source.py
  test_release_auto_owner.py
  test_release_emergency_image_source.py
  test_release_emergency_source_mount_preflight.py
  test_release_emergency_promote_source.py
  test_analysis_review.py
  test_extensions.py
  test_mirror_signing.py
  test_extensions_http.py
  test_extensions_tooling.py
  test_own_api_onboarding.py
  test_own_api_tools.py
  test_own_api_read_v2_manifest.py
  test_own_api_read_v2_acceptance.py
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
  test_release_uncertain_growth.py
  test_registry_boundary.py
  test_registry_gateway_read.py
  test_registry_state_journal.py
  test_registry_state_journal_v2.py
  test_registry_recovery_snapshot.py
  test_registry_checkpoint_cas.py
  test_registry_recovery_reconcile.py
  test_registry_owner_peer_boundary.py
  test_registry_owner_read_boundary.py
  test_registry_owner_runtime_isolation.py
  test_registry_owner_storage_denial.py
  test_registry_enrollment_cutover.py
)
for test in "${tests[@]}"; do
  echo "=== $test ==="
  "$PYTHON" -B -m unittest discover \
    -s fortis_approvals/tests -p "$test" -v
done

# Keep the pinned Source CI workflow byte-identical; this existing entrypoint
# also runs the mandatory isolated browser-logic tests. Missing Node fails CI.
echo '=== local_deny_ui.test.cjs + ui.test.cjs ==='
node --test fortis_approvals/tests/local_deny_ui.test.cjs fortis_approvals/tests/ui.test.cjs

#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
EXACT_TEST="$ROOT_DIR/scripts/run_exact_cargo_lib_test.sh"
SAMPLER="$ROOT_DIR/scripts/measure_native_node_memory.py"

usage() {
  local exit_code="${1:-2}"
  cat >&2 <<'EOF'
usage:
  check_native_node_memory_sync_recovery.sh --structural-only
  check_native_node_memory_sync_recovery.sh --pid PID --rpc-url URL --output CSV \
    --max-rss-growth-kib KIB --max-rss-envelope-kib KIB [sampler options]

The structural gate proves one-snapshot startup reload, bounded canonical
mining/status and non-tip ancestry access, the exact live-size 64-block
missing-parent recovery, equal-height and multi-window fork paging,
branch-bound exact-request/cooldown behavior, atomic side-page persistence,
unverified-target failover/quarantine, and post-resolution mining-gate
reopening.
Full mode additionally records a local process
RSS/progress soak. RSS limits are mandatory policy inputs; this script does
not derive a safe threshold from the observed run.
EOF
  exit "$exit_code"
}

log() {
  printf '[native-memory-sync] %s\n' "$*"
}

run_exact() {
  local test_name="$1"
  log "running $test_name"
  "$EXACT_TEST" hegemon-node "native::tests::$test_name" --no-default-features
}

has_option() {
  local expected="$1"
  shift
  local argument
  for argument in "$@"; do
    if [[ "$argument" == "$expected" || "$argument" == "$expected="* ]]; then
      return 0
    fi
  done
  return 1
}

if [[ $# -eq 0 ]]; then
  usage
fi

if [[ "$1" == "--help" || "$1" == "-h" ]]; then
  usage 0
fi

STRUCTURAL_ONLY=0
if [[ "$1" == "--structural-only" ]]; then
  STRUCTURAL_ONLY=1
  shift
  if [[ $# -ne 0 ]]; then
    usage
  fi
else
  has_option --pid "$@" || usage
  has_option --rpc-url "$@" || usage
  has_option --output "$@" || usage
  has_option --max-rss-growth-kib "$@" || usage
  has_option --max-rss-envelope-kib "$@" || usage
fi

run_exact pow_schedule_metadata_loads_are_retarget_window_bounded_and_match_full_chain
run_exact canonical_pow_schedule_rejects_stale_parent_and_corrupt_anchor_indexes
run_exact canonical_pow_schedule_rejects_valid_side_block_anchor_index
run_exact pow_schedule_rejects_mutated_supplied_parent_metadata
run_exact pow_schedule_compares_large_stored_parent_without_decoding_action_bytes
run_exact sync_batch_pow_schedule_follows_stored_side_parent_ancestry_at_retarget
run_exact canonical_mining_uses_cached_mmr_without_chain_reconstruction
run_exact header_hash_history_uses_compact_ancestry_without_body_decode_or_chain_reconstruction
run_exact prepare_work_rejects_missing_persisted_canonical_tip
run_exact prepare_work_rejects_malformed_cached_header_mmr_peaks
run_exact non_tip_announce_reuses_one_parent_ancestry_for_losing_and_winning_paths
run_exact multi_mib_sync_announce_uses_borrowed_import_without_owned_body_clone
run_exact scalar_and_latest_header_rpcs_do_not_clone_or_decode_tip_action_body
run_exact nonwinning_sync_streams_deep_large_action_ancestry_before_suffix_persistence
run_exact all_known_deep_large_action_winning_sync_streams_stored_reorg_and_reopens
run_exact canonical_publication_paths_clear_prepared_candidate_actions
run_exact reorg_reopen_preserves_mmr_peaks_across_four_leaf_shape_boundary
run_exact canonical_reorg_prestores_only_unknown_suffix_and_reopens
run_exact canonical_reorg_prestore_crash_window_is_noncanonical_and_retryable
run_exact reorg_orphan_suffix_walk_matches_legacy_order_without_full_old_chain
run_exact startup_reuses_one_validated_canonical_chain_snapshot
run_exact canonical_index_rebuild_streams_one_block_and_matches_legacy_plan
run_exact sync_tip_extension_across_retargets_avoids_chain_reconstruction
run_exact borrowed_native_sync_response_encoding_matches_owned_wire_bytes
run_exact native_sync_message_variant_ordinals_are_append_only
run_exact native_sync_legacy_variant_bytes_remain_frozen_across_append_only_extensions
run_exact native_sync_chunk_digest_domain_and_record_schema_are_independently_pinned
run_exact incremental_native_sync_response_sizer_matches_full_wire_oracle_at_varint_boundaries
run_exact sync_block_range_stops_loading_at_wire_prefix_budget
run_exact single_sync_block_may_cross_soft_target_but_not_hard_transport_cap
run_exact oversized_valid_native_block_advances_through_bounded_chunk_fallback
run_exact chunk_preflight_rejects_unsolicited_malformed_and_expired_sessions_without_growth
run_exact chunk_completion_reserve_failure_cools_down_authorized_request
run_exact symmetric_native_sync_chunk_sessions_transfer_and_close_without_directional_deadlock
run_exact announce_tip_is_unverified_request_planning_evidence_and_never_opens_gate
run_exact truncated_native_sync_response_prefix_remains_publishable
run_exact native_sync_response_prefix_rejects_suffix_gap_duplicate_and_wrong_parent
run_exact native_sync_response_in_flight_deduplicates_peer
run_exact native_sync_response_workers_are_globally_bounded
run_exact sync_response_missing_fork_parent_stops_suffix_then_recovers
run_exact tip_extension_multi_batch_error_reports_current_batch_boundary
run_exact all_known_disconnected_winning_suffix_backfills_then_reorgs
run_exact mixed_known_missing_known_winning_response_persists_connector_and_advances_once
run_exact mixed_known_missing_mismatched_known_descendant_is_terminal_without_writes
run_exact all_known_winning_sync_corrupt_parent_cycle_is_terminal
run_exact all_known_sync_response_requires_changed_recovery_range
run_exact stored_noncanonical_sync_response_requires_changed_recovery_range
run_exact equal_height_recovery_pagination_crosses_protocol_window_then_resumes_forward
run_exact equal_height_recovery_pages_store_connected_batch_then_adopt_target
run_exact sync_nonwinning_branch_batch_avoids_per_block_reconstruction_and_advances
run_exact valid_noncanonical_sync_batch_persists_exact_rows_without_canonical_changes_after_reopen
run_exact invalid_noncanonical_sync_batch_persists_no_partial_records_or_canonical_indexes
run_exact observed_live_topology_missing_parent_range_changes_and_straddles_fork
run_exact live_shape_sync_orchestration_recovers_range_bounds_retry_and_holds_gate
run_exact deep_fork_recovery_expands_request_cap_until_protocol_limit
run_exact native_sync_recovery_ranges_fail_closed_at_numeric_boundaries
run_exact outbound_native_sync_request_retries_after_live_timeout
run_exact unproductive_native_sync_response_cooldown_suppresses_tick_retries
run_exact same_peer_target_advance_retargets_cursor_without_tuple_corruption
run_exact same_target_hash_peer_failover_after_timeout_rebinds_cursor_and_retry
run_exact stale_sync_target_gate_snapshot_cannot_open_gate_or_clear_rebound_peer
run_exact unverified_extreme_target_timeout_quarantines_peer_and_allows_lower_recovery
run_exact stale_unverified_terminal_hook_cannot_evict_verified_rebound_target
run_exact unverified_target_deferred_during_import_is_scheduled_before_expiry
run_exact terminal_failure_hook_evicts_exact_unverified_target_and_quarantines_peer
run_exact unverified_target_chunk_session_expiry_recovers_without_reannouncement
run_exact unverified_target_peer_cooldowns_are_bounded_and_pruned
run_exact outbound_native_sync_response_completion_is_range_aware
run_exact truncated_sync_response_retains_full_completed_request_fingerprint
run_exact truncated_verified_sync_response_preserves_announced_target_and_schedules_forward
run_exact empty_sync_response_cools_down_exact_completed_request
run_exact broadcast_native_sync_response_cools_down_matched_broadcast_key
run_exact cooldown_native_sync_request_rejects_late_response_without_clearing_fingerprint
run_exact deep_sync_recovery_cursor_survives_request_expiry_and_beats_near_tip_restart
run_exact deep_equal_height_recovery_page_bypasses_stale_and_preserves_target
run_exact native_sync_recovery_context_binds_forward_parent_and_final_tip
run_exact verified_equal_height_sync_evidence_clears_stale_fork_target
run_exact unvalidated_nonwinning_hash_anchored_sync_response_does_not_clear_target
run_exact validated_durable_nonwinning_target_clears_gate_after_full_import
run_exact authorized_sync_target_resolution_requires_successful_durable_import

if [[ "$STRUCTURAL_ONLY" -eq 1 ]]; then
  log "structural gate passed; RSS was not measured"
  exit 0
fi

log "structural gate passed; starting explicit-PID local RSS/progress soak"
python3 "$SAMPLER" \
  --require-mining \
  --require-gate-open \
  --require-not-syncing \
  "$@"
log "local RSS/progress soak passed"

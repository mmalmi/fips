#!/usr/bin/env bash
# Run the deterministic FIPS dataplane safety tests inside a Linux container.
#
# Useful from local macOS hosts: local `cargo test` exercises Darwin cfg paths,
# while this covers Linux-only fair-worker queue behavior without needing a
# separate host checkout.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
IMAGE="${FIPS_LINUX_TEST_IMAGE:-rust:1.93-bookworm}"
TARGET_VOLUME="${FIPS_LINUX_TEST_TARGET_VOLUME:-fips-dataplane-safety-target}"
REGISTRY_VOLUME="${FIPS_LINUX_TEST_REGISTRY_VOLUME:-fips-dataplane-safety-registry}"
GIT_VOLUME="${FIPS_LINUX_TEST_GIT_VOLUME:-fips-dataplane-safety-git}"
RUSTUP_VOLUME="${FIPS_LINUX_TEST_RUSTUP_VOLUME:-fips-dataplane-safety-rustup}"

DEFAULT_FILTERS=(
  test_pipelined_send_counter_reservation_is_single_owner
  rx_loop_data_drain_stats_owns_counts_total_and_pressure
  rx_loop_maintenance_state_owns_activity_window_and_timeout_skip
  rx_loop_maintenance_plan_owns_pressure_skip_and_timeout_budget
  endpoint_command_owns_lane_selected_at_construction
  endpoint_send_command_owns_payload_lane_and_queue_stamp
  endpoint_data_payload_owns_drop_policy_selected_at_construction
  endpoint_data_send_owns_remote_identity_and_payload_policy
  pending_endpoint_data_queue_owns_drop_oldest_policy
  pending_tun_packet_queue_owns_drop_oldest_policy
  pending_session_traffic_queues_own_destination_admission
  pending_discovery_lookup_queue_owns_dedup_and_capacity
  recent_discovery_requests_own_reverse_path_dedup_capacity_and_expiry
  pending_route_retries_own_expiry_due_order_and_budgets
  local_send_failures_own_peer_scoped_fast_dead_clear_and_expiry
  traversal_path_liveness_keeps_mobile_safe_floor
  poll_nostr_discovery_configured_only_drops_nonconfigured_handoff
  session_direct_degradation_owns_hold_extension_expiry_and_clear
  discovery_fallback_transit_owns_target_exception_block_and_bootstrap_policy
  bootstrap_transports_own_membership_peer_npub_and_cleanup
  pending_outbound_handshakes_own_msg2_index_matching_and_cleanup
  link_address_index_owns_lookup_replace_and_stale_safe_remove
  link_registry_owns_storage_address_index_and_stale_safe_cleanup
  session_index_registry_owns_lookup_replace_remove_and_peer_membership
  peer_lifecycle_registry_owns_session_index_removal_and_remaining_owner_state
  peer_lifecycle_registry_owns_active_peer_insert_and_current_session_index
  peer_lifecycle_registry_owns_current_session_index_repair
  peer_lifecycle_registry_owns_current_session_replacement_and_index_handoff
  peer_lifecycle_registry_owns_pending_rekey_session_and_index_registration
  peer_lifecycle_registry_owns_authenticated_fmp_receive_bookkeeping
  peer_lifecycle_registry_owns_fmp_send_bookkeeping
  session_registry_owns_fsp_send_bookkeeping
  identity_cache_owns_prefix_validation_lru_touch_and_lookup_views
  configured_peer_send_weights_own_identity_parse_and_default_policy
  learned_route_fallback_exploration_owns_interval_dedup_and_expiry
  pending_session_queues_drop_oldest_per_destination
  pending_session_queues_reject_new_destinations_at_cap
  endpoint_command_tx_helper_classifies_priority_and_bulk_payloads
  endpoint_payload_traffic_classifier_prioritizes_control_sized_packets
  endpoint_payload_traffic_classifier_prioritizes_ipv4_icmp_ping
  test_reply_learned_prefers_live_mesh_route_over_stale_direct_peer
  test_reply_learned_prefers_live_mesh_route_over_session_degraded_direct_peer
  test_reply_learned_keeps_configured_static_direct_peer_over_lower_cost_fallback
  test_tree_routing_skips_session_degraded_direct_peer_for_payload
  test_stale_session_receiver_reports_do_not_change_route_choice
  test_stale_mmp_receiver_reports_do_not_change_route_choice
  test_session_receiver_loss_degrades_direct_and_uses_fallback
  test_fresh_bogus_session_metrics_without_valid_rtt_do_not_change_route_choice
  test_ignores_duplicate_receiver_report_after_valid_sample
  test_ignores_out_of_order_receiver_report_after_valid_sample
  test_parent_reeval_ignores_unmeasured_peer_costs
  test_parent_reeval_ignores_fresh_bogus_metrics_without_valid_rtt
)

if [[ "$#" -gt 0 ]]; then
  FILTERS=("$@")
else
  FILTERS=("${DEFAULT_FILTERS[@]}")
fi

docker run --rm \
  -v "$ROOT_DIR:/workspace:ro" \
  -v "$TARGET_VOLUME:/cargo-target" \
  -v "$REGISTRY_VOLUME:/usr/local/cargo/registry" \
  -v "$GIT_VOLUME:/usr/local/cargo/git" \
  -v "$RUSTUP_VOLUME:/usr/local/rustup" \
  -w /workspace \
  "$IMAGE" \
  bash -euo pipefail -c '
    export DEBIAN_FRONTEND=noninteractive
    if ! dpkg -s libdbus-1-dev libclang-dev pkg-config >/dev/null 2>&1; then
      apt-get update >/dev/null
      apt-get install -y --no-install-recommends libdbus-1-dev libclang-dev pkg-config >/dev/null
      rm -rf /var/lib/apt/lists/*
    fi
    export CARGO_TARGET_DIR=/cargo-target
    for filter in "$@"; do
      echo "--- cargo test -p fips-core ${filter} ---"
      cargo test -p fips-core "$filter"
    done
  ' bash "${FILTERS[@]}"

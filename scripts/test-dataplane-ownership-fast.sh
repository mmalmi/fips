#!/usr/bin/env bash
# Fast tiered validation for pure FIPS dataplane ownership/type-boundary changes.
#
# This is intentionally smaller than the full deterministic Linux runner and
# much smaller than nvpn perf/matrix/soak gates. Use it when a change should not
# alter queueing, routing, connected-UDP, maintenance timing, or send policy.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
RUN_DOCKER=1
RUN_RELEASE_CHECK=1
BATCH_DEFAULTS=1

DEFAULT_LOCAL_FILTERS=(
  rx_loop_data_drain_stats_owns_counts_total_and_pressure
  rx_loop_maintenance_state_owns_activity_window_and_timeout_skip
  rx_loop_maintenance_plan_owns_pressure_skip_and_timeout_budget
  endpoint_event_queue_owns_backlog_message_count
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
)

DEFAULT_LINUX_FILTERS=(
  rx_loop_data_drain_stats_owns_counts_total_and_pressure
  rx_loop_maintenance_state_owns_activity_window_and_timeout_skip
  rx_loop_maintenance_plan_owns_pressure_skip_and_timeout_budget
  endpoint_event_queue_owns_backlog_message_count
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
)

LOCAL_FILTERS=()
LINUX_FILTERS=()
POSITIONAL_FILTERS=()

usage() {
  cat <<'USAGE'
Usage: scripts/test-dataplane-ownership-fast.sh [options] [filter ...]

Fast validation tier for pure dataplane ownership/type-boundary changes.

Options:
  --skip-docker           Do not run the focused Linux Docker slice.
  --skip-release-check    Do not run cargo check -p fips-core --release.
  --no-batch-defaults     Run every default filter separately.
  --local-filter FILTER   Add a local cargo test filter.
  --linux-filter FILTER   Add a Linux Docker cargo test filter.
  -h, --help              Show this help.

If positional filters are provided, they replace both default filter lists.
USAGE
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --skip-docker)
      RUN_DOCKER=0
      shift
      ;;
    --skip-release-check)
      RUN_RELEASE_CHECK=0
      shift
      ;;
    --no-batch-defaults)
      BATCH_DEFAULTS=0
      shift
      ;;
    --local-filter)
      [[ "$#" -ge 2 ]] || {
        echo "error: --local-filter requires a value" >&2
        exit 2
      }
      LOCAL_FILTERS+=("$2")
      shift 2
      ;;
    --linux-filter)
      [[ "$#" -ge 2 ]] || {
        echo "error: --linux-filter requires a value" >&2
        exit 2
      }
      LINUX_FILTERS+=("$2")
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    --)
      shift
      while [[ "$#" -gt 0 ]]; do
        POSITIONAL_FILTERS+=("$1")
        shift
      done
      ;;
    -*)
      echo "error: unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
    *)
      POSITIONAL_FILTERS+=("$1")
      shift
      ;;
  esac
done

if [[ "${#POSITIONAL_FILTERS[@]}" -gt 0 ]]; then
  LOCAL_FILTERS=("${POSITIONAL_FILTERS[@]}")
  LINUX_FILTERS=("${POSITIONAL_FILTERS[@]}")
else
  if [[ "${#LOCAL_FILTERS[@]}" -eq 0 ]]; then
    if [[ "$BATCH_DEFAULTS" -eq 1 ]]; then
      LOCAL_FILTERS=("_own" "mac_queue_tests")
    else
      LOCAL_FILTERS=("${DEFAULT_LOCAL_FILTERS[@]}")
    fi
  fi
  if [[ "${#LINUX_FILTERS[@]}" -eq 0 ]]; then
    if [[ "$BATCH_DEFAULTS" -eq 1 ]]; then
      LINUX_FILTERS=("_own" "fair_dispatch_does_not_block_rx_loop_on_full_bulk_queue")
    else
      LINUX_FILTERS=("${DEFAULT_LINUX_FILTERS[@]}")
    fi
  fi
fi

cd "$ROOT_DIR"

if [[ "$BATCH_DEFAULTS" -eq 1 && "${#POSITIONAL_FILTERS[@]}" -eq 0 ]]; then
  echo "--- batching default ownership filters via broad cargo test patterns ---"
fi

echo "--- cargo fmt --check ---"
cargo fmt --check

for filter in "${LOCAL_FILTERS[@]}"; do
  echo "--- cargo test -p fips-core ${filter} ---"
  cargo test -p fips-core "$filter" -- --nocapture
done

if [[ "$RUN_RELEASE_CHECK" -eq 1 ]]; then
  echo "--- cargo check -p fips-core --release ---"
  cargo check -p fips-core --release
fi

if [[ "$RUN_DOCKER" -eq 1 ]]; then
  echo "--- focused Linux Docker ownership slice ---"
  ./scripts/test-dataplane-safety-linux-docker.sh "${LINUX_FILTERS[@]}"
fi

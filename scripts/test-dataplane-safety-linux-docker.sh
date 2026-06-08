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
  encrypt_worker_lane_policy_keeps_endpoint_bulk_explicit
  single_flow_full_backpressures_instead_of_dropping
  new_flow_can_enter_when_hot_flow_reaches_per_flow_cap
  hot_flow_backpressures_when_others_are_waiting
  priority_flow_enters_when_bulk_flow_reaches_per_flow_cap
  fair_admission_keys_pressure_by_exact_send_target
  encrypt_worker_dispatch_preserves_single_flow_worker_and_fifo_order
  fair_dispatch_does_not_block_rx_loop_on_full_bulk_queue
  decrypt_worker_channel_cap_prefers_specific_then_shared_value
  decrypt_worker_priority_packet_classifier_keeps_small_packets_reserved
  decrypt_worker_full_queue_drops_bulk_without_waiting
  decrypt_worker_priority_packet_uses_priority_lane_when_bulk_queue_is_full
  decrypt_worker_register_uses_priority_lane_when_bulk_queue_is_full
  decrypt_worker_register_full_returns_false_without_waiting
  decrypt_worker_drain_registers_priority_before_bulk_jobs
  decrypt_worker_drain_unregisters_priority_before_bulk_jobs
  decrypt_session_key_routes_registration_jobs_and_unregister_to_same_worker
  decrypt_worker_unregister_uses_priority_lane_when_bulk_queue_is_full
  decrypt_worker_unregister_full_returns_false_without_waiting
  decrypt_worker_fallback_event_classifier_uses_priority_and_bulk_lanes
  decrypt_worker_fallback_bulk_full_does_not_starve_priority_events
  worker_preserves_fmp_flags_through_fallback
  worker_reports_fmp_aead_failure_to_rx_loop
  pending_session_queues_drop_oldest_per_destination
  pending_session_queues_reject_new_destinations_at_cap
  endpoint_payload_traffic_classifier_prioritizes_control_sized_packets
  test_reply_learned_prefers_live_mesh_route_over_stale_direct_peer
  test_reply_learned_prefers_live_mesh_route_over_session_degraded_direct_peer
  test_reply_learned_keeps_configured_static_direct_peer_despite_session_degraded
  test_reply_learned_keeps_configured_static_direct_peer_over_lower_cost_fallback
  test_tree_routing_skips_session_degraded_direct_peer_for_payload
  test_stale_session_receiver_reports_do_not_change_route_choice
  test_stale_mmp_receiver_reports_do_not_change_route_choice
  test_session_receiver_loss_degrades_direct_and_uses_fallback
  test_ignores_duplicate_receiver_report_after_valid_sample
  test_ignores_out_of_order_receiver_report_after_valid_sample
  test_parent_reeval_ignores_unmeasured_peer_costs
  test_parent_reeval_ignores_fresh_bogus_metrics_without_valid_rtt
  connected_udp
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

#!/usr/bin/env bash
# Run the deterministic FIPS dataplane safety tests inside a Linux container.
#
# Useful from macOS mini: local `cargo test` exercises Darwin cfg paths, while
# this covers Linux-only fair-worker queue behavior without needing a separate
# host checkout.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
IMAGE="${FIPS_LINUX_TEST_IMAGE:-rust:1.93-bookworm}"
TARGET_VOLUME="${FIPS_LINUX_TEST_TARGET_VOLUME:-fips-dataplane-safety-target}"
REGISTRY_VOLUME="${FIPS_LINUX_TEST_REGISTRY_VOLUME:-fips-dataplane-safety-registry}"
GIT_VOLUME="${FIPS_LINUX_TEST_GIT_VOLUME:-fips-dataplane-safety-git}"
RUSTUP_VOLUME="${FIPS_LINUX_TEST_RUSTUP_VOLUME:-fips-dataplane-safety-rustup}"

DEFAULT_FILTERS=(
  single_flow_full_backpressures_instead_of_dropping
  new_flow_can_enter_when_hot_flow_reaches_per_flow_cap
  hot_flow_backpressures_when_others_are_waiting
  fair_dispatch_does_not_block_rx_loop_on_full_bulk_queue
  decrypt_worker_channel_cap_prefers_specific_then_shared_value
  decrypt_worker_priority_packet_classifier_keeps_small_packets_reserved
  decrypt_worker_full_queue_drops_bulk_without_waiting
  decrypt_worker_priority_packet_uses_priority_lane_when_bulk_queue_is_full
  decrypt_worker_register_uses_priority_lane_when_bulk_queue_is_full
  decrypt_worker_register_full_returns_false_without_waiting
  endpoint_payload_traffic_classifier_prioritizes_control_sized_packets
  test_stale_session_receiver_reports_do_not_change_route_choice
  test_session_receiver_loss_degrades_direct_and_uses_fallback
  test_ignores_duplicate_receiver_report_after_valid_sample
  test_ignores_out_of_order_receiver_report_after_valid_sample
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

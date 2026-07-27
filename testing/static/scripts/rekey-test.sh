#!/bin/bash
# Integration test for Noise rekey (periodic key rotation).
#
# Verifies that FMP link rekey and FSP session rekey complete without
# disrupting connectivity. Uses aggressive rekey timers (75s) so that
# baseline connectivity can converge before the first rotation while
# multiple rekey cycles still complete within CI time budgets.
#
# Tested failure modes:
#   - Cross-connection msg1 misidentified as rekey (session age guard)
#   - K-bit cutover and drain window (old session cleanup)
#   - FMP + FSP coordinated rekeying
#   - Multi-hop session survival across rekey
#   - Back-to-back rekey cycles (consecutive rekeys)
#   - Link stability through rekey (no spurious link teardowns)
#
# Usage:
#   ./rekey-test.sh                 Run the full test (containers must be up)
#   ./rekey-test.sh inject-config   Inject rekey config into generated configs
#   ./rekey-test.sh collect-artifacts
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../../lib/wait-converge.sh"
# Selectable topology — defaults to "rekey" but the rekey-accept-off
# variant exercises the auto_connect-initiator-with-accept-off
# regression class (udp.accept_connections=false on a peer that
# also auto-connects).
TOPOLOGY="${REKEY_TOPOLOGY:-rekey}"
NODES="a b c d e"
# Comma-separated list of node IDs to set udp.accept_connections=false
# on during inject-config. Empty (default) leaves all nodes accepting.
# When set, also asserted by the test that no sustained "Dual rekey
# initiation" log lines appear on the affected node.
REKEY_ACCEPT_OFF_NODES="${REKEY_ACCEPT_OFF_NODES:-}"

# Comma-separated list of node IDs to set udp.outbound_only=true on
# during inject-config. For each such node, peer addresses are also
# rewritten from numeric docker IPs to docker hostnames (e.g.
# 172.20.0.12:2121 → node-c:2121). This reproduces the production
# scenario where peer configs carry hostnames so the `addr_to_link`
# key is hostname-form while inbound packet source addrs are numeric,
# making the should_admit_msg1 carve-out's `addr_to_link.contains_key`
# check miss.
REKEY_OUTBOUND_ONLY_NODES="${REKEY_OUTBOUND_ONLY_NODES:-}"

# The staggered-overlap scenario drives node B's real production send-counter
# trigger twice inside the 45-second FSP drain window. Three non-adjacent
# sessions start at different times so their pending/draining epochs overlap.
REKEY_SCENARIO="${REKEY_SCENARIO:-standard}"
case "$REKEY_SCENARIO" in
    standard)
        REKEY_AFTER_SECS=75
        ;;
    staggered-overlap)
        REKEY_AFTER_SECS=300
        ;;
    *)
        echo "Error: unknown REKEY_SCENARIO '$REKEY_SCENARIO'" >&2
        exit 2
        ;;
esac

rekey_after_messages_for_node() {
    local node="$1"
    if [ "$REKEY_SCENARIO" != "staggered-overlap" ]; then
        echo 65536
        return
    fi
    case "$node" in
        b) echo 512 ;;
        a | c | d | e) echo 65536 ;;
        *)
            echo "Error: unknown rekey node '$node'" >&2
            return 2
            ;;
    esac
}

inject_rekey_config() {
    local cfg="$1"
    local accept_off="$2"
    local outbound_only="$3"
    local after_messages="$4"
    local tmp

    tmp="$(mktemp "${cfg}.XXXXXX")"
    if ! awk \
        -v after_secs="$REKEY_AFTER_SECS" \
        -v after_messages="$after_messages" \
        -v accept_off="$accept_off" \
        -v outbound_only="$outbound_only" '
        /^node:[[:space:]]*$/ && !inserted_rekey {
            print
            print "  rekey:"
            print "    enabled: true"
            print "    after_secs: " after_secs
            print "    after_messages: " after_messages
            inserted_rekey = 1
            next
        }
        /^  udp:[[:space:]]*$/ && !inserted_udp {
            print
            if (accept_off == "true") {
                print "    accept_connections: false"
            }
            if (outbound_only == "true") {
                print "    outbound_only: true"
            }
            inserted_udp = 1
            next
        }
        { print }
        END {
            if (!inserted_rekey) {
                exit 2
            }
        }
    ' "$cfg" >"$tmp"; then
        rm -f "$tmp"
        echo "  Error: failed to inject rekey config into $cfg" >&2
        exit 1
    fi

    mv "$tmp" "$cfg"

    if [ "$outbound_only" = "true" ]; then
        perl -0pi -e '
            s/172\.20\.0\.10:/node-a:/g;
            s/172\.20\.0\.11:/node-b:/g;
            s/172\.20\.0\.12:/node-c:/g;
            s/172\.20\.0\.13:/node-d:/g;
            s/172\.20\.0\.14:/node-e:/g;
        ' "$cfg"
    fi
}

# ── inject-config subcommand ──────────────────────────────────────────
# Inject rekey config into generated node configs. Called separately
# by CI before building Docker images.
if [ "${1:-}" = "inject-config" ]; then
    echo "Injecting rekey config (scenario=$REKEY_SCENARIO, after_secs=$REKEY_AFTER_SECS) into node configs (topology=$TOPOLOGY)..."
    if [ -n "$REKEY_ACCEPT_OFF_NODES" ]; then
        echo "  Setting udp.accept_connections=false on nodes: $REKEY_ACCEPT_OFF_NODES"
    fi
    if [ -n "$REKEY_OUTBOUND_ONLY_NODES" ]; then
        echo "  Setting udp.outbound_only=true + rewriting peer addrs to docker hostnames on nodes: $REKEY_OUTBOUND_ONLY_NODES"
    fi
    for node in $NODES; do
        cfg="$SCRIPT_DIR/../generated-configs/$TOPOLOGY/node-$node.yaml"
        if [ ! -f "$cfg" ]; then
            echo "  Error: $cfg not found" >&2
            exit 1
        fi
        accept_off="false"
        if [ -n "$REKEY_ACCEPT_OFF_NODES" ]; then
            for off_node in ${REKEY_ACCEPT_OFF_NODES//,/ }; do
                if [ "$off_node" = "$node" ]; then
                    accept_off="true"
                fi
            done
        fi
        outbound_only="false"
        if [ -n "$REKEY_OUTBOUND_ONLY_NODES" ]; then
            for oo_node in ${REKEY_OUTBOUND_ONLY_NODES//,/ }; do
                if [ "$oo_node" = "$node" ]; then
                    outbound_only="true"
                fi
            done
        fi
        after_messages="$(rekey_after_messages_for_node "$node")"
        inject_rekey_config "$cfg" "$accept_off" "$outbound_only" "$after_messages"
        suffix=""
        if [ "$accept_off" = "true" ]; then
            suffix=" (accept_connections=false)"
        fi
        if [ "$outbound_only" = "true" ]; then
            suffix=" (outbound_only=true, hostname peer addrs)"
        fi
        echo "  ✓ node-$node (after_messages=$after_messages)$suffix"
    done
    echo "✓ Config injection complete"
    exit 0
fi

# ── Diagnostic artifact helpers ────────────────────────────────────────
ARTIFACT_DIR="${REKEY_ARTIFACT_DIR:-$SCRIPT_DIR/../artifacts/rekey-$TOPOLOGY-$REKEY_SCENARIO}"
PHASE_TIMESTAMPS="$ARTIFACT_DIR/phase-timestamps.tsv"
PROBE_DIR="$ARTIFACT_DIR/continuous-probes"
PROBE_SUMMARY_JSON="$ARTIFACT_DIR/continuous-probes.json"
PROBE_SUMMARY_TSV="$ARTIFACT_DIR/continuous-probes.tsv"

record_phase() {
    local phase="$1"
    local state="$2"
    local detail="${3:-}"
    mkdir -p "$ARTIFACT_DIR"
    python3 - "$PHASE_TIMESTAMPS" "$phase" "$state" "$detail" "$SECONDS" <<'PY'
from datetime import datetime, timezone
from pathlib import Path
import sys
import time

path = Path(sys.argv[1])
new_file = not path.exists() or path.stat().st_size == 0
with path.open("a") as output:
    if new_file:
        output.write("unix_ms\trfc3339\telapsed_seconds\tphase\tstate\tdetail\n")
    now = datetime.now(timezone.utc)
    output.write(
        f"{time.time_ns() // 1_000_000}\t"
        f"{now.isoformat(timespec='milliseconds').replace('+00:00', 'Z')}\t"
        f"{sys.argv[5]}\t{sys.argv[2]}\t{sys.argv[3]}\t{sys.argv[4]}\n"
    )
PY
}

write_artifact_metadata() {
    mkdir -p "$ARTIFACT_DIR"
    {
        echo "topology=$TOPOLOGY"
        echo "scenario=$REKEY_SCENARIO"
        echo "rekey_after_secs=$REKEY_AFTER_SECS"
        for node in $NODES; do
            echo "node_${node}_rekey_after_messages=$(rekey_after_messages_for_node "$node")"
        done
        echo "git_revision=$(git -C "$SCRIPT_DIR/../../.." rev-parse HEAD 2>/dev/null || echo unknown)"
    } >"$ARTIFACT_DIR/metadata.env"
}

capture_artifacts() {
    mkdir -p "$ARTIFACT_DIR/logs" "$ARTIFACT_DIR/decrypt-failures" \
        "$ARTIFACT_DIR/peer-snapshots" "$ARTIFACT_DIR/container-inspect"
    write_artifact_metadata
    docker ps --no-trunc >"$ARTIFACT_DIR/docker-ps.txt" 2>&1 || true
    for node in $NODES; do
        docker logs --timestamps "fips-node-$node" \
            >"$ARTIFACT_DIR/logs/node-$node.log" 2>&1 || true
        grep -E \
            "Session AEAD decryption failed|FSP AEAD decryption failed|FSP AEAD failure" \
            "$ARTIFACT_DIR/logs/node-$node.log" \
            >"$ARTIFACT_DIR/decrypt-failures/node-$node.log" || true
        docker exec "fips-node-$node" fipsctl show peers \
            >"$ARTIFACT_DIR/peer-snapshots/node-$node.txt" 2>&1 || true
        docker inspect "fips-node-$node" \
            >"$ARTIFACT_DIR/container-inspect/node-$node.json" 2>&1 || true
    done
}

if [ "${1:-}" = "collect-artifacts" ]; then
    record_phase "artifact-collection" "start" "workflow safety collection"
    capture_artifacts
    record_phase "artifact-collection" "end" "complete per-node logs captured"
    echo "Rekey diagnostics saved to $ARTIFACT_DIR"
    exit 0
fi

# ── Full test ─────────────────────────────────────────────────────────
# Wait times derived from rekey timer
BASELINE_CONVERGENCE_TIMEOUT=60
REKEY_SETTLE=12        # > FMP drain window so post-rekey link samples are off the old session
# First FMP rekey should follow shortly after the configured interval once the mesh is
# fully converged. Keep this bounded to preserve a meaningful scheduling check
# while still allowing for log visibility at the timeout edge.
if [ "$REKEY_SCENARIO" = "staggered-overlap" ]; then
    FIRST_REKEY_TIMEOUT=60
    SECOND_REKEY_WAIT=50
else
    FIRST_REKEY_TIMEOUT=$((REKEY_AFTER_SECS + 15))
    SECOND_REKEY_WAIT=40
fi
LOG_EVENT_POLL_INTERVAL=1
FMP_REKEY_PATTERN="Rekey cutover complete (initiator), K-bit flipped"
FSP_REKEY_PATTERN="FSP rekey: completed XK\|FSP rekey cutover complete"
FSP_CUTOVER_PATTERN="FSP rekey cutover complete"
DECRYPT_FAILURE_PATTERN="Session AEAD decryption failed\|FSP AEAD decryption failed"
CONTINUOUS_PING_INTERVAL="${REKEY_CONTINUOUS_PING_INTERVAL:-0.5}"
CONTINUOUS_PING_MIN_REPLIES="${REKEY_CONTINUOUS_PING_MIN_REPLIES:-20}"
CONTINUOUS_PROBE_START_STAGGER="${REKEY_CONTINUOUS_PROBE_START_STAGGER:-0.05}"

TIMEOUT=5
CONVERGENCE_PING_TIMEOUT=1
PASSED=0
FAILED=0
TOTAL_PASSED=0
TOTAL_FAILED=0
BASELINE_FMP_REKEY_COUNT=0
BASELINE_FSP_REKEY_COUNT=0
BASELINE_FSP_CUTOVER_COUNT=0
BASELINE_DECRYPT_FAILURE_COUNT=0

# Node identities
ENV_FILE="$SCRIPT_DIR/../generated-configs/npubs.env"
if [ ! -f "$ENV_FILE" ]; then
    echo "Error: $ENV_FILE not found. Run generate-configs.sh first." >&2
    exit 1
fi
source "$ENV_FILE"

NPUBS=("$NPUB_A" "$NPUB_B" "$NPUB_C" "$NPUB_D" "$NPUB_E")
LABELS=(A B C D E)
PROBES_RUNNING=0
PROBE_HOST_PIDS="$ARTIFACT_DIR/continuous-probe-host-pids.txt"

# ── Helpers ────────────────────────────────────────────────────────────

ping_one() {
    local from="$1"
    local to_npub="$2"
    local label="$3"
    local quiet="${4:-}"
    local ping_timeout="${5:-$TIMEOUT}"

    if output=$(docker exec "fips-$from" ping6 -c 1 -W "$ping_timeout" "${to_npub}.fips" 2>&1); then
        local rtt=$(echo "$output" | grep -oE 'time=[0-9.]+' | cut -d= -f2)
        if [ -z "$quiet" ]; then
            echo "  $label ... OK (${rtt:-?}ms)"
        fi
        PASSED=$((PASSED + 1))
    else
        if [ -z "$quiet" ]; then
            echo "  $label ... FAIL"
        fi
        FAILED=$((FAILED + 1))
    fi
}

lower_label() {
    printf '%s' "$1" | tr '[:upper:]' '[:lower:]'
}

continuous_probe_interval_for_pair() {
    local from="$1"
    local to="$2"
    if [ "$REKEY_SCENARIO" = "staggered-overlap" ] \
        && [ "$from" = "b" ] \
        && { [ "$to" = "a" ] || [ "$to" = "d" ] || [ "$to" = "e" ]; }; then
        echo 0.05
    else
        echo "$CONTINUOUS_PING_INTERVAL"
    fi
}

stagger_overlap_probe_start() {
    local from="$1"
    local to="$2"
    if [ "$REKEY_SCENARIO" != "staggered-overlap" ] || [ "$from" != "b" ]; then
        return
    fi
    case "$to" in
        d | e) sleep 2 ;;
    esac
}

start_continuous_probes() {
    mkdir -p "$PROBE_DIR"
    : >"$PROBE_HOST_PIDS"
    PROBES_RUNNING=1
    record_phase \
        "continuous-probes" "start" \
        "20 directed streams interval=${CONTINUOUS_PING_INTERVAL}s"

    for i in 0 1 2 3 4; do
        local from
        from="$(lower_label "${LABELS[$i]}")"
        for j in 0 1 2 3 4; do
            [ "$i" -eq "$j" ] && continue
            local to
            local target
            local pid_file
            local interval
            to="$(lower_label "${LABELS[$j]}")"
            target="${NPUBS[$j]}.fips"
            pid_file="/tmp/fips-rekey-probe-${from}-to-${to}.pid"
            stagger_overlap_probe_start "$from" "$to"
            interval="$(continuous_probe_interval_for_pair "$from" "$to")"
            docker exec "fips-node-$from" sh -c \
                'echo "$$" > "$1"; exec ping6 -n -D -O -i "$2" "$3"' \
                rekey-probe "$pid_file" "$interval" "$target" \
                >"$PROBE_DIR/${from}-to-${to}.log" 2>&1 &
            echo "$!" >>"$PROBE_HOST_PIDS"
            sleep "$CONTINUOUS_PROBE_START_STAGGER"
        done
    done
}

stop_continuous_probes() {
    if [ "$PROBES_RUNNING" -ne 1 ]; then
        return
    fi
    record_phase "continuous-probes" "stop-requested" ""
    for node in $NODES; do
        docker exec "fips-node-$node" sh -c '
            for pid_file in /tmp/fips-rekey-probe-*.pid; do
                [ -f "$pid_file" ] || continue
                kill -INT "$(cat "$pid_file")" 2>/dev/null || true
                rm -f "$pid_file"
            done
        ' >/dev/null 2>&1 || true
    done
    if [ -f "$PROBE_HOST_PIDS" ]; then
        while IFS= read -r pid; do
            wait "$pid" 2>/dev/null || true
        done <"$PROBE_HOST_PIDS"
    fi
    PROBES_RUNNING=0
    record_phase "continuous-probes" "stopped" ""
}

assert_continuous_probes() {
    if python3 "$SCRIPT_DIR/analyze_rekey_probes.py" "$PROBE_DIR" \
        --expected-streams 20 \
        --min-replies "$CONTINUOUS_PING_MIN_REPLIES" \
        --json "$PROBE_SUMMARY_JSON" \
        --tsv "$PROBE_SUMMARY_TSV"; then
        echo "  ✓ Continuous sequenced payload delivery: zero loss"
        PASSED=$((PASSED + 1))
    else
        echo "  ✗ Continuous sequenced payload delivery failed"
        FAILED=$((FAILED + 1))
    fi
}

# Run all 20 directed pairs
ping_all() {
    local quiet="${1:-}"
    local ping_timeout="${2:-$TIMEOUT}"
    PASSED=0
    FAILED=0
    for i in 0 1 2 3 4; do
        local from_node
        from_node="node-$(lower_label "${LABELS[$i]}")"
        if [ -z "$quiet" ]; then
            echo "  From $from_node:"
        fi
        for j in 0 1 2 3 4; do
            [ "$i" -eq "$j" ] && continue
            ping_one "$from_node" "${NPUBS[$j]}" \
                "${LABELS[$i]} → ${LABELS[$j]}" "$quiet" "$ping_timeout"
        done
    done
}

wait_for_full_baseline() {
    local timeout="${1:-30}"
    local start_secs=$SECONDS
    local best_passed=0
    local best_failed=20

    while (( SECONDS - start_secs < timeout )); do
        ping_all quiet "$CONVERGENCE_PING_TIMEOUT"
        if [ "$PASSED" -gt "$best_passed" ]; then
            best_passed="$PASSED"
            best_failed="$FAILED"
        fi
        if [ "$FAILED" -eq 0 ]; then
            return 0
        fi
        sleep 1
    done

    PASSED="$best_passed"
    FAILED="$best_failed"
    return 1
}

phase_result() {
    local phase="$1"
    TOTAL_PASSED=$((TOTAL_PASSED + PASSED))
    TOTAL_FAILED=$((TOTAL_FAILED + FAILED))
    if [ "$FAILED" -eq 0 ]; then
        echo "  ✓ $phase: $PASSED/$((PASSED + FAILED)) passed"
        record_phase "$phase" "passed" "$PASSED/$((PASSED + FAILED))"
    else
        echo "  ✗ $phase: $PASSED passed, $FAILED FAILED"
        record_phase "$phase" "failed" "$PASSED passed, $FAILED failed"
    fi
}

# Count occurrences of a pattern across all node logs
count_log_pattern() {
    local pattern="$1"
    local total=0
    for node in $NODES; do
        local count=$(docker logs "fips-node-$node" 2>&1 | grep -c "$pattern" || true)
        total=$((total + count))
    done
    echo "$total"
}

wait_for_log_pattern_delta() {
    local pattern="$1"
    local baseline="$2"
    local min_delta="$3"
    local timeout="$4"
    local start_secs=$SECONDS

    while (( SECONDS - start_secs < timeout )); do
        local count
        count=$(count_log_pattern "$pattern")
        if [ $((count - baseline)) -ge "$min_delta" ]; then
            return 0
        fi
        sleep "$LOG_EVENT_POLL_INTERVAL"
    done

    local count
    count=$(count_log_pattern "$pattern")
    [ $((count - baseline)) -ge "$min_delta" ]
}

snapshot_log_baseline() {
    BASELINE_FMP_REKEY_COUNT="$(count_log_pattern "$FMP_REKEY_PATTERN")"
    BASELINE_FSP_REKEY_COUNT="$(count_log_pattern "$FSP_REKEY_PATTERN")"
    BASELINE_FSP_CUTOVER_COUNT="$(count_log_pattern "$FSP_CUTOVER_PATTERN")"
    BASELINE_DECRYPT_FAILURE_COUNT="$(count_log_pattern "$DECRYPT_FAILURE_PATTERN")"
    {
        printf 'pattern\tcount\n'
        printf 'fmp_rekey\t%s\n' "$BASELINE_FMP_REKEY_COUNT"
        printf 'fsp_rekey_progress\t%s\n' "$BASELINE_FSP_REKEY_COUNT"
        printf 'fsp_cutover\t%s\n' "$BASELINE_FSP_CUTOVER_COUNT"
        printf 'decrypt_failure\t%s\n' "$BASELINE_DECRYPT_FAILURE_COUNT"
    } >"$ARTIFACT_DIR/log-count-baseline.tsv"
    record_phase \
        "log-baseline" "captured" \
        "fmp=$BASELINE_FMP_REKEY_COUNT fsp=$BASELINE_FSP_REKEY_COUNT cutover=$BASELINE_FSP_CUTOVER_COUNT decrypt=$BASELINE_DECRYPT_FAILURE_COUNT"
}

assert_min_count_since_baseline() {
    local pattern="$1"
    local baseline="$2"
    local min_count="$3"
    local description="$4"
    local count
    local delta
    count=$(count_log_pattern "$pattern")
    delta=$((count - baseline))
    if [ "$delta" -ge "$min_count" ]; then
        echo "  ✓ $description: $delta new events (>= $min_count)"
        PASSED=$((PASSED + 1))
    else
        echo "  ✗ $description: $delta new events (expected >= $min_count)"
        FAILED=$((FAILED + 1))
    fi
}

# Check that a pattern appears zero times across all logs
assert_zero_count() {
    local pattern="$1"
    local description="$2"
    local count=$(count_log_pattern "$pattern")
    if [ "$count" -eq 0 ]; then
        echo "  ✓ $description: 0"
        PASSED=$((PASSED + 1))
    else
        echo "  ✗ $description: $count (expected 0)"
        FAILED=$((FAILED + 1))
    fi
}

dump_peer_connectivity() {
    echo "=== Peer connectivity snapshot ==="
    for node in $NODES; do
        echo "--- node-$node ---"
        docker exec "fips-node-$node" fipsctl show peers 2>/dev/null || true
        echo ""
    done
}

on_test_exit() {
    local status=$?
    trap - EXIT INT TERM
    stop_continuous_probes || true
    record_phase "test" "exit" "status=$status" || true
    capture_artifacts || true
    exit "$status"
}

trap on_test_exit EXIT
trap 'echo ""; echo "Test interrupted"; exit 130' INT TERM

# ── Main ───────────────────────────────────────────────────────────────

mkdir -p "$ARTIFACT_DIR"
: >"$PHASE_TIMESTAMPS"
write_artifact_metadata
record_phase "test" "start" "topology=$TOPOLOGY scenario=$REKEY_SCENARIO"

echo "=== FIPS Rekey Integration Test ==="
echo ""
echo "Config: scenario=$REKEY_SCENARIO rekey.after_secs=$REKEY_AFTER_SECS"
echo ""

# ── Phase 1: Pre-rekey baseline ───────────────────────────────────────
record_phase "phase-1-baseline" "start" ""
echo "Phase 1: Pre-rekey connectivity (waiting for convergence)"
wait_for_peers fips-node-a 2 "$BASELINE_CONVERGENCE_TIMEOUT" || true
if wait_for_full_baseline "$BASELINE_CONVERGENCE_TIMEOUT"; then
    ping_all
    phase_result "Pre-rekey baseline (all 20 pairs)"
else
    echo "  Best observed baseline before timeout: $PASSED/$((PASSED + FAILED)) passed"
    phase_result "Pre-rekey baseline (all 20 pairs)"
    echo ""
    dump_peer_connectivity
    echo "=== Results: $TOTAL_PASSED passed, $TOTAL_FAILED failed ==="
    exit 1
fi
snapshot_log_baseline
start_continuous_probes
echo ""

# ── Phase 2: Wait for first rekey activity ────────────────────────────
record_phase "phase-2-first-rekey" "start" ""
echo "Phase 2: First rekey activity (waiting up to ${FIRST_REKEY_TIMEOUT}s)"
PASSED=0
FAILED=0
echo "  Checking rekey events..."
if [ "$REKEY_SCENARIO" = "staggered-overlap" ]; then
    wait_for_log_pattern_delta \
        "$FSP_CUTOVER_PATTERN" "$BASELINE_FSP_CUTOVER_COUNT" 1 "$FIRST_REKEY_TIMEOUT" || true
    assert_min_count_since_baseline \
        "$FSP_CUTOVER_PATTERN" "$BASELINE_FSP_CUTOVER_COUNT" 1 \
        "First counter-driven FSP cutover"
else
    wait_for_log_pattern_delta \
        "$FMP_REKEY_PATTERN" "$BASELINE_FMP_REKEY_COUNT" 1 "$FIRST_REKEY_TIMEOUT" || true
    assert_min_count_since_baseline \
        "$FMP_REKEY_PATTERN" "$BASELINE_FMP_REKEY_COUNT" 1 \
        "FMP rekey responder cutovers"
fi
phase_result "First rekey events"
echo ""

# Verify connectivity after first rekey (strict — no failures allowed)
record_phase "phase-3-post-first-rekey" "start" "settle_seconds=$REKEY_SETTLE"
echo "Phase 3: Post-rekey connectivity (settling ${REKEY_SETTLE}s)"
sleep "$REKEY_SETTLE"
ping_all
phase_result "Post-first-rekey (all 20 pairs)"
echo ""

# ── Phase 4: Wait for second rekey cycle ──────────────────────────────
record_phase "phase-4-second-rekey" "start" "wait_seconds=$SECOND_REKEY_WAIT"
echo "Phase 4: Second rekey cycle (waiting ${SECOND_REKEY_WAIT}s)"
sleep "$SECOND_REKEY_WAIT"

# Verify connectivity after second rekey (back-to-back)
record_phase "phase-5-post-second-rekey" "start" "settle_seconds=$REKEY_SETTLE"
echo "Phase 5: Post-second-rekey connectivity (settling ${REKEY_SETTLE}s)"
sleep "$REKEY_SETTLE"
ping_all
phase_result "Post-second-rekey (all 20 pairs)"
echo ""

# ── Phase 6: Log analysis ─────────────────────────────────────────────
record_phase "phase-6-log-analysis" "start" ""
echo "Phase 6: Log analysis"
PASSED=0
FAILED=0

# FSP session rekey trails link-layer rekey in practice. The overlap lane
# requires two cutovers on each end of B's three deliberately staggered
# non-adjacent sessions: 3 sessions × 2 cycles × 2 endpoints = 12.
if [ "$REKEY_SCENARIO" = "staggered-overlap" ]; then
    wait_for_log_pattern_delta \
        "$FSP_CUTOVER_PATTERN" "$BASELINE_FSP_CUTOVER_COUNT" 12 30 || true
else
    wait_for_log_pattern_delta \
        "$FSP_REKEY_PATTERN" "$BASELINE_FSP_REKEY_COUNT" 1 "$FIRST_REKEY_TIMEOUT" || true
fi

stop_continuous_probes
assert_continuous_probes

# Positive checks: rekey machinery worked. The overlap lane deliberately
# isolates FSP's counter trigger; ordinary lanes retain the FMP assertion.
if [ "$REKEY_SCENARIO" != "staggered-overlap" ]; then
    assert_min_count_since_baseline \
        "$FMP_REKEY_PATTERN" "$BASELINE_FMP_REKEY_COUNT" 1 \
        "FMP rekey responder cutovers"
fi

# FSP rekey checks (sessions between non-adjacent nodes)
assert_min_count_since_baseline \
    "$FSP_REKEY_PATTERN" "$BASELINE_FSP_REKEY_COUNT" 1 \
    "FSP session rekey progress"
if [ "$REKEY_SCENARIO" = "staggered-overlap" ]; then
    assert_min_count_since_baseline \
        "$FSP_CUTOVER_PATTERN" "$BASELINE_FSP_CUTOVER_COUNT" 12 \
        "Two staggered FSP cutovers on both endpoints of three sessions"
fi

# Negative checks: no bad things happened
assert_zero_count "PANIC\|panicked" "Panics"
assert_zero_count "ERROR" "Errors"
assert_zero_count "MMP link teardown" "Spurious link teardowns"
assert_zero_count "Excessive decrypt failures" \
    "Excessive decrypt failure removals"
assert_zero_count "Rekey msg2 processing failed" "Rekey msg2 failures"
assert_zero_count "$DECRYPT_FAILURE_PATTERN" \
    "FSP decryption failures during rekey"

# Variant-specific: when one or more nodes have udp.accept_connections=false,
# verify the dual-init carve-out keeps the "we win, dropping their msg1"
# log line below the bug threshold. Pre-fix, a 1Hz dual-init loop produced
# ~120 occurrences over the 2-minute test; with the carve-out, the line
# fires at most a handful of times from genuine simultaneous rekeys.
if [ -n "$REKEY_ACCEPT_OFF_NODES" ]; then
    DUAL_INIT_THRESHOLD=10
    for off_node in ${REKEY_ACCEPT_OFF_NODES//,/ }; do
        count=$(docker logs "fips-node-$off_node" 2>&1 \
            | grep -cE "Dual rekey initiation: we win" || true)
        if [ "${count:-0}" -le "$DUAL_INIT_THRESHOLD" ]; then
            echo "  PASS: node-$off_node dual-init drops below threshold ($count <= $DUAL_INIT_THRESHOLD)"
            PASSED=$((PASSED + 1))
        else
            echo "  FAIL: node-$off_node sustained dual-init drops ($count > $DUAL_INIT_THRESHOLD)"
            FAILED=$((FAILED + 1))
        fi
    done
fi

# Variant-specific: udp.outbound_only=true. The pre-fix bug fired the
# dual-init loop on the OTHER side (the peer of the outbound-only node)
# because the outbound-only side rejects the inbound rekey msg1 due to
# the addr_to_link hostname-vs-numeric mismatch, leaving the peer's
# rekey state in a 1Hz retry loop that the outbound-only side keeps
# dropping. The exact node that emits "we win" depends on which side
# has the smaller NodeAddr, so check all five nodes for the sustained-
# loop signature.
if [ -n "$REKEY_OUTBOUND_ONLY_NODES" ]; then
    DUAL_INIT_THRESHOLD=10
    for n in $NODES; do
        count=$(docker logs "fips-node-$n" 2>&1 \
            | grep -cE "Dual rekey initiation: we win" || true)
        if [ "${count:-0}" -le "$DUAL_INIT_THRESHOLD" ]; then
            echo "  PASS: node-$n dual-init drops below threshold ($count <= $DUAL_INIT_THRESHOLD)"
            PASSED=$((PASSED + 1))
        else
            echo "  FAIL: node-$n sustained dual-init drops ($count > $DUAL_INIT_THRESHOLD)"
            FAILED=$((FAILED + 1))
        fi
    done
fi

phase_result "Log analysis"
echo ""

# ── Summary ────────────────────────────────────────────────────────────
echo "=== Results: $TOTAL_PASSED passed, $TOTAL_FAILED failed ==="
record_phase \
    "summary" "$([ "$TOTAL_FAILED" -eq 0 ] && echo passed || echo failed)" \
    "$TOTAL_PASSED passed, $TOTAL_FAILED failed"

if [ "$TOTAL_FAILED" -eq 0 ]; then
    exit 0
else
    capture_artifacts
    echo ""
    echo "=== Complete decrypt-failure events ==="
    for node in $NODES; do
        echo "--- node-$node ---"
        cat "$ARTIFACT_DIR/decrypt-failures/node-$node.log"
        echo ""
    done
    echo "Complete timestamped logs: $ARTIFACT_DIR/logs"
    exit 1
fi

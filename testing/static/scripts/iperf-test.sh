#!/bin/bash
# End-to-end iperf3 bandwidth test between FIPS nodes via DNS resolution.
# Usage: ./iperf-test.sh [mesh|chain] [--live]
#
# Optional environment:
#   FIPS_IPERF_DURATION=10       Test duration in seconds
#   FIPS_IPERF_PARALLEL=8        Parallel iperf streams
#   FIPS_IPERF_MIN_MBPS=250      Fail if aggregate sender bandwidth is lower
#
# Requires containers to be running:
#   docker compose --profile mesh up -d
#   ./scripts/iperf-test.sh mesh
#   ./scripts/iperf-test.sh mesh --live  # Show live iperf3 output
set -e

# Exit entire script on Ctrl+C
trap 'echo ""; echo "Test interrupted"; exit 130' INT

PROFILE="${1:-mesh}"
LIVE_OUTPUT=false
if [ "$2" = "--live" ] || [ "$1" = "--live" ]; then
    LIVE_OUTPUT=true
    [ "$1" = "--live" ] && PROFILE="mesh"
fi

DURATION="${FIPS_IPERF_DURATION:-10}"
PARALLEL="${FIPS_IPERF_PARALLEL:-8}"
MIN_MBPS="${FIPS_IPERF_MIN_MBPS:-}"
PASSED=0
FAILED=0

if [ "$LIVE_OUTPUT" = true ] && [ -n "$MIN_MBPS" ]; then
    echo "Error: --live cannot enforce FIPS_IPERF_MIN_MBPS because output is not parsed." >&2
    exit 1
fi

if [ -n "$MIN_MBPS" ] && ! [[ "$MIN_MBPS" =~ ^[0-9]+([.][0-9]+)?$ ]]; then
    echo "Error: FIPS_IPERF_MIN_MBPS must be numeric, got '$MIN_MBPS'." >&2
    exit 1
fi

bandwidth_to_mbps() {
    local value="$1"
    local unit="$2"

    awk -v value="$value" -v unit="$unit" '
        BEGIN {
            if (unit == "bits/sec") {
                scale = 0.000001
            } else if (unit == "Kbits/sec") {
                scale = 0.001
            } else if (unit == "Mbits/sec") {
                scale = 1
            } else if (unit == "Gbits/sec") {
                scale = 1000
            } else {
                exit 2
            }
            printf "%.3f", value * scale
        }
    '
}

bandwidth_meets_min() {
    local actual="$1"
    local minimum="$2"

    awk -v actual="$actual" -v minimum="$minimum" \
        'BEGIN { exit !(actual + 0 >= minimum + 0) }'
}

# Node identities (from generated env file)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="$SCRIPT_DIR/../generated-configs/npubs.env"
if [ ! -f "$ENV_FILE" ]; then
    echo "Error: $ENV_FILE not found. Run generate-configs.sh first." >&2
    exit 1
fi
# shellcheck source=../generated-configs/npubs.env
source "$ENV_FILE"

iperf_test() {
    local server_node="$1"
    local client_node="$2"
    local dest_npub="$3"
    local label="$4"

    echo ""
    echo "=== $label ==="
    
    # iperf3 server is already running in daemon mode in each container
    
    if [ "$LIVE_OUTPUT" = true ]; then
        # Show live output
        echo "Running iperf3 test (live output):"
        if docker exec "fips-$client_node" iperf3 -c "${dest_npub}.fips" -t "$DURATION" -P "$PARALLEL"; then
            PASSED=$((PASSED + 1))
        else
            echo "FAIL"
            FAILED=$((FAILED + 1))
        fi
    else
        # Capture and summarize output
        echo -n "Running iperf3 test... "
        local output
        if output=$(docker exec "fips-$client_node" iperf3 -c "${dest_npub}.fips" -t "$DURATION" -P "$PARALLEL" 2>&1); then
            # Check if we got valid results
            if echo "$output" | grep -q "sender"; then
                # Extract and display results (get SUM line for aggregate bandwidth)
                local bandwidth
                bandwidth=$(echo "$output" | grep "\[SUM\].*sender" | tail -1 | awk '{for(i=1;i<=NF;i++) if($i ~ /bits\/sec/) {print $(i-1), $i; exit}}')

                local bandwidth_value bandwidth_unit bandwidth_mbps
                read -r bandwidth_value bandwidth_unit <<< "$bandwidth"
                if [ -z "$bandwidth_value" ] || [ -z "$bandwidth_unit" ]; then
                    echo "FAIL (no aggregate bandwidth data)"
                    echo "Output: $output"
                    FAILED=$((FAILED + 1))
                    return
                fi

                if ! bandwidth_mbps=$(bandwidth_to_mbps "$bandwidth_value" "$bandwidth_unit"); then
                    echo "FAIL (unknown bandwidth unit: $bandwidth_unit)"
                    echo "Output: $output"
                    FAILED=$((FAILED + 1))
                    return
                fi

                if [ -n "$MIN_MBPS" ] && ! bandwidth_meets_min "$bandwidth_mbps" "$MIN_MBPS"; then
                    echo "FAIL (below ${MIN_MBPS} Mbits/sec floor)"
                    echo "Bandwidth: $bandwidth (${bandwidth_mbps} Mbits/sec)"
                    FAILED=$((FAILED + 1))
                    return
                fi

                echo "OK"
                echo "Bandwidth: $bandwidth (${bandwidth_mbps} Mbits/sec)"
                PASSED=$((PASSED + 1))
            else
                echo "FAIL (no bandwidth data)"
                echo "Output: $output"
                FAILED=$((FAILED + 1))
            fi
        else
            echo "FAIL"
            echo "Error output:"
            echo "$output" | head -10
            FAILED=$((FAILED + 1))
        fi
    fi
}

echo "=== FIPS iperf3 Bandwidth Test ($PROFILE topology) ==="
echo ""
echo "Duration: ${DURATION}s, parallel streams: $PARALLEL"
if [ -n "$MIN_MBPS" ]; then
    echo "Minimum bandwidth: ${MIN_MBPS} Mbits/sec"
fi

# Wait for nodes to converge
echo "Waiting 3s for mesh convergence..."
sleep 3

if [ "$PROFILE" = "mesh" ] || [ "$PROFILE" = "mesh-public" ]; then
    # Test key paths in mesh topology
    echo ""
    echo "Testing mesh topology paths:"
    
    # Direct peer links (client on A, server on D/E)
    iperf_test node-d node-a "$NPUB_D" "A → D (direct peer)"
    iperf_test node-e node-a "$NPUB_E" "A → E (direct peer)"

    # Multi-hop paths (client on A, server on B/C)
    iperf_test node-b node-a "$NPUB_B" "A → B (multi-hop)"
    iperf_test node-c node-a "$NPUB_C" "A → C (multi-hop)"

    # Reverse test (client on E, server on A)
    iperf_test node-a node-e "$NPUB_A" "E → A (direct peer)"

elif [ "$PROFILE" = "chain" ]; then
    echo ""
    echo "Testing chain topology paths:"
    
    # Adjacent hop (client on A, server on B)
    iperf_test node-b node-a "$NPUB_B" "A → B (1 hop)"

    # Multi-hop tests (client on A, server on C/D/E)
    iperf_test node-c node-a "$NPUB_C" "A → C (2 hops)"
    iperf_test node-d node-a "$NPUB_D" "A → D (3 hops)"
    iperf_test node-e node-a "$NPUB_E" "A → E (4 hops)"

    # Reverse multi-hop (client on E, server on A)
    iperf_test node-a node-e "$NPUB_A" "E → A (4 hops)"
fi

echo ""
echo "=== Results: $PASSED passed, $FAILED failed ==="
[ "$FAILED" -eq 0 ] && exit 0 || exit 1

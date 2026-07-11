#!/usr/bin/env bash
# Saturate A -> C through B while checking that independent D -> C traffic,
# latency, and peer liveness continue through the same forwarder.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
COMPOSE=(docker compose -f "$SCRIPT_DIR/docker-compose.yml")

DURATION="${FIPS_FAIR_DURATION:-10}"
PING_INTERVAL="${FIPS_FAIR_PING_INTERVAL:-0.02}"
IDLE_PINGS="${FIPS_FAIR_IDLE_PINGS:-200}"
D_RATE="${FIPS_FAIR_D_RATE:-10M}"
D_MIN_MBIT="${FIPS_FAIR_D_MIN_MBIT:-1}"
A_PORT="${FIPS_FAIR_A_PORT:-5202}"
D_PORT="${FIPS_FAIR_D_PORT:-5203}"
BUILD=0

usage() {
    echo "usage: $0 [--build]"
    echo "  --build    rebuild fips-test:latest first"
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --build) BUILD=1 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
    esac
    shift
done

for command in docker python3; do
    command -v "$command" >/dev/null || { echo "missing command: $command" >&2; exit 1; }
done

if [ "$BUILD" -eq 1 ]; then
    "$PROJECT_ROOT/testing/scripts/build.sh"
elif ! docker image inspect fips-test:latest >/dev/null 2>&1; then
    echo "fips-test:latest is absent; rerun with --build" >&2
    exit 1
fi

python3 "$SCRIPT_DIR/generate-configs.py"
# shellcheck source=/dev/null
source "$SCRIPT_DIR/generated-configs/npubs.env"

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
RESULT_DIR="${FIPS_FAIR_RESULT_DIR:-$SCRIPT_DIR/results/$STAMP}"
mkdir -p "$RESULT_DIR"

cleanup() {
    if [ "${FIPS_FAIR_KEEP:-0}" != "1" ]; then
        "${COMPOSE[@]}" down --volumes --remove-orphans >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT INT TERM

"${COMPOSE[@]}" down --volumes --remove-orphans >/dev/null 2>&1 || true
"${COMPOSE[@]}" up -d
python3 "$SCRIPT_DIR/verify-topology.py" | tee "$RESULT_DIR/topology.txt"

# Network inspection above is authoritative. These probes additionally catch
# an accidentally installed cross-underlay route inside a test container.
for probe in \
    "fips-fair-a 172.28.120.12" \
    "fips-fair-a 172.28.130.13" \
    "fips-fair-c 172.28.110.10" \
    "fips-fair-c 172.28.130.13" \
    "fips-fair-d 172.28.110.10" \
    "fips-fair-d 172.28.120.12"; do
    container="${probe%% *}"
    address="${probe#* }"
    if docker exec "$container" ping -c 1 -W 1 "$address" >/dev/null 2>&1; then
        echo "refusing benchmark: $container reached leaf underlay $address" >&2
        exit 1
    fi
done

DEST="${NPUB_C}.fips"
echo "waiting for both transit paths and all direct B links..."
deadline=$((SECONDS + 90))
while true; do
    a_ready=0
    d_ready=0
    b_peers=0
    docker exec fips-fair-a ping -6 -n -c 1 -W 1 "$DEST" >/dev/null 2>&1 && a_ready=1
    docker exec fips-fair-d ping -6 -n -c 1 -W 1 "$DEST" >/dev/null 2>&1 && d_ready=1
    b_peers=$(docker exec fips-fair-b fipsctl show peers 2>/dev/null \
        | python3 -c "import json,sys; print(sum(p.get('connectivity') == 'connected' for p in json.load(sys.stdin).get('peers', [])))" \
        2>/dev/null || echo 0)
    if [ "$a_ready" -eq 1 ] && [ "$d_ready" -eq 1 ] && [ "$b_peers" -ge 3 ]; then
        break
    fi
    if [ "$SECONDS" -ge "$deadline" ]; then
        echo "multi-peer FIPS paths did not converge" >&2
        "${COMPOSE[@]}" logs --no-color >"$RESULT_DIR/startup.log" 2>&1
        exit 1
    fi
    sleep 1
done

for node in a b c d; do
    docker exec "fips-fair-$node" fipsctl show peers >"$RESULT_DIR/peers-before-$node.json"
done
docker exec fips-fair-b fipsctl show routing >"$RESULT_DIR/forwarding-before.json"
docker exec fips-fair-d ping -6 -n -i "$PING_INTERVAL" -c "$IDLE_PINGS" "$DEST" \
    >"$RESULT_DIR/d-idle.ping" 2>&1

cpu_usage_ns() {
    docker exec fips-fair-b sh -c '
        if [ -r /sys/fs/cgroup/cpu.stat ]; then
            awk '\''$1 == "usage_usec" { printf "%.0f\n", $2 * 1000; found=1 } END { exit !found }'\'' /sys/fs/cgroup/cpu.stat
        elif [ -r /sys/fs/cgroup/cpuacct/cpuacct.usage ]; then
            cat /sys/fs/cgroup/cpuacct/cpuacct.usage
        elif [ -r /sys/fs/cgroup/cpuacct.usage ]; then
            cat /sys/fs/cgroup/cpuacct.usage
        else
            exit 1
        fi'
}

# Separate one-shot iperf servers allow A and D to run concurrently.
docker exec -d fips-fair-c sh -c "iperf3 -s -1 -p $A_PORT >/tmp/fair-a-server.log 2>&1"
docker exec -d fips-fair-c sh -c "iperf3 -s -1 -p $D_PORT >/tmp/fair-d-server.log 2>&1"
sleep 1

log_lines=$(docker logs fips-fair-b 2>&1 | wc -l | tr -d ' ')
docker exec fips-fair-d ping -6 -n -i "$PING_INTERVAL" -w "$DURATION" "$DEST" \
    >"$RESULT_DIR/d-loaded.ping" 2>&1 &
ping_pid=$!
start_cpu_ns=$(cpu_usage_ns)

docker exec fips-fair-a iperf3 -J -c "$DEST" -p "$A_PORT" -t "$DURATION" -P 8 \
    >"$RESULT_DIR/a-tcp8.iperf.json" 2>"$RESULT_DIR/a-tcp8.iperf.stderr" &
a_pid=$!
docker exec fips-fair-d iperf3 -J -c "$DEST" -p "$D_PORT" -t "$DURATION" \
    -u -b "$D_RATE" -l 1100 \
    >"$RESULT_DIR/d-small.iperf.json" 2>"$RESULT_DIR/d-small.iperf.stderr" &
d_pid=$!

FAILED=0
wait "$a_pid" || { echo "A TCP8 failed" >&2; FAILED=1; }
wait "$d_pid" || { echo "D small flow failed" >&2; FAILED=1; }
end_cpu_ns=$(cpu_usage_ns)
wait "$ping_pid" || true

awk -v start="$start_cpu_ns" -v end="$end_cpu_ns" \
    'BEGIN { printf "%.9f\n", (end - start) / 1000000000 }' >"$RESULT_DIR/b.cpu-seconds"
docker logs fips-fair-b 2>&1 | tail -n "+$((log_lines + 1))" >"$RESULT_DIR/b-loaded.log"
docker exec fips-fair-c sh -c 'cat /tmp/fair-a-server.log 2>/dev/null || true' \
    >"$RESULT_DIR/a-server.log"
docker exec fips-fair-c sh -c 'cat /tmp/fair-d-server.log 2>/dev/null || true' \
    >"$RESULT_DIR/d-server.log"

docker exec fips-fair-b fipsctl show routing >"$RESULT_DIR/forwarding-after.json"
for node in a b c d; do
    docker exec "fips-fair-$node" fipsctl show peers >"$RESULT_DIR/peers-after-$node.json"
done

python3 - "$RESULT_DIR/manifest.json" "$DURATION" "$D_RATE" "$D_MIN_MBIT" "$PROJECT_ROOT" <<'PY'
import json
import platform
import subprocess
import sys
from pathlib import Path

destination, duration, d_rate, d_min_mbit, root = sys.argv[1:]
payload = {
    "metadata": {
        "git_commit": subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=root, text=True
        ).strip(),
        "duration_seconds": int(duration),
        "host": platform.platform(),
    },
    "d_offered_rate": d_rate,
    "gates": {
        "d_min_throughput_mbps": float(d_min_mbit),
        "d_max_loss_percent": 50.0,
        "d_max_ping_loss_percent": 50.0,
        "d_min_ping_replies": 10,
    },
}
Path(destination).write_text(json.dumps(payload, indent=2) + "\n")
PY

if ! python3 "$SCRIPT_DIR/analyze.py" "$RESULT_DIR"; then
    FAILED=1
fi
echo "raw results: $RESULT_DIR"
exit "$FAILED"

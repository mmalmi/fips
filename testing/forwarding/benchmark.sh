#!/usr/bin/env bash
# Repeatable FIPS A--B--C forwarding benchmark. A and C have no shared
# underlay; all measured application traffic must be forwarded by B.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
COMPOSE=(docker compose -f "$SCRIPT_DIR/docker-compose.yml")

DURATION="${FIPS_FORWARD_DURATION:-10}"
TCP_STREAMS="${FIPS_FORWARD_TCP_STREAMS:-1 4 8}"
UDP_RATES="${FIPS_FORWARD_UDP_RATES:-100M 200M 250M 300M}"
UDP_LENGTH="${FIPS_FORWARD_UDP_LENGTH:-1100}"
PING_INTERVAL="${FIPS_FORWARD_PING_INTERVAL:-0.01}"
IDLE_PINGS="${FIPS_FORWARD_IDLE_PINGS:-500}"
PERF=0
BUILD=0
QUICK=0

usage() {
    echo "usage: $0 [--build] [--profile] [--quick]"
    echo "  --build    rebuild fips-test:latest first"
    echo "  --profile  enable FIPS_PERF and report B's batching-collapse ratios"
    echo "  --quick    one TCP4 and UDP200M case, five seconds each"
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --build) BUILD=1 ;;
        --profile) PERF=1 ;;
        --quick) QUICK=1 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
    esac
    shift
done

if [ "$QUICK" -eq 1 ]; then
    DURATION=5
    TCP_STREAMS="4"
    UDP_RATES="200M"
    IDLE_PINGS=200
fi

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
RESULT_DIR="${FIPS_FORWARD_RESULT_DIR:-$SCRIPT_DIR/results/$STAMP}"
mkdir -p "$RESULT_DIR"

cleanup() {
    if [ "${FIPS_FORWARD_KEEP:-0}" != "1" ]; then
        "${COMPOSE[@]}" down --volumes --remove-orphans >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT INT TERM

"${COMPOSE[@]}" down --volumes --remove-orphans >/dev/null 2>&1 || true
FIPS_PERF="$PERF" "${COMPOSE[@]}" up -d
python3 "$SCRIPT_DIR/verify-topology.py"

# Docker bridge isolation should also reject a direct A->C underlay probe.
if docker exec fips-forward-a ping -c 1 -W 1 172.31.20.12 >/dev/null 2>&1; then
    echo "refusing benchmark: A reached C's underlay directly" >&2
    exit 1
fi

DEST="${NPUB_C}.fips"
echo "waiting for A->B->C FIPS convergence..."
deadline=$((SECONDS + 90))
until docker exec fips-forward-a ping -6 -n -c 1 -W 1 "$DEST" >/dev/null 2>&1; do
    if [ "$SECONDS" -ge "$deadline" ]; then
        echo "FIPS A->B->C path did not converge" >&2
        "${COMPOSE[@]}" logs --no-color >"$RESULT_DIR/startup.log" 2>&1
        exit 1
    fi
    sleep 1
done

docker exec fips-forward-b fipsctl show routing >"$RESULT_DIR/forwarding-before.json"
docker exec fips-forward-a ping -6 -n -i "$PING_INTERVAL" -c "$IDLE_PINGS" "$DEST" \
    >"$RESULT_DIR/idle.ping" 2>&1

CASE_FILE="$RESULT_DIR/cases.ndjson"
: >"$CASE_FILE"
FAILED=0

cpu_usage_ns() {
    # The cgroup includes the daemon and any worker processes/threads. PID 1
    # accounting alone can silently undercount a non-exec entrypoint or child.
    docker exec fips-forward-b sh -c '
        if [ -r /sys/fs/cgroup/cpu.stat ]; then
            awk '\''$1 == "usage_usec" { printf "%.0f\n", $2 * 1000; found=1 } END { exit !found }'\'' /sys/fs/cgroup/cpu.stat
        elif [ -r /sys/fs/cgroup/cpuacct/cpuacct.usage ]; then
            cat /sys/fs/cgroup/cpuacct/cpuacct.usage
        elif [ -r /sys/fs/cgroup/cpuacct.usage ]; then
            cat /sys/fs/cgroup/cpuacct.usage
        else
            echo "container cgroup CPU accounting unavailable" >&2
            exit 1
        fi'
}

run_case() {
    local name="$1"
    local protocol="$2"
    local argument="$3"
    local ping_pid start_cpu_ns end_cpu_ns log_lines
    local -a iperf_args

    if [ "$protocol" = "tcp" ]; then
        iperf_args=(-P "$argument")
        printf '{"name":"%s","protocol":"tcp","streams":%s}\n' "$name" "$argument" >>"$CASE_FILE"
    else
        iperf_args=(-u -b "$argument" -l "$UDP_LENGTH")
        printf '{"name":"%s","protocol":"udp","offered_rate":"%s","datagram_bytes":%s}\n' \
            "$name" "$argument" "$UDP_LENGTH" >>"$CASE_FILE"
    fi

    echo "running $name..."
    log_lines=$(docker logs fips-forward-b 2>&1 | wc -l | tr -d ' ')
    docker exec fips-forward-a ping -6 -n -i "$PING_INTERVAL" -w "$((DURATION + 2))" "$DEST" \
        >"$RESULT_DIR/$name.ping" 2>&1 &
    ping_pid=$!
    sleep 1
    start_cpu_ns=$(cpu_usage_ns)
    if ! docker exec fips-forward-a iperf3 -J -c "$DEST" -t "$DURATION" "${iperf_args[@]}" \
        >"$RESULT_DIR/$name.iperf.json" 2>"$RESULT_DIR/$name.iperf.stderr"; then
        echo "warning: $name iperf failed" >&2
        FAILED=1
    fi
    end_cpu_ns=$(cpu_usage_ns)
    wait "$ping_pid" || true
    sleep 1

    awk -v start="$start_cpu_ns" -v end="$end_cpu_ns" \
        'BEGIN { printf "%.9f\n", (end - start) / 1000000000 }' >"$RESULT_DIR/$name.cpu-seconds"
    docker logs fips-forward-b 2>&1 | tail -n "+$((log_lines + 1))" | grep '^\[pipe ' \
        >"$RESULT_DIR/$name.pipe.log" || true
}

for streams in $TCP_STREAMS; do
    run_case "tcp-$streams" tcp "$streams"
done
for rate in $UDP_RATES; do
    name_rate=$(printf '%s' "$rate" | tr '[:upper:]' '[:lower:]' | tr -c 'a-z0-9' '-')
    run_case "udp-${name_rate%-}" udp "$rate"
done

docker exec fips-forward-b fipsctl show routing >"$RESULT_DIR/forwarding-after.json"
python3 - "$CASE_FILE" "$RESULT_DIR/cases.json" "$DURATION" "$PERF" "$PROJECT_ROOT" <<'PY'
import json
import platform
import subprocess
import sys
from pathlib import Path

source, destination, duration, perf, root = sys.argv[1:]
cases = [json.loads(line) for line in Path(source).read_text().splitlines() if line]
commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
payload = {
    "metadata": {
        "git_commit": commit,
        "duration_seconds": int(duration),
        "perf_enabled": perf == "1",
        "host": platform.platform(),
    },
    "cases": cases,
}
Path(destination).write_text(json.dumps(payload, indent=2) + "\n")
PY
python3 "$SCRIPT_DIR/analyze.py" "$RESULT_DIR"
echo "raw results: $RESULT_DIR"
exit "$FAILED"

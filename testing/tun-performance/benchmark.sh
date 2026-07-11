#!/usr/bin/env bash
# Direct A--B FIPS system-TUN benchmark with load generators in separate
# cgroups, so endpoint CPU accounting excludes iperf3 and ping.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
COMPOSE=(docker compose -f "$SCRIPT_DIR/docker-compose.yml")

DURATION="${FIPS_TUN_DURATION:-10}"
TCP_STREAMS="${FIPS_TUN_TCP_STREAMS:-1 4 8}"
UDP_RATES="${FIPS_TUN_UDP_RATES:-100M 250M 500M 1G 2G 5G 10G}"
UDP_GSO_RATES="${FIPS_TUN_UDP_GSO_RATES:-2G}"
UDP_LENGTH="${FIPS_TUN_UDP_LENGTH:-1100}"
UDP_GSO_SEGMENTS="${FIPS_TUN_UDP_GSO_SEGMENTS:-32}"
PING_INTERVAL="${FIPS_TUN_PING_INTERVAL:-0.01}"
IDLE_PINGS="${FIPS_TUN_IDLE_PINGS:-500}"
PERF=0
BUILD=0
QUICK=0

usage() {
    echo "usage: $0 [--build] [--profile] [--quick]"
    echo "  --build    rebuild fips-test:latest first"
    echo "  --profile  report Linux TUN packet/frame ratios from FIPS_PERF"
    echo "  --quick    one TCP4 and UDP500M case, five seconds each"
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
    UDP_RATES="500M"
    UDP_GSO_RATES="500M"
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
RESULT_DIR="${FIPS_TUN_RESULT_DIR:-$SCRIPT_DIR/results/$STAMP}"
mkdir -p "$RESULT_DIR"

cleanup() {
    if [ "${FIPS_TUN_KEEP:-0}" != "1" ]; then
        "${COMPOSE[@]}" down --volumes --remove-orphans >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT INT TERM

"${COMPOSE[@]}" down --volumes --remove-orphans >/dev/null 2>&1 || true
FIPS_PERF="$PERF" "${COMPOSE[@]}" up -d
python3 "$SCRIPT_DIR/verify-topology.py"
docker exec fips-tun-load-b iperf3 -s -D

DEST="${NPUB_B}.fips"
echo "waiting for direct FIPS system-TUN convergence..."
deadline=$((SECONDS + 90))
until docker exec fips-tun-load-a ping -6 -n -c 1 -W 1 "$DEST" >/dev/null 2>&1; do
    if [ "$SECONDS" -ge "$deadline" ]; then
        echo "direct FIPS TUN path did not converge" >&2
        "${COMPOSE[@]}" logs --no-color >"$RESULT_DIR/startup.log" 2>&1
        exit 1
    fi
    sleep 1
done

docker exec fips-tun-a fipsctl show routing >"$RESULT_DIR/a-before.json"
docker exec fips-tun-b fipsctl show routing >"$RESULT_DIR/b-before.json"
docker exec fips-tun-load-a ping -6 -n -i "$PING_INTERVAL" -c "$IDLE_PINGS" "$DEST" \
    >"$RESULT_DIR/idle.ping" 2>&1

CASE_FILE="$RESULT_DIR/cases.ndjson"
: >"$CASE_FILE"
FAILED=0

cpu_usage_ns() {
    local container="$1"
    docker exec "$container" sh -c '
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
    local ping_pid a_start a_end b_start b_end a_log_lines b_log_lines
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
    a_log_lines=$(docker logs fips-tun-a 2>&1 | wc -l | tr -d ' ')
    b_log_lines=$(docker logs fips-tun-b 2>&1 | wc -l | tr -d ' ')
    docker exec fips-tun-load-a ping -6 -n -i "$PING_INTERVAL" -w "$((DURATION + 2))" "$DEST" \
        >"$RESULT_DIR/$name.ping" 2>&1 &
    ping_pid=$!
    sleep 1
    a_start=$(cpu_usage_ns fips-tun-a)
    b_start=$(cpu_usage_ns fips-tun-b)
    if ! docker exec fips-tun-load-a iperf3 -J -c "$DEST" -t "$DURATION" "${iperf_args[@]}" \
        >"$RESULT_DIR/$name.iperf.json" 2>"$RESULT_DIR/$name.iperf.stderr"; then
        echo "warning: $name iperf failed" >&2
        FAILED=1
    fi
    a_end=$(cpu_usage_ns fips-tun-a)
    b_end=$(cpu_usage_ns fips-tun-b)
    wait "$ping_pid" || true
    sleep 1

    awk -v start="$a_start" -v end="$a_end" \
        'BEGIN { printf "%.9f\n", (end - start) / 1000000000 }' >"$RESULT_DIR/$name.a.cpu-seconds"
    awk -v start="$b_start" -v end="$b_end" \
        'BEGIN { printf "%.9f\n", (end - start) / 1000000000 }' >"$RESULT_DIR/$name.b.cpu-seconds"
    docker logs fips-tun-a 2>&1 | tail -n "+$((a_log_lines + 1))" | grep '^\[pipe ' \
        >"$RESULT_DIR/$name.a.pipe.log" || true
    docker logs fips-tun-b 2>&1 | tail -n "+$((b_log_lines + 1))" | grep '^\[pipe ' \
        >"$RESULT_DIR/$name.b.pipe.log" || true
}

run_udp_gso_case() {
    local name="$1"
    local rate="$2"
    local ping_pid receiver_pid a_start a_end b_start b_end a_log_lines b_log_lines

    printf '{"name":"%s","protocol":"udp-gso","offered_rate":"%s","segment_bytes":%s,"segments_per_send":%s}\n' \
        "$name" "$rate" "$UDP_LENGTH" "$UDP_GSO_SEGMENTS" >>"$CASE_FILE"
    echo "running $name with Linux UDP_SEGMENT..."
    a_log_lines=$(docker logs fips-tun-a 2>&1 | wc -l | tr -d ' ')
    b_log_lines=$(docker logs fips-tun-b 2>&1 | wc -l | tr -d ' ')
    docker exec fips-tun-load-b python3 /opt/fips-bench/udp_gso.py receive \
        --duration "$((DURATION + 3))" >"$RESULT_DIR/$name.receiver.json" \
        2>"$RESULT_DIR/$name.receiver.stderr" &
    receiver_pid=$!
    docker exec fips-tun-load-a ping -6 -n -i "$PING_INTERVAL" -w "$((DURATION + 2))" "$DEST" \
        >"$RESULT_DIR/$name.ping" 2>&1 &
    ping_pid=$!
    sleep 1
    a_start=$(cpu_usage_ns fips-tun-a)
    b_start=$(cpu_usage_ns fips-tun-b)
    if ! docker exec fips-tun-load-a python3 /opt/fips-bench/udp_gso.py send "$DEST" \
        --duration "$DURATION" --rate "$rate" --segment-size "$UDP_LENGTH" \
        --segments "$UDP_GSO_SEGMENTS" >"$RESULT_DIR/$name.sender.json" \
        2>"$RESULT_DIR/$name.sender.stderr"; then
        echo "warning: $name UDP_SEGMENT sender failed or is unsupported" >&2
        FAILED=1
    fi
    # Include the short pipeline drain after the final aggregate send.
    sleep 0.1
    a_end=$(cpu_usage_ns fips-tun-a)
    b_end=$(cpu_usage_ns fips-tun-b)
    wait "$ping_pid" || true
    if ! wait "$receiver_pid"; then
        echo "warning: $name receiver failed" >&2
        FAILED=1
    fi
    sleep 1

    awk -v start="$a_start" -v end="$a_end" \
        'BEGIN { printf "%.9f\n", (end - start) / 1000000000 }' >"$RESULT_DIR/$name.a.cpu-seconds"
    awk -v start="$b_start" -v end="$b_end" \
        'BEGIN { printf "%.9f\n", (end - start) / 1000000000 }' >"$RESULT_DIR/$name.b.cpu-seconds"
    docker logs fips-tun-a 2>&1 | tail -n "+$((a_log_lines + 1))" | grep '^\[pipe ' \
        >"$RESULT_DIR/$name.a.pipe.log" || true
    docker logs fips-tun-b 2>&1 | tail -n "+$((b_log_lines + 1))" | grep '^\[pipe ' \
        >"$RESULT_DIR/$name.b.pipe.log" || true
}

for streams in $TCP_STREAMS; do
    run_case "tcp-$streams" tcp "$streams"
done
for rate in $UDP_RATES; do
    name_rate=$(printf '%s' "$rate" | tr '[:upper:]' '[:lower:]' | tr -c 'a-z0-9' '-')
    run_case "udp-${name_rate%-}" udp "$rate"
done
for rate in $UDP_GSO_RATES; do
    name_rate=$(printf '%s' "$rate" | tr '[:upper:]' '[:lower:]' | tr -c 'a-z0-9' '-')
    run_udp_gso_case "udp-gso-${name_rate%-}" "$rate"
done

docker exec fips-tun-a fipsctl show routing >"$RESULT_DIR/a-after.json"
docker exec fips-tun-b fipsctl show routing >"$RESULT_DIR/b-after.json"
docker logs fips-tun-a >"$RESULT_DIR/node-a.log" 2>&1
docker logs fips-tun-b >"$RESULT_DIR/node-b.log" 2>&1
python3 - "$CASE_FILE" "$RESULT_DIR/cases.json" "$DURATION" "$PERF" "$PROJECT_ROOT" <<'PY'
import json
import os
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
        "linux_tun_vnet": os.environ.get("FIPS_LINUX_TUN_VNET", "1") not in {"0", "false", "False"},
        "load_generators_separate_cgroups": True,
        "host": platform.platform(),
    },
    "cases": cases,
}
Path(destination).write_text(json.dumps(payload, indent=2) + "\n")
PY
python3 "$SCRIPT_DIR/analyze.py" "$RESULT_DIR"
echo "raw results: $RESULT_DIR"
exit "$FAILED"

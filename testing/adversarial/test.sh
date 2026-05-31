#!/bin/bash
# Adversarial ingress metric harness.
#
# Usage:
#   testing/adversarial/test.sh [--skip-build] [--keep-up]
#       [--udp-packets N] [--tcp-connections N] [--sources N]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TESTING_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
COMPOSE_FILE="$SCRIPT_DIR/docker-compose.yml"
RESULTS_DIR="$SCRIPT_DIR/results"
SNAPSHOT_DIR="$RESULTS_DIR/snapshots"
PHASE_DIR="$RESULTS_DIR/phases"

VICTIM="fips-adversarial-victim"
ATTACKER="fips-adversarial-attacker"
TARGET_IP="172.33.0.10"

SKIP_BUILD=false
KEEP_UP=false
UDP_PACKETS=20000
TCP_CONNECTIONS=96
SOURCES=64
HOLD_SECS=8
SLOWLORIS_SETTLE_SECS=4

while [ $# -gt 0 ]; do
    case "$1" in
        --skip-build) SKIP_BUILD=true; shift ;;
        --keep-up) KEEP_UP=true; shift ;;
        --udp-packets) UDP_PACKETS="$2"; shift 2 ;;
        --tcp-connections) TCP_CONNECTIONS="$2"; shift 2 ;;
        --sources) SOURCES="$2"; shift 2 ;;
        --hold-secs) HOLD_SECS="$2"; shift 2 ;;
        --slowloris-settle-secs) SLOWLORIS_SETTLE_SECS="$2"; shift 2 ;;
        *) echo "Unknown option: $1" >&2; exit 1 ;;
    esac
done

cleanup() {
    if [ "$KEEP_UP" = false ]; then
        docker compose -f "$COMPOSE_FILE" down >/dev/null 2>&1 || true
    fi
}

trap cleanup EXIT

log() {
    echo "=== $*"
}

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

wait_for_control() {
    for _ in $(seq 1 40); do
        if docker exec "$VICTIM" fipsctl show status >/dev/null 2>&1; then
            return 0
        fi
        sleep 0.5
    done
    docker logs "$VICTIM" >&2 || true
    fail "victim control socket did not become ready"
}

snapshot() {
    local name="$1"
    docker exec "$VICTIM" python3 /adversarial/scripts/snapshot_victim.py > "$SNAPSHOT_DIR/${name}.json"
}

run_phase() {
    local phase="$1"
    log "Phase: $phase"
    snapshot "before-${phase}"
    docker exec "$ATTACKER" python3 /adversarial/scripts/ingress_gauntlet.py \
        --phase "$phase" \
        --target "$TARGET_IP" \
        --udp-packets "$UDP_PACKETS" \
        --tcp-connections "$TCP_CONNECTIONS" \
        --sources "$SOURCES" \
        --out "/results/phases/${phase}.json" >/dev/null
    sleep 1
    snapshot "after-${phase}"
}

run_slowloris_phase() {
    local phase="tcp-slowloris"
    local ready="$RESULTS_DIR/slowloris.ready.json"
    rm -f "$ready" "$PHASE_DIR/${phase}.json"
    log "Phase: $phase"
    snapshot "before-${phase}"
    docker exec "$ATTACKER" python3 /adversarial/scripts/ingress_gauntlet.py \
        --phase "$phase" \
        --target "$TARGET_IP" \
        --tcp-connections "$TCP_CONNECTIONS" \
        --hold-secs "$HOLD_SECS" \
        --ready-file "/results/slowloris.ready.json" \
        --out "/results/phases/${phase}.json" >/dev/null &
    local pid="$!"

    for _ in $(seq 1 40); do
        if [ -f "$ready" ]; then
            break
        fi
        sleep 0.25
    done
    [ -f "$ready" ] || fail "slowloris phase did not report ready"

    sleep "$SLOWLORIS_SETTLE_SECS"
    snapshot "during-${phase}"
    wait "$pid"
    sleep 1
    snapshot "after-${phase}"
}

assert_container_safety() {
    local container="$1"
    local expected_caps="$2"
    local id
    id="$(docker compose -f "$COMPOSE_FILE" ps -q "$container")"
    [ -n "$id" ] || fail "missing container id for $container"

    local privileged network_mode cap_add cap_drop binds
    privileged="$(docker inspect "$id" --format '{{.HostConfig.Privileged}}')"
    network_mode="$(docker inspect "$id" --format '{{.HostConfig.NetworkMode}}')"
    cap_add="$(docker inspect "$id" --format '{{json .HostConfig.CapAdd}}')"
    cap_drop="$(docker inspect "$id" --format '{{json .HostConfig.CapDrop}}')"
    binds="$(docker inspect "$id" --format '{{json .HostConfig.Binds}}')"

    [ "$privileged" = "false" ] || fail "$container is privileged"
    [ "$network_mode" != "host" ] || fail "$container uses host networking"
    printf '%s' "$binds" | grep -q 'docker.sock' && fail "$container mounts docker.sock"
    printf '%s' "$cap_drop" | grep -q '"ALL"' || fail "$container does not drop default capabilities"

    case "$expected_caps" in
        none)
            [ "$cap_add" = "null" ] || [ "$cap_add" = "[]" ] || fail "$container has unexpected cap_add: $cap_add"
            ;;
        attacker)
            printf '%s' "$cap_add" | grep -q 'NET_ADMIN' || fail "$container lacks NET_ADMIN"
            printf '%s' "$cap_add" | grep -q 'NET_RAW' || fail "$container lacks NET_RAW"
            ;;
    esac
}

assert_network_internal() {
    local id networks internal
    id="$(docker compose -f "$COMPOSE_FILE" ps -q attacker)"
    networks="$(docker inspect "$id" --format '{{range $name, $_ := .NetworkSettings.Networks}}{{println $name}}{{end}}')"
    [ -n "$networks" ] || fail "attacker has no Docker networks"
    while IFS= read -r network; do
        [ -n "$network" ] || continue
        internal="$(docker network inspect "$network" --format '{{.Internal}}')"
        [ "$internal" = "true" ] || fail "network $network is not internal"
    done <<< "$networks"
}

assert_victim_healthy() {
    local status peers
    status="$(docker exec "$VICTIM" fipsctl show status)"
    peers="$(printf '%s' "$status" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("peer_count", -1))')"
    [ "$peers" = "0" ] || fail "garbage input unexpectedly authenticated peers: peer_count=$peers"
}

rm -rf "$RESULTS_DIR"
mkdir -p "$SNAPSHOT_DIR" "$PHASE_DIR"

if [ "$SKIP_BUILD" = false ]; then
    log "Building Linux test binaries"
    "$TESTING_DIR/scripts/build.sh" --no-docker
fi

log "Starting isolated adversarial harness"
docker compose -f "$COMPOSE_FILE" down >/dev/null 2>&1 || true
docker compose -f "$COMPOSE_FILE" up -d --build victim attacker

log "Verifying Docker isolation"
assert_container_safety victim none
assert_container_safety attacker attacker
assert_network_internal

log "Waiting for victim control socket"
wait_for_control

run_phase "udp-random"
run_phase "udp-msg1"
run_phase "udp-established"
run_phase "udp-spoofed"
run_phase "tcp-malformed"
run_slowloris_phase

log "Checking victim survived"
assert_victim_healthy

log "Writing combined report"
python3 "$SCRIPT_DIR/scripts/merge_report.py" \
    --results "$RESULTS_DIR" \
    --safety "victim cap_drop=ALL, no added capabilities" \
    --safety "attacker cap_drop=ALL with only NET_ADMIN and NET_RAW added" \
    --safety "no privileged containers, no host networking, no docker.sock mount" \
    --safety "Docker bridge network is internal=true"

log "Adversarial ingress gauntlet passed"

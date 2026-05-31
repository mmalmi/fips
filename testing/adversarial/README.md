# FIPS Adversarial Ingress Gauntlet

This harness runs one victim FIPS daemon and one attacker container on an
internal Docker bridge. It is intended to produce repeatable spam/DoS metrics
without touching the Docker host network namespace.

## Safety Model

- The victim runs without TUN/DNS and with `cap_drop: [ALL]`.
- The attacker gets only `NET_ADMIN` and `NET_RAW`.
- The attacker is not privileged and does not use host networking.
- The Docker network is `internal: true`, so the test bridge is isolated from
  external routing/NAT.
- The attacker only adds temporary IPv4 aliases to its own container `eth0`.
- No host firewall, host routes, or Docker daemon socket are mounted.

Docker capabilities are scoped to the container's network namespace unless the
container is privileged or uses host networking. This harness deliberately does
neither.

## Run

```bash
testing/adversarial/test.sh
```

Useful options:

```bash
testing/adversarial/test.sh --skip-build
testing/adversarial/test.sh --keep-up
testing/adversarial/test.sh --udp-packets 50000 --tcp-connections 128
testing/adversarial/test.sh --slowloris-settle-secs 4
```

The test writes:

- `testing/adversarial/results/latest.json`
- `testing/adversarial/results/summary.md`
- per-phase traffic reports under `testing/adversarial/results/phases/`
- victim snapshots under `testing/adversarial/results/snapshots/`

## What It Exercises

- UDP random garbage from many assigned source IPs.
- UDP valid-looking FMP Msg1 frames from many assigned source IPs.
- UDP established-frame-shaped packets with unknown receiver indexes.
- UDP raw Ethernet/IPv4 spoofed-source packets, when `NET_RAW` is available.
- TCP malformed FMP prefixes and frames.
- TCP slowloris-style partial-prefix connections held open long enough to
  snapshot victim resource use.

The suite fails only on harness safety violations, victim crash/control-socket
loss, or accidental authentication from garbage input. The report is the main
artifact: it shows packet counts, send errors, elapsed time, victim RSS/HWM,
FD/thread counts, FIPS status, transport counters, and kernel network counters.

# FIPS transit forwarding benchmark

This harness measures the exact application path `A -> FIPS B -> C`. It uses
two internal Docker bridges:

```text
A -- ab underlay -- B -- bc underlay -- C
```

Only B is dual-homed. The harness verifies the network attachments and refuses
to run if A can reach C's underlay address. This prevents the dynamic direct
A-C shortcut that invalidates a shared-bridge forwarding benchmark.

Build and run the uninstrumented scorecard on an otherwise-idle Linux Docker
host:

```sh
testing/forwarding/benchmark.sh --build
```

The result directory contains raw iperf3 JSON, raw idle/loaded ping samples,
B's cgroup CPU deltas, before/after forwarding counters, `summary.json`, and a
compact `summary.md`. The default sweep covers TCP with 1/4/8 streams and UDP
at 100/200/250/300 Mbit/s. B CPU comes from the container cgroup, so worker
processes and threads cannot escape the measurement. UDP uses explicit
1100-byte datagrams to stay safely below the FIPS path MTU. Environment
variables tune it:

```sh
FIPS_FORWARD_DURATION=20 \
FIPS_FORWARD_TCP_STREAMS="1 8" \
FIPS_FORWARD_UDP_RATES="100M 200M 250M 300M" \
FIPS_FORWARD_UDP_LENGTH=1100 \
testing/forwarding/benchmark.sh
```

Run a second, explicitly instrumented pass for forwarding attribution:

```sh
testing/forwarding/benchmark.sh --profile
```

`--profile` enables the opt-in `[pipe]` reporter. The summary calls out B's
crypto-open, crypto-seal, live-output, and `sendmmsg` packets-per-batch ratios,
plus seal allocations per packet. Ratios near `1.0` identify the known
forwarding-side batching collapse. Stage logs also expose forwarding latency
distributions. The units differ by stage: `session_datagram_decode`,
`coord_cache_warm`, `transit_route`, and `transit_encode` emit one sample per
planned packet. `transit_encode` covers either the scalar envelope copy or the
zero-copy owned-buffer rewrite. `transit_submit` and `transit_total` emit one
sample per contiguous forwarding run flushed to the dataplane, which may
contain many packets; submit covers the dataplane pump and total additionally
covers run construction and terminal receipt accounting. Do not compare
per-run latency samples directly with the per-packet stages. The profiler adds
timestamps and atomics on these hot paths, so do not compare its absolute
throughput/CPU values with the uninstrumented scorecard.

For a smoke run:

```sh
testing/forwarding/benchmark.sh --quick
```

For multi-peer saturation and control-liveness fairness, use the
[`multipeer`](multipeer/README.md) A/D→B→C lab.

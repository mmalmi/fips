# FIPS direct system-TUN benchmark

This harness measures direct `A -> B` traffic through both Linux system-TUN
adapters and the full FIPS session/link stack. A and B share one internal
Docker bridge. Each endpoint runs only FIPS plus its local DNS forwarder;
iperf3 and ping run in separate containers that share the endpoint network
namespaces but have separate CPU cgroups. The reported endpoint CPU therefore
does not include load-generator or iperf-server work.

Build and run the uninstrumented scorecard on an otherwise-idle Linux Docker
host:

```sh
testing/tun-performance/benchmark.sh --build
```

The default sweep runs TCP with 1/4/8 streams, ordinary iperf UDP at
100M/250M/500M/1G/2G/5G/10G, and a focused `udp-gso-2g` case. UDP uses
explicit 1100-byte datagrams below the 1280-byte TUN MTU. Each case records throughput, loss, loaded latency tails,
endpoint A/B/combined cgroup CPU-sec/Gbit, raw iperf3 JSON, ping samples, FIPS
counters, daemon logs, `summary.json`, and `summary.md`. Tune the sweep with:

```sh
FIPS_TUN_DURATION=20 \
FIPS_TUN_TCP_STREAMS="1 8" \
FIPS_TUN_UDP_RATES="250M 500M 1G 2G 5G 10G" \
FIPS_TUN_UDP_GSO_RATES="1G 2G 5G" \
FIPS_TUN_UDP_LENGTH=1100 \
testing/tun-performance/benchmark.sh
```

Run a separate profiling pass for Linux VNET adapter effectiveness:

```sh
testing/tun-performance/benchmark.sh --profile
```

The profile summary reports A's outbound TUN-read and B's inbound TUN-write
packets per frame. Ratios above 1 mean VNET/GSO or GRO is preserving multiple
IP packets per syscall-sized frame. Profiling adds per-packet timestamps and
atomics, so compare absolute throughput/CPU only between uninstrumented runs.

The `udp-gso` case uses Linux `sendmsg(2)` with `SOL_UDP/UDP_SEGMENT` from the
separate load-A cgroup. Each syscall carries 32 sequence-numbered 1100-byte
segments by default. Load-B counts received sequence datagrams, so the summary
includes delivered throughput and loss. An unsupported kernel returns an
explicit `udp_segment_supported: false` result and fails the run instead of
silently falling back to singleton UDP. `FIPS_TUN_UDP_GSO_SEGMENTS` changes the
segments per aggregate send.

For a smoke run:

```sh
testing/tun-performance/benchmark.sh --quick
```

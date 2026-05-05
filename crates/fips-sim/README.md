# fips-sim

Fast in-process simulation for FIPS routing strategy comparison.

This crate is intentionally lighter than `testing/chaos`: it does not start
containers or sockets. It models FIPS tree coordinates and greedy forwarding
directly, then compares strategies under honest, malicious, and misbehaving
peers.

```rust
use fips_sim::{AdversaryConfig, SimConfig, Simulation};

let report = Simulation::new(SimConfig {
    node_count: 100,
    target_edges: 240,
    route_probe_count: 1_000,
    stream_probe_count: 150,
    stream_size_bytes: 64 * 1024 * 1024,
    max_multipath_routes: 3,
    adversary: AdversaryConfig {
        root_grinder_fraction: 0.03,
        phantom_root_fraction: 0.05,
        blackhole_fraction: 0.08,
        flaky_fraction: 0.05,
        flaky_drop_probability: 0.30,
    },
    ..SimConfig::default()
})
.run();
```

Run the built-in comparison example:

```sh
cargo run -p fips-sim --example compare_routing_strategies
```

Built-in strategies:

- `current_fips`: current smallest-root, transitive-ancestry FIPS v1 behavior.
- `verified_ancestry`: proposed hardening model that rejects phantom ancestry
  by requiring every ancestry hop to correspond to a real topology edge.
- `pinned_root`: private-mesh model where nodes only follow a configured root
  identity. In the simulator this is the smallest honest endpoint.
- `reply_learned_flood`: Reticulum-like discovery model where first contact
  floods through peers and a next-hop route is cached only after a reply/proof
  returns on the reverse path.
- `reply_learned_multipath`: large-stream model that keeps route-quality and
  peer-reputation scores, then adaptively schedules bytes across confirmed
  routes when the added path improves estimated completion time.

The simulator reports root capture, malicious parent selection, route success,
unconfirmed deliveries, reply failures, discovery floods, learned route
attempts, stream completion rates, latency, throughput, route fanout, total
transmissions, source packet counts, packet loss, blackhole/flaky drops,
loops, no-route failures, and hop percentiles. Each strategy also reports a
`tcp_streams` view where ordinary TCP-over-FIPS keeps one active route, keeps
warm route candidates for failover, and pays a retransmission-timeout-style
penalty when the route changes.

This crate is still an analytical model. Real host TCP behavior is exercised
by the Docker chaos scenarios, especially `testing/chaos/scenarios/tcp-mesh.yaml`,
which runs `iperf3` through the FIPS IPv6 adapter while UDP/TCP mesh links are
degraded and flapped.

Reachability evidence is modeled as local evidence, not peer claims. A direct
FMP/Noise session proves the directly connected peer is reachable on that link;
a reply-confirmed discovery proves a recent bidirectional multi-hop path. An
advertised "I can reach X" hint is not treated as an authoritative route.

Native FIPS streams and ordinary TCP-over-FIPS are reported separately because
they have different failure modes. Native FIPS chunks can carry route/chunk
identity and be reassembled or retransmitted by FIPS, so multiple active paths
can improve bulk transfer. A normal TCP flow through the IPv6 adapter has one
congestion-control loop; striping it over paths with different RTT/loss can look
like packet loss and collapse throughput. The `tcp_streams` view therefore uses
one active route plus warm standby candidates unless FIPS grows resequencing,
FEC, or MPTCP-like semantics below the host TCP stack.
